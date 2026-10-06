package cli

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3operation"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type encryptInputs struct {
	selections  []string
	inputFiles  []string
	onlyFiles   []string
	onlyFolders []string
}

func absoluteCleanPath(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

func resolveEncryptInputs(literals, patterns []string, followSymlinks bool) (encryptInputs, error) {
	return resolveEncryptInputsWithBudget(context.Background(), literals, patterns, followSymlinks, fileops.NewZIPResourceBudget())
}

func resolveEncryptInputsWithBudget(ctx context.Context, literals, patterns []string, followSymlinks bool, budget *fileops.ZIPResourceBudget) (encryptInputs, error) {
	var result encryptInputs
	if err := pcv3operation.AdmitZIPWorkingMemory(ctx, budget); err != nil {
		return result, err
	}
	var retained uint64
	defer func() { budget.Release(retained) }()
	reservePath := func(path string) (uint64, error) {
		pathBytes := len(path)
		if !filepath.IsAbs(path) {
			cwd, err := os.Getwd()
			if err != nil {
				return 0, err
			}
			pathBytes += len(cwd) + 1
		}
		cost, err := fileops.ReserveZIPInputPath(budget, pathBytes)
		if err == nil {
			retained += cost
		}
		return cost, err
	}
	seenSelections := make(map[string]struct{})
	seenFiles := make(map[string]struct{})

	addFile := func(path string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		cost, err := reservePath(path)
		if err != nil {
			return err
		}
		key, err := absoluteCleanPath(path)
		if err != nil {
			return err
		}
		if _, exists := seenFiles[key]; exists {
			budget.Release(cost)
			retained -= cost
			return nil
		}
		seenFiles[key] = struct{}{}
		result.inputFiles = append(result.inputFiles, path)
		return nil
	}

	addSelection := func(path string) error {
		if path == "" {
			return errors.New("input path must not be empty")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		cost, err := reservePath(path)
		if err != nil {
			return err
		}
		key, err := absoluteCleanPath(path)
		if err != nil {
			return err
		}
		if _, exists := seenSelections[key]; exists {
			budget.Release(cost)
			retained -= cost
			return nil
		}
		seenSelections[key] = struct{}{}

		info, err := os.Stat(path)
		if err != nil {
			looksLikeGlob := looksLikeGlobPath(path)
			if errors.Is(err, os.ErrNotExist) || isInvalidWindowsWildcardPath(path, err) {
				if looksLikeGlob {
					return fmt.Errorf("input path %q does not exist; use --glob %q to select by pattern", path, path)
				}
				return fmt.Errorf("input path %q does not exist", path)
			}
			return fmt.Errorf("cannot access input path %q: %w", path, err)
		}
		result.selections = append(result.selections, path)
		if info.IsDir() {
			result.onlyFolders = append(result.onlyFolders, path)
			return fileops.WalkZIPInputs(ctx, path, budget, func(walkPath string, walkInfo os.FileInfo, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if walkInfo.Mode().IsRegular() {
					return addFile(walkPath)
				}
				if followSymlinks && walkInfo.Mode()&os.ModeSymlink != 0 {
					if target, err := filepath.EvalSymlinks(walkPath); err == nil {
						targetInfo, err := os.Stat(target)
						if err == nil && targetInfo.Mode().IsRegular() {
							return addFile(walkPath)
						}
					}
				}
				return nil
			})
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("input path %q is not a regular file or directory", path)
		}
		result.onlyFiles = append(result.onlyFiles, path)
		return addFile(path)
	}

	for _, path := range literals {
		if err := addSelection(path); err != nil {
			return encryptInputs{}, err
		}
	}
	for _, pattern := range patterns {
		matches := 0
		err := fileops.GlobZIPInputs(ctx, pattern, budget, func(match string) error {
			matches++
			return addSelection(match)
		})
		if err != nil {
			if errors.Is(err, filepath.ErrBadPattern) {
				return encryptInputs{}, fmt.Errorf("invalid glob pattern %q: %w", pattern, err)
			}
			return encryptInputs{}, err
		}
		if matches == 0 {
			return encryptInputs{}, fmt.Errorf("glob %q matched no paths", pattern)
		}
	}
	if len(result.inputFiles) == 0 {
		return encryptInputs{}, errors.New("no regular files found to encrypt")
	}
	return result, nil
}

func validateEncryptOutputPaths(inputs encryptInputs, keyfiles []string, output string, split bool) error {
	budget := fileops.NewZIPResourceBudget()
	for _, paths := range [][]string{inputs.selections, inputs.inputFiles, keyfiles} {
		for _, path := range paths {
			if _, err := fileops.ReserveZIPInputPath(budget, len(path)); err != nil {
				return err
			}
		}
	}
	reserved := []string{output}
	protected := make([]string, 0, len(inputs.selections)+len(inputs.inputFiles)+len(keyfiles))
	protected = append(protected, inputs.selections...)
	protected = append(protected, inputs.inputFiles...)
	protected = append(protected, keyfiles...)
	for _, path := range protected {
		for _, artifact := range reserved {
			same, err := samePathOrFile(path, artifact)
			if err != nil {
				return err
			}
			if same {
				return fmt.Errorf("protected source %q conflicts with output artifact %q", path, artifact)
			}
		}
		if split {
			artifact, ok, err := splitOutputArtifact(path, output)
			if err != nil {
				return err
			}
			if ok {
				return fmt.Errorf("protected source %q conflicts with output artifact %q", path, artifact)
			}
		}
	}
	if split {
		existing, err := existingSplitOutputArtifactsWithBudget(output, budget)
		if err != nil {
			return err
		}
		for _, artifact := range existing {
			for _, path := range protected {
				same, err := samePathOrFile(path, artifact)
				if err != nil {
					return err
				}
				if same {
					return fmt.Errorf("protected source %q conflicts with output artifact %q", path, artifact)
				}
			}
		}
	}
	return nil
}

func samePathOrFile(first, second string) (bool, error) {
	same, err := fileops.SamePathOrFile(first, second)
	if err != nil {
		return false, fmt.Errorf("compare protected path %q with output artifact %q: %w", first, second, err)
	}
	return same, nil
}

func splitOutputArtifact(path, output string) (string, bool, error) {
	pathAbs, err := absoluteCleanPath(path)
	if err != nil {
		return "", false, fmt.Errorf("resolve protected path %q: %w", path, err)
	}
	outputAbs, err := absoluteCleanPath(output)
	if err != nil {
		return "", false, fmt.Errorf("resolve output path %q: %w", output, err)
	}
	suffix, ok := splitArtifactSuffix(filepath.Base(pathAbs))
	if !ok {
		return "", false, nil
	}
	canonical := outputAbs + suffix
	same, err := samePathOrFile(pathAbs, canonical)
	if err != nil {
		return "", false, err
	}
	if !same {
		return "", false, nil
	}
	return path, true, nil
}

func splitArtifactSuffix(name string) (string, bool) {
	numericEnd := len(name)
	const incomplete = ".incomplete"
	hasIncomplete := hasASCIIInsensitiveSuffix(name, incomplete)
	if hasIncomplete {
		numericEnd -= len(incomplete)
	}
	dot := strings.LastIndexByte(name[:numericEnd], '.')
	if dot < 0 || dot == numericEnd-1 {
		return "", false
	}
	for i := dot + 1; i < numericEnd; i++ {
		if name[i] < '0' || name[i] > '9' {
			return "", false
		}
	}
	if hasIncomplete {
		return name[dot:numericEnd] + incomplete, true
	}
	return name[dot:], true
}

func hasASCIIInsensitiveSuffix(value, suffix string) bool {
	if len(value) < len(suffix) {
		return false
	}
	value = value[len(value)-len(suffix):]
	for i := range suffix {
		left := value[i]
		right := suffix[i]
		if left >= 'A' && left <= 'Z' {
			left += 'a' - 'A'
		}
		if right >= 'A' && right <= 'Z' {
			right += 'a' - 'A'
		}
		if left != right {
			return false
		}
	}
	return true
}

func existingSplitOutputArtifactsWithBudget(output string, budget *fileops.ZIPResourceBudget) ([]string, error) {
	cost, err := fileops.ReserveZIPInputPath(budget, len(output))
	if err != nil {
		return nil, err
	}
	defer budget.Release(cost)
	outputAbs, err := absoluteCleanPath(output)
	if err != nil {
		return nil, fmt.Errorf("resolve output path %q: %w", output, err)
	}
	outputDir := filepath.Dir(outputAbs)
	var artifacts []string
	var retained uint64
	err = fileops.VisitZIPDirectoryNames(context.Background(), outputDir, budget, func(name string) error {
		cost, err := fileops.ReserveZIPInputPath(budget, len(outputDir)+len(name)+1)
		if err != nil {
			return err
		}
		candidate := filepath.Join(outputDir, name)
		_, ok, err := splitOutputArtifact(candidate, outputAbs)
		if err != nil || !ok {
			budget.Release(cost)
			return err
		}
		retained += cost
		artifacts = append(artifacts, candidate)
		return nil
	})
	if err != nil {
		budget.Release(retained)
		return nil, fmt.Errorf("inspect output directory %q: %w", outputDir, err)
	}
	return artifacts, nil
}
