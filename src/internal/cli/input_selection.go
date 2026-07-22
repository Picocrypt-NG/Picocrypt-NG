package cli

import (
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
	var result encryptInputs
	seenSelections := make(map[string]struct{})
	seenFiles := make(map[string]struct{})

	addFile := func(path string) error {
		key, err := absoluteCleanPath(path)
		if err != nil {
			return err
		}
		if _, exists := seenFiles[key]; exists {
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
		key, err := absoluteCleanPath(path)
		if err != nil {
			return err
		}
		if _, exists := seenSelections[key]; exists {
			return nil
		}
		seenSelections[key] = struct{}{}

		info, err := os.Stat(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				if strings.ContainsAny(path, "*?[") {
					return fmt.Errorf("input path %q does not exist; use --glob %q to select by pattern", path, path)
				}
				return fmt.Errorf("input path %q does not exist", path)
			}
			return fmt.Errorf("cannot access input path %q: %w", path, err)
		}
		result.selections = append(result.selections, path)
		if info.IsDir() {
			result.onlyFolders = append(result.onlyFolders, path)
			return filepath.Walk(path, func(walkPath string, walkInfo os.FileInfo, walkErr error) error {
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
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return encryptInputs{}, fmt.Errorf("invalid glob pattern %q: %w", pattern, err)
		}
		if len(matches) == 0 {
			return encryptInputs{}, fmt.Errorf("glob %q matched no paths", pattern)
		}
		for _, match := range matches {
			if err := addSelection(match); err != nil {
				return encryptInputs{}, err
			}
		}
	}
	if len(result.inputFiles) == 0 {
		return encryptInputs{}, errors.New("no regular files found to encrypt")
	}
	return result, nil
}

func validateEncryptOutputPaths(inputs encryptInputs, keyfiles []string, output string, payloadZip, deniability, split bool) error {
	reserved := []string{output, output + ".incomplete"}
	if payloadZip {
		reserved = append(reserved, strings.TrimSuffix(output, ".pcv")+".tmp")
	}
	if deniability {
		reserved = append(reserved, output+".tmp")
	}
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
			if artifact, ok := splitOutputArtifact(path, output); ok {
				return fmt.Errorf("protected source %q conflicts with output artifact %q", path, artifact)
			}
		}
	}
	if split {
		existing, err := existingSplitOutputArtifacts(output)
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
	firstAbs, err := absoluteCleanPath(first)
	if err != nil {
		return false, fmt.Errorf("resolve protected path %q: %w", first, err)
	}
	secondAbs, err := absoluteCleanPath(second)
	if err != nil {
		return false, fmt.Errorf("resolve output artifact path %q: %w", second, err)
	}
	if firstAbs == secondAbs {
		return true, nil
	}
	firstInfo, firstErr := os.Stat(first)
	secondInfo, secondErr := os.Stat(second)
	if firstErr != nil {
		if errors.Is(firstErr, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("inspect protected path %q: %w", first, firstErr)
	}
	if secondErr != nil {
		if errors.Is(secondErr, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("inspect output artifact %q: %w", second, secondErr)
	}
	return os.SameFile(firstInfo, secondInfo), nil
}

func splitOutputArtifact(path, output string) (string, bool) {
	pathAbs, err := absoluteCleanPath(path)
	if err != nil {
		return "", false
	}
	outputAbs, err := absoluteCleanPath(output)
	if err != nil {
		return "", false
	}
	prefix := outputAbs + "."
	if !strings.HasPrefix(pathAbs, prefix) {
		return "", false
	}
	suffix := strings.TrimPrefix(pathAbs, prefix)
	suffix = strings.TrimSuffix(suffix, ".incomplete")
	if suffix == "" {
		return "", false
	}
	for i := range suffix {
		if suffix[i] < '0' || suffix[i] > '9' {
			return "", false
		}
	}
	return path, true
}

func existingSplitOutputArtifacts(output string) ([]string, error) {
	outputAbs, err := absoluteCleanPath(output)
	if err != nil {
		return nil, fmt.Errorf("resolve output path %q: %w", output, err)
	}
	outputDir := filepath.Dir(outputAbs)
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		return nil, fmt.Errorf("inspect output directory %q: %w", outputDir, err)
	}

	artifacts := make([]string, 0)
	for _, entry := range entries {
		candidate := filepath.Join(outputDir, entry.Name())
		if _, ok := splitOutputArtifact(candidate, outputAbs); ok {
			artifacts = append(artifacts, candidate)
		}
	}
	return artifacts, nil
}
