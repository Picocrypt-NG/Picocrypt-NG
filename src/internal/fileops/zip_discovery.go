package fileops

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

// ReserveZIPInputPath admits a retained selection before path normalization,
// map insertion or slice growth. The allowance includes string backing storage,
// deduplication keys and concurrent frontend/operation snapshots with allocator
// growth overlap. It is a conservative byte model, not a process RSS limit.
func ReserveZIPInputPath(budget *ZIPResourceBudget, pathBytes int) (uint64, error) {
	cost, ok := zipResourceMultiply(uint64(pathBytes), 8)
	if !ok {
		return 0, ErrZIPMetadataLimit
	}
	cost, ok = zipResourceAdd(cost, 1024)
	if !ok {
		return 0, ErrZIPMetadataLimit
	}
	if err := budget.Reserve(cost); err != nil {
		return 0, err
	}
	return cost, nil
}

func zipDiscoveryBytes(base, multiplier uint64, lengths ...int) (uint64, error) {
	var length uint64
	for _, part := range lengths {
		if part < 0 {
			return 0, ErrZIPMetadataLimit
		}
		var ok bool
		length, ok = zipResourceAdd(length, uint64(part))
		if !ok {
			return 0, ErrZIPMetadataLimit
		}
	}
	cost, ok := zipResourceMultiply(length, multiplier)
	if !ok {
		return 0, ErrZIPMetadataLimit
	}
	cost, ok = zipResourceAdd(base, cost)
	if !ok {
		return 0, ErrZIPMetadataLimit
	}
	return cost, nil
}

// readZIPDirectoryNames bounds directory collection before lexical sorting.
// ReadDir(-1), filepath.Walk and filepath.Glob accumulate the whole directory
// before their caller has an opportunity to refuse it. Only one name is read per batch, so an unusual filesystem
// cannot multiply long transient components before admission. Close before descending so depth does not retain file descriptors.
func readZIPDirectoryNames(ctx context.Context, path string, budget *ZIPResourceBudget) (names []string, charged uint64, err error) {
	const readWorkspace = 128 << 10
	if err = ctx.Err(); err != nil {
		return nil, 0, err
	}
	if err = budget.Reserve(readWorkspace); err != nil {
		return nil, 0, err
	}
	defer budget.Release(readWorkspace)
	defer func() {
		if err != nil {
			budget.Release(charged)
			names = nil
			charged = 0
		}
	}()
	directory, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer func() { err = errors.Join(err, directory.Close()) }()
	for {
		if err = ctx.Err(); err != nil {
			return nil, charged, err
		}
		batch, readErr := directory.Readdirnames(1)
		for _, name := range batch {
			cost, costErr := zipDiscoveryBytes(96, 4, len(name))
			if costErr != nil {
				return nil, charged, costErr
			}
			if err = budget.Reserve(cost); err != nil {
				return nil, charged, err
			}
			charged += cost
			names = append(names, name)
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				return nil, charged, readErr
			}
			break
		}
	}
	if err = ctx.Err(); err != nil {
		return nil, charged, err
	}
	slices.Sort(names)
	return names, charged, nil
}

// WalkZIPInputs visits native input paths in filepath.Walk lexical order, with
// the same Lstat/no-follow and callback error/SkipDir behavior. The caller shares
// one budget across all roots and reserves any retained callback result.
func WalkZIPInputs(ctx context.Context, root string, budget *ZIPResourceBudget, visit filepath.WalkFunc) error {
	if budget == nil {
		budget = NewZIPResourceBudget()
	}
	var walk func(string) error
	walk = func(path string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		cost, err := zipDiscoveryBytes(512, 4, len(path))
		if err != nil {
			return err
		}
		if err := budget.Reserve(cost); err != nil {
			return err
		}
		defer budget.Release(cost)
		info, err := os.Lstat(path)
		if err != nil {
			return visit(path, nil, err)
		}
		if !info.IsDir() {
			if err := visit(path, info, nil); err != nil {
				return err
			}
			return ctx.Err()
		}
		names, charged, readErr := readZIPDirectoryNames(ctx, path, budget)
		defer budget.Release(charged)
		if err := ctx.Err(); err != nil {
			return err
		}
		if errors.Is(readErr, ErrZIPMetadataLimit) {
			return readErr
		}
		if err := visit(path, info, readErr); err != nil || readErr != nil {
			if err == filepath.SkipDir { //nolint:errorlint // filepath.Walk consumes only bare SkipDir; wrapped callback errors stay terminal.
				return nil
			}
			return err
		}
		for _, name := range names {
			if err := ctx.Err(); err != nil {
				return err
			}
			childCost, err := zipDiscoveryBytes(66, 2, len(path), len(name))
			if err != nil {
				return err
			}
			if err := budget.Reserve(childCost); err != nil {
				return err
			}
			err = func() error {
				defer budget.Release(childCost)
				return walk(filepath.Join(path, name))
			}()
			if err != nil {
				if err == filepath.SkipDir { //nolint:errorlint // filepath.Walk consumes only bare SkipDir; wrapped callback errors stay terminal.
					return nil
				}
				return err
			}
		}
		return ctx.Err()
	}
	err := walk(root)
	if err == filepath.SkipDir || err == filepath.SkipAll { //nolint:errorlint // Preserve filepath.Walk exact sentinel semantics; wrapped errors stay terminal.
		return nil
	}
	return err
}

func hasZIPGlobMeta(path string) bool {
	meta := `*?[\`
	if runtime.GOOS == "windows" {
		meta = `*?[`
	}
	return strings.ContainsAny(path, meta)
}

// GlobZIPInputs streams filepath.Glob-compatible lexical matches without first
// collecting an unbounded directory or full match list. Filesystem access errors
// are ignored as in filepath.Glob; cancellation/resource refusal are terminal.
func GlobZIPInputs(ctx context.Context, pattern string, budget *ZIPResourceBudget, visit func(string) error) error {
	if budget == nil {
		budget = NewZIPResourceBudget()
	}
	if _, err := filepath.Match(pattern, ""); err != nil {
		return err
	}
	var glob func(string, int, func(string) error) error
	glob = func(pattern string, depth int, emit func(string) error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if depth == 10000 {
			return filepath.ErrBadPattern
		}
		cost, err := zipDiscoveryBytes(512, 4, len(pattern))
		if err != nil {
			return err
		}
		if err := budget.Reserve(cost); err != nil {
			return err
		}
		defer budget.Release(cost)
		if !hasZIPGlobMeta(pattern) {
			if _, err := os.Lstat(pattern); err != nil {
				return nil
			}
			if err := emit(pattern); err != nil {
				return err
			}
			return ctx.Err()
		}
		dir, file := filepath.Split(pattern)
		volumeLen := 0
		if runtime.GOOS == "windows" {
			volumeLen = len(filepath.VolumeName(dir))
			switch {
			case dir == "":
				dir = "."
			case volumeLen+1 == len(dir) && os.IsPathSeparator(dir[len(dir)-1]):
				volumeLen++
			case volumeLen == len(dir) && len(dir) == 2:
				dir += "."
			default:
				if volumeLen >= len(dir) {
					volumeLen = len(dir) - 1
				}
				dir = dir[:len(dir)-1]
			}
		} else if dir == "" {
			dir = "."
		} else if dir != string(filepath.Separator) {
			// Like filepath.Glob, remove only the trailing separator: cleaning
			// here would bypass missing components and change symlink/.. lookup.
			dir = dir[:len(dir)-1]
		}
		matchDirectory := func(directory string) error {
			info, err := os.Stat(directory)
			if err != nil || !info.IsDir() {
				return nil
			}
			names, charged, err := readZIPDirectoryNames(ctx, directory, budget)
			defer budget.Release(charged)
			if err != nil {
				if errors.Is(err, ErrZIPMetadataLimit) || ctx.Err() != nil {
					return err
				}
				return nil
			}
			for _, name := range names {
				if err := ctx.Err(); err != nil {
					return err
				}
				matched, err := filepath.Match(file, name)
				if err != nil {
					return err
				}
				if !matched {
					continue
				}
				pathCost, err := zipDiscoveryBytes(66, 2, len(directory), len(name))
				if err != nil {
					return err
				}
				if err := budget.Reserve(pathCost); err != nil {
					return err
				}
				err = func() error {
					defer budget.Release(pathCost)
					return emit(filepath.Join(directory, name))
				}()
				if err != nil {
					return err
				}
			}
			return ctx.Err()
		}
		if !hasZIPGlobMeta(dir[volumeLen:]) {
			return matchDirectory(dir)
		}
		if dir == pattern {
			return filepath.ErrBadPattern
		}
		return glob(dir, depth+1, matchDirectory)
	}
	return glob(pattern, 0, visit)
}

// VisitZIPDirectoryNames visits one admitted directory in lexical order. Names
// are borrowed during the callback; retained paths must be reserved separately.
func VisitZIPDirectoryNames(ctx context.Context, directory string, budget *ZIPResourceBudget, visit func(string) error) error {
	if budget == nil {
		budget = NewZIPResourceBudget()
	}
	names, charged, err := readZIPDirectoryNames(ctx, directory, budget)
	defer budget.Release(charged)
	if err != nil {
		return err
	}
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := visit(name); err != nil {
			return err
		}
	}
	return ctx.Err()
}
