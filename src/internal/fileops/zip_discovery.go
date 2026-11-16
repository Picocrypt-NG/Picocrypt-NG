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
func readZIPDirectoryNames(ctx context.Context, path string, budget *ZIPResourceBudget) ([]string, uint64, error) {
	directory, err := captureZIPDirectory(path)
	if err != nil {
		return nil, 0, err
	}
	return readZIPDirectoryNamesFrom(ctx, directory, budget)
}

func readZIPDirectoryNamesFrom(ctx context.Context, authority *zipDirectoryIdentity, budget *ZIPResourceBudget) (names []string, charged uint64, err error) {
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
	root, err := authority.open()
	if err != nil {
		return nil, 0, err
	}
	directory, err := root.Open(".")
	err = errors.Join(err, root.Close())
	if err != nil {
		if directory != nil {
			err = errors.Join(err, directory.Close())
		}
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
	return WalkZIPInputCandidates(ctx, root, budget, func(candidate ZIPInputCandidate, err error) error {
		return visit(candidate.Path, candidate.Info, err)
	})
}

// WalkZIPInputCandidates preserves WalkZIPInputs ordering and callback rules,
// and carries the original directory identities into Capture. Callers reserve
// retained candidates/identities before retaining them, as with WalkZIPInputs.
func WalkZIPInputCandidates(ctx context.Context, root string, budget *ZIPResourceBudget, visit func(ZIPInputCandidate, error) error) error {
	return walkZIPInputCandidates(ctx, root, nil, budget, visit)
}

// Walk retains an already discovered directory's identity, including a glob
// match, rather than reselecting its mutable pathname as a new root.
func (candidate ZIPInputCandidate) Walk(ctx context.Context, budget *ZIPResourceBudget, visit func(ZIPInputCandidate, error) error) error {
	return walkZIPInputCandidates(ctx, candidate.Path, &candidate, budget, visit)
}

func walkZIPInputCandidates(ctx context.Context, root string, initial *ZIPInputCandidate, budget *ZIPResourceBudget, visit func(ZIPInputCandidate, error) error) error {
	if budget == nil {
		budget = NewZIPResourceBudget()
	}
	var walk func(string, *zipDirectoryIdentity) error
	walk = func(path string, parent *zipDirectoryIdentity) error {
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
		var candidate ZIPInputCandidate
		if parent == nil {
			if initial != nil {
				candidate = *initial
			} else {
				candidate, err = InspectZIPInput(path)
			}
		} else {
			candidate, err = parent.candidate(path, filepath.Base(path))
		}
		if err != nil {
			return visit(ZIPInputCandidate{Path: path}, err)
		}
		if candidate.Info == nil {
			return visit(candidate, errors.New("archive input identity is unavailable"))
		}
		if !candidate.Info.IsDir() {
			if err := visit(candidate, nil); err != nil {
				return err
			}
			return ctx.Err()
		}
		directory, err := candidate.directory()
		if err != nil {
			return err
		}
		names, charged, readErr := readZIPDirectoryNamesFrom(ctx, directory, budget)
		defer budget.Release(charged)
		if err := ctx.Err(); err != nil {
			return err
		}
		if errors.Is(readErr, ErrZIPMetadataLimit) {
			return readErr
		}
		if err := visit(candidate, readErr); err != nil || readErr != nil {
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
				return walk(filepath.Join(path, name), directory)
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
	err := walk(root, nil)
	if err == filepath.SkipDir || err == filepath.SkipAll { //nolint:errorlint // Preserve filepath.Walk exact sentinel semantics; wrapped errors stay terminal.
		return nil
	}
	return err
}

func zipNativeLookupPath(path string) string {
	if runtime.GOOS != "windows" {
		return path
	}
	// Win32 normalizes ordinary DOS/UNC paths before resolving links. Keep
	// verbatim/device namespaces untouched, since they disable that parsing.
	if len(path) >= 4 && os.IsPathSeparator(path[0]) && os.IsPathSeparator(path[3]) &&
		((os.IsPathSeparator(path[1]) && (path[2] == '?' || path[2] == '.')) || (path[1] == '?' && path[2] == '?')) {
		return path
	}
	return filepath.Clean(path)
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
	return GlobZIPInputCandidates(ctx, pattern, budget, func(candidate ZIPInputCandidate) error { return visit(candidate.Path) })
}

// GlobZIPInputCandidates retains directory authority across pattern expansion
// and selection. Capture or Walk a matched candidate instead of recapturing its
// pathname. Access errors are ignored as in filepath.Glob.
func GlobZIPInputCandidates(ctx context.Context, pattern string, budget *ZIPResourceBudget, visit func(ZIPInputCandidate) error) error {
	if budget == nil {
		budget = NewZIPResourceBudget()
	}
	var metadata ZIPInputMetadataReservation
	if err := metadata.bind(budget); err != nil {
		return err
	}
	defer metadata.Release()
	if _, err := filepath.Match(pattern, ""); err != nil {
		return err
	}
	var glob func(string, int, func(ZIPInputCandidate) error) error
	glob = func(pattern string, depth int, emit func(ZIPInputCandidate) error) error {
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
			candidate, err := metadata.Inspect(budget, pattern)
			if err != nil {
				if errors.Is(err, ErrZIPMetadataLimit) {
					return err
				}
				return nil
			}
			if err := emit(candidate); err != nil {
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
		matchDirectory := func(candidate ZIPInputCandidate) error {
			directory := candidate.Path
			resolved, err := candidate.resolveWithMetadata(255, &metadata)
			if errors.Is(err, ErrZIPMetadataLimit) {
				return err
			}
			if err != nil || !resolved.Info.IsDir() {
				return nil
			}
			authority, err := resolved.directory()
			if err != nil {
				return nil
			}
			names, charged, err := readZIPDirectoryNamesFrom(ctx, authority, budget)
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
					candidate, err := authority.candidate(filepath.Join(directory, name), name)
					if err != nil {
						return err
					}
					return emit(candidate)
				}()
				if err != nil {
					return err
				}
			}
			return ctx.Err()
		}
		if !hasZIPGlobMeta(dir[volumeLen:]) {
			candidate, err := metadata.Inspect(budget, dir)
			if err != nil {
				if errors.Is(err, ErrZIPMetadataLimit) {
					return err
				}
				return nil
			}
			return matchDirectory(candidate)
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
