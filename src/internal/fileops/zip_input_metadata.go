package fileops

import (
	"os"
	"strings"
)

// ZIPInputMetadataReservation accounts distinct directory snapshots retained by
// one selection or writer. Its zero value is ready to use. Release after the
// last selection callback or writer returns; the next owner recounts its inputs.
type ZIPInputMetadataReservation struct {
	budget      *ZIPResourceBudget
	directories map[*zipDirectoryIdentity]struct{}
	charged     uint64
}

func (reservation *ZIPInputMetadataReservation) bind(budget *ZIPResourceBudget) error {
	if budget == nil || (reservation.budget != nil && reservation.budget != budget) {
		return ErrZIPMetadataLimit
	}
	reservation.budget = budget
	return nil
}

// Directory bytes include node/FileInfo allocation and allocator overlap. Map
// bytes cover the entry, bucket growth overlap and first allocation separately.
func (reservation *ZIPInputMetadataReservation) admit(name string) error {
	cost, err := zipDiscoveryBytes(512+128, 2, len(name))
	if err != nil {
		return err
	}
	if reservation.directories == nil {
		var ok bool
		cost, ok = zipResourceAdd(cost, 256)
		if !ok {
			return ErrZIPMetadataLimit
		}
	}
	if err := reservation.budget.Reserve(cost); err != nil {
		return err
	}
	reservation.charged += cost
	if reservation.directories == nil {
		reservation.directories = make(map[*zipDirectoryIdentity]struct{})
	}
	return nil
}

func (reservation *ZIPInputMetadataReservation) retain(directory *zipDirectoryIdentity) error {
	for directory != nil {
		if _, exists := reservation.directories[directory]; exists {
			return nil
		}
		if err := reservation.admit(directory.name); err != nil {
			return err
		}
		reservation.directories[directory] = struct{}{}
		directory = directory.parent
	}
	return nil
}

func (reservation *ZIPInputMetadataReservation) directory(parent *zipDirectoryIdentity, name string, info os.FileInfo) (*zipDirectoryIdentity, error) {
	if err := reservation.retain(parent); err != nil {
		return nil, err
	}
	if err := reservation.admit(name); err != nil {
		return nil, err
	}
	directory := &zipDirectoryIdentity{parent: parent, name: strings.Clone(name), info: info}
	reservation.directories[directory] = struct{}{}
	return directory, nil
}

// RetainCandidate admits its actual ancestors before a caller retains a root
// across a worker handoff. Shared nodes are counted once by pointer identity.
func (reservation *ZIPInputMetadataReservation) RetainCandidate(budget *ZIPResourceBudget, candidate ZIPInputCandidate) error {
	if err := reservation.bind(budget); err != nil {
		return err
	}
	return reservation.retain(candidate.parent)
}

// Inspect admits an explicit root before retaining its metadata. A permission
// exception for a named file is marked only during this initial capture.
func (reservation *ZIPInputMetadataReservation) Inspect(budget *ZIPResourceBudget, path string) (ZIPInputCandidate, error) {
	if err := reservation.bind(budget); err != nil {
		return ZIPInputCandidate{}, err
	}
	return inspectExplicitZIPInput(path, reservation)
}

// Capture accounts retained ancestors and admits any new symlink-resolution
// directory node before allocating it. The caller separately reserves paths.
func (reservation *ZIPInputMetadataReservation) Capture(budget *ZIPResourceBudget, candidate ZIPInputCandidate, followSymlinks bool) (ZIPInputIdentity, error) {
	if err := reservation.RetainCandidate(budget, candidate); err != nil {
		return ZIPInputIdentity{}, err
	}
	return candidate.capture(followSymlinks, reservation)
}

// FromFileInfo preserves the caller's original metadata, including a borrowed
// descriptor's identity, while admitting its parent and normalized read path.
func (reservation *ZIPInputMetadataReservation) FromFileInfo(budget *ZIPResourceBudget, path string, info os.FileInfo) (ZIPInputIdentity, error) {
	if err := reservation.bind(budget); err != nil {
		return ZIPInputIdentity{}, err
	}
	return zipInputFromFileInfo(path, info, reservation)
}

// CaptureInputs retains supplied snapshots, or captures missing explicit inputs
// under this owner's graph and canonical-path admission.
func (reservation *ZIPInputMetadataReservation) CaptureInputs(budget *ZIPResourceBudget, paths []string, identities []ZIPInputIdentity) ([]ZIPInputIdentity, error) {
	return reservation.captureInputs(budget, paths, identities, false)
}

func (reservation *ZIPInputMetadataReservation) admitReadPath(selectedPath string, length uint64) error {
	// The caller's original path allowance already covers this many bytes.
	// Canonical expansion needs its own backing storage and growth allowance.
	if length <= uint64(len(selectedPath)) {
		return nil
	}
	cost, ok := zipResourceMultiply(length-uint64(len(selectedPath)), 2)
	if !ok {
		return ErrZIPMetadataLimit
	}
	if err := reservation.budget.Reserve(cost); err != nil {
		return err
	}
	reservation.charged += cost
	return nil
}

func (reservation *ZIPInputMetadataReservation) captureInputs(budget *ZIPResourceBudget, paths []string, identities []ZIPInputIdentity, providedPathsAdmitted bool) ([]ZIPInputIdentity, error) {
	if err := reservation.bind(budget); err != nil {
		return nil, err
	}
	if identities != nil {
		identities, err := CaptureZIPInputs(paths, identities)
		if err != nil {
			return nil, err
		}
		for _, input := range identities {
			if err := reservation.retain(input.parent); err != nil {
				return nil, err
			}
			if !providedPathsAdmitted {
				if err := reservation.admitReadPath(input.selectedPath, uint64(len(input.readPath))); err != nil {
					return nil, err
				}
			}
		}
		return identities, nil
	}
	identities = make([]ZIPInputIdentity, 0, len(paths))
	for _, path := range paths {
		candidate, err := inspectExplicitZIPInput(path, reservation)
		if err != nil {
			return nil, err
		}
		identity, err := candidate.capture(false, reservation)
		if err != nil {
			return nil, err
		}
		identities = append(identities, identity)
	}
	return identities, nil
}

// Release retires this owner's graph and memoization charge, including partial
// admission after failure. It does not invalidate immutable input snapshots.
func (reservation *ZIPInputMetadataReservation) Release() bool {
	ok := true
	if reservation.budget != nil {
		ok = reservation.budget.Release(reservation.charged)
	}
	*reservation = ZIPInputMetadataReservation{}
	return ok
}
