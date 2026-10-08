package volume

import "Picocrypt-NG/internal/fileops"

// Admit before selectionRoots, filepath normalization, or the entry-name map
// allocate. Source lists are borrowed; both them and their derived copies stay
// charged while the writer holds its independent workspace reservation.
func reserveZIPSelection(budget *fileops.ZIPResourceBudget, req *EncryptRequest, files []string) (uint64, error) {
	charge := uint64(1 << 20)
	limit := budget.LimitBytes()
	for _, paths := range [][]string{files, req.OnlyFiles, req.OnlyFolders} {
		for _, path := range paths {
			// Covers map buckets, slice growth, normalized roots/names and transient
			// path copies conservatively without constructing any of those objects.
			if uint64(len(path)) > (limit-min(charge, limit))/8 {
				return 0, fileops.ErrZIPMetadataLimit
			}
			cost := uint64(256) + 8*uint64(len(path))
			if cost > limit-min(charge, limit) {
				return 0, fileops.ErrZIPMetadataLimit
			}
			charge += cost
		}
	}
	if e := budget.Reserve(charge); e != nil {
		return 0, e
	}
	return charge, nil
}
