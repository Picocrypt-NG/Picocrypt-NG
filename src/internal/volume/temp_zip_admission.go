package volume

import (
	"Picocrypt-NG/internal/diskspace"
	"Picocrypt-NG/internal/pcv3operation"
	"errors"
	"math"
	"path/filepath"
)

var errTemporaryZIPDiskAdmission = errors.New("insufficient space for temporary archive and final encrypted output")

// admitTemporaryZIP bounds the private spool while the complete final output
// (and, for splitting, its chunk set) coexist. Free space is an observation,
// never a reservation: subsequent write, quota and Sync errors stay authoritative.
func admitTemporaryZIP(req *EncryptRequest) (uint64, error) {
	free, e := diskspace.Available(filepath.Dir(req.OutputFile))
	if e != nil {
		return 0, e
	}
	if free <= 0 {
		return 0, errTemporaryZIPDiskAdmission
	}
	return admittedTemporaryZIPExtent(req, uint64(free))
}

func admittedTemporaryZIPExtent(req *EncryptRequest, available uint64) (uint64, error) {
	if len(req.Comments) > 99999 {
		return 0, errTemporaryZIPDiskAdmission
	}
	cost := func(plain uint64) (uint64, uint64, error) {
		records := plain / 65536
		if plain%65536 != 0 || records == 0 {
			records++
		}
		if plain > math.MaxInt64 || records > (math.MaxInt64-plain)/16 {
			return 0, 0, errTemporaryZIPDiskAdmission
		}
		physical := plain + 16*records
		var final uint64
		var e error
		if req.PCV3 {
			mode := pcv3operation.WriteModeNormal
			if req.Deniability {
				mode = pcv3operation.WriteModeD1
			}
			final, e = pcv3operation.WriteCiphertextLength(mode, plain, uint32(len(req.Comments)), req.ReedSolomon) //nolint:gosec // Comment bytes are bounded to 99999 above.
		} else {
			final, e = legacyPreparedCiphertextLength(req, plain)
		}
		if e != nil {
			return 0, 0, e
		}
		if req.Split || (!req.PCV3 && req.Deniability) {
			if final > math.MaxUint64/2 {
				return 0, 0, errTemporaryZIPDiskAdmission
			}
			final *= 2
		}
		if final > math.MaxUint64-physical {
			return 0, 0, errTemporaryZIPDiskAdmission
		}
		return physical + final, physical, nil
	}
	minimum, _, e := cost(0)
	if e != nil {
		return 0, e
	}
	if minimum > available {
		return 0, errTemporaryZIPDiskAdmission
	}
	low, high := uint64(0), min(available, uint64(math.MaxInt64))
	for low < high {
		mid := low + (high-low)/2 + 1
		used, _, e := cost(mid)
		if e == nil && used <= available {
			low = mid
		} else {
			high = mid - 1
		}
	}
	_, physical, e := cost(low)
	return physical, e
}
