package volume

import (
	"Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/header"
	"Picocrypt-NG/internal/util"
	"errors"
	"math"
)

var errLegacyPreparedLength = errors.New("invalid legacy ciphertext length")

// legacyPreparedCiphertextLength follows the existing writer's one-MiB
// payload framing. A nonempty partial RS block always has a padding chunk,
// including when its data length is already a multiple of 128 bytes.
// This calculates the final extent, not the simultaneous temporary disk cost.
func legacyPreparedCiphertextLength(req *EncryptRequest, plain uint64) (uint64, error) {
	if req == nil || req.PCV3 || len(req.Comments) > header.MaxCommentLen || plain > math.MaxInt64 {
		return 0, errLegacyPreparedLength
	}
	prefix := uint64(header.HeaderSize(len(req.Comments))) //nolint:gosec // The checked comment length bounds HeaderSize to [789, 300786].
	if req.Deniability {
		prefix += header.SaltSize + header.NonceSize
	}
	available := uint64(math.MaxInt64) - prefix
	payload := plain
	if req.ReedSolomon {
		full := plain / util.MiB
		partial := plain % util.MiB
		if full > available/encoding.RSEncodedBlockSize {
			return 0, errLegacyPreparedLength
		}
		payload = full * encoding.RSEncodedBlockSize
		if partial != 0 {
			tail := (partial/encoding.RS128DataSize + 1) * encoding.RS128EncodedSize
			if tail > available-payload {
				return 0, errLegacyPreparedLength
			}
			payload += tail
		}
	}
	if payload > available {
		return 0, errLegacyPreparedLength
	}
	return prefix + payload, nil
}
