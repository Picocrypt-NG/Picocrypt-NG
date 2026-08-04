package pcv3

import (
	pcv3crypto "Picocrypt-NG/internal/crypto"
	pcencoding "Picocrypt-NG/internal/encoding"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"unicode/utf8"
)

const (
	metadataMagic        = "PCVM"
	metadataSchema       = uint16(1)
	metadataUTF8Encoding = uint16(1)
)

var errInvalidMetadataRequest = errors.New("pcv3: invalid metadata request")

type metadataRecoveryState uint8

const (
	metadataRecoveryDamaged metadataRecoveryState = iota + 1
	metadataRecoveryCanonical
)

// metadataRecovery retains canonical decoded bytes only inside the package.
// No comment byte crosses the authenticated-metadata boundary through this
// intermediate value.
type metadataRecovery struct {
	state   metadataRecoveryState
	header  [16]byte
	comment []byte
	tag     [64]byte
}

func (recovery *metadataRecovery) close() {
	if recovery == nil {
		return
	}
	pcv3crypto.SecureZero(recovery.header[:])
	pcv3crypto.SecureZero(recovery.comment)
	pcv3crypto.SecureZero(recovery.tag[:])
	recovery.comment = nil
	recovery.state = 0
}

// readMetadata recovers and validates only the authenticated metadata extent.
// Raw metadata fields never select an allocation, block count, or source read.
func readMetadata(
	ctx context.Context,
	source io.ReaderAt,
	auth *normalAuthResult,
	codecs *pcencoding.RSCodecs,
) (*metadataRecovery, error) {
	if ctx == nil {
		return nil, errInvalidMetadataRequest
	}
	if err := ctx.Err(); err != nil {
		return nil, metadataOperationFailure(StageCancellation, err)
	}
	if source == nil {
		return nil, NewInputError(errInvalidReader)
	}
	if codecs == nil || codecs.RS128 == nil {
		return nil, errInvalidMetadataRequest
	}

	core, blocks, front, ok := authenticatedMetadataAuthority(auth)
	if !ok {
		return nil, errInvalidMetadataRequest
	}
	decodedLength, ok := checkedMul64(blocks, rs128DataLength)
	if !ok || decodedLength > maximumMetadataBlocks*rs128DataLength {
		return nil, errInvalidMetadataRequest
	}
	decoded := make([]byte, int(decodedLength))
	defer pcv3crypto.SecureZero(decoded)

	for block := uint64(0); block < blocks; block++ {
		delta, ok := checkedMul64(block, rs128CodewordLength)
		if !ok {
			return nil, errInvalidMetadataRequest
		}
		offset, ok := checkedAdd64(frontHeaderBase, delta)
		end, endOK := checkedAdd64(offset, rs128CodewordLength)
		if !ok || !endOK || end > uint64(front) {
			return nil, errInvalidMetadataRequest
		}

		decodedBlock, damaged, err := readMetadataBlock(
			ctx,
			source,
			int64(offset),
			codecs,
		)
		if err != nil {
			return nil, err
		}
		if damaged {
			return damagedMetadataRecovery(), nil
		}
		start := block * rs128DataLength
		copy(decoded[int(start):int(start+rs128DataLength)], decodedBlock)
		pcv3crypto.SecureZero(decodedBlock)
	}
	if err := ctx.Err(); err != nil {
		return nil, metadataOperationFailure(StageCancellation, err)
	}
	return parseCanonicalMetadata(decoded, core.commentLength), nil
}

func authenticatedMetadataAuthority(
	auth *normalAuthResult,
) (logicalCore, uint64, int64, bool) {
	if auth == nil || auth.authenticated == 0 ||
		(auth.outcome != OutcomeSuccess && auth.outcome != OutcomeAuthenticatedDegraded) {
		return logicalCore{}, 0, 0, false
	}
	core := auth.candidate.core
	if !validLogicalCore(core) {
		return logicalCore{}, 0, 0, false
	}
	blocks, expectedFront, ok := canonicalMetadataGeometry(core.commentLength)
	if !ok || blocks < minimumMetadataBlocks || blocks > maximumMetadataBlocks ||
		auth.geometry.metadataBlocks != blocks ||
		auth.geometry.frontHeaderLength < 0 ||
		uint64(auth.geometry.frontHeaderLength) != expectedFront ||
		uint64(core.frontHeaderLength) != expectedFront {
		return logicalCore{}, 0, 0, false
	}
	return core, blocks, auth.geometry.frontHeaderLength, true
}

func readMetadataBlock(
	ctx context.Context,
	source io.ReaderAt,
	offset int64,
	codecs *pcencoding.RSCodecs,
) ([]byte, bool, error) {
	var encoded [rs128CodewordLength]byte
	defer pcv3crypto.SecureZero(encoded[:])
	truncated, err := readMetadataExactAt(ctx, source, offset, encoded[:])
	if err != nil {
		return nil, false, err
	}
	if truncated {
		return nil, true, nil
	}
	decoded, err := pcencoding.Decode(codecs.RS128, encoded[:], false)
	if err != nil || len(decoded) != int(rs128DataLength) {
		pcv3crypto.SecureZero(decoded)
		return nil, true, nil
	}
	if err := ctx.Err(); err != nil {
		pcv3crypto.SecureZero(decoded)
		return nil, false, metadataOperationFailure(StageCancellation, err)
	}
	return decoded, false, nil
}

// readMetadataExactAt is local because metadata truncation is nonterminal
// damage, while readExactAt maps EOF to a pre-KDF structural failure.
func readMetadataExactAt(
	ctx context.Context,
	source io.ReaderAt,
	offset int64,
	destination []byte,
) (bool, error) {
	if ctx == nil {
		return false, errInvalidMetadataRequest
	}
	if source == nil {
		return false, NewInputError(errInvalidReader)
	}
	if offset < 0 {
		return false, errInvalidMetadataRequest
	}
	if uint64(offset) > uint64(1<<63-1)-uint64(len(destination)) {
		return false, errInvalidMetadataRequest
	}
	if len(destination) == 0 {
		return false, nil
	}

	read := 0
	consecutiveNoProgress := 0
	callLimit := len(destination) + 2
	for range callLimit {
		if err := ctx.Err(); err != nil {
			return false, metadataOperationFailure(StageCancellation, err)
		}
		count, err := source.ReadAt(destination[read:], offset+int64(read))
		if cancellation := ctx.Err(); cancellation != nil {
			return false, metadataOperationFailure(StageCancellation, cancellation)
		}
		if count < 0 || count > len(destination)-read {
			return false, NewInputError(errInvalidReadProgress)
		}
		if count > 0 {
			read += count
			consecutiveNoProgress = 0
		} else if err == nil {
			consecutiveNoProgress++
			if consecutiveNoProgress == 2 {
				return false, NewInputError(errReaderNoProgress)
			}
		}

		if read == len(destination) {
			if err == nil || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return false, nil
			}
			return false, NewInputError(err)
		}
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return true, nil
			}
			return false, NewInputError(err)
		}
	}
	return false, NewInputError(errReaderCallLimit)
}

func parseCanonicalMetadata(
	decoded []byte,
	trustedCommentLength uint32,
) *metadataRecovery {
	commentLength := int(trustedCommentLength)
	commentEnd := 16 + commentLength
	tagEnd := commentEnd + 64
	if tagEnd > len(decoded) ||
		string(decoded[0:4]) != metadataMagic ||
		binary.BigEndian.Uint16(decoded[4:6]) != metadataSchema ||
		binary.BigEndian.Uint16(decoded[6:8]) != metadataUTF8Encoding ||
		binary.BigEndian.Uint32(decoded[8:12]) != trustedCommentLength ||
		decoded[12] != 0 || decoded[13] != 0 || decoded[14] != 0 || decoded[15] != 0 ||
		!utf8.Valid(decoded[16:commentEnd]) ||
		!metadataBytesAreZero(decoded[tagEnd:]) {
		return damagedMetadataRecovery()
	}

	recovery := &metadataRecovery{
		state:   metadataRecoveryCanonical,
		comment: make([]byte, commentLength),
	}
	copy(recovery.header[:], decoded[:16])
	copy(recovery.comment, decoded[16:commentEnd])
	copy(recovery.tag[:], decoded[commentEnd:tagEnd])
	return recovery
}

func damagedMetadataRecovery() *metadataRecovery {
	return &metadataRecovery{state: metadataRecoveryDamaged}
}

func metadataBytesAreZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

func metadataOperationFailure(stage Stage, cause error) error {
	return newError(OutcomeOperationFailed, stage, cause)
}
