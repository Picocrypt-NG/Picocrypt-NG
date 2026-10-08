package pcv3recovery

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
)

// The authenticated core seam leaves parser, resource ledger, stage and cleanup real.
func TestD1ArchivePreparationMetadataRefusalKeepsResourceStageAndNoOutput(t *testing.T) {
	data := recoveryResourceZIP64(t, recoveryArchiveBytes(t), math.MaxUint64)
	reader, err := fileops.OpenZIPReader(bytes.NewReader(data), int64(len(data)), fileops.ZIPReadOptions{})
	if reader != nil {
		reader.Close()
	}
	if !errors.Is(err, fileops.ErrZIPMetadataLimit) {
		t.Fatalf("fixture must hit parser resource refusal: %v", err)
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "plaintext.zip")
	result := runWithCoreOptions(context.Background(), &Request{Target: target, Mode: pcv3.RecoveryModeNormalV3}, recoveryArchiveCore(data, nil), ExecutionOptions{PrepareArchive: true})
	if result.Outcome() != pcv3.OutcomeOperationFailed || result.Stage() != pcv3.StageResourceBudget || result.PublicationAttempted() || result.TakeArchiveHandoff() != nil {
		t.Fatalf("metadata refusal lost resource semantics: outcome=%v stage=%v publication=%v", result.Outcome(), result.Stage(), result.PublicationAttempted())
	}
	if result.PublicationState() != 0 || result.PublicationStage() != pcv3.StageNone || result.PublicationCode() != 0 {
		t.Errorf("pre-publication resource refusal retained publication tuple: %v/%v/%v", result.PublicationState(), result.PublicationStage(), result.PublicationCode())
	}

	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("resource refusal published plaintext: %v", err)
	}
	assertNoRecoveryStageResidue(t, directory)
}

func recoveryResourceZIP64(t *testing.T, archive []byte, count uint64) []byte {
	t.Helper()
	end := len(archive) - 22
	footer := append([]byte(nil), archive[end:]...)
	var extension [76]byte
	binary.LittleEndian.PutUint32(extension[:], 0x06064b50)
	binary.LittleEndian.PutUint64(extension[4:], 44)
	binary.LittleEndian.PutUint16(extension[12:], 45)
	binary.LittleEndian.PutUint16(extension[14:], 45)
	binary.LittleEndian.PutUint64(extension[24:], count)
	binary.LittleEndian.PutUint64(extension[32:], count)
	binary.LittleEndian.PutUint64(extension[40:], uint64(binary.LittleEndian.Uint32(footer[12:])))
	binary.LittleEndian.PutUint64(extension[48:], uint64(binary.LittleEndian.Uint32(footer[16:])))
	binary.LittleEndian.PutUint32(extension[56:], 0x07064b50)
	binary.LittleEndian.PutUint64(extension[64:], uint64(end))
	binary.LittleEndian.PutUint32(extension[72:], 1)
	binary.LittleEndian.PutUint16(footer[8:], 0xffff)
	binary.LittleEndian.PutUint16(footer[10:], 0xffff)
	binary.LittleEndian.PutUint32(footer[12:], 0xffffffff)
	binary.LittleEndian.PutUint32(footer[16:], 0xffffffff)
	result := append([]byte(nil), archive[:end]...)
	result = append(result, extension[:]...)
	return append(result, footer...)
}
