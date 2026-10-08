package pcv3

import (
	"Picocrypt-NG/internal/fileops"
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

func TestArchiveSAFMetadataBudgetRefusesBeforeSessionAndCleansStage(t *testing.T) {
	// 1024 empty directories with maximum ZIP comments: about 64 MiB, no
	// decompression, KDF, or provider calls. The previous manifest admitted it.
	archive := buildArchiveSAFZIP(t, []archiveSAFZIPEntry{{name: "empty/", directory: true}})
	end := len(archive) - 22
	start := int(binary.LittleEndian.Uint32(archive[end+16:]))
	header := append([]byte(nil), archive[start:end]...)
	binary.LittleEndian.PutUint16(header[32:], 65_535)
	comment := make([]byte, 65_535)
	var data bytes.Buffer
	data.Grow(start + 1024*(len(header)+len(comment)) + 22)
	data.Write(archive[:start])
	for index := range 1024 {
		copy(header[46:], fmt.Sprintf("%05d/", index))
		data.Write(header)
		data.Write(comment)
	}
	footer := append([]byte(nil), archive[end:]...)
	binary.LittleEndian.PutUint16(footer[8:], 1024)
	binary.LittleEndian.PutUint16(footer[10:], 1024)
	binary.LittleEndian.PutUint32(footer[12:], uint32(data.Len()-start))
	data.Write(footer)
	handoff, parent, target := newArchiveSAFHandoffFromZIP(t, data.Bytes(), true)
	begin := handoff.BeginSAF()
	if begin.Kind() != NativeArchiveSAFBeginTerminal || begin.Session() != nil || begin.Result() == nil ||
		begin.Result().State() != fileops.UnpackStateNotPublished || begin.Result().AttemptedEver() || begin.Result().CleanupIncomplete() {
		t.Fatalf("oversized metadata granted provider authority or lost cleanup: %#v", begin)
	}
	classification, ok := any(begin.Result()).(interface{ ResourceLimited() bool })
	if !ok || !classification.ResourceLimited() {
		t.Fatal("metadata refusal lost resource-limit classification")
	}
	assertNativeArchiveStage(t, parent, target, 0)
}
