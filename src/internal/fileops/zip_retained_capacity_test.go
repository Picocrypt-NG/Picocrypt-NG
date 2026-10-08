package fileops

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"testing"
)

// A valid reader may retain the declared directory capacity even if its
// actual entry count only matches modulo 65536. That backing is still live.
func TestZIPReaderRetainsChargeForDeclaredDirectoryCapacity(t *testing.T) {
	classic := independentStoredZIP(t, 1, 0)
	end := len(classic) - 22
	start := int(binary.LittleEndian.Uint32(classic[end+16:]))
	const declared = 7*65536 + 1
	const padding = declared * 30
	padded := make([]byte, 0, len(classic)+padding)
	padded = append(padded, classic[:start]...)
	padded = append(padded, make([]byte, padding)...)
	padded = append(padded, classic[start:]...)
	binary.LittleEndian.PutUint32(padded[len(padded)-22+16:], uint32(start+padding))
	data := zip64FromClassic(t, padded, declared)
	budget := NewZIPResourceBudget()
	reader, err := OpenZIPReader(bytes.NewReader(data), int64(len(data)), ZIPReadOptions{Budget: budget})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	backingBytes := uint64(cap(reader.File)) * uint64(strconv.IntSize/8)
	t.Logf("actual=%d capacity=%d backingBytes=%d retainedCharge=%d peak=%d", len(reader.File), cap(reader.File), backingBytes, budget.CurrentBytes(), budget.PeakBytes())
	if budget.CurrentBytes() < backingBytes {
		t.Fatalf("retained charge does not even cover still-live File pointer backing")
	}
}
