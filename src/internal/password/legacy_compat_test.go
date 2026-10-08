package password

import (
	"bytes"
	"testing"
)

func TestCandidatesRetainHistoricalUnicode15NFCWithoutChangingNewEncryption(t *testing.T) {
	// x/text v0.41.0 under Go 1.26.6 normalized U+10041 U+0300 to
	// U+00C0 because the old recomposition map truncated scalar operands.
	// These literal bytes are frozen from that historical implementation.
	input := []byte{0xf0, 0x90, 0x81, 0x81, 0xcc, 0x80}
	original := append([]byte(nil), input...)
	want := [][]byte{original, {0xc3, 0x80}}
	got := Candidates(input)
	if len(got) != len(want) {
		t.Fatalf("historical password candidates = %x; want modern raw then frozen historical NFC %x", got, want)
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("candidate %d = %x; want %x", i, got[i], want[i])
		}
	}
	if encoded := EncodeForKDF(input); !bytes.Equal(encoded, original) {
		t.Fatalf("new encryption used historical normalization: %x; want %x", encoded, original)
	}
	clear(got[0])
	if !bytes.Equal(got[1], want[1]) || !bytes.Equal(input, original) {
		t.Fatal("clearing modern candidate changed historical candidate or caller input")
	}
	clear(got[1])
	if !bytes.Equal(input, original) {
		t.Fatal("historical candidate aliases caller input")
	}
}
