package encoding

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

func TestRSDecoderUnknownErrorsPreserveSourceAndClearScratch(t *testing.T) {
	codecs := mustCodecs(t)
	// Existing frozen RS128 wire vector; neither encoding nor correction computes
	// this oracle. Data and parity damage must be corrected as unknown errors.
	frozen, err := hex.DecodeString("01080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8eff6fd040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4ebf2f900070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c737aa5d74e94add3b8cd")
	if err != nil {
		t.Fatal(err)
	}
	decoder := NewRSDecoder(codecs.RS128)
	defer decoder.Close()
	for count := range 5 {
		t.Run(fmt.Sprintf("unknown-errors-%d", count), func(t *testing.T) {
			encoded := bytes.Clone(frozen)
			for _, index := range []int{0, 135, 31, 128}[:count] {
				encoded[index] ^= 0xab
			}
			original := bytes.Clone(encoded)
			destination := make([]byte, 128)
			if err := decoder.DecodeInto(destination, encoded); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(destination, frozen[:128]) {
				t.Fatal("unknown symbol repair differs from frozen systematic bytes")
			}
			if !bytes.Equal(encoded, original) {
				t.Fatal("correction modified borrowed source")
			}
		})
	}
	scratch := decoder.codeword
	decoder.Close()
	if !bytes.Equal(scratch, make([]byte, len(scratch))) || decoder.parity[0] != 0 {
		t.Fatal("Close retained owned correction bytes")
	}
}
