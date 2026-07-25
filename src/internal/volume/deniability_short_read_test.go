package volume

import (
	"Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/util"
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// deniabilityShortReadSeam installs newDeniabilityReader to wrap the payload
// reader in a shortReader, and returns a restore func. max is deliberately
// smaller than the 1 MiB block so reads never align to block boundaries,
// forcing the io.ReadFull loops to reassemble full blocks. Mirrors
// shortReadSeam (which targets the main-payload newPayloadReader seam).
func deniabilityShortReadSeam(max int) func() {
	prev := newDeniabilityReader
	newDeniabilityReader = func(r io.Reader) io.Reader {
		return &shortReader{r: r, max: max}
	}
	return func() { newDeniabilityReader = prev }
}

// TestDeniabilityAddShortReadsByteIdentical isolates the AddDeniability encrypt
// loop. The deniability layer is a pure XChaCha20 keystream over the whole
// volume, so the only chunk-sensitive behaviour is the rekey boundary. Adding
// deniability to the same input twice — once with full reads, once under a
// short-read seam — must yield byte-identical output. With the old
// `counter += int64(n)` + bare Read, a short read advances the rekey offset
// early, so the two outputs diverge after the first rekey crossing.
func TestDeniabilityAddShortReadsByteIdentical(t *testing.T) {
	tmp := t.TempDir()

	// Lower the rekey threshold so a small synthetic volume crosses it.
	prevThreshold := crypto.RekeyThreshold
	crypto.RekeyThreshold = 4 * int64(util.MiB)
	defer func() { crypto.RekeyThreshold = prevThreshold }()

	// 8 MiB > 4 MiB threshold (and > 4 MiB + one short-read's worth of slack),
	// guaranteeing data past the rekey boundary where a desync would show.
	payload := randomPlaintext(t, 8*1024*1024)

	// Pin salt+nonce: AddDeniability draws them via crypto.RandomBytes(rand.Reader),
	// so reseeding rand.Reader before each call gives both runs an identical
	// header. That leaves the rekey offset as the only thing that can differ.
	prevRand := rand.Reader
	defer func() { rand.Reader = prevRand }()

	add := func(name string) []byte {
		path := filepath.Join(tmp, name)
		if err := os.WriteFile(path, payload, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		rand.Reader = newDeterministicReader()
		if err := AddDeniability(path, []byte("deniability-short-read"), nil); err != nil {
			t.Fatalf("AddDeniability(%s): %v", name, err)
		}
		out, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		return out
	}

	full := add("full.bin") // identity seam (full reads)

	restore := deniabilityShortReadSeam(shortReadMax)
	defer restore()
	short := add("short.bin") // short reads

	if !bytes.Equal(full, short) {
		t.Fatalf("deniability rekey offset is not chunk-independent: full-read and short-read output differ (len full=%d short=%d)", len(full), len(short))
	}
}

// TestDeniabilityRemoveShortReadsRoundTrip isolates the RemoveDeniability
// decrypt loop. A deniable volume written with full reads must decrypt cleanly
// under a short-read seam and recover the inner .pcv byte-for-byte. With the
// old bare Read + `counter += int64(n)`, the short-read decrypt rekeys at a
// different offset than encrypt did, corrupting the inner volume past the rekey
// boundary so RemoveDeniability's validity check fails outright.
func TestDeniabilityRemoveShortReadsRoundTrip(t *testing.T) {
	rs := newRSCodecsT(t)
	tmp := t.TempDir()

	prevThreshold := crypto.RekeyThreshold
	crypto.RekeyThreshold = 4 * int64(util.MiB)
	defer func() { crypto.RekeyThreshold = prevThreshold }()

	// Build a real inner volume: RemoveDeniability verifies the decrypted output
	// is a valid volume, so a corrupt rekey would surface as a failed check.
	plaintext := randomPlaintext(t, 8*1024*1024) // inner .pcv ends up > 4 MiB threshold
	inputPath := filepath.Join(tmp, "in.bin")
	if err := os.WriteFile(inputPath, plaintext, 0o600); err != nil {
		t.Fatalf("write input: %v", err)
	}
	volPath := filepath.Join(tmp, "in.bin.pcv")
	encReq := &EncryptRequest{
		InputFile:   inputPath,
		OutputFile:  volPath,
		Password:    []byte("deniability-roundtrip"),
		ReedSolomon: false,
		Reporter:    &GoldenTestReporter{},
		RSCodecs:    rs,
	}
	if err := Encrypt(context.Background(), encReq); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Snapshot the inner .pcv before deniability wraps it in place.
	innerVolume, err := os.ReadFile(volPath)
	if err != nil {
		t.Fatalf("read inner volume: %v", err)
	}

	// Add deniability with full reads (the known-good encrypt path).
	if err := AddDeniability(volPath, []byte("deniability-roundtrip"), nil); err != nil {
		t.Fatalf("AddDeniability: %v", err)
	}

	// Remove deniability under a short-read seam.
	restore := deniabilityShortReadSeam(shortReadMax)
	defer restore()
	outStage, err := RemoveDeniability(volPath, []byte("deniability-roundtrip"), nil, rs)
	if err != nil {
		t.Fatalf("RemoveDeniability under short-read seam: %v", err)
	}
	defer outStage.Cleanup()

	recovered, err := os.ReadFile(outStage.Path())
	if err != nil {
		t.Fatalf("read recovered volume: %v", err)
	}
	if !bytes.Equal(recovered, innerVolume) {
		t.Fatalf("short-read decrypt did not recover the inner volume (len recovered=%d want=%d)", len(recovered), len(innerVolume))
	}
}
