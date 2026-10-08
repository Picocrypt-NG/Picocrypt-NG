package pcv3crypto

import (
	"bytes"
	"fmt"
	"testing"

	"golang.org/x/crypto/chacha20"
)

func TestPCV3StandardOverlappingBuffersPreserveBytesAndBounds(t *testing.T) {
	key := mustPCV3StreamHex(t, pcv3StreamStandardXKey)
	nonce := mustPCV3StreamHex(t, pcv3StreamStandardNonce)
	for _, length := range []int{0, 1, 63, 64, 65, 127, 128, 129, 1 << 20} {
		plain := make([]byte, length)
		for i := range plain {
			plain[i] = byte(i % 251)
		}
		// The direct library invocation is an overlap/order oracle independent
		// of our wrapper; the existing frozen vectors remain the crypto oracle.
		want := make([]byte, length)
		cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
		if err != nil {
			t.Fatal(err)
		}
		cipher.XORKeyStream(want, plain)
		for _, shift := range []int{-1, 0, 1} {
			t.Run(fmt.Sprintf("length-%d-shift-%d", length, shift), func(t *testing.T) {
				for _, transform := range []func([]byte, []byte, []byte, []byte) error{PCV3WrapStandard1, PCV3UnwrapStandard1} {
					backing := bytes.Repeat([]byte{0xa5}, length+34)
					source, destination := backing[17:17+length], backing[17+shift:17+shift+length]
					copy(source, plain)
					before := append([]byte(nil), backing...)
					if err := transform(destination, source, key, nonce); err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(destination, want) || !bytes.Equal(backing[:17+shift], before[:17+shift]) || !bytes.Equal(backing[17+shift+length:], before[17+shift+length:]) {
						t.Fatal("overlap changed the transform or wrote beyond the destination")
					}
				}
			})
		}
	}
	if !bytes.Equal(key, mustPCV3StreamHex(t, pcv3StreamStandardXKey)) || !bytes.Equal(nonce, mustPCV3StreamHex(t, pcv3StreamStandardNonce)) {
		t.Fatal("transform changed independent key or nonce storage")
	}
	if err := PCV3WrapStandard1(nil, nil, key, nonce); err != nil {
		t.Fatal(err)
	}
}

func TestPCV3StandardCapturesParametersBeforeDestinationMutation(t *testing.T) {
	destination := make([]byte, 80)
	key, nonce := destination[:32], destination[32:56]
	copy(key, mustPCV3StreamHex(t, pcv3StreamStandardXKey))
	copy(nonce, mustPCV3StreamHex(t, pcv3StreamStandardNonce))
	source := bytes.Repeat([]byte{0x73}, len(destination))
	want := make([]byte, len(destination))
	cipher, err := chacha20.NewUnauthenticatedCipher(key, nonce)
	if err != nil {
		t.Fatal(err)
	}
	cipher.XORKeyStream(want, source)
	if err := PCV3WrapStandard1(destination, source, key, nonce); err != nil || !bytes.Equal(destination, want) {
		t.Fatalf("overwritten parameters changed the transform: %v", err)
	}
}

func TestPCV3StandardReusesCallerRecordBuffersWithoutAllocation(t *testing.T) {
	source, destination := make([]byte, 1<<20), make([]byte, 1<<20)
	key := mustPCV3StreamHex(t, pcv3StreamStandardXKey)
	nonce := mustPCV3StreamHex(t, pcv3StreamStandardNonce)
	allocations := testing.AllocsPerRun(8, func() {
		if err := PCV3WrapStandard1(destination, source, key, nonce); err != nil {
			t.Fatal(err)
		}
	})
	if allocations != 0 {
		t.Fatalf("record transform allocated %.0f objects despite caller-owned buffers", allocations)
	}
}

func BenchmarkPCV3StandardRecordBuffers(b *testing.B) {
	source, destination := make([]byte, 1<<20), make([]byte, 1<<20)
	var key [32]byte
	var nonce [24]byte
	b.ReportAllocs()
	b.SetBytes(int64(len(source)))
	for b.Loop() {
		if err := PCV3WrapStandard1(destination, source, key[:], nonce[:]); err != nil {
			b.Fatal(err)
		}
	}
}
