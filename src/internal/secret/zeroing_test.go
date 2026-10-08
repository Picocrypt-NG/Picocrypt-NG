package secret

import (
	"bytes"
	"testing"
)

func TestSecureZeroClearsOnlyOwnedExtentWithoutAllocation(t *testing.T) {
	backing := bytes.Repeat([]byte{0xa5}, (1<<20)+2)
	owned := backing[1 : len(backing)-1]
	allocations := testing.AllocsPerRun(8, func() {
		for i := range owned {
			owned[i] = 0x73
		}
		SecureZero(owned)
	})
	if allocations != 0 {
		t.Fatalf("wiping reused record storage allocated %.0f objects; want no extra scratch allocation", allocations)
	}
	for i, b := range owned {
		if b != 0 {
			t.Fatalf("owned byte %d retained sensitive data", i)
		}
	}
	if backing[0] != 0xa5 || backing[len(backing)-1] != 0xa5 {
		t.Fatal("wipe crossed the owned slice's length into adjacent data")
	}
	SecureZero(nil)
	SecureZero(backing[:0])
	if backing[0] != 0xa5 {
		t.Fatal("empty wipe changed the backing array")
	}
}

func BenchmarkSecureZeroRecordBuffer(b *testing.B) {
	buffer := make([]byte, 1<<20)
	b.ReportAllocs()
	b.SetBytes(int64(len(buffer)))
	for b.Loop() {
		buffer[0] = 0x73
		SecureZero(buffer)
	}
	if buffer[0] != 0 {
		b.Fatal("wipe did not clear reused record storage")
	}
}
