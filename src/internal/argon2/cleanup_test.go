package argon2

import (
	"bytes"
	"encoding/hex"
	"testing"

	upstream "golang.org/x/crypto/argon2"
)

func TestDerivationClearsOriginalWorkspaceAfterExtractingKey(t *testing.T) {
	for _, tc := range []struct {
		name    string
		threads uint8
		want    string
	}{
		{"single_lane", 1, "655ad15eac652dc59f7170a7332bf49b8469be1fdb9c28bb"},
		{"multiple_lanes_and_memory_rounding", 3, "4a15b31aec7c2590b87d1f520be7d96f56658172deaa3079"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			passwordBacking := []byte("password:borrowed tail")
			saltBacking := []byte("somesalt:borrowed tail")
			passwordBefore := bytes.Clone(passwordBacking)
			saltBefore := bytes.Clone(saltBacking)
			want, err := hex.DecodeString(tc.want)
			if err != nil {
				t.Fatal(err)
			}
			passes := uint32(1)
			if tc.threads == 3 {
				passes = 2
			}
			var original []block
			key := deriveKey(argon2id, passwordBacking[:8], saltBacking[:8], nil, nil, passes, 64, tc.threads, uint32(len(want)), func(workspace []block) {
				// Retain the actual allocation used by the production derivation,
				// without replacing its allocation, processing, or cleanup.
				original = workspace
				if workspace[0] == (block{}) {
					t.Fatal("observer did not see the initialized workspace")
				}
			})
			if !bytes.Equal(key, want) {
				t.Fatalf("derived key = %x, want frozen upstream vector %x", key, want)
			}
			if !bytes.Equal(passwordBacking, passwordBefore) || !bytes.Equal(saltBacking, saltBefore) {
				t.Error("derivation changed borrowed password or salt backing storage")
			}
			if len(original) == 0 {
				t.Fatal("derivation did not expose its actual workspace")
			}
			for i := range original {
				if original[i] != (block{}) {
					t.Errorf("original workspace block %d remains nonzero after derivation", i)
					break
				}
			}
			// The caller owns an independent output after workspace cleanup.
			original[len(original)-1][0] = 1
			if !bytes.Equal(key, want) {
				t.Error("returned key aliases the original workspace")
			}
			clear(original)
		})
	}
}

func TestInitBlocksClearsInitialHashAfterItsLastUse(t *testing.T) {
	h0 := initHash([]byte("password"), []byte("somesalt"), nil, nil, 1, 64, 2, 32, argon2id)
	if h0 == ([72]byte{}) {
		t.Fatal("initial hash unexpectedly empty")
	}
	workspace := initBlocks(&h0, 64, 2)
	defer clear(workspace)
	if workspace[0] == (block{}) || workspace[32] == (block{}) {
		t.Error("initial hash was cleared before all lane blocks were initialized")
	}
	if h0 != ([72]byte{}) {
		t.Error("initial hash remains nonzero after block initialization")
	}
}

func TestPublicKeysMatchUpstreamAtMemoryAndOutputBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name    string
		memory  uint32
		threads uint8
		keyLen  uint32
	}{
		{"minimum_memory", 0, 1, 1},
		{"rounded_memory", 65, 3, 32},
		{"full_blake2b_output", 64, 4, 64},
		{"extended_output", 257, 8, 65},
		{"multiple_output_blocks", 64, 2, 128},
	} {
		t.Run(tc.name, func(t *testing.T) {
			password, salt := []byte("password"), []byte("somesalt")
			if got, want := IDKey(password, salt, 2, tc.memory, tc.threads, tc.keyLen), upstream.IDKey(password, salt, 2, tc.memory, tc.threads, tc.keyLen); !bytes.Equal(got, want) {
				t.Errorf("IDKey = %x, want upstream %x", got, want)
			}
			if got, want := Key(password, salt, 2, tc.memory, tc.threads, tc.keyLen), upstream.Key(password, salt, 2, tc.memory, tc.threads, tc.keyLen); !bytes.Equal(got, want) {
				t.Errorf("Key = %x, want upstream %x", got, want)
			}
		})
	}
}
