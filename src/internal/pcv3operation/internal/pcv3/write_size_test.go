package pcv3

import (
	pcencoding "Picocrypt-NG/internal/encoding"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"math"
	"os"
	"testing"
)

// Literal format dimensions catch undercounting at the ceil boundaries used by
// temporary-ZIP disk admission. They are independent of production helpers.
func TestWriteCiphertextLengthCanonicalCeilBoundaries(t *testing.T) {
	for _, test := range []struct {
		plain      uint64
		comment    uint32
		rs         bool
		normal, d1 uint64
	}{
		{0, 0, false, 2232, 2760},
		{0, 0, true, 2304, 2832},
		{1, 0, false, 2345, 2873},
		{1, 0, true, 2488, 3016},
		{64, 0, true, 2488, 3016},
		{65, 0, true, 2624, 3152},
		{0, 48, false, 2232, 2760},
		{0, 49, false, 2368, 2896},
		{0, 99999, false, 108448, 108976},
		{1048575, 0, false, 1050919, 1051511},
		{1048576, 0, false, 1050920, 1051512},
		{1048577, 0, false, 1051033, 1051625},
		{1048575, 0, true, 1116600, 1117192},
		{1048576, 0, true, 1116600, 1117192},
		{1048577, 0, true, 1116784, 1117376},
		// The outer D1 stream emits an extra final tag at exact-full boundaries.
		{1046215, 0, false, 1048559, 1049087},
		{1046216, 0, false, 1048560, 1049152},
		{1046217, 0, false, 1048561, 1049153},
		// Large logical sizes stay O(1); outputs below MaxInt64 remain admissible.
		{4611686018427387904, 0, false, 4612178599636633784, 4612460104678116040},
		{4611686018427387904, 0, true, 4900725635137145088, 4901024751692024592},
	} {
		t.Run(fmt.Sprintf("%d/%d/%t", test.plain, test.comment, test.rs), func(t *testing.T) {
			for _, mode := range []WriteSizeMode{WriteSizeNormal, WriteSizeD1} {
				want := test.normal
				if mode == WriteSizeD1 {
					want = test.d1
				}
				got, err := WriteCiphertextLength(mode, test.plain, test.comment, test.rs)
				if err != nil || got != want {
					t.Fatalf("mode %d length=%d err=%v; want %d", mode, got, err, want)
				}
			}
		})
	}
}

func TestWriteCiphertextLengthRejectsUnrepresentableOutput(t *testing.T) {
	for _, mode := range []WriteSizeMode{WriteSizeNormal, WriteSizeD1} {
		for _, rs := range []bool{false, true} {
			for _, plain := range []uint64{math.MaxInt64, uint64(math.MaxInt64) + 1, math.MaxUint64} {
				if got, err := WriteCiphertextLength(mode, plain, 0, rs); got != 0 || err == nil {
					t.Fatalf("mode %d rs=%t plain=%d accepted: %d/%v", mode, rs, plain, got, err)
				}
			}
		}
	}
	for _, mode := range []WriteSizeMode{0, 255, WriteSizeNormal, WriteSizeD1} {
		if got, err := WriteCiphertextLength(mode, 0, 100000, false); got != 0 || err == nil {
			t.Fatalf("invalid comment/mode accepted: %d/%v", got, err)
		}
	}
}

func TestWriteCiphertextLengthMatchesIndependentWholeContainers(t *testing.T) {
	for _, test := range []struct {
		mode   WriteSizeMode
		file   string
		want   uint64
		digest string
	}{
		{WriteSizeNormal, "normal.pcv", 2395, "a468f66c81849b03c58312acf7f2f90677e317ad200820e90ec38da5b0459bcb"},
		{WriteSizeD1, "d1.pcv", 2923, "30b62308a0bcda8d56368ac37c8c7424c36e37945401048cbd20b1044773c631"},
	} {
		volume, err := os.ReadFile("testdata/d1/independent/" + test.file)
		if err != nil {
			t.Fatal(err)
		}
		if uint64(len(volume)) != test.want || fmt.Sprintf("%x", sha256.Sum256(volume)) != test.digest {
			t.Fatalf("frozen independent %s differs", test.file)
		}
		// Independent generator inputs: 51 plaintext bytes, empty comment, no RS.
		got, err := WriteCiphertextLength(test.mode, 51, 0, false)
		if err != nil || got != test.want {
			t.Fatalf("%s: %d/%v want %d", test.file, got, err, test.want)
		}
	}
}

func TestWriteCiphertextLengthMatchesFrozenNormalAndRealSerializer(t *testing.T) {
	codecs, err := pcencoding.NewRSCodecs()
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range loadNormalFixtureManifest(t).Fixtures {
		// Negative and degraded reader fixtures intentionally are not writer output.
		if fixture.Expected.Outcome != "success" {
			continue
		}
		volume := readNormalFixtureArtifact(t, fixture.Volume)
		request, material, entropy := decodeNormalWriterFixtureInputs(t, fixture, volume)
		got, err := WriteCiphertextLength(WriteSizeNormal, request.plaintextLength, uint32(len(request.comment)), request.payloadBodyRS)
		if err != nil || got != uint64(len(volume)) {
			t.Fatalf("frozen %s: %d/%v want %d", fixture.ID, got, err, len(volume))
		}
		var output bytes.Buffer
		completion, err := serializeNormalVolume(context.Background(), request,
			bytes.NewReader(readNormalFixturePlaintext(t, fixture.Plaintext)), &output,
			material, normalWriteSeams{entropy: bytes.NewReader(entropy), codecs: codecs})
		material.keys.close()
		if err != nil || completion == nil || uint64(output.Len()) != got || !bytes.Equal(output.Bytes(), volume) {
			t.Fatalf("writer %s: bytes=%d length=%d err=%v", fixture.ID, output.Len(), got, err)
		}
	}
}

func TestWriteCiphertextLengthMatchesSmallPublishedD1(t *testing.T) {
	for _, plain := range []int{0, 1, 65} {
		for _, rs := range []bool{false, true} {
			fixture := newD1CreationTestFixtureWithSize(t, plain)
			fixture.request.normal.payloadBodyRS = rs
			fixture.request.normal.comment = bytes.Repeat([]byte{'c'}, 49)
			got, err := WriteCiphertextLength(WriteSizeD1, uint64(plain), 49, rs)
			if err != nil {
				t.Fatal(err)
			}
			result, err := composeD1OuterStage(context.Background(), fixture.request,
				newD1LiteralStageIntegrationSeams(t, defaultD1CreationSeams().observe))
			if err != nil || result == nil {
				t.Fatalf("D1 serializer: %v", err)
			}
			info, err := os.Stat(fixture.destinationPath)
			if err != nil || uint64(info.Size()) != got {
				t.Fatalf("D1 output plain=%d rs=%t length=%d stat=%v err=%v", plain, rs, got, info, err)
			}
		}
	}
}
