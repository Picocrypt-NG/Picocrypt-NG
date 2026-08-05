package pcv3

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

type recoveryRead struct {
	offset int64
	length int
}

type observingRecoveryReader struct {
	data  []byte
	reads []recoveryRead
}

func (reader *observingRecoveryReader) ReadAt(destination []byte, offset int64) (int, error) {
	reader.reads = append(reader.reads, recoveryRead{offset: offset, length: len(destination)})
	return bytes.NewReader(reader.data).ReadAt(destination, offset)
}

func TestInspectRecoveryReadsOnlyFixedPrimaryAnd49TailIntervals(t *testing.T) {
	fixture := loadNormalFixtureManifest(t).FixturesByID()["normal-standard-password-only-small"]
	volume := readNormalFixtureArtifact(t, fixture.Volume)
	reader := &observingRecoveryReader{data: volume}

	structure, err := InspectRecovery(reader, int64(len(volume)))
	if err != nil {
		t.Fatalf("InspectRecovery(frozen normal volume): %v", err)
	}
	if structure.CandidateCount() != 2 {
		t.Fatalf("candidate count = %d; want fixed primary plus one structural tail", structure.CandidateCount())
	}

	want := []recoveryRead{{offset: 0, length: 16}, {offset: 16, length: 960}}
	for truncation := int64(0); truncation <= 48; truncation++ {
		want = append(want, recoveryRead{
			offset: int64(len(volume)) - truncation - 960,
			length: 960,
		})
	}
	if !reflect.DeepEqual(reader.reads, want) {
		t.Fatalf("recovery reads = %#v; want exact raw preamble, primary, and 49 tail intervals %#v", reader.reads, want)
	}
}

func TestInspectRecoveryRetainsPrimaryAcrossFrozenSuffixBoundaries(t *testing.T) {
	fixture := loadNormalFixtureManifest(t).FixturesByID()["normal-standard-password-only-small"]
	volume := readNormalFixtureArtifact(t, fixture.Volume)
	tests := []struct {
		truncate int
		want     int
	}{
		{truncate: 0, want: 2},
		{truncate: 48, want: 2},
		{truncate: 49, want: 1},
		{truncate: 960, want: 1},
		{truncate: 1008, want: 1},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("truncate-%d", test.truncate), func(t *testing.T) {
			source := volume[:len(volume)-test.truncate]
			structure, err := InspectRecovery(bytes.NewReader(source), int64(len(source)))
			if err != nil {
				t.Fatalf("InspectRecovery(truncate=%d): %v", test.truncate, err)
			}
			if structure.CandidateCount() != test.want {
				t.Fatalf("truncate=%d candidate count = %d; want %d", test.truncate, structure.CandidateCount(), test.want)
			}
			if test.truncate != 0 && !structure.SuffixDamaged() {
				t.Fatalf("truncate=%d did not retain suffix damage", test.truncate)
			}
		})
	}
}

func TestInspectRecoveryTreatsRawPreambleAsDamageNotRoutingAuthority(t *testing.T) {
	fixture := loadNormalFixtureManifest(t).FixturesByID()["normal-standard-password-only-small"]
	volume := append([]byte(nil), readNormalFixtureArtifact(t, fixture.Volume)...)
	volume[0] ^= 0xff

	structure, err := InspectRecovery(bytes.NewReader(volume), int64(len(volume)))
	if err != nil {
		t.Fatalf("InspectRecovery(damaged raw preamble): %v", err)
	}
	if !structure.PreambleDamaged() || structure.CandidateCount() != 2 {
		t.Fatalf("preamble damaged/candidates = %v/%d; want true/2", structure.PreambleDamaged(), structure.CandidateCount())
	}
}

func TestRecoveryFixtureOracleIsFrozenAndTestOnly(t *testing.T) {
	encoded, err := os.ReadFile(filepath.Join("testdata", "recovery", "manifest.json"))
	if err != nil {
		t.Fatalf("read frozen recovery manifest: %v", err)
	}
	var manifest struct {
		Format   string `json:"format"`
		TestOnly bool   `json:"test_only"`
		Cases    []any  `json:"cases"`
	}
	if err := json.Unmarshal(encoded, &manifest); err != nil {
		t.Fatalf("decode frozen recovery manifest: %v", err)
	}
	if manifest.Format != "PCV3 recovery fixtures v1" || !manifest.TestOnly || len(manifest.Cases) != 4 {
		t.Fatalf("recovery manifest identity = %q/%v/%d; want frozen v1 TEST ONLY four-case oracle", manifest.Format, manifest.TestOnly, len(manifest.Cases))
	}
}
