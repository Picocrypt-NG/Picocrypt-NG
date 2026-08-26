package pcv3_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"testing"
)

const (
	literalFixturePath       = "testdata/schema1-minimal.pcv"
	literalProvenancePath    = "testdata/provenance.json"
	literalGeneratorPath     = "testdata/generate/main.go"
	literalFixtureLength     = 2232
	literalFixtureSHA256     = "3866a4543150211bece6e50d45d3dc5b909fd33c5ace65c1c2fb7e6c05b7fbd7"
	literalGeneratorSHA256   = "3a6086261108c86375d97afaf130f902d723b40aae37041a9943060e5c44c778"
	literalSpecSHA256        = "9b0c7cac133e1e349ed58bd2232ebff860d1e567348611d09c79d295bd81ad73"
	literalReproduction      = "mise exec go@1.26.5 -- go run ./internal/pcv3/testdata/generate"
	literalPrimaryRoleOffset = 240
	literalBackupRoleOffset  = 1448
	literalTrailerOffset     = 2184
)

type literalRegion struct {
	Name   string `json:"name"`
	Offset int    `json:"offset"`
	Length int    `json:"length"`
}

type literalSemantics struct {
	Major             uint16 `json:"major"`
	Schema            uint16 `json:"schema"`
	Suite             uint16 `json:"suite"`
	FeatureFlags      uint16 `json:"feature_flags"`
	FrontHeaderLength uint32 `json:"front_header_length"`
	PayloadKind       uint8  `json:"payload_kind"`
	PlaintextLength   uint64 `json:"plaintext_length"`
	RecordCount       uint64 `json:"record_count"`
	CommentLength     uint32 `json:"comment_length"`
	MetadataBlocks    uint16 `json:"metadata_blocks"`
	PrimaryRole       uint8  `json:"primary_role"`
	BackupRole        uint8  `json:"backup_role"`
	CredentialMode    uint8  `json:"credential_mode"`
	KeyfileMode       uint8  `json:"keyfile_mode"`
	KDFProfile        uint8  `json:"kdf_profile"`
	KeyfileCount      uint16 `json:"keyfile_count"`
}

type literalProvenance struct {
	SpecRevision          string           `json:"spec_revision"`
	SpecSHA256            string           `json:"spec_sha256"`
	GeneratorSourceSHA256 string           `json:"generator_source_sha256"`
	ReproductionCommand   string           `json:"reproduction_command"`
	Fixture               string           `json:"fixture"`
	FixtureLength         int              `json:"fixture_length"`
	FixtureSHA256         string           `json:"fixture_sha256"`
	PayloadBodyRS         bool             `json:"payload_body_rs"`
	Regions               []literalRegion  `json:"regions"`
	Semantics             literalSemantics `json:"semantics"`
}

func TestLiteralSchema1FixtureProvenance(t *testing.T) {
	fixture := readFixtureFile(t, literalFixturePath)
	if len(fixture) != literalFixtureLength {
		t.Fatalf("literal fixture length = %d; want %d", len(fixture), literalFixtureLength)
	}
	if got := sha256Hex(fixture); got != literalFixtureSHA256 {
		t.Fatalf("literal fixture SHA-256 = %s; want %s", got, literalFixtureSHA256)
	}

	manifestBytes := readFixtureFile(t, literalProvenancePath)
	decoder := json.NewDecoder(bytes.NewReader(manifestBytes))
	decoder.DisallowUnknownFields()
	var manifest literalProvenance
	if err := decoder.Decode(&manifest); err != nil {
		t.Fatalf("decode fixture provenance: %v", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		t.Fatalf("fixture provenance has trailing JSON: %v", err)
	}

	wantRegions := []literalRegion{
		{Name: "preamble", Offset: 0, Length: 16},
		{Name: "primary_capsule", Offset: 16, Length: 960},
		{Name: "metadata", Offset: 976, Length: 136},
		{Name: "payload", Offset: 1112, Length: 112},
		{Name: "final_descriptor", Offset: 1112, Length: 48},
		{Name: "final_body", Offset: 1160, Length: 64},
		{Name: "backup_capsule", Offset: 1224, Length: 960},
		{Name: "trailer", Offset: literalTrailerOffset, Length: 48},
	}
	wantSemantics := literalSemantics{
		Major:             3,
		Schema:            1,
		Suite:             1,
		FeatureFlags:      0,
		FrontHeaderLength: 1112,
		PayloadKind:       1,
		PlaintextLength:   0,
		RecordCount:       0,
		CommentLength:     0,
		MetadataBlocks:    1,
		PrimaryRole:       0,
		BackupRole:        1,
		CredentialMode:    1,
		KeyfileMode:       0,
		KDFProfile:        1,
		KeyfileCount:      0,
	}
	if manifest.SpecRevision != "0.3" || manifest.SpecSHA256 != literalSpecSHA256 {
		t.Errorf("fixture specification identity = %q/%q; want 0.3/%s", manifest.SpecRevision, manifest.SpecSHA256, literalSpecSHA256)
	}
	if manifest.GeneratorSourceSHA256 != literalGeneratorSHA256 {
		t.Errorf("recorded generator SHA-256 = %s; want %s", manifest.GeneratorSourceSHA256, literalGeneratorSHA256)
	}
	if got := sha256Hex(readFixtureFile(t, literalGeneratorPath)); got != literalGeneratorSHA256 {
		t.Errorf("checked-in generator SHA-256 = %s; want %s", got, literalGeneratorSHA256)
	}
	if manifest.ReproductionCommand != literalReproduction {
		t.Errorf("fixture reproduction command = %q; want %q", manifest.ReproductionCommand, literalReproduction)
	}
	if manifest.Fixture != "schema1-minimal.pcv" || manifest.FixtureLength != literalFixtureLength || manifest.FixtureSHA256 != literalFixtureSHA256 {
		t.Errorf("fixture output identity = %q/%d/%q; want schema1-minimal.pcv/%d/%s", manifest.Fixture, manifest.FixtureLength, manifest.FixtureSHA256, literalFixtureLength, literalFixtureSHA256)
	}
	if manifest.PayloadBodyRS {
		t.Error("minimum literal fixture unexpectedly enables payload-body RS")
	}
	if !reflect.DeepEqual(manifest.Regions, wantRegions) {
		t.Errorf("fixture region inventory = %#v; want %#v", manifest.Regions, wantRegions)
	}
	if manifest.Semantics != wantSemantics {
		t.Errorf("fixture semantic inventory = %#v; want %#v", manifest.Semantics, wantSemantics)
	}

	if !bytes.Equal(fixture[0:4], []byte{'P', 'C', 'V', 0}) {
		t.Fatalf("literal discriminator = %x; want PCV\\x00", fixture[0:4])
	}
	if got := binary.BigEndian.Uint16(fixture[4:6]); got != 3 {
		t.Errorf("literal major = %d; want 3", got)
	}
	if got := binary.BigEndian.Uint16(fixture[6:8]); got != 1 {
		t.Errorf("literal schema = %d; want 1", got)
	}
	if got := binary.BigEndian.Uint16(fixture[8:10]); got != 1 {
		t.Errorf("literal suite = %d; want 1", got)
	}
	if got := binary.BigEndian.Uint16(fixture[10:12]); got != 0 {
		t.Errorf("literal feature flags = %#x; want 0", got)
	}
	if got := binary.BigEndian.Uint32(fixture[12:16]); got != 1112 {
		t.Errorf("literal front-header length = %d; want 1112", got)
	}
	if got := fixture[literalPrimaryRoleOffset]; got != 0 {
		t.Errorf("literal primary capsule role = %d; want 0", got)
	}
	if got := fixture[literalBackupRoleOffset]; got != 1 {
		t.Errorf("literal backup capsule role = %d; want 1", got)
	}
	trailer := fixture[literalTrailerOffset:]
	if !bytes.Equal(trailer[0:4], []byte("PCVT")) ||
		binary.BigEndian.Uint16(trailer[4:6]) != 3 ||
		binary.BigEndian.Uint16(trailer[6:8]) != 1 ||
		binary.BigEndian.Uint32(trailer[8:12]) != 960 ||
		binary.BigEndian.Uint16(trailer[12:14]) != 1 ||
		binary.BigEndian.Uint16(trailer[14:16]) != 0 {
		t.Errorf("literal systematic trailer fields = %x; want canonical schema-1 trailer", trailer[:16])
	}
}

func readFixtureFile(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read required fixture file %q: %v", path, err)
	}
	return contents
}

func sha256Hex(contents []byte) string {
	digest := sha256.Sum256(contents)
	return hex.EncodeToString(digest[:])
}
