// Command generate creates the independent literal Phase-3 structural fixture.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Picocrypt/infectious"
)

const (
	specRevision = "0.3"
	specSHA256   = "9b0c7cac133e1e349ed58bd2232ebff860d1e567348611d09c79d295bd81ad73"

	fixtureName    = "schema1-minimal.pcv"
	provenanceName = "provenance.json"

	frontHeaderLength = 1112
	fixtureLength     = 2232

	reproductionCommand = "mise exec go@1.26.5 -- go run ./internal/pcv3/testdata/generate"
)

type region struct {
	Name   string `json:"name"`
	Offset int    `json:"offset"`
	Length int    `json:"length"`
}

type semantics struct {
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

type provenance struct {
	SpecRevision          string    `json:"spec_revision"`
	SpecSHA256            string    `json:"spec_sha256"`
	GeneratorSourceSHA256 string    `json:"generator_source_sha256"`
	ReproductionCommand   string    `json:"reproduction_command"`
	Fixture               string    `json:"fixture"`
	FixtureLength         int       `json:"fixture_length"`
	FixtureSHA256         string    `json:"fixture_sha256"`
	PayloadBodyRS         bool      `json:"payload_body_rs"`
	Regions               []region  `json:"regions"`
	Semantics             semantics `json:"semantics"`
}

type codecs struct {
	rs16  *infectious.FEC
	rs64  *infectious.FEC
	rs128 *infectious.FEC
}

func main() {
	outDir := flag.String("out", "internal/pcv3/testdata", "fixture output directory")
	sourcePath := flag.String("source", "internal/pcv3/testdata/generate/main.go", "generator source path")
	specPath := flag.String("spec", "../docs/PCV3_FORMAT_SPEC.md", "PCV3 specification path")
	flag.Parse()

	if err := run(*outDir, *sourcePath, *specPath); err != nil {
		fmt.Fprintln(os.Stderr, "generate PCV3 structural fixture:", err)
		os.Exit(1)
	}
}

func run(outDir, sourcePath, specPath string) error {
	if err := verifyFileDigest(specPath, specSHA256); err != nil {
		return fmt.Errorf("specification identity: %w", err)
	}
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		return fmt.Errorf("read generator source: %w", err)
	}

	codecSet, err := newCodecs()
	if err != nil {
		return err
	}
	fixture, err := buildFixture(codecSet)
	if err != nil {
		return err
	}
	if len(fixture) != fixtureLength {
		return fmt.Errorf("fixture length %d != %d", len(fixture), fixtureLength)
	}

	fixtureDigest := sha256.Sum256(fixture)
	sourceDigest := sha256.Sum256(source)
	manifest := provenance{
		SpecRevision:          specRevision,
		SpecSHA256:            specSHA256,
		GeneratorSourceSHA256: hex.EncodeToString(sourceDigest[:]),
		ReproductionCommand:   reproductionCommand,
		Fixture:               fixtureName,
		FixtureLength:         len(fixture),
		FixtureSHA256:         hex.EncodeToString(fixtureDigest[:]),
		PayloadBodyRS:         false,
		Regions: []region{
			{Name: "preamble", Offset: 0, Length: 16},
			{Name: "primary_capsule", Offset: 16, Length: 960},
			{Name: "metadata", Offset: 976, Length: 136},
			{Name: "payload", Offset: 1112, Length: 112},
			{Name: "final_descriptor", Offset: 1112, Length: 48},
			{Name: "final_body", Offset: 1160, Length: 64},
			{Name: "backup_capsule", Offset: 1224, Length: 960},
			{Name: "trailer", Offset: 2184, Length: 48},
		},
		Semantics: semantics{
			Major:             3,
			Schema:            1,
			Suite:             1,
			FeatureFlags:      0,
			FrontHeaderLength: frontHeaderLength,
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
		},
	}
	encodedManifest, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode provenance: %w", err)
	}
	encodedManifest = append(encodedManifest, '\n')

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, fixtureName), fixture, 0o644); err != nil {
		return fmt.Errorf("write fixture: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, provenanceName), encodedManifest, 0o644); err != nil {
		return fmt.Errorf("write provenance: %w", err)
	}
	return nil
}

func newCodecs() (*codecs, error) {
	rs16, err := infectious.NewFEC(16, 48)
	if err != nil {
		return nil, fmt.Errorf("create RS16: %w", err)
	}
	rs64, err := infectious.NewFEC(64, 192)
	if err != nil {
		return nil, fmt.Errorf("create RS64: %w", err)
	}
	rs128, err := infectious.NewFEC(128, 136)
	if err != nil {
		return nil, fmt.Errorf("create RS128: %w", err)
	}
	return &codecs{rs16: rs16, rs64: rs64, rs128: rs128}, nil
}

func buildFixture(codecSet *codecs) ([]byte, error) {
	core := buildLogicalCore()
	primary, err := buildCapsule(codecSet.rs64, core, 0)
	if err != nil {
		return nil, fmt.Errorf("primary capsule: %w", err)
	}
	backup, err := buildCapsule(codecSet.rs64, core, 1)
	if err != nil {
		return nil, fmt.Errorf("backup capsule: %w", err)
	}
	metadata, err := buildMetadata(codecSet.rs128)
	if err != nil {
		return nil, fmt.Errorf("metadata: %w", err)
	}
	descriptor, err := buildFinalDescriptor(codecSet.rs16)
	if err != nil {
		return nil, fmt.Errorf("final descriptor: %w", err)
	}
	trailer, err := buildTrailer(codecSet.rs16)
	if err != nil {
		return nil, fmt.Errorf("trailer: %w", err)
	}

	fixture := make([]byte, 0, fixtureLength)
	fixture = append(fixture, core[:16]...)
	fixture = append(fixture, primary...)
	fixture = append(fixture, metadata...)
	fixture = append(fixture, descriptor...)
	finalTag := make([]byte, 64)
	fillSequence(finalTag, 0xd0)
	fixture = append(fixture, finalTag...)
	fixture = append(fixture, backup...)
	fixture = append(fixture, trailer...)
	return fixture, nil
}

func buildLogicalCore() [96]byte {
	var core [96]byte
	copy(core[0:4], "PCV\x00")
	binary.BigEndian.PutUint16(core[4:6], 3)
	binary.BigEndian.PutUint16(core[6:8], 1)
	binary.BigEndian.PutUint16(core[8:10], 1)
	binary.BigEndian.PutUint16(core[10:12], 0)
	binary.BigEndian.PutUint32(core[12:16], frontHeaderLength)
	fillSequence(core[16:48], 0x10)
	core[48] = 1
	core[49] = 1
	core[50] = 1
	core[51] = 0
	binary.BigEndian.PutUint64(core[52:60], 0)
	binary.BigEndian.PutUint64(core[60:68], 0)
	fillSequence(core[68:84], 0x30)
	// Standard-1 requires core[84:92] to remain zero.
	binary.BigEndian.PutUint32(core[92:96], 0)
	return core
}

func buildCapsule(rs64 *infectious.FEC, core [96]byte, role byte) ([]byte, error) {
	var decoded [320]byte
	copy(decoded[0:96], core[:])
	decoded[96] = role
	decoded[97] = 1
	decoded[98] = 0
	decoded[99] = 1
	binary.BigEndian.PutUint16(decoded[100:102], 0)
	// decoded[102:104] and the Standard-1 wrap IV stay zero.
	fillSequence(decoded[104:120], 0x50)
	if role == 0 {
		fillSequence(decoded[120:144], 0x60)
		fillSequence(decoded[160:192], 0x80)
		fillSequence(decoded[192:256], 0xa0)
		fillSequence(decoded[256:320], 0x20)
	} else {
		fillSequence(decoded[120:144], 0x70)
		fillSequence(decoded[160:192], 0x90)
		fillSequence(decoded[192:256], 0xb0)
		fillSequence(decoded[256:320], 0x40)
	}

	encoded := make([]byte, 0, 960)
	for block := range 5 {
		codeword, err := encode(rs64, decoded[block*64:(block+1)*64])
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, codeword...)
	}
	return encoded, nil
}

func buildMetadata(rs128 *infectious.FEC) ([]byte, error) {
	var decoded [128]byte
	copy(decoded[0:4], "PCVM")
	binary.BigEndian.PutUint16(decoded[4:6], 1)
	binary.BigEndian.PutUint16(decoded[6:8], 1)
	binary.BigEndian.PutUint32(decoded[8:12], 0)
	// decoded[12:16] and decoded[80:128] are reserved zero bytes.
	fillSequence(decoded[16:80], 0xc0)
	return encode(rs128, decoded[:])
}

func buildFinalDescriptor(rs16 *infectious.FEC) ([]byte, error) {
	var decoded [16]byte
	// Index and length are zero for the mandatory empty final record.
	decoded[12] = 1
	return encode(rs16, decoded[:])
}

func buildTrailer(rs16 *infectious.FEC) ([]byte, error) {
	var decoded [16]byte
	copy(decoded[0:4], "PCVT")
	binary.BigEndian.PutUint16(decoded[4:6], 3)
	binary.BigEndian.PutUint16(decoded[6:8], 1)
	binary.BigEndian.PutUint32(decoded[8:12], 960)
	binary.BigEndian.PutUint16(decoded[12:14], 1)
	return encode(rs16, decoded[:])
}

func encode(codec *infectious.FEC, data []byte) ([]byte, error) {
	if len(data) != codec.Required() {
		return nil, fmt.Errorf("input length %d != required %d", len(data), codec.Required())
	}
	encoded := make([]byte, codec.Total())
	if err := codec.Encode(data, func(share infectious.Share) {
		encoded[share.Number] = share.Data[0]
	}); err != nil {
		return nil, fmt.Errorf("encode RS(%d,%d): %w", codec.Required(), codec.Total(), err)
	}
	return encoded, nil
}

func fillSequence(destination []byte, start byte) {
	for index := range destination {
		destination[index] = start + byte(index)
	}
}

func verifyFileDigest(path, expected string) error {
	contents, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(contents)
	if actual := hex.EncodeToString(digest[:]); actual != expected {
		return fmt.Errorf("SHA-256 %s != %s", actual, expected)
	}
	return nil
}
