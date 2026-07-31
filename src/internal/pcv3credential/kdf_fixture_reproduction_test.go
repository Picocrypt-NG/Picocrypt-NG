//go:build pcv3_fixture_reproduction

package pcv3credential

import (
	"Picocrypt-NG/internal/crypto"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"
)

const (
	reproductionInputSHA  = "a1891d0b780d94213e4b2af38635d1d2fefec1aaa68200714246062b39db94de"
	reproductionOutputSHA = "17e39ae0474b4351e1e9978b4fc8f98e640f700a34e4af110d6b728e95235b83"
	reproductionSourceSHA = "04ab368f13b36a46ef4d52be616c292068afdfbae69a3f9c191bf0ed85fc2d1f"
	reproductionNotice    = "PUBLIC DETERMINISTIC PCV3 TEST DATA; NOT SECRET OR OPERATIONAL CREDENTIALS OR KEYS"
)

type reproductionCredentialCase struct {
	ID             string `json:"id"`
	CredentialMode uint8  `json:"credential_mode"`
	KeyfileMode    uint8  `json:"keyfile_mode"`
	TranscriptHex  string `json:"transcript_hex"`
	NormalInputHex string `json:"normal_input_hex"`
}

type reproductionInputRow struct {
	ID          string `json:"id"`
	Root        string `json:"root"`
	SuiteID     uint16 `json:"suite_id"`
	Role        uint8  `json:"role"`
	Label       string `json:"label"`
	OutputBytes uint16 `json:"output_bytes"`
}

type reproductionInputProfile struct {
	ID               string                 `json:"id"`
	ProfileID        uint8                  `json:"profile_id"`
	SuiteID          uint16                 `json:"suite_id"`
	Argon2Version    uint8                  `json:"argon2_version"`
	Time             uint32                 `json:"time"`
	MemoryKiB        uint32                 `json:"memory_kib"`
	Parallelism      uint8                  `json:"parallelism"`
	OutputBytes      uint32                 `json:"output_bytes"`
	ArgonSaltHex     string                 `json:"argon_salt_hex"`
	CredentialCaseID string                 `json:"credential_case_id"`
	VolumeIDHex      string                 `json:"volume_id_hex"`
	VolumeKeyHex     string                 `json:"volume_key_hex"`
	Schedule         []reproductionInputRow `json:"schedule"`
}

type reproductionInput struct {
	SchemaVersion        int                          `json:"schema_version"`
	PublicTestDataNotice string                       `json:"public_test_data_notice"`
	CredentialCases      []reproductionCredentialCase `json:"credential_cases"`
	Profiles             []reproductionInputProfile   `json:"profiles"`
}

type reproductionProvenance struct {
	InputSHA256     string `json:"input_sha256"`
	GeneratorSHA256 string `json:"generator_sha256"`
	GoVersion       string `json:"go_version"`
	XCryptoVersion  string `json:"x_crypto_version"`
	XCryptoChecksum string `json:"x_crypto_checksum"`
}

type reproductionOutputRow struct {
	ID              string `json:"id"`
	Root            string `json:"root"`
	SuiteID         uint16 `json:"suite_id"`
	Role            uint8  `json:"role"`
	Label           string `json:"label"`
	OutputBytes     uint16 `json:"output_bytes"`
	InfoHex         string `json:"info_hex"`
	ExpandOutputHex string `json:"expand_output_hex"`
}

type reproductionOutputProfile struct {
	ID                string                  `json:"id"`
	ArgonCallIndex    int                     `json:"argon_call_index"`
	ProfileID         uint8                   `json:"profile_id"`
	SuiteID           uint16                  `json:"suite_id"`
	Argon2Version     uint8                   `json:"argon2_version"`
	Time              uint32                  `json:"time"`
	MemoryKiB         uint32                  `json:"memory_kib"`
	Parallelism       uint8                   `json:"parallelism"`
	OutputBytes       uint32                  `json:"output_bytes"`
	CredentialCaseID  string                  `json:"credential_case_id"`
	NormalInputHex    string                  `json:"normal_input_hex"`
	ArgonSaltHex      string                  `json:"argon_salt_hex"`
	CredentialRootHex string                  `json:"argon2id_output_hex"`
	VolumeIDHex       string                  `json:"volume_id_hex"`
	CredentialPRKHex  string                  `json:"wrap_prk_hex"`
	VolumePRKHex      string                  `json:"volume_prk_hex"`
	Rows              []reproductionOutputRow `json:"rows"`
}

type reproductionOutput struct {
	SchemaVersion        int                         `json:"schema_version"`
	PublicTestDataNotice string                      `json:"public_test_data_notice"`
	Provenance           reproductionProvenance      `json:"provenance"`
	Profiles             []reproductionOutputProfile `json:"profiles"`
}

func readReproductionFile(
	t *testing.T,
	path string,
	wantSHA string,
) []byte {
	t.Helper()
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read immutable fixture %s: %v", path, err)
	}
	digest := sha256.Sum256(value)
	if got := hex.EncodeToString(digest[:]); got != wantSHA {
		t.Fatalf("immutable fixture %s SHA-256 = %s; want %s", path, got, wantSHA)
	}
	return value
}

func decodeReproductionJSON[T any](t *testing.T, value []byte) T {
	t.Helper()
	var decoded T
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decoded); err != nil {
		t.Fatalf("strict fixture decode: %v", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Fatalf("fixture has trailing JSON: %v", err)
	}
	return decoded
}

func decodeReproductionHex(
	t *testing.T,
	name string,
	value string,
	width int,
) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
	if len(decoded) != width {
		t.Fatalf("%s width = %d; want %d", name, len(decoded), width)
	}
	return decoded
}

func reproductionRootName(root scheduleRoot) string {
	switch root {
	case scheduleRootCredential:
		return "credential-prk"
	case scheduleRootVolume:
		return "volume-prk"
	default:
		return ""
	}
}

func TestKDFLiteralFixtureReproduction(t *testing.T) {
	const (
		inputPath  = "testdata/vector_fixture_input.json"
		outputPath = "testdata/kdf_vectors.json"
	)
	inputBytes := readReproductionFile(t, inputPath, reproductionInputSHA)
	outputBytes := readReproductionFile(t, outputPath, reproductionOutputSHA)
	input := decodeReproductionJSON[reproductionInput](t, inputBytes)
	output := decodeReproductionJSON[reproductionOutput](t, outputBytes)

	if input.SchemaVersion != 1 || output.SchemaVersion != 1 ||
		input.PublicTestDataNotice != reproductionNotice ||
		output.PublicTestDataNotice != reproductionNotice {
		t.Fatal("immutable fixture schema or public-data notice changed")
	}
	if output.Provenance.InputSHA256 != reproductionInputSHA ||
		output.Provenance.GeneratorSHA256 != reproductionSourceSHA ||
		output.Provenance.GoVersion != "go1.26.5" ||
		output.Provenance.XCryptoVersion != "v0.54.0" ||
		output.Provenance.XCryptoChecksum !=
			"h1:YLIA59K4fiNzHzjnZt2tUJQjQtUWfWbeHBqKtk3eScw=" {
		t.Fatalf("immutable fixture provenance changed: %+v", output.Provenance)
	}

	credentialCases := make(
		map[string]reproductionCredentialCase,
		len(input.CredentialCases),
	)
	for _, credentialCase := range input.CredentialCases {
		transcriptBytes := decodeReproductionHex(
			t,
			"credential transcript "+credentialCase.ID,
			credentialCase.TranscriptHex,
			len(credentialCase.TranscriptHex)/2,
		)
		transcript := &CanonicalTranscript{
			secret: crypto.SecretFrom(transcriptBytes),
		}
		normalInput, err := NewCredentialInputNormal(transcript)
		if err != nil {
			t.Fatalf(
				"reproduce normal input %s: %v",
				credentialCase.ID,
				err,
			)
		}
		wantNormal := decodeReproductionHex(
			t,
			"normal input "+credentialCase.ID,
			credentialCase.NormalInputHex,
			64,
		)
		if !bytes.Equal(normalInput.secret.Bytes(), wantNormal) {
			normalInput.Close()
			crypto.SecureZero(wantNormal)
			t.Fatalf("normal input %s did not reproduce", credentialCase.ID)
		}
		normalInput.Close()
		crypto.SecureZero(wantNormal)
		credentialCases[credentialCase.ID] = credentialCase
	}
	if len(credentialCases) != 4 {
		t.Fatalf("credential case count = %d; want 4", len(credentialCases))
	}

	inputProfiles := make(
		map[string]reproductionInputProfile,
		len(input.Profiles),
	)
	for _, profile := range input.Profiles {
		inputProfiles[profile.ID] = profile
	}
	if len(output.Profiles) != 2 || len(inputProfiles) != 2 {
		t.Fatalf(
			"input/output profile counts = %d/%d; want 2/2",
			len(inputProfiles),
			len(output.Profiles),
		)
	}

	totalRows := 0
	for outputIndex, expected := range output.Profiles {
		source, ok := inputProfiles[expected.ID]
		if !ok {
			t.Fatalf("output profile %s has no input", expected.ID)
		}
		suite := Suite(expected.SuiteID)
		profile, err := fixedProfileForSuite(suite)
		if err != nil {
			t.Fatalf("fixed profile %s: %v", expected.ID, err)
		}
		if expected.ArgonCallIndex != outputIndex+1 ||
			source.ProfileID != expected.ProfileID ||
			source.SuiteID != expected.SuiteID ||
			source.Argon2Version != expected.Argon2Version ||
			source.Time != expected.Time ||
			source.MemoryKiB != expected.MemoryKiB ||
			source.Parallelism != expected.Parallelism ||
			source.OutputBytes != expected.OutputBytes ||
			source.ArgonSaltHex != expected.ArgonSaltHex ||
			source.CredentialCaseID != expected.CredentialCaseID ||
			profile.ID != expected.ProfileID ||
			profile.Argon2Version != expected.Argon2Version ||
			profile.Time != expected.Time ||
			profile.MemoryKiB != expected.MemoryKiB ||
			profile.Parallelism != expected.Parallelism ||
			profile.OutputBytes != expected.OutputBytes {
			t.Fatalf("profile %s metadata did not reproduce", expected.ID)
		}
		credentialCase := credentialCases[expected.CredentialCaseID]
		if expected.NormalInputHex != credentialCase.NormalInputHex {
			t.Fatalf("profile %s normal input linkage changed", expected.ID)
		}

		credentialRootBytes := decodeReproductionHex(
			t,
			"provided Argon2id output "+expected.ID,
			expected.CredentialRootHex,
			32,
		)
		volumeKeyBytes := decodeReproductionHex(
			t,
			"VolumeKey "+expected.ID,
			source.VolumeKeyHex,
			32,
		)
		volumeID := decodeReproductionHex(
			t,
			"volume ID "+expected.ID,
			expected.VolumeIDHex,
			32,
		)
		if expected.VolumeIDHex != source.VolumeIDHex {
			t.Fatalf("profile %s volume ID linkage changed", expected.ID)
		}

		rows, err := fixedScheduleForSuite(suite)
		if err != nil {
			t.Fatalf("fixed schedule %s: %v", expected.ID, err)
		}
		if len(rows) != len(source.Schedule) || len(rows) != len(expected.Rows) {
			t.Fatalf(
				"profile %s row counts = %d/%d/%d",
				expected.ID,
				len(rows),
				len(source.Schedule),
				len(expected.Rows),
			)
		}
		requests := make([]KeyRequest, len(rows))
		for i := range rows {
			inputRow := source.Schedule[i]
			outputRow := expected.Rows[i]
			rootName := reproductionRootName(rows[i].root)
			if rootName == "" ||
				inputRow.ID != outputRow.ID ||
				inputRow.Root != rootName ||
				outputRow.Root != rootName ||
				inputRow.SuiteID != uint16(suite) ||
				outputRow.SuiteID != uint16(suite) ||
				inputRow.Role != uint8(rows[i].request.Role) ||
				outputRow.Role != uint8(rows[i].request.Role) ||
				inputRow.Label != string(rows[i].request.Label) ||
				outputRow.Label != string(rows[i].request.Label) ||
				inputRow.OutputBytes != rows[i].request.OutputBytes ||
				outputRow.OutputBytes != rows[i].request.OutputBytes ||
				outputRow.InfoHex !=
					hex.EncodeToString([]byte(scheduleInfo(rows[i]))) {
				t.Fatalf(
					"profile %s row %d metadata/Info did not reproduce",
					expected.ID,
					i,
				)
			}
			requests[i] = rows[i].request
		}
		totalRows += len(rows)

		schedule, err := validateKeySchedule(suite, requests)
		if err != nil {
			t.Fatalf("validate fixture schedule %s: %v", expected.ID, err)
		}
		root := &credentialRoot{
			secret: crypto.SecretFrom(credentialRootBytes),
		}
		key := &volumeKey{secret: crypto.SecretFrom(volumeKeyBytes)}
		material, err := deriveKeyMaterial(
			schedule,
			root,
			key,
			volumeID,
		)
		if err != nil || material == nil {
			t.Fatalf(
				"derive fixture profile %s = %v, %v",
				expected.ID,
				material,
				err,
			)
		}
		wantCredentialPRK := decodeReproductionHex(
			t,
			"CredentialPRK "+expected.ID,
			expected.CredentialPRKHex,
			32,
		)
		wantVolumePRK := decodeReproductionHex(
			t,
			"VolumePRK "+expected.ID,
			expected.VolumePRKHex,
			32,
		)
		if !bytes.Equal(
			material.credentialPRK.secret.Bytes(),
			wantCredentialPRK,
		) || !bytes.Equal(
			material.volumePRK.secret.Bytes(),
			wantVolumePRK,
		) {
			material.close()
			crypto.SecureZero(wantCredentialPRK)
			crypto.SecureZero(wantVolumePRK)
			t.Fatalf("profile %s Extract roots did not reproduce", expected.ID)
		}
		crypto.SecureZero(wantCredentialPRK)
		crypto.SecureZero(wantVolumePRK)

		retained := [][]byte{
			material.credentialRoot.secret.Bytes(),
			material.volumeKey.secret.Bytes(),
			material.credentialPRK.secret.Bytes(),
			material.volumePRK.secret.Bytes(),
		}
		for i := range material.keys {
			wantKey := decodeReproductionHex(
				t,
				"expanded key "+expected.Rows[i].ID,
				expected.Rows[i].ExpandOutputHex,
				32,
			)
			if material.keys[i].row != rows[i] ||
				!bytes.Equal(material.keys[i].secret.Bytes(), wantKey) {
				material.close()
				crypto.SecureZero(wantKey)
				t.Fatalf(
					"profile %s expanded row %d did not reproduce",
					expected.ID,
					i,
				)
			}
			crypto.SecureZero(wantKey)
			retained = append(retained, material.keys[i].secret.Bytes())
		}
		material.close()
		for i, alias := range retained {
			if !allZero(alias) {
				t.Fatalf(
					"profile %s retained secret alias %d",
					expected.ID,
					i,
				)
			}
		}
	}
	if totalRows != 21 {
		t.Fatalf("reproduced row count = %d; want 21", totalRows)
	}

	finalInput := readReproductionFile(t, inputPath, reproductionInputSHA)
	finalOutput := readReproductionFile(t, outputPath, reproductionOutputSHA)
	if !bytes.Equal(inputBytes, finalInput) ||
		!bytes.Equal(outputBytes, finalOutput) {
		t.Fatal("immutable fixture bytes changed during read-only reproduction")
	}
}
