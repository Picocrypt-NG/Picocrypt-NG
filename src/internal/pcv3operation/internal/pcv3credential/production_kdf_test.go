//go:build pcv3_production_kdf

package pcv3credential

import (
	pcsecret "Picocrypt-NG/internal/secret"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

const (
	productionKDFFixtureSHA256  = "17e39ae0474b4351e1e9978b4fc8f98e640f700a34e4af110d6b728e95235b83"
	productionKDFInputBytes     = 64
	productionKDFSaltBytes      = 16
	productionKDFRootBytes      = 32
	productionKDFProfileCount   = 2
	productionKDFFixtureVersion = 1
)

type productionKDFFixture struct {
	SchemaVersion int                   `json:"schema_version"`
	Profiles      []productionKDFVector `json:"profiles"`
}

type productionKDFVector struct {
	ID                string `json:"id"`
	ArgonCallIndex    int    `json:"argon_call_index"`
	ProfileID         uint8  `json:"profile_id"`
	SuiteID           uint16 `json:"suite_id"`
	Argon2Version     uint8  `json:"argon2_version"`
	Time              uint32 `json:"time"`
	MemoryKiB         uint32 `json:"memory_kib"`
	Parallelism       uint8  `json:"parallelism"`
	OutputBytes       uint32 `json:"output_bytes"`
	NormalInputHex    string `json:"normal_input_hex"`
	ArgonSaltHex      string `json:"argon_salt_hex"`
	CredentialRootHex string `json:"argon2id_output_hex"`
}

type productionKDFAdmitter struct {
	want  KDFProfile
	got   KDFProfile
	calls int
}

func (admitter *productionKDFAdmitter) AdmitKDF(
	_ context.Context,
	profile KDFProfile,
) (KDFAdmission, error) {
	admitter.calls++
	admitter.got = profile
	if profile != admitter.want {
		return KDFAdmissionDenied, nil
	}
	return KDFAdmissionGranted, nil
}

func TestProductionKDFExactProfiles(t *testing.T) {
	vectors := loadProductionKDFVectors(t)
	tests := []struct {
		id    string
		suite Suite
	}{
		{id: "normal-1", suite: SuiteStandard1},
		{id: "paranoid-1", suite: SuiteParanoid1},
	}
	if len(vectors) != len(tests) {
		t.Fatalf(
			"production KDF profile count = %d; want %d",
			len(vectors),
			len(tests),
		)
	}

	for index, test := range tests {
		vector := vectors[index]
		t.Run(test.id, func(t *testing.T) {
			if vector.ID != test.id ||
				vector.ArgonCallIndex != index+1 ||
				vector.SuiteID != uint16(test.suite) {
				t.Fatalf(
					"production KDF row %d identity = %q/%d/%#04x; want %q/%d/%#04x",
					index,
					vector.ID,
					vector.ArgonCallIndex,
					vector.SuiteID,
					test.id,
					index+1,
					test.suite,
				)
			}

			wantProfile := KDFProfile{
				ID:            vector.ProfileID,
				Argon2Version: vector.Argon2Version,
				Time:          vector.Time,
				MemoryKiB:     vector.MemoryKiB,
				Parallelism:   vector.Parallelism,
				SaltBytes:     productionKDFSaltBytes,
				OutputBytes:   vector.OutputBytes,
			}
			fixedProfile, err := fixedProfileForSuite(test.suite)
			if err != nil {
				t.Fatalf("select fixed profile %s: %v", test.id, err)
			}
			if fixedProfile != wantProfile {
				t.Fatalf(
					"fixed profile %s = %+v; want fixture %+v",
					test.id,
					fixedProfile,
					wantProfile,
				)
			}

			normalInput := decodeProductionKDFHex(
				t,
				test.id+" normal input",
				vector.NormalInputHex,
				productionKDFInputBytes,
			)
			input := &CredentialInputNormal{
				secret: pcsecret.SecretFrom(normalInput),
			}
			defer input.Close()
			salt := decodeProductionKDFHex(
				t,
				test.id+" Argon2id salt",
				vector.ArgonSaltHex,
				productionKDFSaltBytes,
			)
			defer pcsecret.SecureZero(salt)
			wantRoot := decodeProductionKDFHex(
				t,
				test.id+" CredentialRoot",
				vector.CredentialRootHex,
				productionKDFRootBytes,
			)
			defer pcsecret.SecureZero(wantRoot)

			admitter := &productionKDFAdmitter{want: wantProfile}
			root, err := runCredentialKDF(
				context.Background(),
				input,
				salt,
				test.suite,
				admitter,
				deriveArgon2ID,
			)
			if err != nil {
				t.Fatalf("run production KDF %s: %v", test.id, err)
			}
			if admitter.calls != 1 || admitter.got != wantProfile {
				t.Fatalf(
					"production KDF admission %s = %d calls, profile %+v; want 1, %+v",
					test.id,
					admitter.calls,
					admitter.got,
					wantProfile,
				)
			}
			if root == nil || root.secret == nil {
				t.Fatalf("production KDF %s returned no CredentialRoot", test.id)
			}
			defer root.close()
			if root.secret.Len() != productionKDFRootBytes ||
				!bytes.Equal(root.secret.Bytes(), wantRoot) {
				t.Fatalf(
					"production KDF %s CredentialRoot = %x; want %x",
					test.id,
					root.secret.Bytes(),
					wantRoot,
				)
			}
		})
	}
}

func loadProductionKDFVectors(t *testing.T) []productionKDFVector {
	t.Helper()

	value, err := os.ReadFile("testdata/kdf_vectors.json")
	if err != nil {
		t.Fatalf("read production KDF fixture: %v", err)
	}
	digest := sha256.Sum256(value)
	if got := hex.EncodeToString(digest[:]); got != productionKDFFixtureSHA256 {
		t.Fatalf(
			"production KDF fixture SHA-256 = %s; want %s",
			got,
			productionKDFFixtureSHA256,
		)
	}

	var fixture productionKDFFixture
	if err := json.Unmarshal(value, &fixture); err != nil {
		t.Fatalf("decode production KDF fixture: %v", err)
	}
	if fixture.SchemaVersion != productionKDFFixtureVersion ||
		len(fixture.Profiles) != productionKDFProfileCount {
		t.Fatalf(
			"production KDF fixture schema/profile count = %d/%d; want %d/%d",
			fixture.SchemaVersion,
			len(fixture.Profiles),
			productionKDFFixtureVersion,
			productionKDFProfileCount,
		)
	}
	return fixture.Profiles
}

func decodeProductionKDFHex(
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
