//go:build pcv3_production_kdf

package pcv3

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3ranges"
	"Picocrypt-NG/internal/pcv3publication"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// These tests consume independently encoded bytes, never the current writer.
// The production lane deliberately executes the real 1-GiB fixed KDF serially.
type independentD1Admitter struct{ calls int }

func (a *independentD1Admitter) AdmitKDF(_ context.Context, p pcv3credential.KDFProfile) (pcv3credential.KDFAdmission, error) {
	if (p.ID != 2 && p.ID != 3) || p.Argon2Version != 19 || p.Time != 8 || p.MemoryKiB != 1048576 || p.Parallelism != 8 || p.OutputBytes != 32 {
		return pcv3credential.KDFAdmissionDenied, nil
	}
	a.calls++
	return pcv3credential.KDFAdmissionGranted, nil
}

func independentD1File(t *testing.T, name string) []byte {
	t.Helper()
	hashes := map[string]string{
		"normal.pcv":        "a468f66c81849b03c58312acf7f2f90677e317ad200820e90ec38da5b0459bcb",
		"d1.pcv":            "487a18056597d97e36ebcaf70aed25ec9cdbd306803ebaf618eba186e05d00bd",
		"d1-standard.pcv":   "22fda4fbe068d85f41d8fe22857320172c67fc5ba806823ce57bdd1072b113bf",
		"d1-pre-c.pcv":      "30b62308a0bcda8d56368ac37c8c7424c36e37945401048cbd20b1044773c631",
		"plaintext.bin":     "42ae995f0c0b4be8883494e43a5ebb425bbd7e70407c6316a2bbc2069299c93b",
		"password.bin":      "e56cef65373463f9559e0f852b508b4fdb6af16b8a57c73f2a20bcc6f2a5e4f3",
		"keyfile-alpha.bin": "2300d62bf2bb24b5cfd294337ce09e851b99f1f1598c17bd3c064c221991e7e1",
		"keyfile-beta.bin":  "2e2004c7040e3d7e85819090bcfbcd4beb0774772019ef021c5db566b057ae48",
	}
	directory := "testdata/d1/independent"
	if name == "d1-pre-c.pcv" {
		directory = "testdata/d1/obsolete"
	}
	data, err := os.ReadFile(filepath.Join(directory, name))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != hashes[name] {
		t.Fatalf("independent fixture %s checksum mismatch", name)
	}
	return data
}

func independentD1Factors(t *testing.T, mutation string) *pcv3credential.FactorRequest {
	t.Helper()
	password := independentD1File(t, "password.bin")
	files := [][]byte{independentD1File(t, "keyfile-alpha.bin"), independentD1File(t, "keyfile-beta.bin")}
	switch mutation {
	case "password changed":
		password[0] ^= 1
	case "factor deleted":
		files = files[:1]
	case "factor changed":
		files[0][0] ^= 1
	case "factors reordered":
		files[0], files[1] = files[1], files[0]
	}
	readers := make([]*pcv3credential.KeyfileReader, 0, len(files))
	for _, data := range files {
		readers = append(readers, pcv3credential.OwnKeyfileReader(io.NopCloser(bytes.NewReader(data))))
	}
	return &pcv3credential.FactorRequest{Mode: pcv3credential.CredentialModePasswordAndKeyfiles, KeyfileMode: pcv3credential.KeyfileModeOrdered, ExpectedPolicy: pcv3credential.FactorPolicyPasswordAndKeyfiles, Password: password, Keyfiles: readers}
}

func TestIndependentFullNormalAndD1ProductionKDF(t *testing.T) {
	for _, test := range []struct {
		name     string
		fixture  string
		mode     RecoveryMode
		kdfCalls int
	}{
		{"normal", "normal.pcv", RecoveryModeNormalV3, 1},
		{"d1 paranoid", "d1.pcv", RecoveryModeNormalV3, 1},
		{"d1 standard", "d1-standard.pcv", RecoveryModeNormalV3, 1},
		{"d1 force paranoid", "d1.pcv", RecoveryModeForce, 2},
		{"d1 force standard", "d1-standard.pcv", RecoveryModeForce, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			volume := independentD1File(t, test.fixture)
			want := independentD1File(t, "plaintext.bin")
			admitter := &independentD1Admitter{}
			var plaintext []byte
			outputs := 0
			emit := func(result *RecoveryResult, plan RecoveryOutputPlan, emitter RecoveryEmitter) error {
				if plan.PlaintextLength() != uint64(len(want)) || result.PlaintextLength() != 0 || result.Ranges() != nil {
					t.Fatal("ordinary recovery output plan lost exact length or exposed semantic evidence")
				}
				outputs++
				return emitter(func(r RecoveryRange, data []byte) error {
					if r.State() != RecoveryRangeVerified || r.Start() != uint64(len(plaintext)) || r.End() != uint64(len(plaintext)+len(data)) {
						t.Fatal("independent fixture emitted unverified or noncanonical plaintext range")
					}
					plaintext = append(plaintext, data...)
					return nil
				})
			}
			var result *RecoveryResult
			var err error
			if test.fixture == "normal.pcv" {
				result, err = Recover(context.Background(), bytes.NewReader(volume), int64(len(volume)), independentD1Factors(t, ""), admitter, RecoveryModeNormalV3, func(r *RecoveryResult, _ CapsuleRole, plan RecoveryOutputPlan, e RecoveryEmitter) error {
					return emit(r, plan, e)
				})
			} else {
				result, err = RecoverD1(context.Background(), bytes.NewReader(volume), int64(len(volume)), independentD1Factors(t, ""), admitter, test.mode, func(r *RecoveryResult, _ D1BootstrapRole, _ string, plan RecoveryOutputPlan, e RecoveryEmitter) error {
					return emit(r, plan, e)
				})
			}
			if result == nil {
				t.Fatalf("independent %s returned no result: %v", test.name, err)
			}
			defer result.Close()
			if err != nil || result.Outcome() != OutcomeSuccess || outputs != 1 || !bytes.Equal(plaintext, want) {
				t.Fatalf("independent %s: outcome=%v stage=%v error=%v outputs=%d plaintext=%x", test.name, result.Outcome(), result.Stage(), err, outputs, plaintext)
			}
			if admitter.calls != test.kdfCalls {
				t.Fatalf("real KDF calls=%d want=%d", admitter.calls, test.kdfCalls)
			}
		})
	}
}

func TestIndependentD1FactorChangesFailBeforeOutput(t *testing.T) {
	for _, fixture := range []string{"d1.pcv", "d1-standard.pcv"} {
		for _, mutation := range []string{"password changed", "factor deleted", "factor changed", "factors reordered"} {
			t.Run(fixture+"/"+mutation, func(t *testing.T) {
				volume := independentD1File(t, fixture)
				admitter := &independentD1Admitter{}
				outputs := 0
				result, err := RecoverD1(context.Background(), bytes.NewReader(volume), int64(len(volume)), independentD1Factors(t, mutation), admitter, RecoveryModeNormalV3, func(_ *RecoveryResult, _ D1BootstrapRole, _ string, _ RecoveryOutputPlan, _ RecoveryEmitter) error {
					outputs++
					return nil
				})
				if result == nil {
					t.Fatalf("missing factor failure result: %v", err)
				}
				defer result.Close()
				// Any selected-factor change must deny plaintext, including the tail fallback.
				if err != nil || result.Outcome() != OutcomeCredentialsOrDamage || result.Stage() != StageD1Bootstrap || outputs != 0 || admitter.calls != 2 {
					t.Fatalf("%s: outcome=%v stage=%v err=%v outputs=%d real KDF calls=%d", mutation, result.Outcome(), result.Stage(), err, outputs, admitter.calls)
				}
			})
		}
	}
}

func independentD1Entropy(t *testing.T, suite Suite) *bytes.Reader {
	t.Helper()
	raw, err := os.ReadFile("testdata/d1/independent/randomness.json")
	if err != nil {
		t.Fatal(err)
	}
	var randomness map[string]string
	if err := json.Unmarshal(raw, &randomness); err != nil {
		t.Fatal(err)
	}
	var entropy []byte
	labels := []string{"outer salt 0", "outer salt 1", "outer nonce 0", "outer nonce 1", "outer iv 0", "outer iv 1", "inner salt", "volume id", "volume key", "outer key", "inner credential root", "inner nonce"}
	if suite == SuiteParanoid {
		labels = append(labels, "inner iv")
	}
	for _, role := range []string{"0", "1"} {
		labels = append(labels, "inner wrap nonce "+role)
		if suite == SuiteParanoid {
			labels = append(labels, "inner wrap iv "+role)
		}
	}
	for _, label := range labels {
		value, err := hex.DecodeString(randomness[label])
		if err != nil || len(value) == 0 {
			t.Fatalf("missing independent entropy %q", label)
		}
		entropy = append(entropy, value...)
	}
	return bytes.NewReader(entropy)
}

// Exact independently authored bytes are the oracle for the full production
// writer, including real credential derivation and publication. Only randomness
// is deterministic; no cipher, encoder, KDF, or credential seam is replaced.
func TestIndependentD1ProductionWriterMatchesReference(t *testing.T) {
	for _, test := range []struct {
		name    string
		fixture string
		suite   Suite
	}{{"paranoid", "d1.pcv", SuiteParanoid}, {"standard", "d1-standard.pcv", SuiteStandard}} {
		t.Run(test.name, func(t *testing.T) {
			independentD1ProductionWriterMatchesReference(t, test.fixture, test.suite)
		})
	}
}

func independentD1ProductionWriterMatchesReference(t *testing.T, fixture string, suite Suite) {
	t.Helper()
	entropy := independentD1Entropy(t, suite)
	plaintext := independentD1File(t, "plaintext.bin")
	directory := t.TempDir()
	sourcePath := filepath.Join(directory, "source.bin")
	target := filepath.Join(directory, "output.pcv")
	if err := os.WriteFile(sourcePath, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	admitter := &independentD1Admitter{}
	request := &d1CreationRequest{
		sourcePath: sourcePath, destinationPath: target, source: source, plaintext: source,
		normal:  normalWriteRequest{suite: suite, payloadKind: PayloadKindRaw, plaintextLength: uint64(len(plaintext))},
		factors: independentD1Factors(t, ""), admitter: admitter,
	}
	seams := defaultD1CreationSeams()
	seams.entropy = entropy
	result, err := composeD1OuterStage(context.Background(), request, seams)
	if err != nil || result == nil || result.State() != pcv3publication.StatePublishedDurable {
		t.Fatalf("independent production writer publication: %v, %v", result, err)
	}
	actual, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if admitter.calls != 2 || entropy.Len() != 0 {
		t.Fatalf("writer used %d real KDF calls and left %d entropy bytes", admitter.calls, entropy.Len())
	}
	t.Logf("real KDF calls=%d, fixture entropy fully consumed", admitter.calls)
	expected := independentD1File(t, fixture)
	if !bytes.Equal(actual, expected) {
		t.Fatalf("production D1 bytes differ from independent reference: got SHA256 %x want %x", sha256.Sum256(actual), sha256.Sum256(expected))
	}
}

func TestIndependentD1CompleteBootstrapLossRetainsAuthenticatedPlaintext(t *testing.T) {
	// Literal frozen wire length keeps loss independent of production geometry.
	const bootstrapBytes = 320
	for _, fixture := range []string{"d1.pcv", "d1-standard.pcv"} {
		for _, lost := range []string{"front", "tail"} {
			t.Run(fixture+"/"+lost, func(t *testing.T) {
				volume := independentD1File(t, fixture)
				wantCalls, provenance := 1, D1BootstrapProvenanceFront
				if lost == "front" {
					volume = volume[bootstrapBytes:]
					wantCalls, provenance = 2, D1BootstrapProvenanceTail
				} else {
					volume = volume[:len(volume)-bootstrapBytes]
				}
				admitter := &independentD1Admitter{}
				var plaintext []byte
				outputs := 0
				result, err := RecoverD1(context.Background(), bytes.NewReader(volume), int64(len(volume)), independentD1Factors(t, ""), admitter, RecoveryModeNormalV3, func(_ *RecoveryResult, _ D1BootstrapRole, _ string, _ RecoveryOutputPlan, emitter RecoveryEmitter) error {
					outputs++
					return emitter(func(r RecoveryRange, data []byte) error {
						if r.State() != RecoveryRangeVerified || r.Start() != uint64(len(plaintext)) || r.End() != uint64(len(plaintext)+len(data)) {
							t.Fatal("bootstrap loss emitted unverified or noncanonical plaintext")
						}
						plaintext = append(plaintext, data...)
						return nil
					})
				})
				if result == nil {
					t.Fatalf("bootstrap loss returned no result: %v", err)
				}
				defer result.Close()
				if err != nil || result.Outcome() != OutcomeAuthenticatedDegraded || result.Stage() != StageD1Bootstrap || result.D1BootstrapProvenance() != provenance || outputs != 1 || !bytes.Equal(plaintext, independentD1File(t, "plaintext.bin")) || admitter.calls != wantCalls {
					t.Fatalf("bootstrap loss: outcome=%v stage=%v provenance=%v error=%v outputs=%d KDF calls=%d want=%d", result.Outcome(), result.Stage(), result.D1BootstrapProvenance(), err, outputs, admitter.calls, wantCalls)
				}
			})
		}
	}
}

func TestIndependentObsoleteD1DoesNotFallBackOrEmitPlaintext(t *testing.T) {
	volume := independentD1File(t, "d1-pre-c.pcv")
	admitter := &independentD1Admitter{}
	outputs := 0
	result, err := RecoverD1(context.Background(), bytes.NewReader(volume), int64(len(volume)), independentD1Factors(t, ""), admitter, RecoveryModeNormalV3, func(*RecoveryResult, D1BootstrapRole, string, RecoveryOutputPlan, RecoveryEmitter) error {
		outputs++
		return nil
	})
	if result == nil {
		t.Fatalf("obsolete D1 returned no result: %v", err)
	}
	defer result.Close()
	if err != nil || result.Outcome() != OutcomeCredentialsOrDamage || result.Stage() != StageD1Bootstrap || outputs != 0 || admitter.calls != 2 {
		t.Fatalf("obsolete D1: outcome=%v stage=%v error=%v outputs=%d real KDF calls=%d", result.Outcome(), result.Stage(), err, outputs, admitter.calls)
	}
}

func TestD1RecoveryMapExhaustionKeepsResourceStage(t *testing.T) {
	volume := independentD1File(t, "d1.pcv")
	request, _ := newD1RecoveryRequest(RecoveryModeNormalV3)
	request.budget = pcv3ranges.NewBudget(4095)
	outputs := 0
	result, err := recoverD1WithRequest(context.Background(), bytes.NewReader(volume), int64(len(volume)), independentD1Factors(t, ""), &independentD1Admitter{}, request, func(*RecoveryResult, D1BootstrapRole, string, RecoveryOutputPlan, RecoveryEmitter) error {
		outputs++
		return nil
	})
	if result == nil {
		t.Fatalf("missing D1 resource result: %v", err)
	}
	defer result.Close()
	if err == nil || result.Outcome() != OutcomeOperationFailed || result.Stage() != StageResourceBudget || result.Code() != CodeOperationFailed || outputs != 0 {
		t.Fatalf("D1 resource refusal: %v/%v/%v, %v, outputs %d", result.Outcome(), result.Stage(), result.Code(), err, outputs)
	}
}
