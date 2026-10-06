package pcv3

import (
	pcencoding "Picocrypt-NG/internal/encoding"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3ranges"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"reflect"
	"testing"
)

func forceResourceVolume(t *testing.T, records uint64) []byte {
	t.Helper()
	fixture := loadNormalFixtureManifest(t).FixturesByID()["normal-standard-password-only-small"]
	volume := append([]byte(nil), readNormalFixtureArtifact(t, fixture.Volume)[:1112]...)
	// These public fields need no authentication key to forge. Preserve valid
	// RS and canonical arithmetic so this exercises the resource boundary.
	rewriteCapsule(t, volume, 16, func(decoded []byte) {
		binary.BigEndian.PutUint64(decoded[52:60], records*(1<<20))
		binary.BigEndian.PutUint64(decoded[60:68], records)
	})
	return volume
}

func TestForceRecoveryMapBudgetAdmitsCanonicalBoundary(t *testing.T) {
	volume := forceResourceVolume(t, 65536)
	structure, err := InspectRecovery(bytes.NewReader(volume), int64(len(volume)))
	if err != nil || structure.CandidateCount() != 1 {
		t.Fatalf("affordable truncated geometry admission = %d candidates, %v; want retained primary", structure.CandidateCount(), err)
	}
	candidate, _ := structure.CandidateAt(0)
	if candidate.RecordCount() != 65536 || candidate.PlaintextLength() != 68719476736 {
		t.Fatal("admission changed the declared geometry instead of retaining its canonical missing ranges")
	}
}

func TestForceRecoveryHugeHeaderKeepsKDFAdmissionAndOutputBounded(t *testing.T) {
	for _, mode := range []RecoveryMode{RecoveryModeNormalV3, RecoveryModeForce, RecoveryModeForceUnverified} {
		t.Run(fmt.Sprint(mode), func(t *testing.T) {
			volume := forceResourceVolume(t, 65537)
			original := append([]byte(nil), volume...)
			reader := &observingRecoveryReader{data: volume}
			password := []byte("arbitrary-wrong-password")
			factors := &pcv3credential.FactorRequest{
				Mode: pcv3credential.CredentialModePasswordOnly, KeyfileMode: pcv3credential.KeyfileModeNone,
				ExpectedPolicy: pcv3credential.FactorPolicyPasswordOnly, Password: password,
			}
			// Denial keeps the defective pre-fix path bounded without executing
			// the attacker-requested map or a production KDF.
			admitter := &d1CountingAdmitter{admission: pcv3credential.KDFAdmissionDeniedInsufficient}
			outputs := 0
			output := func(*RecoveryResult, CapsuleRole, RecoveryOutputPlan, RecoveryEmitter) error {
				outputs++
				return nil
			}
			var result *RecoveryResult
			var err error
			if mode == RecoveryModeForceUnverified {
				result, err = RecoverUnverified(context.Background(), reader, int64(len(volume)), factors, admitter, CapsuleRolePrimary, output)
			} else {
				result, err = Recover(context.Background(), reader, int64(len(volume)), factors, admitter, mode, output)
			}
			if result == nil {
				t.Fatalf("recovery returned no result: %v", err)
			}
			defer result.Close()
			if err == nil || result.Outcome() != OutcomeOperationFailed || result.Stage() != StageCredentialPolicy ||
				admitter.calls != 1 || outputs != 0 || len(testRecoveryRanges(result.Ranges())) != 0 {
				t.Fatalf("over-budget recovery = %v/%v, error %v, KDF admissions %d, outputs %d; want one bounded KDF admission and no output", result.Outcome(), result.Stage(), err, admitter.calls, outputs)
			}
			if !bytes.Equal(password, make([]byte, len(password))) || !bytes.Equal(volume, original) {
				t.Fatal("resource refusal did not clear owned password or altered source")
			}
			if len(reader.reads) > 51 {
				t.Fatalf("resource refusal issued %d reads; only fixed recovery inspection is allowed", len(reader.reads))
			}
		})
	}
}

func TestForceRecoveryDoesNotReadAbsentDeclaredRecords(t *testing.T) {
	volume := forceResourceVolume(t, 4096)
	reader := &observingRecoveryReader{data: volume}
	factors := &pcv3credential.FactorRequest{
		Mode: pcv3credential.CredentialModePasswordOnly, KeyfileMode: pcv3credential.KeyfileModeNone,
		ExpectedPolicy: pcv3credential.FactorPolicyPasswordOnly, Password: []byte("arbitrary-wrong-password"),
	}
	outputs := 0
	result, err := Recover(context.Background(), reader, int64(len(volume)), factors, &literalKDFAdmitter{}, RecoveryModeForce,
		func(*RecoveryResult, CapsuleRole, RecoveryOutputPlan, RecoveryEmitter) error {
			outputs++
			return nil
		})
	if result == nil {
		t.Fatalf("recovery returned no result: %v", err)
	}
	defer result.Close()
	if err != nil || result.Outcome() != OutcomeCredentialsOrDamage || outputs != 0 {
		t.Fatalf("unanchored recovery = %v, error %v, outputs %d; want no-output credentials-or-damage", result.Outcome(), err, outputs)
	}
	for _, read := range reader.reads {
		if read.offset >= int64(len(volume)) {
			t.Fatalf("Force attempted absent record read at %d for %d physical bytes", read.offset, len(volume))
		}
	}
	if len(reader.reads) > 52 {
		t.Fatalf("Force issued %d reads for header-only input; want fixed inspection and metadata only", len(reader.reads))
	}
}

func TestForceRecoveryTruncatedPrefixRetainsCanonicalMissingTail(t *testing.T) {
	fixture := loadNormalFixtureManifest(t).FixturesByID()["normal-standard-combined-ordered-two-mib"]
	// Frozen non-RS geometry: 1112-byte front + 48-byte descriptor +
	// 1048576-byte ciphertext + 64-byte tag. The second record is absent.
	volume := readNormalFixtureArtifact(t, fixture.Volume)[:1049800]
	structure, err := InspectRecovery(bytes.NewReader(volume), int64(len(volume)))
	if err != nil {
		t.Fatal(err)
	}
	candidate, _ := structure.CandidateAt(0)
	geometry, _ := structure.GeometryAt(0)
	provider := newNormalFixtureCredentialProvider(t, fixture.Keys)
	provider.access.adopted = true
	defer provider.close()
	request, _ := newRecoveryRequest(RecoveryModeForce)
	reader := &observingRecoveryReader{data: volume}
	analysis, err := analyzeRecoveryRecords(context.Background(), reader, int64(len(volume)), candidate, geometry, provider, request, candidate.Role())
	if err != nil {
		t.Fatal(err)
	}
	want := []RecoveryRange{
		{recordIndex: 0, start: 0, end: 1048576, state: RecoveryRangeVerified},
		{recordIndex: 1, start: 1048576, end: 2097152, state: RecoveryRangeMissing},
	}
	if !reflect.DeepEqual(testRecoveryRanges(analysis.ranges), want) || analysis.final != RecoveryFinalMissing || analysis.damageStage != StageDescriptor {
		t.Fatalf("truncated analysis = %#v/%v/%v; want exact verified prefix, missing second range/final", analysis.ranges, analysis.final, analysis.damageStage)
	}
	if len(reader.reads) != 2 {
		t.Fatalf("truncated analysis issued %d reads; only present descriptor/body may be read", len(reader.reads))
	}
	var emitted []byte
	err = emitRecoveryRecords(context.Background(), reader, candidate, geometry, provider, request, candidate.Role(), analysis,
		func(recoveryRange RecoveryRange, plaintext []byte) error {
			if recoveryRange != want[0] {
				t.Fatalf("emitted range = %#v; want only verified prefix", recoveryRange)
			}
			emitted = append(emitted, plaintext...)
			return nil
		})
	if err != nil || !bytes.Equal(emitted, bytes.Repeat([]byte{0x06}, 1048576)) {
		t.Fatalf("truncated recovery lost frozen prefix plaintext: %v", err)
	}
}

func TestRecoveryAdmitsLargeMissingTailWithoutLogicalAllocation(t *testing.T) {
	volume := forceResourceVolume(t, 65537)
	structure, err := InspectRecovery(bytes.NewReader(volume), int64(len(volume)))
	if err != nil {
		t.Fatalf("large physically bounded recovery rejected: %v", err)
	}
	candidate, _ := structure.CandidateAt(0)
	geometry, _ := structure.GeometryAt(0)
	fixture := loadNormalFixtureManifest(t).FixturesByID()["normal-standard-password-only-small"]
	provider := newNormalFixtureCredentialProvider(t, fixture.Keys)
	provider.access.adopted = true
	defer provider.close()
	request, _ := newRecoveryRequest(RecoveryModeForce)
	analysis, err := analyzeRecoveryRecords(context.Background(), bytes.NewReader(volume), int64(len(volume)), candidate, geometry, provider, request, candidate.Role())
	if err != nil || analysis.final != RecoveryFinalMissing {
		t.Fatalf("analysis failed: %v", err)
	}
	tail, ok := analysis.ranges.At(65536)
	if !ok || tail.Start != 68719476736 || tail.End != 68720525312 || tail.State != pcv3ranges.Missing {
		t.Fatalf("incorrect far tail: %+v", tail)
	}
}

func TestRecoveryAuthenticatedHugeMissingTailPreservesRealPrefix(t *testing.T) {
	fixture := loadNormalFixtureManifest(t).FixturesByID()["normal-standard-combined-ordered-two-mib"]
	frozen := readNormalFixtureArtifact(t, fixture.Volume)
	request, material, entropy := decodeNormalWriterFixtureInputs(t, fixture, frozen)
	defer material.keys.close()
	request.plaintextLength = 1125899906842625 // 1 PiB plus one byte; last interval is short.
	codecs, err := pcencoding.NewRSCodecs()
	if err != nil {
		t.Fatal(err)
	}
	plaintext := bytes.Repeat([]byte{0x5a}, 1048576)
	var written bytes.Buffer
	completion, err := serializeNormalVolume(context.Background(), request, bytes.NewReader(plaintext), &written, material, normalWriteSeams{entropy: bytes.NewReader(entropy), codecs: codecs})
	if err == nil || completion != nil || written.Len() != 1049848 {
		t.Fatalf("intentional writer truncation: size %d, completion %v, error %v", written.Len(), completion, err)
	}
	volume := written.Bytes()[:1049800]
	original := append([]byte(nil), volume...)
	structure, err := InspectRecovery(bytes.NewReader(volume), int64(len(volume)))
	if err != nil {
		t.Fatal(err)
	}
	candidate, _ := structure.CandidateAt(0)
	geometry, _ := structure.GeometryAt(0)
	provider := newNormalFixtureCredentialProvider(t, fixture.Keys)
	provider.access.adopted = true
	defer provider.close()
	recoveryRequest, _ := newRecoveryRequest(RecoveryModeForce)
	analysis, err := analyzeRecoveryRecords(context.Background(), bytes.NewReader(volume), int64(len(volume)), candidate, geometry, provider, recoveryRequest, candidate.Role())
	if err != nil {
		t.Fatal(err)
	}
	first, _ := analysis.ranges.At(0)
	tail, ok := analysis.ranges.At(1073741824)
	if first.State != pcv3ranges.Verified || !ok || tail.Start != 1125899906842624 || tail.End != 1125899906842625 || tail.State != pcv3ranges.Missing || analysis.ranges.Summary().Missing != 1073741824 {
		t.Fatalf("lost prefix or huge tail: first %+v tail %+v summary %+v", first, tail, analysis.ranges.Summary())
	}
	var recovered bytes.Buffer
	err = emitRecoveryRecords(context.Background(), bytes.NewReader(volume), candidate, geometry, provider, recoveryRequest, candidate.Role(), analysis, func(r RecoveryRange, data []byte) error {
		if r.Start() != 0 || r.End() != 1048576 {
			t.Fatal("noncanonical prefix")
		}
		_, err := recovered.Write(data)
		return err
	})
	if err != nil || !bytes.Equal(plaintext, recovered.Bytes()) || !bytes.Equal(volume, original) {
		t.Fatalf("prefix emission/source preservation failed: %v", err)
	}
	if recoveryRequest.budget.Used() > 1024 {
		t.Fatalf("logical tail allocated %d bytes", recoveryRequest.budget.Used())
	}
}

func TestRecoveryMapExhaustionIsResourceFailureWithoutOutput(t *testing.T) {
	volume := forceResourceVolume(t, 65537)
	original := append([]byte(nil), volume...)
	request, _ := newRecoveryRequest(RecoveryModeForce)
	request.budget = pcv3ranges.NewBudget(4095)
	factors := &pcv3credential.FactorRequest{Mode: pcv3credential.CredentialModePasswordOnly, KeyfileMode: pcv3credential.KeyfileModeNone, ExpectedPolicy: pcv3credential.FactorPolicyPasswordOnly, Password: []byte("wrong-password")}
	outputs := 0
	result, err := recoverWithRequest(context.Background(), bytes.NewReader(volume), int64(len(volume)), factors, &literalKDFAdmitter{}, request, func(*RecoveryResult, CapsuleRole, RecoveryOutputPlan, RecoveryEmitter) error { outputs++; return nil })
	if result == nil {
		t.Fatalf("missing resource result: %v", err)
	}
	defer result.Close()
	if err == nil || result.Outcome() != OutcomeOperationFailed || result.Stage() != StageResourceBudget || result.Code() != CodeOperationFailed || outputs != 0 || !bytes.Equal(volume, original) {
		t.Fatalf("resource refusal lost classification or wrote output: %v/%v/%v err %v outputs %d", result.Outcome(), result.Stage(), result.Code(), err, outputs)
	}
}
