package pcv3

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"bytes"
	"context"
	"encoding/hex"
	"testing"
)

// Frozen independent wire bytes and literal keys exercise codec and retention behavior.
// These tests do not cover password/KDF authentication.
func TestMemoryNormalCodecFrozenVolumes(t *testing.T) {
	for _, fixture := range loadNormalFixtureManifest(t).Fixtures {
		if fixture.SessionView != nil {
			continue // Dynamic source mutation is covered by the reader's session tests.
		}
		t.Run(fixture.ID, func(t *testing.T) {
			source := readNormalFixtureArtifact(t, fixture.Volume)
			want := readNormalFixturePlaintext(t, fixture.Plaintext)
			result, err := runMemoryNormalRead(context.Background(), bytes.NewReader(source), int64(len(source)), newNormalFixtureCredentialProvider(t, fixture.Keys), uint64(len(source)))
			if err != nil || result == nil {
				t.Fatalf("memory codec: %v", err)
			}
			defer result.Close()
			if result.Outcome() != normalFixtureOutcome(t, fixture.Expected.Outcome) || result.Stage() != normalFixtureStage(t, fixture.Expected.Stage) {
				t.Fatalf("outcome=%v stage=%v", result.Outcome(), result.Stage())
			}
			if fixture.Expected.Completion {
				if !bytes.Equal(result.Bytes(), want) {
					t.Fatal("frozen plaintext changed")
				}
				comment, err := hex.DecodeString(fixture.CommentHex)
				if err != nil {
					t.Fatal(err)
				}
				if fixture.Expected.Stage != "metadata" && result.AuthenticatedComment() != string(comment) {
					t.Fatal("authenticated public comment changed")
				}
			} else if len(result.Bytes()) != 0 || result.AuthenticatedComment() != "" {
				t.Fatal("incomplete authentication exposed plaintext or metadata")
			}
			alias := result.Bytes()
			result.Close()
			if !allZero(alias) || result.Bytes() != nil {
				t.Fatal("Close retained plaintext")
			}
		})
	}
}

func TestMemoryNormalLimitRefusesBeforeCredentialWork(t *testing.T) {
	fixture := loadNormalFixtureManifest(t).Fixtures[0]
	source := readNormalFixtureArtifact(t, fixture.Volume)
	provider := newNormalFixtureCredentialProvider(t, fixture.Keys)
	result, err := runMemoryNormalRead(context.Background(), bytes.NewReader(source), int64(len(source)), provider, 1)
	if result == nil || err == nil || result.Stage() != StageResourceBudget || len(result.Bytes()) != 0 || provider.credentialCalls != 0 {
		t.Fatalf("bounded refusal: result=%v error=%v credential calls=%d", result, err, provider.credentialCalls)
	}
	result.Close()
}

func TestMemoryWriteBoundConsumesFactorsAndPreservesBorrowedData(t *testing.T) {
	for _, deniable := range []bool{false, true} {
		password := []byte("memory adapter factor cleanup")
		comment := []byte("public comment")
		data := []byte("borrowed payload")
		admitter := &memoryDenyAdmitter{}
		request := &MemoryWriteRequest{
			Suite: SuiteStandard, PayloadKind: PayloadKindRaw, Comment: comment,
			Factors: memoryPasswordFactors(password), Admitter: admitter, Data: data, Deniability: deniable, MaxOutputBytes: 1,
		}
		output, err := RunMemoryWrite(context.Background(), request)
		if err == nil || output != nil || admitter.calls != 0 || !allZero(password) || !allZero(comment) {
			t.Fatalf("write bound: error=%v output=%d admission=%d", err, len(output), admitter.calls)
		}
		if string(data) != "borrowed payload" || request.Data != nil || request.Factors != nil {
			t.Fatal("write changed borrowed data or retained request ownership")
		}
	}
}

func TestMemoryWriteKDFRefusalReturnsNoCiphertext(t *testing.T) {
	for _, deniable := range []bool{false, true} {
		password := []byte("refused credential")
		comment := []byte("owned public comment")
		data := []byte("borrowed payload")
		admitter := &memoryDenyAdmitter{}
		output, err := RunMemoryWrite(context.Background(), &MemoryWriteRequest{
			Suite:       SuiteStandard,
			PayloadKind: PayloadKindRaw, Comment: comment, Factors: memoryPasswordFactors(password),
			Admitter: admitter, Data: data, Deniability: deniable, MaxOutputBytes: 8192,
		})
		if err == nil || output != nil || admitter.calls != 1 || !allZero(password) || !allZero(comment) || string(data) != "borrowed payload" {
			t.Fatalf("KDF refusal: deniable=%v error=%v bytes=%d admission=%d", deniable, err, len(output), admitter.calls)
		}
	}
}

func TestMemoryReadCancellationConsumesFactorsWithoutOutput(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	password := []byte("cancelled secret")
	result, err := RunMemoryRead(ctx, &MemoryReadRequest{Source: []byte("PCV\x00"), Factors: memoryPasswordFactors(password), Admitter: &memoryDenyAdmitter{}, Mode: MemoryReadNormal, MaxOutputBytes: 1024})
	if result == nil || err == nil || result.Stage() != StageCancellation || len(result.Bytes()) != 0 || !allZero(password) {
		t.Fatalf("cancelled memory read: result=%v error=%v", result, err)
	}
	result.Close()
}

func TestMemoryReadRejectsInapplicableForceAuthorityBeforeCredentials(t *testing.T) {
	for _, fields := range []MemoryReadRequest{
		{Mode: MemoryReadNormal, SuiteHint: SuiteStandard},
		{Mode: MemoryReadD1, D1Role: D1BootstrapTail},
		{Mode: MemoryForceNormal, Role: CapsuleRoleBackup},
		{Mode: MemoryForceUnverifiedNormal, Role: 255},
		{Mode: MemoryForceUnverifiedD1, D1Role: 255},
		{Mode: MemoryForceUnverifiedD1, SuiteHint: 255},
	} {
		password := []byte("unused authority")
		fields.Source = []byte("PCV\x00")
		fields.Factors = memoryPasswordFactors(password)
		admitter := &memoryDenyAdmitter{}
		fields.Admitter, fields.MaxOutputBytes = admitter, 1024
		result, err := RunMemoryRead(context.Background(), &fields)
		if result == nil || err == nil || result.Stage() != StageCredentialPolicy || len(result.Bytes()) != 0 || admitter.calls != 0 || !allZero(password) {
			t.Fatalf("inapplicable authority: result=%v err=%v KDF=%d", result, err, admitter.calls)
		}
		result.Close()
	}
}

func TestMemoryPlaintextSinkAbortClearsOwnedBuffer(t *testing.T) {
	sink := &memoryNormalSink{limit: 64}
	if err := sink.writeVerifiedRecord(context.Background(), 0, []byte("verified before final record")); err != nil {
		t.Fatal(err)
	}
	alias := sink.data
	sink.abortUncommitted()
	if !allZero(alias) || sink.data != nil {
		t.Fatal("failed final authentication would retain staged plaintext")
	}
}

type memoryDenyAdmitter struct{ calls int }

func (a *memoryDenyAdmitter) AdmitKDF(context.Context, pcv3credential.KDFProfile) (pcv3credential.KDFAdmission, error) {
	a.calls++
	return pcv3credential.KDFAdmissionDenied, nil
}

func memoryPasswordFactors(password []byte) *pcv3credential.FactorRequest {
	return &pcv3credential.FactorRequest{Mode: pcv3credential.CredentialModePasswordOnly, KeyfileMode: pcv3credential.KeyfileModeNone, ExpectedPolicy: pcv3credential.FactorPolicyPasswordOnly, Password: password}
}
