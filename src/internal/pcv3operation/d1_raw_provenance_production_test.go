//go:build pcv3_production_kdf

package pcv3operation

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3artifact"
	"Picocrypt-NG/internal/pcv3publication"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func frozenD1ProvenanceFile(t *testing.T, name string) []byte {
	t.Helper()
	want := map[string]string{
		"d1.pcv":            "30b62308a0bcda8d56368ac37c8c7424c36e37945401048cbd20b1044773c631",
		"plaintext.bin":     "42ae995f0c0b4be8883494e43a5ebb425bbd7e70407c6316a2bbc2069299c93b",
		"password.bin":      "e56cef65373463f9559e0f852b508b4fdb6af16b8a57c73f2a20bcc6f2a5e4f3",
		"keyfile-alpha.bin": "2300d62bf2bb24b5cfd294337ce09e851b99f1f1598c17bd3c064c221991e7e1",
		"keyfile-beta.bin":  "2e2004c7040e3d7e85819090bcfbcd4beb0774772019ef021c5db566b057ae48",
	}
	data, err := os.ReadFile(filepath.Join("internal/pcv3/testdata/d1/independent", name))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != want[name] {
		t.Fatalf("frozen fixture %s changed", name)
	}
	return data
}

func frozenD1ProvenanceFactors(t *testing.T) *FactorRequest {
	t.Helper()
	return &FactorRequest{Mode: CredentialModePasswordAndKeyfiles, KeyfileMode: KeyfileModeOrdered,
		ExpectedPolicy: FactorPolicyPasswordAndKeyfiles, Password: frozenD1ProvenanceFile(t, "password.bin"),
		Keyfiles: []*KeyfileReader{
			OwnKeyfileReader(io.NopCloser(bytes.NewReader(frozenD1ProvenanceFile(t, "keyfile-alpha.bin")))),
			OwnKeyfileReader(io.NopCloser(bytes.NewReader(frozenD1ProvenanceFile(t, "keyfile-beta.bin")))),
		}}
}

// The independent 2923-byte vector contains 224-byte bootstraps and one
// 2411-byte outer ciphertext record followed by its 64-byte final tag.
// Corrupting that tag leaves every inner byte and both bootstraps intact.
// Promoting authenticated inner records to ordinary plaintext must fail here.
func TestD1RawOuterSelectionNeverPromotesAuthenticatedInner(t *testing.T) {
	for _, role := range []PhysicalRole{RoleD1Front, RoleD1Tail} {
		t.Run(map[PhysicalRole]string{RoleD1Front: "front", RoleD1Tail: "tail"}[role], func(t *testing.T) {
			volume := frozenD1ProvenanceFile(t, "d1.pcv")
			volume[2635] ^= 1
			dir := t.TempDir()
			sourcePath, target := filepath.Join(dir, "source.d1"), filepath.Join(dir, "artifact")
			if err := os.WriteFile(sourcePath, volume, 0o600); err != nil {
				t.Fatal(err)
			}
			source, err := os.Open(sourcePath)
			if err != nil {
				t.Fatal(err)
			}
			result := runWithSeams(context.Background(), &Request{Mode: ModeForceUnverifiedD1,
				Source: source, Target: target, Factors: frozenD1ProvenanceFactors(t),
				Consent: func(request ConsentRequest, action ConsentAction) error {
					if !slices.Equal(request.AllowedRoles(), []PhysicalRole{RoleD1Front, RoleD1Tail}) {
						t.Fatal("incorrect consent roles")
					}
					return action(role)
				}}, operationSeams{admitter: &operationTestAdmitter{grant: true}})
			if result.Outcome() != pcv3.OutcomeForceUnverified || result.Code() != pcv3.CodeForceUnverified ||
				result.ForceProvenance() != pcv3.ForceProvenanceUnverified ||
				result.PublicationState() != pcv3publication.StatePublishedDurable ||
				result.SourceDeletionAllowed() || result.CompletionClass() != CompletionWarning ||
				!slices.Contains(result.Presentation().Warnings(), WarningForceUnverified) {
				t.Fatalf("raw-selected authenticated inner promoted or refused: %v outcome=%v force=%v publication=%v warnings=%v", result, result.Outcome(), result.ForceProvenance(), result.PublicationState(), result.Warnings())
			}
			if result.ArchiveFollowUp() != nil || result.AuthenticatedComment() != "" {
				t.Fatal("raw selection granted automatic plaintext interpretation")
			}
			encoded, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			artifact, err := pcv3artifact.Parse(context.Background(), bytes.NewReader(encoded), int64(len(encoded)))
			if err != nil {
				t.Fatalf("published output is not an explicit artifact: %v", err)
			}
			wantRole := pcv3artifact.RoleD1Front
			if role == RoleD1Tail {
				wantRole = pcv3artifact.RoleD1Tail
			}
			metadata := artifact.Metadata()
			if metadata.State != pcv3artifact.StateUnverifiedForensic || metadata.Role != wantRole || metadata.Final != pcv3artifact.FinalVerified {
				t.Fatalf("artifact lost provenance or real final authentication: %#v", metadata)
			}
			want := frozenD1ProvenanceFile(t, "plaintext.bin")
			var recovered []byte
			if err := artifact.VisitRanges(context.Background(), func(entry pcv3artifact.Entry, reader io.Reader) error {
				if entry.Status != pcv3artifact.RangeVerified {
					t.Fatal("real inner MAC was relabeled unverified")
				}
				segment, err := io.ReadAll(reader)
				recovered = append(recovered, segment...)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(recovered, want) || bytes.Equal(encoded, want) {
				t.Fatal("artifact recovered wrong bytes or published ordinary plaintext")
			}
			inspection := result.ArtifactInspection()
			if inspection == nil || inspection.Metadata().VerifiedRangeCount != 1 || inspection.Metadata().UnverifiedRangeCount != 0 {
				t.Fatal("frontend inspection lost actual inner evidence")
			}
			requireOperationFileBytes(t, sourcePath, volume)
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 2 {
				t.Fatalf("private stage not cleaned: %v %v", entries, err)
			}
		})
	}
}

func TestD1RawOuterWithoutLiveExactConsentPublishesNothing(t *testing.T) {
	for _, scenario := range []string{"no consent", "wrong role", "expired consent", "verified force"} {
		t.Run(scenario, func(t *testing.T) {
			volume := frozenD1ProvenanceFile(t, "d1.pcv")
			volume[2635] ^= 1
			dir := t.TempDir()
			sourcePath, target := filepath.Join(dir, "source.d1"), filepath.Join(dir, "artifact")
			if err := os.WriteFile(sourcePath, volume, 0o600); err != nil {
				t.Fatal(err)
			}
			source, err := os.Open(sourcePath)
			if err != nil {
				t.Fatal(err)
			}
			var expired ConsentAction
			request := &Request{Mode: ModeForceUnverifiedD1, Source: source, Target: target, Factors: frozenD1ProvenanceFactors(t)}
			switch scenario {
			case "wrong role":
				request.Consent = func(_ ConsentRequest, action ConsentAction) error { return action(RolePrimary) }
			case "expired consent":
				request.Consent = func(_ ConsentRequest, action ConsentAction) error { expired = action; return nil }
			case "verified force":
				request.Mode = ModeForceD1
			}
			result := runWithSeams(context.Background(), request, operationSeams{admitter: &operationTestAdmitter{grant: true}})
			if expired != nil && !errors.Is(expired(RoleD1Front), ErrConsentExpired) {
				t.Fatal("stale consent was usable")
			}
			if result.PublicationAttempted() || result.SourceDeletionAllowed() || result.ArtifactInspection() != nil {
				t.Fatalf("invalid consent granted output: %v", result)
			}
			if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unexpected target: %v", err)
			}
			requireOperationFileBytes(t, sourcePath, volume)
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 1 {
				t.Fatalf("invalid consent left private stage: %v %v", entries, err)
			}
		})
	}
}

func TestD1AuthenticatedDegradedWithoutRawSelectionRemainsPlaintext(t *testing.T) {
	// Removing only the tail bootstrap preserves authenticated front/body/inner.
	volume := frozenD1ProvenanceFile(t, "d1.pcv")
	volume = volume[:2699]
	dir := t.TempDir()
	sourcePath, target := filepath.Join(dir, "source.d1"), filepath.Join(dir, "plaintext")
	if err := os.WriteFile(sourcePath, volume, 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	result := runWithSeams(context.Background(), &Request{Mode: ModeRecoverD1, Source: source, Target: target,
		Factors: frozenD1ProvenanceFactors(t)}, operationSeams{admitter: &operationTestAdmitter{grant: true}})
	if result.Outcome() != pcv3.OutcomeAuthenticatedDegraded || result.ForceProvenance() != pcv3.ForceProvenanceNone ||
		result.ArtifactInspection() != nil || slices.Contains(result.Warnings(), WarningForceUnverified) {
		t.Fatalf("authenticated degraded positive changed: %v", result)
	}
	requireOperationFileBytes(t, target, frozenD1ProvenanceFile(t, "plaintext.bin"))
	requireOperationFileBytes(t, sourcePath, volume)
}
