//go:build pcv3_production_kdf

package pcv3operation

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3artifact"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// The independent two-record volume separates per-range evidence from whole
// completion. No writer or candidate-analysis seam supplies the oracle.
func TestRecoveryTrustKeepsRangeAndFinalEvidenceSeparate(t *testing.T) {
	frozen, err := os.ReadFile("internal/pcv3/testdata/normal/volumes/normal-standard-combined-ordered-two-mib.pcv")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(frozen)
	if hex.EncodeToString(digest[:]) != "5845cf7585fb85f5e48d20b9c0e2a075355190e2bb9445217f455bca31fcc9da" {
		t.Fatal("independent two-record volume changed")
	}
	for _, test := range []struct {
		name         string
		mode         Mode
		damage       []int
		wantStatuses []pcv3artifact.RangeStatus
		wantFinal    pcv3artifact.FinalStatus
	}{
		{"verified-and-unverified", ModeForceUnverifiedNormal, []int{2098424, 2098536}, []pcv3artifact.RangeStatus{pcv3artifact.RangeVerified, pcv3artifact.RangeUnverified}, pcv3artifact.FinalUnverified},
		{"verified-and-missing", ModeForceNormal, []int{2098424}, []pcv3artifact.RangeStatus{pcv3artifact.RangeVerified, pcv3artifact.RangeMissing}, pcv3artifact.FinalVerified},
		{"final-only-damage", ModeForceNormal, []int{2098536}, []pcv3artifact.RangeStatus{pcv3artifact.RangeVerified, pcv3artifact.RangeVerified}, pcv3artifact.FinalMissing},
		{"fully-verified-recovery", ModeRecoverNormal, nil, nil, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			volume := bytes.Clone(frozen)
			for _, offset := range test.damage {
				volume[offset] ^= 1
			}
			dir := t.TempDir()
			sourcePath, target := filepath.Join(dir, "source.pcv"), filepath.Join(dir, "result")
			if err := os.WriteFile(sourcePath, volume, 0o600); err != nil {
				t.Fatal(err)
			}
			source, err := os.Open(sourcePath)
			if err != nil {
				t.Fatal(err)
			}
			request := &Request{Mode: test.mode, Source: source, Target: target,
				Factors: &FactorRequest{Mode: CredentialModePasswordAndKeyfiles, KeyfileMode: KeyfileModeOrdered, ExpectedPolicy: FactorPolicyPasswordAndKeyfiles, Password: []byte("mix"), Keyfiles: []*KeyfileReader{OwnKeyfileReader(io.NopCloser(bytes.NewBufferString("red"))), OwnKeyfileReader(io.NopCloser(bytes.NewBufferString("blue")))}}}
			consented := false
			if test.mode == ModeForceUnverifiedNormal {
				request.Consent = func(request ConsentRequest, action ConsentAction) error {
					if !slices.Equal(request.AllowedRoles(), []PhysicalRole{RolePrimary, RoleBackup}) {
						t.Fatal("live consent roles changed")
					}
					consented = true
					return action(RoleBackup)
				}
			}
			result := runWithSeams(context.Background(), request, operationSeams{admitter: &operationTestAdmitter{grant: true}})
			requireOperationFileBytes(t, sourcePath, volume)
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 2 || entries[0].Name() != "result" || entries[1].Name() != "source.pcv" {
				t.Fatalf("recovery left non-artifact output or private staging: %v, %v", entries, err)
			}
			encoded, err := os.ReadFile(target)
			if err != nil {
				t.Fatalf("recovery did not publish: %v result=%v", err, result)
			}
			if test.mode == ModeRecoverNormal {
				if result.Outcome() != OutcomeSuccess || result.ArtifactInspection() != nil || !bytes.Equal(encoded, bytes.Repeat([]byte{6}, 2097152)) {
					t.Fatalf("fully authenticated recovery no longer yields plaintext: %v", result)
				}
				return
			}
			if result.Outcome() != OutcomeForcePartial || result.SourceDeletionAllowed() || result.ArchiveFollowUp() != nil || result.Presentation().ArchivePending() || !slices.Contains(result.Warnings(), WarningForcePartial) {
				t.Fatalf("partial result granted normal plaintext authority: %v", result)
			}
			if test.mode == ModeForceUnverifiedNormal && !consented {
				t.Fatal("unverified bytes published without live consent")
			}
			artifact, err := pcv3artifact.Parse(context.Background(), bytes.NewReader(encoded), int64(len(encoded)))
			if err != nil {
				t.Fatal(err)
			}
			metadata := artifact.Metadata()
			if metadata.State != pcv3artifact.StatePartial || metadata.Final != test.wantFinal {
				t.Fatalf("partial evidence metadata = %#v", metadata)
			}
			wantRole := pcv3artifact.RoleNone
			if test.mode == ModeForceUnverifiedNormal {
				wantRole = pcv3artifact.RoleBackup
			}
			if metadata.Role != wantRole {
				t.Fatalf("artifact consent role = %v; want %v", metadata.Role, wantRole)
			}
			var statuses []pcv3artifact.RangeStatus
			if err := artifact.VisitRanges(context.Background(), func(entry pcv3artifact.Entry, reader io.Reader) error {
				if entry.Start != entry.RecordIndex*1048576 || entry.End != (entry.RecordIndex+1)*1048576 {
					t.Fatalf("range boundaries = %#v", entry)
				}
				statuses = append(statuses, entry.Status)
				if reader != nil {
					data, err := io.ReadAll(reader)
					if err != nil {
						return err
					}
					if !bytes.Equal(data, bytes.Repeat([]byte{6}, 1048576)) {
						t.Fatal("MAC-only damage altered recovered data bytes")
					}
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(statuses, test.wantStatuses) {
				t.Fatalf("per-range evidence = %v; want %v", statuses, test.wantStatuses)
			}
		})
	}
}
