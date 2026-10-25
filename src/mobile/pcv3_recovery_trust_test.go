//go:build android || linux

package mobile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
)

// Capture only public, path-free bridge metadata when explicitly requested.
// Android consumes this actual operation snapshot in its renderer regression.
func capturePCV3RecoverySnapshot(t *testing.T, name string, snapshot *PCV3Snapshot, inspection *PCV3ArtifactInspection) {
	t.Helper()
	directory := os.Getenv("PCV3_RECOVERY_SNAPSHOT_OUTPUT_DIR")
	if directory == "" {
		return
	}
	args, statusArgs, warnings := []string{}, []string{}, []string{}
	for index := range snapshot.ArgCount() {
		args = append(args, snapshot.ArgAt(index))
	}
	for index := range snapshot.StatusArgCount() {
		statusArgs = append(statusArgs, snapshot.StatusArgAt(index))
	}
	for index := range snapshot.WarningCount() {
		warnings = append(warnings, snapshot.WarningAt(index))
	}
	data := map[string]any{
		"statusCode": snapshot.StatusCode(), "statusArgs": statusArgs,
		"outcome": snapshot.Outcome(), "stage": snapshot.Stage(), "code": snapshot.Code(),
		"forceProvenance": snapshot.ForceProvenance(), "d1BootstrapProvenance": snapshot.D1BootstrapProvenance(), "detailStage": snapshot.DetailStage(),
		"publicationAttempted": snapshot.PublicationAttempted(), "publicationState": snapshot.PublicationState(), "publicationStage": snapshot.PublicationStage(), "publicationCode": snapshot.PublicationCode(),
		"diagnostic": snapshot.Diagnostic(), "completionClass": snapshot.CompletionClass(), "args": args, "warnings": warnings, "archivePending": snapshot.ArchivePending(),
		"artifact": map[string]string{"kind": inspection.Kind(), "role": inspection.Role(), "final": inspection.FinalStatus(), "verified": inspection.VerifiedCount(), "unverified": inspection.UnverifiedCount(), "missing": inspection.MissingCount()},
	}
	encoded, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, name+".json"), append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestPCV3RecoveryTrustMessagesFromRealOperation(t *testing.T) {
	frozen, err := os.ReadFile("../internal/pcv3operation/internal/pcv3/testdata/normal/volumes/normal-standard-combined-ordered-two-mib.pcv")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(frozen)
	if hex.EncodeToString(digest[:]) != "5845cf7585fb85f5e48d20b9c0e2a075355190e2bb9445217f455bca31fcc9da" {
		t.Fatal("independent two-record volume changed")
	}
	for _, test := range []struct {
		name, mode, outcome, warning, final, verified, unverified string
		damage                                                    []int
		statuses                                                  []string
	}{
		{"mixed", "force-unverified-normal", "force-partial", "force-partial", "unverified", "1", "1", []int{2098424, 2098536}, []string{"verified", "unverified"}},
		{"final-only", "force-normal", "force-partial", "force-partial", "missing", "2", "0", []int{2098536}, []string{"verified", "verified"}},
		{"no-anchor", "force-unverified-normal", "force-unverified", "force-unverified", "unverified", "0", "2", []int{1049736, 2098424, 2098536}, []string{"unverified", "unverified"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				volume := bytes.Clone(frozen)
				for _, offset := range test.damage {
					volume[offset] ^= 1
				}
				dir := t.TempDir()
				source := writePCV3MobileFile(t, dir, "source.pcv", string(volume))
				red, blue := writePCV3MobileFile(t, dir, "red.key", "red"), writePCV3MobileFile(t, dir, "blue.key", "blue")
				target := filepath.Join(dir, "recovery.pcv3-recovery")
				password := []byte("mix")
				start := StartPCV3(pcv3TestEnvelope(test.mode, "password-and-keyfiles", "ordered", source, target, []string{red, blue}), password)
				if start == nil || start.Code() != "" || start.Operation() == nil {
					t.Fatalf("real bridge start = %#v", start)
				}
				if !allZero(password) {
					t.Fatal("bridge did not clear caller password")
				}
				operation := start.Operation()
				defer func() {
					operation.Cancel()
					if consent := operation.Consent(); consent != nil {
						_ = consent.Refuse()
					}
					synctest.Wait()
					cleanupOperation(operation.ID())
				}()
				synctest.Wait()
				if test.mode == "force-unverified-normal" {
					consent := operation.Consent()
					if consent == nil || consent.RoleCount() != 2 || consent.RoleAt(1) != "backup" {
						t.Fatal("live role-bound consent missing")
					}
					if code := consent.Choose("backup"); code != "" {
						t.Fatalf("consent rejected: %s", code)
					}
					synctest.Wait()
				}
				snapshot := operation.Snapshot()
				if snapshot.Outcome() != test.outcome || snapshot.WarningCount() != 1 || snapshot.WarningAt(0) != test.warning || snapshot.PublicationState() != "published-durable" || snapshot.ArchivePending() || operation.Archive() != nil {
					t.Fatalf("real recovery snapshot = %s", pcv3MobileSnapshotText(snapshot))
				}
				inspection := operation.ArtifactInspection()
				if inspection == nil || inspection.FinalStatus() != test.final || inspection.VerifiedCount() != test.verified || inspection.UnverifiedCount() != test.unverified || inspection.MissingCount() != "0" {
					t.Fatalf("real bridge lost independent range/final evidence: %#v", inspection)
				}
				wantRole, wantKind := "backup", "partial"
				if test.mode == "force-normal" {
					wantRole = "none"
				}
				if test.outcome == "force-unverified" {
					wantKind = "unverified-forensic"
				}
				if inspection.Role() != wantRole || inspection.Kind() != wantKind || inspection.RangeCount() != "2" || inspection.PlaintextLength() != "2097152" {
					t.Fatal("bridge lost exact consent role or artifact semantics")
				}
				page := inspection.Page("0", 2)
				if page == nil || page.Count() != 2 {
					t.Fatal("real bridge range page missing")
				}
				for index, status := range test.statuses {
					if page.StatusAt(index) != status {
						t.Fatalf("record %d status=%s; want %s", index, page.StatusAt(index), status)
					}
				}
				if page.StartAt(0) != "0" || page.EndAt(0) != "1048576" || page.StartAt(1) != "1048576" || page.EndAt(1) != "2097152" {
					t.Fatal("bridge changed frozen range boundaries")
				}
				retained, err := os.ReadFile(source)
				if err != nil || !bytes.Equal(retained, volume) {
					t.Fatal("bridge recovery changed source")
				}
				artifact, err := os.ReadFile(target)
				if err != nil || !bytes.HasPrefix(artifact, []byte("PICO-RECOVERY-3\x00")) || len(artifact) == 2097152 {
					t.Fatal("bridge recovery published ordinary plaintext")
				}
				capturePCV3RecoverySnapshot(t, test.name, snapshot, inspection)
				output := operation.Output()
				if output == nil {
					t.Fatal("real bridge lost retained artifact ownership")
				}
				if discarded := output.Discard(); discarded == nil || discarded.Code() != "discarded" {
					t.Fatal("cannot discard real retained artifact")
				}
				pcv3MobileRequireNoResidue(t, dir, []string{"blue.key", "red.key", "source.pcv"})
			})
		})
	}
}
