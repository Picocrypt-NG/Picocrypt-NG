package mobile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
)

// phase9MobileFixturePath locates the frozen public production-vector volume.
const phase9MobileFixturePath = "../internal/pcv3/testdata/normal/volumes/normal-standard-combined-ordered-one.pcv"

// phase9MobileObserveDescriptors records every descriptor the bridge opens
// while delegating to the real no-follow opener; it replaces nothing.
func phase9MobileObserveDescriptors(t *testing.T) *[]*os.File {
	t.Helper()
	var opened []*os.File
	original := openPCV3Existing
	openPCV3Existing = func(path string, flag int) (*os.File, error) {
		file, err := original(path, flag)
		if err == nil {
			opened = append(opened, file)
		}
		return file, err
	}
	t.Cleanup(func() { openPCV3Existing = original })
	return &opened
}

func phase9MobileRequireDescriptorsClosed(t *testing.T, opened []*os.File) {
	t.Helper()
	if len(opened) == 0 {
		t.Fatal("bridge opened no descriptors; the ownership oracle is vacuous")
	}
	for _, file := range opened {
		if _, err := file.Stat(); err == nil {
			t.Fatalf("transferred descriptor %q remained open", file.Name())
		}
	}
}

// phase9MobileSnapshotText collects every string the snapshot can render so a
// sentinel scan covers the complete bridge channel.
func phase9MobileSnapshotText(snapshot *PCV3Snapshot) string {
	var parts []string
	parts = append(parts,
		snapshot.Outcome(), snapshot.Stage(), snapshot.Code(),
		snapshot.ForceProvenance(), snapshot.D1BootstrapProvenance(),
		snapshot.DetailStage(), snapshot.PublicationState(),
		snapshot.PublicationStage(), snapshot.PublicationCode(),
		snapshot.Diagnostic(), snapshot.CompletionClass(), snapshot.StatusCode(),
	)
	for index := range snapshot.WarningCount() {
		parts = append(parts, snapshot.WarningAt(index))
	}
	for index := range snapshot.ArgCount() {
		parts = append(parts, snapshot.ArgAt(index))
	}
	for index := range snapshot.StatusArgCount() {
		parts = append(parts, snapshot.StatusArgAt(index))
	}
	return strings.Join(parts, "|")
}

func phase9MobileRequireNoResidue(t *testing.T, directory string, keep []string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("inspect bridge directory: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".picocrypt-pcv3-") {
			t.Fatalf("bridge left publication stage residue %q", entry.Name())
		}
	}
	if len(entries) != len(keep) {
		t.Fatalf("bridge directory entries = %v; want exactly %v", entries, keep)
	}
	for index, name := range keep {
		if entries[index].Name() != name {
			t.Fatalf("bridge directory entries = %v; want exactly %v", entries, keep)
		}
	}
}

// TestPhase9MobileResultAndPrivacyBoundary drives the real gomobile bridge
// (no operation substitution) with real envelopes and proves the mobile
// surface consumes the same closed operation result: exact snapshot axes, no
// frontend crypto or result decisions, descriptor/password ownership, and the
// fail-closed unconfigured Android contract. On this host the production
// desktop resource admission fails closed before derivation (the cgroup v2
// root exposes no memory controller files), so admitted real cases terminate
// with the exact resource-unknown refusal; the fixed-profile success tuples
// are owned by the pcv3operation matrix.
func TestPhase9MobileResultAndPrivacyBoundary(t *testing.T) {
	t.Run("real fail-closed operation maps the exact closed result and preserves the unconfigured contract", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			temp := t.TempDir()
			red := writePCV3MobileFile(t, temp, "red.key", "red")
			blue := writePCV3MobileFile(t, temp, "blue.key", "blue")
			target := filepath.Join(temp, "plain.txt")
			opened := phase9MobileObserveDescriptors(t)

			password := []byte("mix")
			start := StartPCV3(
				pcv3TestEnvelope(
					"read-normal", "password-and-keyfiles", "ordered",
					phase9MobileFixturePath, target, []string{red, blue},
				),
				password,
			)
			if start == nil || start.Code() != "" || start.Operation() == nil {
				t.Fatalf("valid start = %#v", start)
			}
			if !allZero(password) {
				t.Fatal("bridge retained the caller password after StartPCV3 returned")
			}
			operation := start.Operation()
			t.Cleanup(func() { cleanupOperation(operation.ID()) })
			synctest.Wait()

			snapshot := operation.Snapshot()
			if snapshot.Outcome() != "operation-failed" ||
				snapshot.Stage() != "credential-policy" ||
				snapshot.Code() != "PCV3_OPERATION_FAILED" ||
				snapshot.Diagnostic() != "resource-unknown" ||
				snapshot.CompletionClass() != "refused" ||
				snapshot.PublicationAttempted() ||
				snapshot.PublicationState() != "none" ||
				snapshot.PublicationCode() != "none" ||
				snapshot.WarningCount() != 0 ||
				snapshot.ArchivePending() {
				t.Fatalf(
					"real bridge snapshot = %s/%s/%s diagnostic=%s class=%s publication=%v/%s/%s warnings=%d pending=%v; want the exact resource refusal",
					snapshot.Outcome(), snapshot.Stage(), snapshot.Code(),
					snapshot.Diagnostic(), snapshot.CompletionClass(),
					snapshot.PublicationAttempted(), snapshot.PublicationState(),
					snapshot.PublicationCode(), snapshot.WarningCount(), snapshot.ArchivePending(),
				)
			}
			if operation.Output() != nil || operation.Archive() != nil ||
				operation.ArtifactInspection() != nil {
				t.Fatal("refused bridge operation retained output, archive, or inspection authority")
			}
			if challenge := operation.ResourceChallenge(); challenge != nil {
				t.Fatal("unconfigured operation exposed a resource challenge")
			}
			if got := PCV3AndroidPolicyState(); got != "unconfigured" {
				t.Fatalf("PCV3AndroidPolicyState() = %q; want the exact fail-closed state", got)
			}
			phase9MobileRequireDescriptorsClosed(t, *opened)
			if _, err := os.Lstat(target); !os.IsNotExist(err) {
				t.Fatalf("refused bridge operation created output: %v", err)
			}
			phase9MobileRequireNoResidue(t, temp, []string{"blue.key", "red.key"})
			if code := operation.Release(); code != "" {
				t.Fatalf("terminal release = %q; want consumed release", code)
			}
			if snapshot := operation.Snapshot(); snapshot.CompletionClass() != "unknown" {
				t.Fatalf("post-release snapshot class = %q; want unknown", snapshot.CompletionClass())
			}
			if code := operation.Release(); code != pcv3OperationReleaseDenied {
				t.Fatalf("second release = %q; want release denied", code)
			}
		})
	})

	t.Run("secret credentials and sentinel paths never reach bridge channels", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			base := t.TempDir()
			temp := filepath.Join(base, "p9mobile-path-51b0e2")
			if err := os.Mkdir(temp, 0o700); err != nil {
				t.Fatalf("create sentinel directory: %v", err)
			}
			red := writePCV3MobileFile(t, temp, "red.key", "red")
			blue := writePCV3MobileFile(t, temp, "blue.key", "blue")
			target := filepath.Join(temp, "plain.txt")
			secret := "p9mobile-secret-7d21c94af0"
			opened := phase9MobileObserveDescriptors(t)

			password := []byte(secret)
			start := StartPCV3(
				pcv3TestEnvelope(
					"read-normal", "password-and-keyfiles", "ordered",
					phase9MobileFixturePath, target, []string{red, blue},
				),
				password,
			)
			if start == nil || start.Code() != "" || start.Operation() == nil {
				t.Fatalf("valid start = %#v", start)
			}
			if !allZero(password) {
				t.Fatal("bridge retained the secret caller password after StartPCV3 returned")
			}
			operation := start.Operation()
			t.Cleanup(func() { cleanupOperation(operation.ID()) })
			synctest.Wait()

			snapshot := operation.Snapshot()
			if snapshot.Outcome() != "operation-failed" ||
				snapshot.Diagnostic() != "resource-unknown" ||
				snapshot.CompletionClass() != "refused" {
				t.Fatalf(
					"privacy snapshot = %s diagnostic=%s class=%s; want the exact resource refusal",
					snapshot.Outcome(), snapshot.Diagnostic(), snapshot.CompletionClass(),
				)
			}
			rendered := phase9MobileSnapshotText(snapshot)
			if strings.Contains(rendered, secret) || strings.Contains(rendered, "p9mobile-path-51b0e2") {
				t.Fatalf("bridge channels disclosed secret or path sentinel: %q", rendered)
			}
			phase9MobileRequireDescriptorsClosed(t, *opened)
			if _, err := os.Lstat(target); !os.IsNotExist(err) {
				t.Fatalf("refused bridge operation created output: %v", err)
			}
			if code := operation.Release(); code != "" {
				t.Fatalf("privacy release = %q", code)
			}
		})
	})

	t.Run("invalid claimed structure refuses before KDF with the exact snapshot", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			temp := t.TempDir()
			source := writePCV3MobileFile(t, temp, "claimed.pcv", "PCV\x00")
			target := filepath.Join(temp, "plain.txt")
			opened := phase9MobileObserveDescriptors(t)

			password := []byte("structural")
			start := StartPCV3(
				pcv3TestEnvelope("read-normal", "password", "none", source, target, nil),
				password,
			)
			if start == nil || start.Code() != "" || start.Operation() == nil {
				t.Fatalf("valid start = %#v", start)
			}
			if !allZero(password) {
				t.Fatal("bridge retained the caller password")
			}
			operation := start.Operation()
			t.Cleanup(func() { cleanupOperation(operation.ID()) })
			synctest.Wait()

			snapshot := operation.Snapshot()
			if snapshot.Outcome() != "invalid-structure-pre-kdf" ||
				snapshot.Stage() != "preamble" ||
				snapshot.Code() != "PCV3_INVALID_STRUCTURE" ||
				snapshot.Diagnostic() != "none" ||
				snapshot.CompletionClass() != "no-output" ||
				snapshot.PublicationAttempted() ||
				snapshot.WarningCount() != 0 {
				t.Fatalf(
					"invalid-structure snapshot = %s/%s/%s diagnostic=%s class=%s attempted=%v warnings=%d; want the exact structural refusal",
					snapshot.Outcome(), snapshot.Stage(), snapshot.Code(),
					snapshot.Diagnostic(), snapshot.CompletionClass(),
					snapshot.PublicationAttempted(), snapshot.WarningCount(),
				)
			}
			phase9MobileRequireDescriptorsClosed(t, *opened)
			if _, err := os.Lstat(target); !os.IsNotExist(err) {
				t.Fatalf("invalid structure created output: %v", err)
			}
			if code := operation.Release(); code != "" {
				t.Fatalf("structural release = %q", code)
			}
		})
	})
}
