package mobile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
)

// pcv3MobileFixturePath locates the frozen public production-vector volume.
const pcv3MobileFixturePath = "../internal/pcv3operation/internal/pcv3/testdata/normal/volumes/normal-standard-combined-ordered-one.pcv"

// pcv3MobileObserveDescriptors records every descriptor the bridge opens
// while delegating to the real no-follow opener; it replaces nothing.
func pcv3MobileObserveDescriptors(t *testing.T) *[]*os.File {
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

func pcv3MobileRequireDescriptorsClosed(t *testing.T, opened []*os.File) {
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

// pcv3MobileSnapshotText collects every string the snapshot can render so a
// sentinel scan covers the complete bridge channel.
func pcv3MobileSnapshotText(snapshot *PCV3Snapshot) string {
	var parts []string
	parts = append(parts,
		snapshot.Outcome(), snapshot.Stage(), snapshot.Code(),
		snapshot.ForceProvenance(), snapshot.D1BootstrapProvenance(),
		snapshot.DetailStage(), snapshot.PublicationState(),
		snapshot.PublicationStage(), snapshot.PublicationCode(),
		snapshot.Diagnostic(), snapshot.CompletionClass(), snapshot.StatusCode(),
		snapshot.RestoredReceipt(), snapshot.AuthenticatedComment(),
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

func pcv3MobileRequireNoResidue(t *testing.T, directory string, keep []string) {
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

// TestPCV3MobileResultAndPrivacyBoundary drives the real gomobile bridge
// (no operation substitution) with real envelopes and proves the mobile
// surface consumes the same closed operation result: exact snapshot axes, no
// frontend crypto or result decisions, descriptor/password ownership, and the
// unconfigured Android policy contract. Host-native bridge success is not
// physical Android execution or Android support evidence.
func TestPCV3MobileResultAndPrivacyBoundary(t *testing.T) {
	t.Run("host-native success retains exactly one output capability without Android support evidence", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			temp := t.TempDir()
			red := writePCV3MobileFile(t, temp, "red.key", "red")
			blue := writePCV3MobileFile(t, temp, "blue.key", "blue")
			target := filepath.Join(temp, "plain.txt")
			opened := pcv3MobileObserveDescriptors(t)

			password := []byte("mix")
			start := StartPCV3(
				pcv3TestEnvelope(
					"read-normal", "password-and-keyfiles", "ordered",
					pcv3MobileFixturePath, target, []string{red, blue},
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
			if snapshot.Outcome() != "success" ||
				snapshot.Stage() != "none" ||
				snapshot.Code() != "PCV3_SUCCESS" ||
				snapshot.Diagnostic() != "none" ||
				snapshot.CompletionClass() != "clean" ||
				!snapshot.PublicationAttempted() ||
				snapshot.AuthenticatedComment() != "TEST ONLY comment" ||
				snapshot.PublicationState() != "published-durable" ||
				snapshot.PublicationStage() != "none" ||
				snapshot.PublicationCode() != "PCV3_PUBLICATION_PUBLISHED_DURABLE" ||
				snapshot.WarningCount() != 0 ||
				snapshot.ArchivePending() {
				t.Fatalf(
					"host-native snapshot = %s/%s/%s diagnostic=%s class=%s publication=%v/%s/%s warnings=%d pending=%v; want the exact durable success",
					snapshot.Outcome(), snapshot.Stage(), snapshot.Code(),
					snapshot.Diagnostic(), snapshot.CompletionClass(),
					snapshot.PublicationAttempted(), snapshot.PublicationState(),
					snapshot.PublicationCode(), snapshot.WarningCount(), snapshot.ArchivePending(),
				)
			}
			output := operation.Output()
			if output == nil || operation.Archive() != nil ||
				operation.ArtifactInspection() != nil {
				t.Fatal("durable bridge operation did not retain exactly its output authority")
			}
			if challenge := operation.ResourceChallenge(); challenge != nil {
				t.Fatal("host-native completed operation exposed an Android resource challenge")
			}
			if got := PCV3AndroidPolicyState(); got != "unconfigured" {
				t.Fatalf("PCV3AndroidPolicyState() = %q; want exact unconfigured Android policy", got)
			}
			pcv3MobileRequireDescriptorsClosed(t, *opened)
			info, err := os.Lstat(target)
			if err != nil {
				t.Fatalf("durable bridge output missing: %v", err)
			}
			if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
				t.Fatalf("durable bridge output mode = %s; want regular mode-0600", info.Mode())
			}
			plaintext, err := os.ReadFile(target)
			if err != nil {
				t.Fatalf("read durable bridge output: %v", err)
			}
			if len(plaintext) != 1 || plaintext[0] != 0x02 {
				t.Fatalf("durable bridge plaintext = %x; want exact frozen byte 02", plaintext)
			}
			pcv3MobileRequireNoResidue(t, temp, []string{"blue.key", "plain.txt", "red.key"})
			if code := operation.Release(); code != pcv3OperationReleaseDenied {
				t.Fatalf("release with live output = %q; want release denied", code)
			}
			if discarded := output.Discard(); discarded == nil || discarded.Code() != "discarded" || discarded.CleanupIncomplete() {
				t.Fatalf("durable output discard = %#v; want exact clean discard", discarded)
			}
			if again := output.Discard(); again == nil || again.Code() != "expired" || again.CleanupIncomplete() {
				t.Fatalf("reused durable output discard = %#v; want one-shot expiration", again)
			}
			if _, err := os.Lstat(target); !os.IsNotExist(err) {
				t.Fatalf("discarded bridge output remained at target: %v", err)
			}
			pcv3MobileRequireNoResidue(t, temp, []string{"blue.key", "red.key"})
			if code := operation.Release(); code != "" {
				t.Fatalf("release after output discard = %q; want consumed release", code)
			}
			if code := operation.Release(); code != pcv3OperationReleaseDenied {
				t.Fatalf("second release = %q; want release denied", code)
			}
		})
	})

	t.Run("secret credentials and sentinel paths never reach bridge channels", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			base := t.TempDir()
			temp := filepath.Join(base, "privacy-mobile-path-51b0e2")
			if err := os.Mkdir(temp, 0o700); err != nil {
				t.Fatalf("create sentinel directory: %v", err)
			}
			fixture, err := os.ReadFile(pcv3MobileFixturePath)
			if err != nil {
				t.Fatalf("read frozen source fixture: %v", err)
			}
			source := writePCV3MobileFile(t, temp, "source-privacy-mobile-source-8a81a4.pcv", string(fixture))
			red := writePCV3MobileFile(t, temp, "keyfile-privacy-mobile-red-1d5ee8.key", "red")
			blue := writePCV3MobileFile(t, temp, "keyfile-privacy-mobile-blue-6e1387.key", "blue")
			target := filepath.Join(temp, "target-privacy-mobile-output-93c7d4.txt")
			secret := "privacy-mobile-secret-7d21c94af0"
			opened := pcv3MobileObserveDescriptors(t)

			password := []byte(secret)
			start := StartPCV3(
				pcv3TestEnvelope(
					"read-normal", "password-and-keyfiles", "ordered",
					source, target, []string{red, blue},
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
			if snapshot.Outcome() != "credentials-or-damage" ||
				snapshot.Stage() != "wrap-auth" ||
				snapshot.Code() != "PCV3_CREDENTIALS_OR_DAMAGE" ||
				snapshot.Diagnostic() != "none" ||
				snapshot.CompletionClass() != "no-output" ||
				snapshot.PublicationAttempted() ||
				snapshot.PublicationState() != "none" ||
				snapshot.PublicationStage() != "none" ||
				snapshot.PublicationCode() != "none" ||
				snapshot.WarningCount() != 0 ||
				snapshot.ArchivePending() {
				t.Fatalf(
					"privacy snapshot = %s/%s/%s diagnostic=%s class=%s publication=%v/%s/%s warnings=%d pending=%v; want exact credentials-or-damage",
					snapshot.Outcome(), snapshot.Stage(), snapshot.Code(),
					snapshot.Diagnostic(), snapshot.CompletionClass(),
					snapshot.PublicationAttempted(), snapshot.PublicationState(), snapshot.PublicationCode(),
					snapshot.WarningCount(), snapshot.ArchivePending(),
				)
			}
			if snapshot.AuthenticatedComment() != "" {
				t.Fatalf("failed authentication exposed comment %q", snapshot.AuthenticatedComment())
			}
			rendered := pcv3MobileSnapshotText(snapshot)
			for _, sensitive := range []string{
				secret,
				source, filepath.Base(source),
				red, filepath.Base(red),
				blue, filepath.Base(blue),
				target, filepath.Base(target),
			} {
				if strings.Contains(rendered, sensitive) {
					t.Fatalf("bridge channels disclosed sensitive sentinel %q: %q", sensitive, rendered)
				}
			}
			if operation.Output() != nil || operation.Archive() != nil || operation.ArtifactInspection() != nil {
				t.Fatal("credentials-or-damage bridge operation retained output, archive, or inspection authority")
			}
			pcv3MobileRequireDescriptorsClosed(t, *opened)
			if _, err := os.Lstat(target); !os.IsNotExist(err) {
				t.Fatalf("credentials-or-damage bridge operation created output: %v", err)
			}
			pcv3MobileRequireNoResidue(t, temp, []string{
				"keyfile-privacy-mobile-blue-6e1387.key",
				"keyfile-privacy-mobile-red-1d5ee8.key",
				"source-privacy-mobile-source-8a81a4.pcv",
			})
			if code := operation.Release(); code != "" {
				t.Fatalf("privacy release = %q; want consumed release", code)
			}
			if code := operation.Release(); code != pcv3OperationReleaseDenied {
				t.Fatalf("second privacy release = %q; want release denied", code)
			}
		})
	})

	t.Run("invalid claimed structure refuses before KDF with the exact snapshot", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			temp := t.TempDir()
			source := writePCV3MobileFile(t, temp, "claimed.pcv", "PCV\x00")
			target := filepath.Join(temp, "plain.txt")
			opened := pcv3MobileObserveDescriptors(t)

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
			if snapshot.AuthenticatedComment() != "" {
				t.Fatalf("invalid structure exposed comment %q", snapshot.AuthenticatedComment())
			}
			pcv3MobileRequireDescriptorsClosed(t, *opened)
			if _, err := os.Lstat(target); !os.IsNotExist(err) {
				t.Fatalf("invalid structure created output: %v", err)
			}
			if code := operation.Release(); code != "" {
				t.Fatalf("structural release = %q", code)
			}
		})
	})
}
