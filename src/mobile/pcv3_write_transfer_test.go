//go:build android || linux

package mobile

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"
)

// TestPCV3MobileWriteNormalRoundTrip proves a volume created through the
// bridge write path decrypts byte-exact through the existing bridge read path,
// including the retained-output SAF FD transfer and the public comment.
// Protects on-disk compatibility of bridge-created volumes. Host-native
// success is not physical Android execution evidence.
func TestPCV3MobileWriteNormalRoundTrip(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		temp := t.TempDir()
		payload := []byte("bridge created this exact payload\x00\x01\x02")
		source := filepath.Join(temp, "plain.bin")
		if err := os.WriteFile(source, payload, 0o600); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(temp, "created.pcv")
		opened := pcv3MobileObserveDescriptors(t)

		password := []byte("correct horse battery staple")
		start := StartPCV3(
			pcv3WriteTestEnvelope(
				"write-normal", "password", "none", "standard", true,
				"bridge-created comment", source, target, nil,
			),
			password,
		)
		if start == nil || start.Code() != "" || start.Operation() == nil {
			t.Fatalf("write start = %#v", start)
		}
		if !allZero(password) {
			t.Fatal("caller password was not zeroed")
		}
		operation := start.Operation()
		t.Cleanup(func() { cleanupOperation(operation.ID()) })
		synctest.Wait()

		snapshot := operation.Snapshot()
		skipOnPCV3ResourceAdmissionDenial(t, snapshot)
		if snapshot.Outcome() != "success" || snapshot.Stage() != "none" ||
			snapshot.Code() != "PCV3_SUCCESS" || snapshot.Diagnostic() != "none" ||
			snapshot.CompletionClass() != "clean" || !snapshot.PublicationAttempted() ||
			snapshot.PublicationState() != "published-durable" ||
			snapshot.PublicationStage() != "none" ||
			snapshot.PublicationCode() != "PCV3_PUBLICATION_PUBLISHED_DURABLE" ||
			snapshot.WarningCount() != 0 || snapshot.ArchivePending() {
			t.Fatalf("creation snapshot = %s", pcv3MobileSnapshotText(snapshot))
		}
		output := operation.Output()
		if output == nil {
			t.Fatal("durable creation retained no output authority")
		}
		if code := operation.Release(); code != pcv3OperationReleaseDenied {
			t.Fatalf("release with live write output = %q", code)
		}

		// SAF transfer: the created volume moves to an Android-owned
		// descriptor, transferred as a duplicate like the SAF contract.
		savedName := filepath.Join(temp, "saved.pcv")
		saved, err := os.OpenFile(savedName, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = saved.Close() })
		savedFD := duplicateMobileTransferredFD(t, saved)
		savedResult := output.SaveFD(savedFD)
		if savedResult == nil || savedResult.Code() != "saved" || savedResult.CleanupIncomplete() {
			t.Fatalf("write output SaveFD = %#v", savedResult)
		}
		assertMobileTransferredFDClosed(t, savedFD)
		if savedResult == nil || savedResult.Code() != "saved" || savedResult.CleanupIncomplete() {
			t.Fatalf("write output SaveFD = %#v", savedResult)
		}
		if again := output.Discard(); again == nil || again.Code() != "expired" {
			t.Fatalf("reused write output = %#v; want one-shot expiration", again)
		}
		if _, err := os.Lstat(target); !os.IsNotExist(err) {
			t.Fatalf("saved created volume remained at staging target: %v", err)
		}
		if code := operation.Release(); code != "" {
			t.Fatalf("creation release = %q", code)
		}

		// The existing read path must decrypt the bridge-created volume
		// byte-exact, including its public comment.
		readTarget := filepath.Join(temp, "roundtrip.bin")
		readPassword := []byte("correct horse battery staple")
		read := StartPCV3(
			pcv3TestEnvelope("read-normal", "password", "none", savedName, readTarget, nil),
			readPassword,
		)
		if read == nil || read.Code() != "" || read.Operation() == nil {
			t.Fatalf("read start = %#v", read)
		}
		readOperation := read.Operation()
		t.Cleanup(func() { cleanupOperation(readOperation.ID()) })
		synctest.Wait()
		readSnapshot := readOperation.Snapshot()
		skipOnPCV3ResourceAdmissionDenial(t, readSnapshot)
		if readSnapshot.Outcome() != "success" || readSnapshot.CompletionClass() != "clean" {
			t.Fatalf("round-trip read snapshot = %s", pcv3MobileSnapshotText(readSnapshot))
		}
		if readSnapshot.AuthenticatedComment() != "bridge-created comment" {
			t.Fatalf("round-trip comment = %q", readSnapshot.AuthenticatedComment())
		}
		plaintext, err := os.ReadFile(readTarget)
		if err != nil {
			t.Fatalf("read round-trip plaintext: %v", err)
		}
		if !bytes.Equal(plaintext, payload) {
			t.Fatalf("round-trip plaintext = %x; want %x", plaintext, payload)
		}
		readOutput := readOperation.Output()
		if readOutput == nil {
			t.Fatal("round-trip read retained no output authority")
		}
		if discarded := readOutput.Discard(); discarded == nil || discarded.Code() != "discarded" {
			t.Fatalf("round-trip read output discard = %#v", discarded)
		}
		if code := readOperation.Release(); code != "" {
			t.Fatalf("round-trip read release = %q", code)
		}
		pcv3MobileRequireDescriptorsClosed(t, *opened)
	})
}
