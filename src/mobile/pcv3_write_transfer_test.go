//go:build android || linux

package mobile

import (
	"Picocrypt-NG/internal/pcv3operation"
	"bytes"
	"context"
	"encoding/json"
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

		originalCiphertext, err := os.ReadFile(target)
		if err != nil {
			t.Fatal(err)
		}
		// Unsupported transport must preserve the exact native output for retry.
		failed := output.SaveFD(-1)
		if failed == nil || failed.Code() != "save-failed" || failed.CleanupIncomplete() {
			t.Fatalf("failed transport = %#v", failed)
		}
		if operation.Output() == nil || operation.Release() != pcv3OperationReleaseDenied {
			t.Fatal("failed ciphertext save lost its retained authority")
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
		savedCiphertext, err := os.ReadFile(savedName)
		if err != nil || !bytes.Equal(savedCiphertext, originalCiphertext) {
			t.Fatalf("retry changed ciphertext: %v", err)
		}

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

// TestPCV3MobileWriteD1KeyfilesOnlyRoundTrip proves bridge D1 creation runs
// the fixed paranoid suite, accepts keyfile-only credentials, retains the exact
// ciphertext through a failed transfer and a successful retry, and decrypts byte-exact through the existing read-d1 path.
// Protects D1 creation parity and the keyfile-only D1 policy.
func TestPCV3MobileWriteD1KeyfilesOnlyRoundTrip(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		temp := t.TempDir()
		payload := []byte("d1 keyfile-only bridge payload")
		source := filepath.Join(temp, "plain.bin")
		if err := os.WriteFile(source, payload, 0o600); err != nil {
			t.Fatal(err)
		}
		keyA := writePCV3MobileFile(t, temp, "a.key", "alpha")
		keyB := writePCV3MobileFile(t, temp, "b.key", "bravo")
		target := filepath.Join(temp, "volume.bin")
		opened := pcv3MobileObserveDescriptors(t)

		start := StartPCV3(
			pcv3WriteTestEnvelope(
				"write-d1", "keyfiles", "ordered", "paranoid", false,
				"", source, target, []string{keyA, keyB},
			),
			[]byte{},
		)
		if start == nil || start.Code() != "" || start.Operation() == nil {
			t.Fatalf("d1 write start = %#v", start)
		}
		operation := start.Operation()
		t.Cleanup(func() { cleanupOperation(operation.ID()) })
		synctest.Wait()

		snapshot := operation.Snapshot()
		if snapshot.Outcome() != "success" || snapshot.Stage() != "none" ||
			snapshot.Code() != "PCV3_SUCCESS" || snapshot.Diagnostic() != "none" ||
			snapshot.CompletionClass() != "clean" || !snapshot.PublicationAttempted() ||
			snapshot.PublicationState() != "published-durable" ||
			snapshot.WarningCount() != 0 || snapshot.ArchivePending() {
			t.Fatalf("d1 creation snapshot = %s", pcv3MobileSnapshotText(snapshot))
		}
		target = requirePCV3CiphertextRetry(t, operation, target)
		if code := operation.Release(); code != "" {
			t.Fatalf("d1 creation release = %q", code)
		}

		readTarget := filepath.Join(temp, "roundtrip.bin")
		read := StartPCV3(
			pcv3TestEnvelope("read-d1", "keyfiles", "ordered", target, readTarget, []string{keyA, keyB}),
			[]byte{},
		)
		if read == nil || read.Code() != "" || read.Operation() == nil {
			t.Fatalf("d1 read start = %#v", read)
		}
		readOperation := read.Operation()
		t.Cleanup(func() { cleanupOperation(readOperation.ID()) })
		synctest.Wait()
		readSnapshot := readOperation.Snapshot()
		if readSnapshot.Outcome() != "success" || readSnapshot.CompletionClass() != "clean" {
			t.Fatalf("d1 round-trip read snapshot = %s", pcv3MobileSnapshotText(readSnapshot))
		}
		plaintext, err := os.ReadFile(readTarget)
		if err != nil {
			t.Fatalf("read d1 round-trip plaintext: %v", err)
		}
		if !bytes.Equal(plaintext, payload) {
			t.Fatalf("d1 round-trip plaintext = %x; want %x", plaintext, payload)
		}
		readOutput := readOperation.Output()
		if readOutput == nil {
			t.Fatal("d1 round-trip read retained no output authority")
		}
		if discarded := readOutput.Discard(); discarded == nil || discarded.Code() != "discarded" {
			t.Fatalf("d1 round-trip read output discard = %#v", discarded)
		}
		if code := readOperation.Release(); code != "" {
			t.Fatalf("d1 round-trip read release = %q", code)
		}
		pcv3MobileRequireDescriptorsClosed(t, *opened)
	})
}

func requirePCV3CiphertextRetry(t *testing.T, operation *PCV3Operation, target string) string {
	t.Helper()
	original, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	output := operation.Output()
	if output == nil {
		t.Fatal("created ciphertext has no retained output")
	}
	failed := output.SaveFD(-1)
	if failed.Code() != "save-failed" || failed.CleanupIncomplete() || operation.Output() == nil {
		t.Fatalf("failed save lost ciphertext capability: %v", failed)
	}
	savedName := target + ".saved"
	saved, err := os.Create(savedName)
	if err != nil {
		t.Fatal(err)
	}
	defer saved.Close()
	fd := duplicateMobileTransferredFD(t, saved)
	result := output.SaveFD(fd)
	assertMobileTransferredFDClosed(t, fd)
	if result.Code() != "saved" || result.CleanupIncomplete() {
		t.Fatalf("retry = %v", result)
	}
	copied, err := os.ReadFile(savedName)
	if err != nil || !bytes.Equal(copied, original) {
		t.Fatalf("ciphertext changed: %v", err)
	}
	if output.Discard().Code() != "expired" || operation.Output() != nil {
		t.Fatal("consumed output reused")
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("internal output retained: %v", err)
	}
	return savedName
}

// Exercises real bridge archive creation, ciphertext retry, and shared archive
// extraction. The independent file bytes catch encrypting the encrypted ZIP
// staging bytes instead of its decrypted logical reader.
func TestPCV3MobileFolderWriteRetainsArchiveAndExtractsOriginalBytes(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		dir := t.TempDir()
		tree := filepath.Join(dir, "tree")
		if err := os.Mkdir(tree, 0o700); err != nil {
			t.Fatal(err)
		}
		files := []string{writePCV3MobileFile(t, tree, "a.txt", "first original plaintext"), writePCV3MobileFile(t, tree, "b.txt", "second original plaintext")}
		target := filepath.Join(dir, "created.pcv")
		var wire map[string]any
		if err := json.Unmarshal([]byte(pcv3WriteTestEnvelope("write-normal", "password", "none", "standard", false, "", files[0], target, nil)), &wire); err != nil {
			t.Fatal(err)
		}
		wire["inputFiles"] = files
		wire["onlyFiles"] = []string{}
		wire["onlyFolders"] = []string{tree}
		wire["compress"] = true
		encoded, err := json.Marshal(wire)
		if err != nil {
			t.Fatal(err)
		}
		password := []byte("folder test password")
		start := StartPCV3(string(encoded), password)
		if start.Code() != "" || start.Operation() == nil {
			t.Fatalf("start=%v", start)
		}
		if !allZero(password) {
			t.Fatal("caller credential retained")
		}
		operation := start.Operation()
		defer cleanupOperation(operation.ID())
		synctest.Wait()
		if snapshot := operation.Snapshot(); snapshot.CompletionClass() != "clean" {
			t.Fatalf("write=%s", pcv3MobileSnapshotText(snapshot))
		}
		saved := requirePCV3CiphertextRetry(t, operation, target)
		if operation.Release() != "" {
			t.Fatal("write release refused")
		}
		source, err := os.Open(saved)
		if err != nil {
			t.Fatal(err)
		}
		defer source.Close()
		result := pcv3operation.Run(context.Background(), &pcv3operation.Request{
			Mode: pcv3operation.ModeReadNormal, Source: source, Target: filepath.Join(dir, "decoded"),
			Factors: &pcv3operation.FactorRequest{Mode: pcv3operation.CredentialModePasswordOnly, KeyfileMode: pcv3operation.KeyfileModeNone, ExpectedPolicy: pcv3operation.FactorPolicyPasswordOnly, Password: []byte("folder test password")},
		})
		follow := result.ArchiveFollowUp()
		if follow == nil {
			t.Fatalf("archive not authenticated: %v", result)
		}
		defer follow.Close()
		destination := filepath.Join(dir, "extracted")
		if err := os.Mkdir(destination, 0o700); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(destination)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		extracted := follow.Extract(context.Background(), root)
		if extracted.CompletionClass() != pcv3operation.CompletionClean {
			t.Fatalf("extract=%v", extracted)
		}
		for _, file := range files {
			want, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(filepath.Join(destination, "tree", filepath.Base(file)))
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("extracted %s differs: %v", filepath.Base(file), err)
			}
		}
	})
}
