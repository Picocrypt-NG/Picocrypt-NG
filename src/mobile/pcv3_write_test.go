package mobile

import (
	"Picocrypt-NG/internal/pcv3"
	"Picocrypt-NG/internal/pcv3credential"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
)

// pcv3WriteTestEnvelope builds one exact write-shaped creation envelope.
func pcv3WriteTestEnvelope(
	mode, policy, order, suite string,
	payloadRS bool,
	comment, source, target string,
	keyfiles []string,
) string {
	quotedKeys := make([]string, len(keyfiles))
	for i, path := range keyfiles {
		quotedKeys[i] = fmt.Sprintf("%q", path)
	}
	return fmt.Sprintf(
		`{"version":1,"mode":%q,"factorPolicy":%q,"keyfileOrder":%q,"source":%q,"target":%q,"keyfiles":[%s],"comment":%q,"suite":%q,"payloadRS":%t}`,
		mode, policy, order, source, target, strings.Join(quotedKeys, ","), comment, suite, payloadRS,
	)
}

// TestPCV3MobileWriteEnvelopeShape pins the new creation contract: write modes
// are accepted only in their exact valid shape, and every malformed or
// policy-violating shape is refused deterministically before any descriptor is
// opened, any KDF runs, or any output appears. Protects the bridge's
// fail-closed admission boundary against malformed creation requests.
func TestPCV3MobileWriteEnvelopeShape(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		temp := t.TempDir()
		source := writePCV3MobileFile(t, temp, "plain.bin", "payload")
		keyfile := writePCV3MobileFile(t, temp, "factor.key", "keyfile")
		target := filepath.Join(temp, "volume.pcv")
		valid := pcv3WriteTestEnvelope(
			"write-normal", "password", "none", "standard", false, "", source, target, nil,
		)

		var openCalls atomic.Int64
		oldOpen := openPCV3Existing
		openPCV3Existing = func(path string, flag int) (*os.File, error) {
			openCalls.Add(1)
			return oldOpen(path, flag)
		}
		t.Cleanup(func() { openPCV3Existing = oldOpen })

		var writeCalls atomic.Int64
		oldWrite := runPCV3NativeNormalWrite
		runPCV3NativeNormalWrite = func(context.Context, *pcv3.NativeNormalWriteRequest) error {
			writeCalls.Add(1)
			return nil
		}
		t.Cleanup(func() { runPCV3NativeNormalWrite = oldWrite })

		requiredCases := map[string]struct{}{
			"missing-comment": {}, "missing-suite": {}, "missing-payloadrs": {},
			"d1-requires-paranoid": {}, "unknown-suite": {}, "comment-wrong-type": {},
			"comment-null": {}, "payloadrs-wrong-type": {}, "factor-mismatch": {},
			"keyfile-policy-without-keyfiles": {}, "write-field-on-read-mode": {},
		}
		cases := map[string]string{
			"missing-comment":   strings.Replace(valid, `,"comment":""`, "", 1),
			"missing-suite":     strings.Replace(valid, `,"suite":"standard"`, "", 1),
			"missing-payloadrs": strings.Replace(valid, `,"payloadRS":false`, "", 1),
			"d1-requires-paranoid": strings.Replace(
				valid, `"mode":"write-normal"`, `"mode":"write-d1"`, 1,
			),
			"unknown-suite":      strings.Replace(valid, `"suite":"standard"`, `"suite":"double"`, 1),
			"comment-wrong-type": strings.Replace(valid, `"comment":""`, `"comment":7`, 1),
			"comment-null":       strings.Replace(valid, `"comment":""`, `"comment":null`, 1),
			"payloadrs-wrong-type": strings.Replace(
				valid, `"payloadRS":false`, `"payloadRS":"yes"`, 1,
			),
			"factor-mismatch": strings.Replace(
				valid, `"keyfiles":[]`, fmt.Sprintf(`"keyfiles":[%q]`, keyfile), 1,
			),
			"keyfile-policy-without-keyfiles": strings.Replace(
				valid, `"factorPolicy":"password"`, `"factorPolicy":"keyfiles"`, 1,
			),
			"write-field-on-read-mode": strings.Replace(
				valid, `"mode":"write-normal"`, `"mode":"read-normal"`, 1,
			),
		}
		if len(cases) != len(requiredCases) {
			t.Fatalf("write failure case inventory changed: got %d, want %d", len(cases), len(requiredCases))
		}
		for id := range requiredCases {
			request, ok := cases[id]
			if !ok {
				t.Fatalf("required write failure case %q is not executed", id)
			}
			password := []byte("correct horse battery staple")
			start := StartPCV3(request, password)
			if start == nil || start.Code() != pcv3BridgeInvalidRequest || start.Operation() != nil {
				t.Fatalf("%s: strict write rejection = %#v", id, start)
			}
			if !allZero(password) {
				t.Fatalf("%s: caller password was not zeroed synchronously", id)
			}
			if got := openCalls.Load(); got != 0 {
				t.Fatalf("%s: invalid write envelope opened %d files", id, got)
			}
			if got := writeCalls.Load(); got != 0 {
				t.Fatalf("%s: invalid write envelope reached the native writer %d times", id, got)
			}
			if _, err := os.Stat(target); !os.IsNotExist(err) {
				t.Fatalf("%s: invalid write envelope affected output: %v", id, err)
			}
		}

		// Empty credentials are refused synchronously: password policy with an
		// empty password never reaches the boundary.
		password := []byte{}
		start := StartPCV3(valid, password)
		if start == nil || start.Code() != pcv3BridgeInvalidRequest || start.Operation() != nil {
			t.Fatalf("empty-password write start = %#v", start)
		}
		if got := writeCalls.Load(); got != 0 {
			t.Fatalf("empty-password write reached the native writer %d times", got)
		}
		if _, err := os.Stat(target); !os.IsNotExist(err) {
			t.Fatalf("empty-password write affected output: %v", err)
		}
	})
}

// TestPCV3MobileWriteRoutesToNativeWriter proves a valid creation envelope
// transfers the exact credential, comment, suite, and descriptor intent to the
// native writer boundary, and that bridge-owned password and descriptors are
// released after completion. Protects credential/descriptor ownership transfer
// on the creation path.
func TestPCV3MobileWriteRoutesToNativeWriter(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		temp := t.TempDir()
		payload := "bridge-creation-payload"
		source := writePCV3MobileFile(t, temp, "plain.bin", payload)
		keyfile := writePCV3MobileFile(t, temp, "factor.key", "keyfile")
		target := filepath.Join(temp, "volume.pcv")
		opened := pcv3MobileObserveDescriptors(t)

		workerDone := make(chan struct{})
		var workerPassword []byte
		oldWrite := runPCV3NativeNormalWrite
		runPCV3NativeNormalWrite = func(_ context.Context, request *pcv3.NativeNormalWriteRequest) error {
			defer close(workerDone)
			if request.Suite != pcv3.SuiteParanoid || request.PayloadKind != pcv3.PayloadKindRaw ||
				!request.PayloadBodyRS || request.PlaintextLength != uint64(len(payload)) {
				t.Errorf("native write request shape = suite %d kind %d rs %v length %d",
					request.Suite, request.PayloadKind, request.PayloadBodyRS, request.PlaintextLength)
			}
			if string(request.Comment) != "ordered creation" {
				t.Errorf("native write comment = %q", request.Comment)
			}
			if request.Factors == nil ||
				request.Factors.Mode != pcv3credential.CredentialModePasswordAndKeyfiles ||
				request.Factors.KeyfileMode != pcv3credential.KeyfileModeOrdered ||
				request.Factors.ExpectedPolicy != pcv3credential.FactorPolicyPasswordAndKeyfiles ||
				len(request.Factors.Keyfiles) != 1 {
				t.Errorf("native write factor intent changed: %#v", request.Factors)
			} else {
				workerPassword = request.Factors.Password
			}
			data := make([]byte, len(payload))
			if request.Source == nil {
				t.Errorf("native write source missing")
			} else if _, err := request.Source.Read(data); err != nil || string(data) != payload {
				t.Errorf("native write source read = %q, %v", data, err)
			}
			if request.Destination == nil || request.Admitter == nil {
				t.Errorf("native write destination or admitter missing")
			}
			return nil
		}
		t.Cleanup(func() { runPCV3NativeNormalWrite = oldWrite })

		password := []byte("creation-password")
		start := StartPCV3(
			pcv3WriteTestEnvelope(
				"write-normal", "password-and-keyfiles", "ordered", "paranoid", true,
				"ordered creation", source, target, []string{keyfile},
			),
			password,
		)
		if start == nil || start.Code() != "" || start.Operation() == nil {
			t.Fatalf("write start = %#v", start)
		}
		if !allZero(password) {
			t.Fatal("caller password was not zeroed before StartPCV3 returned")
		}
		operation := start.Operation()
		t.Cleanup(func() { cleanupOperation(operation.ID()) })
		synctest.Wait()
		select {
		case <-workerDone:
		default:
			t.Fatal("creation did not reach the native writer boundary")
		}
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
		if snapshot.AuthenticatedComment() != "" {
			t.Fatalf("creation minted an authenticated comment %q", snapshot.AuthenticatedComment())
		}
		output := operation.Output()
		if output == nil || operation.Archive() != nil || operation.ArtifactInspection() != nil {
			t.Fatal("durable creation did not retain exactly its output authority")
		}
		if code := operation.Release(); code != pcv3OperationReleaseDenied {
			t.Fatalf("release with live write output = %q", code)
		}
		if discarded := output.Discard(); discarded == nil || discarded.Code() != "discarded" ||
			discarded.CleanupIncomplete() {
			t.Fatalf("write output discard = %#v", discarded)
		}
		if _, err := os.Lstat(target); !os.IsNotExist(err) {
			t.Fatalf("discarded created volume remained at target: %v", err)
		}
		synctest.Wait()
		if workerPassword == nil {
			t.Fatal("native writer factor password was not captured")
		}
		if !allZero(workerPassword) {
			t.Fatal("worker factor password was not zeroed after completion")
		}
		pcv3MobileRequireDescriptorsClosed(t, *opened)
		pcv3MobileRequireNoResidue(t, temp, []string{"factor.key", "plain.bin"})
		if code := operation.Release(); code != "" {
			t.Fatalf("creation release = %q", code)
		}
	})
}

// denyPCV3WriteAdmitter is a deterministic resource-denial oracle: it refuses
// the fixed KDF profile the way a constrained Android device does.
type denyPCV3WriteAdmitter struct{ calls *atomic.Int64 }

func (admitter denyPCV3WriteAdmitter) AdmitKDF(
	context.Context, pcv3credential.KDFProfile,
) (pcv3credential.KDFAdmission, error) {
	admitter.calls.Add(1)
	return pcv3credential.KDFAdmissionDeniedInsufficient, nil
}

// TestPCV3MobileWriteAdmissionDenied proves creation fails closed on resource
// admission denial: the refusal happens before the KDF and leaves no output,
// no stage residue, and the exact resource diagnostic. Protects the
// fail-closed admission invariant on the write path.
func TestPCV3MobileWriteAdmissionDenied(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		temp := t.TempDir()
		source := writePCV3MobileFile(t, temp, "plain.bin", "payload")
		target := filepath.Join(temp, "volume.pcv")
		opened := pcv3MobileObserveDescriptors(t)

		var admitCalls atomic.Int64
		oldAdmitter := newPCV3WriteAdmitter
		newPCV3WriteAdmitter = func() pcv3credential.Admitter {
			return denyPCV3WriteAdmitter{calls: &admitCalls}
		}
		t.Cleanup(func() { newPCV3WriteAdmitter = oldAdmitter })

		password := []byte("creation-password")
		start := StartPCV3(
			pcv3WriteTestEnvelope(
				"write-normal", "password", "none", "standard", false, "", source, target, nil,
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

		if got := admitCalls.Load(); got != 1 {
			t.Fatalf("admission decisions = %d; want exactly one", got)
		}
		snapshot := operation.Snapshot()
		if snapshot.Outcome() != "operation-failed" ||
			snapshot.Stage() != "credential-policy" ||
			snapshot.Code() != "PCV3_OPERATION_FAILED" ||
			snapshot.Diagnostic() != "resource-insufficient" ||
			snapshot.CompletionClass() != "refused" ||
			snapshot.PublicationAttempted() ||
			snapshot.WarningCount() != 0 {
			t.Fatalf("admission-denied snapshot = %s", pcv3MobileSnapshotText(snapshot))
		}
		if operation.Output() != nil || operation.Archive() != nil ||
			operation.ArtifactInspection() != nil {
			t.Fatal("admission-denied creation retained output authority")
		}
		if _, err := os.Lstat(target); !os.IsNotExist(err) {
			t.Fatalf("admission-denied creation left output: %v", err)
		}
		pcv3MobileRequireDescriptorsClosed(t, *opened)
		pcv3MobileRequireNoResidue(t, temp, []string{"plain.bin"})
		if code := operation.Release(); code != "" {
			t.Fatalf("admission-denied release = %q", code)
		}
	})
}

// TestPCV3MobileWriteD1KeyfilesOnlyRoundTrip proves bridge D1 creation runs
// the fixed paranoid suite, accepts keyfile-only credentials, produces no
// retained output capability (the native D1 writer publishes the staging file
// directly), and decrypts byte-exact through the existing read-d1 path.
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
		skipOnPCV3ResourceAdmissionDenial(t, snapshot)
		if snapshot.Outcome() != "success" || snapshot.Stage() != "none" ||
			snapshot.Code() != "PCV3_SUCCESS" || snapshot.Diagnostic() != "none" ||
			snapshot.CompletionClass() != "clean" || !snapshot.PublicationAttempted() ||
			snapshot.PublicationState() != "published-durable" ||
			snapshot.WarningCount() != 0 || snapshot.ArchivePending() {
			t.Fatalf("d1 creation snapshot = %s", pcv3MobileSnapshotText(snapshot))
		}
		if operation.Output() != nil {
			t.Fatal("d1 creation minted a retained output capability")
		}
		info, err := os.Lstat(target)
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("d1 volume missing at staging target: %v", err)
		}
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
		skipOnPCV3ResourceAdmissionDenial(t, readSnapshot)
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
