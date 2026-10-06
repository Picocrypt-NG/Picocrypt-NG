package mobile

import (
	"Picocrypt-NG/internal/pcv3operation"
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

// The transport admits the full format comment and realistic maximum selections;
// aggregate allocation remains bounded before parsing or descriptor admission.
func TestPCV3MobileWriteEnvelopeTransportBounds(t *testing.T) {
	comment := strings.Repeat("x", 99999)
	wire := pcv3WriteTestEnvelope("write-normal", "password", "none", "standard", false, comment, "/selected/file-0", "/target", nil)
	decoded, err := decodePCV3Envelope(wire)
	if err != nil || decoded.comment != comment {
		t.Fatalf("maximum valid comment refused: %v", err)
	}
	paths := make([]string, 4096)
	for index := range paths {
		paths[index] = fmt.Sprintf("%q", fmt.Sprintf("/selected/file-%d", index))
	}
	extended := strings.TrimSuffix(wire, "}") + `,"inputFiles":[` + strings.Join(paths, ",") + `],"onlyFiles":[` + strings.Join(paths, ",") + `],"onlyFolders":[],"compress":false}`
	decoded, err = decodePCV3Envelope(extended)
	if err != nil || len(decoded.inputFiles) != 4096 {
		t.Fatalf("bounded selection refused: %v", err)
	}
	if _, err := decodePCV3Envelope(wire + strings.Repeat(" ", 4<<20)); err == nil {
		t.Fatal("oversized transport accepted")
	}
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
		oldWrite := runPCV3WriteWithOptions
		runPCV3WriteWithOptions = func(context.Context, *pcv3operation.WriteRequest, pcv3operation.ExecutionOptions) *pcv3operation.Result {
			writeCalls.Add(1)
			return nil
		}
		t.Cleanup(func() { runPCV3WriteWithOptions = oldWrite })

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
		oldWrite := runPCV3WriteWithOptions
		runPCV3WriteWithOptions = func(_ context.Context, request *pcv3operation.WriteRequest, options pcv3operation.ExecutionOptions) *pcv3operation.Result {
			defer close(workerDone)
			if request.Suite != pcv3operation.SuiteParanoid || request.PayloadKind != pcv3operation.PayloadKindRaw ||
				!request.PayloadBodyRS || request.PlaintextLength != uint64(len(payload)) {
				t.Errorf("native write request shape = suite %d kind %d rs %v length %d",
					request.Suite, request.PayloadKind, request.PayloadBodyRS, request.PlaintextLength)
			}
			if string(request.Comment) != "ordered creation" {
				t.Errorf("native write comment = %q", request.Comment)
			}
			if request.Factors == nil ||
				request.Factors.Mode != pcv3operation.CredentialModePasswordAndKeyfiles ||
				request.Factors.KeyfileMode != pcv3operation.KeyfileModeOrdered ||
				request.Factors.ExpectedPolicy != pcv3operation.FactorPolicyPasswordAndKeyfiles ||
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
			if request.Target != target || !options.RetainDurableOutput || !options.JournalPrivateStage {
				t.Errorf("shared write custody options missing")
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return pcv3operation.RunWriteWithOptions(ctx, request, options)
		}
		t.Cleanup(func() { runPCV3WriteWithOptions = oldWrite })

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
		if snapshot.Diagnostic() != "cancellation" || snapshot.Outcome() != "operation-failed" || operation.Output() != nil {
			t.Fatalf("shared result was not preserved: %s", pcv3MobileSnapshotText(snapshot))
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
