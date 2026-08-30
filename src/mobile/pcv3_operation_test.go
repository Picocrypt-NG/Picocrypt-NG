package mobile

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3"
	"Picocrypt-NG/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/pcv3publication"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
)

type literalMobileArchiveAction struct {
	closeResult pcv3operation.Presentation
	closeCalls  atomic.Int64
}

func (action *literalMobileArchiveAction) Close() pcv3operation.Presentation {
	action.closeCalls.Add(1)
	return action.closeResult
}

func TestPCV3MobileStrictEnvelope(t *testing.T) {
	synctest.Test(t, testPCV3MobileStrictEnvelope)
}

func testPCV3MobileStrictEnvelope(t *testing.T) {
	temp := t.TempDir()
	source := filepath.Join(temp, "source.pcv")
	if err := os.WriteFile(source, []byte("not-a-volume"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(temp, "plain.txt")
	valid := pcv3TestEnvelope("read-normal", "password", "none", source, target, nil)

	var openCalls atomic.Int64
	oldOpen := openPCV3Existing
	openPCV3Existing = func(path string, flag int) (*os.File, error) {
		openCalls.Add(1)
		return fileops.OpenExistingNoSymlink(path, flag)
	}
	t.Cleanup(func() { openPCV3Existing = oldOpen })

	var runCalls atomic.Int64
	runCalled := make(chan struct{}, 1)
	oldRun := runPCV3Operation
	runPCV3Operation = func(_ context.Context, _ *pcv3operation.Request) *pcv3operation.Result {
		runCalls.Add(1)
		runCalled <- struct{}{}
		return nil
	}
	t.Cleanup(func() { runPCV3Operation = oldRun })

	requiredCases := map[string]struct{}{
		"duplicate-field": {}, "unknown-field": {}, "missing-field": {},
		"wrong-case": {}, "null": {}, "wrong-type": {}, "wrong-version": {},
		"nested-value": {}, "trailing-value": {}, "oversized": {},
		"write-mode-read-shape": {}, "unknown-mode": {}, "password-in-json": {},
		"factor-mismatch": {},
	}
	cases := map[string]string{
		"duplicate-field": strings.Replace(valid, `"version":1`, `"version":1,"version":1`, 1),
		"unknown-field":   strings.Replace(valid, "{", `{"resourceAuthority":true,`, 1),
		"missing-field":   strings.Replace(valid, fmt.Sprintf(`,"target":%q`, target), "", 1),
		"wrong-case":      strings.Replace(valid, `"version":1`, `"Version":1`, 1),
		"null":            strings.Replace(valid, fmt.Sprintf(`"source":%q`, source), `"source":null`, 1),
		"wrong-type":      strings.Replace(valid, `"version":1`, `"version":"1"`, 1),
		"wrong-version":   strings.Replace(valid, `"version":1`, `"version":2`, 1),
		"nested-value":    strings.Replace(valid, `"mode":"read-normal"`, `"mode":{"name":"read-normal"}`, 1),
		"trailing-value":  valid + `{}`,
		"oversized":       valid + strings.Repeat(" ", maxPCV3EnvelopeBytes),
		// Write modes are accepted only in their exact write shape; a write
		// mode in a read-shaped envelope (missing comment/suite/payloadRS) is
		// still refused.
		"write-mode-read-shape": strings.Replace(valid, `"mode":"read-normal"`, `"mode":"write-normal"`, 1),
		"unknown-mode":          strings.Replace(valid, `"mode":"read-normal"`, `"mode":"migrate-normal"`, 1),
		"password-in-json": strings.Replace(
			valid, "{", `{"password":"must-not-be-accepted",`, 1,
		),
		"factor-mismatch": strings.Replace(valid, `"keyfiles":[]`, fmt.Sprintf(`"keyfiles":[%q]`, source), 1),
	}
	if len(cases) != len(requiredCases) {
		t.Fatalf("failure case inventory changed: got %d, want %d", len(cases), len(requiredCases))
	}
	for id := range requiredCases {
		request, ok := cases[id]
		if !ok {
			t.Fatalf("required failure case %q is not executed", id)
		}
		beforeOpen := openCalls.Load()
		beforeRun := runCalls.Load()
		password := []byte("correct horse battery staple")
		start := StartPCV3(request, password)
		if start == nil || start.Code() != pcv3BridgeInvalidRequest || start.Operation() != nil {
			t.Fatalf("%s: strict rejection = %#v", id, start)
		}
		if !allZero(password) {
			t.Fatalf("%s: caller password was not zeroed synchronously", id)
		}
		if got := openCalls.Load(); got != beforeOpen {
			t.Fatalf("%s: invalid envelope opened %d files", id, got-beforeOpen)
		}
		if got := runCalls.Load(); got != beforeRun {
			t.Fatalf("%s: invalid envelope started %d core operations", id, got-beforeRun)
		}
		if _, err := os.Stat(target); !os.IsNotExist(err) {
			t.Fatalf("%s: invalid envelope affected output: %v", id, err)
		}
	}

	password := []byte("correct horse battery staple")
	start := StartPCV3(valid, password)
	if start == nil || start.Code() != "" || start.Operation() == nil || start.Operation().ID() == "" {
		t.Fatalf("valid start = %#v", start)
	}
	if !allZero(password) {
		t.Fatal("valid start retained caller password")
	}
	synctest.Wait()
	select {
	case <-runCalled:
	default:
		t.Fatal("valid envelope did not reach the PCV3 operation boundary")
	}
	if code := start.Operation().Release(); code != "" {
		t.Fatalf("completed strict-envelope operation release = %q", code)
	}
}

func TestPCV3MobilePreservesFactorIntent(t *testing.T) {
	synctest.Test(t, testPCV3MobilePreservesFactorIntent)
}

func testPCV3MobilePreservesFactorIntent(t *testing.T) {
	temp := t.TempDir()
	source := writePCV3MobileFile(t, temp, "source.pcv", "source")
	keyA := writePCV3MobileFile(t, temp, "a.key", "a")
	keyB := writePCV3MobileFile(t, temp, "b.key", "b")
	target := filepath.Join(temp, "plain.txt")

	var mu sync.Mutex
	var opened []string
	oldOpen := openPCV3Existing
	openPCV3Existing = func(path string, flag int) (*os.File, error) {
		mu.Lock()
		opened = append(opened, path)
		mu.Unlock()
		return fileops.OpenExistingNoSymlink(path, flag)
	}
	t.Cleanup(func() { openPCV3Existing = oldOpen })

	checked := make(chan struct{}, 1)
	oldRun := runPCV3Operation
	runPCV3Operation = func(_ context.Context, request *pcv3operation.Request) *pcv3operation.Result {
		if request.Mode != pcv3operation.ModeForceD1 {
			t.Errorf("mode = %v", request.Mode)
		}
		if request.Factors == nil ||
			request.Factors.Mode != pcv3credential.CredentialModePasswordAndKeyfiles ||
			request.Factors.KeyfileMode != pcv3credential.KeyfileModeUnordered ||
			request.Factors.ExpectedPolicy != pcv3credential.FactorPolicyPasswordAndKeyfiles ||
			len(request.Factors.Keyfiles) != 3 {
			t.Errorf("factor intent was changed: %#v", request.Factors)
		}
		checked <- struct{}{}
		return nil
	}
	t.Cleanup(func() { runPCV3Operation = oldRun })

	password := []byte("password")
	start := StartPCV3(
		pcv3TestEnvelope("force-d1", "password-and-keyfiles", "unordered", source, target, []string{keyB, keyA, keyB}),
		password,
	)
	if start == nil || start.Code() != "" || start.Operation() == nil {
		t.Fatalf("start = %#v", start)
	}
	if !allZero(password) {
		t.Fatal("caller password was not zeroed")
	}
	synctest.Wait()
	select {
	case <-checked:
	default:
		t.Fatal("operation did not reach the core boundary")
	}
	mu.Lock()
	gotOpened := append([]string(nil), opened...)
	mu.Unlock()
	wantOpened := []string{source, keyB, keyA, keyB}
	if fmt.Sprint(gotOpened) != fmt.Sprint(wantOpened) {
		t.Fatalf("descriptor acquisition order = %q, want %q", gotOpened, wantOpened)
	}
	synctest.Wait()
	if code := start.Operation().Release(); code != "" {
		t.Fatalf("factor-intent operation release = %q", code)
	}
}

func TestPCV3MobileOwnsPasswordAndDescriptors(t *testing.T) {
	synctest.Test(t, testPCV3MobileOwnsPasswordAndDescriptors)
}

func testPCV3MobileOwnsPasswordAndDescriptors(t *testing.T) {
	temp := t.TempDir()
	source := writePCV3MobileFile(t, temp, "source.pcv", "original-source")
	replacement := writePCV3MobileFile(t, temp, "replacement.pcv", "replacement-source")
	keyfile := writePCV3MobileFile(t, temp, "factor.key", "keyfile")
	target := filepath.Join(temp, "plain.txt")

	var opened []*os.File
	oldOpen := openPCV3Existing
	openPCV3Existing = func(path string, flag int) (*os.File, error) {
		file, err := fileops.OpenExistingNoSymlink(path, flag)
		if err != nil {
			return nil, err
		}
		opened = append(opened, file)
		if path == source {
			if err := os.Rename(source, source+".opened"); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(replacement, source); err != nil {
				t.Fatal(err)
			}
		}
		return file, nil
	}
	t.Cleanup(func() { openPCV3Existing = oldOpen })

	workerDone := make(chan struct{})
	var workerPassword []byte
	oldRun := runPCV3Operation
	runPCV3Operation = func(_ context.Context, request *pcv3operation.Request) *pcv3operation.Result {
		reopened, err := os.ReadFile(source)
		if err != nil {
			t.Errorf("read replacement path: %v", err)
		} else if string(reopened) != "replacement-source" {
			t.Errorf("reopened path read %q", reopened)
		}
		if _, err := request.Source.Seek(0, 0); err != nil {
			t.Errorf("seek owned source: %v", err)
		}
		data := make([]byte, len("original-source"))
		if _, err := request.Source.Read(data); err != nil {
			t.Errorf("read owned source: %v", err)
		}
		if string(data) != "original-source" {
			t.Errorf("owned descriptor read %q", data)
		}
		workerPassword = request.Factors.Password
		close(workerDone)
		return nil
	}
	t.Cleanup(func() { runPCV3Operation = oldRun })

	password := []byte("mutable-password")
	start := StartPCV3(
		pcv3TestEnvelope("read-normal", "password-and-keyfiles", "ordered", source, target, []string{keyfile}),
		password,
	)
	if start == nil || start.Code() != "" || start.Operation() == nil {
		t.Fatalf("start = %#v", start)
	}
	if !allZero(password) {
		t.Fatal("caller password was not zeroed before StartPCV3 returned")
	}
	synctest.Wait()
	select {
	case <-workerDone:
	default:
		t.Fatal("worker did not receive transferred resources")
	}
	if !allZero(workerPassword) {
		t.Fatal("worker password copy was not zeroed after completion")
	}
	for _, file := range opened {
		if _, err := file.Stat(); err == nil {
			t.Fatalf("transferred descriptor %q remains open", file.Name())
		}
	}
	if code := start.Operation().Release(); code != "" {
		t.Fatalf("ownership operation release = %q", code)
	}

	symlink := filepath.Join(temp, "symlink.pcv")
	if err := os.Symlink(source, symlink); err != nil {
		t.Fatal(err)
	}
	password = []byte("password")
	rejected := StartPCV3(pcv3TestEnvelope("read-normal", "password", "none", symlink, target, nil), password)
	if rejected == nil || rejected.Code() != pcv3BridgeInputUnavailable || rejected.Operation() != nil {
		t.Fatalf("symlink start = %#v", rejected)
	}
	if !allZero(password) {
		t.Fatal("rejected request retained caller password")
	}
}

func TestPCV3MobileRequiresExplicitModeAndLiveConsent(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		temp := t.TempDir()
		source := writePCV3MobileFile(t, temp, "source.pcv", "claimed-pcv3")
		target := filepath.Join(temp, "plain.txt")
		password := []byte("password")
		start := StartPCV3(
			pcv3TestEnvelope("force-unverified-normal", "password", "none", source, target, nil),
			password,
		)
		if start.Code() != "" || start.Operation() == nil {
			t.Fatalf("unverified start = %#v", start)
		}
		synctest.Wait()
		operation := start.Operation()
		consent := operation.Consent()
		if consent == nil || consent.Mode() != "force-unverified-normal" ||
			consent.RoleCount() != 2 || consent.RoleAt(0) != "primary" || consent.RoleAt(1) != "backup" {
			t.Fatalf("live consent = %#v", consent)
		}
		if _, err := GetProgress(operation.ID()); err == nil {
			t.Fatal("legacy ID lookup exposed PCV3 state")
		}
		if _, err := CancelOperation(operation.ID()); err == nil {
			t.Fatal("legacy ID cancellation reached PCV3 authority")
		}
		if code := consent.Refuse(); code != "" {
			t.Fatalf("consent refusal code = %q", code)
		}
		synctest.Wait()
		snapshot := operation.Snapshot()
		if snapshot.CompletionClass() != "refused" || snapshot.Diagnostic() != "credential-policy" || operation.Consent() != nil {
			t.Fatalf("refusal snapshot = %s/%s consent=%v", snapshot.CompletionClass(), snapshot.Diagnostic(), operation.Consent())
		}
		if code := consent.Refuse(); code != pcv3ConsentExpired {
			t.Fatalf("expired consent code = %q", code)
		}
		if code := operation.Release(); code != "" {
			t.Fatalf("refused operation release = %q", code)
		}

		password = []byte("password")
		normal := StartPCV3(pcv3TestEnvelope("read-normal", "password", "none", source, target, nil), password)
		synctest.Wait()
		if normal.Operation().Consent() != nil {
			t.Fatal("ordinary read minted consent authority")
		}
		if code := normal.Operation().Release(); code != "" {
			t.Fatalf("ordinary read release = %q", code)
		}

		actionStarted := make(chan struct{})
		actionRelease := make(chan struct{})
		var actionReleaseOnce sync.Once
		releaseAction := func() { actionReleaseOnce.Do(func() { close(actionRelease) }) }
		defer releaseAction()
		baseRun := runPCV3Operation
		defer func() { runPCV3Operation = baseRun }()
		runPCV3Operation = func(ctx context.Context, request *pcv3operation.Request) *pcv3operation.Result {
			originalConsent := request.Consent
			request.Consent = func(consentRequest pcv3operation.ConsentRequest, action pcv3operation.ConsentAction) error {
				return originalConsent(consentRequest, func(role pcv3operation.PhysicalRole) error {
					close(actionStarted)
					<-actionRelease
					return action(role)
				})
			}
			return baseRun(ctx, request)
		}
		password = []byte("password")
		chosen := StartPCV3(
			pcv3TestEnvelope("force-unverified-normal", "password", "none", source, target, nil),
			password,
		)
		defer func() { _ = chosen.Operation().Cancel() }()
		synctest.Wait()
		chooseConsent := chosen.Operation().Consent()
		if chooseConsent == nil || chooseConsent.Choose("primary") != "" {
			t.Fatal("valid consent role was not accepted")
		}
		<-actionStarted
		if chosen.Operation().Consent() != nil ||
			chosen.Operation().Release() != pcv3OperationReleaseDenied {
			t.Fatal("consent action did not become detached and in-flight")
		}
		releaseAction()
		synctest.Wait()
		if snapshot := chosen.Operation().Snapshot(); snapshot.CompletionClass() == "unknown" || snapshot.ArchivePending() {
			t.Fatalf("chosen role terminal = %s pending=%v", snapshot.CompletionClass(), snapshot.ArchivePending())
		}
		if chooseConsent.Choose("backup") != pcv3ConsentExpired {
			t.Fatal("consent capability remained live after one selection")
		}
		if code := chosen.Operation().Release(); code != "" {
			t.Fatalf("chosen operation release = %q", code)
		}
		runPCV3Operation = baseRun

		runnerStarted := make(chan struct{})
		runnerRelease := make(chan struct{})
		oldRun := runPCV3Operation
		runPCV3Operation = func(ctx context.Context, request *pcv3operation.Request) *pcv3operation.Result {
			close(runnerStarted)
			<-runnerRelease
			return pcv3operation.Run(ctx, request)
		}
		t.Cleanup(func() { runPCV3Operation = oldRun })
		password = []byte("password")
		cancelled := StartPCV3(pcv3TestEnvelope("read-normal", "password", "none", source, target, nil), password)
		<-runnerStarted
		requested := cancelled.Operation().Cancel()
		if requested.Stage() == "cancellation" || requested.CompletionClass() != "unknown" {
			t.Fatalf("cancel request minted terminal state: %s/%s", requested.Stage(), requested.CompletionClass())
		}
		if code := cancelled.Operation().Release(); code != pcv3OperationReleaseDenied {
			t.Fatalf("in-flight release code = %q", code)
		}
		close(runnerRelease)
		synctest.Wait()
		cancelSnapshot := cancelled.Operation().Snapshot()
		if cancelSnapshot.Stage() != "cancellation" || cancelSnapshot.Diagnostic() != "cancellation" {
			t.Fatalf("core cancel snapshot = %s/%s", cancelSnapshot.Stage(), cancelSnapshot.Diagnostic())
		}
		if code := cancelled.Operation().Release(); code != "" {
			t.Fatalf("cancelled release code = %q", code)
		}
	})
}

func TestPCV3MobileRestoredReceiptIsDenyOnly(t *testing.T) {
	uncertain := mustPCV3Presentation(t, pcv3operation.PresentationSpec{
		Outcome:              pcv3.OutcomeSuccess,
		Stage:                pcv3.StageNone,
		Code:                 pcv3.CodeSuccess,
		PublicationAttempted: true,
		PublicationState:     pcv3publication.StatePublishedDurabilityUncertain,
		PublicationStage:     pcv3.StageDirectorySync,
		PublicationCode:      pcv3publication.CodeDurabilityUncertain,
	})
	operation := startPCV3Operation()
	completePCV3PresentationForOperation(operation, uncertain)
	receiptJSON := operation.Snapshot().RestoredReceipt()
	if receiptJSON == "" {
		t.Fatal("uncertain terminal state did not produce a receipt")
	}
	if code := operation.Release(); code != "" {
		t.Fatalf("receipt source release code = %q", code)
	}
	restored := RestorePCV3Receipt(receiptJSON)
	if restored == nil || restored.Code() != "" || restored.ReceiptID() == "" ||
		restored.OperationID() != operation.ID() || restored.Snapshot() == nil ||
		restored.Snapshot().CompletionClass() != "durability-uncertain" {
		t.Fatalf("restored receipt = %#v", restored)
	}
	if _, err := CancelOperation(restored.OperationID()); err == nil {
		t.Fatal("restored display ID granted cancellation")
	}
	forbidden := map[string]struct{}{
		"Operation": {}, "Consent": {}, "Archive": {}, "Retry": {}, "Resume": {},
		"Extract": {}, "Export": {}, "Discard": {}, "Cleanup": {}, "Delete": {},
	}
	restoredType := reflect.TypeOf(restored)
	for index := range restoredType.NumMethod() {
		method := restoredType.Method(index)
		if _, grants := forbidden[method.Name]; grants {
			t.Fatalf("restored receipt exposes %s authority", method.Name)
		}
	}

	var wire map[string]any
	if err := json.Unmarshal([]byte(receiptJSON), &wire); err != nil {
		t.Fatal(err)
	}
	wire["source"] = "/private/plaintext"
	tampered, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if invalid := RestorePCV3Receipt(string(tampered)); invalid.Code() != pcv3ReceiptInvalid || invalid.Snapshot() != nil {
		t.Fatalf("unknown receipt field was accepted: %#v", invalid)
	}
	wire = map[string]any{}
	if err := json.Unmarshal([]byte(receiptJSON), &wire); err != nil {
		t.Fatal(err)
	}
	wire["publicationState"] = float64(pcv3publication.StatePublishedDurable)
	wire["publicationStage"] = float64(pcv3.StageNone)
	wire["publicationCode"] = float64(pcv3publication.CodePublishedDurable)
	wire["warnings"] = []any{}
	tampered, _ = json.Marshal(wire)
	if invalid := RestorePCV3Receipt(string(tampered)); invalid.Code() != pcv3ReceiptInvalid {
		t.Fatal("non-uncertain restored state was accepted")
	}
}

func TestPCV3MobileBoundsAndRedactsStatus(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		temp := t.TempDir()
		source := writePCV3MobileFile(t, temp, "private-source.pcv", "source")
		target := filepath.Join(temp, "private-output.txt")
		secret := "do-not-disclose"
		oldRun := runPCV3Operation
		runPCV3Operation = func(context.Context, *pcv3operation.Request) *pcv3operation.Result {
			panic(source + target + secret)
		}
		t.Cleanup(func() { runPCV3Operation = oldRun })
		password := []byte(secret)
		start := StartPCV3(pcv3TestEnvelope("read-normal", "password", "none", source, target, nil), password)
		synctest.Wait()
		snapshot := start.Operation().Snapshot()
		if snapshot.Diagnostic() != "callback-panic" || snapshot.Outcome() != "operation-failed" ||
			snapshot.CompletionClass() != "refused" {
			t.Fatalf("contained panic = %s/%s/%s", snapshot.Outcome(), snapshot.Diagnostic(), snapshot.CompletionClass())
		}
		visible := strings.Join([]string{
			snapshot.StatusCode(), snapshot.Outcome(), snapshot.Stage(), snapshot.Code(),
			snapshot.Diagnostic(), snapshot.PublicationState(), snapshot.PublicationCode(),
		}, "|")
		if strings.Contains(visible, source) || strings.Contains(visible, target) || strings.Contains(visible, secret) {
			t.Fatalf("snapshot disclosed private input: %q", visible)
		}
		if code := start.Operation().Release(); code != "" {
			t.Fatalf("panic operation release = %q", code)
		}

		for _, diagnostic := range []struct {
			value pcv3operation.Diagnostic
			want  string
		}{
			{pcv3operation.DiagnosticResourceBusy, "resource-busy"},
			{pcv3operation.DiagnosticResourceInsufficient, "resource-insufficient"},
			{pcv3operation.DiagnosticResourceUnknown, "resource-unknown"},
		} {
			presentation := mustPCV3Presentation(t, pcv3operation.PresentationSpec{
				Outcome:    pcv3.OutcomeOperationFailed,
				Stage:      pcv3.StageCredentialPolicy,
				Code:       pcv3.CodeOperationFailed,
				Diagnostic: diagnostic.value,
			})
			op := startPCV3Operation()
			completePCV3PresentationForOperation(op, presentation)
			if got := op.Snapshot().Diagnostic(); got != diagnostic.want {
				t.Fatalf("diagnostic %d = %q", diagnostic.value, got)
			}
			if code := op.Release(); code != "" {
				t.Fatalf("diagnostic operation release = %q", code)
			}
		}

		if invalid := RestorePCV3Receipt(strings.Repeat("x", maxPCV3ReceiptBytes+1)); invalid.Code() != pcv3ReceiptInvalid || invalid.Snapshot() != nil {
			t.Fatal("oversized restored input was not bounded")
		}
	})
}

// TestPCV3OperationABI is a policy oracle for the exact gomobile surface. It
// does not count as product behavior or descriptor/session evidence. Creation
// support deliberately adds no new gomobile methods: write operations enter
// through the existing StartPCV3 envelope and report through the existing
// PCV3Operation/PCV3Snapshot/PCV3Output surface.
func TestPCV3OperationABI(t *testing.T) {
	wantMethods := map[reflect.Type][]string{
		reflect.TypeOf((*PCV3StartResult)(nil)): {"Code", "Operation"},
		reflect.TypeOf((*PCV3Operation)(nil)): {
			"Archive", "ArtifactInspection", "Cancel", "Consent", "ID", "Output", "Release", "ResourceChallenge", "Snapshot",
		},
		reflect.TypeOf((*PCV3ArtifactInspection)(nil)): {
			"FinalStatus", "Kind", "MissingCount", "Page", "PlaintextLength", "RangeCount", "Role", "UnverifiedCount", "VerifiedCount",
		},
		reflect.TypeOf((*PCV3ArtifactPage)(nil)):      {"Count", "EndAt", "RecordIndexAt", "StartAt", "StatusAt"},
		reflect.TypeOf((*PCV3ResourceChallenge)(nil)): {"Submit"},
		reflect.TypeOf((*PCV3Output)(nil)):            {"Discard", "Format", "GoString", "SaveFD", "String"},
		reflect.TypeOf((*PCV3OutputResult)(nil)):      {"CleanupIncomplete", "Code", "Format", "GoString", "String"},
		reflect.TypeOf((*PCV3Snapshot)(nil)): {
			"ArchivePending", "ArgAt", "ArgCount", "AuthenticatedComment", "Code", "CompletionClass",
			"D1BootstrapProvenance", "DetailStage", "Diagnostic", "ForceProvenance",
			"Outcome", "PublicationAttempted", "PublicationCode", "PublicationStage",
			"PublicationState", "RestoredReceipt", "Stage", "StatusArgAt",
			"StatusArgCount", "StatusCode", "WarningAt", "WarningCount",
		},
		reflect.TypeOf((*PCV3Consent)(nil)):         {"Choose", "Mode", "Refuse", "RoleAt", "RoleCount"},
		reflect.TypeOf((*PCV3Archive)(nil)):         {"BeginSAF", "Close"},
		reflect.TypeOf((*PCV3ArchiveBegin)(nil)):    {"Code", "Kind", "Session", "Snapshot"},
		reflect.TypeOf((*PCV3ArchiveEntry)(nil)):    {"IsDirectory", "Name", "ParentIndex", "Size"},
		reflect.TypeOf((*PCV3ArchiveSession)(nil)):  {"Abort", "AckDirectory", "Attempt", "Cancel", "ConfirmCrashReceiptPersisted", "Entry", "EntryCount", "Finish", "WriteFD"},
		reflect.TypeOf((*PCV3ArchiveStep)(nil)):     {"Kind", "NextIndex"},
		reflect.TypeOf((*PCV3RestoredReceipt)(nil)): {"Code", "OperationID", "ReceiptID", "Snapshot"},
	}
	for publicType, want := range wantMethods {
		got := make([]string, publicType.NumMethod())
		for index := range got {
			got[index] = publicType.Method(index).Name
		}
		if !slices.Equal(got, want) {
			t.Fatalf("gomobile type %s methods = %v; PCV3 mobile ABI requires %v", publicType, got, want)
		}
	}
}

func mustPCV3Presentation(t *testing.T, spec pcv3operation.PresentationSpec) pcv3operation.Presentation {
	t.Helper()
	presentation, err := pcv3operation.NewPresentation(spec)
	if err != nil {
		t.Fatalf("NewPresentation: %v", err)
	}
	return presentation
}

func closedPCV3MobileArchivePresentation(t *testing.T, cleanupIncomplete bool) pcv3operation.Presentation {
	t.Helper()
	var warnings []pcv3operation.Warning
	if cleanupIncomplete {
		warnings = []pcv3operation.Warning{pcv3operation.WarningCleanupIncomplete}
	}
	return mustPCV3Presentation(t, pcv3operation.PresentationSpec{
		Outcome:    pcv3.OutcomeOperationFailed,
		Stage:      pcv3.StageOutputPublication,
		Code:       pcv3.CodeOperationFailed,
		Warnings:   warnings,
		Diagnostic: pcv3operation.DiagnosticNone,
	})
}

func pcv3TestEnvelope(mode, policy, order, source, target string, keyfiles []string) string {
	quotedKeys := make([]string, len(keyfiles))
	for i, path := range keyfiles {
		quotedKeys[i] = fmt.Sprintf("%q", path)
	}
	return fmt.Sprintf(
		`{"version":1,"mode":%q,"factorPolicy":%q,"keyfileOrder":%q,"source":%q,"target":%q,"keyfiles":[%s]}`,
		mode, policy, order, source, target, strings.Join(quotedKeys, ","),
	)
}

func writePCV3MobileFile(t *testing.T, directory, name, contents string) string {
	t.Helper()
	path := filepath.Join(directory, name)
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func allZero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}
