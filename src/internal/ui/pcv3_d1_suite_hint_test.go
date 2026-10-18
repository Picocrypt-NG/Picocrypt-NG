package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/pcv3operation"
	"os"
	"path/filepath"
	"testing"

	"fyne.io/fyne/v2"
)

func TestPCV3D1RecoveryProfileControlCapturesExplicitChoice(t *testing.T) {
	fyneApp := newTestFyneApp(t)
	a := createUIReadyDropTestApp(t, fyneApp)
	path := filepath.Join(t.TempDir(), "input.pcv")
	if err := os.WriteFile(path, []byte("public damaged volume"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if !a.State.SetPCV3Ready(source, app.PCV3FormatD1, path, path+".out", 0) {
		_ = source.Close()
		t.Fatal("set D1 source")
	}
	t.Cleanup(a.State.Reset)
	a.State.SetPCV3Intent(app.PCV3ActionForceUnverified, app.PCV3FactorPolicyPassword, app.PCV3KeyfileOrderUnset)
	fyne.DoAndWait(func() { a.buildPCV3Options(a.State.UISnapshot()) })
	if a.pcv3D1SuiteSelect == nil || a.pcv3D1SuiteControl == nil || !a.pcv3D1SuiteControl.Visible() {
		t.Fatal("unverified D1 recovery has no explicit profile control")
	}
	if a.pcv3D1SuiteSelect.SelectedIndex() != 0 || a.State.UISnapshot().PCV3D1SuiteHint != 0 {
		t.Fatal("recovery profile was guessed before the user chose it")
	}
	fyne.DoAndWait(func() { a.pcv3D1SuiteSelect.SetSelectedIndex(1) })
	if a.State.UISnapshot().PCV3D1SuiteHint != pcv3operation.SuiteStandard {
		t.Fatal("Standard choice did not reach operation intent")
	}
	a.State.SetWorking(true)
	fyne.DoAndWait(func() { a.updateAdvancedDisableState() })
	if !a.pcv3D1SuiteSelect.Disabled() {
		t.Fatal("in-flight operation allowed its captured profile to change")
	}
	a.State.SetWorking(false)
	a.State.SetPCV3Intent(app.PCV3ActionDecrypt, app.PCV3FactorPolicyPassword, app.PCV3KeyfileOrderUnset)
	fyne.DoAndWait(func() { a.updateAdvancedDisableState() })
	if a.pcv3D1SuiteControl.Visible() || a.State.UISnapshot().PCV3D1SuiteHint != 0 {
		t.Fatal("recovery-only choice survived an ordinary read")
	}
	a.State.SetPCV3Intent(app.PCV3ActionForceUnverified, app.PCV3FactorPolicyPassword, app.PCV3KeyfileOrderUnset)
	fyne.DoAndWait(func() { a.updateAdvancedDisableState() })
	if !a.pcv3D1SuiteControl.Visible() || a.pcv3D1SuiteSelect.SelectedIndex() != 0 {
		t.Fatal("returning to recovery displayed a stale profile instead of automatic detection")
	}
}

func TestPCV3D1RecoveryProfileTransfersWithoutGrantingConsent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input.pcv")
	if err := os.WriteFile(path, []byte("public recovery input"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	intent := app.PCV3OperationIntent{
		Format: app.PCV3FormatD1, Action: app.PCV3ActionForceUnverified,
		FactorPolicy: app.PCV3FactorPolicyPassword, Source: source,
		Target: path + ".out", Password: []byte("test password"),
		D1SuiteHint: pcv3operation.SuiteParanoid,
	}
	defer closePCV3Intent(&intent)
	request, err := buildPCV3Request(&intent)
	if err != nil {
		t.Fatal(err)
	}
	defer request.Source.Close()
	defer request.Factors.Close()
	if request.D1SuiteHint != pcv3operation.SuiteParanoid || request.Consent != nil || intent.D1SuiteHint != 0 {
		t.Fatalf("profile transfer changed consent or retained caller state: hint=%v consent=%v caller=%v", request.D1SuiteHint, request.Consent != nil, intent.D1SuiteHint)
	}
}

func TestPCV3D1RecoveryProfileCannotOverrideOtherOperations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.pcv")
	if err := os.WriteFile(path, []byte("public selection"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, action := range []app.PCV3Action{app.PCV3ActionDecrypt, app.PCV3ActionRecovery, app.PCV3ActionForce} {
		source, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		intent := app.PCV3OperationIntent{
			Format: app.PCV3FormatD1, Action: action, Source: source,
			FactorPolicy: app.PCV3FactorPolicyPassword, Target: path + ".out",
			Password: []byte("still caller owned"), D1SuiteHint: pcv3operation.SuiteStandard,
		}
		request, err := buildPCV3Request(&intent)
		if request != nil {
			_ = request.Source.Close()
			_ = request.Factors.Close()
		}
		if err == nil || request != nil || intent.Source != source || string(intent.Password) != "still caller owned" {
			closePCV3Intent(&intent)
			t.Fatalf("action %v accepted a recovery-only profile or consumed its factors", action)
		}
		closePCV3Intent(&intent)
	}
}

func TestPCV3D1MissingProfileNoticeExplainsNoOutput(t *testing.T) {
	presentation := mustPCV3Presentation(t, pcv3operation.PresentationSpec{
		Outcome: pcv3operation.OutcomeOperationFailed, Stage: pcv3operation.StageD1Bootstrap,
		Code: pcv3operation.CodeOperationFailed, Diagnostic: pcv3operation.DiagnosticD1ProfileRequired,
	})
	copy := pcv3OutcomeCopy(presentation)
	if copy.Title != "Choose the D1 recovery profile" || copy.Body != "Choose the profile used to create this D1 volume, then retry unverified recovery. No output was created." {
		t.Fatalf("missing-profile notice = %#v", copy)
	}
}
