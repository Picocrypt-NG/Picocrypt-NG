package ui

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
)

func TestPCV3ResultSurfacePreservesFrontendFinalization(t *testing.T) {
	resetLocalizationForTest(t)
	for _, test := range []struct {
		name      string
		recursive bool
		want      string
	}{
		{"cancelled after publication", false, "Operation cancelled by user"},
		{"one published file then failed selection", true, "Completed (1 ok, 1 failed)"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fyneApp := newTestFyneApp(t)
			a := createUIReadyDropTestApp(t, fyneApp)
			source := filepath.Join(t.TempDir(), "source.txt")
			if err := os.WriteFile(source, []byte("source content"), 0o600); err != nil {
				t.Fatal(err)
			}
			input := operationInput{mode: "encrypt", inputFile: source, outputFile: source + ".pcv"}
			// A real keyfile-only writer provides the published result. These
			// tuples represent frontend work after publication, not crypto results.
			result := executePublicationTestEncryption(t, context.Background(), input, nil)
			if test.recursive {
				result.completed = false
				result.succeeded, result.failed = 1, 1
				result.err = errors.New("recursive selection failed")
			} else {
				result.cancelled = true
			}
			fyne.DoAndWait(func() {
				a.State.Mode = "encrypt"
				a.State.Recursively = test.recursive
				a.State.InputFile = source
				a.State.OutputFile = input.outputFile
				a.State.AllFiles = []string{source}
				a.State.SetWorking(true)
				session := a.newOperationSession()
				defer session.cancel()
				a.setOperationSession(session)
				a.finalizeOperation(session, input, result, test.recursive)
				if a.configurationForm.Visible() || a.operationFooter.Visible() || !a.pcv3Container.Visible() {
					t.Error("finalized PCV3 operation did not replace its inactive form")
				}
				text := pcv3RenderedText(a.pcv3Container)
				if !strings.Contains(text, test.want) {
					t.Errorf("result surface lost current frontend outcome %q: %q", test.want, text)
				}
				if strings.Contains(text, "Operation complete") {
					t.Errorf("result surface still presents the previous file's success as the final outcome: %q", text)
				}
				if runtime.GOOS == "windows" && (!strings.Contains(text, nativePCV3UncertainBody) || !strings.Contains(text, nativePCV3DurabilityWarningText) || strings.Contains(text, "File saved.")) {
					t.Errorf("frontend finalization concealed native uncertainty: %q", text)
				}
				if runtime.GOOS != "windows" && !test.recursive && !strings.Contains(text, "File saved.") {
					t.Errorf("cancellation hid the already-published output: %q", text)
				}
			})
		})
	}
}
