package ui

import (
	"Picocrypt-NG/internal/app"
	"Picocrypt-NG/internal/pcv3operation"
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"fyne.io/fyne/v2"
)

// Headless Fyne apps retain cached renderers after Quit. Isolate these real-KDF
// tests so they neither inherit nor extend the suite process's renderer cache.
func runIsolatedPCV3FyneTest(t *testing.T) bool {
	t.Helper()
	const child = "PICOCRYPT_TEST_REAL_PCV3_FYNE_CHILD"
	if os.Getenv(child) == t.Name() {
		return false
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^"+regexp.QuoteMeta(t.Name())+"$", "-test.timeout=5m", "-test.v")
	command.Env = append(os.Environ(), child+"="+t.Name())
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("isolated real PCV3 Fyne operation: %v\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("--- PASS: "+t.Name()+" (")) {
		t.Fatalf("isolated real PCV3 Fyne operation did not execute and pass %s\n%s", t.Name(), output)
	}
	t.Logf("%s", output)
	return true
}

func TestPCV3FyneUnicode18NormalAndD1(t *testing.T) {
	if runIsolatedPCV3FyneTest(t) {
		return
	}
	resetLocalizationForTest(t)
	// U+20C2 is new in Unicode 18. NormalizationTest-18.0.0.txt line
	// 18205 supplies the suffix and the independent NFC read password.
	const password = "unicode18-\u20C2-a\u0315\u0300\u05AE\u1ADEb"
	const canonicalPassword = "unicode18-\u20C2-\u00E0\u05AE\u1ADE\u0315b"
	for _, mode := range []struct {
		name        string
		deniability bool
		format      app.PCV3Format
	}{
		{"normal", false, app.PCV3FormatNormal},
		{"d1", true, app.PCV3FormatD1},
	} {
		t.Run(mode.name, func(t *testing.T) {
			directory := t.TempDir()
			payload := []byte("Unicode 18 Fyne credential\x00payload")
			source := filepath.Join(directory, "plain.bin")
			volume := filepath.Join(directory, "volume.pcv")
			output := filepath.Join(directory, "opened.bin")
			if err := os.WriteFile(source, payload, 0o600); err != nil {
				t.Fatal(err)
			}
			a := createUIReadyDropTestApp(t, newTestFyneApp(t))
			t.Cleanup(func() { fyne.DoAndWait(a.State.Reset) })
			fyne.DoAndWait(func() { a.onDrop([]string{source}) })
			waitForDropProcessing(t, a)
			fyne.DoAndWait(func() {
				a.State.SetOutputFile(volume)
				a.passwordEntry.SetText(password)
				a.cPasswordEntry.SetText(password)
				a.deniabilityCheck.SetChecked(mode.deniability)
				a.updateUIState()
				if a.State.Password != password || a.State.CPassword != password {
					t.Error("Fyne credential entries changed the literal Unicode-18 write password")
					return
				}
				if a.startButton.Disabled() {
					t.Errorf("Unicode-18 write did not enable Start: %s", a.startReadinessHint(a.State.UISnapshot()))
					return
				}
				a.startButton.OnTapped()
			})
			if t.Failed() {
				return
			}
			drainOperationFinalizer(t, a)
			var created *pcv3operation.Result
			fyne.DoAndWait(func() { created = a.pcv3Result })
			requireNativePCV3Publication(t, created)
			ciphertext, err := os.ReadFile(volume)
			if err != nil {
				t.Fatalf("read Fyne-created ciphertext: %v", err)
			}

			reader, err := os.Open(volume)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = reader.Close() })
			fyne.DoAndWait(func() {
				a.resetUI()
				if !a.State.SetPCV3Ready(reader, mode.format, volume, output, int64(len(ciphertext))) {
					t.Error("Fyne did not accept the created PCV3 read selection")
					return
				}
				a.State.SetPCV3Intent(app.PCV3ActionDecrypt, app.PCV3FactorPolicyUnset, app.PCV3KeyfileOrderUnset)
				a.updateUIState()
				a.passwordEntry.SetText(canonicalPassword)
				if a.State.Password != canonicalPassword {
					t.Error("Fyne credential entry changed the independent NFC read password")
					return
				}
				if a.startButton.Disabled() {
					t.Errorf("Unicode-18 read did not enable Start: %s", a.startReadinessHint(a.State.UISnapshot()))
					return
				}
				a.startButton.OnTapped()
			})
			if t.Failed() {
				return
			}
			drainOperationFinalizer(t, a)
			var opened *pcv3operation.Result
			fyne.DoAndWait(func() {
				opened = a.pcv3Result
				if a.State.Password != "" || a.passwordEntry.Text != "" {
					t.Error("Fyne read retained the transferred credential entry")
				}
			})
			requireNativePCV3Publication(t, opened)
			if _, err := reader.Stat(); err == nil {
				t.Fatal("Fyne read retained its transferred source descriptor")
			}
			for path, want := range map[string][]byte{source: payload, output: payload, volume: ciphertext} {
				if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, want) {
					t.Fatalf("Unicode-18 Fyne changed %s or produced different bytes: %x, %v", filepath.Base(path), got, err)
				}
			}
			entries, err := os.ReadDir(directory)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".picocrypt-pcv3-") {
					t.Fatalf("Unicode-18 Fyne left publication residue %q", entry.Name())
				}
			}
		})
	}
}
