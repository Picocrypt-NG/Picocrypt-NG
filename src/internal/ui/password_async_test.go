package ui

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
)

// Wait until the real expensive estimator has consumed the queued sample.
// Edits made after this point exercise an obsolete in-flight result, rather
// than merely replacing a job before the worker starts.
func waitForPasswordEstimateToStart(t *testing.T, a *App) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		a.passwordStrengthMu.Lock()
		active := a.passwordStrengthRunning && a.passwordStrengthPending == ""
		a.passwordStrengthMu.Unlock()
		if active {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("real password estimator did not begin")
}

func TestPasswordStrengthLatestEditWins(t *testing.T) {
	a := createUIReadyDropTestApp(t, newTestFyneApp(t))
	fyne.DoAndWait(func() {
		a.State.Mode = "encrypt"
		hasFilesForUI(a)
		a.passwordEntry.SetText("x7#Kp$9mNq@2vL!zY")
	})
	a.workers.wait()
	fyne.DoAndWait(func() {
		if a.State.PasswordStrength < 3 || !a.strengthIndicator.visible {
			t.Fatal("known strong password did not receive a visible strong score")
		}
		a.passwordEntry.SetText(strings.Repeat("4@8({[<3691!|70$5+%2", 5))
		if a.State.PasswordStrength != 0 || a.strengthIndicator.visible {
			t.Fatal("new pending input retained the previous strong indicator")
		}
	})
	waitForPasswordEstimateToStart(t, a)
	fyne.DoAndWait(func() {
		for _, value := range []string{"different pending input", "another pending input", "a"} {
			a.passwordEntry.SetText(value)
		}
		if a.State.PasswordStrength != 0 || a.strengthIndicator.visible {
			t.Fatal("weak input displayed an earlier strong score while pending")
		}
	})
	a.workers.wait()
	fyne.DoAndWait(func() {
		if a.State.Password != "a" || a.passwordEntry.Text != "a" || a.State.PasswordStrength != 0 ||
			a.strengthIndicator.strength != 0 || !a.strengthIndicator.visible {
			t.Fatal("obsolete password estimate replaced the latest weak score")
		}
	})
}

func TestPasswordStrengthObsoleteResultStaysHidden(t *testing.T) {
	for _, change := range []string{"clear", "decrypt", "shutdown"} {
		t.Run(change, func(t *testing.T) {
			a := createUIReadyDropTestApp(t, newTestFyneApp(t))
			fyne.DoAndWait(func() {
				a.State.Mode = "encrypt"
				hasFilesForUI(a)
				a.passwordEntry.SetText(strings.Repeat("4@8({[<3691!|70$5+%2", 5))
			})
			waitForPasswordEstimateToStart(t, a)
			started := time.Now()
			fyne.DoAndWait(func() {
				// Also queue a replacement to prove invalidation removes pending
				// password references, not only the current result's authority.
				a.passwordEntry.SetText("pending replacement")
				switch change {
				case "clear":
					test.Tap(a.clearPwdBtn)
				case "decrypt":
					a.State.Mode = "decrypt"
					a.updateUIState()
				case "shutdown":
					a.stopSourcesAndContexts()
				}
				if a.State.PasswordStrength != 0 || a.strengthIndicator.visible {
					t.Fatal("invalidated estimate left an active strength indicator")
				}
			})
			if elapsed := time.Since(started); elapsed > 2*time.Second {
				t.Fatalf("%s waited on the estimator on the UI thread for %v", change, elapsed)
			}
			a.workers.wait()
			fyne.DoAndWait(func() {
				if a.State.PasswordStrength != 0 || a.strengthIndicator.visible {
					t.Fatal("obsolete estimate became visible after invalidation")
				}
				if change == "clear" && (a.State.Password != "" || a.passwordEntry.Text != "") {
					t.Fatal("cleared password was restored by a late estimate")
				}
			})
			a.passwordStrengthMu.Lock()
			pending := a.passwordStrengthPending
			a.passwordStrengthMu.Unlock()
			if pending != "" {
				t.Fatal("invalidated worker retained a pending password reference")
			}
		})
	}
}

func TestPasswordStrengthSampleKeepsUnicodePrefix(t *testing.T) {
	prefix := strings.Repeat("界", 100)
	password := prefix + strings.Repeat("private tail", 10000)
	sample := passwordStrengthSample(password)
	if sample != prefix || !utf8.ValidString(sample) {
		t.Fatal("advisory sample changed or split the first 100 Unicode characters")
	}
}
