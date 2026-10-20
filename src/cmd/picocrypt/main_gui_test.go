//go:build !cli

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2/test"
)

func TestFatalErrorDialogQuitsWhenDismissed(t *testing.T) {
	app := test.NewApp()
	t.Cleanup(app.Quit)

	win := app.NewWindow("Picocrypt NG")
	closed := make(chan struct{}, 1)
	d := newFatalErrorDialog(errors.New("startup failed"), win, func() {
		closed <- struct{}{}
	})

	d.Show()
	d.Dismiss()

	select {
	case <-closed:
	default:
		t.Fatal("fatal error dialog close did not run quit callback")
	}
}

func TestGUIStartupPolicyFailureRefusesBeforeApplicationInput(t *testing.T) {
	if os.Getenv("PICOCRYPT_GUI_STARTUP_FAILURE_CHILD") == "1" {
		os.Args = os.Args[:1]
		run(errors.New("dump protection GUI startup sentinel"))
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestGUIStartupPolicyFailureRefusesBeforeApplicationInput$")
	cmd.Env = append(os.Environ(), "PICOCRYPT_GUI_STARTUP_FAILURE_CHILD=1", "DISPLAY=", "WAYLAND_DISPLAY=")
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil || err == nil || !strings.Contains(string(out), "dump protection GUI startup sentinel") {
		t.Fatalf("GUI startup was not refused before input: error=%v context=%v output=%s", err, ctx.Err(), out)
	}
}
