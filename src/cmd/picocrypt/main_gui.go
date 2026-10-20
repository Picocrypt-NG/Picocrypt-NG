//go:build !cli

package main

import (
	"Picocrypt-NG/internal/cli"
	"Picocrypt-NG/internal/ui"
	"fmt"
	"os"

	"fyne.io/fyne/v2"
	fyneApp "fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/dialog"
)

// run is the GUI+CLI entry point.
// It first checks for CLI subcommands, and if none are found, launches the GUI.
func run(startupErr error) {
	// Check for CLI mode first (encrypt/decrypt subcommands)
	if cli.ExecuteWithStartupError(version, startupErr) {
		return
	}
	if startupErr != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize: %v\n", startupErr)
		os.Exit(1)
	}

	// Initialize and run the graphical user interface.
	// The UI handles drag-and-drop file selection, encryption options,
	// progress reporting, and all user interactions.
	app, err := ui.NewApp(version)
	if err != nil {
		// APP-01/D-05: surface a startup failure (e.g. Reed-Solomon codec
		// init) as a fatal-error dialog instead of panicking, then exit
		// non-zero. The main window does not exist yet here (it is built
		// inside App.Run), so spin up a minimal, transient Fyne app + window
		// solely to host the error dialog.
		showFatalErrorDialog(err)
		os.Exit(1)
	}

	app.Run(os.Args[1:])
}

// showFatalErrorDialog displays err in a transient Fyne window and blocks until
// the user closes it. It always writes err to stderr first so headless/CI runs
// (no display) still see the message and the process still exits non-zero.
//
// The main application window does not exist when NewApp fails, so this builds a
// minimal, throwaway Fyne app + window purely to host dialog.NewError (D-05,
// pre-window bootstrap per 05-RESEARCH Pitfall 3).
func showFatalErrorDialog(err error) {
	// Fallback for headless/CI: always emit to stderr before attempting a GUI.
	fmt.Fprintf(os.Stderr, "Failed to initialize: %v\n", err)

	a := fyneApp.New()
	win := a.NewWindow("Picocrypt NG")
	// Closing the transient window quits the event loop so the caller's
	// os.Exit(1) runs (the error dialog sits on top of this window).
	win.SetCloseIntercept(func() { a.Quit() })
	a.Lifecycle().SetOnStarted(func() {
		newFatalErrorDialog(err, win, a.Quit).Show()
	})
	win.ShowAndRun()
}

func newFatalErrorDialog(err error, win fyne.Window, quit func()) dialog.Dialog {
	d := dialog.NewError(err, win)
	d.SetOnClosed(quit)
	return d
}
