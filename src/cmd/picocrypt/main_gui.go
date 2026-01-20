//go:build !cli

package main

import (
	"fmt"
	"os"

	"Picocrypt-NG/internal/cli"
	"Picocrypt-NG/internal/ui"
)

// run is the GUI+CLI entry point.
// It first checks for CLI subcommands, and if none are found, launches the GUI.
func run() {
	// Check for CLI mode first (encrypt/decrypt subcommands)
	if cli.Execute(version) {
		return
	}

	// Initialize and run the graphical user interface.
	// The UI handles drag-and-drop file selection, encryption options,
	// progress reporting, and all user interactions.
	app, err := ui.NewApp(version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize: %v\n", err)
		os.Exit(1)
	}

	app.Run()
}
