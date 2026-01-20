//go:build cli

package main

import (
	"fmt"
	"os"

	"Picocrypt-NG/internal/cli"
)

// run is the CLI-only entry point.
// This build excludes all GUI dependencies (Fyne, OpenGL, etc.) and can run
// on headless systems without graphics hardware.
func run() {
	if !cli.Execute(version) {
		fmt.Fprintf(os.Stderr, "Picocrypt-NG %s (CLI-only build)\n", version)
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Usage: Picocrypt-NG <command> [options]")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Commands:")
		fmt.Fprintln(os.Stderr, "  encrypt    Encrypt files into a .pcv volume")
		fmt.Fprintln(os.Stderr, "  decrypt    Decrypt a .pcv volume")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Run 'Picocrypt-NG <command> --help' for more information.")
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Note: This is a CLI-only build without GUI support.")
		fmt.Fprintln(os.Stderr, "For GUI version, build without the 'cli' tag.")
		os.Exit(0)
	}
}
