package cli

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
)

// Version is set by main.go
var Version = "dev"

// rootCmd is the base command when called without subcommands
var rootCmd = &cobra.Command{
	Use:   "Picocrypt-NG",
	Short: "Secure file encryption tool",
	Long: `Picocrypt-NG is a secure, audited file encryption tool that uses:
  - Argon2id for password-based key derivation (memory-hard, GPU-resistant)
  - XChaCha20 for symmetric encryption (256-bit security, extended nonce)
  - BLAKE2b-512 for message authentication (or HMAC-SHA3 in paranoid mode)
  - Optional Serpent-CTR as second cipher layer (paranoid mode)
  - Reed-Solomon error correction for data recovery`,
	Version: Version,
}

// Global reporter for signal handling
var globalReporter *Reporter

// Execute runs the CLI application.
// Returns true if CLI mode was activated, false if GUI should run instead.
func Execute(version string) bool {
	Version = version
	rootCmd.Version = version

	// Check if we're in CLI mode (have subcommands)
	if len(os.Args) < 2 {
		return false
	}

	// Check if first arg is a known subcommand
	cmd := os.Args[1]
	if cmd != "encrypt" && cmd != "decrypt" && cmd != "help" && cmd != "--help" && cmd != "-h" && cmd != "version" && cmd != "--version" && cmd != "-v" {
		return false
	}

	// Set up signal handling for graceful cancellation
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		if globalReporter != nil {
			globalReporter.Cancel()
			fmt.Fprintln(os.Stderr, "\nCancelling operation...")
		} else {
			os.Exit(1)
		}
	}()

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
	return true
}

func init() {
	// Disable default completion command
	rootCmd.CompletionOptions.DisableDefaultCmd = true
}
