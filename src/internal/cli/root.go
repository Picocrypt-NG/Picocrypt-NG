package cli

import (
	"Picocrypt-NG/internal/pcv3operation"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"golang.org/x/term"
)

// Version is set by main.go
var Version = "dev"

const (
	ExitGeneralError                 = 1
	ExitForceDecryptKept             = 2
	ExitPCV3Warning                  = 2
	ExitPCV3DurabilityUncertain      = 3
	ExitPCV3PublicationIndeterminate = 4
)

func pcv3ExitCode(result pcv3CLIResult) int {
	if result == nil {
		return ExitGeneralError
	}
	switch result.CompletionClass() {
	case pcv3operation.CompletionClean:
		return 0
	case pcv3operation.CompletionWarning:
		return ExitPCV3Warning
	case pcv3operation.CompletionDurabilityUncertain:
		return ExitPCV3DurabilityUncertain
	case pcv3operation.CompletionPublicationIndeterminate:
		return ExitPCV3PublicationIndeterminate
	default:
		return ExitGeneralError
	}
}

type ExitCodeError interface {
	error
	ExitCode() int
}

type exitCodeError struct {
	message string
	code    int
}

func newExitCodeError(code int, message string) error {
	return exitCodeError{
		message: message,
		code:    code,
	}
}

func (e exitCodeError) Error() string {
	return e.message
}

func (e exitCodeError) ExitCode() int {
	return e.code
}

func exitCodeForError(err error) int {
	if err == nil {
		return 0
	}

	if exitErr, ok := errors.AsType[ExitCodeError](err); ok {
		return exitErr.ExitCode()
	}
	return ExitGeneralError
}

func isExitCodeError(err error) bool {
	var exitErr ExitCodeError
	return errors.As(err, &exitErr)
}

// rootCmd is the base command when called without subcommands
var rootCmd = &cobra.Command{
	Use:   "Picocrypt-NG",
	Short: "Secure file encryption tool",
	Long: `Picocrypt-NG is a secure file encryption tool that uses:
  - Argon2id for password-based key derivation (memory-hard, GPU-resistant)
  - XChaCha20 for symmetric encryption (256-bit security, extended nonce)
  - BLAKE2b-512 for message authentication (or HMAC-SHA3 in paranoid mode)
  - Optional Serpent-CTR as second cipher layer (paranoid mode)
  - Reed-Solomon error correction for data recovery`,
	Version: Version,
}

// Global reporter for signal handling (atomic for safe concurrent access)
var globalReporter atomic.Pointer[Reporter]

// savedTerminalState holds the terminal mode captured at the start of an
// interactive password prompt. term.ReadPassword puts the tty in no-echo mode
// and restores it via a deferred ioctl on normal return; but a SIGINT during
// the prompt drives the signal handler to os.Exit, which skips deferred
// functions and would leave the shell with echo disabled. The signal handler
// reads this to restore the tty before exiting. Nil outside a prompt, so the
// restore is a no-op on every other path.
var savedTerminalState atomic.Pointer[term.State]

// exitFn and restoreTerminalFn are overridable in tests; the signal path calls
// os.Exit and a real termios ioctl, neither of which a unit test can exercise.
var (
	exitFn            = os.Exit
	restoreTerminalFn = func(s *term.State) { _ = term.Restore(int(os.Stdin.Fd()), s) }
)

// handleSignal runs when SIGINT/SIGTERM arrives. If an operation is in flight
// (reporter stored), it cancels cooperatively. Otherwise (typically during the
// interactive password prompt, before the reporter is stored) it restores the
// terminal mode and exits, so the shell is not left with echo disabled.
func handleSignal() {
	if r := globalReporter.Load(); r != nil {
		r.Cancel()
		fmt.Fprintln(os.Stderr, "\nCancelling operation...")
		return
	}
	restoreTerminalState()
	exitFn(1)
}

// restoreTerminalState restores the tty mode captured at prompt start, if any.
func restoreTerminalState() {
	if s := savedTerminalState.Load(); s != nil {
		restoreTerminalFn(s)
	}
}

// Execute runs the CLI application.
// Returns true if CLI mode was activated, false if GUI should run instead.
func Execute(version string) bool {
	Version = version
	rootCmd.Version = version

	if !detectCLIMode(os.Args[1:]) {
		return false
	}

	// Set up signal handling for graceful cancellation
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		handleSignal()
	}()

	if err := rootCmd.Execute(); err != nil {
		if !isExitCodeError(err) {
			fmt.Fprintln(os.Stderr, "Error:", err)
		}
		os.Exit(exitCodeForError(err))
	}
	return true
}

func detectCLIMode(args []string) bool {
	if len(args) == 0 {
		return false
	}

	for _, arg := range args {
		if arg == "-h" || arg == "--help" || arg == "-v" || arg == "--version" {
			return true
		}
	}

	index := 0
	for index < len(args) {
		arg := args[index]
		if arg == "--" {
			index++
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			break
		}

		flagToken := arg
		hasInlineValue := false
		if before, _, ok := strings.Cut(arg, "="); ok {
			flagToken = before
			hasInlineValue = true
		}

		flag := lookupRootPersistentFlag(flagToken)
		if flag == nil {
			return hasKnownRootCommand(args[index+1:])
		}

		if flag.NoOptDefVal == "" && !hasInlineValue {
			nextIndex := index + 1
			if nextIndex >= len(args) {
				return true
			}
			if isKnownRootCommand(args[nextIndex]) {
				return true
			}
			index = nextIndex
		}

		index++
	}

	if index >= len(args) {
		return false
	}

	return isKnownRootCommand(args[index])
}

func lookupRootPersistentFlag(token string) *pflag.Flag {
	switch {
	case strings.HasPrefix(token, "--"):
		return rootCmd.PersistentFlags().Lookup(strings.TrimPrefix(token, "--"))
	case strings.HasPrefix(token, "-") && len(token) == 2:
		return rootCmd.PersistentFlags().ShorthandLookup(strings.TrimPrefix(token, "-"))
	default:
		return nil
	}
}

func hasKnownRootCommand(args []string) bool {
	return slices.ContainsFunc(args, isKnownRootCommand)
}

func isKnownRootCommand(token string) bool {
	if token == "help" {
		return true
	}

	for _, cmd := range rootCmd.Commands() {
		if cmd.Name() == token {
			return true
		}
		if slices.Contains(cmd.Aliases, token) {
			return true
		}
	}

	return false
}

func init() {
	// Disable default completion command
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	// Global flags
	rootCmd.PersistentFlags().StringVar(&TempDirOverride, "temp-dir", "", "Directory for temp files (overrides automatic selection)")
}
