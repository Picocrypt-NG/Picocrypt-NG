package cli

import (
	"Picocrypt-NG/internal/secret"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"

	pwnorm "Picocrypt-NG/internal/password"

	"golang.org/x/term"
)

var (
	ErrPasswordMismatch = errors.New("passwords do not match")
	ErrPasswordEmpty    = errors.New("password cannot be empty")
)

const maximumCLIPasswordBytes = 1 << 20

var errCLIPasswordTooLong = errors.New("password line exceeds 1 MiB")

type passwordLineInput struct {
	source  io.Reader
	scratch [4096]byte
	unread  []byte
	readErr error
}

func (input *passwordLineInput) clear() {
	secret.SecureZero(input.scratch[:])
	input.unread = nil
}

// isTerminal returns true if stdin is a terminal (not piped/redirected).
func isTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// captureTerminalState records the current tty mode so the signal handler can
// restore it if SIGINT arrives during a no-echo password read. A GetState error
// (e.g. fd is not a tty) stores nothing, leaving restore a no-op.
func captureTerminalState() {
	if st, err := term.GetState(int(os.Stdin.Fd())); err == nil {
		savedTerminalState.Store(st)
	}
}

// read must return a wholly owned allocation starting at offset zero. Clear
// partial failures and unused capacity before transferring successful input;
// terminal backspaces can leave deleted bytes beyond the returned length.
func readOwnedPassword(read func() ([]byte, error)) ([]byte, error) {
	password, err := read()
	if err != nil {
		secret.SecureZero(password[:cap(password)])
		return nil, err
	}
	secret.SecureZero(password[len(password):cap(password)])
	return password, nil
}

func readPasswordLine(input *passwordLineInput) ([]byte, error) {
	password, err := readOwnedPassword(func() ([]byte, error) {
		password := make([]byte, maximumCLIPasswordBytes+2)
		used := 0
		for {
			if len(input.unread) == 0 && input.readErr == nil {
				// Up to two framing bytes can follow a password at the limit.
				n, err := input.source.Read(input.scratch[:min(len(input.scratch), len(password)-used)])
				input.unread, input.readErr = input.scratch[:n], err
				if n == 0 && err == nil {
					return password, io.ErrNoProgress
				}
			}

			part := input.unread
			newline := bytes.IndexByte(part, '\n')
			if newline >= 0 {
				part = part[:newline+1]
			}
			used += copy(password[used:], part)
			secret.SecureZero(part)
			input.unread = input.unread[len(part):]

			if newline >= 0 || errors.Is(input.readErr, io.EOF) {
				break
			}
			if input.readErr != nil {
				return password, input.readErr
			}
			if used > maximumCLIPasswordBytes && (used == len(password) || password[used-1] != '\r') {
				return password, errCLIPasswordTooLong
			}
		}

		password = bytes.TrimSuffix(password[:used], []byte("\n"))
		password = bytes.TrimSuffix(password, []byte("\r"))
		if len(password) > maximumCLIPasswordBytes {
			return password, errCLIPasswordTooLong
		}
		return password, nil
	})
	if err != nil {
		input.clear()
	}
	return password, err
}

// readTerminalPassword reads from a real terminal without echo.
func readTerminalPassword(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)

	// Terminal mode: capture the current tty state so a SIGINT during the
	// no-echo read can be restored by the signal handler (os.Exit skips
	// term.ReadPassword's own deferred restore).
	captureTerminalState()

	// Terminal mode: disable echo. term.ReadPassword returns an owned []byte.
	pw, err := readOwnedPassword(func() ([]byte, error) {
		return term.ReadPassword(int(os.Stdin.Fd()))
	})
	fmt.Fprintln(os.Stderr) // newline after hidden input
	if err != nil {
		return nil, fmt.Errorf("reading password: %w", err)
	}
	return pw, nil
}

// ReadPasswordInteractive prompts for password interactively.
// If confirm is true, asks for confirmation (for encryption).
// If allowEmpty is true, empty password is allowed (useful when keyfiles provide credentials).
// nonASCIIPasswordNote returns an advisory to show when an ENCRYPTION password
// (confirm == true) contains non-ASCII characters, or "" when none is warranted.
// The password is normalized (NFC) for cross-platform decryption, but the user
// should still be able to reproduce the exact characters elsewhere — NIST
// SP 800-63B-4 recommends advising this.
func nonASCIIPasswordNote(confirm bool, password []byte) string {
	if confirm && pwnorm.ContainsNonASCII(password) {
		return "Note: your password contains non-ASCII characters. They are normalized " +
			"for cross-platform decryption, but make sure you can type the same " +
			"characters on every device where you'll decrypt this volume."
	}
	return ""
}

func ReadPasswordInteractive(confirm, allowEmpty bool) ([]byte, error) {
	// Once the prompt(s) have returned normally, clear the saved tty state so a
	// later unrelated signal does not re-poke the terminal.
	defer savedTerminalState.Store(nil)
	if isTerminal() {
		return readPasswordInteractive(confirm, allowEmpty, readTerminalPassword)
	}

	input := passwordLineInput{source: os.Stdin}
	defer input.clear()
	return readPasswordInteractive(confirm, allowEmpty, func(prompt string) ([]byte, error) {
		fmt.Fprint(os.Stderr, prompt)
		password, err := readPasswordLine(&input)
		if err != nil {
			return nil, fmt.Errorf("reading password: %w", err)
		}
		return password, nil
	})
}

// read must transfer independent, wholly owned buffers starting at allocation
// offset zero, including any partial result returned with an error.
func readPasswordInteractive(confirm, allowEmpty bool, read func(string) ([]byte, error)) ([]byte, error) {
	password, err := read("Password: ")
	transferred := false
	defer func() {
		if !transferred {
			secret.SecureZero(password[:cap(password)])
		}
	}()
	if err != nil {
		return nil, err
	}

	if len(password) == 0 && !allowEmpty {
		return nil, ErrPasswordEmpty
	}

	if confirm && len(password) > 0 {
		confirmPw, err := read("Confirm password: ")
		// Only the primary is transferred; confirmation is always discarded.
		defer secret.SecureZero(confirmPw[:cap(confirmPw)])
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(password, confirmPw) {
			return nil, ErrPasswordMismatch
		}
	}

	if note := nonASCIIPasswordNote(confirm, password); note != "" {
		fmt.Fprintln(os.Stderr, note)
	}

	transferred = true
	return password, nil
}

// ReadPasswordFromStdin reads password from stdin (for piped input with -P flag).
func ReadPasswordFromStdin() ([]byte, error) {
	pw, err := readPipedPassword(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("reading password from stdin: %w", err)
	}
	return pw, nil
}

// ReadPasswordFromFD reads one bounded password line from an inherited Unix
// descriptor. The child owns and closes the descriptor after this call.
func ReadPasswordFromFD(fd int) (password []byte, retErr error) {
	if runtime.GOOS == "windows" {
		return nil, errors.New("--password-fd is not supported on Windows")
	}
	if fd < 3 {
		return nil, errors.New("--password-fd must be 3 or higher")
	}
	file := os.NewFile(uintptr(fd), "password-fd")
	if file == nil {
		return nil, errors.New("password file descriptor is unavailable")
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			retErr = errors.Join(retErr, errors.New("password file descriptor could not be closed"))
		}
		if retErr != nil {
			secret.SecureZero(password[:cap(password)])
			password = nil
		}
	}()

	password, retErr = readPasswordFDLine(file)
	return password, retErr
}

func readPasswordFDLine(source io.Reader) ([]byte, error) {
	password, err := readPipedPassword(source)
	switch {
	case err == nil:
		return password, nil
	case errors.Is(err, errCLIPasswordTooLong):
		return nil, errors.New("password from file descriptor is too long")
	case errors.Is(err, io.ErrNoProgress):
		return nil, errors.New("reading password from file descriptor made no progress")
	default:
		return nil, errors.New("reading password from file descriptor failed")
	}
}

func readPipedPassword(source io.Reader) ([]byte, error) {
	input := passwordLineInput{source: source}
	defer input.clear()
	return readPasswordLine(&input)
}
