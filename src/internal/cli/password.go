package cli

import (
	"Picocrypt-NG/internal/secret"
	"bufio"
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

func readPasswordLine(reader *bufio.Reader) ([]byte, error) {
	pw, err := reader.ReadBytes('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}

	pw = bytes.TrimSuffix(pw, []byte("\n"))
	pw = bytes.TrimSuffix(pw, []byte("\r"))
	return pw, nil
}

// readPasswordSecure reads a password from stdin without echo, returning owned
// []byte the caller can zero. Falls back to buffered read if stdin is not a
// terminal.
func readPasswordSecure(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)

	if !isTerminal() {
		// stdin is piped; read normally
		reader := bufio.NewReader(os.Stdin)
		pw, err := readPasswordLine(reader)
		if err != nil {
			return nil, fmt.Errorf("reading password: %w", err)
		}
		return pw, nil
	}

	// Terminal mode: capture the current tty state so a SIGINT during the
	// no-echo read can be restored by the signal handler (os.Exit skips
	// term.ReadPassword's own deferred restore).
	captureTerminalState()

	// Terminal mode: disable echo. term.ReadPassword returns an owned []byte.
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
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

	password, err := readPasswordSecure("Password: ")
	if err != nil {
		return nil, err
	}

	if len(password) == 0 && !allowEmpty {
		return nil, ErrPasswordEmpty
	}

	if confirm && len(password) > 0 {
		confirmPw, err := readPasswordSecure("Confirm password: ")
		if err != nil {
			return nil, err
		}
		// Zero the confirmation copy once compared; only `password` is returned.
		defer secret.SecureZero(confirmPw)
		if !bytes.Equal(password, confirmPw) {
			return nil, ErrPasswordMismatch
		}
	}

	if note := nonASCIIPasswordNote(confirm, password); note != "" {
		fmt.Fprintln(os.Stderr, note)
	}

	return password, nil
}

// ReadPasswordFromStdin reads password from stdin (for piped input with -P flag).
func ReadPasswordFromStdin() ([]byte, error) {
	reader := bufio.NewReader(os.Stdin)
	pw, err := readPasswordLine(reader)
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
			secret.SecureZero(password)
			password = nil
		}
	}()

	password, retErr = readPasswordFDLine(file)
	return password, retErr
}

func readPasswordFDLine(reader io.Reader) ([]byte, error) {
	password := make([]byte, maximumCLIPasswordBytes+2)
	used := 0
	success := false
	defer func() {
		if !success {
			secret.SecureZero(password)
		}
	}()

	for {
		if used == len(password) {
			return nil, errors.New("password from file descriptor is too long")
		}
		n, err := reader.Read(password[used:])
		complete := false
		if index := bytes.IndexByte(password[used:used+n], '\n'); index >= 0 {
			lineEnd := used + index
			secret.SecureZero(password[lineEnd : used+n])
			used = lineEnd
			complete = true
		} else {
			used += n
		}
		if complete || errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errors.New("reading password from file descriptor failed")
		}
		if n == 0 {
			return nil, errors.New("reading password from file descriptor made no progress")
		}
	}

	if used > 0 && password[used-1] == '\r' {
		password[used-1] = 0
		used--
	}
	if used > maximumCLIPasswordBytes {
		return nil, errors.New("password from file descriptor is too long")
	}
	success = true
	return password[:used], nil
}
