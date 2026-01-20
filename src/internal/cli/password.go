package cli

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"
)

var (
	ErrPasswordMismatch = errors.New("passwords do not match")
	ErrPasswordEmpty    = errors.New("password cannot be empty")
)

// isTerminal returns true if stdin is a terminal (not piped/redirected).
func isTerminal() bool {
	return term.IsTerminal(int(syscall.Stdin))
}

// readPasswordSecure reads a password from stdin without echo.
// Falls back to buffered read if stdin is not a terminal.
func readPasswordSecure(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)

	if !isTerminal() {
		// stdin is piped; read normally
		reader := bufio.NewReader(os.Stdin)
		pw, err := reader.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("reading password: %w", err)
		}
		pw = strings.TrimSuffix(pw, "\n")
		pw = strings.TrimSuffix(pw, "\r")
		return pw, nil
	}

	// Terminal mode: disable echo
	pw, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr) // newline after hidden input
	if err != nil {
		return "", fmt.Errorf("reading password: %w", err)
	}
	return string(pw), nil
}

// ReadPasswordInteractive prompts for password interactively.
// If confirm is true, asks for confirmation (for encryption).
// If allowEmpty is true, empty password is allowed (useful when keyfiles provide credentials).
func ReadPasswordInteractive(confirm, allowEmpty bool) (string, error) {
	password, err := readPasswordSecure("Password: ")
	if err != nil {
		return "", err
	}

	if password == "" && !allowEmpty {
		return "", ErrPasswordEmpty
	}

	if confirm && password != "" {
		confirmPw, err := readPasswordSecure("Confirm password: ")
		if err != nil {
			return "", err
		}
		if password != confirmPw {
			return "", ErrPasswordMismatch
		}
	}

	return password, nil
}

// ReadPasswordFromStdin reads password from stdin (for piped input with -P flag).
func ReadPasswordFromStdin() (string, error) {
	reader := bufio.NewReader(os.Stdin)
	pw, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("reading password from stdin: %w", err)
	}
	pw = strings.TrimSuffix(pw, "\n")
	pw = strings.TrimSuffix(pw, "\r")
	return pw, nil
}
