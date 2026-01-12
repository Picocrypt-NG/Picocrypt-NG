package cli

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

// readPasswordInteractive prompts user for password with asterisk masking.
// Returns empty string if stdin is not a terminal.
func readPasswordInteractive(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", nil
	}

	fmt.Fprint(os.Stderr, prompt)

	// Put terminal in raw mode for character-by-character reading
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		// Fallback to standard ReadPassword if raw mode fails
		pw, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("reading password: %w", err)
		}
		return string(pw), nil
	}
	defer term.Restore(fd, oldState)

	var password []byte
	var b [1]byte

	for {
		n, err := os.Stdin.Read(b[:])
		if err != nil || n == 0 {
			fmt.Fprint(os.Stderr, "\r\n")
			return string(password), nil
		}

		switch b[0] {
		case '\r', '\n': // Enter
			fmt.Fprint(os.Stderr, "\r\n")
			return string(password), nil
		case 3: // Ctrl+C
			fmt.Fprint(os.Stderr, "\r\n")
			return "", fmt.Errorf("cancelled")
		case 4: // Ctrl+D (EOF)
			fmt.Fprint(os.Stderr, "\r\n")
			return string(password), nil
		case 127, 8: // Backspace (DEL or BS)
			if len(password) > 0 {
				password = password[:len(password)-1]
				fmt.Fprint(os.Stderr, "\b \b") // erase last asterisk
			}
		default:
			if b[0] >= 32 { // Printable character
				password = append(password, b[0])
				fmt.Fprint(os.Stderr, "*")
			}
		}
	}
}
