package util

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
)

// RandomBytes generates n cryptographically secure random bytes using crypto/rand.
// This is suitable for generating keyfiles, salts, and other cryptographic material.
//
// Returns an error if n <= 0 or if the system's cryptographic random number generator fails.
func RandomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, errors.New("invalid length")
	}
	data := make([]byte, n)
	if _, err := rand.Read(data); err != nil {
		return nil, err
	}
	return data, nil
}

// PassgenOptions configures the password generator.
//
// At least one character set (Upper, Lower, Numbers, or Symbols) must be enabled,
// otherwise GenPassword returns an empty string.
type PassgenOptions struct {
	Length  int  // Password length (recommended: 16-32 for strong security)
	Upper   bool // Include uppercase letters A-Z
	Lower   bool // Include lowercase letters a-z
	Numbers bool // Include digits 0-9
	Symbols bool // Include symbols -=_+!@#$^&()?<>
}

// GenPassword generates a cryptographically secure password based on the given options.
//
// The password is generated using crypto/rand for true randomness, making it suitable
// for encryption keys, passphrases, and high-security applications.
//
// Character sets:
//   - Upper: ABCDEFGHIJKLMNOPQRSTUVWXYZ (26 characters)
//   - Lower: abcdefghijklmnopqrstuvwxyz (26 characters)
//   - Numbers: 1234567890 (10 characters)
//   - Symbols: -=_+!@#$^&()?<> (15 characters)
//
// Returns:
//   - Empty string if no character sets are enabled or Length <= 0
//   - Error if crypto/rand fails (extremely rare, indicates system issue)
//
// Example:
//
//	password, err := GenPassword(PassgenOptions{
//	    Length: 20,
//	    Upper: true,
//	    Lower: true,
//	    Numbers: true,
//	    Symbols: false,
//	})
//	// Generates: "aB7xK9mPzR3qW8nL5tY2"
func GenPassword(opts PassgenOptions) (string, error) {
	chars := ""
	if opts.Upper {
		chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	}
	if opts.Lower {
		chars += "abcdefghijklmnopqrstuvwxyz"
	}
	if opts.Numbers {
		chars += "1234567890"
	}
	if opts.Symbols {
		chars += "-=_+!@#$^&()?<>"
	}

	if len(chars) == 0 || opts.Length <= 0 {
		return "", nil
	}

	tmp := make([]byte, opts.Length)
	for i := range opts.Length {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", fmt.Errorf("fatal crypto/rand error: %w", err)
		}
		tmp[i] = chars[j.Int64()]
	}
	return string(tmp), nil
}
