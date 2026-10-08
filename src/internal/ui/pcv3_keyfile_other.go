//go:build windows || wasm

package ui

import (
	"Picocrypt-NG/internal/fileops"
	"os"
)

func openPCV3InputFile(path string) (*os.File, error) {
	return fileops.OpenRegularReadNoSymlink(path)
}
