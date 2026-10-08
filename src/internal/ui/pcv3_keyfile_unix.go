//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package ui

import (
	"Picocrypt-NG/internal/fileops"
	"os"
)

func openPCV3InputFile(path string) (*os.File, error) {
	return fileops.OpenRegularReadNoSymlink(path)
}
