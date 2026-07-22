//go:build windows

package cli

import (
	"errors"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func isInvalidWindowsWildcardPath(path string, err error) bool {
	pathWithoutVolume := strings.TrimPrefix(path, filepath.VolumeName(path))
	return strings.ContainsAny(pathWithoutVolume, "*?") && errors.Is(err, windows.ERROR_INVALID_NAME)
}

func looksLikeGlobPath(path string) bool {
	pathWithoutVolume := strings.TrimPrefix(path, filepath.VolumeName(path))
	return strings.ContainsAny(pathWithoutVolume, "*?[")
}
