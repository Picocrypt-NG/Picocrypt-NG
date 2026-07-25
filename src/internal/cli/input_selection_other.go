//go:build !windows

package cli

import "strings"

func isInvalidWindowsWildcardPath(string, error) bool {
	return false
}

func looksLikeGlobPath(path string) bool {
	return strings.ContainsAny(path, "*?[")
}
