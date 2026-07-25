//go:build windows

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestInvalidWindowsWildcardPathClassification(t *testing.T) {
	invalidName := func(path string) error {
		return &os.PathError{Op: "stat", Path: path, Err: windows.ERROR_INVALID_NAME}
	}
	accessDenied := func(path string) error {
		return &os.PathError{Op: "stat", Path: path, Err: windows.ERROR_ACCESS_DENIED}
	}

	for _, tc := range []struct {
		name string
		path string
		err  error
		want bool
	}{
		{name: "drive wildcard", path: "C:\\data\\*.txt", err: invalidName("C:\\data\\*.txt"), want: true},
		{name: "extended drive wildcard", path: "\\\\?\\C:\\data\\*.txt", err: invalidName("\\\\?\\C:\\data\\*.txt"), want: true},
		{name: "extended drive prefix", path: "\\\\?\\C:\\data\\file.txt", err: invalidName("\\\\?\\C:\\data\\file.txt")},
		{name: "extended UNC prefix", path: "\\\\?\\UNC\\server\\share\\file.txt", err: invalidName("\\\\?\\UNC\\server\\share\\file.txt")},
		{name: "access denied is not hidden", path: "C:\\data\\*.txt", err: accessDenied("C:\\data\\*.txt")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isInvalidWindowsWildcardPath(tc.path, tc.err); got != tc.want {
				t.Fatalf("isInvalidWindowsWildcardPath(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestMissingExtendedWindowsPathIsNotReportedAsGlob(t *testing.T) {
	missing := "\\\\?\\" + filepath.Join(t.TempDir(), "definitely-missing.txt")
	_, err := resolveEncryptInputs([]string{missing}, nil, false)
	if err == nil {
		t.Fatal("expected missing extended path error")
	}
	if strings.Contains(err.Error(), "use --glob") {
		t.Fatalf("missing extended path misclassified as glob: %v", err)
	}
}
