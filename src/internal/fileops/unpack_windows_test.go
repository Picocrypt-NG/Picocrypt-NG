package fileops

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestNormalizeZipPathWindowsBehavior verifies that normalizeZipPath handles
// Windows-specific path scenarios correctly, including edge cases that could
// cause issues on Windows systems.
func TestNormalizeZipPathWindowsBehavior(t *testing.T) {
	testCases := []struct {
		name           string
		input          string
		expectContains string // What the output should contain (platform-agnostic check)
		shouldWork     bool
	}{
		{
			name:           "Unix forward slashes",
			input:          "dir/subdir/file.txt",
			expectContains: "file.txt",
			shouldWork:     true,
		},
		{
			name:           "Windows backslashes",
			input:          "dir\\subdir\\file.txt",
			expectContains: "file.txt",
			shouldWork:     true,
		},
		{
			name:           "Mixed separators",
			input:          "dir/subdir\\file.txt",
			expectContains: "file.txt",
			shouldWork:     true,
		},
		{
			name:           "Double dots in filename (not path traversal)",
			input:          "dir/test..txt",
			expectContains: "test..txt",
			shouldWork:     true,
		},
		{
			name:           "Russian filename with dots",
			input:          "documents/Исследования..копия.docx",
			expectContains: "копия.docx",
			shouldWork:     true,
		},
		{
			name:           "Windows UNC path style (should be normalized)",
			input:          "share\\folder\\file.txt",
			expectContains: "file.txt",
			shouldWork:     true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := normalizeZipPath(tc.input)

			// Verify the result contains expected component
			if !strings.Contains(result, tc.expectContains) {
				t.Errorf("normalizeZipPath(%q) = %q, should contain %q",
					tc.input, result, tc.expectContains)
			}

			// Verify the result uses platform-specific separators
			if runtime.GOOS == "windows" {
				// On Windows, should use backslashes
				if strings.Contains(result, "/") && strings.Contains(tc.input, "/") {
					t.Errorf("normalizeZipPath(%q) = %q, should convert forward slashes to backslashes on Windows",
						tc.input, result)
				}
			} else {
				// On Unix, should use forward slashes
				if strings.Contains(result, "\\") {
					t.Errorf("normalizeZipPath(%q) = %q, should use forward slashes on Unix",
						tc.input, result)
				}
			}

			t.Logf("Platform: %s, Input: %q -> Output: %q", runtime.GOOS, tc.input, result)
		})
	}
}

// TestIsValidExtractionPathWindows verifies that path validation works correctly
// on Windows, including edge cases with drive letters and UNC paths.
func TestIsValidExtractionPathWindows(t *testing.T) {
	// Use temp directory as base (works cross-platform)
	baseDir := t.TempDir()

	testCases := []struct {
		name       string
		path       string // Relative path from baseDir
		shouldPass bool
	}{
		{
			name:       "Normal subdirectory",
			path:       "extracted/file.txt",
			shouldPass: true,
		},
		{
			name:       "Path traversal attempt",
			path:       "../../../etc/passwd",
			shouldPass: false,
		},
		{
			name:       "File with double dots in name",
			path:       "extracted/test..txt",
			shouldPass: true,
		},
		{
			name:       "Subdirectory with double dots in name",
			path:       "extracted..backup/file.txt",
			shouldPass: true,
		},
		{
			name:       "Tricky traversal with forward then backward",
			path:       "good/../../bad/file.txt",
			shouldPass: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Construct full path using filepath.Join (platform-aware)
			fullPath := filepath.Join(baseDir, tc.path)
			result := isValidExtractionPath(fullPath, baseDir)

			if result != tc.shouldPass {
				t.Errorf("isValidExtractionPath(%q, %q) = %v, want %v",
					fullPath, baseDir, result, tc.shouldPass)
			}

			t.Logf("Platform: %s, Path: %q -> Valid: %v", runtime.GOOS, tc.path, result)
		})
	}
}

// TestFilepathFromSlashLimitations verifies that normalizeZipPath collapses both
// slash styles to the single OS path separator on every platform, so neither a
// forward slash nor a backslash can smuggle a hidden path component past
// extraction-root validation. The named inputs are the historically tricky
// filepath.FromSlash edge cases.
func TestFilepathFromSlashLimitations(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		want        string
		description string
	}{
		{
			name:        "Backslash in Unix path",
			input:       "a\\b",
			want:        `a\b`,
			description: "On Unix: filename 'a\\b'. On Windows: file 'b' in directory 'a'",
		},
		{
			name:        "Drive letter path",
			input:       "C:/foo",
			want:        `C:\foo`,
			description: "On Unix: relative path 'C:/foo'. On Windows: absolute path 'C:\\foo'",
		},
		{
			name:        "Mixed separators",
			input:       "a/b\\c",
			want:        `a\b\c`,
			description: "Behavior depends on platform separator handling",
		},
	}

	// foreignSeparator is the slash that is NOT this platform's path separator.
	// normalizeZipPath converts every separator to the OS one, so the foreign
	// slash must never survive: on Windows the backslash is a legitimate
	// separator (not a violation), while a stray forward slash would be; on Unix
	// the reverse holds.
	foreignSeparator := "\\"
	if filepath.Separator == '\\' {
		foreignSeparator = "/"
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			normalized := normalizeZipPath(tc.input)
			if normalized != tc.want {
				t.Errorf("normalizeZipPath(%q) = %q, want %q", tc.input, normalized, tc.want)
			}
			if strings.Contains(normalized, foreignSeparator) {
				t.Errorf("normalizeZipPath(%q) = %q retains foreign separator %q; must use only the OS separator %q (%s)",
					tc.input, normalized, foreignSeparator, string(filepath.Separator), tc.description)
			}
		})
	}
}
