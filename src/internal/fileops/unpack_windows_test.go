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

// TestFilepathFromSlashLimitations documents known limitations of filepath.FromSlash
// that could affect Windows behavior.
func TestFilepathFromSlashLimitations(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		description string
	}{
		{
			name:        "Backslash in Unix path",
			input:       "a\\b",
			description: "On Unix: filename 'a\\b'. On Windows: file 'b' in directory 'a'",
		},
		{
			name:        "Drive letter path",
			input:       "C:/foo",
			description: "On Unix: relative path 'C:/foo'. On Windows: absolute path 'C:\\foo'",
		},
		{
			name:        "Mixed separators",
			input:       "a/b\\c",
			description: "Behavior depends on platform separator handling",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := filepath.FromSlash(tc.input)
			t.Logf("Platform: %s", runtime.GOOS)
			t.Logf("Input: %q", tc.input)
			t.Logf("Output: %q", result)
			t.Logf("Description: %s", tc.description)

			// Verify our normalizeZipPath handles this correctly
			normalized := normalizeZipPath(tc.input)
			t.Logf("After normalizeZipPath: %q", normalized)

			// On Windows, backslashes should be removed before FromSlash
			if runtime.GOOS == "windows" && strings.Contains(tc.input, "\\") {
				// Our normalizeZipPath should have converted backslashes to forward slashes first
				// Then FromSlash converts them to platform separator
				if !strings.Contains(normalized, string(filepath.Separator)) {
					t.Logf("Note: Input had backslashes, normalized correctly")
				}
			}
		})
	}
}
