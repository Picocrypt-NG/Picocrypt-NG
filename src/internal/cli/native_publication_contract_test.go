package cli

import (
	"runtime"
	"strconv"
	"testing"
)

const nativePCV3DurabilityWarning = "Warning: output durability was not confirmed; keep source and destination unchanged\n"

// File publication and byte recovery remain observable on Windows, while its
// native directory barrier cannot assert durability or authorize source deletion.
func nativePCV3FileExit() int {
	if runtime.GOOS == "windows" {
		return ExitPCV3DurabilityUncertain
	}
	return 0
}

func nativePCV3Publication() string {
	if runtime.GOOS == "windows" {
		return "published-durability-uncertain"
	}
	return "published-durable"
}

func requireNativePCV3FileError(t *testing.T, err error) {
	t.Helper()
	if runtime.GOOS == "windows" {
		if err == nil || !isExitCodeError(err) || exitCodeForError(err) != ExitPCV3DurabilityUncertain {
			t.Fatalf("native file result = %v; want typed durability-uncertain exit 3", err)
		}
	} else if err != nil {
		t.Fatalf("native durable file operation failed: %v", err)
	}
}

func requireNativePCV3Published(t *testing.T, result cliTestResult, comment string) {
	t.Helper()
	wantStderr := "Outcome: success\nPublication: " + nativePCV3Publication() + "\n"
	if comment != "" {
		wantStderr += "Comment: " + strconv.Quote(comment) + "\n"
	}
	if runtime.GOOS == "windows" {
		wantStderr += nativePCV3DurabilityWarning
	}
	if result.exitCode != nativePCV3FileExit() || len(result.stdout) != 0 || result.stderr != wantStderr {
		t.Fatalf("native file terminal = exit %d stdout %q stderr %q; want exit %d, empty stdout, stderr %q", result.exitCode, result.stdout, result.stderr, nativePCV3FileExit(), wantStderr)
	}
}
