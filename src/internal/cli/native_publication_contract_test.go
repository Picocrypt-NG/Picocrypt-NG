package cli

import (
	"Picocrypt-NG/internal/pcv3operation"
	"errors"
	"strconv"
	"testing"
)

const (
	nativePCV3DurabilityWarning        = "Warning: output durability was not confirmed; keep source and destination unchanged\n"
	nativePCV3CleanupDurabilityWarning = "Warning: The app could not confirm that deleted temporary files will stay deleted after a power loss. Keep the source files.\n"
)

// Native file fixtures use testing.T.TempDir storage; metadata determines
// whether their publication and cleanup barriers must be durable.
func nativePCV3FileExit(t *testing.T) int {
	if !nativeCLIDirectorySyncSupported(t, t.TempDir()) {
		return ExitPCV3DurabilityUncertain
	}
	return 0
}

func nativePCV3Publication(t *testing.T) string {
	if !nativeCLIDirectorySyncSupported(t, t.TempDir()) {
		return "published-durability-uncertain"
	}
	return "published-durable"
}

func requireNativePCV3FileError(t *testing.T, err error) {
	t.Helper()
	if !nativeCLIDirectorySyncSupported(t, t.TempDir()) {
		if err == nil || !isExitCodeError(err) || exitCodeForError(err) != ExitPCV3DurabilityUncertain {
			t.Fatalf("native file result = %v; want typed durability-uncertain exit 3", err)
		}
	} else if err != nil {
		var result *pcv3operation.Result
		if errors.As(err, &result) && result != nil {
			t.Logf("PCV3 failure: stage=%s diagnostic=%d", result.Stage(), result.Diagnostic())
		}
		t.Fatalf("native durable file operation failed: %v", err)
	}
}

func requireNativePCV3Published(t *testing.T, result cliTestResult, comment string) {
	t.Helper()
	requireNativePCV3FileTerminal(t, result, comment, "success")
}

func requireNativePCV3FileTerminal(t *testing.T, result cliTestResult, comment, outcome string) {
	t.Helper()
	wantStderr := "Outcome: " + outcome + "\nPublication: " + nativePCV3Publication(t) + "\n"
	if comment != "" {
		wantStderr += "Comment: " + strconv.Quote(comment) + "\n"
	}
	if !nativeCLIDirectorySyncSupported(t, t.TempDir()) {
		wantStderr += nativePCV3DurabilityWarning + nativePCV3CleanupDurabilityWarning
	}
	if result.exitCode != nativePCV3FileExit(t) || len(result.stdout) != 0 || result.stderr != wantStderr {
		t.Fatalf("native file terminal = exit %d stdout %q stderr %q; want exit %d, empty stdout, stderr %q", result.exitCode, result.stdout, result.stderr, nativePCV3FileExit(t), wantStderr)
	}
}
