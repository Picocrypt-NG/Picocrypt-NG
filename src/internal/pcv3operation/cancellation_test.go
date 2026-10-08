package pcv3operation

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func cancellationTestSource(t *testing.T) (*os.File, string, string) {
	t.Helper()
	directory := t.TempDir()
	path := filepath.Join(directory, "source")
	if err := os.WriteFile(path, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = source.Close() })
	return source, path, filepath.Join(directory, "ciphertext")
}

func cancellationTestFactors() *FactorRequest {
	return &FactorRequest{
		Mode:           CredentialModePasswordOnly,
		KeyfileMode:    KeyfileModeNone,
		ExpectedPolicy: FactorPolicyPasswordOnly,
		Password:       []byte("public cancellation test password"),
	}
}

func assertCancellationNoOutput(t *testing.T, result *Result, path string) {
	t.Helper()
	if result == nil {
		t.Fatal("missing operation result")
	}
	if result.PublicationAttempted() || result.SourceDeletionAllowed() || result.OutputFollowUp() != nil || result.ArchiveFollowUp() != nil {
		t.Errorf("cancellation granted output/deletion: attempted=%v deletion=%v", result.PublicationAttempted(), result.SourceDeletionAllowed())
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "data" {
		t.Errorf("source changed: got=%q err=%v", got, err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "source" {
		t.Errorf("cancellation left output/private staging: %v", entries)
	}
}

// Public production runner; cancellation occurs before fixed-profile derivation.
// Reaching StatusCheckingResources proves mode/suite/source/target/factors and
// publication capability checks accepted the request before this boundary.
func TestWriteCancellationDuringResourceAdmissionPreservesCause(t *testing.T) {
	for _, mode := range []WriteMode{WriteModeNormal, WriteModeD1} {
		name := "normal"
		suite := SuiteStandard
		if mode == WriteModeD1 {
			name = "d1"
			suite = SuiteParanoid
		}
		t.Run(name, func(t *testing.T) {
			source, sourcePath, target := cancellationTestSource(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reachedAdmission := false
			deriving := false
			factors := cancellationTestFactors()
			password := factors.Password
			result := RunWriteWithOptions(ctx, &WriteRequest{
				Mode: mode, Suite: suite, PayloadKind: PayloadKindRaw,
				PlaintextLength: 4, Source: source, SourceFile: source,
				SourcePath: sourcePath, Target: target, Factors: factors,
				Reporter: func(status Status) error {
					if status.Code() == StatusCheckingResources {
						reachedAdmission = true
						cancel()
					}
					if status.Code() == StatusDerivingKey {
						deriving = true
					}
					return nil
				},
			}, ExecutionOptions{JournalPrivateStage: runtime.GOOS == "linux" || runtime.GOOS == "android"})
			if !reachedAdmission || deriving || ctx.Err() != context.Canceled {
				t.Fatalf("repro did not isolate admission cancellation: reached=%v deriving=%v ctx=%v result=%v", reachedAdmission, deriving, ctx.Err(), result)
			}
			t.Logf("mode=%s stage=%v diagnostic=%v canceled=%v deadline=%v", name, result.Stage(), result.Diagnostic(), errors.Is(result, context.Canceled), errors.Is(result, context.DeadlineExceeded))
			assertCancellationNoOutput(t, result, sourcePath)
			if _, err := source.Stat(); err != nil {
				t.Errorf("borrowed write source was closed: %v", err)
			}
			for _, value := range password {
				if value != 0 {
					t.Error("cancellation retained password bytes")
					break
				}
			}
			if result.Stage() != StageCancellation || result.Diagnostic() != DiagnosticCancellation || !errors.Is(result, context.Canceled) || errors.Is(result, context.DeadlineExceeded) {
				t.Errorf("admission cancellation lost terminal classification: stage=%v diagnostic=%v canceled=%v deadline=%v", result.Stage(), result.Diagnostic(), errors.Is(result, context.Canceled), errors.Is(result, context.DeadlineExceeded))
			}
		})
	}
}

// A canceled read exits inside RunNativeRead before Probe and any KDF; it is
// intentionally canceled after the operation-level initial context check.
func TestReadCancellationAfterValidationPreservesCause(t *testing.T) {
	source, sourcePath, target := cancellationTestSource(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reachedAuthentication := false
	result := Run(ctx, &Request{
		Mode: ModeReadNormal, Source: source, Factors: cancellationTestFactors(), Target: target,
		Reporter: func(status Status) error {
			if status.Code() == StatusAuthenticating {
				reachedAuthentication = true
				cancel()
			}
			return nil
		},
	})
	if !reachedAuthentication || ctx.Err() != context.Canceled || result.Stage() != StageCancellation {
		t.Fatalf("repro did not isolate read cancellation: reached=%v ctx=%v result=%v stage=%v", reachedAuthentication, ctx.Err(), result, result.Stage())
	}
	t.Logf("stage=%v diagnostic=%v canceled=%v", result.Stage(), result.Diagnostic(), errors.Is(result, context.Canceled))
	assertCancellationNoOutput(t, result, sourcePath)
	if _, err := source.Stat(); err == nil {
		t.Error("owned read source remained open")
	}
	if result.Diagnostic() != DiagnosticCancellation || !errors.Is(result, context.Canceled) {
		t.Errorf("native read cancellation lost diagnostic/sentinel: diagnostic=%v canceled=%v", result.Diagnostic(), errors.Is(result, context.Canceled))
	}
}

func TestReadDeadlinePreservesExactSentinel(t *testing.T) {
	source, sourcePath, target := cancellationTestSource(t)
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	result := Run(ctx, &Request{Mode: ModeReadNormal, Source: source, Factors: cancellationTestFactors(), Target: target})
	if ctx.Err() != context.DeadlineExceeded || result.Stage() != StageCancellation || result.Diagnostic() != DiagnosticCancellation {
		t.Fatalf("repro did not reach early deadline: ctx=%v stage=%v diagnostic=%v", ctx.Err(), result.Stage(), result.Diagnostic())
	}
	t.Logf("canceled=%v deadline=%v", errors.Is(result, context.Canceled), errors.Is(result, context.DeadlineExceeded))
	assertCancellationNoOutput(t, result, sourcePath)
	if !errors.Is(result, context.DeadlineExceeded) || errors.Is(result, context.Canceled) {
		t.Errorf("read deadline matched incorrect cancellation sentinel: canceled=%v deadline=%v", errors.Is(result, context.Canceled), errors.Is(result, context.DeadlineExceeded))
	}
}
