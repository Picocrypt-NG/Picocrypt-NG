package pcv3recovery

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3artifact"
	"Picocrypt-NG/internal/pcv3publication"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// A successful callback is insufficient: the core can still fail its final
// verification. This test catches transferring a pending spool too early.
func TestEncryptedStreamRecoveryWithholdsOwnerUntilCoreAccepted(t *testing.T) {
	for _, failure := range []string{"none", "error", "cancel", "classification", "second output", "panic"} {
		t.Run(failure, func(t *testing.T) {
			directory := t.TempDir()
			target := filepath.Join(directory, "output")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			semantic := operationSemantic{outcome: pcv3.OutcomeSuccess, code: pcv3.CodeSuccess}
			runner := func(_ context.Context, _ *Request, output operationOutput) (operationSemantic, error) {
				err := output(semantic, operationRoleCapsulePrimary, "", 5, func(sink operationSegmentSink) error { return sink(operationRange{}, []byte("hello")) })
				if err != nil {
					return operationSemantic{}, err
				}
				entries, err := os.ReadDir(directory)
				if err != nil || len(entries) != 1 {
					t.Fatalf("missing private ciphertext stage: %v %v", entries, err)
				}
				physical, err := os.ReadFile(filepath.Join(directory, entries[0].Name()))
				if err != nil || bytes.Contains(physical, []byte("hello")) {
					t.Fatalf("pending output wrote plaintext to disk: %v", err)
				}
				if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("premature publication: %v", err)
				}
				if failure == "error" {
					return semantic, errors.New("final verification failed")
				}
				if failure == "cancel" {
					cancel()
				}
				if failure == "classification" {
					semantic.outcome, semantic.code = pcv3.OutcomeAuthenticationFailed, pcv3.CodeAuthenticationFailed
				}
				if failure == "second output" {
					_ = output(semantic, operationRoleCapsulePrimary, "", 5, func(operationSegmentSink) error { return nil })
				}
				if failure == "panic" {
					panic("core panic after output")
				}
				return semantic, nil
			}
			var result *Result
			var panicked any
			func() {
				defer func() { panicked = recover() }()
				result = runWithCoreOptions(ctx, &Request{Target: target}, runner, ExecutionOptions{EncryptedStream: true})
			}()
			if failure == "panic" {
				if panicked == nil {
					t.Fatal("core panic was swallowed")
				}
			} else {
				if panicked != nil {
					t.Fatalf("unexpected panic: %v", panicked)
				}
				if result.PublicationAttempted() || result.PublicationState() != 0 || result.TakeRetainedOutput() != nil || result.TakeArchiveHandoff() != nil {
					t.Fatal("stream result gained publication authority")
				}
				owner := result.TakeEncryptedStream()
				if failure == "none" {
					if owner == nil || result.TakeEncryptedStream() != nil {
						t.Fatal("completed stream not transferred once")
					}
					physical, err := os.ReadFile(owner.Path())
					if err != nil || bytes.Contains(physical, []byte("hello")) {
						t.Fatalf("plaintext spool: %v", err)
					}
					reader, err := owner.OpenReader()
					if err != nil {
						t.Fatal(err)
					}
					got, err := io.ReadAll(reader)
					if closeErr := reader.Close(); err != nil || closeErr != nil || string(got) != "hello" {
						t.Fatalf("stream output %q: %v %v", got, err, closeErr)
					}
					if err := owner.Close(); err != nil {
						t.Fatal(err)
					}
				} else if owner != nil {
					_ = owner.Close()
					t.Fatal("failed core granted stream owner")
				}
			}
			entries, err := os.ReadDir(directory)
			if err != nil || len(entries) != 0 {
				t.Fatalf("stream cleanup left entries %v: %v", entries, err)
			}
		})
	}
}

func TestEncryptedStreamForceRecoveryPreservesForensicEnvelope(t *testing.T) {
	for _, unverified := range []bool{false, true} {
		semantic := operationSemantic{
			outcome: pcv3.OutcomeForcePartial, provenance: pcv3.ForceProvenancePartial,
			stage: pcv3.StageRecordAuth, code: pcv3.CodeForcePartial, plaintextLength: 5,
			ranges: fixtureRangeMap([]operationRange{{recordIndex: 0, start: 0, end: 5, state: pcv3.RecoveryRangeVerified}}), final: pcv3.RecoveryFinalMissing,
		}
		if unverified {
			semantic.outcome, semantic.provenance, semantic.code = pcv3.OutcomeForceUnverified, pcv3.ForceProvenanceUnverified, pcv3.CodeForceUnverified
			semantic.ranges = fixtureRangeMap([]operationRange{{recordIndex: 0, start: 0, end: 5, state: pcv3.RecoveryRangeUnverified}})
		}
		result := runWithCoreOptions(context.Background(), &Request{Target: filepath.Join(t.TempDir(), "forensic"), SourceSize: 1024}, fixedCoreRunner(semantic, [][]byte{[]byte("hello")}, nil), ExecutionOptions{EncryptedStream: true})
		owner := result.TakeEncryptedStream()
		if owner == nil {
			t.Fatalf("Force stream unavailable: %v/%v", result.Outcome(), result.Stage())
		}
		reader, err := owner.OpenReader()
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(reader)
		if closeErr := reader.Close(); err != nil || closeErr != nil {
			t.Fatalf("read artifact: %v %v", err, closeErr)
		}
		if err := owner.Close(); err != nil {
			t.Fatal(err)
		}
		artifact, err := pcv3artifact.Parse(context.Background(), bytes.NewReader(got), int64(len(got)))
		if err != nil {
			t.Fatalf("Force output lost forensic envelope: %v", err)
		}
		wantState, wantRole := pcv3artifact.StatePartial, pcv3artifact.RoleNone
		if unverified {
			wantState, wantRole = pcv3artifact.StateUnverifiedForensic, pcv3artifact.RolePrimary
		}
		metadata := artifact.Metadata()
		if metadata.PlaintextLength != 5 || metadata.State != wantState || metadata.Role != wantRole || metadata.Final != pcv3artifact.FinalMissing || metadata.RangeCount != 1 || result.ForceProvenance() != semantic.provenance {
			t.Fatal("Force stream lost recovery provenance")
		}
	}
}

func TestEncryptedStreamRecoveryAdmissionIncludesTagsAndPreservesSources(t *testing.T) {
	for _, test := range []struct {
		name      string
		length    uint64
		available int64
		admitted  bool
	}{
		{"empty tag refused", 0, 64 << 20, false},
		{"empty tag admitted", 0, (64 << 20) + 16, true},
		{"record tag refused", 5, (64 << 20) + 20, false},
		{"record tag admitted", 5, (64 << 20) + 21, true},
		{"second record tag refused", 65537, (64 << 20) + 65568, false},
		{"second record tag admitted", 65537, (64 << 20) + 65569, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := t.TempDir()
			source, target := filepath.Join(directory, "source"), filepath.Join(directory, "existing-output")
			if err := os.WriteFile(source, []byte("original encrypted source"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, []byte("foreign target"), 0o600); err != nil {
				t.Fatal(err)
			}
			emitted := false
			semantic := operationSemantic{outcome: pcv3.OutcomeSuccess, code: pcv3.CodeSuccess}
			runner := func(_ context.Context, _ *Request, output operationOutput) (operationSemantic, error) {
				err := output(semantic, operationRoleCapsulePrimary, "", test.length, func(sink operationSegmentSink) error {
					emitted = true
					return sink(operationRange{}, bytes.Repeat([]byte("x"), int(test.length)))
				})
				return semantic, err
			}
			result := runWithCoreOptions(context.Background(), &Request{Target: target, Protected: []string{source}, availableSpace: func(file *os.File) (int64, error) {
				if file == nil {
					t.Fatal("disk admission did not hold the original encrypted stage")
				}
				return test.available, nil
			}}, runner, ExecutionOptions{EncryptedStream: true})
			owner := result.TakeEncryptedStream()
			if emitted != test.admitted || (owner != nil) != test.admitted {
				t.Fatalf("physical budget accepted=%v emitted=%v", owner != nil, emitted)
			}
			if owner != nil {
				if err := owner.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if result.PublicationAttempted() || result.PublicationState() != 0 {
				t.Fatal("stream budget changed publication truth")
			}
			for path, want := range map[string]string{source: "original encrypted source", target: "foreign target"} {
				got, err := os.ReadFile(path)
				if err != nil || string(got) != want {
					t.Fatalf("stream modified a protected file: %v", err)
				}
			}
			entries, err := os.ReadDir(directory)
			if err != nil || len(entries) != 2 {
				t.Fatalf("stream residue: %v %v", entries, err)
			}
		})
	}
}

func TestEncryptedStreamRecoveryRejectsEmitterLengthMismatchAndWriteFailure(t *testing.T) {
	for _, fault := range []string{"short", "long", "write", "seal"} {
		t.Run(fault, func(t *testing.T) {
			directory := t.TempDir()
			semantic := operationSemantic{outcome: pcv3.OutcomeSuccess, code: pcv3.CodeSuccess}
			runner := func(_ context.Context, _ *Request, output operationOutput) (operationSemantic, error) {
				err := output(semantic, operationRoleCapsulePrimary, "", 5, func(sink operationSegmentSink) error {
					payload := []byte("hello")
					if fault == "short" {
						payload = payload[:4]
					}
					if fault == "long" {
						payload = []byte("longer")
					}
					return sink(operationRange{}, payload)
				})
				return semantic, err
			}
			request := &Request{Target: filepath.Join(directory, "output")}
			if fault == "write" {
				request.stageWriter = func(io.Writer) io.Writer { return recoveryEncryptedFaultWriter{} }
			}
			if fault == "seal" {
				request.stageWriter = func(writer io.Writer) io.Writer {
					owner := writer.(interface{ File() *os.File })
					if err := owner.File().Close(); err != nil {
						t.Fatal(err)
					}
					return writer
				}
			}
			result := runWithCoreOptions(context.Background(), request, runner, ExecutionOptions{EncryptedStream: true})
			if owner := result.TakeEncryptedStream(); owner != nil {
				_ = owner.Close()
				t.Fatal("faulty stream granted output capability")
			}
			if result.Outcome() != pcv3.OutcomeOperationFailed || result.PublicationAttempted() || result.PublicationState() != 0 {
				t.Fatal("faulty stream reported completed output")
			}
			if fault == "seal" && !errors.Is(result, pcv3publication.ErrCleanupIncomplete) {
				t.Fatal("closed original FD cleanup error was dropped")
			}
			entries, err := os.ReadDir(directory)
			if err != nil || len(entries) != 0 {
				t.Fatalf("failed stream residue: %v %v", entries, err)
			}
		})
	}
}

type recoveryEncryptedFaultWriter struct{}

func (recoveryEncryptedFaultWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestEncryptedStreamRecoveryConstructorPreservesCleanupFailureWithoutPublication(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "clean cancellation", true: "foreign replacement"}[replace], func(t *testing.T) {
			directory := t.TempDir()
			ctx := &recoveryConstructorCancellationContext{Context: context.Background(), t: t, directory: directory, replace: replace}
			semantic := operationSemantic{outcome: pcv3.OutcomeSuccess, code: pcv3.CodeSuccess}
			runner := func(_ context.Context, _ *Request, output operationOutput) (operationSemantic, error) {
				err := output(semantic, operationRoleCapsulePrimary, "", 5, func(operationSegmentSink) error { t.Fatal("cancelled constructor reached emitter"); return nil })
				return semantic, err
			}
			result := runWithCoreOptions(ctx, &Request{Target: filepath.Join(directory, "output")}, runner, ExecutionOptions{EncryptedStream: true})
			if result.Outcome() != pcv3.OutcomeOperationFailed || errors.Is(result, pcv3publication.ErrCleanupIncomplete) != replace {
				t.Fatalf("constructor cleanup truth lost: %v", result)
			}
			if result.PublicationAttempted() || result.PublicationState() != 0 || result.TakeEncryptedStream() != nil {
				t.Fatal("constructor failure gained publication or stream authority")
			}
			if replace {
				got, err := os.ReadFile(ctx.replacement)
				if err != nil || string(got) != "foreign replacement" {
					t.Fatalf("foreign replacement changed: %q %v", got, err)
				}
			} else {
				entries, err := os.ReadDir(directory)
				if err != nil || len(entries) != 0 {
					t.Fatalf("clean cancellation left stage: %v %v", entries, err)
				}
			}
		})
	}
}

type recoveryConstructorCancellationContext struct {
	context.Context
	t                      *testing.T
	directory, replacement string
	replace, cancelled     bool
}

func (ctx *recoveryConstructorCancellationContext) Err() error {
	if ctx.cancelled {
		return context.Canceled
	}
	entries, err := os.ReadDir(ctx.directory)
	if err != nil {
		ctx.t.Fatal(err)
	}
	if len(entries) == 0 {
		return nil
	}
	if len(entries) != 1 {
		ctx.t.Fatalf("unexpected constructor stage: %v", entries)
	}
	if ctx.replace {
		ctx.replacement = filepath.Join(ctx.directory, entries[0].Name())
		if err := os.Rename(ctx.replacement, ctx.replacement+".moved"); err != nil {
			ctx.t.Fatal(err)
		}
		if err := os.WriteFile(ctx.replacement, []byte("foreign replacement"), 0o600); err != nil {
			ctx.t.Fatal(err)
		}
	}
	ctx.cancelled = true
	return context.Canceled
}
