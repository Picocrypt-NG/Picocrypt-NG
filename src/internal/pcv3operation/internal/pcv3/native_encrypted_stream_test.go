package pcv3

import (
	"Picocrypt-NG/internal/fileops"
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"testing"
)

// The production codec and frozen keys remain real; only expensive credential
// derivation is bypassed. Plaintext publication or an early handoff breaks this.
func TestNativeEncryptedStreamAuthenticatesBeforeHandoffAndNeverStagesPlaintext(t *testing.T) {
	for _, id := range []string{"normal-standard-password-only-small", normalArchiveFixtureID, "normal-standard-combined-ordered-empty", "normal-negative-final"} {
		t.Run(id, func(t *testing.T) {
			fixture := requireNormalFixture(t, loadNormalFixtureManifest(t).FixturesByID(), id)
			volume := readNormalFixtureArtifact(t, fixture.Volume)
			source := newNormalFixtureSource(t, fixture, volume)
			structure := probeNormalBehavior(t, source, int64(len(volume)))
			directory := t.TempDir()
			target := filepath.Join(directory, "output")
			sink := &nativeReadSink{target: target, encryptedStream: true}
			var owner *fileops.EncryptedSpool
			var escaped *NativeReadOutput
			called := false
			result := runNativeReadSession(context.Background(), source, int64(len(volume)), structure,
				newNormalFixtureCredentialProvider(t, fixture.Keys), sink, func(output *NativeReadOutput) error {
					called = true
					escaped = output
					if output.Disposition() != NativePayloadStream || output.Publish(context.Background()) != nil || output.Archive() != nil {
						t.Fatal("stream output granted filesystem or archive authority")
					}
					owner = output.TakeEncryptedStream()
					if owner == nil || output.TakeEncryptedStream() != nil || sink.stage != nil {
						t.Fatal("encrypted stream was absent, repeated, or accompanied by a plaintext stage")
					}
					return nil
				})
			if id == "normal-negative-final" {
				if called || owner != nil || result.Outcome() == OutcomeSuccess {
					t.Fatal("failed final authentication granted stream authority")
				}
				assertNoNativeEncryptedResidue(t, directory)
				return
			}
			if !called || owner == nil || result.Outcome() != OutcomeSuccess || result.CallbackFailed() || result.PublicationAttempted() || result.PublicationState() != 0 || result.CleanupIncomplete() {
				t.Fatalf("stream result: outcome=%v publication=%v/%v callback=%v cleanup=%v", result.Outcome(), result.PublicationAttempted(), result.PublicationState(), result.CallbackFailed(), result.CleanupIncomplete())
			}
			defer owner.Close()
			if escaped.TakeEncryptedStream() != nil {
				t.Fatal("escaped callback retained stream authority")
			}
			want := readNormalFixturePlaintext(t, fixture.Plaintext)
			physical, err := os.ReadFile(owner.Path())
			if err != nil || (len(want) != 0 && bytes.Contains(physical, want)) {
				t.Fatalf("plaintext reached disk: %v", err)
			}
			reader, err := owner.OpenReader()
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(reader)
			if closeErr := reader.Close(); err != nil || closeErr != nil || !bytes.Equal(got, want) {
				t.Fatalf("authenticated stream differs: read=%v close=%v", err, closeErr)
			}
			if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("published output: %v", err)
			}
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
			assertNoNativeEncryptedResidue(t, directory)
		})
	}
}

func TestNativeEncryptedStreamAbandonedCallbackRemovesCiphertext(t *testing.T) {
	fixture := requireNormalFixture(t, loadNormalFixtureManifest(t).FixturesByID(), "normal-standard-password-only-small")
	volume := readNormalFixtureArtifact(t, fixture.Volume)
	source := newNormalFixtureSource(t, fixture, volume)
	directory := t.TempDir()
	result := runNativeReadSession(context.Background(), source, int64(len(volume)), probeNormalBehavior(t, source, int64(len(volume))),
		newNormalFixtureCredentialProvider(t, fixture.Keys), &nativeReadSink{target: filepath.Join(directory, "output"), encryptedStream: true},
		func(*NativeReadOutput) error { return errors.New("declined") })
	if !result.CallbackFailed() || result.PublicationAttempted() || result.CleanupIncomplete() {
		t.Fatal("abandoned stream lost callback/cleanup truth")
	}
	assertNoNativeEncryptedResidue(t, directory)
}

func TestNativeEncryptedStreamWriteFailureAndPanicCloseOwnedStage(t *testing.T) {
	for _, fault := range []string{"write", "cancel", "panic"} {
		t.Run(fault, func(t *testing.T) {
			fixture := requireNormalFixture(t, loadNormalFixtureManifest(t).FixturesByID(), "normal-standard-password-only-small")
			volume := readNormalFixtureArtifact(t, fixture.Volume)
			source := newNormalFixtureSource(t, fixture, volume)
			directory := t.TempDir()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sink := &nativeReadSink{target: filepath.Join(directory, "output"), encryptedStream: true}
			sink.stageWriter = func(destination io.Writer) io.Writer {
				if sink.stage != nil || sink.encryptedOutput == nil {
					t.Fatal("first plaintext write has no encrypted owner")
				}
				physical, err := os.ReadFile(sink.encryptedOutput.Path())
				if err != nil || len(physical) != 0 {
					t.Fatalf("unexpected pre-write bytes: %v", err)
				}
				if fault == "panic" {
					panic("sink panic")
				}
				if fault == "cancel" {
					cancel()
					return destination
				}
				return nativeEncryptedFaultWriter{}
			}
			called := false
			var result *NativeReadResult
			var panicValue any
			func() {
				defer func() { panicValue = recover() }()
				result = runNativeReadSession(ctx, source, int64(len(volume)), probeNormalBehavior(t, source, int64(len(volume))),
					newNormalFixtureCredentialProvider(t, fixture.Keys), sink, func(*NativeReadOutput) error { called = true; return nil })
			}()
			if called {
				t.Fatal("failed sink reached output callback")
			}
			if fault == "panic" {
				if panicValue == nil {
					t.Fatal("sink panic swallowed")
				}
			} else if panicValue != nil || result.Outcome() != OutcomeOperationFailed || result.PublicationAttempted() || result.CleanupIncomplete() {
				t.Fatalf("sink failure lost result truth: %v %v", result, panicValue)
			}
			assertNoNativeEncryptedResidue(t, directory)
		})
	}
}

func TestNativeEncryptedStreamOverflowClosesCredentialOwnerBeforeReturning(t *testing.T) {
	fixture := requireNormalFixture(t, loadNormalFixtureManifest(t).FixturesByID(), "normal-standard-password-only-small")
	provider := newNormalFixtureCredentialProvider(t, fixture.Keys)
	if provider.metadataMAC == [32]byte{} {
		t.Fatal("fixture must begin with a live owned key")
	}
	directory := t.TempDir()
	result := runNativeReadSession(context.Background(), bytes.NewReader(nil), math.MaxInt64, Structure{}, provider,
		&nativeReadSink{target: filepath.Join(directory, "output"), encryptedStream: true}, func(*NativeReadOutput) error { t.Fatal("overflow reached output"); return nil })
	if result.Outcome() != OutcomeOperationFailed || result.Stage() != StageOutputWrite {
		t.Fatal("overflow was admitted")
	}
	if provider.metadataMAC != [32]byte{} || provider.payloadXChaCha != [32]byte{} || provider.payloadMAC != [32]byte{} {
		t.Fatal("pre-reader refusal retained owned credential keys")
	}
	assertNoNativeEncryptedResidue(t, directory)
}

func TestNativeEncryptedStreamConstructorPreservesCleanupFailureWithoutPublication(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "clean cancellation", true: "foreign replacement"}[replace], func(t *testing.T) {
			directory := t.TempDir()
			ctx := &nativeConstructorCancellationContext{Context: context.Background(), t: t, directory: directory, replace: replace}
			sink := &nativeReadSink{target: filepath.Join(directory, "output"), encryptedStream: true, streamPhysicalLimit: 21}
			err := sink.ensureEncryptedOutput(ctx)
			sink.abortUncommitted()
			var result NativeReadResult
			sink.snapshot(&result)
			if err == nil || errors.Is(err, fileops.ErrEncryptedSpoolCleanupIncomplete) != replace || result.CleanupIncomplete() != replace {
				t.Fatalf("constructor cleanup truth lost: error=%v cleanup=%v", err, result.CleanupIncomplete())
			}
			if result.PublicationAttempted() || result.PublicationState() != 0 || sink.encryptedOutput != nil {
				t.Fatal("constructor failure gained publication or stream authority")
			}
			if replace {
				got, err := os.ReadFile(ctx.replacement)
				if err != nil || string(got) != "foreign replacement" {
					t.Fatalf("foreign replacement changed: %q %v", got, err)
				}
			} else {
				assertNoNativeEncryptedResidue(t, directory)
			}
		})
	}
}

type nativeConstructorCancellationContext struct {
	context.Context
	t                      *testing.T
	directory, replacement string
	replace, cancelled     bool
}

func (ctx *nativeConstructorCancellationContext) Err() error {
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

type nativeEncryptedFaultWriter struct{}

func (nativeEncryptedFaultWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func assertNoNativeEncryptedResidue(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("ciphertext cleanup left entries %v: %v", entries, err)
	}
}
