//go:build linux || darwin

// These native fixtures require durable plaintext custody from PublishRetained.
package pcv3publication

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Yield while the select evaluates Done so an empty copy can also become ready.
// Cancellation state and the returned channel still come from the real context.
type retainedStreamYieldContext struct{ context.Context }

func (ctx retainedStreamYieldContext) Done() <-chan struct{} {
	runtime.Gosched()
	return ctx.Context.Done()
}

func TestRetainedEmptyStreamCancellationClosesDestinationAndConsumesSource(t *testing.T) {
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)

	// The yield makes both select arms ready on the defective path. Selection
	// remains random, so bound the attempts and stop at the first violation.
	for attempt := range 16 {
		path := filepath.Join(t.TempDir(), "retained")
		retained := publishRetainedStreamFile(t, path, nil)
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		result := retained.StreamTo(retainedStreamYieldContext{Context: ctx}, writer)
		if result.Copied() || result.CleanupIncomplete() {
			t.Errorf("attempt %d: pre-cancelled empty stream = copied=%v cleanup=%v; want refused/clean", attempt, result.Copied(), result.CleanupIncomplete())
		}
		requireRetainedStreamConsumed(t, retained, path)
		if _, err := writer.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Errorf("attempt %d: cancelled empty stream left destination open: %v", attempt, err)
		}
		_ = writer.Close()
		var probe [1]byte
		count, readErr := reader.Read(probe[:])
		_ = reader.Close()
		if count != 0 || readErr != io.EOF {
			t.Errorf("attempt %d: cancelled empty stream = count=%d err=%v; want no bytes and EOF", attempt, count, readErr)
		}
		if t.Failed() {
			return
		}
	}
}

func TestRetainedStreamSuccessConsumesSourceAndLeavesDestinationOpen(t *testing.T) {
	for _, test := range []struct {
		name    string
		payload []byte
	}{
		{name: "empty"},
		{name: "nonempty", payload: []byte("authenticated retained plaintext")},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "retained")
			retained := publishRetainedStreamFile(t, path, test.payload)
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			defer writer.Close()
			result := retained.StreamTo(context.Background(), writer)
			if !result.Copied() || result.CleanupIncomplete() {
				t.Fatalf("stream = copied=%v cleanup=%v; want copied/clean", result.Copied(), result.CleanupIncomplete())
			}
			requireRetainedStreamConsumed(t, retained, path)
			if _, err := writer.Stat(); err != nil {
				t.Fatalf("successful stream closed caller-owned destination: %v", err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			streamed, err := io.ReadAll(reader)
			if err != nil || !bytes.Equal(streamed, test.payload) {
				t.Fatalf("streamed = %q err=%v; want %q", streamed, err, test.payload)
			}
		})
	}
}

func TestRetainedEmptyStreamCancellationPreservesCleanupWarning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "retained")
	retained := publishRetainedStreamFile(t, path, nil)
	retained.syncDirectory = func(*os.File) error { return errors.ErrUnsupported }
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := retained.StreamTo(ctx, writer)
	if result.Copied() || !result.CleanupIncomplete() {
		t.Fatalf("cancelled stream with failed cleanup barrier = copied=%v cleanup=%v; want refused/uncertain", result.Copied(), result.CleanupIncomplete())
	}
	requireRetainedStreamConsumed(t, retained, path)
	if _, err := writer.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("cancelled stream with cleanup uncertainty left destination open: %v", err)
	}
}

func publishRetainedStreamFile(t *testing.T, path string, payload []byte) *RetainedFile {
	t.Helper()
	stage, err := Create(path, nil, PolicyNoReplace)
	if err != nil {
		t.Fatalf("create native retained stage: %v", err)
	}
	t.Cleanup(func() { _ = stage.Cleanup() })
	if _, err := stage.File().Write(payload); err != nil {
		t.Fatalf("write native retained stage: %v", err)
	}
	publication, retained := stage.PublishRetained(context.Background())
	if publication == nil || publication.State() != StatePublishedDurable || retained == nil {
		t.Fatalf("native retained publication = %v/%v; want durable capability", publication, retained)
	}
	t.Cleanup(func() { _ = retained.Close() })
	source, parent, root := retained.file, retained.parent, retained.root
	t.Cleanup(func() {
		if _, err := source.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Errorf("stream left source descriptor open: %v", err)
		}
		if _, err := parent.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Errorf("stream left parent descriptor open: %v", err)
		}
		if _, err := root.Stat("."); !errors.Is(err, os.ErrClosed) {
			t.Errorf("stream left root descriptor open: %v", err)
		}
	})
	return retained
}

func requireRetainedStreamConsumed(t *testing.T, retained *RetainedFile, path string) {
	t.Helper()
	if retained.Live() {
		t.Error("stream left retained authority live")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stream left exact retained source: %v", err)
	}
}
