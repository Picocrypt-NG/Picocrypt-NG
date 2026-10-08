package pcv3

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestNativeReadOutputRequiresDurabilityForRetainedOwner(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "private-output.bin")
	payload := []byte("authenticated normal output")
	sink := &nativeReadSink{target: target}
	t.Cleanup(sink.abortUncommitted)
	if err := sink.writeVerifiedRecord(context.Background(), 0, payload); err != nil {
		sink.abortUncommitted()
		t.Fatalf("write verified record into production sink: %v", err)
	}
	state := &nativeReadOutputState{
		active:      true,
		disposition: NativePayloadPublish,
		sink:        sink,
	}
	output := &NativeReadOutput{state: state}

	retained := output.PublishRetained(context.Background())
	if (retained != nil) != (runtime.GOOS != "windows") || (retained != nil && !retained.Live()) {
		sink.abortUncommitted()
		t.Fatal("durable normal output did not transfer its exact retained owner")
	}
	if output.Publish(context.Background()) != nil || output.PublishRetained(context.Background()) != nil ||
		output.Archive() != nil {
		if retained != nil {
			_ = retained.RemoveExact()
		}
		t.Fatal("consumed native output granted a second publication action")
	}

	sink.abortUncommitted()
	nativeResult := &NativeReadResult{
		outcome: OutcomeSuccess,
		stage:   StageNone,
		code:    CodeSuccess,
	}
	sink.snapshot(nativeResult)
	if !nativeResult.PublicationAttempted() ||
		nativeResult.PublicationState() != nativePublicationState() ||
		nativeResult.CleanupIncomplete() {
		if retained != nil {
			_ = retained.RemoveExact()
		}
		t.Fatalf(
			"retained native result = attempted %v state %v cleanup %v; want durable/clean",
			nativeResult.PublicationAttempted(), nativeResult.PublicationState(),
			nativeResult.CleanupIncomplete(),
		)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != string(payload) {
		if retained != nil {
			_ = retained.RemoveExact()
		}
		t.Fatalf("retained native target = %q, %v; want exact payload", got, err)
	}
	if retained != nil {
		if err := retained.RemoveExact(); err != nil {
			t.Fatalf("remove retained native output: %v", err)
		}
		if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("retained native output still exists: %v", err)
		}
	}
}
