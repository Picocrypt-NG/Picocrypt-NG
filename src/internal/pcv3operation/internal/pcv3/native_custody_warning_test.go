//go:build linux

package pcv3

import (
	"Picocrypt-NG/internal/pcv3publication"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestNativeRetainedReadReportsPrivateRetirementWarningBeforeFollowUp(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	sink := &nativeReadSink{target: filepath.Join(parent, "output")}
	defer sink.abortUncommitted()
	if err := sink.writeVerifiedRecord(context.Background(), 0, []byte("authenticated plaintext")); err != nil {
		t.Fatal(err)
	}
	retained := sink.publishRetained(context.Background())
	if retained == nil {
		t.Fatal("durable published output lost original retained custody")
	}
	defer retained.Close()
	var snapshot NativeReadResult
	sink.snapshot(&snapshot)
	if snapshot.PublicationState() != pcv3publication.StatePublishedDurable {
		t.Fatalf("published truth changed: %v", snapshot.PublicationState())
	}
	if !snapshot.CleanupIncomplete() {
		t.Fatal("initial native result hid private-directory cleanup uncertainty until follow-up")
	}
	if !retained.Live() {
		t.Fatal("warning consumed the retry/output capability")
	}
}
