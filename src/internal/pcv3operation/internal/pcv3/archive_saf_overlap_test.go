package pcv3

import (
	"Picocrypt-NG/internal/fileops"
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestArchiveSAFRejectsOverlappingZIPPayloadsBeforeAttempt(t *testing.T) {
	archive := requireReadableSAFZIPPayloadFixture(t, "zip_payload_overlap.zip", map[string]string{
		"first.txt": "shared ZIP payload\n",
		"other.txt": "shared ZIP payload\n",
	})
	handoff, parent, target := newArchiveSAFHandoffFromZIP(t, archive, false)
	begin := handoff.BeginSAF()
	if begin.Kind() != NativeArchiveSAFBeginTerminal {
		if session := begin.Session(); session != nil {
			session.Abort()
		}
		t.Fatalf("overlapping ZIP begin kind = %v; want terminal rejection before provider attempt", begin.Kind())
	}
	result := begin.Result()
	if result == nil || result.State() != fileops.UnpackStateNotPublished ||
		result.AttemptedEver() || result.CleanupIncomplete() || handoff.Live() {
		t.Fatalf("overlap rejection lost no-output/cleanup truth: %#v", result)
	}
	assertNativeArchiveStage(t, parent, target, 0)
}

func TestArchiveSAFAllowsDisjointZIPPayloadsInReversedOrderAndEmptyFile(t *testing.T) {
	want := map[string]string{
		"first.txt": "first stored payload\n",
		"empty.txt": "",
		"last.txt":  "last stored payload\n",
	}
	archive := requireReadableSAFZIPPayloadFixture(t, "zip_disjoint_reordered.zip", want)
	handoff, parent, target := newArchiveSAFHandoffFromZIP(t, archive, false)
	session := armNativeArchiveSAFSession(t, handoff)
	t.Cleanup(func() { session.Abort() })
	if session.EntryCount() != len(want) {
		t.Fatalf("disjoint ZIP manifest has %d entries; want %d", session.EntryCount(), len(want))
	}
	for index := range session.EntryCount() {
		entry := session.Entry(index)
		if step := session.Attempt(index); step.Kind() != NativeArchiveSAFStepAttempted {
			t.Fatalf("disjoint ZIP entry %d was refused", index)
		}
		destination, err := os.CreateTemp(t.TempDir(), "disjoint-saf-*")
		if err != nil {
			t.Fatal(err)
		}
		path := destination.Name()
		if step := session.Write(index, destination); step.Kind() != NativeArchiveSAFStepReady {
			t.Fatalf("disjoint ZIP entry %d did not finish writing", index)
		}
		got, err := os.ReadFile(path)
		if expected, ok := want[entry.Name()]; !ok || err != nil || string(got) != expected {
			t.Fatalf("SAF entry %s = %q, err=%v", entry.Name(), got, err)
		}
	}
	result := session.Finish()
	if result == nil || result.State() != fileops.UnpackStatePublishedDurabilityUncertain ||
		!result.AttemptedEver() || result.CleanupIncomplete() {
		t.Fatalf("disjoint ZIP SAF completion = %#v", result)
	}
	assertNativeArchiveStage(t, parent, target, 0)
}

func requireReadableSAFZIPPayloadFixture(t *testing.T, name string, want map[string]string) []byte {
	t.Helper()
	archive, err := os.ReadFile(filepath.Join("..", "..", "..", "fileops", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	if len(reader.File) != len(want) {
		t.Fatalf("fixture has %d entries; want %d", len(reader.File), len(want))
	}
	for _, file := range reader.File {
		expected, ok := want[file.Name]
		if !ok {
			t.Fatalf("unexpected fixture entry %q", file.Name)
		}
		entry, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		got, readErr := io.ReadAll(entry)
		closeErr := entry.Close()
		if readErr != nil || closeErr != nil || string(got) != expected {
			t.Fatalf("fixture entry %s failed content/CRC validation: read=%v close=%v", file.Name, readErr, closeErr)
		}
	}
	return archive
}
