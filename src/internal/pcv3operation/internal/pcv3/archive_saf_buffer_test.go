package pcv3

import (
	"Picocrypt-NG/internal/fileops"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

// The probe observes the native owner's borrowed scratch after the synchronous
// call returns. It never mutates it; retaining this alias is test instrumentation,
// not a provider implementation or permission to retain ordinary io.Writer input.
type archiveSAFBufferProbe struct {
	file              *os.File
	borrowed          []byte
	failure           string
	closeSawPlaintext bool
}

func (probe *archiveSAFBufferProbe) Write(data []byte) (int, error) {
	probe.borrowed = data[:cap(data)]
	if probe.failure == "write" || probe.failure == "panic" {
		count, err := probe.file.Write(data[:1])
		if err != nil {
			return count, err
		}
		if probe.failure == "panic" {
			panic("public SAF writer test panic")
		}
		return count, errors.New("public SAF writer test failure")
	}
	return probe.file.Write(data)
}

func (probe *archiveSAFBufferProbe) Close() error {
	for _, value := range probe.borrowed {
		if value != 0 {
			probe.closeSawPlaintext = true
			break
		}
	}
	return probe.file.Close()
}

func TestArchiveSAFEntryScratchIsWipedAfterSuccessFailureAndPanic(t *testing.T) {
	for _, failure := range []string{"", "write", "panic", "crc"} {
		t.Run("failure="+failure, func(t *testing.T) {
			body := []byte("public first entry must not remain in reusable plaintext scratch")
			archive := buildArchiveSAFZIP(t, []archiveSAFZIPEntry{{name: "payload", data: body}})
			if failure == "crc" {
				corruptArchiveSAFStoredBody(t, archive)
			}
			handoff, parent, target := newArchiveSAFHandoffFromZIP(t, archive, true)
			session := armNativeArchiveSAFSession(t, handoff)
			defer session.Abort()
			destination := filepath.Join(t.TempDir(), "provider-output")
			file, err := os.Create(destination)
			if err != nil {
				t.Fatal(err)
			}
			probe := &archiveSAFBufferProbe{file: file, failure: failure}
			if session.Attempt(0).Kind() != NativeArchiveSAFStepAttempted {
				t.Fatal("attempt refused")
			}
			step := session.Write(0, probe)
			if probe.closeSawPlaintext {
				t.Fatal("provider Close observed native plaintext after the stream settled")
			}
			if len(probe.borrowed) == 0 {
				t.Fatal("real ZIP read did not reach provider boundary")
			}
			for _, value := range probe.borrowed {
				if value != 0 {
					t.Fatal("native plaintext scratch remains readable after entry settlement")
				}
			}
			if _, err := file.Stat(); err == nil {
				t.Fatal("provider descriptor was not closed")
			}
			if failure == "" {
				if step.Kind() != NativeArchiveSAFStepReady {
					t.Fatal("valid entry refused")
				}
				got, err := os.ReadFile(destination)
				if err != nil || !bytes.Equal(got, body) {
					t.Fatalf("provider bytes changed: %v", err)
				}
				if session.Finish().State() != fileops.UnpackStatePublishedDurabilityUncertain {
					t.Fatal("invalid success durability")
				}
			} else {
				if step.Kind() != NativeArchiveSAFStepPoisoned {
					t.Fatal("failed stream remained actionable")
				}
				result := session.Abort()
				if result.State() != fileops.UnpackStatePublicationIndeterminate || result.CleanupIncomplete() {
					t.Fatalf("failure cleanup/result = %#v", result)
				}
			}
			assertNativeArchiveStage(t, parent, target, 0)
		})
	}
}

func TestArchiveSAFEntryScratchReusePreservesDifferentSizedPayloads(t *testing.T) {
	archive := buildArchiveSAFZIP(t, []archiveSAFZIPEntry{
		{name: "first", data: bytes.Repeat([]byte("A"), 65536)},
		{name: "second", data: []byte("B")},
	})
	handoff, parent, target := newArchiveSAFHandoffFromZIP(t, archive, true)
	session := armNativeArchiveSAFSession(t, handoff)
	defer session.Abort()
	var first []byte
	for index := range 2 {
		file, err := os.CreateTemp(t.TempDir(), "provider-*")
		if err != nil {
			t.Fatal(err)
		}
		probe := &archiveSAFBufferProbe{file: file}
		if session.Attempt(index).Kind() != NativeArchiveSAFStepAttempted || session.Write(index, probe).Kind() != NativeArchiveSAFStepReady {
			t.Fatal("entry transfer failed")
		}
		if index == 0 {
			first = probe.borrowed
		} else if &first[0] != &probe.borrowed[0] {
			t.Fatal("per-entry scratch allocation returned")
		}
		if probe.closeSawPlaintext {
			t.Fatal("provider Close observed stale entry plaintext")
		}
		if !bytes.Equal(probe.borrowed, make([]byte, len(probe.borrowed))) {
			t.Fatal("stale entry plaintext remains")
		}
		got, err := os.ReadFile(file.Name())
		want := []byte("B")
		if index == 0 {
			want = bytes.Repeat([]byte("A"), 65536)
		}
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("scratch reuse changed provider bytes")
		}
	}
	if session.Finish().CleanupIncomplete() {
		t.Fatal("stage cleanup failed")
	}
	assertNativeArchiveStage(t, parent, target, 0)
}

type archiveSAFBorrowedWriter struct {
	*archiveSAFBufferProbe
	entered     chan struct{}
	closed      chan struct{}
	proceed     chan struct{}
	releaseOnce sync.Once
}

func (writer *archiveSAFBorrowedWriter) Write(data []byte) (int, error) {
	writer.borrowed = data[:cap(data)]
	close(writer.entered)
	<-writer.proceed
	return writer.file.Write(data)
}

func (writer *archiveSAFBorrowedWriter) Close() error {
	err := writer.file.Close()
	close(writer.closed)
	return err
}

func (writer *archiveSAFBorrowedWriter) release() {
	writer.releaseOnce.Do(func() { close(writer.proceed) })
}

func TestArchiveSAFEntryScratchCancellationWaitsForBorrowerBeforeWiping(t *testing.T) {
	body := []byte("public borrowed plaintext must survive until Write returns")
	archive := buildArchiveSAFZIP(t, []archiveSAFZIPEntry{{name: "payload", data: body}})
	handoff, parent, target := newArchiveSAFHandoffFromZIP(t, archive, true)
	session := armNativeArchiveSAFSession(t, handoff)
	file, err := os.CreateTemp(t.TempDir(), "provider-*")
	if err != nil {
		t.Fatal(err)
	}
	writer := &archiveSAFBorrowedWriter{archiveSAFBufferProbe: &archiveSAFBufferProbe{file: file}, entered: make(chan struct{}), closed: make(chan struct{}), proceed: make(chan struct{})}
	defer func() { writer.release(); session.Abort() }()
	if session.Attempt(0).Kind() != NativeArchiveSAFStepAttempted {
		t.Fatal("attempt refused")
	}
	done := make(chan *NativeArchiveSAFStep, 1)
	go func() { done <- session.Write(0, writer) }()
	select {
	case <-writer.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("writer not entered")
	}
	// A copied capability cannot borrow or clear the active owner's buffer.
	alias := *session
	rejected := &archiveSAFDiscardWriter{}
	if alias.Write(0, rejected).Kind() != NativeArchiveSAFStepPoisoned || rejected.bytes != 0 {
		t.Fatal("concurrent writer acquired scratch")
	}
	if session.Cancel().Kind() != NativeArchiveSAFStepPoisoned {
		t.Fatal("cancel not acknowledged")
	}
	select {
	case <-writer.closed:
	default:
		t.Fatal("cancel did not close the active provider")
	}
	if !bytes.Equal(writer.borrowed[:len(body)], body) {
		t.Fatal("scratch was changed while a provider still borrowed it")
	}
	writer.release()
	select {
	case step := <-done:
		if step.Kind() != NativeArchiveSAFStepPoisoned {
			t.Fatal("cancelled write became ready")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("writer did not settle")
	}
	for _, value := range writer.borrowed {
		if value != 0 {
			t.Fatal("cancelled plaintext scratch remains readable")
		}
	}
	result := session.Abort()
	if result.State() != fileops.UnpackStatePublicationIndeterminate || result.CleanupIncomplete() {
		t.Fatalf("cancel result = %#v", result)
	}
	assertNativeArchiveStage(t, parent, target, 0)
}

type archiveSAFDiscardWriter struct{ bytes int64 }

func (writer *archiveSAFDiscardWriter) Write(data []byte) (int, error) {
	writer.bytes += int64(len(data))
	return len(data), nil
}
func (*archiveSAFDiscardWriter) Close() error { return nil }

// Real native Begin/manifest/CRC/entry/terminal paths; no KDF and no provider I/O.
// Allocation measurements include session preparation and private-stage cleanup.
func BenchmarkArchiveSAFSessionEntryAllocations(b *testing.B) {
	for _, count := range []int{1, 1024} {
		b.Run(strconv.Itoa(count), func(b *testing.B) {
			entries := make([]archiveSAFZIPEntry, count)
			for index := range entries {
				entries[index] = archiveSAFZIPEntry{name: fmt.Sprintf("f%06d", index), data: []byte("public provider body\n")}
			}
			archive := buildArchiveSAFZIP(b, entries)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				handoff, _, _ := newArchiveSAFHandoffFromZIP(b, archive, false)
				session := armNativeArchiveSAFSession(b, handoff)
				writer := &archiveSAFDiscardWriter{}
				for index := range count {
					if session.Attempt(index).Kind() != NativeArchiveSAFStepAttempted || session.Write(index, writer).Kind() != NativeArchiveSAFStepReady {
						b.Fatal("entry transfer failed")
					}
				}
				if writer.bytes != int64(count)*int64(len(entries[0].data)) {
					b.Fatal("entry bytes missing")
				}
				if result := session.Finish(); result.State() != fileops.UnpackStatePublishedDurabilityUncertain || result.CleanupIncomplete() {
					b.Fatal("session failed")
				}
			}
		})
	}
}
