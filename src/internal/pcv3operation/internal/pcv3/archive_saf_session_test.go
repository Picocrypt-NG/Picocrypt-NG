package pcv3

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3publication"
	"Picocrypt-NG/internal/util"
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestArchiveSAFSessionStreamsExactFilesAndFinishesDurabilityUncertain(t *testing.T) {
	archive := buildArchiveSAFZIP(t, []archiveSAFZIPEntry{
		{name: "empty/", directory: true},
		{name: "zero.txt"},
		{name: "payload.txt", data: []byte("exact provider payload")},
	})
	handoff, stageParent, rawTarget := newArchiveSAFHandoffFromZIP(t, archive, true)
	session := armNativeArchiveSAFSession(t, handoff)
	wantBodies := map[int][]byte{
		1: {},
		2: []byte("exact provider payload"),
	}

	for index := range session.EntryCount() {
		attempt := session.Attempt(index)
		if attempt == nil || attempt.Kind() != NativeArchiveSAFStepAttempted ||
			attempt.NextIndex() != index || !session.AttemptedEver() {
			t.Fatalf("attempt %d = %#v attempted-ever=%v", index, attempt, session.AttemptedEver())
		}
		entry := session.Entry(index)
		if entry.IsDirectory() {
			step := session.AckDirectory(index)
			if step == nil || step.Kind() != NativeArchiveSAFStepReady ||
				step.NextIndex() != index+1 {
				t.Fatalf("directory acknowledgement %d = %#v", index, step)
			}
			continue
		}

		destination, err := os.CreateTemp(t.TempDir(), "saf-destination-*")
		if err != nil {
			t.Fatalf("create provider destination %d: %v", index, err)
		}
		destinationPath := destination.Name()
		step := session.Write(index, destination)
		if step == nil || step.Kind() != NativeArchiveSAFStepReady ||
			step.NextIndex() != index+1 {
			t.Fatalf("file write %d = %#v", index, step)
		}
		if _, err := destination.Stat(); err == nil {
			t.Fatalf("destination %d remained open after transfer", index)
		}
		got, err := os.ReadFile(destinationPath)
		if err != nil || !bytes.Equal(got, wantBodies[index]) {
			t.Fatalf("destination %d = %q, error %v; want %q", index, got, err, wantBodies[index])
		}
	}

	finished := session.Finish()
	if finished == nil || finished.State() != fileops.UnpackStatePublishedDurabilityUncertain ||
		!finished.AttemptedEver() || finished.CleanupIncomplete() {
		t.Fatalf("finished SAF result = %#v; want attempted durability-uncertain with exact cleanup", finished)
	}
	if repeated := session.Finish(); repeated != finished {
		t.Fatal("repeated Finish did not return the canonical terminal result")
	}
	if aborted := session.Abort(); aborted != finished {
		t.Fatal("post-terminal Abort replaced the canonical terminal result")
	}
	assertNativeArchiveStage(t, stageParent, rawTarget, 0)
}

func TestArchiveSAFSessionStreamsToANonSeekablePipe(t *testing.T) {
	body := bytes.Repeat([]byte("pipe-data-"), 16*1024)
	archive := buildArchiveSAFZIP(t, []archiveSAFZIPEntry{{name: "pipe.bin", data: body}})
	handoff, _, _ := newArchiveSAFHandoffFromZIP(t, archive, false)
	session := armNativeArchiveSAFSession(t, handoff)
	if step := session.Attempt(0); step.Kind() != NativeArchiveSAFStepAttempted {
		t.Fatalf("pipe attempt = %#v", step)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create provider pipe: %v", err)
	}
	readResult := make(chan struct {
		data []byte
		err  error
	}, 1)
	go func() {
		data, readErr := io.ReadAll(reader)
		_ = reader.Close()
		readResult <- struct {
			data []byte
			err  error
		}{data: data, err: readErr}
	}()
	step := session.Write(0, writer)
	if step.Kind() != NativeArchiveSAFStepReady {
		t.Fatalf("pipe write = %#v", step)
	}
	read := <-readResult
	if read.err != nil || !bytes.Equal(read.data, body) {
		t.Fatalf("pipe body length=%d error=%v; want exact %d bytes", len(read.data), read.err, len(body))
	}
	_ = session.Finish()
}

func TestArchiveSAFSessionFrozenAuthenticatedArchiveStreamsToRealDescriptors(t *testing.T) {
	handoff, stageParent, rawTarget := newNativeArchiveHandoffFixture(t)
	session := armNativeArchiveSAFSession(t, handoff)
	wantBodies := map[int][]byte{
		0: []byte("PCV3 authenticated archive fixture\n"),
		2: []byte("Extraction is admitted only after whole-volume authentication.\n"),
	}

	for index := range session.EntryCount() {
		if step := session.Attempt(index); step == nil ||
			step.Kind() != NativeArchiveSAFStepAttempted || step.NextIndex() != index {
			t.Fatalf("authenticated attempt %d = %#v", index, step)
		}
		entry := session.Entry(index)
		if entry == nil {
			t.Fatalf("authenticated entry %d is nil", index)
		}
		if entry.IsDirectory() {
			if step := session.AckDirectory(index); step == nil ||
				step.Kind() != NativeArchiveSAFStepReady || step.NextIndex() != index+1 {
				t.Fatalf("authenticated directory %d = %#v", index, step)
			}
			continue
		}

		destination, err := os.CreateTemp(t.TempDir(), "authenticated-saf-*")
		if err != nil {
			t.Fatalf("create authenticated provider destination %d: %v", index, err)
		}
		path := destination.Name()
		if step := session.Write(index, destination); step == nil ||
			step.Kind() != NativeArchiveSAFStepReady || step.NextIndex() != index+1 {
			t.Fatalf("authenticated write %d = %#v", index, step)
		}
		body, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(body, wantBodies[index]) {
			t.Fatalf("authenticated body %d = %q, error %v; want %q", index, body, err, wantBodies[index])
		}
	}

	result := session.Finish()
	if result == nil || result.State() != fileops.UnpackStatePublishedDurabilityUncertain ||
		!result.AttemptedEver() || result.CleanupIncomplete() {
		t.Fatalf("authenticated SAF finish = %#v; want attempted durability-uncertain", result)
	}
	assertNativeArchiveStage(t, stageParent, rawTarget, 0)
}

func TestArchiveSAFSessionRejectsCRCAndRatioFailuresAfterAttempt(t *testing.T) {
	t.Run("CRC and EOF", func(t *testing.T) {
		archive := buildArchiveSAFZIP(t, []archiveSAFZIPEntry{
			{name: "crc.bin", data: []byte("authenticated archive body")},
		})
		corruptArchiveSAFStoredBody(t, archive)
		assertArchiveSAFStreamFailureIsAttemptedIndeterminate(t, archive)
	})

	t.Run("decompression ratio", func(t *testing.T) {
		// Share the frozen valid ZIP so encoder changes cannot alter this case.
		archive, err := os.ReadFile(filepath.Join("..", "..", "..", "fileops", "testdata", "unpack_high_ratio_above_floor.zip"))
		if err != nil {
			t.Fatal(err)
		}
		reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
		if err != nil {
			t.Fatalf("open ratio fixture: %v", err)
		}
		if len(reader.File) != 1 {
			t.Fatal("ratio fixture must contain one file")
		}
		file := reader.File[0]
		if file.Method != zip.Deflate || file.UncompressedSize64 != 2*util.MiB ||
			file.CompressedSize64 == 0 || file.UncompressedSize64 <= 1000*file.CompressedSize64 {
			t.Fatalf("invalid ratio fixture: method=%d uncompressed=%d compressed=%d", file.Method, file.UncompressedSize64, file.CompressedSize64)
		}
		entry, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		defer entry.Close()
		content, err := io.ReadAll(entry)
		if err != nil || !bytes.Equal(content, bytes.Repeat([]byte("A"), 2*util.MiB)) {
			t.Fatalf("ratio fixture contents or CRC invalid: %v", err)
		}
		assertArchiveSAFStreamFailureIsAttemptedIndeterminate(t, archive)
	})
}

func TestArchiveSAFSessionRejectsDeclaredShortAndLongSourcesAfterAttempt(t *testing.T) {
	body := []byte("exact archive body")
	tests := []struct {
		name         string
		declaredSize uint32
	}{
		{name: "declared body is shorter than source", declaredSize: uint32(len(body) - 1)},
		{name: "declared body is longer than source", declaredSize: uint32(len(body) + 1)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			archive := buildArchiveSAFZIP(t, []archiveSAFZIPEntry{
				{name: "size.bin", data: body},
			})
			setArchiveSAFCentralUncompressedSize(t, archive, test.declaredSize)
			assertArchiveSAFStreamFailureIsAttemptedIndeterminate(t, archive)
		})
	}
}

func TestArchiveSAFSessionTreatsDestinationCloseFailureAndPanicsAsAttemptedIndeterminate(t *testing.T) {
	tests := []struct {
		name        string
		destination func(*testing.T) io.WriteCloser
	}{
		{
			name: "close ambiguity",
			destination: func(t *testing.T) io.WriteCloser {
				file, err := os.CreateTemp(t.TempDir(), "close-ambiguity-*")
				if err != nil {
					t.Fatalf("create close-ambiguity destination: %v", err)
				}
				return &archiveSAFCloseErrorWriter{File: file}
			},
		},
		{
			name: "write panic",
			destination: func(t *testing.T) io.WriteCloser {
				file, err := os.CreateTemp(t.TempDir(), "panic-writer-*")
				if err != nil {
					t.Fatalf("create panic destination: %v", err)
				}
				return &archiveSAFPanicWriter{file: file}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			archive := buildArchiveSAFZIP(t, []archiveSAFZIPEntry{
				{name: "payload", data: []byte("provider payload")},
			})
			handoff, _, _ := newArchiveSAFHandoffFromZIP(t, archive, false)
			session := armNativeArchiveSAFSession(t, handoff)
			if step := session.Attempt(0); step.Kind() != NativeArchiveSAFStepAttempted {
				t.Fatalf("attempt = %#v", step)
			}
			step := session.Write(0, test.destination(t))
			if step == nil || step.Kind() != NativeArchiveSAFStepPoisoned {
				t.Fatalf("ambiguous write = %#v; want poisoned", step)
			}
			result := session.Abort()
			if result.State() != fileops.UnpackStatePublicationIndeterminate ||
				!result.AttemptedEver() {
				t.Fatalf("ambiguous terminal = %#v", result)
			}
		})
	}
}

func TestArchiveSAFSessionNilDestinationAfterAttemptPoisonsWithoutRetry(t *testing.T) {
	archive := buildArchiveSAFZIP(t, []archiveSAFZIPEntry{
		{name: "payload", data: []byte("provider payload")},
	})
	handoff, _, _ := newArchiveSAFHandoffFromZIP(t, archive, false)
	session := armNativeArchiveSAFSession(t, handoff)
	if step := session.Attempt(0); step == nil || step.Kind() != NativeArchiveSAFStepAttempted {
		t.Fatalf("attempt = %#v", step)
	}
	if step := session.Write(0, nil); step == nil ||
		step.Kind() != NativeArchiveSAFStepPoisoned || step.NextIndex() != 0 {
		t.Fatalf("nil destination = %#v; want irreversible poison", step)
	}

	retry, err := os.CreateTemp(t.TempDir(), "forbidden-retry-*")
	if err != nil {
		t.Fatalf("create retry destination: %v", err)
	}
	if step := session.Write(0, retry); step == nil ||
		step.Kind() != NativeArchiveSAFStepPoisoned || step.NextIndex() != 0 {
		t.Fatalf("retry after nil destination = %#v; want poison", step)
	}
	if _, err := retry.Stat(); err == nil {
		t.Fatal("forbidden retry destination remained open")
	}
	result := session.Finish()
	if result == nil || result.State() != fileops.UnpackStatePublicationIndeterminate ||
		!result.AttemptedEver() {
		t.Fatalf("nil-destination terminal = %#v; want attempted indeterminate", result)
	}
}

func TestArchiveSAFSessionCancelClosesOnlyActiveWriterWithoutHoldingStateLock(t *testing.T) {
	body := bytes.Repeat([]byte("blocking-provider-body"), 16*1024)
	archive := buildArchiveSAFZIP(t, []archiveSAFZIPEntry{{name: "blocking.bin", data: body}})
	handoff, _, _ := newArchiveSAFHandoffFromZIP(t, archive, false)
	session := armNativeArchiveSAFSession(t, handoff)
	if step := session.Attempt(0); step.Kind() != NativeArchiveSAFStepAttempted {
		t.Fatalf("attempt = %#v", step)
	}
	file, err := os.CreateTemp(t.TempDir(), "blocking-writer-*")
	if err != nil {
		t.Fatalf("create blocking destination: %v", err)
	}
	destination := newArchiveSAFBlockingWriter(file)
	writeDone := make(chan *NativeArchiveSAFStep, 1)
	go func() { writeDone <- session.Write(0, destination) }()
	select {
	case <-destination.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("provider writer never entered blocking I/O")
	}

	abortDone := make(chan *NativeArchiveSAFResult, 1)
	go func() { abortDone <- session.Abort() }()
	select {
	case result := <-abortDone:
		t.Fatalf("Abort returned before active writer settled: %#v", result)
	case <-time.After(50 * time.Millisecond):
	}

	entryCountDone := make(chan int, 1)
	go func() { entryCountDone <- session.EntryCount() }()
	select {
	case count := <-entryCountDone:
		if count != 1 {
			t.Fatalf("entry count during I/O = %d; want 1", count)
		}
	case <-time.After(time.Second):
		destination.forceClose()
		t.Fatal("session mutex was held across blocking writer I/O")
	}

	cancelDone := make(chan *NativeArchiveSAFStep, 1)
	go func() { cancelDone <- session.Cancel() }()
	select {
	case step := <-cancelDone:
		if step == nil || step.Kind() != NativeArchiveSAFStepPoisoned {
			t.Fatalf("Cancel = %#v; want poisoned", step)
		}
	case <-time.After(time.Second):
		destination.forceClose()
		t.Fatal("Cancel did not close the active writer without waiting on I/O")
	}
	// A blocked Abort may win the state lock after the first Cancel settles the
	// writer and move the session to Finishing/Terminal, in which case a repeat
	// Cancel is correctly Rejected (archive_saf.go). Both acknowledgements are
	// fail-closed; neither grants provider-effect authority.
	if step := session.Cancel(); step == nil ||
		(step.Kind() != NativeArchiveSAFStepPoisoned && step.Kind() != NativeArchiveSAFStepRejected) {
		t.Fatalf("idempotent Cancel = %#v", step)
	}
	select {
	case step := <-writeDone:
		if step == nil || step.Kind() != NativeArchiveSAFStepPoisoned {
			t.Fatalf("cancelled write = %#v", step)
		}
	case <-time.After(2 * time.Second):
		destination.forceClose()
		t.Fatal("cancelled writer did not settle")
	}
	select {
	case result := <-abortDone:
		if result == nil || result.State() != fileops.UnpackStatePublicationIndeterminate ||
			!result.AttemptedEver() {
			t.Fatalf("cancelled abort = %#v", result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Abort did not resume after active writer settled")
	}
	if _, err := file.Stat(); err == nil {
		t.Fatal("Cancel left the exact active destination descriptor open")
	}
}

func TestArchiveSAFSessionCancelSettlesBlockedRealPipeWrite(t *testing.T) {
	body := bytes.Repeat([]byte("real-pipe-cancellation"), 128*1024)
	archive := buildArchiveSAFZIP(t, []archiveSAFZIPEntry{{name: "blocked.bin", data: body}})
	handoff, _, _ := newArchiveSAFHandoffFromZIP(t, archive, false)
	session := armNativeArchiveSAFSession(t, handoff)
	if step := session.Attempt(0); step == nil || step.Kind() != NativeArchiveSAFStepAttempted {
		t.Fatalf("real pipe attempt = %#v", step)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create blocked provider pipe: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	writeDone := make(chan *NativeArchiveSAFStep, 1)
	go func() { writeDone <- session.Write(0, writer) }()

	deadline := time.Now().Add(2 * time.Second)
	for {
		session.state.mu.Lock()
		active := session.state.activeWriter != nil && session.state.status == nativeArchiveSAFWriting
		session.state.mu.Unlock()
		if active {
			break
		}
		if time.Now().After(deadline) {
			_ = writer.Close()
			t.Fatal("real pipe writer never became active")
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case step := <-writeDone:
		t.Fatalf("undrained real pipe write completed before cancellation: %#v", step)
	case <-time.After(50 * time.Millisecond):
	}

	if step := session.Cancel(); step == nil || step.Kind() != NativeArchiveSAFStepPoisoned {
		t.Fatalf("real pipe Cancel = %#v; want poisoned", step)
	}
	select {
	case step := <-writeDone:
		if step == nil || step.Kind() != NativeArchiveSAFStepPoisoned {
			t.Fatalf("cancelled real pipe write = %#v", step)
		}
	case <-time.After(2 * time.Second):
		_ = reader.Close()
		t.Fatal("closing the active real pipe writer did not settle Write")
	}
	result := session.Abort()
	if result == nil || result.State() != fileops.UnpackStatePublicationIndeterminate ||
		!result.AttemptedEver() {
		t.Fatalf("cancelled real pipe terminal = %#v", result)
	}
}

func TestArchiveSAFSessionAliasesAndOutOfOrderActionsCannotAdvanceAuthority(t *testing.T) {
	archive := buildArchiveSAFZIP(t, []archiveSAFZIPEntry{
		{name: "dir/", directory: true},
		{name: "dir/file", data: []byte("body")},
	})
	firstHandoff, _, _ := newArchiveSAFHandoffFromZIP(t, archive, false)
	secondHandoff, _, _ := newArchiveSAFHandoffFromZIP(t, archive, false)
	firstBegin := firstHandoff.BeginSAF()
	secondBegin := secondHandoff.BeginSAF()
	first := firstBegin.Session()
	second := secondBegin.Session()
	if step := first.ConfirmReceiptPersisted(secondBegin.ReceiptArm()); step.Kind() != NativeArchiveSAFStepRejected {
		t.Fatalf("cross-session arm = %#v", step)
	}
	if step := first.ConfirmReceiptPersisted(firstBegin.ReceiptArm()); step.Kind() != NativeArchiveSAFStepReady {
		t.Fatalf("exact arm = %#v", step)
	}
	copyOfFirst := *first
	if step := copyOfFirst.Attempt(0); step.Kind() != NativeArchiveSAFStepAttempted {
		t.Fatalf("copied session attempt = %#v", step)
	}
	if step := first.Attempt(0); step.Kind() != NativeArchiveSAFStepPoisoned {
		t.Fatalf("duplicate attempt = %#v; want poison", step)
	}
	if result := first.Abort(); result.State() != fileops.UnpackStatePublicationIndeterminate ||
		!result.AttemptedEver() {
		t.Fatalf("aliased abort = %#v", result)
	}

	if step := second.ConfirmReceiptPersisted(secondBegin.ReceiptArm()); step.Kind() != NativeArchiveSAFStepReady {
		t.Fatalf("second exact arm = %#v", step)
	}
	if step := second.Attempt(1); step.Kind() != NativeArchiveSAFStepPoisoned ||
		second.AttemptedEver() {
		t.Fatalf("out-of-order attempt = %#v attempted-ever=%v; want no provider authority", step, second.AttemptedEver())
	}
	if result := second.Abort(); result.State() != fileops.UnpackStateNotPublished ||
		result.AttemptedEver() {
		t.Fatalf("out-of-order abort = %#v", result)
	}
}

func TestArchiveSAFSessionCleanupUncertaintyIsIndeterminateWithoutProviderAttempt(t *testing.T) {
	for _, fault := range []string{"stage pathname replacement", "journal hardlink"} {
		t.Run(fault, func(t *testing.T) {
			if fault == "journal hardlink" && runtime.GOOS != "linux" && runtime.GOOS != "android" {
				t.Skip("extra-link cleanup identity requires supported journal metadata; pathname replacement is tested on every host")
			}
			archive := buildArchiveSAFZIP(t, []archiveSAFZIPEntry{{name: "file", data: []byte("body")}})
			handoff, parent, target := newArchiveSAFHandoffFromZIP(t, archive, true)
			copiedHandoff := *handoff
			begin := handoff.BeginSAF()
			if begin.Kind() != NativeArchiveSAFBeginSession || begin.Session() == nil {
				t.Fatalf("cleanup fixture did not reach a real SAF session: %#v", begin)
			}
			session := begin.Session()
			t.Cleanup(func() { _ = session.Abort() })
			stagePath := findArchiveSAFStagePath(t, parent)
			foreign := []byte("foreign stage pathname must survive")
			var retainedPath string
			if fault == "journal hardlink" {
				retainedPath = filepath.Join(parent, "unexpected-plaintext-link")
				if err := os.Link(stagePath, retainedPath); err != nil {
					t.Fatalf("create unexpected stage hardlink: %v", err)
				}
			} else {
				retainedPath = filepath.Join(parent, "moved-private-stage")
				if err := os.Rename(stagePath, retainedPath); err != nil {
					t.Fatalf("move exact stage before pathname replacement: %v", err)
				}
				if err := os.WriteFile(stagePath, foreign, 0o600); err != nil {
					t.Fatalf("replace stage pathname with a foreign file: %v", err)
				}
			}
			result := session.Abort()
			if result == nil || result.State() != fileops.UnpackStatePublicationIndeterminate ||
				result.AttemptedEver() || !result.CleanupIncomplete() {
				t.Fatalf("cleanup-uncertain abort = %#v; want unattempted indeterminate", result)
			}
			if handoff.Live() || copiedHandoff.Live() || copiedHandoff.BeginSAF().Kind() != NativeArchiveSAFBeginExpired ||
				session.Abort() != result || session.Finish() != result {
				t.Fatal("uncertain cleanup retained or replaced one-shot authority")
			}
			if step := session.Attempt(0); step.Kind() != NativeArchiveSAFStepRejected || session.AttemptedEver() {
				t.Fatal("terminal cleanup uncertainty granted provider-effect authority")
			}
			wantStage := archive
			if fault == "stage pathname replacement" {
				wantStage = foreign
			}
			for path, want := range map[string][]byte{stagePath: wantStage, retainedPath: archive} {
				if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, want) {
					t.Fatalf("uncertain cleanup changed preserved file %q: %v", filepath.Base(path), err)
				}
			}
			if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unattempted cleanup published archive plaintext: %v", err)
			}
		})
	}
}

func TestArchiveSAFSessionAbortSettlesProviderEvidenceDeliveredDuringCleanup(t *testing.T) {
	archive := buildArchiveSAFZIP(t, []archiveSAFZIPEntry{
		{name: "payload", data: []byte("provider payload")},
	})
	handoff, _, _ := newArchiveSAFHandoffFromZIP(t, archive, false)
	begin := handoff.BeginSAF()
	if begin == nil || begin.Kind() != NativeArchiveSAFBeginSession {
		t.Fatalf("BeginSAF = %#v; want session", begin)
	}
	session := begin.Session()
	alias := *session

	cleanupStarted := make(chan struct{})
	releaseCleanup := make(chan struct{})
	var releaseCleanupOnce sync.Once
	releaseCleanupNow := func() { releaseCleanupOnce.Do(func() { close(releaseCleanup) }) }
	t.Cleanup(releaseCleanupNow)
	session.state.mu.Lock()
	realCleanup := session.state.cleanupStage
	session.state.cleanupStage = func(stage *pcv3publication.Stage) bool {
		close(cleanupStarted)
		<-releaseCleanup
		return realCleanup(stage)
	}
	session.state.mu.Unlock()

	abortDone := make(chan *NativeArchiveSAFResult, 1)
	go func() { abortDone <- session.Abort() }()
	select {
	case <-cleanupStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("Abort did not enter the controlled real Stage cleanup")
	}

	file, err := os.CreateTemp(t.TempDir(), "late-provider-object-*")
	if err != nil {
		t.Fatalf("create late provider object: %v", err)
	}
	destination := newArchiveSAFSettlementWriter(file)
	t.Cleanup(destination.release)
	writeDone := make(chan *NativeArchiveSAFStep, 1)
	go func() { writeDone <- alias.Write(0, destination) }()
	select {
	case <-destination.closeStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("late provider object was not accepted for settlement")
	}

	releaseCleanupNow()
	select {
	case result := <-abortDone:
		t.Fatalf("Abort returned before late provider closer settled: %#v", result)
	case <-time.After(50 * time.Millisecond):
	}
	destination.release()
	select {
	case step := <-writeDone:
		if step == nil || step.Kind() != NativeArchiveSAFStepPoisoned {
			t.Fatalf("late provider settlement = %#v; want poisoned", step)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("late provider closer did not settle")
	}
	select {
	case result := <-abortDone:
		if result == nil || result.State() != fileops.UnpackStatePublicationIndeterminate ||
			!result.AttemptedEver() {
			t.Fatalf("late-provider abort = %#v; want attempted indeterminate", result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Abort did not resume after late provider settlement")
	}
	if _, err := file.Stat(); err == nil {
		t.Fatal("late provider descriptor remained open after settlement")
	}
}

func TestArchiveSAFSessionAbortWaitsForInvalidProviderCloserStartedBeforeFinishing(t *testing.T) {
	archive := buildArchiveSAFZIP(t, []archiveSAFZIPEntry{
		{name: "payload", data: []byte("provider payload")},
	})
	handoff, _, _ := newArchiveSAFHandoffFromZIP(t, archive, false)
	session := armNativeArchiveSAFSession(t, handoff)
	file, err := os.CreateTemp(t.TempDir(), "invalid-provider-object-*")
	if err != nil {
		t.Fatalf("create invalid provider object: %v", err)
	}
	destination := newArchiveSAFSettlementWriter(file)
	t.Cleanup(destination.release)
	writeDone := make(chan *NativeArchiveSAFStep, 1)
	go func() { writeDone <- session.Write(0, destination) }()
	select {
	case <-destination.closeStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("invalid provider closer did not start")
	}

	abortDone := make(chan *NativeArchiveSAFResult, 1)
	go func() { abortDone <- session.Abort() }()
	select {
	case result := <-abortDone:
		t.Fatalf("Abort returned before pre-finishing provider closer settled: %#v", result)
	case <-time.After(50 * time.Millisecond):
	}
	destination.release()
	select {
	case step := <-writeDone:
		if step == nil || step.Kind() != NativeArchiveSAFStepPoisoned {
			t.Fatalf("invalid provider settlement = %#v; want poisoned", step)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("invalid provider closer did not settle")
	}
	select {
	case result := <-abortDone:
		if result == nil || result.State() != fileops.UnpackStatePublicationIndeterminate ||
			!result.AttemptedEver() {
			t.Fatalf("invalid-provider abort = %#v; want attempted indeterminate", result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Abort did not resume after invalid provider settlement")
	}
	if _, err := file.Stat(); err == nil {
		t.Fatal("invalid provider descriptor remained open after settlement")
	}
}

func armNativeArchiveSAFSession(
	t testing.TB,
	handoff *NativeArchiveHandoff,
) *NativeArchiveSAFSession {
	t.Helper()
	begin := handoff.BeginSAF()
	if begin == nil || begin.Kind() != NativeArchiveSAFBeginSession || begin.Session() == nil {
		t.Fatalf("BeginSAF = %#v; want session", begin)
	}
	step := begin.Session().ConfirmReceiptPersisted(begin.ReceiptArm())
	if step == nil || step.Kind() != NativeArchiveSAFStepReady || step.NextIndex() != 0 {
		t.Fatalf("ConfirmReceiptPersisted = %#v; want ready zero", step)
	}
	return begin.Session()
}

func assertArchiveSAFStreamFailureIsAttemptedIndeterminate(t *testing.T, archive []byte) {
	t.Helper()
	handoff, _, _ := newArchiveSAFHandoffFromZIP(t, archive, false)
	session := armNativeArchiveSAFSession(t, handoff)
	if step := session.Attempt(0); step.Kind() != NativeArchiveSAFStepAttempted {
		t.Fatalf("attempt = %#v", step)
	}
	destination, err := os.CreateTemp(t.TempDir(), "failed-stream-*")
	if err != nil {
		t.Fatalf("create failed-stream destination: %v", err)
	}
	if step := session.Write(0, destination); step == nil ||
		step.Kind() != NativeArchiveSAFStepPoisoned {
		t.Fatalf("failed stream step = %#v; want poisoned", step)
	}
	result := session.Abort()
	if result == nil || result.State() != fileops.UnpackStatePublicationIndeterminate ||
		!result.AttemptedEver() {
		t.Fatalf("failed stream terminal = %#v", result)
	}
}

func corruptArchiveSAFStoredBody(t *testing.T, archive []byte) {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil || len(reader.File) != 1 {
		t.Fatalf("open CRC fixture = %v entries=%d", err, len(reader.File))
	}
	offset, err := reader.File[0].DataOffset()
	if err != nil || offset < 0 || offset >= int64(len(archive)) {
		t.Fatalf("CRC fixture data offset = %d, %v", offset, err)
	}
	archive[offset] ^= 0xff
}

func setArchiveSAFCentralUncompressedSize(t *testing.T, archive []byte, size uint32) {
	t.Helper()
	const centralUncompressedSizeOffset = 24
	central := bytes.Index(archive, []byte{'P', 'K', 1, 2})
	if central < 0 || central+centralUncompressedSizeOffset+4 > len(archive) {
		t.Fatal("ZIP fixture central-directory header not found")
	}
	binary.LittleEndian.PutUint32(
		archive[central+centralUncompressedSizeOffset:central+centralUncompressedSizeOffset+4],
		size,
	)
}

type archiveSAFCloseErrorWriter struct{ *os.File }

func (writer *archiveSAFCloseErrorWriter) Close() error {
	_ = writer.File.Close()
	return errors.New("provider close ambiguity")
}

type archiveSAFPanicWriter struct{ file *os.File }

func (writer *archiveSAFPanicWriter) Write([]byte) (int, error) {
	panic("provider writer panic")
}

func (writer *archiveSAFPanicWriter) Close() error { return writer.file.Close() }

type archiveSAFBlockingWriter struct {
	file      *os.File
	entered   chan struct{}
	released  chan struct{}
	enterOnce sync.Once
	closeOnce sync.Once
	closeErr  error
}

func newArchiveSAFBlockingWriter(file *os.File) *archiveSAFBlockingWriter {
	return &archiveSAFBlockingWriter{
		file:     file,
		entered:  make(chan struct{}),
		released: make(chan struct{}),
	}
}

func (writer *archiveSAFBlockingWriter) Write(data []byte) (int, error) {
	writer.enterOnce.Do(func() { close(writer.entered) })
	<-writer.released
	return writer.file.Write(data)
}

func (writer *archiveSAFBlockingWriter) Close() error {
	writer.closeOnce.Do(func() {
		writer.closeErr = writer.file.Close()
		close(writer.released)
	})
	return writer.closeErr
}

func (writer *archiveSAFBlockingWriter) forceClose() { _ = writer.Close() }

type archiveSAFSettlementWriter struct {
	*os.File
	closeStarted chan struct{}
	closeRelease chan struct{}
	closeOnce    sync.Once
	releaseOnce  sync.Once
	closeErr     error
}

func newArchiveSAFSettlementWriter(file *os.File) *archiveSAFSettlementWriter {
	return &archiveSAFSettlementWriter{
		File:         file,
		closeStarted: make(chan struct{}),
		closeRelease: make(chan struct{}),
	}
}

func (writer *archiveSAFSettlementWriter) Close() error {
	writer.closeOnce.Do(func() {
		close(writer.closeStarted)
		<-writer.closeRelease
		writer.closeErr = writer.File.Close()
	})
	return writer.closeErr
}

func (writer *archiveSAFSettlementWriter) release() {
	writer.releaseOnce.Do(func() { close(writer.closeRelease) })
}

func findArchiveSAFStagePath(t *testing.T, parent string) string {
	t.Helper()
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatalf("read stage parent: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".picocrypt-pcv3-") &&
			!strings.HasSuffix(entry.Name(), ".journal") {
			return filepath.Join(parent, entry.Name())
		}
	}
	t.Fatal("journaled archive stage not found")
	return ""
}
