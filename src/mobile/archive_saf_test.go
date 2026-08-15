package mobile

import (
	"Picocrypt-NG/internal/pcv3"
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/pcv3publication"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type mobileArchiveSAFActionProbe struct {
	begin        func() pcv3ArchiveSAFCoreBegin
	closeResult  pcv3operation.Presentation
	closeEntered chan struct{}
}

func (action *mobileArchiveSAFActionProbe) Close() pcv3operation.Presentation {
	if action.closeEntered != nil {
		select {
		case action.closeEntered <- struct{}{}:
		default:
		}
	}
	return action.closeResult
}

func (action *mobileArchiveSAFActionProbe) beginSAF() pcv3ArchiveSAFCoreBegin {
	return action.begin()
}

type mobileArchiveSAFSessionProbe struct {
	mu sync.Mutex

	entries []pcv3ArchiveSAFCoreEntry
	payload []byte

	armed     bool
	nextIndex int
	attempted bool
	poisoned  bool
	terminal  bool
	active    io.WriteCloser

	confirmEntered chan struct{}
	writeEntered   chan struct{}
	writeProceed   chan struct{}
	finishEntered  chan struct{}
	abortEntered   chan struct{}
	panicWrite     bool

	finishResult pcv3operation.Presentation
	abortResult  pcv3operation.Presentation
}

func (probe *mobileArchiveSAFSessionProbe) EntryCount() int {
	probe.mu.Lock()
	defer probe.mu.Unlock()
	return len(probe.entries)
}

func (probe *mobileArchiveSAFSessionProbe) Entry(index int) (pcv3ArchiveSAFCoreEntry, bool) {
	probe.mu.Lock()
	defer probe.mu.Unlock()
	if index < 0 || index >= len(probe.entries) {
		return pcv3ArchiveSAFCoreEntry{}, false
	}
	return probe.entries[index], true
}

func (probe *mobileArchiveSAFSessionProbe) ConfirmReceiptPersisted() pcv3ArchiveSAFCoreStep {
	probe.mu.Lock()
	defer probe.mu.Unlock()
	if probe.terminal || probe.armed {
		return rejectedMobileArchiveSAFCoreStep()
	}
	probe.armed = true
	if probe.confirmEntered != nil {
		select {
		case probe.confirmEntered <- struct{}{}:
		default:
		}
	}
	return pcv3ArchiveSAFCoreStep{kind: "ready", nextIndex: probe.nextIndex}
}

func (probe *mobileArchiveSAFSessionProbe) Attempt(index int) pcv3ArchiveSAFCoreStep {
	probe.mu.Lock()
	defer probe.mu.Unlock()
	if probe.terminal || probe.poisoned || !probe.armed || probe.attempted ||
		index != probe.nextIndex || index < 0 || index >= len(probe.entries) {
		return rejectedMobileArchiveSAFCoreStep()
	}
	probe.attempted = true
	return pcv3ArchiveSAFCoreStep{kind: "attempted", nextIndex: probe.nextIndex}
}

func (probe *mobileArchiveSAFSessionProbe) AckDirectory(index int) pcv3ArchiveSAFCoreStep {
	probe.mu.Lock()
	defer probe.mu.Unlock()
	if probe.terminal || probe.poisoned || !probe.attempted || index != probe.nextIndex ||
		index < 0 || index >= len(probe.entries) || !probe.entries[index].directory {
		return rejectedMobileArchiveSAFCoreStep()
	}
	probe.attempted = false
	probe.nextIndex++
	return pcv3ArchiveSAFCoreStep{kind: "ready", nextIndex: probe.nextIndex}
}

func (probe *mobileArchiveSAFSessionProbe) Write(
	index int,
	destination io.WriteCloser,
) pcv3ArchiveSAFCoreStep {
	if probe.writeEntered != nil {
		select {
		case probe.writeEntered <- struct{}{}:
		default:
		}
	}
	if probe.writeProceed != nil {
		<-probe.writeProceed
	}
	probe.mu.Lock()
	if probe.terminal || probe.poisoned || !probe.attempted || index != probe.nextIndex ||
		index < 0 || index >= len(probe.entries) || probe.entries[index].directory {
		probe.mu.Unlock()
		if destination != nil {
			_ = destination.Close()
		}
		return rejectedMobileArchiveSAFCoreStep()
	}
	if destination == nil {
		probe.poisoned = true
		probe.attempted = false
		probe.mu.Unlock()
		return pcv3ArchiveSAFCoreStep{kind: "poisoned", nextIndex: index}
	}
	probe.active = destination
	panicWrite := probe.panicWrite
	payload := append([]byte(nil), probe.payload...)
	probe.mu.Unlock()

	if panicWrite {
		panic("test-only SAF writer panic")
	}
	reader := struct{ io.Reader }{Reader: bytes.NewReader(payload)}
	_, writeErr := io.CopyBuffer(destination, reader, make([]byte, 4<<10))
	closeErr := destination.Close()

	probe.mu.Lock()
	probe.active = nil
	probe.attempted = false
	if writeErr != nil || closeErr != nil {
		probe.poisoned = true
		probe.mu.Unlock()
		return pcv3ArchiveSAFCoreStep{kind: "poisoned", nextIndex: index}
	}
	probe.nextIndex++
	next := probe.nextIndex
	probe.mu.Unlock()
	return pcv3ArchiveSAFCoreStep{kind: "ready", nextIndex: next}
}

func (probe *mobileArchiveSAFSessionProbe) Cancel() pcv3ArchiveSAFCoreStep {
	probe.mu.Lock()
	if probe.terminal {
		probe.mu.Unlock()
		return rejectedMobileArchiveSAFCoreStep()
	}
	probe.poisoned = true
	active := probe.active
	nextIndex := probe.nextIndex
	probe.mu.Unlock()
	if active != nil {
		_ = active.Close()
	}
	return pcv3ArchiveSAFCoreStep{kind: "poisoned", nextIndex: nextIndex}
}

func (probe *mobileArchiveSAFSessionProbe) Finish() pcv3operation.Presentation {
	if probe.finishEntered != nil {
		select {
		case probe.finishEntered <- struct{}{}:
		default:
		}
	}
	probe.mu.Lock()
	complete := !probe.poisoned && !probe.attempted && probe.nextIndex == len(probe.entries)
	probe.terminal = true
	result := probe.finishResult
	if !complete {
		result = probe.abortResult
	}
	probe.mu.Unlock()
	return result
}

func (probe *mobileArchiveSAFSessionProbe) Abort() pcv3operation.Presentation {
	probe.mu.Lock()
	probe.poisoned = true
	probe.terminal = true
	active := probe.active
	probe.mu.Unlock()
	if active != nil {
		_ = active.Close()
	}
	if probe.abortEntered != nil {
		select {
		case probe.abortEntered <- struct{}{}:
		default:
		}
	}
	return probe.abortResult
}

func rejectedMobileArchiveSAFCoreStep() pcv3ArchiveSAFCoreStep {
	return pcv3ArchiveSAFCoreStep{kind: "rejected", nextIndex: -1}
}

func TestPCV3MobileArchiveSAFBeginCopiesShareOneClosedVariant(t *testing.T) {
	beginEntered := make(chan struct{})
	beginRelease := make(chan struct{})
	probe := newMobileArchiveSAFSessionProbe(t, []pcv3ArchiveSAFCoreEntry{
		{name: "file.txt", parentIndex: -1, size: 7},
	})
	action := &mobileArchiveSAFActionProbe{
		begin: func() pcv3ArchiveSAFCoreBegin {
			close(beginEntered)
			<-beginRelease
			return pcv3ArchiveSAFCoreBegin{kind: "session", session: probe}
		},
		closeResult: probe.abortResult,
	}
	operation, archive := newMobileArchiveSAFOperation(t, action)
	copyOfArchive := *archive
	winning := make(chan *PCV3ArchiveBegin, 1)
	go func() { winning <- archive.BeginSAF() }()
	<-beginEntered

	if code := operation.Release(); code != pcv3OperationReleaseDenied {
		t.Fatalf("Release during BeginSAF = %q; want denial", code)
	}
	losing := copyOfArchive.BeginSAF()
	if losing == nil || losing.Kind() != "expired" || losing.Code() != "expired" ||
		losing.Session() != nil || losing.Snapshot() != nil {
		t.Fatalf("copied losing BeginSAF = %#v; want closed expired", losing)
	}
	close(beginRelease)
	begin := <-winning
	if begin == nil || begin.Kind() != "session" || begin.Code() != "" ||
		begin.Session() == nil || begin.Snapshot() == nil {
		t.Fatalf("winning BeginSAF = %#v; want one closed session", begin)
	}
	if got := begin.Session().EntryCount(); got != 1 {
		t.Fatalf("EntryCount = %d; want one immutable manifest entry", got)
	}
	entry := begin.Session().Entry(0)
	if entry == nil || entry.Name() != "file.txt" || entry.ParentIndex() != -1 ||
		entry.IsDirectory() || entry.Size() != 7 || begin.Session().Entry(-1) != nil {
		t.Fatalf("bounded manifest entry = %#v", entry)
	}

	receipt := begin.Snapshot().RestoredReceipt()
	if receipt == "" || len(receipt) > maxPCV3ReceiptBytes {
		t.Fatalf("active receipt length = %d; want bounded v1 bytes", len(receipt))
	}
	var wire pcv3ReceiptWire
	if err := json.Unmarshal([]byte(receipt), &wire); err != nil {
		t.Fatalf("decode active v1 receipt: %v", err)
	}
	if wire.Version != 1 || wire.OperationID != operation.ID() || !validPCV3ReceiptID(wire.ReceiptID) ||
		wire.Outcome != uint8(pcv3.OutcomeSuccess) || wire.Stage != uint8(pcv3.StageNone) ||
		wire.Code != uint8(pcv3.CodeSuccess) || !wire.PublicationAttempted ||
		wire.PublicationState != uint8(pcv3publication.StatePublicationIndeterminate) ||
		wire.PublicationStage != uint8(pcv3.StageOutputPublication) ||
		wire.PublicationCode != uint8(pcv3publication.CodePublicationIndeterminate) {
		t.Fatalf("active receipt tuple = %#v", wire)
	}
	for _, forbidden := range []string{"content://", "path", "uri", "resume", "source", "file.txt"} {
		if strings.Contains(strings.ToLower(receipt), forbidden) {
			t.Fatalf("active receipt disclosed %q: %s", forbidden, receipt)
		}
	}
	if restored := RestorePCV3Receipt(receipt); restored == nil || restored.Code() != "" ||
		restored.Snapshot() == nil || restored.Snapshot().CompletionClass() != "publication-indeterminate" {
		t.Fatalf("active v1 receipt was not existing deny-only schema: %#v", restored)
	}
	if code := operation.Release(); code != pcv3OperationReleaseDenied {
		t.Fatalf("Release with live session = %q; want denial", code)
	}
	terminal := begin.Session().Abort()
	if terminal == nil || terminal.ArchivePending() || terminal.CompletionClass() == "unknown" {
		t.Fatalf("Abort terminal = %#v", terminal)
	}
	if code := operation.Release(); code != "" {
		t.Fatalf("Release after Abort = %q", code)
	}
}

func TestPCV3MobileArchiveSAFTerminalReplacementCapturesSnapshotBeforeRelease(t *testing.T) {
	terminalPresentation := mobileArchiveSAFAbortPresentation(t)
	action := &mobileArchiveSAFActionProbe{
		begin:       func() pcv3ArchiveSAFCoreBegin { return pcv3ArchiveSAFCoreBegin{} },
		closeResult: terminalPresentation,
	}
	operation, archive := newMobileArchiveSAFOperation(t, action)
	if _, consumed := archive.consume(); consumed == nil {
		t.Fatal("test setup did not move the archive action in flight")
	}

	terminal := replacePCV3ArchivePresentation(operation, terminalPresentation)
	if code := operation.Release(); code != "" {
		t.Fatalf("Release after terminal replacement = %q", code)
	}
	if live := operation.Snapshot(); live.CompletionClass() != "unknown" {
		t.Fatalf("released registry snapshot = %q; want unknown", live.CompletionClass())
	}
	if terminal == nil || terminal.CompletionClass() != "publication-indeterminate" ||
		terminal.RestoredReceipt() == "" || terminal.operationID != operation.ID() {
		t.Fatalf("captured terminal snapshot after Release = %#v", terminal)
	}
}

func TestPCV3MobileArchiveSAFTerminalCallersCaptureSnapshotBeforeRelease(t *testing.T) {
	for _, test := range []struct {
		name  string
		setup func(*testing.T) (*PCV3Operation, func() *PCV3Snapshot)
	}{
		{
			name: "terminal begin",
			setup: func(t *testing.T) (*PCV3Operation, func() *PCV3Snapshot) {
				terminal := mobileArchiveSAFFinishPresentation(t)
				action := &mobileArchiveSAFActionProbe{
					begin: func() pcv3ArchiveSAFCoreBegin {
						return pcv3ArchiveSAFCoreBegin{kind: "terminal", presentation: terminal}
					},
					closeResult: terminal,
				}
				operation, archive := newMobileArchiveSAFOperation(t, action)
				return operation, func() *PCV3Snapshot {
					begin := archive.BeginSAF()
					if begin == nil || begin.Kind() != "terminal" {
						return nil
					}
					return begin.Snapshot()
				}
			},
		},
		{
			name: "session finish",
			setup: func(t *testing.T) (*PCV3Operation, func() *PCV3Snapshot) {
				probe := newMobileArchiveSAFSessionProbe(t, nil)
				operation, begin := beginMobileArchiveSAFSession(t, probe)
				return operation, begin.Session().Finish
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			operation, terminalCall := test.setup(t)
			generatorEntered := make(chan struct{})
			generatorProceed := make(chan struct{})
			originalGenerator := pcv3ReceiptIDGenerator
			pcv3ReceiptIDGenerator = func() string {
				close(generatorEntered)
				<-generatorProceed
				return "r_00000000000000000000000000000001"
			}
			t.Cleanup(func() { pcv3ReceiptIDGenerator = originalGenerator })

			terminalResult := make(chan *PCV3Snapshot, 1)
			go func() { terminalResult <- terminalCall() }()
			<-generatorEntered

			locked := true
			globalProgressMap.mu.Lock()
			defer func() {
				if locked {
					globalProgressMap.mu.Unlock()
				}
			}()
			close(generatorProceed)
			if !mobileArchiveSAFWriterBlockedOnProgressMap("replacePCV3ArchivePresentationWithReceipt") {
				globalProgressMap.mu.Unlock()
				locked = false
				t.Fatal("terminal replacement did not queue on the held progress lock")
			}
			releaseResult := make(chan string, 1)
			go func() { releaseResult <- operation.Release() }()
			if !mobileArchiveSAFWriterBlockedOnProgressMap("(*PCV3Operation).Release") {
				globalProgressMap.mu.Unlock()
				locked = false
				t.Fatal("Release did not queue behind terminal replacement")
			}
			globalProgressMap.mu.Unlock()
			locked = false

			if code := <-releaseResult; code != "" {
				t.Fatalf("queued Release = %q", code)
			}
			terminal := <-terminalResult
			if terminal == nil || terminal.CompletionClass() == "unknown" ||
				terminal.RestoredReceipt() == "" || terminal.operationID != operation.ID() {
				t.Fatalf("terminal caller snapshot after queued Release = %#v", terminal)
			}
		})
	}
}

func TestPCV3MobileArchiveSAFCompletionDrainsAdmittedWriteBeforeCoreTerminal(t *testing.T) {
	for _, test := range []struct {
		name     string
		complete func(*PCV3ArchiveSession) *PCV3Snapshot
		entered  func(*mobileArchiveSAFSessionProbe) chan struct{}
	}{
		{
			name:     "finish",
			complete: (*PCV3ArchiveSession).Finish,
			entered: func(probe *mobileArchiveSAFSessionProbe) chan struct{} {
				probe.finishEntered = make(chan struct{}, 1)
				return probe.finishEntered
			},
		},
		{
			name:     "abort",
			complete: (*PCV3ArchiveSession).Abort,
			entered: func(probe *mobileArchiveSAFSessionProbe) chan struct{} {
				probe.abortEntered = make(chan struct{}, 1)
				return probe.abortEntered
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := []byte("provider effect before terminal truth")
			probe := newMobileArchiveSAFSessionProbe(t, []pcv3ArchiveSAFCoreEntry{{
				name: "file", parentIndex: -1, size: int64(len(payload)),
			}})
			probe.payload = payload
			probe.writeEntered = make(chan struct{}, 1)
			probe.writeProceed = make(chan struct{})
			terminalEntered := test.entered(probe)
			operation, begin := beginMobileArchiveSAFSession(t, probe)
			session := armMobileArchiveSAFSession(t, begin)
			if step := session.Attempt(0); step == nil || step.Kind() != "attempted" {
				t.Fatalf("Attempt = %#v", step)
			}
			destination, err := os.CreateTemp(t.TempDir(), "provider")
			if err != nil {
				t.Fatal(err)
			}
			defer destination.Close()
			transferredFD := duplicateMobileArchiveSAFFD(t, destination)
			writeResult := make(chan *PCV3ArchiveStep, 1)
			go func() { writeResult <- session.WriteFD(0, transferredFD) }()
			<-probe.writeEntered

			terminalResult := make(chan *PCV3Snapshot, 1)
			go func() { terminalResult <- test.complete(session) }()
			waitMobileArchiveSAFSessionSealed(t, session)
			select {
			case <-terminalEntered:
				t.Fatal("core terminal froze before the admitted provider call settled")
			default:
			}
			select {
			case terminal := <-terminalResult:
				t.Fatalf("completion returned before admitted provider call: %#v", terminal)
			default:
			}

			close(probe.writeProceed)
			if step := <-writeResult; step == nil || step.Kind() != "ready" {
				t.Fatalf("admitted WriteFD settlement = %#v", step)
			}
			terminal := <-terminalResult
			select {
			case <-terminalEntered:
			default:
				t.Fatal("core terminal was not called after the provider call settled")
			}
			if terminal == nil || terminal.CompletionClass() == "unknown" {
				t.Fatalf("terminal after admitted provider call = %#v", terminal)
			}
			assertMobileArchiveSAFFDClosed(t, transferredFD)
			if code := operation.Release(); code != "" {
				t.Fatalf("Release after settled completion = %q", code)
			}
		})
	}
}

func TestPCV3MobileArchiveSAFBeginContainsPreparationAndReceiptFailures(t *testing.T) {
	t.Run("core terminal", func(t *testing.T) {
		terminal := closedPCV3MobileArchivePresentation(t, false)
		action := &mobileArchiveSAFActionProbe{
			begin: func() pcv3ArchiveSAFCoreBegin {
				return pcv3ArchiveSAFCoreBegin{kind: "terminal", presentation: terminal}
			},
			closeResult: terminal,
		}
		operation, archive := newMobileArchiveSAFOperation(t, action)
		begin := archive.BeginSAF()
		if begin == nil || begin.Kind() != "terminal" || begin.Code() != "PCV3_OPERATION_FAILED" ||
			begin.Session() != nil || begin.Snapshot() == nil || begin.Snapshot().ArchivePending() {
			t.Fatalf("terminal BeginSAF = %#v", begin)
		}
		if code := operation.Release(); code != "" {
			t.Fatalf("Release after terminal BeginSAF = %q", code)
		}
	})

	t.Run("panic", func(t *testing.T) {
		closed := closedPCV3MobileArchivePresentation(t, true)
		closeEntered := make(chan struct{}, 1)
		action := &mobileArchiveSAFActionProbe{
			begin:        func() pcv3ArchiveSAFCoreBegin { panic("test-only BeginSAF panic") },
			closeResult:  closed,
			closeEntered: closeEntered,
		}
		operation, archive := newMobileArchiveSAFOperation(t, action)
		begin := archive.BeginSAF()
		if begin == nil || begin.Kind() != "terminal" || begin.Session() != nil ||
			begin.Snapshot() == nil || begin.Snapshot().CompletionClass() == "unknown" {
			t.Fatalf("contained panic BeginSAF = %#v", begin)
		}
		select {
		case <-closeEntered:
		default:
			t.Fatal("BeginSAF panic did not settle the consumed archive action")
		}
		if code := operation.Release(); code != "" {
			t.Fatalf("Release after contained BeginSAF panic = %q", code)
		}
	})

	t.Run("receipt mint", func(t *testing.T) {
		probe := newMobileArchiveSAFSessionProbe(t, nil)
		probe.abortEntered = make(chan struct{}, 1)
		action := &mobileArchiveSAFActionProbe{
			begin:       func() pcv3ArchiveSAFCoreBegin { return pcv3ArchiveSAFCoreBegin{kind: "session", session: probe} },
			closeResult: probe.abortResult,
		}
		operation, archive := newMobileArchiveSAFOperation(t, action)
		originalGenerator := pcv3ReceiptIDGenerator
		pcv3ReceiptIDGenerator = func() string { return "" }
		t.Cleanup(func() { pcv3ReceiptIDGenerator = originalGenerator })

		begin := archive.BeginSAF()
		if begin == nil || begin.Kind() != "terminal" || begin.Session() != nil ||
			begin.Snapshot() == nil || begin.Snapshot().ArchivePending() {
			t.Fatalf("receipt-mint failure BeginSAF = %#v", begin)
		}
		select {
		case <-probe.abortEntered:
		default:
			t.Fatal("receipt-mint failure did not Abort the prepared core session")
		}
		if code := operation.Release(); code != "" {
			t.Fatalf("Release after receipt-mint Abort = %q", code)
		}
	})

	for _, malformed := range []struct {
		name  string
		begin pcv3ArchiveSAFCoreBegin
	}{
		{name: "zero begin"},
		{name: "nil session", begin: pcv3ArchiveSAFCoreBegin{kind: "session"}},
		{name: "unexpected expired", begin: pcv3ArchiveSAFCoreBegin{kind: "expired"}},
	} {
		t.Run(malformed.name, func(t *testing.T) {
			closed := closedPCV3MobileArchivePresentation(t, true)
			action := &mobileArchiveSAFActionProbe{
				begin:       func() pcv3ArchiveSAFCoreBegin { return malformed.begin },
				closeResult: closed,
			}
			operation, archive := newMobileArchiveSAFOperation(t, action)
			begin := archive.BeginSAF()
			if begin == nil || begin.Kind() != "terminal" || begin.Session() != nil ||
				begin.Snapshot() == nil || begin.Snapshot().CompletionClass() == "unknown" {
				t.Fatalf("malformed core begin = %#v; want terminal", begin)
			}
			if code := operation.Release(); code != "" {
				t.Fatalf("Release after malformed core begin = %q", code)
			}
		})
	}

	for _, contradictoryKind := range []string{"terminal", "expired"} {
		t.Run("prepared session with "+contradictoryKind, func(t *testing.T) {
			probe := newMobileArchiveSAFSessionProbe(t, nil)
			probe.abortEntered = make(chan struct{}, 1)
			coreBegin := pcv3ArchiveSAFCoreBegin{
				kind:         contradictoryKind,
				session:      probe,
				presentation: mobileArchiveSAFFinishPresentation(t),
			}
			action := &mobileArchiveSAFActionProbe{
				begin:       func() pcv3ArchiveSAFCoreBegin { return coreBegin },
				closeResult: probe.abortResult,
			}
			operation, archive := newMobileArchiveSAFOperation(t, action)
			begin := archive.BeginSAF()
			if begin == nil || begin.Kind() != "terminal" || begin.Session() != nil ||
				begin.Snapshot() == nil || begin.Snapshot().CompletionClass() == "unknown" {
				t.Fatalf("contradictory core begin = %#v; want closed terminal", begin)
			}
			select {
			case <-probe.abortEntered:
			default:
				t.Fatal("non-transferred prepared session was not aborted")
			}
			if code := operation.Release(); code != "" {
				t.Fatalf("Release after contradictory core begin = %q", code)
			}
		})
	}
}

func TestPCV3MobileArchiveSAFReceiptArmsOnlyTheExactLiveSession(t *testing.T) {
	firstProbe := newMobileArchiveSAFSessionProbe(t, []pcv3ArchiveSAFCoreEntry{{name: "a", parentIndex: -1}})
	firstProbe.confirmEntered = make(chan struct{}, 1)
	firstOperation, firstBegin := beginMobileArchiveSAFSession(t, firstProbe)
	secondProbe := newMobileArchiveSAFSessionProbe(t, []pcv3ArchiveSAFCoreEntry{{name: "b", parentIndex: -1}})
	_, secondBegin := beginMobileArchiveSAFSession(t, secondProbe)
	firstSession := firstBegin.Session()
	firstReceipt := firstBegin.Snapshot().RestoredReceipt()
	secondReceipt := secondBegin.Snapshot().RestoredReceipt()

	if step := firstSession.Attempt(0); step == nil || step.Kind() != "rejected" || step.NextIndex() != -1 {
		t.Fatalf("unarmed Attempt = %#v; want rejected", step)
	}
	for _, mismatch := range []string{"", "unknown", secondReceipt, firstReceipt + " "} {
		if step := firstSession.ConfirmCrashReceiptPersisted(mismatch); step == nil || step.Kind() != "rejected" {
			t.Fatalf("mismatched confirmation %q = %#v", mismatch, step)
		}
	}
	select {
	case <-firstProbe.confirmEntered:
		t.Fatal("mismatched receipt reached the unforgeable core arm")
	default:
	}
	if step := firstSession.ConfirmCrashReceiptPersisted(firstReceipt); step == nil ||
		step.Kind() != "ready" || step.NextIndex() != 0 {
		t.Fatalf("exact receipt confirmation = %#v", step)
	}
	select {
	case <-firstProbe.confirmEntered:
	default:
		t.Fatal("exact receipt did not reach the core arm")
	}
	if step := firstSession.ConfirmCrashReceiptPersisted(firstReceipt); step == nil || step.Kind() != "rejected" {
		t.Fatalf("duplicate exact confirmation = %#v", step)
	}
	if step := firstSession.Attempt(0); step == nil || step.Kind() != "attempted" {
		t.Fatalf("armed Attempt = %#v", step)
	}
	if terminal := firstSession.Abort(); terminal == nil || terminal.ArchivePending() {
		t.Fatalf("first Abort = %#v", terminal)
	}
	if step := firstSession.ConfirmCrashReceiptPersisted(firstReceipt); step == nil || step.Kind() != "rejected" {
		t.Fatalf("stale confirmation after Abort = %#v", step)
	}
	if code := firstOperation.Release(); code != "" {
		t.Fatalf("first operation Release = %q", code)
	}
	_ = secondBegin.Session().Abort()
}

func TestPCV3MobileArchiveSAFWriteFDOwnsRegularAndRejectsInvalidDescriptors(t *testing.T) {
	t.Run("regular and retained observer", func(t *testing.T) {
		payload := []byte("mobile SAF descriptor payload")
		probe := newMobileArchiveSAFSessionProbe(t, []pcv3ArchiveSAFCoreEntry{{name: "file", parentIndex: -1, size: int64(len(payload))}})
		probe.payload = payload
		operation, begin := beginMobileArchiveSAFSession(t, probe)
		activeReceipt := begin.Snapshot().RestoredReceipt()
		session := armMobileArchiveSAFSession(t, begin)
		if step := session.Attempt(0); step.Kind() != "attempted" {
			t.Fatalf("Attempt = %#v", step)
		}
		path := filepath.Join(t.TempDir(), "provider.bin")
		original, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatalf("create provider observer: %v", err)
		}
		defer original.Close()
		transferredFD := duplicateMobileArchiveSAFFD(t, original)
		step := session.WriteFD(0, transferredFD)
		if step == nil || step.Kind() != "ready" || step.NextIndex() != 1 {
			t.Fatalf("WriteFD regular = %#v", step)
		}
		assertMobileArchiveSAFFDClosed(t, transferredFD)
		if _, err := original.Stat(); err != nil {
			t.Fatalf("Go closed Kotlin-retained original observer: %v", err)
		}
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("provider file = %q, %v; want %q", got, err, payload)
		}
		terminal := session.Finish()
		if terminal == nil || terminal.PublicationState() != "published-durability-uncertain" ||
			terminal.CompletionClass() != "durability-uncertain" {
			t.Fatalf("Finish = %#v", terminal)
		}
		terminalReceipt := terminal.RestoredReceipt()
		if terminalReceipt == "" || terminalReceipt == activeReceipt {
			t.Fatalf("Finish receipt transition = active %q terminal %q; want nonempty replacement", activeReceipt, terminalReceipt)
		}
		if code := operation.Release(); code != "" {
			t.Fatalf("Release after Finish = %q", code)
		}
	})

	t.Run("out of range poisons after Attempt without touching another fd", func(t *testing.T) {
		probe := newMobileArchiveSAFSessionProbe(t, []pcv3ArchiveSAFCoreEntry{{name: "file", parentIndex: -1}})
		_, begin := beginMobileArchiveSAFSession(t, probe)
		session := armMobileArchiveSAFSession(t, begin)
		_ = session.Attempt(0)
		guard, err := os.CreateTemp(t.TempDir(), "guard")
		if err != nil {
			t.Fatal(err)
		}
		defer guard.Close()
		if _, err := guard.WriteString("guard"); err != nil {
			t.Fatal(err)
		}
		step := session.WriteFD(0, maxPCV3OutputFD+1)
		if step == nil || step.Kind() != "poisoned" {
			t.Fatalf("out-of-range WriteFD = %#v; want core poison", step)
		}
		if _, err := guard.Stat(); err != nil {
			t.Fatalf("out-of-range fd acted on unrelated descriptor: %v", err)
		}
		_ = session.Abort()
	})

	t.Run("directory type is rejected and adopted fd is closed", func(t *testing.T) {
		probe := newMobileArchiveSAFSessionProbe(t, []pcv3ArchiveSAFCoreEntry{{name: "file", parentIndex: -1}})
		_, begin := beginMobileArchiveSAFSession(t, probe)
		session := armMobileArchiveSAFSession(t, begin)
		_ = session.Attempt(0)
		directory, err := os.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		defer directory.Close()
		transferredFD := duplicateMobileArchiveSAFFD(t, directory)
		step := session.WriteFD(0, transferredFD)
		if step == nil || step.Kind() != "poisoned" {
			t.Fatalf("directory WriteFD = %#v; want core poison", step)
		}
		assertMobileArchiveSAFFDClosed(t, transferredFD)
		if _, err := directory.Stat(); err != nil {
			t.Fatalf("rejected duplicate closed the retained directory: %v", err)
		}
		_ = session.Abort()
	})

	t.Run("expired and duplicate calls still adopt and close", func(t *testing.T) {
		probe := newMobileArchiveSAFSessionProbe(t, nil)
		_, begin := beginMobileArchiveSAFSession(t, probe)
		session := begin.Session()
		stale := *session
		_ = session.Abort()
		first, err := os.CreateTemp(t.TempDir(), "expired")
		if err != nil {
			t.Fatal(err)
		}
		defer first.Close()
		firstFD := duplicateMobileArchiveSAFFD(t, first)
		if step := stale.WriteFD(0, firstFD); step == nil || step.Kind() != "rejected" {
			t.Fatalf("expired WriteFD = %#v", step)
		}
		assertMobileArchiveSAFFDClosed(t, firstFD)
		secondFD := duplicateMobileArchiveSAFFD(t, first)
		if step := stale.WriteFD(0, secondFD); step == nil || step.Kind() != "rejected" {
			t.Fatalf("copied stale WriteFD = %#v", step)
		}
		assertMobileArchiveSAFFDClosed(t, secondFD)
		if _, err := first.Stat(); err != nil {
			t.Fatalf("stale calls closed the retained provider descriptor: %v", err)
		}
	})

	t.Run("backend panic closes through the same once owner", func(t *testing.T) {
		probe := newMobileArchiveSAFSessionProbe(t, []pcv3ArchiveSAFCoreEntry{{name: "file", parentIndex: -1}})
		probe.panicWrite = true
		_, begin := beginMobileArchiveSAFSession(t, probe)
		session := armMobileArchiveSAFSession(t, begin)
		_ = session.Attempt(0)
		destination, err := os.CreateTemp(t.TempDir(), "panic")
		if err != nil {
			t.Fatal(err)
		}
		defer destination.Close()
		transferredFD := duplicateMobileArchiveSAFFD(t, destination)
		step := session.WriteFD(0, transferredFD)
		if step == nil || step.Kind() != "poisoned" {
			t.Fatalf("contained WriteFD panic = %#v", step)
		}
		assertMobileArchiveSAFFDClosed(t, transferredFD)
		if _, err := destination.Stat(); err != nil {
			t.Fatalf("contained panic closed the retained provider descriptor: %v", err)
		}
		_ = session.Abort()
	})
}

func TestPCV3MobileArchiveSAFCancelClosesOnlyTheExactBlockedPipe(t *testing.T) {
	payload := bytes.Repeat([]byte("p"), 2<<20)
	probe := newMobileArchiveSAFSessionProbe(t, []pcv3ArchiveSAFCoreEntry{{name: "pipe", parentIndex: -1, size: int64(len(payload))}})
	probe.payload = payload
	probe.writeEntered = make(chan struct{}, 1)
	operation, begin := beginMobileArchiveSAFSession(t, probe)
	activeReceipt := begin.Snapshot().RestoredReceipt()
	session := armMobileArchiveSAFSession(t, begin)
	_ = session.Attempt(0)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	transferredFD := duplicateMobileArchiveSAFFD(t, writer)
	writeResult := make(chan *PCV3ArchiveStep, 1)
	go func() { writeResult <- session.WriteFD(0, transferredFD) }()
	<-probe.writeEntered

	staleProbe := newMobileArchiveSAFSessionProbe(t, nil)
	_, staleBegin := beginMobileArchiveSAFSession(t, staleProbe)
	stale := staleBegin.Session()
	_ = stale.Abort()
	if step := stale.Cancel(); step == nil || step.Kind() != "rejected" {
		t.Fatalf("stale Cancel = %#v", step)
	}
	select {
	case result := <-writeResult:
		t.Fatalf("stale Cancel settled another session: %#v", result)
	default:
	}

	if step := session.Cancel(); step == nil || step.Kind() != "poisoned" {
		t.Fatalf("exact Cancel = %#v", step)
	}
	if result := <-writeResult; result == nil || result.Kind() != "poisoned" {
		t.Fatalf("blocked pipe WriteFD settlement = %#v", result)
	}
	assertMobileArchiveSAFFDClosed(t, transferredFD)
	if _, err := writer.Stat(); err != nil {
		t.Fatalf("Cancel closed the retained pipe writer: %v", err)
	}
	if _, err := reader.Stat(); err != nil {
		t.Fatalf("Cancel closed the untransferred pipe reader: %v", err)
	}
	terminal := session.Abort()
	if terminal == nil || terminal.PublicationState() != "publication-indeterminate" {
		t.Fatalf("attempted Cancel Abort = %#v", terminal)
	}
	if terminalReceipt := terminal.RestoredReceipt(); terminalReceipt != activeReceipt {
		t.Fatalf("unchanged attempted Abort receipt = %q; want exact active %q", terminalReceipt, activeReceipt)
	}
	if code := operation.Release(); code != "" {
		t.Fatalf("Release after pipe settlement = %q", code)
	}
}

func TestPCV3MobileArchiveSAFJournalWrapperUsesOnlyClosedLocalStates(t *testing.T) {
	absentParent := t.TempDir()
	if state := CleanupPCV3Journal(absentParent); state != "absent" {
		t.Fatalf("absent journal cleanup = %q", state)
	}
	if state := CleanupPCV3Journal("content://provider/tree/private"); state != "incomplete" {
		t.Fatalf("SAF value cleanup = %q; want incomplete", state)
	}
	if state := CleanupPCV3Journal("relative/private"); state != "incomplete" {
		t.Fatalf("relative cleanup = %q; want incomplete", state)
	}

	parent := t.TempDir()
	target := filepath.Join(parent, "output.bin")
	stage, err := pcv3publication.Create(target, nil, pcv3publication.PolicyNoReplace)
	if err != nil {
		t.Fatalf("create journaled stage: %v", err)
	}
	if err := stage.PersistCleanupJournal(); err != nil {
		_ = stage.Cleanup()
		t.Fatalf("persist cleanup journal: %v", err)
	}
	if _, err := stage.File().WriteString("private plaintext"); err != nil {
		_ = stage.Cleanup()
		t.Fatalf("write journaled stage: %v", err)
	}
	if state := CleanupPCV3Journal(parent); state != "cleaned" {
		t.Fatalf("real journal cleanup = %q", state)
	}
	if entries, err := os.ReadDir(parent); err != nil || len(entries) != 0 {
		t.Fatalf("cleaned parent entries = %v, %v; want empty", entries, err)
	}
	if state := CleanupPCV3Journal(parent); state != "absent" {
		t.Fatalf("second journal cleanup = %q; want absent", state)
	}

	malformedParent := t.TempDir()
	journal := filepath.Join(malformedParent, ".picocrypt-pcv3-stage.journal")
	if err := os.WriteFile(journal, []byte("not a journal\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if state := CleanupPCV3Journal(malformedParent); state != "incomplete" {
		t.Fatalf("malformed journal cleanup = %q", state)
	}
	if got, err := os.ReadFile(journal); err != nil || !bytes.Equal(got, []byte("not a journal\n")) {
		t.Fatalf("malformed journal was not preserved: %q, %v", got, err)
	}
}

func duplicateMobileArchiveSAFFD(t *testing.T, original *os.File) int64 {
	t.Helper()
	if original == nil {
		t.Fatal("duplicate SAF descriptor from nil original")
	}
	fd, err := unix.Dup(int(original.Fd()))
	if err != nil {
		t.Fatalf("duplicate SAF descriptor: %v", err)
	}
	return int64(fd)
}

func assertMobileArchiveSAFFDClosed(t *testing.T, fd int64) {
	t.Helper()
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("transferred SAF descriptor %d remains open: %v", fd, err)
	}
}

func mobileArchiveSAFWriterBlockedOnProgressMap(frame string) bool {
	deadline := time.Now().Add(2 * time.Second)
	stack := make([]byte, 1<<20)
	for time.Now().Before(deadline) {
		n := runtime.Stack(stack, true)
		for _, goroutine := range strings.Split(string(stack[:n]), "\n\n") {
			if strings.Contains(goroutine, "sync.(*RWMutex).Lock") &&
				strings.Contains(goroutine, frame) {
				return true
			}
		}
		runtime.Gosched()
	}
	return false
}

func waitMobileArchiveSAFSessionSealed(t *testing.T, session *PCV3ArchiveSession) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if session != nil && session.state != nil {
			session.state.mu.Lock()
			sealed := session.state.sealed
			session.state.mu.Unlock()
			if sealed {
				return
			}
		}
		runtime.Gosched()
	}
	t.Fatal("session completion did not seal new provider-call admission")
}

func newMobileArchiveSAFOperation(
	t *testing.T,
	action pcv3ArchiveAction,
) (*PCV3Operation, *PCV3Archive) {
	t.Helper()
	operation := startPCV3Operation()
	t.Cleanup(func() {
		if archive := operation.Archive(); archive != nil {
			_ = archive.Close()
		}
		_ = operation.Release()
	})
	pending := mustPCV3Presentation(t, pcv3operation.PresentationSpec{
		Outcome:        pcv3.OutcomeSuccess,
		Stage:          pcv3.StageNone,
		Code:           pcv3.CodeSuccess,
		ArchivePending: true,
	})
	completePCV3PresentationWithArchive(operation, pending, action)
	archive := operation.Archive()
	if archive == nil {
		t.Fatal("archive-pending operation exposed no one-shot mobile archive")
	}
	return operation, archive
}

func beginMobileArchiveSAFSession(
	t *testing.T,
	probe *mobileArchiveSAFSessionProbe,
) (*PCV3Operation, *PCV3ArchiveBegin) {
	t.Helper()
	action := &mobileArchiveSAFActionProbe{
		begin: func() pcv3ArchiveSAFCoreBegin {
			return pcv3ArchiveSAFCoreBegin{kind: "session", session: probe}
		},
		closeResult: probe.abortResult,
	}
	operation, archive := newMobileArchiveSAFOperation(t, action)
	begin := archive.BeginSAF()
	if begin == nil || begin.Kind() != "session" || begin.Session() == nil || begin.Snapshot() == nil {
		t.Fatalf("BeginSAF = %#v; want session", begin)
	}
	return operation, begin
}

func armMobileArchiveSAFSession(t *testing.T, begin *PCV3ArchiveBegin) *PCV3ArchiveSession {
	t.Helper()
	receipt := begin.Snapshot().RestoredReceipt()
	if receipt == "" {
		t.Fatal("active session exposed no deny-only receipt")
	}
	session := begin.Session()
	if step := session.ConfirmCrashReceiptPersisted(receipt); step == nil || step.Kind() != "ready" {
		t.Fatalf("arm active session = %#v", step)
	}
	return session
}

func newMobileArchiveSAFSessionProbe(
	t *testing.T,
	entries []pcv3ArchiveSAFCoreEntry,
) *mobileArchiveSAFSessionProbe {
	t.Helper()
	return &mobileArchiveSAFSessionProbe{
		entries:      append([]pcv3ArchiveSAFCoreEntry(nil), entries...),
		finishResult: mobileArchiveSAFFinishPresentation(t),
		abortResult:  mobileArchiveSAFAbortPresentation(t),
	}
}

func mobileArchiveSAFFinishPresentation(t *testing.T) pcv3operation.Presentation {
	t.Helper()
	return mustPCV3Presentation(t, pcv3operation.PresentationSpec{
		Outcome:              pcv3.OutcomeSuccess,
		Stage:                pcv3.StageNone,
		Code:                 pcv3.CodeSuccess,
		PublicationAttempted: true,
		PublicationState:     pcv3publication.StatePublishedDurabilityUncertain,
		PublicationStage:     pcv3.StageDirectorySync,
		PublicationCode:      pcv3publication.CodeDurabilityUncertain,
	})
}

func mobileArchiveSAFAbortPresentation(t *testing.T) pcv3operation.Presentation {
	t.Helper()
	return mustPCV3Presentation(t, pcv3operation.PresentationSpec{
		Outcome:              pcv3.OutcomeSuccess,
		Stage:                pcv3.StageNone,
		Code:                 pcv3.CodeSuccess,
		PublicationAttempted: true,
		PublicationState:     pcv3publication.StatePublicationIndeterminate,
		PublicationStage:     pcv3.StageOutputPublication,
		PublicationCode:      pcv3publication.CodePublicationIndeterminate,
	})
}
