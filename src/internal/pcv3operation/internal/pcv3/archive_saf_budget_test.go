package pcv3

import (
	"Picocrypt-NG/internal/fileops"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArchiveSAFAdmitsShortManifestAboveFormerCountAndReleasesMetadata(t *testing.T) {
	entries := make([]archiveSAFZIPEntry, 65_537)
	for index := range entries {
		entries[index] = archiveSAFZIPEntry{name: fmt.Sprintf("f%05d", index)}
	}
	archive := buildArchiveSAFZIP(t, entries)
	handoff, stageParent, rawTarget := newArchiveSAFHandoffFromZIP(t, archive, false)
	begin := handoff.BeginSAF()
	if begin == nil || begin.Kind() != NativeArchiveSAFBeginSession {
		t.Fatalf("affordable manifest above old count refused: %#v", begin)
	}
	session := begin.Session()
	if session.EntryCount() != 65_537 || session.Entry(0).Name() != "f00000" ||
		session.Entry(65_536).Name() != "f65536" {
		t.Fatal("manifest lost canonical entries")
	}
	budget := session.state.zipReader.Budget()
	if budget.CurrentBytes() == 0 {
		t.Fatal("live manifest reader was not accounted")
	}
	result := session.Abort()
	if result == nil || result.State() != fileops.UnpackStateNotPublished ||
		result.AttemptedEver() || result.CleanupIncomplete() {
		t.Fatalf("unattempted abort lost exact cleanup: %#v", result)
	}
	if budget.CurrentBytes() != 0 {
		t.Fatal("terminal session retained its archive allocation charge")
	}
	assertNativeArchiveStage(t, stageParent, rawTarget, 0)
}

func TestArchiveSAFHostAllowanceExcludesLiveNativeMetadata(t *testing.T) {
	archive := buildArchiveSAFZIP(t, []archiveSAFZIPEntry{{name: "file"}})
	handoff, _, _ := newArchiveSAFHandoffFromZIP(t, archive, false)
	session := handoff.BeginSAF().Session()
	defer session.Abort()
	host, ok := any(session).(interface{ HostMemoryBudgetBytes() int64 })
	if !ok {
		t.Fatal("SAF session does not expose native remaining allowance")
	}
	budget := session.state.zipReader.Budget()
	remaining := host.HostMemoryBudgetBytes()
	if remaining <= 0 || uint64(remaining)+budget.CurrentBytes() > min(budget.LimitBytes(), uint64(192<<20)) {
		t.Fatalf("host allowance %d overlaps retained native charge %d", remaining, budget.CurrentBytes())
	}
	session.Abort()
	if host.HostMemoryBudgetBytes() != 0 {
		t.Fatal("terminal session granted host memory authority")
	}
}

func TestArchiveSAFPreparationCancellationConsumesAndCleansWithoutSession(t *testing.T) {
	archive := buildArchiveSAFZIP(t, []archiveSAFZIPEntry{{name: "file"}})
	handoff, parent, target := newArchiveSAFHandoffFromZIP(t, archive, false)
	cancellable, ok := any(handoff).(interface {
		BeginSAFWithContext(context.Context) *NativeArchiveSAFBegin
	})
	if !ok {
		t.Fatal("SAF preparation has no cancellation boundary")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	begin := cancellable.BeginSAFWithContext(ctx)
	if begin.Kind() != NativeArchiveSAFBeginTerminal || begin.Session() != nil || begin.Result().AttemptedEver() || begin.Result().CleanupIncomplete() {
		t.Fatalf("cancelled preparation granted authority or leaked stage: %#v", begin)
	}
	if handoff.BeginSAF().Kind() != NativeArchiveSAFBeginExpired {
		t.Fatal("cancelled begin revived handoff")
	}
	assertNativeArchiveStage(t, parent, target, 0)
}

func TestArchiveSAFSessionOutlivesPreparationContext(t *testing.T) {
	fixture := requireNormalFixture(t, loadNormalFixtureManifest(t).FixturesByID(), normalArchiveFixtureID)
	original := readNormalFixtureArtifact(t, fixture.Volume)
	originalPath := filepath.Join(normalPublicFixtureRoot, fixture.Volume.File)
	originalInfo, err := os.Stat(originalPath)
	if err != nil {
		t.Fatal(err)
	}
	handoff, parent, target := newNativeArchiveHandoffFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	begin := handoff.BeginSAFWithContext(ctx)
	if begin == nil || begin.Kind() != NativeArchiveSAFBeginSession || begin.Session() == nil {
		t.Fatalf("preparation = %#v; want authenticated session", begin)
	}
	session := begin.Session()
	defer session.Abort()
	budget := session.state.zipReader.Budget()
	// The mobile bridge retires this context as soon as BeginSAF returns.
	// Provider streaming must belong to the newly issued session instead.
	cancel()
	if step := session.ConfirmReceiptPersisted(begin.ReceiptArm()); step == nil || step.Kind() != NativeArchiveSAFStepReady {
		t.Fatalf("receipt confirmation = %#v", step)
	}
	wantBodies := map[int][]byte{
		0: []byte("PCV3 authenticated archive fixture\n"),
		2: []byte("Extraction is admitted only after whole-volume authentication.\n"),
	}
	for index := range session.EntryCount() {
		if step := session.Attempt(index); step == nil || step.Kind() != NativeArchiveSAFStepAttempted {
			t.Fatalf("attempt %d = %#v", index, step)
		}
		if session.Entry(index).IsDirectory() {
			if step := session.AckDirectory(index); step == nil || step.Kind() != NativeArchiveSAFStepReady {
				t.Fatalf("directory %d = %#v", index, step)
			}
			continue
		}
		destination, err := os.CreateTemp(t.TempDir(), "prepared-saf-*")
		if err != nil {
			t.Fatal(err)
		}
		path := destination.Name()
		if step := session.Write(index, destination); step == nil || step.Kind() != NativeArchiveSAFStepReady {
			t.Fatalf("completed preparation cancellation poisoned write %d: %#v", index, step)
		}
		if _, err := destination.Stat(); err == nil {
			t.Fatal("session did not close its provider descriptor")
		}
		body, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(body, wantBodies[index]) {
			t.Fatalf("payload %d = %q, error %v; want frozen plaintext", index, body, err)
		}
	}
	result := session.Finish()
	if result == nil || result.State() != fileops.UnpackStatePublishedDurabilityUncertain ||
		!result.AttemptedEver() || result.CleanupIncomplete() || budget.CurrentBytes() != 0 {
		t.Fatalf("finished session = %#v, live charge %d", result, budget.CurrentBytes())
	}
	assertNativeArchiveStage(t, parent, target, 0)
	after, err := os.Stat(originalPath)
	if err != nil || !os.SameFile(originalInfo, after) || !bytes.Equal(original, readNormalFixtureArtifact(t, fixture.Volume)) {
		t.Fatal("SAF export changed the original frozen volume")
	}
}

type blockedArchiveSAFContext struct {
	context.Context
	checks  int
	entered chan struct{}
	proceed chan struct{}
}

func (ctx *blockedArchiveSAFContext) Err() error {
	ctx.checks++
	if ctx.checks == 5 {
		close(ctx.entered)
		<-ctx.proceed
	}
	return ctx.Context.Err()
}

func TestArchiveSAFActualPreparationCancellationDuringMetadataScan(t *testing.T) {
	entries := make([]archiveSAFZIPEntry, 1024)
	for i := range entries {
		entries[i] = archiveSAFZIPEntry{name: fmt.Sprintf("f%05d", i)}
	}
	handoff, parent, target := newArchiveSAFHandoffFromZIP(t, buildArchiveSAFZIP(t, entries), false)
	base, cancel := context.WithCancel(context.Background())
	ctx := &blockedArchiveSAFContext{Context: base, entered: make(chan struct{}), proceed: make(chan struct{})}
	result := make(chan *NativeArchiveSAFBegin, 1)
	go func() { result <- handoff.BeginSAFWithContext(ctx) }()
	<-ctx.entered
	cancel()
	close(ctx.proceed)
	begin := <-result
	if begin.Kind() != NativeArchiveSAFBeginTerminal || begin.Session() != nil || begin.Result().State() != fileops.UnpackStateNotPublished || begin.Result().CleanupIncomplete() {
		t.Fatal("cancelled actual metadata scan retained authority or leaked stage")
	}
	classification, ok := any(begin.Result()).(interface{ Cancelled() bool })
	if !ok || !classification.Cancelled() {
		t.Fatal("cancelled preparation lost typed cancellation outcome")
	}
	assertNativeArchiveStage(t, parent, target, 0)
}

func TestArchiveSAFSharedPathsAboveFormerAggregateRetainCombinedHostAllowance(t *testing.T) {
	prefix := strings.Repeat(strings.Repeat("d", 239)+"/", 16)
	entries := make([]archiveSAFZIPEntry, 4_400)
	for i := range entries {
		entries[i] = archiveSAFZIPEntry{name: prefix + fmt.Sprintf("file%028d", i)}
	}
	if len(entries[0].name)*len(entries) <= 16<<20 {
		t.Fatal("fixture does not cross former aggregate-path gate")
	}
	handoff, parent, target := newArchiveSAFHandoffFromZIP(t, buildArchiveSAFZIP(t, entries), false)
	begin := handoff.BeginSAF()
	if begin.Kind() != NativeArchiveSAFBeginSession {
		t.Fatalf("affordable shared paths refused: %#v", begin)
	}
	session := begin.Session()
	defer session.Abort()
	if session.EntryCount() != 4_416 || session.Entry(16).ParentIndex() != 15 || session.Entry(4_415).Name() != "file0000000000000000000000004399" {
		t.Fatal("shared parent ordering or final component changed")
	}
	// Independently bounded Kotlin model: 4416 nodes, 16 directory components
	// of 239 bytes, and 4400 file components of 32 bytes, plus the 8 MiB reserve.
	hostNeed := int64(8<<20) + 4_416*768 + 6*(16*239+4_400*32)
	if session.HostMemoryBudgetBytes() < hostNeed {
		t.Fatalf("native metadata leaves %d, host manifest requires %d", session.HostMemoryBudgetBytes(), hostNeed)
	}
	session.Abort()
	assertNativeArchiveStage(t, parent, target, 0)
}
