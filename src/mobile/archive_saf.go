package mobile

import (
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/pcv3publication"
	"context"
	"io"
	"os"
	"sync"
)

const (
	pcv3ArchiveSAFExpired  = "expired"
	pcv3ArchiveSAFSession  = "session"
	pcv3ArchiveSAFTerminal = "terminal"
)

type pcv3ArchiveSAFCoreEntry struct {
	name        string
	parentIndex int
	directory   bool
	size        int64
}

type pcv3ArchiveSAFCoreStep struct {
	kind      string
	nextIndex int
}

type pcv3ArchiveSAFCoreSession interface {
	EntryCount() int
	Entry(int) (pcv3ArchiveSAFCoreEntry, bool)
	ConfirmReceiptPersisted() pcv3ArchiveSAFCoreStep
	Attempt(int) pcv3ArchiveSAFCoreStep
	AckDirectory(int) pcv3ArchiveSAFCoreStep
	Write(int, io.WriteCloser) pcv3ArchiveSAFCoreStep
	Cancel() pcv3ArchiveSAFCoreStep
	Finish() pcv3operation.Presentation
	Abort() pcv3operation.Presentation
}

type pcv3ArchiveSAFCoreBegin struct {
	kind         string
	session      pcv3ArchiveSAFCoreSession
	presentation pcv3operation.Presentation
}

type pcv3ArchiveSAFAction interface {
	beginSAF() pcv3ArchiveSAFCoreBegin
}

type nativePCV3ArchiveSAFSession struct {
	session *pcv3operation.ArchiveSAFSession
	arm     *pcv3operation.ArchiveSAFReceiptArm
}

func (action *nativePCV3ArchiveAction) beginSAF() pcv3ArchiveSAFCoreBegin {
	return action.beginSAFWithContext(context.Background())
}

func (action *nativePCV3ArchiveAction) beginSAFWithContext(ctx context.Context) pcv3ArchiveSAFCoreBegin {
	if action == nil || action.followUp == nil {
		return pcv3ArchiveSAFCoreBegin{kind: pcv3ArchiveSAFTerminal, presentation: pcv3ArchiveSAFFailurePresentation()}
	}
	begin := action.followUp.BeginSAFWithContext(ctx)
	if begin == nil {
		return pcv3ArchiveSAFCoreBegin{kind: pcv3ArchiveSAFTerminal, presentation: pcv3ArchiveSAFFailurePresentation()}
	}
	switch begin.Kind() {
	case pcv3operation.ArchiveSAFBeginExpired:
		return pcv3ArchiveSAFCoreBegin{kind: pcv3ArchiveSAFExpired}
	case pcv3operation.ArchiveSAFBeginTerminal:
		return pcv3ArchiveSAFCoreBegin{
			kind:         pcv3ArchiveSAFTerminal,
			presentation: pcv3ArchiveSAFResultPresentation(begin.Result()),
		}
	case pcv3operation.ArchiveSAFBeginSession:
		session := begin.Session()
		arm := begin.ReceiptArm()
		if session == nil || arm == nil {
			if session != nil {
				_ = session.Abort()
			}
			return pcv3ArchiveSAFCoreBegin{kind: pcv3ArchiveSAFTerminal, presentation: pcv3ArchiveSAFFailurePresentation()}
		}
		return pcv3ArchiveSAFCoreBegin{
			kind: pcv3ArchiveSAFSession,
			session: &nativePCV3ArchiveSAFSession{
				session: session,
				arm:     arm,
			},
		}
	default:
		return pcv3ArchiveSAFCoreBegin{kind: pcv3ArchiveSAFTerminal, presentation: pcv3ArchiveSAFFailurePresentation()}
	}
}

func (session *nativePCV3ArchiveSAFSession) EntryCount() int {
	if session == nil || session.session == nil {
		return 0
	}
	return session.session.EntryCount()
}

func (session *nativePCV3ArchiveSAFSession) Entry(index int) (pcv3ArchiveSAFCoreEntry, bool) {
	if session == nil || session.session == nil {
		return pcv3ArchiveSAFCoreEntry{}, false
	}
	entry := session.session.Entry(index)
	if entry == nil {
		return pcv3ArchiveSAFCoreEntry{}, false
	}
	return pcv3ArchiveSAFCoreEntry{
		name:        entry.Name(),
		parentIndex: entry.ParentIndex(),
		directory:   entry.IsDirectory(),
		size:        entry.Size(),
	}, true
}

func (session *nativePCV3ArchiveSAFSession) ConfirmReceiptPersisted() pcv3ArchiveSAFCoreStep {
	if session == nil || session.session == nil || session.arm == nil {
		return rejectedPCV3ArchiveSAFCoreStep()
	}
	return pcv3ArchiveSAFCoreStepFromNative(
		session.session.ConfirmReceiptPersisted(session.arm),
	)
}

func (session *nativePCV3ArchiveSAFSession) Attempt(index int) pcv3ArchiveSAFCoreStep {
	if session == nil || session.session == nil {
		return rejectedPCV3ArchiveSAFCoreStep()
	}
	return pcv3ArchiveSAFCoreStepFromNative(session.session.Attempt(index))
}

func (session *nativePCV3ArchiveSAFSession) AckDirectory(index int) pcv3ArchiveSAFCoreStep {
	if session == nil || session.session == nil {
		return rejectedPCV3ArchiveSAFCoreStep()
	}
	return pcv3ArchiveSAFCoreStepFromNative(session.session.AckDirectory(index))
}

func (session *nativePCV3ArchiveSAFSession) Write(
	index int,
	destination io.WriteCloser,
) pcv3ArchiveSAFCoreStep {
	if session == nil || session.session == nil {
		if destination != nil {
			_ = destination.Close()
		}
		return rejectedPCV3ArchiveSAFCoreStep()
	}
	return pcv3ArchiveSAFCoreStepFromNative(session.session.Write(index, destination))
}

func (session *nativePCV3ArchiveSAFSession) Cancel() pcv3ArchiveSAFCoreStep {
	if session == nil || session.session == nil {
		return rejectedPCV3ArchiveSAFCoreStep()
	}
	return pcv3ArchiveSAFCoreStepFromNative(session.session.Cancel())
}

func (session *nativePCV3ArchiveSAFSession) Finish() pcv3operation.Presentation {
	if session == nil || session.session == nil {
		return pcv3ArchiveSAFFailurePresentation()
	}
	return pcv3ArchiveSAFResultPresentation(session.session.Finish())
}

func (session *nativePCV3ArchiveSAFSession) Abort() pcv3operation.Presentation {
	if session == nil || session.session == nil {
		return pcv3ArchiveSAFFailurePresentation()
	}
	return pcv3ArchiveSAFResultPresentation(session.session.Abort())
}

func pcv3ArchiveSAFCoreStepFromNative(step *pcv3operation.ArchiveSAFStep) pcv3ArchiveSAFCoreStep {
	if step == nil {
		return rejectedPCV3ArchiveSAFCoreStep()
	}
	return pcv3ArchiveSAFCoreStep{kind: string(step.Kind()), nextIndex: step.NextIndex()}
}

func rejectedPCV3ArchiveSAFCoreStep() pcv3ArchiveSAFCoreStep {
	return pcv3ArchiveSAFCoreStep{kind: string(pcv3operation.ArchiveSAFStepRejected), nextIndex: -1}
}

func poisonedPCV3ArchiveSAFCoreStep() pcv3ArchiveSAFCoreStep {
	return pcv3ArchiveSAFCoreStep{kind: string(pcv3operation.ArchiveSAFStepPoisoned), nextIndex: -1}
}

func pcv3ArchiveSAFResultPresentation(result *pcv3operation.Result) pcv3operation.Presentation {
	if result == nil {
		return pcv3ArchiveSAFFailurePresentation()
	}
	return result.Presentation()
}

// PCV3ArchiveBegin closes the copied archive-consumer race. It contains one
// session, one terminal snapshot, or the authority-free expired variant.
type PCV3ArchiveBegin struct {
	kind     string
	code     string
	session  *PCV3ArchiveSession
	snapshot *PCV3Snapshot
}

func (begin *PCV3ArchiveBegin) Kind() string {
	if begin == nil {
		return pcv3ArchiveSAFExpired
	}
	return begin.kind
}

func (begin *PCV3ArchiveBegin) Code() string {
	if begin == nil {
		return pcv3ArchiveSAFExpired
	}
	return begin.code
}

func (begin *PCV3ArchiveBegin) Session() *PCV3ArchiveSession {
	if begin == nil || begin.kind != pcv3ArchiveSAFSession {
		return nil
	}
	return begin.session
}

func (begin *PCV3ArchiveBegin) Snapshot() *PCV3Snapshot {
	if begin == nil || begin.kind == pcv3ArchiveSAFExpired {
		return nil
	}
	return begin.snapshot
}

// PCV3ArchiveEntry is one immutable, bounded manifest entry. Name is its
// canonical leaf component; it is never a source filesystem path.
type PCV3ArchiveEntry struct {
	name        string
	parentIndex int
	directory   bool
	size        int64
}

func (entry *PCV3ArchiveEntry) Name() string {
	if entry == nil {
		return ""
	}
	return entry.name
}

func (entry *PCV3ArchiveEntry) ParentIndex() int {
	if entry == nil {
		return -1
	}
	return entry.parentIndex
}

func (entry *PCV3ArchiveEntry) IsDirectory() bool {
	return entry != nil && entry.directory
}

func (entry *PCV3ArchiveEntry) Size() int64 {
	if entry == nil {
		return 0
	}
	return entry.size
}

// PCV3ArchiveStep is the closed result of one session transition.
type PCV3ArchiveStep struct {
	kind      string
	nextIndex int
}

func (step *PCV3ArchiveStep) Kind() string {
	if step == nil {
		return string(pcv3operation.ArchiveSAFStepRejected)
	}
	return step.kind
}

func (step *PCV3ArchiveStep) NextIndex() int {
	if step == nil {
		return -1
	}
	return step.nextIndex
}

type pcv3ArchiveSAFSessionState struct {
	mu sync.Mutex

	operation      *PCV3Operation
	core           pcv3ArchiveSAFCoreSession
	activeSnapshot *PCV3Snapshot
	activeReceipt  string
	confirmed      bool

	completing     bool
	sealed         bool
	pendingCalls   int
	pendingSettled chan struct{}
	settled        chan struct{}
	terminal       *PCV3Snapshot
}

// PCV3ArchiveSession copies share one native transition authority, one exact
// receipt confirmation, and one canonical terminal snapshot.
type PCV3ArchiveSession struct{ state *pcv3ArchiveSAFSessionState }

func (archive *PCV3Archive) BeginSAF() (result *PCV3ArchiveBegin) {
	state, action := archive.consume()
	if state == nil || action == nil {
		return expiredPCV3ArchiveBegin()
	}
	safAction, ok := action.(pcv3ArchiveSAFAction)
	if !ok {
		closed, cleanupIncomplete := closePCV3ArchiveAction(action)
		presentation := archiveFailurePCV3Presentation(closed)
		if cleanupIncomplete {
			presentation = pcv3ArchiveSAFFailurePresentation()
		}
		return terminalPCV3ArchiveBegin(state.operation, presentation)
	}

	base := pcv3operation.WithAndroidResourceSession(context.Background(), state.operation.resourceSession)
	ctx, cancel := context.WithCancel(base)
	state.mu.Lock()
	state.preparationCancel = cancel
	if state.preparationCancelled {
		cancel()
	}
	state.mu.Unlock()
	defer func() {
		state.mu.Lock()
		state.preparationCancel = nil
		state.mu.Unlock()
		cancel()
	}()
	coreBegin, panicked := callPCV3ArchiveSAFBegin(ctx, safAction)
	if panicked {
		closed, cleanupIncomplete := closePCV3ArchiveAction(action)
		presentation := archiveFailurePCV3Presentation(closed)
		if cleanupIncomplete {
			presentation = pcv3ArchiveSAFFailurePresentation()
		}
		return terminalPCV3ArchiveBegin(state.operation, presentation)
	}
	if ctx.Err() != nil && coreBegin.session != nil {
		presentation := callPCV3ArchiveSAFTerminal(coreBegin.session, true)
		return terminalPCV3ArchiveBegin(state.operation, presentation)
	}
	switch coreBegin.kind {
	case pcv3ArchiveSAFTerminal:
		if coreBegin.session != nil {
			presentation := callPCV3ArchiveSAFTerminal(coreBegin.session, true)
			return terminalPCV3ArchiveBegin(state.operation, presentation)
		}
		return terminalPCV3ArchiveBegin(state.operation, coreBegin.presentation)
	case pcv3ArchiveSAFSession:
		if coreBegin.session == nil {
			return malformedPCV3ArchiveSAFBegin(state.operation, action, nil)
		}
	default:
		return malformedPCV3ArchiveSAFBegin(state.operation, action, coreBegin.session)
	}

	receiptID := pcv3ReceiptIDGenerator()
	activePresentation := pcv3ArchiveSAFActivePresentation()
	stateCopy, _ := copyPCV3State(state.operation)
	activeSnapshot := newPCV3Snapshot(
		activePresentation,
		stateCopy.status,
		state.operation.id,
		receiptID,
		stateCopy.authenticatedComment,
	)
	activeReceipt := activeSnapshot.RestoredReceipt()
	if activeReceipt == "" {
		presentation := callPCV3ArchiveSAFTerminal(coreBegin.session, true)
		return terminalPCV3ArchiveBegin(state.operation, presentation)
	}
	sessionState := &pcv3ArchiveSAFSessionState{
		operation:      state.operation,
		core:           coreBegin.session,
		activeSnapshot: activeSnapshot,
		activeReceipt:  activeReceipt,
	}
	return &PCV3ArchiveBegin{
		kind:     pcv3ArchiveSAFSession,
		session:  &PCV3ArchiveSession{state: sessionState},
		snapshot: activeSnapshot,
	}
}

func callPCV3ArchiveSAFBegin(ctx context.Context, action pcv3ArchiveSAFAction) (
	begin pcv3ArchiveSAFCoreBegin,
	panicked bool,
) {
	defer func() {
		if recover() != nil {
			begin = pcv3ArchiveSAFCoreBegin{}
			panicked = true
		}
	}()
	if cancellable, ok := action.(interface {
		beginSAFWithContext(context.Context) pcv3ArchiveSAFCoreBegin
	}); ok {
		return cancellable.beginSAFWithContext(ctx), false
	}
	return action.beginSAF(), false
}

func malformedPCV3ArchiveSAFBegin(
	operation *PCV3Operation,
	action pcv3ArchiveAction,
	preparedSession pcv3ArchiveSAFCoreSession,
) *PCV3ArchiveBegin {
	if preparedSession != nil {
		presentation := callPCV3ArchiveSAFTerminal(preparedSession, true)
		return terminalPCV3ArchiveBegin(operation, presentation)
	}
	_, _ = closePCV3ArchiveAction(action)
	return terminalPCV3ArchiveBegin(operation, pcv3ArchiveSAFFailurePresentation())
}

func expiredPCV3ArchiveBegin() *PCV3ArchiveBegin {
	return &PCV3ArchiveBegin{kind: pcv3ArchiveSAFExpired, code: pcv3ArchiveSAFExpired}
}

func terminalPCV3ArchiveBegin(
	operation *PCV3Operation,
	presentation pcv3operation.Presentation,
) *PCV3ArchiveBegin {
	if presentation.CompletionClass() == pcv3operation.CompletionUnknown || presentation.ArchivePending() {
		presentation = pcv3ArchiveSAFFailurePresentation()
	}
	snapshot := replacePCV3ArchivePresentation(operation, presentation)
	return &PCV3ArchiveBegin{
		kind:     pcv3ArchiveSAFTerminal,
		code:     snapshot.Code(),
		snapshot: snapshot,
	}
}

// HostMemoryBudgetBytes is native policy, never a host-selected allowance.
func (session *PCV3ArchiveSession) HostMemoryBudgetBytes() int64 {
	core := session.core()
	if budget, ok := core.(interface{ HostMemoryBudgetBytes() int64 }); ok {
		return budget.HostMemoryBudgetBytes()
	}
	return 0
}

func (session *nativePCV3ArchiveSAFSession) HostMemoryBudgetBytes() int64 {
	if session == nil || session.session == nil {
		return 0
	}
	return session.session.HostMemoryBudgetBytes()
}

func (session *PCV3ArchiveSession) EntryCount() int {
	core := session.core()
	if core == nil {
		return 0
	}
	count, panicked := callPCV3ArchiveSAFEntryCount(core)
	if panicked || count < 0 {
		return 0
	}
	return count
}

func (session *PCV3ArchiveSession) Entry(index int) *PCV3ArchiveEntry {
	if index < 0 {
		return nil
	}
	core := session.core()
	if core == nil {
		return nil
	}
	entry, ok, panicked := callPCV3ArchiveSAFEntry(core, index)
	if panicked || !ok || entry.name == "" || entry.parentIndex < -1 || entry.size < 0 {
		return nil
	}
	return &PCV3ArchiveEntry{
		name:        entry.name,
		parentIndex: entry.parentIndex,
		directory:   entry.directory,
		size:        entry.size,
	}
}

func (session *PCV3ArchiveSession) ConfirmCrashReceiptPersisted(
	exactReceipt string,
) *PCV3ArchiveStep {
	if session == nil || session.state == nil {
		return rejectedPCV3ArchiveStep()
	}
	state := session.state
	state.mu.Lock()
	if state.terminal != nil || state.sealed || state.core == nil || state.confirmed ||
		exactReceipt == "" || len(exactReceipt) > maxPCV3ReceiptBytes ||
		exactReceipt != state.activeReceipt {
		state.mu.Unlock()
		return rejectedPCV3ArchiveStep()
	}
	state.confirmed = true
	core := state.core
	state.startPendingCallLocked()
	state.mu.Unlock()
	defer state.finishPendingCall()
	return session.callStep(core, func() pcv3ArchiveSAFCoreStep {
		return core.ConfirmReceiptPersisted()
	})
}

func (session *PCV3ArchiveSession) Attempt(index int) *PCV3ArchiveStep {
	core, done := session.beginCoreCall()
	if core == nil {
		return rejectedPCV3ArchiveStep()
	}
	defer done()
	return session.callStep(core, func() pcv3ArchiveSAFCoreStep { return core.Attempt(index) })
}

func (session *PCV3ArchiveSession) AckDirectory(index int) *PCV3ArchiveStep {
	core, done := session.beginCoreCall()
	if core == nil {
		return rejectedPCV3ArchiveStep()
	}
	defer done()
	return session.callStep(core, func() pcv3ArchiveSAFCoreStep { return core.AckDirectory(index) })
}

func (session *PCV3ArchiveSession) WriteFD(index int, destinationFD int64) *PCV3ArchiveStep {
	core, done := session.beginCoreCall()
	if done != nil {
		defer done()
	}
	destination := adoptPCV3ArchiveSAFDestination(destinationFD)
	if destination != nil {
		defer func() { _ = destination.Close() }()
	}
	if core == nil {
		return rejectedPCV3ArchiveStep()
	}
	if destination == nil || !destination.providerTypeAllowed() {
		return session.callStep(core, func() pcv3ArchiveSAFCoreStep {
			return core.Write(index, nil)
		})
	}
	return session.callStep(core, func() pcv3ArchiveSAFCoreStep {
		return core.Write(index, destination)
	})
}

func (session *PCV3ArchiveSession) Cancel() *PCV3ArchiveStep {
	core, done := session.beginCoreCall()
	if core == nil {
		return rejectedPCV3ArchiveStep()
	}
	defer done()
	return session.callStep(core, core.Cancel)
}

func (session *PCV3ArchiveSession) Finish() *PCV3Snapshot {
	return session.complete(false)
}

func (session *PCV3ArchiveSession) Abort() *PCV3Snapshot {
	return session.complete(true)
}

func (session *PCV3ArchiveSession) core() pcv3ArchiveSAFCoreSession {
	if session == nil || session.state == nil {
		return nil
	}
	session.state.mu.Lock()
	defer session.state.mu.Unlock()
	if session.state.terminal != nil {
		return nil
	}
	return session.state.core
}

func (session *PCV3ArchiveSession) beginCoreCall() (
	pcv3ArchiveSAFCoreSession,
	func(),
) {
	if session == nil || session.state == nil {
		return nil, nil
	}
	state := session.state
	state.mu.Lock()
	if state.terminal != nil || state.sealed || state.core == nil {
		state.mu.Unlock()
		return nil, nil
	}
	core := state.core
	state.startPendingCallLocked()
	state.mu.Unlock()
	return core, state.finishPendingCall
}

func (state *pcv3ArchiveSAFSessionState) startPendingCallLocked() {
	if state.pendingCalls == 0 {
		state.pendingSettled = make(chan struct{})
	}
	state.pendingCalls++
}

func (state *pcv3ArchiveSAFSessionState) finishPendingCall() {
	state.mu.Lock()
	if state.pendingCalls > 0 {
		state.pendingCalls--
		if state.pendingCalls == 0 {
			close(state.pendingSettled)
			state.pendingSettled = nil
		}
	}
	state.mu.Unlock()
}

func (session *PCV3ArchiveSession) callStep(
	core pcv3ArchiveSAFCoreSession,
	call func() pcv3ArchiveSAFCoreStep,
) *PCV3ArchiveStep {
	step, panicked := callPCV3ArchiveSAFStep(call)
	if panicked {
		_, _ = callPCV3ArchiveSAFStep(core.Cancel)
		step = poisonedPCV3ArchiveSAFCoreStep()
	}
	return &PCV3ArchiveStep{kind: step.kind, nextIndex: step.nextIndex}
}

func callPCV3ArchiveSAFStep(call func() pcv3ArchiveSAFCoreStep) (
	step pcv3ArchiveSAFCoreStep,
	panicked bool,
) {
	defer func() {
		if recover() != nil {
			step = poisonedPCV3ArchiveSAFCoreStep()
			panicked = true
		}
	}()
	if call == nil {
		return rejectedPCV3ArchiveSAFCoreStep(), false
	}
	return call(), false
}

func (session *PCV3ArchiveSession) complete(abort bool) *PCV3Snapshot {
	if session == nil || session.state == nil {
		return newPCV3Snapshot(pcv3operation.Presentation{}, pcv3operation.Status{}, "", "", "")
	}
	state := session.state
	state.mu.Lock()
	if state.terminal != nil {
		terminal := state.terminal
		state.mu.Unlock()
		return terminal
	}
	if state.completing {
		settled := state.settled
		state.mu.Unlock()
		<-settled
		state.mu.Lock()
		terminal := state.terminal
		state.mu.Unlock()
		return terminal
	}
	state.completing = true
	state.sealed = true
	state.settled = make(chan struct{})
	settled := state.settled
	core := state.core
	operation := state.operation
	activeSnapshot := state.activeSnapshot
	activeReceipt := state.activeReceipt
	for state.pendingCalls != 0 {
		pendingSettled := state.pendingSettled
		state.mu.Unlock()
		<-pendingSettled
		state.mu.Lock()
	}
	state.mu.Unlock()

	presentation := callPCV3ArchiveSAFTerminal(core, abort)
	terminal := replacePCV3ArchiveSAFPresentation(
		operation,
		presentation,
		activeSnapshot,
		activeReceipt,
	)

	state.mu.Lock()
	state.terminal = terminal
	state.core = nil
	state.completing = false
	close(settled)
	state.mu.Unlock()
	return terminal
}

func callPCV3ArchiveSAFTerminal(
	core pcv3ArchiveSAFCoreSession,
	abort bool,
) (presentation pcv3operation.Presentation) {
	presentation = pcv3ArchiveSAFFailurePresentation()
	if core == nil {
		return presentation
	}
	panicked := false
	func() {
		defer func() {
			if recover() != nil {
				panicked = true
			}
		}()
		if abort {
			presentation = core.Abort()
		} else {
			presentation = core.Finish()
		}
	}()
	if panicked && !abort {
		func() {
			defer func() { _ = recover() }()
			presentation = core.Abort()
		}()
	}
	if panicked || presentation.CompletionClass() == pcv3operation.CompletionUnknown || presentation.ArchivePending() {
		return pcv3ArchiveSAFFailurePresentation()
	}
	return presentation
}

func callPCV3ArchiveSAFEntryCount(core pcv3ArchiveSAFCoreSession) (
	count int,
	panicked bool,
) {
	defer func() {
		if recover() != nil {
			count = 0
			panicked = true
		}
	}()
	return core.EntryCount(), false
}

func callPCV3ArchiveSAFEntry(
	core pcv3ArchiveSAFCoreSession,
	index int,
) (entry pcv3ArchiveSAFCoreEntry, ok bool, panicked bool) {
	defer func() {
		if recover() != nil {
			entry = pcv3ArchiveSAFCoreEntry{}
			ok = false
			panicked = true
		}
	}()
	entry, ok = core.Entry(index)
	return entry, ok, false
}

type pcv3ArchiveSAFDestination struct {
	file                *os.File
	nonBlockingPrepared bool
	close               sync.Once
	closeErr            error
}

func adoptPCV3ArchiveSAFDestination(destinationFD int64) *pcv3ArchiveSAFDestination {
	if destinationFD < 0 || destinationFD > maxPCV3OutputFD {
		return nil
	}
	nonBlockingPrepared := preparePCV3ArchiveSAFNonblocking(destinationFD)
	file := os.NewFile(uintptr(destinationFD), "pcv3-archive-saf")
	if file == nil {
		return nil
	}
	return &pcv3ArchiveSAFDestination{
		file:                file,
		nonBlockingPrepared: nonBlockingPrepared,
	}
}

func (destination *pcv3ArchiveSAFDestination) Write(data []byte) (int, error) {
	if destination == nil || destination.file == nil {
		return 0, os.ErrInvalid
	}
	return destination.file.Write(data)
}

func (destination *pcv3ArchiveSAFDestination) Close() error {
	if destination == nil {
		return nil
	}
	destination.close.Do(func() {
		if destination.file != nil {
			destination.closeErr = destination.file.Close()
		}
	})
	return destination.closeErr
}

func (destination *pcv3ArchiveSAFDestination) providerTypeAllowed() bool {
	if destination == nil || destination.file == nil {
		return false
	}
	info, err := destination.file.Stat()
	if err != nil || info == nil {
		return false
	}
	switch info.Mode() & os.ModeType {
	case 0:
		return true
	case os.ModeNamedPipe, os.ModeSocket:
		return destination.nonBlockingPrepared
	default:
		return false
	}
}

func rejectedPCV3ArchiveStep() *PCV3ArchiveStep {
	step := rejectedPCV3ArchiveSAFCoreStep()
	return &PCV3ArchiveStep{kind: step.kind, nextIndex: step.nextIndex}
}

func pcv3ArchiveSAFActivePresentation() pcv3operation.Presentation {
	presentation, err := pcv3operation.NewPresentation(pcv3operation.PresentationSpec{
		Outcome:              pcv3operation.OutcomeSuccess,
		Stage:                pcv3operation.StageNone,
		Code:                 pcv3operation.CodeSuccess,
		PublicationAttempted: true,
		PublicationState:     pcv3publication.StatePublicationIndeterminate,
		PublicationStage:     pcv3operation.StageOutputPublication,
		PublicationCode:      pcv3publication.CodePublicationIndeterminate,
	})
	if err != nil {
		return pcv3operation.Presentation{}
	}
	return presentation
}

func pcv3ArchiveSAFFailurePresentation() pcv3operation.Presentation {
	presentation, err := pcv3operation.NewPresentation(pcv3operation.PresentationSpec{
		Outcome:              pcv3operation.OutcomeSuccess,
		Stage:                pcv3operation.StageNone,
		Code:                 pcv3operation.CodeSuccess,
		PublicationAttempted: true,
		PublicationState:     pcv3publication.StatePublicationIndeterminate,
		PublicationStage:     pcv3operation.StageOutputPublication,
		PublicationCode:      pcv3publication.CodePublicationIndeterminate,
		Warnings:             []pcv3operation.Warning{pcv3operation.WarningCleanupIncomplete},
		Diagnostic:           pcv3operation.DiagnosticCoreFailure,
	})
	if err != nil {
		return fallbackPCV3Presentation(pcv3operation.DiagnosticCoreFailure)
	}
	return presentation
}
