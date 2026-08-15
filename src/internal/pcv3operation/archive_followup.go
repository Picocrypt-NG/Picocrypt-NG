package pcv3operation

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3"
	"Picocrypt-NG/internal/pcv3publication"
	"io"
	"os"
	"sync"
)

type nativeArchiveFollowUpState struct {
	mu      sync.Mutex
	active  bool
	handoff *pcv3.NativeArchiveHandoff
}

func newArchiveFollowUp(handoff *pcv3.NativeArchiveHandoff) *ArchiveFollowUp {
	if handoff == nil || !handoff.Live() {
		return nil
	}
	return &ArchiveFollowUp{state: &nativeArchiveFollowUpState{
		active: true, handoff: handoff,
	}}
}

func (state *nativeArchiveFollowUpState) live() bool {
	if state == nil {
		return false
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.active && state.handoff != nil && state.handoff.Live()
}

func (state *nativeArchiveFollowUpState) extract(root *os.Root) *Result {
	handoff := state.consume()
	if handoff == nil {
		return archiveNoOutput(DiagnosticInvalidRequest, closeExtractionRoot(root))
	}
	return resultFromArchiveExtraction(handoff.Extract(root))
}

func (state *nativeArchiveFollowUpState) close() *Result {
	handoff := state.consume()
	if handoff == nil {
		return archiveNoOutput(DiagnosticInvalidRequest, false)
	}
	return archiveNoOutput(DiagnosticNone, handoff.Close())
}

func (state *nativeArchiveFollowUpState) beginSAF() *ArchiveSAFBegin {
	handoff := state.consume()
	if handoff == nil {
		return &ArchiveSAFBegin{kind: ArchiveSAFBeginExpired}
	}
	return archiveSAFBeginFromNative(handoff.BeginSAF())
}

func (state *nativeArchiveFollowUpState) consume() *pcv3.NativeArchiveHandoff {
	if state == nil {
		return nil
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.active || state.handoff == nil {
		return nil
	}
	state.active = false
	handoff := state.handoff
	state.handoff = nil
	return handoff
}

// Extract consumes the follow-up before effects and takes ownership of the
// caller-opened, pre-existing extraction root.
func (followUp *ArchiveFollowUp) Extract(root *os.Root) *Result {
	if followUp == nil || followUp.state == nil {
		return archiveNoOutput(DiagnosticInvalidRequest, closeExtractionRoot(root))
	}
	return followUp.state.extract(root)
}

// Close consumes the follow-up without publishing or extracting plaintext.
func (followUp *ArchiveFollowUp) Close() *Result {
	if followUp == nil || followUp.state == nil {
		return archiveNoOutput(DiagnosticInvalidRequest, false)
	}
	return followUp.state.close()
}

// ArchiveSAFBeginKind closes the one-shot archive consumer race. A begin value
// contains exactly one live session, one terminal result, or neither authority
// when another copied follow-up won.
type ArchiveSAFBeginKind string

const (
	ArchiveSAFBeginExpired  ArchiveSAFBeginKind = "expired"
	ArchiveSAFBeginSession  ArchiveSAFBeginKind = "session"
	ArchiveSAFBeginTerminal ArchiveSAFBeginKind = "terminal"
)

type ArchiveSAFBegin struct {
	kind    ArchiveSAFBeginKind
	session *ArchiveSAFSession
	arm     *ArchiveSAFReceiptArm
	result  *Result
}

func (begin *ArchiveSAFBegin) Kind() ArchiveSAFBeginKind {
	if begin == nil {
		return ""
	}
	return begin.kind
}

func (begin *ArchiveSAFBegin) Session() *ArchiveSAFSession {
	if begin == nil || begin.kind != ArchiveSAFBeginSession {
		return nil
	}
	return begin.session
}

// ReceiptArm is a Go-only, unforgeable capability. The mobile wrapper retains
// it while Kotlin durably stores and byte-compares the exact receipt; no
// receipt body or frontend policy enters the core.
func (begin *ArchiveSAFBegin) ReceiptArm() *ArchiveSAFReceiptArm {
	if begin == nil || begin.kind != ArchiveSAFBeginSession {
		return nil
	}
	return begin.arm
}

func (begin *ArchiveSAFBegin) Result() *Result {
	if begin == nil || begin.kind != ArchiveSAFBeginTerminal {
		return nil
	}
	return begin.result
}

type archiveSAFBeginState interface {
	beginSAF() *ArchiveSAFBegin
}

// BeginSAF consumes the same follow-up as Extract and Close. Implementations
// not backed by the authenticated native handoff return the closed expired
// variant rather than a consumed nil/error gap.
func (followUp *ArchiveFollowUp) BeginSAF() *ArchiveSAFBegin {
	if followUp == nil || followUp.state == nil {
		return &ArchiveSAFBegin{kind: ArchiveSAFBeginExpired}
	}
	state, ok := followUp.state.(archiveSAFBeginState)
	if !ok {
		return &ArchiveSAFBegin{kind: ArchiveSAFBeginExpired}
	}
	begin := state.beginSAF()
	if begin == nil {
		return &ArchiveSAFBegin{
			kind:   ArchiveSAFBeginTerminal,
			result: archiveSAFCoreFailure(true),
		}
	}
	return begin
}

func archiveSAFBeginFromNative(begin *pcv3.NativeArchiveSAFBegin) *ArchiveSAFBegin {
	if begin == nil {
		return &ArchiveSAFBegin{kind: ArchiveSAFBeginTerminal, result: archiveSAFCoreFailure(true)}
	}
	switch begin.Kind() {
	case pcv3.NativeArchiveSAFBeginExpired:
		return &ArchiveSAFBegin{kind: ArchiveSAFBeginExpired}
	case pcv3.NativeArchiveSAFBeginTerminal:
		return &ArchiveSAFBegin{
			kind:   ArchiveSAFBeginTerminal,
			result: resultFromArchiveSAF(begin.Result()),
		}
	case pcv3.NativeArchiveSAFBeginSession:
		nativeSession := begin.Session()
		nativeArm := begin.ReceiptArm()
		if nativeSession == nil || nativeArm == nil {
			if nativeSession != nil {
				_ = nativeSession.Abort()
			}
			return &ArchiveSAFBegin{
				kind:   ArchiveSAFBeginTerminal,
				result: archiveSAFCoreFailure(true),
			}
		}
		state := &archiveSAFSessionState{native: nativeSession}
		return &ArchiveSAFBegin{
			kind:    ArchiveSAFBeginSession,
			session: &ArchiveSAFSession{state: state},
			arm:     &ArchiveSAFReceiptArm{native: nativeArm, state: state},
		}
	default:
		return &ArchiveSAFBegin{kind: ArchiveSAFBeginTerminal, result: archiveSAFCoreFailure(true)}
	}
}

type ArchiveSAFReceiptArm struct {
	native *pcv3.NativeArchiveSAFReceiptArm
	state  *archiveSAFSessionState
}

type ArchiveSAFStepKind string

const (
	ArchiveSAFStepRejected  ArchiveSAFStepKind = "rejected"
	ArchiveSAFStepReady     ArchiveSAFStepKind = "ready"
	ArchiveSAFStepAttempted ArchiveSAFStepKind = "attempted"
	ArchiveSAFStepPoisoned  ArchiveSAFStepKind = "poisoned"
)

type ArchiveSAFStep struct {
	kind      ArchiveSAFStepKind
	nextIndex int
}

func (step *ArchiveSAFStep) Kind() ArchiveSAFStepKind {
	if step == nil {
		return ""
	}
	return step.kind
}

func (step *ArchiveSAFStep) NextIndex() int {
	if step == nil {
		return -1
	}
	return step.nextIndex
}

type ArchiveSAFEntry struct{ native *pcv3.NativeArchiveSAFEntry }

func (entry *ArchiveSAFEntry) Name() string {
	if entry == nil || entry.native == nil {
		return ""
	}
	return entry.native.Name()
}

func (entry *ArchiveSAFEntry) ParentIndex() int {
	if entry == nil || entry.native == nil {
		return -1
	}
	return entry.native.ParentIndex()
}

func (entry *ArchiveSAFEntry) IsDirectory() bool {
	return entry != nil && entry.native != nil && entry.native.IsDirectory()
}

func (entry *ArchiveSAFEntry) Size() int64 {
	if entry == nil || entry.native == nil {
		return 0
	}
	return entry.native.Size()
}

type archiveSAFSessionState struct {
	mu       sync.Mutex
	native   *pcv3.NativeArchiveSAFSession
	terminal *Result
}

// ArchiveSAFSession copies share both native transition authority and the
// canonical mapped terminal Result.
type ArchiveSAFSession struct{ state *archiveSAFSessionState }

func (session *ArchiveSAFSession) EntryCount() int {
	if session == nil || session.state == nil || session.state.native == nil {
		return 0
	}
	return session.state.native.EntryCount()
}

func (session *ArchiveSAFSession) Entry(index int) *ArchiveSAFEntry {
	if session == nil || session.state == nil || session.state.native == nil {
		return nil
	}
	entry := session.state.native.Entry(index)
	if entry == nil {
		return nil
	}
	return &ArchiveSAFEntry{native: entry}
}

func (session *ArchiveSAFSession) ConfirmReceiptPersisted(
	arm *ArchiveSAFReceiptArm,
) *ArchiveSAFStep {
	if session == nil || session.state == nil || session.state.native == nil ||
		arm == nil || arm.state != session.state {
		return &ArchiveSAFStep{kind: ArchiveSAFStepRejected, nextIndex: -1}
	}
	return archiveSAFStepFromNative(
		session.state.native.ConfirmReceiptPersisted(arm.native),
	)
}

func (session *ArchiveSAFSession) Attempt(index int) *ArchiveSAFStep {
	if session == nil || session.state == nil || session.state.native == nil {
		return &ArchiveSAFStep{kind: ArchiveSAFStepRejected, nextIndex: -1}
	}
	return archiveSAFStepFromNative(session.state.native.Attempt(index))
}

func (session *ArchiveSAFSession) AckDirectory(index int) *ArchiveSAFStep {
	if session == nil || session.state == nil || session.state.native == nil {
		return &ArchiveSAFStep{kind: ArchiveSAFStepRejected, nextIndex: -1}
	}
	return archiveSAFStepFromNative(session.state.native.AckDirectory(index))
}

func (session *ArchiveSAFSession) Write(
	index int,
	destination io.WriteCloser,
) *ArchiveSAFStep {
	if session == nil || session.state == nil || session.state.native == nil {
		closeArchiveSAFDestination(destination)
		return &ArchiveSAFStep{kind: ArchiveSAFStepRejected, nextIndex: -1}
	}
	return archiveSAFStepFromNative(session.state.native.Write(index, destination))
}

func closeArchiveSAFDestination(destination io.Closer) {
	if destination == nil {
		return
	}
	defer func() { _ = recover() }()
	_ = destination.Close()
}

func (session *ArchiveSAFSession) Cancel() *ArchiveSAFStep {
	if session == nil || session.state == nil || session.state.native == nil {
		return &ArchiveSAFStep{kind: ArchiveSAFStepRejected, nextIndex: -1}
	}
	return archiveSAFStepFromNative(session.state.native.Cancel())
}

func (session *ArchiveSAFSession) AttemptedEver() bool {
	return session != nil && session.state != nil && session.state.native != nil &&
		session.state.native.AttemptedEver()
}

func (session *ArchiveSAFSession) Finish() *Result {
	if session == nil || session.state == nil || session.state.native == nil {
		return archiveSAFCoreFailure(true)
	}
	return session.state.complete(session.state.native.Finish())
}

func (session *ArchiveSAFSession) Abort() *Result {
	if session == nil || session.state == nil || session.state.native == nil {
		return archiveSAFCoreFailure(true)
	}
	return session.state.complete(session.state.native.Abort())
}

func (state *archiveSAFSessionState) complete(native archiveSAFResult) *Result {
	if state == nil {
		return archiveSAFCoreFailure(true)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.terminal == nil {
		state.terminal = resultFromArchiveSAF(native)
	}
	return state.terminal
}

func archiveSAFStepFromNative(step *pcv3.NativeArchiveSAFStep) *ArchiveSAFStep {
	if step == nil {
		return &ArchiveSAFStep{kind: ArchiveSAFStepRejected, nextIndex: -1}
	}
	kind := ArchiveSAFStepRejected
	switch step.Kind() {
	case pcv3.NativeArchiveSAFStepReady:
		kind = ArchiveSAFStepReady
	case pcv3.NativeArchiveSAFStepAttempted:
		kind = ArchiveSAFStepAttempted
	case pcv3.NativeArchiveSAFStepPoisoned:
		kind = ArchiveSAFStepPoisoned
	}
	return &ArchiveSAFStep{kind: kind, nextIndex: step.NextIndex()}
}

type archiveSAFResult interface {
	State() fileops.UnpackState
	AttemptedEver() bool
	CleanupIncomplete() bool
}

func resultFromArchiveSAF(native archiveSAFResult) *Result {
	if native == nil {
		return archiveSAFCoreFailure(true)
	}
	data := resultData{
		outcome:              pcv3.OutcomeSuccess,
		stage:                pcv3.StageNone,
		code:                 pcv3.CodeSuccess,
		publicationAttempted: true,
	}
	switch native.State() {
	case fileops.UnpackStateNotPublished:
		if native.AttemptedEver() || native.CleanupIncomplete() {
			return archiveSAFCoreFailure(true)
		}
		data.outcome = pcv3.OutcomeOperationFailed
		data.stage = pcv3.StageOutputPublication
		data.code = pcv3.CodeOperationFailed
		data.publicationState = pcv3publication.StateNotPublished
		data.publicationStage = pcv3.StageOutputPublication
		data.publicationCode = pcv3publication.CodeAtomicFailed
	case fileops.UnpackStatePublishedDurabilityUncertain:
		if !native.AttemptedEver() {
			return archiveSAFCoreFailure(true)
		}
		data.publicationState = pcv3publication.StatePublishedDurabilityUncertain
		data.publicationStage = pcv3.StageDirectorySync
		data.publicationCode = pcv3publication.CodeDurabilityUncertain
	case fileops.UnpackStatePublicationIndeterminate:
		data.publicationState = pcv3publication.StatePublicationIndeterminate
		data.publicationStage = pcv3.StageOutputPublication
		data.publicationCode = pcv3publication.CodePublicationIndeterminate
	default:
		return archiveSAFCoreFailure(true)
	}
	result := newResult(data)
	if native.CleanupIncomplete() {
		result.appendWarning(WarningCleanupIncomplete)
	}
	return result
}

func archiveSAFCoreFailure(cleanupIncomplete bool) *Result {
	result := newResult(resultData{
		outcome:              pcv3.OutcomeSuccess,
		stage:                pcv3.StageNone,
		code:                 pcv3.CodeSuccess,
		publicationAttempted: true,
		publicationState:     pcv3publication.StatePublicationIndeterminate,
		publicationStage:     pcv3.StageOutputPublication,
		publicationCode:      pcv3publication.CodePublicationIndeterminate,
		diagnostic:           DiagnosticCoreFailure,
	})
	if cleanupIncomplete {
		result.appendWarning(WarningCleanupIncomplete)
	}
	return result
}

type archiveExtractionResult interface {
	State() fileops.UnpackState
	CleanupIncomplete() bool
}

func resultFromArchiveExtraction(extraction archiveExtractionResult) *Result {
	if extraction == nil {
		return archiveNoOutput(DiagnosticInvalidRequest, false)
	}
	data := resultData{
		outcome:              pcv3.OutcomeSuccess,
		stage:                pcv3.StageNone,
		code:                 pcv3.CodeSuccess,
		publicationAttempted: true,
	}
	switch extraction.State() {
	case fileops.UnpackStateNotPublished:
		data.outcome = pcv3.OutcomeOperationFailed
		data.stage = pcv3.StageOutputPublication
		data.code = pcv3.CodeOperationFailed
		data.publicationState = pcv3publication.StateNotPublished
		data.publicationStage = pcv3.StageOutputPublication
		data.publicationCode = pcv3publication.CodeAtomicFailed
	case fileops.UnpackStatePublishedDurable:
		data.publicationState = pcv3publication.StatePublishedDurable
		data.publicationCode = pcv3publication.CodePublishedDurable
	case fileops.UnpackStatePublishedDurabilityUncertain:
		data.publicationState = pcv3publication.StatePublishedDurabilityUncertain
		data.publicationStage = pcv3.StageDirectorySync
		data.publicationCode = pcv3publication.CodeDurabilityUncertain
	case fileops.UnpackStatePublicationIndeterminate:
		data.publicationState = pcv3publication.StatePublicationIndeterminate
		data.publicationStage = pcv3.StageOutputPublication
		data.publicationCode = pcv3publication.CodePublicationIndeterminate
	default:
		return archiveNoOutput(DiagnosticCoreFailure, extraction.CleanupIncomplete())
	}
	result := newResult(data)
	if extraction.CleanupIncomplete() {
		result.appendWarning(WarningCleanupIncomplete)
	}
	return result
}

func archiveNoOutput(diagnostic Diagnostic, cleanupIncomplete bool) *Result {
	result := newResult(resultData{
		outcome:    pcv3.OutcomeOperationFailed,
		stage:      pcv3.StageOutputPublication,
		code:       pcv3.CodeOperationFailed,
		diagnostic: diagnostic,
	})
	if cleanupIncomplete {
		result.appendWarning(WarningCleanupIncomplete)
	}
	return result
}

func closeExtractionRoot(root *os.Root) bool {
	return root != nil && root.Close() != nil
}
