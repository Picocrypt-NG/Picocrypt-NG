package mobile

import (
	"Picocrypt-NG/internal/pcv3"
	"Picocrypt-NG/internal/pcv3operation"
	"Picocrypt-NG/internal/pcv3publication"
	"Picocrypt-NG/internal/pcv3resource"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	maxPCV3ReceiptBytes        = 4096
	maxPCV3OutputFD            = int64(1<<31 - 1)
	pcv3ReceiptInvalid         = "PCV3_RECEIPT_INVALID"
	pcv3ConsentExpired         = "PCV3_CONSENT_EXPIRED"
	pcv3OperationReleaseDenied = "PCV3_OPERATION_RELEASE_DENIED"
)

// PCV3StartResult is the closed result of attempting to start a PCV3 mobile
// operation. It carries either a fixed bridge code or one Go-owned operation
// handle; it never contains caller input or a recoverable authority token.
type PCV3StartResult struct {
	code      string
	operation *PCV3Operation
}

func newPCV3StartResult(code string, operation *PCV3Operation) *PCV3StartResult {
	return &PCV3StartResult{code: code, operation: operation}
}

func (result *PCV3StartResult) Code() string {
	if result == nil {
		return pcv3BridgeOperationUnavailable
	}
	return result.code
}

func (result *PCV3StartResult) Operation() *PCV3Operation {
	if result == nil {
		return nil
	}
	return result.operation
}

// PCV3Operation is the Go-owned live operation object returned exactly once by
// StartPCV3. ID identifies status only; no exported API reconstructs this
// object or any consent/archive authority from the ID.
type PCV3Operation struct {
	id              string
	generation      uint64
	resourceSession *pcv3resource.AndroidResourceSession
}

func (operation *PCV3Operation) ID() string {
	if operation == nil {
		return ""
	}
	return operation.id
}

func (operation *PCV3Operation) Snapshot() *PCV3Snapshot {
	state, ok := copyPCV3State(operation)
	if !ok {
		return newPCV3Snapshot(pcv3operation.Presentation{}, pcv3operation.Status{}, "", "")
	}
	return newPCV3Snapshot(state.presentation, state.status, operation.id, state.receiptID)
}

func (operation *PCV3Operation) Consent() *PCV3Consent {
	globalProgressMap.mu.RLock()
	defer globalProgressMap.mu.RUnlock()
	state, ok := livePCV3StateLocked(operation)
	if !ok || state.consent == nil || !state.consent.isLive() {
		return nil
	}
	return &PCV3Consent{state: state.consent}
}

func (operation *PCV3Operation) Archive() *PCV3Archive {
	globalProgressMap.mu.RLock()
	defer globalProgressMap.mu.RUnlock()
	state, ok := livePCV3StateLocked(operation)
	if !ok || state.archive == nil || !state.archive.isLive() {
		return nil
	}
	return &PCV3Archive{state: state.archive}
}

// Output returns the one-shot Go-owned retained-output capability only through
// its matching live operation object. It exposes no path, descriptor, or
// recoverable operation lookup.
func (operation *PCV3Operation) Output() *PCV3Output {
	globalProgressMap.mu.RLock()
	defer globalProgressMap.mu.RUnlock()
	state, ok := livePCV3StateLocked(operation)
	if !ok || state.output == nil || !state.output.isLive() {
		return nil
	}
	return &PCV3Output{state: state.output}
}

// ArtifactInspection returns only an already-attached immutable, path-free
// Force-artifact view. It never returns an action or an artifact identity.
func (operation *PCV3Operation) ArtifactInspection() *PCV3ArtifactInspection {
	globalProgressMap.mu.RLock()
	defer globalProgressMap.mu.RUnlock()
	state, ok := livePCV3StateLocked(operation)
	if !ok || !state.terminal {
		return nil
	}
	return state.artifactInspection
}

// PCV3ResourceChallenge is a one-shot transport capability for bounded,
// non-secret Android observations. It exposes no resource-policy terms or
// admission result and cannot be reconstructed from an operation ID.
type PCV3ResourceChallenge struct {
	operation *PCV3Operation
	challenge *pcv3resource.AndroidResourceChallenge
}

// ResourceChallenge returns the current challenge only through its matching
// live operation object. An unconfigured policy and a non-waiting KDF both
// return nil.
func (operation *PCV3Operation) ResourceChallenge() *PCV3ResourceChallenge {
	globalProgressMap.mu.RLock()
	state, ok := livePCV3StateLocked(operation)
	live := ok && !state.terminal && !state.cancelRequested
	globalProgressMap.mu.RUnlock()
	if !live || operation.resourceSession == nil {
		return nil
	}
	challenge := operation.resourceSession.Challenge()
	if challenge == nil {
		return nil
	}
	return &PCV3ResourceChallenge{operation: operation, challenge: challenge}
}

// Submit transfers only current-device observations. The return value reports
// whether this one-shot transport handle was consumed; it is never a resource
// sufficiency or KDF admission decision.
func (challenge *PCV3ResourceChallenge) Submit(
	manufacturer string,
	model string,
	abi string,
	osArch string,
	totalRAMBytes int64,
	effectiveAvailable int64,
	processIs64Bit bool,
	emulatorTraitsClear bool,
	lowMemory bool,
) bool {
	if challenge == nil || challenge.operation == nil || challenge.challenge == nil {
		return false
	}
	globalProgressMap.mu.RLock()
	state, ok := livePCV3StateLocked(challenge.operation)
	live := ok && !state.terminal && !state.cancelRequested
	globalProgressMap.mu.RUnlock()
	if !live {
		return false
	}
	return challenge.challenge.Submit(
		manufacturer,
		model,
		abi,
		osArch,
		totalRAMBytes,
		effectiveAvailable,
		processIs64Bit,
		emulatorTraitsClear,
		lowMemory,
	)
}

// Cancel requests cancellation once through the live Go object. The operation
// core remains the sole authority for the eventual terminal presentation.
func (operation *PCV3Operation) Cancel() *PCV3Snapshot {
	var cancel context.CancelFunc
	var consent *pcv3ConsentState
	globalProgressMap.mu.Lock()
	state, ok := livePCV3StateLocked(operation)
	if ok && !state.terminal && !state.cancelRequested {
		state.cancelRequested = true
		consent = state.consent
		cancel = globalProgressMap.cancels[operation.id]
	}
	globalProgressMap.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if consent != nil {
		consent.refuse()
	}
	return operation.Snapshot()
}

// Release removes a matching terminal operation after all live capabilities
// and effects are finished. It never acts on an ID alone.
func (operation *PCV3Operation) Release() string {
	var cancel context.CancelFunc
	globalProgressMap.mu.Lock()
	state, ok := livePCV3StateLocked(operation)
	if !ok || !state.terminal || state.consent != nil || state.archive != nil ||
		state.archiveInFlight || state.output != nil || state.outputInFlight {
		globalProgressMap.mu.Unlock()
		return pcv3OperationReleaseDenied
	}
	cancel = globalProgressMap.cancels[operation.id]
	delete(globalProgressMap.pcv3, operation.id)
	delete(globalProgressMap.ctxs, operation.id)
	delete(globalProgressMap.cancels, operation.id)
	globalProgressMap.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	return ""
}

// PCV3Snapshot is an authority-free scalar view. It intentionally has no raw
// error, path, completion boolean, or capability field.
type PCV3Snapshot struct {
	presentation pcv3operation.Presentation
	status       pcv3operation.Status
	operationID  string
	receiptID    string
	args         [4]uint64
	argCount     int
	warnings     [8]string
	warningCount int
}

func newPCV3Snapshot(
	presentation pcv3operation.Presentation,
	status pcv3operation.Status,
	operationID, receiptID string,
) *PCV3Snapshot {
	snapshot := &PCV3Snapshot{
		presentation: presentation,
		status:       status,
		operationID:  operationID,
		receiptID:    receiptID,
	}
	args := presentation.Args()
	if len(args) > len(snapshot.args) {
		args = args[:len(snapshot.args)]
	}
	copy(snapshot.args[:], args)
	snapshot.argCount = len(args)
	warnings := presentation.Warnings()
	if len(warnings) > len(snapshot.warnings) {
		warnings = warnings[:len(snapshot.warnings)]
	}
	for index, warning := range warnings {
		snapshot.warnings[index] = pcv3WarningCode(warning)
	}
	snapshot.warningCount = len(warnings)
	return snapshot
}

func (snapshot *PCV3Snapshot) StatusCode() string {
	if snapshot == nil {
		return "none"
	}
	return pcv3StatusCode(snapshot.status.Code())
}

func (snapshot *PCV3Snapshot) StatusArgCount() int {
	if snapshot == nil {
		return 0
	}
	args := snapshot.status.Args()
	if len(args) > 4 {
		return 4
	}
	return len(args)
}

func (snapshot *PCV3Snapshot) StatusArgAt(index int) string {
	if snapshot == nil || index < 0 {
		return "0"
	}
	args := snapshot.status.Args()
	if index >= len(args) || index >= 4 {
		return "0"
	}
	return strconv.FormatUint(args[index], 10)
}

func (snapshot *PCV3Snapshot) Outcome() string {
	if snapshot == nil {
		return "unknown-outcome"
	}
	return snapshot.presentation.Outcome().String()
}

func (snapshot *PCV3Snapshot) Stage() string {
	if snapshot == nil {
		return "unknown-stage"
	}
	return snapshot.presentation.Stage().String()
}

func (snapshot *PCV3Snapshot) Code() string {
	if snapshot == nil {
		return "PCV3_UNKNOWN"
	}
	return snapshot.presentation.Code().String()
}

func (snapshot *PCV3Snapshot) ForceProvenance() string {
	if snapshot == nil {
		return "none"
	}
	return pcv3ForceProvenance(snapshot.presentation.ForceProvenance())
}

func (snapshot *PCV3Snapshot) D1BootstrapProvenance() string {
	if snapshot == nil {
		return "none"
	}
	return pcv3D1Provenance(snapshot.presentation.D1BootstrapProvenance())
}

func (snapshot *PCV3Snapshot) DetailStage() string {
	if snapshot == nil {
		return "none"
	}
	return snapshot.presentation.DetailStage().String()
}

func (snapshot *PCV3Snapshot) PublicationAttempted() bool {
	return snapshot != nil && snapshot.presentation.PublicationAttempted()
}

func (snapshot *PCV3Snapshot) PublicationState() string {
	if snapshot == nil || snapshot.presentation.PublicationState() == 0 {
		return "none"
	}
	return snapshot.presentation.PublicationState().String()
}

func (snapshot *PCV3Snapshot) PublicationStage() string {
	if snapshot == nil {
		return "none"
	}
	return snapshot.presentation.PublicationStage().String()
}

func (snapshot *PCV3Snapshot) PublicationCode() string {
	if snapshot == nil || snapshot.presentation.PublicationCode() == 0 {
		return "none"
	}
	return snapshot.presentation.PublicationCode().String()
}

func (snapshot *PCV3Snapshot) Diagnostic() string {
	if snapshot == nil {
		return "none"
	}
	return pcv3DiagnosticCode(snapshot.presentation.Diagnostic())
}

func (snapshot *PCV3Snapshot) CompletionClass() string {
	if snapshot == nil {
		return "unknown"
	}
	return pcv3CompletionCode(snapshot.presentation.CompletionClass())
}

func (snapshot *PCV3Snapshot) ArchivePending() bool {
	return snapshot != nil && snapshot.presentation.ArchivePending()
}

func (snapshot *PCV3Snapshot) ArgCount() int {
	if snapshot == nil {
		return 0
	}
	return snapshot.argCount
}

func (snapshot *PCV3Snapshot) ArgAt(index int) string {
	if snapshot == nil || index < 0 || index >= snapshot.argCount {
		return "0"
	}
	return strconv.FormatUint(snapshot.args[index], 10)
}

func (snapshot *PCV3Snapshot) WarningCount() int {
	if snapshot == nil {
		return 0
	}
	return snapshot.warningCount
}

func (snapshot *PCV3Snapshot) WarningAt(index int) string {
	if snapshot == nil || index < 0 || index >= snapshot.warningCount {
		return "none"
	}
	return snapshot.warnings[index]
}

func (snapshot *PCV3Snapshot) RestoredReceipt() string {
	if snapshot == nil {
		return ""
	}
	return mintPCV3ReceiptV1(snapshot.operationID, snapshot.receiptID, snapshot.presentation)
}

type pcv3ProgressState struct {
	generation         uint64
	presentation       pcv3operation.Presentation
	status             pcv3operation.Status
	terminal           bool
	receiptID          string
	cancelRequested    bool
	consent            *pcv3ConsentState
	archive            *pcv3ArchiveState
	archiveInFlight    bool
	output             *pcv3OutputState
	outputInFlight     bool
	artifactInspection *PCV3ArtifactInspection
}

type pcv3StateCopy struct {
	presentation pcv3operation.Presentation
	status       pcv3operation.Status
	receiptID    string
}

type pcv3ConsentState struct {
	mu        sync.Mutex
	operation *PCV3Operation
	request   pcv3operation.ConsentRequest
	decision  chan pcv3ConsentDecision
	live      bool
}

type pcv3ConsentDecision struct {
	role   pcv3operation.PhysicalRole
	invoke bool
}

// PCV3Consent is a one-shot Go-owned live capability.
type PCV3Consent struct{ state *pcv3ConsentState }

func (consent *PCV3Consent) Mode() string {
	if consent == nil || consent.state == nil {
		return "none"
	}
	return pcv3ModeCode(consent.state.request.Mode())
}

func (consent *PCV3Consent) RoleCount() int {
	if consent == nil || consent.state == nil {
		return 0
	}
	return len(consent.state.request.AllowedRoles())
}

func (consent *PCV3Consent) RoleAt(index int) string {
	if consent == nil || consent.state == nil || index < 0 {
		return "none"
	}
	roles := consent.state.request.AllowedRoles()
	if index >= len(roles) {
		return "none"
	}
	return pcv3RoleCode(roles[index])
}

func (consent *PCV3Consent) Choose(role string) string {
	if consent == nil || consent.state == nil {
		return pcv3ConsentExpired
	}
	return consent.state.choose(pcv3Role(role))
}

func (consent *PCV3Consent) Refuse() string {
	if consent == nil || consent.state == nil || !consent.state.refuse() {
		return pcv3ConsentExpired
	}
	return ""
}

func (state *pcv3ConsentState) isLive() bool {
	if state == nil {
		return false
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.live
}

func (state *pcv3ConsentState) choose(role pcv3operation.PhysicalRole) string {
	if state == nil {
		return pcv3ConsentExpired
	}
	state.mu.Lock()
	if !state.live {
		state.mu.Unlock()
		return pcv3ConsentExpired
	}
	allowed := false
	for _, candidate := range state.request.AllowedRoles() {
		if role == candidate {
			allowed = true
			break
		}
	}
	state.live = false
	state.mu.Unlock()
	detachPCV3Consent(state)
	state.decision <- pcv3ConsentDecision{role: role, invoke: allowed}
	if !allowed {
		return "PCV3_CONSENT_ROLE_REFUSED"
	}
	return ""
}

func (state *pcv3ConsentState) refuse() bool {
	if state == nil {
		return false
	}
	state.mu.Lock()
	if !state.live {
		state.mu.Unlock()
		return false
	}
	state.live = false
	state.mu.Unlock()
	detachPCV3Consent(state)
	state.decision <- pcv3ConsentDecision{}
	return true
}

type pcv3ArchiveAction interface {
	Close() pcv3operation.Presentation
}

type nativePCV3ArchiveAction struct {
	followUp *pcv3operation.ArchiveFollowUp
}

func (action *nativePCV3ArchiveAction) Close() pcv3operation.Presentation {
	if action == nil || action.followUp == nil {
		return fallbackPCV3Presentation(pcv3operation.DiagnosticInvalidRequest)
	}
	result := action.followUp.Close()
	if result == nil {
		return fallbackPCV3Presentation(pcv3operation.DiagnosticCoreFailure)
	}
	return result.Presentation()
}

type pcv3ArchiveState struct {
	mu        sync.Mutex
	operation *PCV3Operation
	action    pcv3ArchiveAction
	live      bool
}

// PCV3Archive is a one-shot Go-owned archive follow-up capability.
type PCV3Archive struct{ state *pcv3ArchiveState }

func (archive *PCV3Archive) Close() *PCV3Snapshot {
	state, action := archive.consume()
	if state == nil {
		return archive.snapshot()
	}
	presentation := action.Close()
	return replacePCV3ArchivePresentation(state.operation, presentation)
}

func (archive *PCV3Archive) consume() (*pcv3ArchiveState, pcv3ArchiveAction) {
	if archive == nil || archive.state == nil {
		return nil, nil
	}
	state := archive.state
	state.mu.Lock()
	if !state.live || state.action == nil {
		state.mu.Unlock()
		return nil, nil
	}
	state.live = false
	action := state.action
	state.action = nil
	state.mu.Unlock()
	markPCV3ArchiveInFlight(state)
	return state, action
}

func (archive *PCV3Archive) snapshot() *PCV3Snapshot {
	if archive == nil || archive.state == nil || archive.state.operation == nil {
		return newPCV3Snapshot(pcv3operation.Presentation{}, pcv3operation.Status{}, "", "")
	}
	return archive.state.operation.Snapshot()
}

func (state *pcv3ArchiveState) isLive() bool {
	if state == nil {
		return false
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.live && state.action != nil
}

type pcv3OutputActionResult struct {
	code              string
	cleanupIncomplete bool
}

type pcv3OutputAction interface {
	Discard() pcv3OutputActionResult
	SaveTo(*os.File) pcv3OutputActionResult
}

type nativePCV3OutputAction struct {
	followUp *pcv3operation.OutputFollowUp
}

func (action *nativePCV3OutputAction) Discard() pcv3OutputActionResult {
	if action == nil || action.followUp == nil {
		return pcv3OutputActionResult{code: "discard-cleanup-incomplete", cleanupIncomplete: true}
	}
	result := action.followUp.Discard()
	return pcv3OutputActionResult{
		code:              result.Code().String(),
		cleanupIncomplete: result.CleanupIncomplete(),
	}
}

func (action *nativePCV3OutputAction) SaveTo(destination *os.File) pcv3OutputActionResult {
	if action == nil || action.followUp == nil {
		return pcv3OutputActionResult{code: "save-failed-cleanup-incomplete", cleanupIncomplete: true}
	}
	result := action.followUp.SaveTo(destination)
	return pcv3OutputActionResult{
		code:              result.Code().String(),
		cleanupIncomplete: result.CleanupIncomplete(),
	}
}

func discardPCV3OutputAction(action pcv3OutputAction) (result pcv3OutputActionResult) {
	result = pcv3OutputActionResult{code: "discard-cleanup-incomplete", cleanupIncomplete: true}
	if action == nil {
		return result
	}
	defer func() {
		if recover() != nil {
			result = pcv3OutputActionResult{code: "discard-cleanup-incomplete", cleanupIncomplete: true}
		}
	}()
	return action.Discard()
}

func savePCV3OutputAction(action pcv3OutputAction, destination *os.File) (result pcv3OutputActionResult) {
	result = pcv3OutputActionResult{code: "save-failed-cleanup-incomplete", cleanupIncomplete: true}
	if action == nil {
		return result
	}
	defer func() {
		if recover() != nil {
			result = pcv3OutputActionResult{code: "save-failed-cleanup-incomplete", cleanupIncomplete: true}
		}
	}()
	return action.SaveTo(destination)
}

type pcv3OutputState struct {
	mu        sync.Mutex
	operation *PCV3Operation
	action    pcv3OutputAction
	live      bool
}

// PCV3Output is a one-shot Go-owned retained-output follow-up capability.
// Copies share one consumption state.
type PCV3Output struct{ state *pcv3OutputState }

func (output *PCV3Output) String() string { return "pcv3 output" }

func (output *PCV3Output) GoString() string { return output.String() }

func (output *PCV3Output) Format(state fmt.State, verb rune) {
	value := output.String()
	if verb == 'q' {
		value = strconv.Quote(value)
	}
	_, _ = state.Write([]byte(value))
}

// PCV3OutputResult is the path-free terminal result of one output action.
type PCV3OutputResult struct {
	code              string
	cleanupIncomplete bool
}

func (result *PCV3OutputResult) String() string {
	if result == nil {
		return "expired"
	}
	return result.code
}

func (result *PCV3OutputResult) GoString() string { return result.String() }

func (result *PCV3OutputResult) Format(state fmt.State, verb rune) {
	value := result.String()
	if verb == 'q' {
		value = strconv.Quote(value)
	}
	_, _ = state.Write([]byte(value))
}

func (result *PCV3OutputResult) Code() string {
	if result == nil {
		return "expired"
	}
	return result.code
}

func (result *PCV3OutputResult) CleanupIncomplete() bool {
	return result != nil && result.cleanupIncomplete
}

// Discard consumes the capability before removing only its exact retained
// plaintext owner. Any blocking filesystem effect occurs outside the global
// operation registry lock.
func (output *PCV3Output) Discard() (result *PCV3OutputResult) {
	state, action := output.consume()
	if state == nil || action == nil {
		return &PCV3OutputResult{code: "expired"}
	}
	inFlight := markPCV3OutputInFlight(state)
	defer func() {
		if inFlight {
			settlePCV3Output(state)
		}
	}()
	actionResult := discardPCV3OutputAction(action)
	return &PCV3OutputResult{code: actionResult.code, cleanupIncomplete: actionResult.cleanupIncomplete}
}

// SaveFD consumes the capability before transferring one Android-owned file
// descriptor to the exact retained-output action. It accepts no path, URI, or
// operation lookup, and always closes a validated transferred descriptor.
func (output *PCV3Output) SaveFD(destinationFD int64) (result *PCV3OutputResult) {
	destination := pcv3OutputFileFromFD(destinationFD)
	if destination != nil {
		defer func() { _ = destination.Close() }()
	}
	state, action := output.consume()
	if state == nil || action == nil {
		return &PCV3OutputResult{code: "expired"}
	}
	inFlight := markPCV3OutputInFlight(state)
	defer func() {
		if inFlight {
			settlePCV3Output(state)
		}
	}()

	actionResult := savePCV3OutputAction(action, destination)
	return &PCV3OutputResult{code: actionResult.code, cleanupIncomplete: actionResult.cleanupIncomplete}
}

func pcv3OutputFileFromFD(destinationFD int64) *os.File {
	if destinationFD < 0 || destinationFD > maxPCV3OutputFD {
		return nil
	}
	return os.NewFile(uintptr(destinationFD), "pcv3-output")
}

func (output *PCV3Output) consume() (*pcv3OutputState, pcv3OutputAction) {
	if output == nil || output.state == nil {
		return nil, nil
	}
	state := output.state
	state.mu.Lock()
	if !state.live || state.action == nil {
		state.mu.Unlock()
		return nil, nil
	}
	state.live = false
	action := state.action
	state.action = nil
	state.mu.Unlock()
	return state, action
}

func (state *pcv3OutputState) isLive() bool {
	if state == nil {
		return false
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	return state.live && state.action != nil
}

// ProgressState represents the current state of an operation
type ProgressState struct {
	ID                      string
	Status                  string
	StatusCode              string
	StatusSpeedMiBPerSecond float64
	StatusETA               string
	Progress                float32
	Info                    string
	InfoCode                string
	InfoCurrent             int64
	InfoTotal               int64
	Error                   string
	// Code is a stable, locale-independent classification of Error (see
	// errorCode); empty on success/cancel-without-error. The Android layer maps
	// it to a typed AppError to gate force-decrypt / password-retry.
	Code string
	Done bool
}

// progressMap stores progress state for all active operations
type progressMap struct {
	mu      sync.RWMutex
	ops     map[string]*ProgressState
	pcv3    map[string]*pcv3ProgressState
	ctxs    map[string]context.Context
	cancels map[string]context.CancelFunc
}

var globalProgressMap = &progressMap{
	ops:     make(map[string]*ProgressState),
	pcv3:    make(map[string]*pcv3ProgressState),
	ctxs:    make(map[string]context.Context),
	cancels: make(map[string]context.CancelFunc),
}

var (
	operationSequence atomic.Uint64
	pcv3Generation    atomic.Uint64
)

// newOperationID generates a unique operation ID
func newOperationID() string {
	return fmt.Sprintf("op_%d_%d", time.Now().UnixNano(), operationSequence.Add(1))
}

// startOperation creates a new operation and returns its ID
func startOperation() string {
	status := classifyStatus("Starting...")
	info := classifyInfo("")
	for {
		id := newOperationID()
		ctx, cancel := context.WithCancel(context.Background()) //nolint:gosec // G118: stored in registry and released by cancellation/cleanup
		globalProgressMap.mu.Lock()
		if !operationIDAvailableLocked(id) {
			globalProgressMap.mu.Unlock()
			cancel()
			continue
		}
		globalProgressMap.ops[id] = &ProgressState{
			ID:                      id,
			Status:                  "Starting...",
			StatusCode:              status.Code,
			StatusSpeedMiBPerSecond: status.SpeedMiBPerSecond,
			StatusETA:               status.ETA,
			Progress:                0.0,
			Info:                    "",
			InfoCode:                info.Code,
			InfoCurrent:             info.Current,
			InfoTotal:               info.Total,
		}
		globalProgressMap.ctxs[id] = ctx
		globalProgressMap.cancels[id] = cancel
		globalProgressMap.mu.Unlock()
		return id
	}
}

func startPCV3Operation() *PCV3Operation {
	for {
		id := newOperationID()
		generation := pcv3Generation.Add(1)
		resourceSession := pcv3resource.NewAndroidResourceSession()
		baseContext, cancel := context.WithCancel(context.Background()) //nolint:gosec // G118: stored in registry and released by PCV3Operation.Cancel/cleanup
		ctx := pcv3resource.WithAndroidResourceSession(baseContext, resourceSession)
		globalProgressMap.mu.Lock()
		if !operationIDAvailableLocked(id) {
			globalProgressMap.mu.Unlock()
			cancel()
			continue
		}
		globalProgressMap.pcv3[id] = &pcv3ProgressState{generation: generation}
		globalProgressMap.ctxs[id] = ctx
		globalProgressMap.cancels[id] = cancel
		globalProgressMap.mu.Unlock()
		return &PCV3Operation{
			id:              id,
			generation:      generation,
			resourceSession: resourceSession,
		}
	}
}

func operationIDAvailableLocked(id string) bool {
	_, legacy := globalProgressMap.ops[id]
	_, pcv3State := globalProgressMap.pcv3[id]
	_, contextExists := globalProgressMap.ctxs[id]
	_, cancelExists := globalProgressMap.cancels[id]
	return !legacy && !pcv3State && !contextExists && !cancelExists
}

func livePCV3StateLocked(operation *PCV3Operation) (*pcv3ProgressState, bool) {
	if operation == nil || operation.id == "" || operation.generation == 0 {
		return nil, false
	}
	state, ok := globalProgressMap.pcv3[operation.id]
	return state, ok && state.generation == operation.generation
}

func copyPCV3State(operation *PCV3Operation) (pcv3StateCopy, bool) {
	globalProgressMap.mu.RLock()
	defer globalProgressMap.mu.RUnlock()
	state, ok := livePCV3StateLocked(operation)
	if !ok {
		return pcv3StateCopy{}, false
	}
	return pcv3StateCopy{
		presentation: state.presentation,
		status:       state.status,
		receiptID:    state.receiptID,
	}, true
}

func pcv3Reporter(operation *PCV3Operation) pcv3operation.Reporter {
	return func(status pcv3operation.Status) error {
		globalProgressMap.mu.Lock()
		defer globalProgressMap.mu.Unlock()
		state, ok := livePCV3StateLocked(operation)
		if !ok || state.terminal {
			return errors.New("PCV3 operation is not live")
		}
		state.status = status
		return nil
	}
}

func pcv3ConsentCallback(operation *PCV3Operation) pcv3operation.Consent {
	return func(request pcv3operation.ConsentRequest, action pcv3operation.ConsentAction) error {
		state := &pcv3ConsentState{
			operation: operation,
			request:   request,
			decision:  make(chan pcv3ConsentDecision, 1),
			live:      true,
		}
		globalProgressMap.mu.Lock()
		progress, ok := livePCV3StateLocked(operation)
		if !ok || progress.terminal || progress.consent != nil {
			globalProgressMap.mu.Unlock()
			return nil
		}
		progress.consent = state
		globalProgressMap.mu.Unlock()
		decision := <-state.decision
		detachPCV3Consent(state)
		if !decision.invoke {
			return nil
		}
		return action(decision.role)
	}
}

func detachPCV3Consent(consent *pcv3ConsentState) {
	if consent == nil || consent.operation == nil {
		return
	}
	globalProgressMap.mu.Lock()
	if state, ok := livePCV3StateLocked(consent.operation); ok && state.consent == consent {
		state.consent = nil
	}
	globalProgressMap.mu.Unlock()
}

func completePCV3Result(operation *PCV3Operation, result *pcv3operation.Result) {
	presentation := fallbackPCV3Presentation(pcv3operation.DiagnosticCoreFailure)
	var archive pcv3ArchiveAction
	var output pcv3OutputAction
	var inspection *PCV3ArtifactInspection
	if result != nil {
		presentation = result.Presentation()
		if followUp := result.ArchiveFollowUp(); followUp != nil {
			archive = &nativePCV3ArchiveAction{followUp: followUp}
		}
		if followUp := result.OutputFollowUp(); followUp != nil {
			output = &nativePCV3OutputAction{followUp: followUp}
		}
		inspection = newPCV3ArtifactInspection(result.ArtifactInspection())
	}
	if archive != nil && output != nil {
		outputResult := discardPCV3OutputAction(output)
		closed := archive.Close()
		completePCV3PresentationForOperation(
			operation,
			outputArchiveFailurePCV3Presentation(closed, outputResult),
		)
		return
	}
	if archive != nil && inspection != nil {
		completePCV3PresentationWithArchiveAndInspection(operation, presentation, archive, inspection)
		return
	}
	if output != nil {
		completePCV3PresentationWithOutputAndInspection(operation, presentation, output, inspection)
		return
	}
	if archive == nil {
		completePCV3PresentationWithInspection(operation, presentation, inspection)
		return
	}
	completePCV3PresentationWithArchive(operation, presentation, archive)
}

func completePCV3Panic(operation *PCV3Operation) {
	completePCV3PresentationForOperation(operation, fallbackPCV3Presentation(pcv3operation.DiagnosticCallbackPanic))
}

func completePCV3Presentation(id string, presentation pcv3operation.Presentation) {
	if presentation.CompletionClass() == pcv3operation.CompletionUnknown || presentation.ArchivePending() {
		presentation = fallbackPCV3Presentation(pcv3operation.DiagnosticCoreFailure)
	}
	receiptID := ""
	if restorablePCV3Presentation(presentation) {
		receiptID = pcv3ReceiptIDGenerator()
	}
	globalProgressMap.mu.Lock()
	defer globalProgressMap.mu.Unlock()
	state, ok := globalProgressMap.pcv3[id]
	if !ok || state.terminal {
		return
	}
	state.presentation = presentation
	state.terminal = true
	state.receiptID = receiptID
}

func completePCV3PresentationForOperation(
	operation *PCV3Operation,
	presentation pcv3operation.Presentation,
) {
	completePCV3PresentationWithInspection(operation, presentation, nil)
}

func completePCV3PresentationWithInspection(
	operation *PCV3Operation,
	presentation pcv3operation.Presentation,
	inspection *PCV3ArtifactInspection,
) {
	completePCV3PresentationWithArchiveAndInspection(operation, presentation, nil, inspection)
}

func completePCV3PresentationWithArchive(
	operation *PCV3Operation,
	presentation pcv3operation.Presentation,
	action pcv3ArchiveAction,
) {
	completePCV3PresentationWithArchiveAndInspection(operation, presentation, action, nil)
}

func completePCV3PresentationWithArchiveAndInspection(
	operation *PCV3Operation,
	presentation pcv3operation.Presentation,
	action pcv3ArchiveAction,
	inspection *PCV3ArtifactInspection,
) {
	if presentation.CompletionClass() == pcv3operation.CompletionUnknown ||
		(action != nil && inspection != nil) ||
		(action != nil && !presentation.ArchivePending()) ||
		(action == nil && presentation.ArchivePending()) {
		var closed pcv3operation.Presentation
		cleanupIncomplete := false
		if action != nil {
			closed, cleanupIncomplete = closePCV3ArchiveAction(action)
			action = nil
		}
		inspection = nil
		if cleanupIncomplete {
			presentation = archiveCleanupIncompletePCV3Presentation()
		} else {
			presentation = archiveFailurePCV3Presentation(closed)
		}
	}
	var rejected pcv3ArchiveAction
	receiptID := ""
	if restorablePCV3Presentation(presentation) {
		receiptID = pcv3ReceiptIDGenerator()
	}
	globalProgressMap.mu.Lock()
	state, ok := livePCV3StateLocked(operation)
	if !ok || state.terminal {
		if action != nil {
			rejected = action
		}
		globalProgressMap.mu.Unlock()
		if rejected != nil {
			_ = rejected.Close()
		}
		return
	}
	state.presentation = presentation
	state.terminal = true
	if action != nil {
		state.archive = &pcv3ArchiveState{operation: operation, action: action, live: true}
	} else if inspection != nil {
		state.artifactInspection = inspection
	}
	state.receiptID = receiptID
	globalProgressMap.mu.Unlock()
	if rejected != nil {
		_ = rejected.Close()
	}
}

func completePCV3PresentationWithOutput(
	operation *PCV3Operation,
	presentation pcv3operation.Presentation,
	action pcv3OutputAction,
) {
	completePCV3PresentationWithOutputAndInspection(operation, presentation, action, nil)
}

func completePCV3PresentationWithOutputAndInspection(
	operation *PCV3Operation,
	presentation pcv3operation.Presentation,
	action pcv3OutputAction,
	inspection *PCV3ArtifactInspection,
) {
	if action == nil {
		completePCV3PresentationWithInspection(operation, presentation, inspection)
		return
	}
	completion := presentation.CompletionClass()
	if completion != pcv3operation.CompletionClean && completion != pcv3operation.CompletionWarning {
		result := discardPCV3OutputAction(action)
		completePCV3PresentationForOperation(
			operation,
			outputFailurePCV3Presentation(pcv3operation.DiagnosticCoreFailure, result),
		)
		return
	}

	var rejected pcv3OutputAction
	receiptID := ""
	if restorablePCV3Presentation(presentation) {
		receiptID = pcv3ReceiptIDGenerator()
	}
	globalProgressMap.mu.Lock()
	state, ok := livePCV3StateLocked(operation)
	if !ok || state.terminal || state.archive != nil || state.output != nil {
		rejected = action
		globalProgressMap.mu.Unlock()
		_ = discardPCV3OutputAction(rejected)
		return
	}
	state.presentation = presentation
	state.terminal = true
	state.output = &pcv3OutputState{operation: operation, action: action, live: true}
	state.artifactInspection = inspection
	state.receiptID = receiptID
	globalProgressMap.mu.Unlock()
}

func replacePCV3ArchivePresentation(
	operation *PCV3Operation,
	presentation pcv3operation.Presentation,
) *PCV3Snapshot {
	return replacePCV3ArchivePresentationWithReceipt(operation, presentation, nil, "")
}

func replacePCV3ArchiveSAFPresentation(
	operation *PCV3Operation,
	presentation pcv3operation.Presentation,
	activeSnapshot *PCV3Snapshot,
	activeReceipt string,
) *PCV3Snapshot {
	return replacePCV3ArchivePresentationWithReceipt(operation, presentation, activeSnapshot, activeReceipt)
}

func replacePCV3ArchivePresentationWithReceipt(
	operation *PCV3Operation,
	presentation pcv3operation.Presentation,
	activeSnapshot *PCV3Snapshot,
	activeReceipt string,
) *PCV3Snapshot {
	if presentation.CompletionClass() == pcv3operation.CompletionUnknown || presentation.ArchivePending() {
		presentation = fallbackPCV3Presentation(pcv3operation.DiagnosticCoreFailure)
	}
	receiptID := ""
	if restorablePCV3Presentation(presentation) {
		if operation != nil && activeSnapshot != nil && activeReceipt != "" &&
			activeSnapshot.operationID == operation.id &&
			mintPCV3ReceiptV1(
				activeSnapshot.operationID,
				activeSnapshot.receiptID,
				presentation,
			) == activeReceipt {
			receiptID = activeSnapshot.receiptID
		} else {
			receiptID = pcv3ReceiptIDGenerator()
		}
	}
	globalProgressMap.mu.Lock()
	defer globalProgressMap.mu.Unlock()
	state, ok := livePCV3StateLocked(operation)
	if !ok || state.archive != nil || !state.archiveInFlight || presentation.ArchivePending() {
		return newPCV3Snapshot(pcv3operation.Presentation{}, pcv3operation.Status{}, "", "")
	}
	state.presentation = presentation
	state.terminal = true
	state.receiptID = receiptID
	state.archiveInFlight = false
	return newPCV3Snapshot(state.presentation, state.status, operation.id, state.receiptID)
}

func markPCV3ArchiveInFlight(archive *pcv3ArchiveState) {
	if archive == nil || archive.operation == nil {
		return
	}
	globalProgressMap.mu.Lock()
	if state, ok := livePCV3StateLocked(archive.operation); ok && state.archive == archive {
		state.archive = nil
		state.archiveInFlight = true
	}
	globalProgressMap.mu.Unlock()
}

func markPCV3OutputInFlight(output *pcv3OutputState) bool {
	if output == nil || output.operation == nil {
		return false
	}
	globalProgressMap.mu.Lock()
	defer globalProgressMap.mu.Unlock()
	state, ok := livePCV3StateLocked(output.operation)
	if !ok || state.output != output {
		return false
	}
	state.output = nil
	state.outputInFlight = true
	return true
}

func settlePCV3Output(output *pcv3OutputState) {
	if output == nil || output.operation == nil {
		return
	}
	globalProgressMap.mu.Lock()
	defer globalProgressMap.mu.Unlock()
	if state, ok := livePCV3StateLocked(output.operation); ok && state.output == nil && state.outputInFlight {
		state.outputInFlight = false
	}
}

func fallbackPCV3Presentation(diagnostic pcv3operation.Diagnostic) pcv3operation.Presentation {
	presentation, err := pcv3operation.NewPresentation(pcv3operation.PresentationSpec{
		Outcome:    pcv3.OutcomeOperationFailed,
		Stage:      pcv3.StageCredentialPolicy,
		Code:       pcv3.CodeOperationFailed,
		Diagnostic: diagnostic,
	})
	if err != nil {
		return pcv3operation.Presentation{}
	}
	return presentation
}

// closePCV3ArchiveAction contains only terminal-projection cleanup panics.
// It runs before any registry mutation, so the caller can publish one bounded
// cleanup-uncertain terminal state instead of leaking a goroutine panic.
func closePCV3ArchiveAction(action pcv3ArchiveAction) (presentation pcv3operation.Presentation, cleanupIncomplete bool) {
	presentation = fallbackPCV3Presentation(pcv3operation.DiagnosticCoreFailure)
	cleanupIncomplete = true
	if action == nil {
		return presentation, cleanupIncomplete
	}
	defer func() {
		if recover() != nil {
			presentation = fallbackPCV3Presentation(pcv3operation.DiagnosticCoreFailure)
			cleanupIncomplete = true
		}
	}()
	presentation = action.Close()
	cleanupIncomplete = false
	return presentation, cleanupIncomplete
}

func archiveCleanupIncompletePCV3Presentation() pcv3operation.Presentation {
	presentation, err := pcv3operation.NewPresentation(pcv3operation.PresentationSpec{
		Outcome:    pcv3.OutcomeOperationFailed,
		Stage:      pcv3.StageOutputPublication,
		Code:       pcv3.CodeOperationFailed,
		Warnings:   []pcv3operation.Warning{pcv3operation.WarningCleanupIncomplete},
		Diagnostic: pcv3operation.DiagnosticCoreFailure,
	})
	if err != nil {
		return fallbackPCV3Presentation(pcv3operation.DiagnosticCoreFailure)
	}
	return presentation
}

func archiveFailurePCV3Presentation(closed pcv3operation.Presentation) pcv3operation.Presentation {
	var warnings []pcv3operation.Warning
	for _, warning := range closed.Warnings() {
		if warning == pcv3operation.WarningCleanupIncomplete {
			warnings = append(warnings, warning)
			break
		}
	}
	presentation, err := pcv3operation.NewPresentation(pcv3operation.PresentationSpec{
		Outcome:    pcv3.OutcomeOperationFailed,
		Stage:      pcv3.StageOutputPublication,
		Code:       pcv3.CodeOperationFailed,
		Warnings:   warnings,
		Diagnostic: pcv3operation.DiagnosticCoreFailure,
	})
	if err != nil {
		return fallbackPCV3Presentation(pcv3operation.DiagnosticCoreFailure)
	}
	return presentation
}

func outputFailurePCV3Presentation(
	diagnostic pcv3operation.Diagnostic,
	result pcv3OutputActionResult,
) pcv3operation.Presentation {
	var warnings []pcv3operation.Warning
	if result.cleanupIncomplete {
		warnings = append(warnings, pcv3operation.WarningCleanupIncomplete)
	}
	presentation, err := pcv3operation.NewPresentation(pcv3operation.PresentationSpec{
		Outcome:    pcv3.OutcomeOperationFailed,
		Stage:      pcv3.StageOutputPublication,
		Code:       pcv3.CodeOperationFailed,
		Warnings:   warnings,
		Diagnostic: diagnostic,
	})
	if err != nil {
		return fallbackPCV3Presentation(pcv3operation.DiagnosticCoreFailure)
	}
	return presentation
}

func outputArchiveFailurePCV3Presentation(
	closed pcv3operation.Presentation,
	result pcv3OutputActionResult,
) pcv3operation.Presentation {
	presentation := archiveFailurePCV3Presentation(closed)
	if !result.cleanupIncomplete {
		return presentation
	}
	return outputFailurePCV3Presentation(pcv3operation.DiagnosticCoreFailure, result)
}

func newPCV3ReceiptID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return ""
	}
	return "r_" + hex.EncodeToString(value[:])
}

var pcv3ReceiptIDGenerator = newPCV3ReceiptID

type pcv3ReceiptWire struct {
	Version               uint8    `json:"version"`
	ReceiptID             string   `json:"receiptID"`
	OperationID           string   `json:"operationID"`
	Outcome               uint8    `json:"outcome"`
	Stage                 uint8    `json:"stage"`
	Code                  uint8    `json:"code"`
	ForceProvenance       uint8    `json:"forceProvenance"`
	D1BootstrapProvenance uint8    `json:"d1BootstrapProvenance"`
	DetailStage           uint8    `json:"detailStage"`
	PublicationAttempted  bool     `json:"publicationAttempted"`
	PublicationState      uint8    `json:"publicationState"`
	PublicationStage      uint8    `json:"publicationStage"`
	PublicationCode       uint8    `json:"publicationCode"`
	Args                  []uint64 `json:"args"`
	Warnings              []uint8  `json:"warnings"`
	Diagnostic            uint8    `json:"diagnostic"`
}

func pcv3ReceiptWireFromSnapshot(snapshot *PCV3Snapshot) pcv3ReceiptWire {
	warnings := snapshot.presentation.Warnings()
	wire := pcv3ReceiptWire{
		Version:               1,
		ReceiptID:             snapshot.receiptID,
		OperationID:           snapshot.operationID,
		Outcome:               uint8(snapshot.presentation.Outcome()),
		Stage:                 uint8(snapshot.presentation.Stage()),
		Code:                  uint8(snapshot.presentation.Code()),
		ForceProvenance:       uint8(snapshot.presentation.ForceProvenance()),
		D1BootstrapProvenance: uint8(snapshot.presentation.D1BootstrapProvenance()),
		DetailStage:           uint8(snapshot.presentation.DetailStage()),
		PublicationAttempted:  snapshot.presentation.PublicationAttempted(),
		PublicationState:      uint8(snapshot.presentation.PublicationState()),
		PublicationStage:      uint8(snapshot.presentation.PublicationStage()),
		PublicationCode:       uint8(snapshot.presentation.PublicationCode()),
		Args:                  append([]uint64{}, snapshot.presentation.Args()...),
		Warnings:              make([]uint8, 0, len(warnings)),
		Diagnostic:            uint8(snapshot.presentation.Diagnostic()),
	}
	for _, warning := range warnings {
		wire.Warnings = append(wire.Warnings, uint8(warning))
	}
	return wire
}

func mintPCV3ReceiptV1(
	operationID, receiptID string,
	presentation pcv3operation.Presentation,
) string {
	if !validPCV3OpaqueID(operationID) || !validPCV3ReceiptID(receiptID) ||
		!restorablePCV3Presentation(presentation) {
		return ""
	}
	wire := pcv3ReceiptWireFromSnapshot(&PCV3Snapshot{
		presentation: presentation,
		operationID:  operationID,
		receiptID:    receiptID,
	})
	encoded, err := json.Marshal(wire)
	if err != nil || len(encoded) > maxPCV3ReceiptBytes {
		return ""
	}
	return string(encoded)
}

// PCV3RestoredReceipt is display-only state reconstructed after process death.
// It deliberately has no operation, consent, archive, retry, or cleanup method.
type PCV3RestoredReceipt struct {
	code        string
	receiptID   string
	operationID string
	snapshot    *PCV3Snapshot
}

func (receipt *PCV3RestoredReceipt) Code() string {
	if receipt == nil {
		return pcv3ReceiptInvalid
	}
	return receipt.code
}

func (receipt *PCV3RestoredReceipt) ReceiptID() string {
	if receipt == nil {
		return ""
	}
	return receipt.receiptID
}

func (receipt *PCV3RestoredReceipt) OperationID() string {
	if receipt == nil {
		return ""
	}
	return receipt.operationID
}

func (receipt *PCV3RestoredReceipt) Snapshot() *PCV3Snapshot {
	if receipt == nil {
		return nil
	}
	return receipt.snapshot
}

// RestorePCV3Receipt accepts only the bounded fixed receipt schema and returns
// an authority-free display snapshot for durability uncertainty.
func RestorePCV3Receipt(input string) *PCV3RestoredReceipt {
	invalid := &PCV3RestoredReceipt{code: pcv3ReceiptInvalid}
	fields := map[string]struct{}{
		"version": {}, "receiptID": {}, "operationID": {}, "outcome": {},
		"stage": {}, "code": {}, "forceProvenance": {},
		"d1BootstrapProvenance": {}, "detailStage": {},
		"publicationAttempted": {}, "publicationState": {},
		"publicationStage": {}, "publicationCode": {}, "args": {},
		"warnings": {}, "diagnostic": {},
	}
	values, err := decodePCV3ExactObject(input, maxPCV3ReceiptBytes, fields)
	if err != nil {
		return invalid
	}
	for _, value := range values {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return invalid
		}
	}
	var wire pcv3ReceiptWire
	decoder := json.NewDecoder(strings.NewReader(input))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&wire); err != nil || !jsonDecoderAtEOF(decoder) ||
		wire.Version != 1 || !validPCV3ReceiptID(wire.ReceiptID) ||
		!validPCV3OpaqueID(wire.OperationID) || wire.Args == nil || wire.Warnings == nil ||
		len(wire.Args) > 4 || len(wire.Warnings) > 8 {
		return invalid
	}
	warnings := make([]pcv3operation.Warning, len(wire.Warnings))
	for index, warning := range wire.Warnings {
		warnings[index] = pcv3operation.Warning(warning)
	}
	presentation, err := pcv3operation.NewPresentation(pcv3operation.PresentationSpec{
		Outcome:               pcv3.Outcome(wire.Outcome),
		Stage:                 pcv3.Stage(wire.Stage),
		Code:                  pcv3.Code(wire.Code),
		ForceProvenance:       pcv3.ForceProvenance(wire.ForceProvenance),
		D1BootstrapProvenance: pcv3.D1BootstrapProvenance(wire.D1BootstrapProvenance),
		DetailStage:           pcv3.Stage(wire.DetailStage),
		PublicationAttempted:  wire.PublicationAttempted,
		PublicationState:      pcv3publication.State(wire.PublicationState),
		PublicationStage:      pcv3.Stage(wire.PublicationStage),
		PublicationCode:       pcv3publication.Code(wire.PublicationCode),
		Args:                  wire.Args,
		Warnings:              warnings,
		Diagnostic:            pcv3operation.Diagnostic(wire.Diagnostic),
	})
	if err != nil || !restorablePCV3Presentation(presentation) {
		return invalid
	}
	snapshot := newPCV3Snapshot(presentation, pcv3operation.Status{}, wire.OperationID, wire.ReceiptID)
	return &PCV3RestoredReceipt{
		receiptID: wire.ReceiptID, operationID: wire.OperationID, snapshot: snapshot,
	}
}

func restorablePCV3Presentation(presentation pcv3operation.Presentation) bool {
	completion := presentation.CompletionClass()
	return !presentation.ArchivePending() &&
		(completion == pcv3operation.CompletionDurabilityUncertain ||
			completion == pcv3operation.CompletionPublicationIndeterminate)
}

func validPCV3ReceiptID(id string) bool {
	if len(id) != 34 || !strings.HasPrefix(id, "r_") {
		return false
	}
	decoded, err := hex.DecodeString(id[2:])
	return err == nil && len(decoded) == 16
}

func validPCV3OpaqueID(id string) bool {
	if len(id) < 4 || len(id) > 128 || !strings.HasPrefix(id, "op_") {
		return false
	}
	for _, character := range id[3:] {
		if (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}

func decodePCV3ExactObject(
	input string,
	maximum int,
	required map[string]struct{},
) (map[string]json.RawMessage, error) {
	if len(input) == 0 || len(input) > maximum {
		return nil, errors.New("invalid PCV3 object")
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(input)))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("invalid PCV3 object")
	}
	values := make(map[string]json.RawMessage, len(required))
	for decoder.More() {
		nameToken, tokenErr := decoder.Token()
		name, ok := nameToken.(string)
		if tokenErr != nil || !ok {
			return nil, errors.New("invalid PCV3 object")
		}
		if _, ok := required[name]; !ok {
			return nil, errors.New("invalid PCV3 object")
		}
		if _, duplicate := values[name]; duplicate {
			return nil, errors.New("invalid PCV3 object")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, errors.New("invalid PCV3 object")
		}
		values[name] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') ||
		len(values) != len(required) || !jsonDecoderAtEOF(decoder) {
		return nil, errors.New("invalid PCV3 object")
	}
	return values, nil
}

// completeOperation marks an operation as done
func completeOperation(id string, err error) {
	globalProgressMap.mu.Lock()
	defer globalProgressMap.mu.Unlock()

	if op, exists := globalProgressMap.ops[id]; exists {
		if op.Done {
			return
		}
		op.Done = true
		if err != nil {
			status := classifyStatus("Error")
			op.Error = err.Error()
			op.Code = errorCode(err)
			op.Status = "Error"
			op.StatusCode = status.Code
			op.StatusSpeedMiBPerSecond = status.SpeedMiBPerSecond
			op.StatusETA = status.ETA
		} else {
			status := classifyStatus("Completed")
			op.Status = "Completed"
			op.StatusCode = status.Code
			op.StatusSpeedMiBPerSecond = status.SpeedMiBPerSecond
			op.StatusETA = status.ETA
			op.Progress = 1.0
		}
	}
}

// getProgress retrieves the current progress state for an operation
func getProgress(id string) (*ProgressState, error) {
	globalProgressMap.mu.RLock()
	defer globalProgressMap.mu.RUnlock()

	op, exists := globalProgressMap.ops[id]
	if !exists {
		return nil, fmt.Errorf("operation %s not found", id)
	}

	// Return a copy to avoid race conditions
	return copyProgressState(op), nil
}

func copyProgressState(op *ProgressState) *ProgressState {
	return &ProgressState{
		ID:                      op.ID,
		Status:                  op.Status,
		StatusCode:              op.StatusCode,
		StatusSpeedMiBPerSecond: op.StatusSpeedMiBPerSecond,
		StatusETA:               op.StatusETA,
		Progress:                op.Progress,
		Info:                    op.Info,
		InfoCode:                op.InfoCode,
		InfoCurrent:             op.InfoCurrent,
		InfoTotal:               op.InfoTotal,
		Error:                   op.Error,
		Code:                    op.Code,
		Done:                    op.Done,
	}
}

// cancelOperationAndGetProgress cancels an operation and returns the canonical
// terminal state selected while holding the same lock. If completion already
// won the race, its terminal state is preserved and returned instead.
func cancelOperationAndGetProgress(id string) (*ProgressState, error) {
	globalProgressMap.mu.Lock()
	defer globalProgressMap.mu.Unlock()

	cancel, exists := globalProgressMap.cancels[id]
	if !exists {
		return nil, fmt.Errorf("operation %s not found", id)
	}

	op, opExists := globalProgressMap.ops[id]
	if !opExists {
		return nil, fmt.Errorf("operation %s not found", id)
	}

	if !op.Done {
		cancel()
		status := classifyStatus("Cancelled")
		op.Status = "Cancelled"
		op.StatusCode = status.Code
		op.StatusSpeedMiBPerSecond = status.SpeedMiBPerSecond
		op.StatusETA = status.ETA
		op.Done = true
	}

	return copyProgressState(op), nil
}

// cancelOperation cancels an operation.
func cancelOperation(id string) error {
	_, err := cancelOperationAndGetProgress(id)
	return err
}

// getContext retrieves the context for an operation
func getContext(id string) (context.Context, bool) {
	globalProgressMap.mu.RLock()
	defer globalProgressMap.mu.RUnlock()

	ctx, exists := globalProgressMap.ctxs[id]
	return ctx, exists
}

// cleanupOperation removes an operation from the map (called after completion)
func cleanupOperation(id string) {
	globalProgressMap.mu.Lock()
	defer globalProgressMap.mu.Unlock()

	delete(globalProgressMap.ops, id)
	delete(globalProgressMap.pcv3, id)
	delete(globalProgressMap.ctxs, id)
	delete(globalProgressMap.cancels, id)
}
