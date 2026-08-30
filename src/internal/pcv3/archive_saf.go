package pcv3

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3publication"
	"Picocrypt-NG/internal/util"
	"archive/zip"
	"errors"
	"io"
	"math"
	"os"
	"strings"
	"sync"
)

const (
	nativeArchiveSAFMaxEntries   = 65_536
	nativeArchiveSAFMaxPathBytes = 16 * util.MiB
)

var errNativeArchiveSAFManifest = errors.New("pcv3: invalid SAF archive manifest")

// NativeArchiveSAFBeginKind closes the one-shot handoff race without a
// consumed-but-unowned nil result.
type NativeArchiveSAFBeginKind uint8

const (
	NativeArchiveSAFBeginExpired NativeArchiveSAFBeginKind = iota + 1
	NativeArchiveSAFBeginSession
	NativeArchiveSAFBeginTerminal
)

// NativeArchiveSAFStepKind is a closed transition acknowledgement. Rejected
// never grants provider-effect authority.
type NativeArchiveSAFStepKind uint8

const (
	NativeArchiveSAFStepRejected NativeArchiveSAFStepKind = iota + 1
	NativeArchiveSAFStepReady
	NativeArchiveSAFStepAttempted
	NativeArchiveSAFStepPoisoned
)

type NativeArchiveSAFStep struct {
	kind      NativeArchiveSAFStepKind
	nextIndex int
}

func (step *NativeArchiveSAFStep) Kind() NativeArchiveSAFStepKind {
	if step == nil {
		return 0
	}
	return step.kind
}

func (step *NativeArchiveSAFStep) NextIndex() int {
	if step == nil {
		return -1
	}
	return step.nextIndex
}

type NativeArchiveSAFResult struct {
	state             fileops.UnpackState
	attemptedEver     bool
	cleanupIncomplete bool
}

func (result *NativeArchiveSAFResult) State() fileops.UnpackState {
	if result == nil {
		return 0
	}
	return result.state
}

func (result *NativeArchiveSAFResult) AttemptedEver() bool {
	return result != nil && result.attemptedEver
}

func (result *NativeArchiveSAFResult) CleanupIncomplete() bool {
	return result != nil && result.cleanupIncomplete
}

type NativeArchiveSAFEntry struct {
	name        string
	parentIndex int
	directory   bool
	size        int64
}

func (entry *NativeArchiveSAFEntry) Name() string {
	if entry == nil {
		return ""
	}
	return entry.name
}

func (entry *NativeArchiveSAFEntry) ParentIndex() int {
	if entry == nil {
		return -1
	}
	return entry.parentIndex
}

func (entry *NativeArchiveSAFEntry) IsDirectory() bool {
	return entry != nil && entry.directory
}

func (entry *NativeArchiveSAFEntry) Size() int64 {
	if entry == nil {
		return 0
	}
	return entry.size
}

type nativeArchiveSAFManifestEntry struct {
	NativeArchiveSAFEntry
	path string
	file *zip.File
}

type NativeArchiveSAFReceiptArm struct {
	state  *nativeArchiveSAFSessionState
	marker *nativeArchiveSAFArmMarker
}

// A non-zero-size marker gives every receipt arm a distinct pointer identity.
type nativeArchiveSAFArmMarker struct{ _ byte }

type NativeArchiveSAFBegin struct {
	kind    NativeArchiveSAFBeginKind
	session *NativeArchiveSAFSession
	arm     *NativeArchiveSAFReceiptArm
	result  *NativeArchiveSAFResult
}

func (begin *NativeArchiveSAFBegin) Kind() NativeArchiveSAFBeginKind {
	if begin == nil {
		return 0
	}
	return begin.kind
}

func (begin *NativeArchiveSAFBegin) Session() *NativeArchiveSAFSession {
	if begin == nil || begin.kind != NativeArchiveSAFBeginSession {
		return nil
	}
	return begin.session
}

func (begin *NativeArchiveSAFBegin) ReceiptArm() *NativeArchiveSAFReceiptArm {
	if begin == nil || begin.kind != NativeArchiveSAFBeginSession {
		return nil
	}
	return begin.arm
}

func (begin *NativeArchiveSAFBegin) Result() *NativeArchiveSAFResult {
	if begin == nil || begin.kind != NativeArchiveSAFBeginTerminal {
		return nil
	}
	return begin.result
}

type nativeArchiveSAFStatus uint8

const (
	nativeArchiveSAFReceiptUnarmed nativeArchiveSAFStatus = iota + 1
	nativeArchiveSAFReady
	nativeArchiveSAFAttempted
	nativeArchiveSAFWriting
	nativeArchiveSAFPoisoned
	nativeArchiveSAFFinishing
	nativeArchiveSAFTerminal
)

type nativeArchiveSAFSessionState struct {
	mu           sync.Mutex
	cond         *sync.Cond
	status       nativeArchiveSAFStatus
	stage        *pcv3publication.Stage
	cleanupStage func(*pcv3publication.Stage) bool
	manifest     []nativeArchiveSAFManifestEntry
	current      int

	armMarker                *nativeArchiveSAFArmMarker
	attemptedEver            bool
	activeWriter             *nativeArchiveSAFOwnedWriter
	pendingEffectSettlements int
	finishingPoisoned        bool
	terminalResult           *NativeArchiveSAFResult
}

type nativeArchiveSAFOwnedWriter struct {
	destination io.WriteCloser
	closeOnce   sync.Once
	closeErr    error
}

func (writer *nativeArchiveSAFOwnedWriter) Write(data []byte) (written int, err error) {
	if writer == nil || writer.destination == nil {
		return 0, errors.New("pcv3: SAF destination unavailable")
	}
	defer func() {
		if recover() != nil {
			written = 0
			err = errors.New("pcv3: SAF destination write panic")
		}
	}()
	return writer.destination.Write(data)
}

func (writer *nativeArchiveSAFOwnedWriter) Close() (err error) {
	if writer == nil {
		return nil
	}
	writer.closeOnce.Do(func() {
		defer func() {
			if recover() != nil {
				writer.closeErr = errors.New("pcv3: SAF destination close panic")
			}
		}()
		if writer.destination == nil {
			writer.closeErr = errors.New("pcv3: SAF destination unavailable")
			return
		}
		writer.closeErr = writer.destination.Close()
	})
	return writer.closeErr
}

// NativeArchiveSAFSession copies share this exact state and cannot recover
// authority from scalar entry metadata.
type NativeArchiveSAFSession struct {
	state *nativeArchiveSAFSessionState
}

// BeginSAF consumes the same authenticated handoff used by local extraction.
// Preparation syncs and parses the sole existing Stage; it never creates a
// second plaintext file.
func (handoff *NativeArchiveHandoff) BeginSAF() (begin *NativeArchiveSAFBegin) {
	completion, stage, ok := handoff.consume()
	if !ok {
		return &NativeArchiveSAFBegin{kind: NativeArchiveSAFBeginExpired}
	}
	terminal := func() *NativeArchiveSAFBegin {
		return nativeArchiveSAFTerminalBegin(stage, false)
	}
	defer func() {
		if recover() != nil {
			begin = terminal()
		}
	}()
	if validateAuthenticatedArchive(completion, stage.File()) != nil {
		return terminal()
	}
	file := stage.File()
	info, err := file.Stat()
	if err != nil || info == nil || !info.Mode().IsRegular() || info.Size() < 0 ||
		file.Sync() != nil {
		return terminal()
	}
	reader, err := zip.NewReader(file, info.Size())
	if err != nil {
		return terminal()
	}
	manifest, err := buildNativeArchiveSAFManifest(reader.File)
	if err != nil {
		return terminal()
	}
	marker := &nativeArchiveSAFArmMarker{}
	state := &nativeArchiveSAFSessionState{
		status:       nativeArchiveSAFReceiptUnarmed,
		stage:        stage,
		cleanupStage: cleanupNativeArchiveSAFStage,
		manifest:     manifest,
		armMarker:    marker,
	}
	state.cond = sync.NewCond(&state.mu)
	session := &NativeArchiveSAFSession{state: state}
	return &NativeArchiveSAFBegin{
		kind:    NativeArchiveSAFBeginSession,
		session: session,
		arm:     &NativeArchiveSAFReceiptArm{state: state, marker: marker},
	}
}

func nativeArchiveSAFTerminalBegin(
	stage *pcv3publication.Stage,
	attemptedEver bool,
) *NativeArchiveSAFBegin {
	cleanupIncomplete := cleanupNativeArchiveSAFStage(stage)
	state := fileops.UnpackStateNotPublished
	if attemptedEver || cleanupIncomplete {
		state = fileops.UnpackStatePublicationIndeterminate
	}
	return &NativeArchiveSAFBegin{
		kind: NativeArchiveSAFBeginTerminal,
		result: &NativeArchiveSAFResult{
			state:             state,
			attemptedEver:     attemptedEver,
			cleanupIncomplete: cleanupIncomplete,
		},
	}
}

func cleanupNativeArchiveSAFStage(stage *pcv3publication.Stage) (incomplete bool) {
	if stage == nil {
		return true
	}
	defer func() {
		if recover() != nil {
			incomplete = true
		}
	}()
	return stage.Cleanup() != nil
}

func buildNativeArchiveSAFManifest(
	files []*zip.File,
) ([]nativeArchiveSAFManifestEntry, error) {
	if len(files) == 0 || len(files) > nativeArchiveSAFMaxEntries {
		return nil, errNativeArchiveSAFManifest
	}
	manifest := make([]nativeArchiveSAFManifestEntry, 0, len(files))
	byPath := make(map[string]int, len(files))
	explicitDirectories := make(map[string]struct{})
	var totalPathBytes int64
	var totalSize int64

	for _, file := range files {
		if file == nil {
			return nil, errNativeArchiveSAFManifest
		}
		modeType := file.Mode() & os.ModeType
		if modeType != 0 && modeType != os.ModeDir {
			return nil, errNativeArchiveSAFManifest
		}
		directory := modeType == os.ModeDir
		canonical, err := fileops.ParseZIPEntryPath(
			file.Name,
			directory,
			fileops.ZIPPathPortableExact,
		)
		if err != nil {
			return nil, errNativeArchiveSAFManifest
		}
		size, ok := util.SafeUint64ToInt64(file.UncompressedSize64)
		if !ok || directory && size != 0 {
			return nil, errNativeArchiveSAFManifest
		}
		if _, ok := fileops.ZIPDecompressionLimit(file.CompressedSize64); !ok {
			return nil, errNativeArchiveSAFManifest
		}
		if !directory {
			if totalSize > math.MaxInt64-size {
				return nil, errNativeArchiveSAFManifest
			}
			totalSize += size
		}

		components := strings.Split(canonical, "/")
		parentIndex := -1
		for componentIndex, component := range components {
			path := strings.Join(components[:componentIndex+1], "/")
			leaf := componentIndex == len(components)-1
			entryDirectory := !leaf || directory
			if existingIndex, exists := byPath[path]; exists {
				existing := &manifest[existingIndex]
				if existing.directory != entryDirectory {
					return nil, errNativeArchiveSAFManifest
				}
				if leaf {
					if !entryDirectory {
						return nil, errNativeArchiveSAFManifest
					}
					if _, duplicate := explicitDirectories[path]; duplicate {
						return nil, errNativeArchiveSAFManifest
					}
					explicitDirectories[path] = struct{}{}
				}
				parentIndex = existingIndex
				continue
			}
			if len(manifest) >= nativeArchiveSAFMaxEntries ||
				totalPathBytes > nativeArchiveSAFMaxPathBytes-int64(len(path)) {
				return nil, errNativeArchiveSAFManifest
			}
			totalPathBytes += int64(len(path))
			entry := nativeArchiveSAFManifestEntry{
				NativeArchiveSAFEntry: NativeArchiveSAFEntry{
					name:        component,
					parentIndex: parentIndex,
					directory:   entryDirectory,
				},
				path: path,
			}
			if leaf {
				if entryDirectory {
					explicitDirectories[path] = struct{}{}
				} else {
					entry.size = size
					entry.file = file
				}
			}
			manifest = append(manifest, entry)
			parentIndex = len(manifest) - 1
			byPath[path] = parentIndex
		}
	}
	return manifest, nil
}

func (session *NativeArchiveSAFSession) EntryCount() int {
	if session == nil || session.state == nil {
		return 0
	}
	session.state.mu.Lock()
	defer session.state.mu.Unlock()
	if session.state.status == nativeArchiveSAFTerminal {
		return 0
	}
	return len(session.state.manifest)
}

func (session *NativeArchiveSAFSession) Entry(index int) *NativeArchiveSAFEntry {
	if session == nil || session.state == nil {
		return nil
	}
	session.state.mu.Lock()
	defer session.state.mu.Unlock()
	if session.state.status == nativeArchiveSAFTerminal || index < 0 ||
		index >= len(session.state.manifest) {
		return nil
	}
	entry := session.state.manifest[index].NativeArchiveSAFEntry
	return &entry
}

func (session *NativeArchiveSAFSession) ConfirmReceiptPersisted(
	arm *NativeArchiveSAFReceiptArm,
) *NativeArchiveSAFStep {
	if session == nil || session.state == nil || arm == nil {
		return &NativeArchiveSAFStep{kind: NativeArchiveSAFStepRejected, nextIndex: -1}
	}
	state := session.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.status != nativeArchiveSAFReceiptUnarmed || arm.state != state ||
		arm.marker == nil || arm.marker != state.armMarker {
		return &NativeArchiveSAFStep{kind: NativeArchiveSAFStepRejected, nextIndex: state.current}
	}
	state.armMarker = nil
	state.status = nativeArchiveSAFReady
	return &NativeArchiveSAFStep{kind: NativeArchiveSAFStepReady, nextIndex: state.current}
}

func (session *NativeArchiveSAFSession) Attempt(index int) *NativeArchiveSAFStep {
	if session == nil || session.state == nil {
		return &NativeArchiveSAFStep{kind: NativeArchiveSAFStepRejected, nextIndex: -1}
	}
	state := session.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.status == nativeArchiveSAFReceiptUnarmed ||
		state.status == nativeArchiveSAFTerminal || state.status == nativeArchiveSAFFinishing {
		return &NativeArchiveSAFStep{kind: NativeArchiveSAFStepRejected, nextIndex: state.current}
	}
	if state.status != nativeArchiveSAFReady || index != state.current ||
		index < 0 || index >= len(state.manifest) {
		state.status = nativeArchiveSAFPoisoned
		return &NativeArchiveSAFStep{kind: NativeArchiveSAFStepPoisoned, nextIndex: state.current}
	}
	state.status = nativeArchiveSAFAttempted
	state.attemptedEver = true
	return &NativeArchiveSAFStep{kind: NativeArchiveSAFStepAttempted, nextIndex: state.current}
}

func (session *NativeArchiveSAFSession) AckDirectory(index int) *NativeArchiveSAFStep {
	if session == nil || session.state == nil {
		return &NativeArchiveSAFStep{kind: NativeArchiveSAFStepRejected, nextIndex: -1}
	}
	state := session.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.status == nativeArchiveSAFTerminal {
		return &NativeArchiveSAFStep{kind: NativeArchiveSAFStepRejected, nextIndex: state.current}
	}
	if state.status == nativeArchiveSAFFinishing {
		// A directory acknowledgement proves that a provider create call may
		// already have succeeded. Preserve that evidence while terminal cleanup
		// is outside the lock.
		state.attemptedEver = true
		state.finishingPoisoned = true
		return &NativeArchiveSAFStep{kind: NativeArchiveSAFStepPoisoned, nextIndex: state.current}
	}
	if state.status != nativeArchiveSAFAttempted || index != state.current ||
		index < 0 || index >= len(state.manifest) || !state.manifest[index].directory {
		// An acknowledgement can only follow a provider create call. Treat even
		// an out-of-order acknowledgement as evidence that an effect was possible.
		state.attemptedEver = true
		state.status = nativeArchiveSAFPoisoned
		return &NativeArchiveSAFStep{kind: NativeArchiveSAFStepPoisoned, nextIndex: state.current}
	}
	state.current++
	state.status = nativeArchiveSAFReady
	return &NativeArchiveSAFStep{kind: NativeArchiveSAFStepReady, nextIndex: state.current}
}

// Write consumes destination on every path. The exact streaming writer or a
// rejected closer settlement is registered under the state lock before any
// archive or provider I/O begins, then all I/O runs without that lock held.
func (session *NativeArchiveSAFSession) Write(
	index int,
	destination io.WriteCloser,
) *NativeArchiveSAFStep {
	owned := &nativeArchiveSAFOwnedWriter{destination: destination}
	if session == nil || session.state == nil {
		_ = owned.Close()
		return &NativeArchiveSAFStep{kind: NativeArchiveSAFStepRejected, nextIndex: -1}
	}
	state := session.state
	state.mu.Lock()
	settleRejectedWriter := func(next int) *NativeArchiveSAFStep {
		state.pendingEffectSettlements++
		state.mu.Unlock()
		_ = owned.Close()
		state.mu.Lock()
		state.pendingEffectSettlements--
		state.cond.Broadcast()
		state.mu.Unlock()
		return &NativeArchiveSAFStep{kind: NativeArchiveSAFStepPoisoned, nextIndex: next}
	}
	if state.status == nativeArchiveSAFFinishing && destination != nil {
		// Receipt of an owned provider closer is evidence of a possible create
		// or open effect. Register its settlement before closing outside the
		// mutex so the in-progress terminal operation cannot freeze stale truth.
		state.attemptedEver = true
		state.finishingPoisoned = true
		return settleRejectedWriter(state.current)
	}
	if destination == nil {
		next := state.current
		kind := NativeArchiveSAFStepRejected
		if state.status == nativeArchiveSAFAttempted {
			// Descriptor adoption failure after Attempt is an ambiguous provider
			// boundary and must never leave the entry retryable.
			state.status = nativeArchiveSAFPoisoned
			kind = NativeArchiveSAFStepPoisoned
		}
		state.mu.Unlock()
		_ = owned.Close()
		return &NativeArchiveSAFStep{kind: kind, nextIndex: next}
	}
	if state.status != nativeArchiveSAFAttempted || index != state.current ||
		index < 0 || index >= len(state.manifest) || state.manifest[index].directory ||
		state.activeWriter != nil {
		if state.status != nativeArchiveSAFTerminal && state.status != nativeArchiveSAFFinishing {
			// Receipt of a provider-owned closer means a create/open effect may
			// already have happened even if the caller violated Attempt ordering.
			state.attemptedEver = true
			state.status = nativeArchiveSAFPoisoned
		}
		next := state.current
		return settleRejectedWriter(next)
	}
	entry := state.manifest[index]
	state.activeWriter = owned
	state.status = nativeArchiveSAFWriting
	state.mu.Unlock()

	writeErr := streamNativeArchiveSAFEntry(entry, owned)
	closeErr := owned.Close()

	state.mu.Lock()
	if state.activeWriter == owned {
		state.activeWriter = nil
	}
	if writeErr == nil && closeErr == nil && state.status == nativeArchiveSAFWriting {
		state.current++
		state.status = nativeArchiveSAFReady
	} else {
		state.status = nativeArchiveSAFPoisoned
	}
	kind := NativeArchiveSAFStepPoisoned
	if state.status == nativeArchiveSAFReady {
		kind = NativeArchiveSAFStepReady
	}
	next := state.current
	state.cond.Broadcast()
	state.mu.Unlock()
	return &NativeArchiveSAFStep{kind: kind, nextIndex: next}
}

func streamNativeArchiveSAFEntry(
	entry nativeArchiveSAFManifestEntry,
	destination *nativeArchiveSAFOwnedWriter,
) (retErr error) {
	defer func() {
		if recover() != nil {
			retErr = errors.New("pcv3: SAF archive stream panic")
		}
	}()
	if entry.file == nil || entry.directory || entry.size < 0 || destination == nil {
		return errors.New("pcv3: SAF archive entry unavailable")
	}
	limit, ok := fileops.ZIPDecompressionLimit(entry.file.CompressedSize64)
	if !ok {
		return errors.New("pcv3: SAF compressed size unavailable")
	}
	source, err := entry.file.Open()
	if err != nil {
		return errors.New("pcv3: SAF archive entry open failed")
	}
	defer func() {
		if closeErr := source.Close(); closeErr != nil {
			retErr = errors.Join(retErr, errors.New("pcv3: SAF archive entry close failed"))
		}
	}()

	buffer := make([]byte, 64*util.KiB)
	var written int64
	for {
		count, readErr := source.Read(buffer)
		if count < 0 || count > len(buffer) {
			return errors.New("pcv3: SAF archive reader contract violated")
		}
		if count > 0 {
			count64 := int64(count)
			if count64 > entry.size-written || count64 > limit-written {
				return errors.New("pcv3: SAF archive expansion limit exceeded")
			}
			if err := writeNativeArchiveSAFFull(destination, buffer[:count]); err != nil {
				return err
			}
			written += count64
		}
		switch {
		case readErr == io.EOF:
			if written != entry.size {
				return io.ErrUnexpectedEOF
			}
			return nil
		case readErr != nil:
			return errors.New("pcv3: SAF archive entry verification failed")
		case count == 0:
			return io.ErrNoProgress
		}
	}
}

func writeNativeArchiveSAFFull(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := writer.Write(data)
		if written < 0 || written > len(data) {
			return errors.New("pcv3: SAF writer contract violated")
		}
		data = data[written:]
		if err != nil {
			return errors.New("pcv3: SAF provider write failed")
		}
		if written == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

// Cancel is idempotent and closes only the exact writer currently owned by
// this session. Close runs outside the session lock because provider closers
// may block.
func (session *NativeArchiveSAFSession) Cancel() *NativeArchiveSAFStep {
	if session == nil || session.state == nil {
		return &NativeArchiveSAFStep{kind: NativeArchiveSAFStepRejected, nextIndex: -1}
	}
	state := session.state
	state.mu.Lock()
	if state.status == nativeArchiveSAFTerminal || state.status == nativeArchiveSAFFinishing {
		next := state.current
		state.mu.Unlock()
		return &NativeArchiveSAFStep{kind: NativeArchiveSAFStepRejected, nextIndex: next}
	}
	state.status = nativeArchiveSAFPoisoned
	writer := state.activeWriter
	next := state.current
	state.mu.Unlock()
	if writer != nil {
		_ = writer.Close()
	}
	return &NativeArchiveSAFStep{kind: NativeArchiveSAFStepPoisoned, nextIndex: next}
}

func (session *NativeArchiveSAFSession) AttemptedEver() bool {
	if session == nil || session.state == nil {
		return false
	}
	session.state.mu.Lock()
	defer session.state.mu.Unlock()
	return session.state.attemptedEver
}

func (session *NativeArchiveSAFSession) Abort() *NativeArchiveSAFResult {
	if session == nil || session.state == nil {
		return nil
	}
	state := session.state
	state.mu.Lock()
	for state.status == nativeArchiveSAFFinishing || state.activeWriter != nil {
		state.cond.Wait()
	}
	if state.status == nativeArchiveSAFTerminal {
		result := state.terminalResult
		state.mu.Unlock()
		return result
	}
	state.status = nativeArchiveSAFFinishing
	stage := state.stage
	state.stage = nil
	cleanupStage := state.cleanupStage
	state.cleanupStage = nil
	state.mu.Unlock()

	if cleanupStage == nil {
		cleanupStage = cleanupNativeArchiveSAFStage
	}
	cleanupIncomplete := cleanupStage(stage)
	state.mu.Lock()
	for state.pendingEffectSettlements != 0 {
		state.cond.Wait()
	}
	attemptedEver := state.attemptedEver
	publicationState := fileops.UnpackStateNotPublished
	if attemptedEver || cleanupIncomplete || state.finishingPoisoned {
		publicationState = fileops.UnpackStatePublicationIndeterminate
	}
	result := &NativeArchiveSAFResult{
		state:             publicationState,
		attemptedEver:     attemptedEver,
		cleanupIncomplete: cleanupIncomplete,
	}
	state.status = nativeArchiveSAFTerminal
	state.manifest = nil
	state.terminalResult = result
	state.cond.Broadcast()
	state.mu.Unlock()
	return result
}

// Finish is valid only after every manifest entry has been acknowledged. SAF
// has no directory durability primitive, so even a complete export cannot
// return PublishedDurable.
func (session *NativeArchiveSAFSession) Finish() *NativeArchiveSAFResult {
	if session == nil || session.state == nil {
		return nil
	}
	state := session.state
	state.mu.Lock()
	for state.status == nativeArchiveSAFFinishing {
		state.cond.Wait()
	}
	if state.status == nativeArchiveSAFTerminal {
		result := state.terminalResult
		state.mu.Unlock()
		return result
	}
	if state.status != nativeArchiveSAFReady || state.current != len(state.manifest) ||
		state.activeWriter != nil {
		state.status = nativeArchiveSAFPoisoned
		state.mu.Unlock()
		return session.Abort()
	}
	state.status = nativeArchiveSAFFinishing
	stage := state.stage
	state.stage = nil
	cleanupStage := state.cleanupStage
	state.cleanupStage = nil
	state.mu.Unlock()

	if cleanupStage == nil {
		cleanupStage = cleanupNativeArchiveSAFStage
	}
	cleanupIncomplete := cleanupStage(stage)
	state.mu.Lock()
	for state.pendingEffectSettlements != 0 {
		state.cond.Wait()
	}
	attemptedEver := state.attemptedEver
	publicationState := fileops.UnpackStatePublishedDurabilityUncertain
	if state.finishingPoisoned {
		publicationState = fileops.UnpackStatePublicationIndeterminate
	}
	result := &NativeArchiveSAFResult{
		state:             publicationState,
		attemptedEver:     attemptedEver,
		cleanupIncomplete: cleanupIncomplete,
	}
	state.status = nativeArchiveSAFTerminal
	state.manifest = nil
	state.terminalResult = result
	state.cond.Broadcast()
	state.mu.Unlock()
	return result
}
