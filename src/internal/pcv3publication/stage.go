package pcv3publication

import (
	"Picocrypt-NG/internal/fileops"
	pcv3 "Picocrypt-NG/internal/pcv3result"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const stageNamePrefix = ".picocrypt-pcv3-"

// ErrCleanupIncomplete reports that absence of operation-owned publication
// residue was not proven. It does not claim that residue is present or that a
// proven publication did or did not occur.
var ErrCleanupIncomplete = errors.New("pcv3 publication: cleanup incomplete")

type platformOperations struct {
	atomicPublish       func(*os.File, string, string, Policy) error
	syncDirectory       func(*os.File) error
	syncStage           func(*os.File) error
	closeStage          func(*os.File) error
	statStage           func(*os.File) (os.FileInfo, error)
	openRetained        func(*os.Root, string) (*os.File, error)
	removeStage         func(*os.Root, string) error
	supportsSafeReplace bool
}

type cleanupDisposition uint8

const (
	cleanupUncertain cleanupDisposition = iota
	cleanupOwned
	cleanupPublishedOwned
	cleanupNotRequired
)

// Stage owns one private sibling staging file and the pinned directory handles
// needed to publish it. It has no source-deletion authority.
type Stage struct {
	file       *os.File
	root       *os.Root
	parent     *os.File
	rootInfo   os.FileInfo
	stageInfo  os.FileInfo
	targetInfo os.FileInfo

	parentPath string
	stagePath  string
	stageName  string
	targetName string
	protected  []string

	policy     Policy
	operations platformOperations
	terminal   Result

	cleanupDisposition cleanupDisposition
	cleanupMayRemain   bool
	cleanupDone        bool
	cleanupErr         error
	retentionAttempted bool
}

// Create validates a publication request and creates its private stage through
// the native fail-closed platform operations.
func Create(target string, protected []string, policy Policy) (*Stage, error) {
	return createWithOperations(target, protected, policy, nativeOperations())
}

func createWithOperations(
	target string,
	protected []string,
	policy Policy,
	operations platformOperations,
) (*Stage, error) {
	if policy != PolicyNoReplace && policy != PolicySafeReplace {
		return nil, newResult(StateNotPublished, pcv3.StageOutputPublication, CodeInvalidRequest)
	}
	if operations.atomicPublish == nil || operations.syncDirectory == nil {
		return nil, newResult(StateNotPublished, pcv3.StageOutputPublication, CodePolicyUnsupported)
	}
	if operations.syncStage == nil {
		operations.syncStage = (*os.File).Sync
	}
	if operations.closeStage == nil {
		operations.closeStage = (*os.File).Close
	}
	if operations.statStage == nil {
		operations.statStage = (*os.File).Stat
	}
	if operations.openRetained == nil {
		operations.openRetained = (*os.Root).Open
	}
	if operations.removeStage == nil {
		operations.removeStage = (*os.Root).Remove
	}
	if policy == PolicySafeReplace && !operations.supportsSafeReplace {
		return nil, newResult(StateNotPublished, pcv3.StageOutputPublication, CodePolicyUnsupported)
	}
	if target == "" {
		return nil, newResult(StateNotPublished, pcv3.StageOutputPublication, CodeInvalidRequest)
	}

	absoluteTarget, err := filepath.Abs(filepath.Clean(target))
	if err != nil {
		return nil, newResult(StateNotPublished, pcv3.StageOutputPublication, CodeInvalidRequest)
	}
	targetName := filepath.Base(absoluteTarget)
	if targetName == "" || targetName == "." || targetName == string(filepath.Separator) {
		return nil, newResult(StateNotPublished, pcv3.StageOutputPublication, CodeInvalidRequest)
	}
	protectedPaths := make([]string, 0, len(protected))
	for _, protectedPath := range protected {
		if protectedPath == "" {
			return nil, newResult(StateNotPublished, pcv3.StageOutputPublication, CodeInvalidRequest)
		}
		absoluteProtected, pathErr := filepath.Abs(filepath.Clean(protectedPath))
		if pathErr != nil {
			return nil, newResult(StateNotPublished, pcv3.StageOutputPublication, CodeInvalidRequest)
		}
		alias, aliasErr := fileops.SamePathOrFile(absoluteTarget, absoluteProtected)
		if aliasErr != nil || alias {
			return nil, newResult(StateNotPublished, pcv3.StageOutputPublication, CodeInvalidRequest)
		}
		protectedPaths = append(protectedPaths, absoluteProtected)
	}

	parentPath := filepath.Dir(absoluteTarget)
	root, err := os.OpenRoot(parentPath)
	if err != nil {
		return nil, newResult(StateNotPublished, pcv3.StageOutputPublication, CodeStageFailure)
	}
	rootInfo, err := root.Stat(".")
	if err != nil {
		_ = root.Close()
		return nil, newResult(StateNotPublished, pcv3.StageOutputPublication, CodeStageFailure)
	}
	parent, err := root.Open(".")
	if err != nil {
		_ = root.Close()
		return nil, newResult(StateNotPublished, pcv3.StageOutputPublication, CodeStageFailure)
	}
	parentInfo, err := parent.Stat()
	if err != nil || !os.SameFile(rootInfo, parentInfo) {
		_ = parent.Close()
		_ = root.Close()
		return nil, newResult(StateNotPublished, pcv3.StageOutputPublication, CodeStageFailure)
	}
	currentParent, err := os.Stat(parentPath)
	if err != nil || !os.SameFile(rootInfo, currentParent) {
		_ = parent.Close()
		_ = root.Close()
		return nil, newResult(StateNotPublished, pcv3.StageOutputPublication, CodeIdentityChanged)
	}

	targetInfo, targetErr := root.Lstat(targetName)
	switch policy {
	case PolicyNoReplace:
		if targetErr == nil {
			_ = parent.Close()
			_ = root.Close()
			return nil, newResult(StateNotPublished, pcv3.StageOutputPublication, CodeDestinationExists)
		}
		if !errors.Is(targetErr, os.ErrNotExist) {
			_ = parent.Close()
			_ = root.Close()
			return nil, newResult(StateNotPublished, pcv3.StageOutputPublication, CodeStageFailure)
		}
		targetInfo = nil
	case PolicySafeReplace:
		if targetErr != nil || !targetInfo.Mode().IsRegular() {
			_ = parent.Close()
			_ = root.Close()
			return nil, newResult(StateNotPublished, pcv3.StageOutputPublication, CodeInvalidRequest)
		}
	}

	stageName := stageNamePrefix + rand.Text()
	file, err := root.OpenFile(stageName, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		_ = parent.Close()
		_ = root.Close()
		return nil, newResult(StateNotPublished, pcv3.StageOutputPublication, CodeStageFailure)
	}
	stageInfo, err := operations.statStage(file)
	if err != nil || stageInfo == nil || !stageInfo.Mode().IsRegular() {
		_ = file.Close()
		_ = parent.Close()
		_ = root.Close()
		return nil, errors.Join(
			newResult(StateNotPublished, pcv3.StageOutputPublication, CodeStageFailure),
			ErrCleanupIncomplete,
		)
	}

	stage := &Stage{
		file:               file,
		root:               root,
		parent:             parent,
		rootInfo:           rootInfo,
		stageInfo:          stageInfo,
		targetInfo:         targetInfo,
		parentPath:         parentPath,
		stagePath:          filepath.Join(parentPath, stageName),
		stageName:          stageName,
		targetName:         targetName,
		protected:          protectedPaths,
		policy:             policy,
		operations:         operations,
		cleanupDisposition: cleanupOwned,
	}
	if !stage.parentIdentityCurrent() {
		result := newResult(StateNotPublished, pcv3.StageOutputPublication, CodeIdentityChanged)
		if cleanupErr := stage.Cleanup(); cleanupErr != nil {
			return nil, errors.Join(result, cleanupErr)
		}
		return nil, result
	}
	return stage, nil
}

// File returns the original open stage handle while it remains writable.
func (stage *Stage) File() *os.File {
	if stage == nil {
		return nil
	}
	return stage.file
}

// Publish finalizes the stage, invokes the one platform atomic operation, and
// reports the identity-proven terminal state. Repeated calls return the same
// result without repeating filesystem effects.
func (stage *Stage) Publish(ctx context.Context) Result {
	if stage == nil {
		return newResult(StateNotPublished, pcv3.StageOutputPublication, CodeInvalidRequest)
	}
	if stage.terminal != nil {
		return stage.terminal
	}
	if ctx == nil || stage.file == nil || stage.root == nil || stage.parent == nil {
		return stage.finish(StateNotPublished, pcv3.StageOutputPublication, CodeInvalidRequest)
	}
	if ctx.Err() != nil {
		return stage.finish(StateNotPublished, pcv3.StageCancellation, CodeCancelled)
	}
	if err := stage.operations.syncStage(stage.file); err != nil {
		return stage.finish(StateNotPublished, pcv3.StageOutputPublication, CodeStageFailure)
	}
	if ctx.Err() != nil {
		return stage.finish(StateNotPublished, pcv3.StageCancellation, CodeCancelled)
	}
	if err := stage.operations.closeStage(stage.file); err != nil {
		stage.file = nil
		return stage.finish(StateNotPublished, pcv3.StageOutputPublication, CodeStageFailure)
	}
	stage.file = nil
	if ctx.Err() != nil {
		return stage.finish(StateNotPublished, pcv3.StageCancellation, CodeCancelled)
	}
	if !stage.parentIdentityCurrent() || !stage.stageIdentityCurrent() {
		return stage.finish(StateNotPublished, pcv3.StageOutputPublication, CodeIdentityChanged)
	}
	if code := stage.targetIdentityCode(); code != 0 {
		return stage.finish(StateNotPublished, pcv3.StageOutputPublication, code)
	}
	if ctx.Err() != nil {
		return stage.finish(StateNotPublished, pcv3.StageCancellation, CodeCancelled)
	}
	// This is the last safe userspace check before the platform atomic call. It
	// blocks aliases visible at this boundary, but cannot promise safety against
	// a hostile process racing namespace changes after the check.
	if stage.protectedStageAliasUncertain() {
		return stage.finish(StateNotPublished, pcv3.StageOutputPublication, CodeIdentityChanged)
	}

	atomicErr := stage.operations.atomicPublish(
		stage.parent,
		stage.stageName,
		stage.targetName,
		stage.policy,
	)
	classification, stageStillOwned := stage.classifyAfterAtomic()
	if atomicErr == nil && classification != atomicCommitted {
		if stageStillOwned {
			stage.cleanupDisposition = cleanupOwned
		} else {
			stage.cleanupDisposition = cleanupUncertain
		}
		return stage.finish(
			StatePublicationIndeterminate,
			pcv3.StageOutputPublication,
			CodePublicationIndeterminate,
		)
	}

	switch classification {
	case atomicCommitted:
		stage.cleanupDisposition = cleanupNotRequired
		if err := stage.operations.syncDirectory(stage.parent); err != nil {
			return stage.finish(
				StatePublishedDurabilityUncertain,
				pcv3.StageDirectorySync,
				CodeDurabilityUncertain,
			)
		}
		return stage.finish(StatePublishedDurable, pcv3.StageNone, CodePublishedDurable)
	case atomicNotCommitted:
		stage.cleanupDisposition = cleanupOwned
		return stage.finish(StateNotPublished, pcv3.StageOutputPublication, CodeAtomicFailed)
	default:
		if stageStillOwned {
			stage.cleanupDisposition = cleanupOwned
		} else {
			stage.cleanupDisposition = cleanupUncertain
		}
		return stage.finish(
			StatePublicationIndeterminate,
			pcv3.StageOutputPublication,
			CodePublicationIndeterminate,
		)
	}
}

// PublishRetained performs the same publication as Publish and transfers an
// opaque exact-file owner only after durable publication is proven. Failure to
// establish the post-publication identity grants no capability and immediately
// removes the exact published file; any cleanup uncertainty is terminal.
func (stage *Stage) PublishRetained(ctx context.Context) (Result, *RetainedFile) {
	if stage != nil && stage.retentionAttempted {
		return stage.terminal, nil
	}
	if stage != nil {
		stage.retentionAttempted = true
	}
	publication := stage.Publish(ctx)
	if publication == nil || publication.State() != StatePublishedDurable {
		return publication, nil
	}
	retained := stage.takeRetainedFile()
	if retained == nil {
		// A prior Cleanup may already have closed every pinned handle after an
		// ordinary durable Publish. Preserve that durable truth; no exact cleanup
		// authority remains from which a retained capability could be minted.
		if stage.cleanupDone {
			return publication, nil
		}
		stage.cleanupDisposition = cleanupPublishedOwned
		if cleanupErr := stage.Cleanup(); cleanupErr != nil {
			stage.terminal = newResult(
				StatePublicationIndeterminate,
				pcv3.StageOutputPublication,
				CodePublicationIndeterminate,
			)
		} else {
			stage.terminal = newResult(
				StateNotPublished,
				pcv3.StageOutputPublication,
				CodeStageFailure,
			)
		}
		return stage.terminal, nil
	}
	return publication, retained
}

func (stage *Stage) takeRetainedFile() *RetainedFile {
	if stage == nil || stage.terminal == nil ||
		stage.terminal.State() != StatePublishedDurable || stage.file != nil ||
		stage.root == nil || stage.parent == nil || stage.stageInfo == nil ||
		stage.targetName == "" || stage.operations.removeStage == nil ||
		stage.operations.openRetained == nil || stage.operations.syncDirectory == nil ||
		!stage.parentIdentityCurrent() ||
		probeIdentity(stage.root, stage.targetName, stage.stageInfo) != identityExpected {
		return nil
	}

	file, err := stage.operations.openRetained(stage.root, stage.targetName)
	if err != nil {
		return nil
	}
	info, err := file.Stat()
	if err != nil || info == nil || !info.Mode().IsRegular() ||
		!os.SameFile(stage.stageInfo, info) ||
		probeIdentity(stage.root, stage.targetName, stage.stageInfo) != identityExpected {
		_ = file.Close()
		return nil
	}

	retained := &RetainedFile{
		file:          file,
		root:          stage.root,
		parent:        stage.parent,
		identity:      stage.stageInfo,
		targetName:    stage.targetName,
		remove:        stage.operations.removeStage,
		syncDirectory: stage.operations.syncDirectory,
		active:        true,
	}
	stage.root = nil
	stage.parent = nil
	stage.rootInfo = nil
	stage.stageInfo = nil
	stage.targetInfo = nil
	stage.parentPath = ""
	stage.stagePath = ""
	stage.stageName = ""
	stage.targetName = ""
	stage.protected = nil
	stage.cleanupDisposition = cleanupNotRequired
	stage.cleanupDone = true
	return retained
}

func (stage *Stage) finish(state State, failureStage pcv3.Stage, code Code) Result {
	stage.terminal = newResult(state, failureStage, code)
	return stage.terminal
}

func (stage *Stage) parentIdentityCurrent() bool {
	if stage == nil || stage.parent == nil || stage.rootInfo == nil {
		return false
	}
	pinned, err := stage.parent.Stat()
	if err != nil || !os.SameFile(stage.rootInfo, pinned) {
		return false
	}
	current, err := os.Stat(stage.parentPath)
	return err == nil && os.SameFile(stage.rootInfo, current)
}

func (stage *Stage) stageIdentityCurrent() bool {
	if stage == nil || stage.root == nil || stage.stageInfo == nil || stage.stageName == "" {
		return false
	}
	current, err := stage.root.Lstat(stage.stageName)
	return err == nil && current.Mode().IsRegular() && os.SameFile(stage.stageInfo, current)
}

func (stage *Stage) targetIdentityCode() Code {
	current, err := stage.root.Lstat(stage.targetName)
	switch stage.policy {
	case PolicyNoReplace:
		if errors.Is(err, os.ErrNotExist) {
			return 0
		}
		if err == nil {
			return CodeDestinationExists
		}
		return CodeStageFailure
	case PolicySafeReplace:
		if err != nil || stage.targetInfo == nil || !current.Mode().IsRegular() ||
			!os.SameFile(stage.targetInfo, current) {
			return CodeIdentityChanged
		}
		return 0
	default:
		return CodeInvalidRequest
	}
}

func (stage *Stage) protectedStageAliasUncertain() bool {
	if stage == nil || stage.stagePath == "" {
		if stage != nil {
			stage.cleanupMayRemain = true
		}
		return true
	}
	for _, protectedPath := range stage.protected {
		alias, err := fileops.SamePathOrFile(stage.stagePath, protectedPath)
		if err != nil || alias {
			// Cleanup may remove only the operation-owned stage name. An alias or
			// an uninspectable protected name prevents proving that no ciphertext
			// remains reachable elsewhere.
			stage.cleanupMayRemain = true
			return true
		}
	}
	return false
}

type atomicClassification uint8

const (
	atomicIndeterminate atomicClassification = iota
	atomicNotCommitted
	atomicCommitted
)

type identityProbe uint8

const (
	identityUnknown identityProbe = iota
	identityMissing
	identityExpected
	identityOther
)

func (stage *Stage) classifyAfterAtomic() (atomicClassification, bool) {
	stageProbe := probeIdentity(stage.root, stage.stageName, stage.stageInfo)
	targetProbe := probeIdentity(stage.root, stage.targetName, stage.stageInfo)
	stageStillOwned := stageProbe == identityExpected

	if targetProbe == identityExpected && stageProbe != identityExpected {
		return atomicCommitted, false
	}
	if stageProbe == identityExpected && targetProbe != identityExpected &&
		targetProbe != identityUnknown {
		return atomicNotCommitted, true
	}
	return atomicIndeterminate, stageStillOwned && targetProbe != identityExpected
}

func probeIdentity(root *os.Root, name string, expected os.FileInfo) identityProbe {
	if root == nil || name == "" || expected == nil {
		return identityUnknown
	}
	current, err := root.Lstat(name)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return identityMissing
	case err != nil:
		return identityUnknown
	case current.Mode().IsRegular() && os.SameFile(expected, current):
		return identityExpected
	default:
		return identityOther
	}
}

// Cleanup closes retained handles and removes only the exact operation-owned
// stage when publication state permits it. A missing, replaced, or
// uninspectable cleanup-required pathname is uncertainty, not proof that the
// owned plaintext is absent, and the observed pathname is left untouched.
func (stage *Stage) Cleanup() error {
	if stage == nil {
		return nil
	}
	if stage.cleanupDone {
		return stage.cleanupErr
	}
	stage.cleanupDone = true
	cleanupFailed := false

	if stage.file != nil {
		if err := stage.file.Close(); err != nil {
			cleanupFailed = true
		}
		stage.file = nil
	}
	if stage.cleanupDisposition == cleanupUncertain && stage.stageName != "" {
		cleanupFailed = true
	}
	if stage.cleanupDisposition == cleanupOwned {
		// Publication can fail before the precommit check. Probe again before
		// removing the owned name so cleanup never claims all ciphertext is gone
		// while a protected alias may still retain it.
		stage.protectedStageAliasUncertain()
		if stage.root == nil || stage.stageName == "" || stage.stageInfo == nil ||
			stage.operations.removeStage == nil {
			cleanupFailed = true
		} else {
			switch probeIdentity(stage.root, stage.stageName, stage.stageInfo) {
			case identityExpected:
				if err := stage.operations.removeStage(stage.root, stage.stageName); err != nil {
					cleanupFailed = true
				}
			case identityMissing, identityOther, identityUnknown:
				cleanupFailed = true
			}
		}
	}
	if stage.cleanupDisposition == cleanupPublishedOwned {
		if stage.root == nil || stage.targetName == "" || stage.stageInfo == nil ||
			stage.operations.removeStage == nil || stage.operations.syncDirectory == nil {
			cleanupFailed = true
		} else {
			switch probeIdentity(stage.root, stage.targetName, stage.stageInfo) {
			case identityExpected:
				if err := stage.operations.removeStage(stage.root, stage.targetName); err != nil {
					cleanupFailed = true
				} else if stage.parent == nil ||
					stage.operations.syncDirectory(stage.parent) != nil {
					cleanupFailed = true
				}
			case identityMissing, identityOther, identityUnknown:
				cleanupFailed = true
			}
		}
	}
	if stage.cleanupMayRemain {
		cleanupFailed = true
	}
	if stage.parent != nil {
		if err := stage.parent.Close(); err != nil {
			cleanupFailed = true
		}
		stage.parent = nil
	}
	if stage.root != nil {
		if err := stage.root.Close(); err != nil {
			cleanupFailed = true
		}
		stage.root = nil
	}
	stage.rootInfo = nil
	stage.stageInfo = nil
	stage.targetInfo = nil
	stage.protected = nil
	if cleanupFailed {
		stage.cleanupErr = ErrCleanupIncomplete
	}
	return stage.cleanupErr
}

func (stage *Stage) String() string {
	return "pcv3 publication stage"
}

func (stage *Stage) GoString() string {
	return stage.String()
}

func (stage *Stage) Format(state fmt.State, verb rune) {
	writeFixedFormat(state, verb, stage.String())
}
