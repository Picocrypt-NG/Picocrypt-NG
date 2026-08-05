package pcv3publication

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const stageNamePrefix = ".picocrypt-pcv3-"

// ErrCleanupIncomplete reports retained publication residue without claiming
// that a proven publication did or did not occur.
var ErrCleanupIncomplete = errors.New("pcv3 publication: cleanup incomplete")

type platformOperations struct {
	atomicPublish       func(*os.File, string, string, Policy) error
	syncDirectory       func(*os.File) error
	supportsSafeReplace bool
}

// The native build-tagged implementation replaces this fail-closed zero value
// in the platform task. Until then, Create cannot perform filesystem effects.
var defaultOperations platformOperations

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

	policy     Policy
	operations platformOperations
	terminal   Result

	cleanupAllowed bool
	cleanupDone    bool
	cleanupErr     error
}

// Create validates a publication request and creates its private stage through
// the native fail-closed platform operations.
func Create(target string, protected []string, policy Policy) (*Stage, error) {
	return createWithOperations(target, protected, policy, defaultOperations)
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
	for _, protectedPath := range protected {
		if protectedPath == "" {
			return nil, newResult(StateNotPublished, pcv3.StageOutputPublication, CodeInvalidRequest)
		}
		alias, aliasErr := fileops.SamePathOrFile(absoluteTarget, protectedPath)
		if aliasErr != nil || alias {
			return nil, newResult(StateNotPublished, pcv3.StageOutputPublication, CodeInvalidRequest)
		}
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
	stageInfo, err := file.Stat()
	if err != nil || !stageInfo.Mode().IsRegular() {
		_ = file.Close()
		_ = parent.Close()
		_ = root.Close()
		return nil, newResult(StateNotPublished, pcv3.StageOutputPublication, CodeStageFailure)
	}

	stage := &Stage{
		file:           file,
		root:           root,
		parent:         parent,
		rootInfo:       rootInfo,
		stageInfo:      stageInfo,
		targetInfo:     targetInfo,
		parentPath:     parentPath,
		stagePath:      filepath.Join(parentPath, stageName),
		stageName:      stageName,
		targetName:     targetName,
		policy:         policy,
		operations:     operations,
		cleanupAllowed: true,
	}
	if !stage.parentIdentityCurrent() {
		_ = stage.Cleanup()
		return nil, newResult(StateNotPublished, pcv3.StageOutputPublication, CodeIdentityChanged)
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
	if err := stage.file.Sync(); err != nil {
		return stage.finish(StateNotPublished, pcv3.StageOutputPublication, CodeStageFailure)
	}
	if ctx.Err() != nil {
		return stage.finish(StateNotPublished, pcv3.StageCancellation, CodeCancelled)
	}
	if err := stage.file.Close(); err != nil {
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

	atomicErr := stage.operations.atomicPublish(
		stage.parent,
		stage.stageName,
		stage.targetName,
		stage.policy,
	)
	classification, stageStillOwned := stage.classifyAfterAtomic()
	if atomicErr == nil && classification != atomicCommitted {
		stage.cleanupAllowed = false
		return stage.finish(
			StatePublicationIndeterminate,
			pcv3.StageOutputPublication,
			CodePublicationIndeterminate,
		)
	}

	switch classification {
	case atomicCommitted:
		stage.cleanupAllowed = false
		if err := stage.operations.syncDirectory(stage.parent); err != nil {
			return stage.finish(
				StatePublishedDurabilityUncertain,
				pcv3.StageDirectorySync,
				CodeDurabilityUncertain,
			)
		}
		return stage.finish(StatePublishedDurable, pcv3.StageNone, CodePublishedDurable)
	case atomicNotCommitted:
		stage.cleanupAllowed = true
		return stage.finish(StateNotPublished, pcv3.StageOutputPublication, CodeAtomicFailed)
	default:
		stage.cleanupAllowed = stageStillOwned
		return stage.finish(
			StatePublicationIndeterminate,
			pcv3.StageOutputPublication,
			CodePublicationIndeterminate,
		)
	}
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
// stage when publication state permits it. It never removes a replacement path.
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
	if stage.cleanupAllowed && stage.root != nil && stage.stageName != "" {
		switch probeIdentity(stage.root, stage.stageName, stage.stageInfo) {
		case identityExpected:
			if err := stage.root.Remove(stage.stageName); err != nil {
				remaining := probeIdentity(stage.root, stage.stageName, stage.stageInfo)
				if remaining == identityExpected || remaining == identityUnknown {
					cleanupFailed = true
				}
			}
		case identityUnknown:
			cleanupFailed = true
		}
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
