package pcv3operation

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3"
	"Picocrypt-NG/internal/pcv3publication"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// ArchiveAction selects what happens to an authenticated archive. The default
// preserves the reader's existing behavior: Normal archives remain pending,
// while D1 reads publish a file unless archive preparation is requested.
type ArchiveAction uint8

// ArchiveSummary describes the validated, fully authenticated ZIP to extract.
type ArchiveSummary = fileops.ZIPSummary

const (
	ArchiveDefault ArchiveAction = iota
	ArchiveSave
	ArchivePrepare
	ArchiveExtract
	ArchiveExtractSameLevel
)

type archiveReadPlan struct {
	action          ArchiveAction
	parentRoot      *os.Root
	parentDirectory *os.File
	parentInfo      os.FileInfo
	parentPath      string
	directoryName   string
	review          func(context.Context, ArchiveSummary) error
}

// newArchiveReadPlan pins extraction destinations before credential work. It
// does not create a directory or grant authority to read or publish plaintext.
func newArchiveReadPlan(action ArchiveAction, target string) (_ *archiveReadPlan, err error) {
	if action > ArchiveExtractSameLevel {
		return nil, os.ErrInvalid
	}
	if action == ArchiveDefault || action == ArchivePrepare {
		return nil, nil
	}
	plan := &archiveReadPlan{action: action}
	if action == ArchiveSave {
		return plan, nil
	}
	defer func() {
		if err != nil && plan.close() {
			err = errors.Join(err, pcv3publication.ErrCleanupIncomplete)
		}
	}()
	if target == "" {
		return nil, os.ErrInvalid
	}
	absoluteTarget, err := filepath.Abs(filepath.Clean(target))
	if err != nil {
		return nil, err
	}
	plan.parentPath = filepath.Dir(absoluteTarget)
	plan.directoryName = filepath.Base(absoluteTarget)
	if strings.EqualFold(filepath.Ext(plan.directoryName), ".zip") {
		plan.directoryName = plan.directoryName[:len(plan.directoryName)-len(".zip")]
	}
	if action == ArchiveExtract && (plan.directoryName == "" || plan.directoryName == "." ||
		plan.directoryName == ".." || plan.directoryName == string(filepath.Separator)) {
		return nil, os.ErrInvalid
	}
	plan.parentRoot, err = fileops.OpenRootNoSymlink(plan.parentPath)
	if err != nil {
		return nil, err
	}
	plan.parentInfo, err = plan.parentRoot.Stat(".")
	if err != nil {
		return nil, err
	}
	plan.parentDirectory, err = plan.parentRoot.Open(".")
	if err != nil {
		return nil, err
	}
	opened, err := plan.parentDirectory.Stat()
	if err != nil || opened == nil || !os.SameFile(plan.parentInfo, opened) {
		return nil, errors.Join(os.ErrInvalid, err)
	}
	if !plan.parentUnchanged() {
		return nil, os.ErrInvalid
	}
	if action == ArchiveExtract {
		_, err = plan.parentRoot.Lstat(plan.directoryName)
		if !errors.Is(err, os.ErrNotExist) {
			return nil, errors.Join(os.ErrExist, err)
		}
	}
	return plan, nil
}

func (plan *archiveReadPlan) apply(ctx context.Context, read *Result) (result *Result) {
	if plan == nil || plan.action == ArchiveDefault || plan.action == ArchivePrepare {
		return read
	}
	followUp := read.ArchiveFollowUp()
	if followUp == nil {
		return read
	}
	defer func() {
		if result != nil {
			result.authenticatedComment = read.authenticatedComment
			result.forceProvenance = read.forceProvenance
			result.d1BootstrapProvenance = read.d1BootstrapProvenance
			result.detailStage = read.detailStage
			for _, warning := range read.Warnings() {
				result.appendWarning(warning)
			}
		}
	}()
	if plan.action == ArchiveSave {
		return followUp.Publish(ctx)
	}
	if ctx == nil || ctx.Err() != nil || !plan.parentUnchanged() {
		return plan.reject(ctx, followUp)
	}

	if err := AdmitZIPWorkingMemory(ctx, fileops.NewZIPResourceBudget()); err != nil {
		closed := followUp.Close()
		result = archiveWorkingMemoryRefusal(ctx, closed == nil)
		if closed != nil {
			for _, warning := range closed.Warnings() {
				result.appendWarning(warning)
			}
		}
		return result
	}

	name := "."
	expected := plan.parentInfo
	if plan.action == ArchiveExtract {
		name = plan.directoryName
		if err := plan.parentRoot.Mkdir(name, 0o700); err != nil {
			return plan.reject(ctx, followUp)
		}
		var err error
		expected, err = plan.parentRoot.Lstat(name)
		if err != nil || expected == nil || !expected.IsDir() || expected.Mode()&os.ModeSymlink != 0 {
			result = plan.reject(ctx, followUp)
			result.appendWarning(WarningCleanupIncomplete)
			return result
		}
		defer func() {
			// Never remove published, uncertain, or warning-bearing output. Even
			// on a clean failure, Remove only accepts the same empty directory.
			if result != nil && result.warningCount == 0 &&
				(!result.publicationAttempted || result.publicationState == pcv3publication.StateNotPublished) {
				if !plan.removeEmptyDirectory(expected) {
					result.appendWarning(WarningCleanupIncomplete)
				}
			}
		}()
	}

	root, err := plan.parentRoot.OpenRoot(name)
	if err != nil {
		return plan.reject(ctx, followUp)
	}
	opened, statErr := root.Stat(".")
	current, pathErr := plan.parentRoot.Lstat(name)
	if statErr != nil || pathErr != nil || opened == nil || current == nil ||
		!current.IsDir() || current.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(expected, opened) || !os.SameFile(expected, current) || !plan.parentUnchanged() {
		result = plan.reject(ctx, followUp)
		if closeExtractionRoot(root) {
			result.appendWarning(WarningCleanupIncomplete)
		}
		return result
	}
	// Extract owns root from this point and consumes only the already-held,
	// fully authenticated archive descriptor.
	var review func(fileops.ZIPSummary) error
	if plan.review != nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(ctx)
		defer cancel()
		review = func(summary fileops.ZIPSummary) error {
			err := plan.review(ctx, summary)
			if errors.Is(err, context.Canceled) {
				cancel()
			}
			return err
		}
	}
	result = followUp.extract(ctx, root, review)
	if plan.action == ArchiveExtract && result.PublicationState() != pcv3publication.StateNotPublished {
		if fileops.SyncDirectory(plan.parentDirectory) != nil &&
			result.PublicationState() == pcv3publication.StatePublishedDurable {
			result.publicationState = pcv3publication.StatePublishedDurabilityUncertain
			result.publicationStage = pcv3.StageDirectorySync
			result.publicationCode = pcv3publication.CodeDurabilityUncertain
			result.appendWarning(WarningDurabilityUncertain)
		}
	}
	return result
}

func (plan *archiveReadPlan) reject(ctx context.Context, followUp *ArchiveFollowUp) *Result {
	result := followUp.Close()
	result.diagnostic = DiagnosticInvalidRequest
	if ctx != nil && ctx.Err() != nil {
		result.stage = pcv3.StageCancellation
		result.diagnostic = DiagnosticCancellation
		result.cancellationDeadline = errors.Is(ctx.Err(), context.DeadlineExceeded)
	}
	return result
}

func (plan *archiveReadPlan) parentUnchanged() bool {
	if plan == nil || plan.parentRoot == nil || plan.parentInfo == nil {
		return false
	}
	opened, err := plan.parentRoot.Stat(".")
	if err != nil || opened == nil || !os.SameFile(plan.parentInfo, opened) {
		return false
	}
	current, err := os.Lstat(plan.parentPath)
	return err == nil && current != nil && current.IsDir() &&
		current.Mode()&os.ModeSymlink == 0 && os.SameFile(plan.parentInfo, current)
}

func (plan *archiveReadPlan) removeEmptyDirectory(expected os.FileInfo) bool {
	current, err := plan.parentRoot.Lstat(plan.directoryName)
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	if err != nil || current == nil || !current.IsDir() ||
		current.Mode()&os.ModeSymlink != 0 || !os.SameFile(expected, current) {
		return false
	}
	return plan.parentRoot.Remove(plan.directoryName) == nil
}

// close releases the preflight handles. It never removes output.
func (plan *archiveReadPlan) close() bool {
	if plan == nil {
		return false
	}
	cleanupIncomplete := false
	if plan.parentDirectory != nil {
		cleanupIncomplete = plan.parentDirectory.Close() != nil
		plan.parentDirectory = nil
	}
	if plan.parentRoot != nil {
		if plan.parentRoot.Close() != nil {
			cleanupIncomplete = true
		}
		plan.parentRoot = nil
	}
	return cleanupIncomplete
}
