package pcv3recovery

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3publication"
	"context"
	"errors"
	"os"
	"sync"
)

// ArchiveResult preserves extraction publication truth separately from cleanup.
// It never exposes stage paths, file descriptors, or platform errors.
type ArchiveResult struct {
	state             fileops.UnpackState
	cleanupIncomplete bool
	resourceLimited   bool
}

func (result *ArchiveResult) State() fileops.UnpackState {
	if result == nil {
		return 0
	}
	return result.state
}

func (result *ArchiveResult) CleanupIncomplete() bool {
	return result != nil && result.cleanupIncomplete
}

// ResourceLimited reports a closed resource-refusal cause, independently of
// publication and cleanup truth.
func (result *ArchiveResult) ResourceLimited() bool {
	return result != nil && result.resourceLimited
}

// ArchiveHandoff holds one unpublished D1 plaintext ZIP after the complete
// authenticated core run. Copies share a single consuming operation.
type ArchiveHandoff struct {
	state *archiveHandoffState
}

type archiveHandoffState struct {
	mu    sync.Mutex
	stage *pcv3publication.Stage
}

func newArchiveHandoff(stage *pcv3publication.Stage) *ArchiveHandoff {
	return &ArchiveHandoff{state: &archiveHandoffState{stage: stage}}
}

func (handoff *ArchiveHandoff) Live() bool {
	if handoff == nil || handoff.state == nil {
		return false
	}
	handoff.state.mu.Lock()
	defer handoff.state.mu.Unlock()
	return handoff.state.stage != nil
}

// Publish consumes the handoff before publishing the unchanged ZIP to its
// original no-replace target. Cleanup uncertainty is independent of commit state.
func (handoff *ArchiveHandoff) Publish(ctx context.Context) (publication pcv3publication.Result, cleanupIncomplete bool) {
	stage := handoff.consume()
	if stage == nil {
		return nil, false
	}
	defer func() {
		cleanupIncomplete = stage.Cleanup() != nil
		if recovered := recover(); recovered != nil {
			if cleanupIncomplete {
				panic(pcv3publication.ErrCleanupIncomplete)
			}
			panic(recovered)
		}
	}()
	return stage.Publish(ctx), false
}

// Extract consumes the handoff and owns root on every path. The held private
// descriptor is the only archive input; no plaintext path is reopened.
func (handoff *ArchiveHandoff) Extract(ctx context.Context, root *os.Root) *ArchiveResult {
	return handoff.ExtractWithReview(ctx, root, nil)
}

// ExtractWithReview keeps the same ownership and cleanup as Extract while
// asking the caller to approve the declared expansion budget before file output.
func (handoff *ArchiveHandoff) ExtractWithReview(ctx context.Context, root *os.Root, review func(fileops.ZIPSummary) error) *ArchiveResult {
	stage := handoff.consume()
	result := &ArchiveResult{state: fileops.UnpackStateNotPublished}
	defer func() {
		if stage != nil && stage.Cleanup() != nil {
			result.cleanupIncomplete = true
		}
		if root != nil && root.Close() != nil {
			result.cleanupIncomplete = true
		}
		if recovered := recover(); recovered != nil {
			if result.cleanupIncomplete {
				panic(pcv3publication.ErrCleanupIncomplete)
			}
			panic(recovered)
		}
	}()
	if stage == nil || root == nil || ctx == nil || ctx.Err() != nil {
		return result
	}
	file := stage.File()
	if file == nil {
		return result
	}
	expectedRoot, err := root.Stat(".")
	if err != nil || expectedRoot == nil || !expectedRoot.IsDir() {
		return result
	}
	unpack := fileops.UnpackWithResult(fileops.UnpackOptions{
		ZipFile:             file,
		ExtractDir:          root.Name(),
		ExtractRoot:         root,
		ExpectedExtractRoot: expectedRoot,
		Cancel:              func() bool { return ctx.Err() != nil },
		Review:              review,
	})
	if unpack != nil {
		result.state = unpack.State()
		result.resourceLimited = errors.Is(unpack, fileops.ErrZIPMetadataLimit)
		result.cleanupIncomplete = errors.Is(unpack, fileops.ErrUnpackCleanupIncomplete)
	}
	return result
}

// Close consumes unused archive custody and reports incomplete stage cleanup.
func (handoff *ArchiveHandoff) Close() bool {
	stage := handoff.consume()
	return stage != nil && stage.Cleanup() != nil
}

func (handoff *ArchiveHandoff) consume() *pcv3publication.Stage {
	if handoff == nil || handoff.state == nil {
		return nil
	}
	handoff.state.mu.Lock()
	defer handoff.state.mu.Unlock()
	stage := handoff.state.stage
	handoff.state.stage = nil
	return stage
}
