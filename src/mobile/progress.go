package mobile

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ProgressState represents the current state of an operation
type ProgressState struct {
	ID       string
	Status   string
	Progress float32
	Info     string
	Error    string
	Done     bool
}

// progressMap stores progress state for all active operations
type progressMap struct {
	mu   sync.RWMutex
	ops  map[string]*ProgressState
	ctxs map[string]context.Context
	cancels map[string]context.CancelFunc
}

var globalProgressMap = &progressMap{
	ops:  make(map[string]*ProgressState),
	ctxs:  make(map[string]context.Context),
	cancels: make(map[string]context.CancelFunc),
}

// newOperationID generates a unique operation ID
func newOperationID() string {
	return fmt.Sprintf("op_%d", time.Now().UnixNano())
}

// startOperation creates a new operation and returns its ID
func startOperation() (string, context.Context, context.CancelFunc) {
	id := newOperationID()
	ctx, cancel := context.WithCancel(context.Background())
	
	globalProgressMap.mu.Lock()
	defer globalProgressMap.mu.Unlock()
	
	globalProgressMap.ops[id] = &ProgressState{
		ID:       id,
		Status:   "Starting...",
		Progress: 0.0,
		Info:     "",
		Error:    "",
		Done:     false,
	}
	globalProgressMap.ctxs[id] = ctx
	globalProgressMap.cancels[id] = cancel
	
	return id, ctx, cancel
}

// updateProgress updates the progress state for an operation
func updateProgress(id string, status string, progress float32, info string) {
	globalProgressMap.mu.Lock()
	defer globalProgressMap.mu.Unlock()
	
	if op, exists := globalProgressMap.ops[id]; exists {
		op.Status = status
		op.Progress = progress
		op.Info = info
	}
}

// completeOperation marks an operation as done
func completeOperation(id string, err error) {
	globalProgressMap.mu.Lock()
	defer globalProgressMap.mu.Unlock()
	
	if op, exists := globalProgressMap.ops[id]; exists {
		op.Done = true
		if err != nil {
			op.Error = err.Error()
			op.Status = "Error"
		} else {
			op.Status = "Completed"
			op.Progress = 1.0
		}
	}
}

// getProgress retrieves the current progress state for an operation
func getProgress(id string) (*ProgressState, error) {
	globalProgressMap.mu.RLock()
	op, exists := globalProgressMap.ops[id]
	globalProgressMap.mu.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("operation %s not found", id)
	}
	
	// Return a copy to avoid race conditions
	return &ProgressState{
		ID:       op.ID,
		Status:   op.Status,
		Progress: op.Progress,
		Info:     op.Info,
		Error:    op.Error,
		Done:     op.Done,
	}, nil
}

// cancelOperation cancels an operation
func cancelOperation(id string) error {
	globalProgressMap.mu.Lock()
	defer globalProgressMap.mu.Unlock()
	
	cancel, exists := globalProgressMap.cancels[id]
	if !exists {
		return fmt.Errorf("operation %s not found", id)
	}
	
	cancel()
	if op, exists := globalProgressMap.ops[id]; exists {
		op.Status = "Cancelled"
		op.Done = true
	}
	
	return nil
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
	delete(globalProgressMap.ctxs, id)
	delete(globalProgressMap.cancels, id)
}

