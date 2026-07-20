package mobile

import (
	"context"
	"fmt"
	"sync"
	"time"
)

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
	ctxs    map[string]context.Context
	cancels map[string]context.CancelFunc
}

var globalProgressMap = &progressMap{
	ops:     make(map[string]*ProgressState),
	ctxs:    make(map[string]context.Context),
	cancels: make(map[string]context.CancelFunc),
}

// newOperationID generates a unique operation ID
func newOperationID() string {
	return fmt.Sprintf("op_%d", time.Now().UnixNano())
}

// startOperation creates a new operation and returns its ID
func startOperation() string {
	id := newOperationID()
	ctx, cancel := context.WithCancel(context.Background()) //nolint:gosec // G118: cancel is stored in globalProgressMap.cancels and called by cancelOperation
	status := classifyStatus("Starting...")
	info := classifyInfo("")

	globalProgressMap.mu.Lock()
	defer globalProgressMap.mu.Unlock()

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
		Error:                   "",
		Done:                    false,
	}
	globalProgressMap.ctxs[id] = ctx
	globalProgressMap.cancels[id] = cancel

	return id
}

// completeOperation marks an operation as done
func completeOperation(id string, err error) {
	globalProgressMap.mu.Lock()
	defer globalProgressMap.mu.Unlock()

	if op, exists := globalProgressMap.ops[id]; exists {
		if op.StatusCode == "CANCELLED" {
			op.Done = true
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
		status := classifyStatus("Cancelled")
		op.Status = "Cancelled"
		op.StatusCode = status.Code
		op.StatusSpeedMiBPerSecond = status.SpeedMiBPerSecond
		op.StatusETA = status.ETA
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
