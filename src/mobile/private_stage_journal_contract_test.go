package mobile

import (
	"Picocrypt-NG/internal/pcv3operation"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestAndroidPCV3RunnerEnablesRetainedJournaledCustody(t *testing.T) {
	oldRunWithOptions := runPCV3OperationWithOptions
	var calls int
	var gotRequest *pcv3operation.Request
	var gotOptions pcv3operation.ExecutionOptions
	runPCV3OperationWithOptions = func(
		_ context.Context,
		request *pcv3operation.Request,
		options pcv3operation.ExecutionOptions,
	) *pcv3operation.Result {
		calls++
		gotRequest = request
		gotOptions = options
		return nil
	}
	t.Cleanup(func() { runPCV3OperationWithOptions = oldRunWithOptions })

	request := &pcv3operation.Request{}
	if result := runAndroidPCV3Operation(context.Background(), request); result != nil {
		t.Fatalf("observed Android wrapper result = %#v; want downstream sentinel", result)
	}
	if calls != 1 || gotRequest != request || !gotOptions.RetainDurableOutput ||
		!gotOptions.JournalPrivateStage {
		t.Fatalf(
			"Android execution custody = calls %d request-preserved %v retained %v journaled %v; want one exact retained+journaled call",
			calls, gotRequest == request, gotOptions.RetainDurableOutput,
			gotOptions.JournalPrivateStage,
		)
	}
}

func TestPCV3EnvelopeCannotEnablePrivateStageJournal(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source.pcv")
	if err := os.WriteFile(source, []byte("not read by rejected request"), 0o600); err != nil {
		t.Fatalf("seed rejected-request source: %v", err)
	}
	target := filepath.Join(directory, "output.bin")
	requestJSON := strings.Replace(
		pcv3TestEnvelope("read-normal", "password", "none", source, target, nil),
		"{",
		`{"journalPrivateStage":true,`,
		1,
	)

	var runCalls atomic.Int64
	oldRun := runPCV3Operation
	runPCV3Operation = func(context.Context, *pcv3operation.Request) *pcv3operation.Result {
		runCalls.Add(1)
		return nil
	}
	t.Cleanup(func() { runPCV3Operation = oldRun })

	password := []byte("correct horse battery staple")
	start := StartPCV3(requestJSON, password)
	if start == nil || start.Code() != pcv3BridgeInvalidRequest || start.Operation() != nil {
		t.Fatalf("attacker-selected journal option result = %#v; want synchronous rejection", start)
	}
	if !allZero(password) {
		t.Fatal("rejected attacker-selected journal option retained caller password")
	}
	if runCalls.Load() != 0 {
		t.Fatalf("attacker-selected journal option started %d core operations; want zero", runCalls.Load())
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("attacker-selected journal option affected output: %v", err)
	}
}
