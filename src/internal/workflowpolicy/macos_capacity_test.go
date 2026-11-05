package workflowpolicy

import (
	"reflect"
	"testing"
)

func TestMacOSPRCapacityLimitKeepsNativeDiscovery(t *testing.T) {
	workflow := mustReadWorkflowDoc(t, ".github/workflows/pr-test-build-macos.yml")
	tests := mustJob(t, workflow, "pcv3-tests")
	if tests.Strategy.MaxParallel != 1 || !reflect.DeepEqual(tests.Strategy.Matrix.Group, []int{1, 2}) {
		t.Fatal("macOS PR tests must use two shards with one runner at a time")
	}
	if tests.RunsOn != "macos-15" || tests.Env["CGO_ENABLED"] != "1" {
		t.Fatal("runner capacity limits must preserve native macOS ARM64 CGO execution")
	}
	run := mustStepNamed(t, tests, "Run native test group")
	if run.Env["SHARD_INDEX"] != "${{ strategy.job-index }}" || run.Env["SHARD_COUNT"] != "${{ strategy.job-total }}" {
		t.Fatal("native discovery must repartition all parents for the actual matrix size")
	}
	if run.Run != "bash .github/scripts/test-macos-pcv3.sh \"$SHARD_INDEX\" \"$SHARD_COUNT\"" {
		t.Fatal("capacity changes must retain the existing full native discovery runner")
	}
}
