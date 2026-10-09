package workflowpolicy

import "testing"

// This is CI policy coverage: positive native resource tests must run with
// genuine OS facts outside the runner job, using the selected toolchain.
func TestWindowsPRWorkflowsSelectNativeJobCheckedSerialTests(t *testing.T) {
	for _, test := range []struct {
		path, job, toolchain, arguments string
	}{
		{
			path: ".github/workflows/pr-test-build-windows.yml", job: "pr-test-build-windows",
			toolchain: "-GoExecutable (Get-Command go -CommandType Application | Select-Object -First 1).Source",
			arguments: "@('test', '-v', '-p', '1', '-tags', 'migrated_fynedo', '-timeout', '15m', './...')",
		},
		{
			path: ".github/workflows/pr-test-build-windows-legacy.yml", job: "pr-test-build-windows-legacy",
			toolchain: "-GoExecutable 'C:\\go-legacy\\go\\bin\\go.exe'",
			arguments: "@('test', '-v', '-count=1', '-p', '1', '-timeout', '15m', './internal/cli', './internal/fileops', './internal/volume')",
		},
	} {
		t.Run(test.path, func(t *testing.T) {
			job := mustJob(t, mustReadWorkflowDoc(t, test.path), test.job)
			controls := mustStepNamed(t, job, "Verify native test launcher controls")
			if controls.Shell != "pwsh" || controls.ContinueOnError != nil {
				t.Fatal("launcher exit/timeout safety controls must fail CI on errors")
			}
			mustContain(t, controls.Run, "& .github/scripts/test-windows-native-tests.ps1")
			mustContainInOrder(t, mustReadWorkflow(t, test.path), "name: Verify native test launcher controls", "name: Run tests")
			step := mustStepNamed(t, job, "Run tests")
			if step.Shell != "pwsh" || step.ContinueOnError != nil {
				t.Fatalf("native tests require pwsh and a failing CI step on errors: %+v", step)
			}
			mustContain(t, step.Run, "& .github/scripts/run-windows-native-tests.ps1")
			mustContain(t, step.Run, test.toolchain)
			mustContain(t, step.Run, "-GoArguments "+test.arguments)
			if step.Env["PICOCRYPT_RUN_CLI_INTEGRATION"] != "1" {
				t.Fatal("native runner must retain actual CLI integration coverage")
			}
		})
	}
}
