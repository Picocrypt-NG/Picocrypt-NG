package workflowpolicy

import "testing"

// This is release policy coverage; test-install-nsis.ps1 exercises the verifier.
func TestWindowsNSISConsumersUseVerifiedPortableCompiler(t *testing.T) {
	for _, tc := range []struct{ path, job, install string }{
		{".github/workflows/build-windows.yml", "build", "Install NSIS"},
		{".github/workflows/build-windows.yml", "sign", "Export unsigned NSIS uninstaller"},
		{".github/workflows/pr-test-build-windows.yml", "pr-test-build-windows", "Install NSIS"},
		{".github/workflows/pr-test-installer-upgrade.yml", "installer-upgrade", "Install NSIS"},
	} {
		t.Run(tc.path+"/"+tc.job, func(t *testing.T) {
			job := mustJob(t, mustReadWorkflowDoc(t, tc.path), tc.job)
			install := mustStepNamed(t, job, tc.install)
			if install.Shell != "pwsh" || install.ContinueOnError != nil {
				t.Fatal("NSIS verification errors must fail the workflow")
			}
			mustContainInOrder(t, install.Run,
				`$makensis = & .github/scripts/install-nsis.ps1`,
				`"NSIS_EXE=$makensis"`,
				`& $makensis -VERSION`,
				`if ($LASTEXITCODE -ne 0)`,
			)
			for _, step := range job.Steps {
				mustNotContain(t, step.Run, "choco install")
				mustNotContain(t, step.Run, `C:\Program Files (x86)\NSIS`)
			}
		})
	}
	for _, tc := range []struct{ path, job, step, command string }{
		{".github/workflows/build-windows.yml", "build", "Build NSIS installer", `& $env:NSIS_EXE`},
		{".github/workflows/build-windows.yml", "sign", "Export unsigned NSIS uninstaller", `& $makensis`},
		{".github/workflows/build-windows.yml", "sign", "Build NSIS installer from signed components", `& $env:NSIS_EXE`},
		{".github/workflows/pr-test-build-windows.yml", "pr-test-build-windows", "Build NSIS installer", `& $env:NSIS_EXE`},
	} {
		job := mustJob(t, mustReadWorkflowDoc(t, tc.path), tc.job)
		mustContain(t, mustStepNamed(t, job, tc.step).Run, tc.command+" `")
	}
	job := mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/pr-test-installer-upgrade.yml"), "installer-upgrade")
	runtime := mustStepNamed(t, job, "Runtime upgrade / orphan-sweep / running-instance test")
	mustContainInOrder(t, runtime.Run, `$makensis = $env:NSIS_EXE`, `& $makensis -WX`)
	controls := mustStepNamed(t, job, "Verify NSIS archive controls")
	if controls.Shell != "pwsh" || controls.ContinueOnError != nil {
		t.Fatal("NSIS archive rejection regression must fail CI on errors")
	}
	mustContain(t, controls.Run, `& .github/scripts/test-install-nsis.ps1`)
}
