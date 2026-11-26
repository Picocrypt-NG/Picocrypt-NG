//go:build linux

package workflowpolicy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestAppImageDependencyReviewReportsUpdatesAndUnavailability(t *testing.T) {
	for _, test := range []struct {
		name, candidates, aptError, want string
		reportOnly, wantError            bool
	}{
		{
			name:       "reports newer Debian versions",
			candidates: "example:\n  Candidate: 1:10-1\n",
			want:       "| example | 1:9-1 | 1:10-1 |",
		},
		{
			name:       "reports unchanged packages",
			candidates: "example:\n  Candidate: 1:9-1\n",
			want:       "The locked packages match the current Jammy candidates.",
		},
		{
			name:       "missing candidate leaves review incomplete",
			candidates: "example:\n  Candidate: (none)\n",
			want:       "No current Jammy candidate for example",
			wantError:  true,
		},
		{
			name:      "failed metadata refresh leaves review incomplete",
			aptError:  "1",
			want:      "Could not refresh signed Ubuntu package indexes",
			wantError: true,
		},
		{
			name:       "failed metadata refresh is advisory in the coordinator",
			aptError:   "1",
			want:       "Could not refresh signed Ubuntu package indexes",
			reportOnly: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			lockDir := filepath.Join(dir, ".github", "toolchains", "appimage-release")
			if err := os.MkdirAll(lockDir, 0o700); err != nil {
				t.Fatal(err)
			}
			const script = ".github/scripts/check-appimage-dependency-updates.sh"
			scriptPath := filepath.Join(dir, script)
			if err := os.MkdirAll(filepath.Dir(scriptPath), 0o700); err != nil {
				t.Fatal(err)
			}
			const packageDigest = "0000000000000000000000000000000000000000000000000000000000000000"
			files := map[string]string{
				scriptPath:                                       mustReadRepoFile(t, script),
				filepath.Join(lockDir, "manifest.json"):          `{"snapshot":"20261115T083000Z"}`,
				filepath.Join(lockDir, "os-packages-amd64.lock"): "example\t1:9-1\tamd64\t" + packageDigest + "\tpool/main/e/example/example.deb\n",
				filepath.Join(dir, "apt-get"):                    "#!/bin/sh\nexit \"$TEST_APT_REFRESH_ERROR\"\n",
				filepath.Join(dir, "apt-cache"):                  "#!/bin/sh\nprintf '%s' \"$TEST_APT_CANDIDATES\"\n",
			}
			for path, contents := range files {
				if err := os.WriteFile(path, []byte(contents), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			summary := filepath.Join(dir, "summary.md")
			aptError := test.aptError
			if aptError == "" {
				aptError = "0"
			}
			command := exec.Command("bash", scriptPath)
			if test.reportOnly {
				step := mustStepNamed(t, mustJob(t, mustReadWorkflowDoc(t, ".github/workflows/release.yml"), "validation"), "Report AppImage dependency updates")
				command = exec.Command("bash", "-e", "-o", "pipefail", "-c", step.Run)
			}
			command.Dir = dir
			command.Env = append(os.Environ(),
				"PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"),
				"GITHUB_STEP_SUMMARY="+summary,
				"TEST_APT_CANDIDATES="+test.candidates,
				"TEST_APT_REFRESH_ERROR="+aptError,
			)
			output, err := command.CombinedOutput()
			if (err != nil) != test.wantError {
				t.Fatalf("dependency review error = %v, want error %v:\n%s", err, test.wantError, output)
			}
			report, err := os.ReadFile(summary)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(report), test.want) {
				t.Errorf("summary lacks %q:\n%s", test.want, report)
			}
		})
	}
}
