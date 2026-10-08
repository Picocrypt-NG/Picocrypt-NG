package mobile

import (
	"Picocrypt-NG/internal/pcv3operation"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
)

// Keyfile opening happens after selection capture and before the asynchronous
// input preparation. This boundary mutation tests the actual mobile start and
// preparation paths without a timing race or a synthetic archive reader.
func TestPCV3MobileArchiveRejectsInputReplacementAfterStart(t *testing.T) {
	for _, kind := range []string{"symlink", "regular"} {
		t.Run(kind, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				dir := t.TempDir()
				first := writePCV3MobileFile(t, dir, "first", "stable first input")
				selected := writePCV3MobileFile(t, dir, "selected", "selected contents")
				foreign := writePCV3MobileFile(t, dir, "foreign", "unintended secret")
				keyfile := writePCV3MobileFile(t, dir, "keyfile", "public test keyfile")
				target := filepath.Join(dir, "out.pcv")
				oldOpen := openPCV3Existing
				openPCV3Existing = func(path string) (*os.File, error) {
					if path == keyfile {
						if err := os.Rename(selected, selected+".selected"); err != nil {
							return nil, err
						}
						var err error
						if kind == "symlink" {
							err = os.Symlink(foreign, selected)
						} else {
							err = os.WriteFile(selected, []byte("unintended secret"), 0o600)
						}
						if err != nil {
							return nil, err
						}
					}
					return oldOpen(path)
				}
				t.Cleanup(func() { openPCV3Existing = oldOpen })
				deriving := false
				oldWrite := runPCV3WriteWithOptions
				runPCV3WriteWithOptions = func(ctx context.Context, request *pcv3operation.WriteRequest, options pcv3operation.ExecutionOptions) *pcv3operation.Result {
					report := request.Reporter
					request.Reporter = func(status pcv3operation.Status) error {
						if status.Code() == pcv3operation.StatusDerivingKey {
							deriving = true
							return errors.New("test refuses KDF for replaced selection")
						}
						if report != nil {
							return report(status)
						}
						return nil
					}
					return oldWrite(ctx, request, options)
				}
				t.Cleanup(func() { runPCV3WriteWithOptions = oldWrite })
				wire := pcv3WriteTestEnvelope("write-normal", "password-and-keyfiles", "ordered", "standard", false, "", first, target, []string{keyfile})
				wire = strings.TrimSuffix(wire, "}") + fmt.Sprintf(`,"inputFiles":[%q,%q],"onlyFiles":[%q,%q],"onlyFolders":[],"compress":false}`, first, selected, first, selected)
				password := []byte("public-test-password")
				start := StartPCV3(wire, password)
				if start == nil || start.Code() != "" || start.Operation() == nil {
					t.Fatalf("valid collection start refused: %#v", start)
				}
				operation := start.Operation()
				t.Cleanup(func() { cleanupOperation(operation.ID()) })
				synctest.Wait()
				snapshot := operation.Snapshot()
				if deriving || snapshot.Outcome() != "operation-failed" || operation.Output() != nil {
					t.Fatalf("replaced input reached KDF/output: deriving=%v snapshot=%s", deriving, pcv3MobileSnapshotText(snapshot))
				}
				if !allZero(password) {
					t.Fatal("caller password retained after rejected preparation")
				}
				for path, want := range map[string]string{selected + ".selected": "selected contents", selected: "unintended secret", foreign: "unintended secret", first: "stable first input", keyfile: "public test keyfile"} {
					got, err := os.ReadFile(path)
					if err != nil || string(got) != want {
						t.Fatalf("protected input %s changed: %q, %v", path, got, err)
					}
				}
				entries, err := os.ReadDir(dir)
				if err != nil || len(entries) != 5 {
					t.Fatalf("failure left output/stage or removed source: %v, %v", entries, err)
				}
			})
		})
	}
}
