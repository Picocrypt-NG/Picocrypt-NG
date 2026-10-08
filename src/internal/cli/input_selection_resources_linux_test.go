//go:build linux && !android

package cli

import (
	"Picocrypt-NG/internal/fileops"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// Single-file discovery has bounded path storage and does not prepare an
// archive. A real address-space limit must refuse expanding ZIP selections
// without preventing that nonarchive path or returning a partial selection.
func TestEncryptDiscoveryRequiresZIPHeadroomOnlyForExpandingSelections(t *testing.T) {
	const child = "PICOCRYPT_INPUT_SELECTION_MEMORY_CHILD"
	mode := os.Getenv(child)
	if mode == "" {
		for _, mode := range []string{"single", "directory", "multiple", "glob"} {
			t.Run(mode, func(t *testing.T) {
				command := exec.Command(os.Args[0], "-test.run=^TestEncryptDiscoveryRequiresZIPHeadroomOnlyForExpandingSelections$", "-test.count=1")
				command.Env = append(os.Environ(), child+"="+mode)
				if output, err := command.CombinedOutput(); err != nil {
					t.Fatalf("bounded input discovery subprocess: %v\n%s", err, output)
				}
			})
		}
		return
	}
	root := t.TempDir()
	path := filepath.Join(root, "source.txt")
	if err := os.WriteFile(path, []byte("source stays intact"), 0o600); err != nil {
		t.Fatal(err)
	}
	literals := []string{path}
	var patterns []string
	switch mode {
	case "directory":
		literals = []string{root}
	case "multiple":
		literals = []string{path, path}
	case "glob":
		literals = nil
		patterns = []string{filepath.Join(root, "*.txt")}
	case "single":
	default:
		t.Fatalf("unknown child mode %q", mode)
	}
	// Initialize the collector before measuring address space, then keep its
	// background allocation outside the narrow admission check under RLIMIT_AS.
	previousGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(previousGC)
	runtime.GC()
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	var virtual uint64
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "VmSize:" {
			virtual, err = strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			virtual *= 1024
		}
	}
	if virtual == 0 {
		t.Fatal("missing virtual size")
	}
	var original syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_AS, &original); err != nil {
		t.Fatal(err)
	}
	limited := original
	limited.Cur = virtual + (128 << 20)
	if err := syscall.Setrlimit(syscall.RLIMIT_AS, &limited); err != nil {
		t.Fatal(err)
	}
	inputs, selectionErr := resolveEncryptInputsWithBudget(context.Background(), literals, patterns, false, fileops.NewZIPResourceBudget())
	if err := syscall.Setrlimit(syscall.RLIMIT_AS, &original); err != nil {
		t.Fatal(err)
	}
	if mode == "single" {
		if selectionErr != nil || !reflect.DeepEqual(inputs.inputFiles, []string{path}) || len(inputs.onlyFolders) != 0 {
			t.Fatalf("single nonarchive file requires ZIP headroom: inputs=%+v err=%v", inputs, selectionErr)
		}
	} else if !errors.Is(selectionErr, fileops.ErrZIPMetadataLimit) || len(inputs.inputFiles) != 0 || len(inputs.selections) != 0 {
		t.Fatalf("expanding selection must refuse without partial inputs: inputs=%+v err=%v", inputs, selectionErr)
	}
	body, err := os.ReadFile(path)
	if err != nil || string(body) != "source stays intact" {
		t.Fatalf("resource admission changed source: %q, %v", body, err)
	}
}
