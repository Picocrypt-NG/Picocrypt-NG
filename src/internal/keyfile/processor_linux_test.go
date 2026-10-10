//go:build linux

package keyfile

import (
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

// The descriptor limit belongs only to the child, never the shared test runner.
// Frozen SHA3 vectors keep sequential opening from changing legacy derivation.
func TestProcessManyKeyfilesUnderDescriptorLimit(t *testing.T) {
	const child = "PICOCRYPT_TEST_KEYFILE_FD_CHILD"
	if os.Getenv(child) != "1" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		command := exec.Command(executable, "-test.run=^TestProcessManyKeyfilesUnderDescriptorLimit$")
		command.Env = append(os.Environ(), child+"=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("descriptor-limited Process: %v\n%s", err, output)
		}
		return
	}

	directory := t.TempDir()
	paths := make([]string, 100)
	for i := range paths {
		paths[i] = filepath.Join(directory, fmt.Sprintf("%03d.key", i))
		if err := os.WriteFile(paths[i], fmt.Appendf(nil, "public keyfile %03d", i), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var limit syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		t.Fatal(err)
	}
	limit.Cur = min(limit.Max, 64)
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &limit); err != nil {
		t.Fatal(err)
	}
	countFDs := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}
	before := countFDs()
	for _, test := range []struct {
		ordered bool
		key     string
		hash    string
	}{
		{true, "33a8ba53bc11741548dfde09048f0c79104f2c180df1594fabc80fb3bbd5efc9", "7105163d6b01a627edf42bb172a3215173785b6a6bff235cf5fe08c826bfc335"},
		{false, "ac24f465e5d9beadc4e331e626ae74fa29d07bff1e8241525ff7ba1fa05aac28", "dfddec1bdcaf3bd3d9a7e7195094434b74900fe893542d0ded00012522161d25"},
	} {
		t.Run(fmt.Sprintf("ordered=%v", test.ordered), func(t *testing.T) {
			var progress float32
			result, err := Process(paths, test.ordered, func(value float32) { progress = value })
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(result.Key) != test.key || hex.EncodeToString(result.Hash) != test.hash {
				t.Fatalf("legacy derivation changed: key=%x hash=%x", result.Key, result.Hash)
			}
			if progress != 1 {
				t.Fatalf("final progress=%v; want 1", progress)
			}
			if got := countFDs(); got != before {
				t.Fatalf("success leaked descriptors: before=%d after=%d", before, got)
			}
			result, err = Process([]string{paths[0], directory}, test.ordered, nil)
			if err == nil || result != nil {
				t.Fatalf("read failure returned partial key: result=%v error=%v", result, err)
			}
			if got := countFDs(); got != before {
				t.Fatalf("read failure leaked descriptors: before=%d after=%d", before, got)
			}
		})
	}
}
