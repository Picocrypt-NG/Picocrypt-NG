//go:build linux && !android

package ui

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3operation"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestDeletionManifestRefusesLowFreshMemory(t *testing.T) {
	const child = "PICOCRYPT_DELETION_LOW_MEMORY"
	if os.Getenv(child) == "" {
		c := exec.Command(os.Args[0], "-test.run=^TestDeletionManifestRefusesLowFreshMemory$", "-test.count=1")
		// A high CPU count can make GC grow cgo thread stacks after RLIMIT_AS
		// is narrowed. Admission must refuse without starting that collector.
		c.Env = append(os.Environ(), child+"=1", "GOMAXPROCS=32")
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("child: %v\n%s", err, out)
		}
		return
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	if err := os.WriteFile(source, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Isolate explicit collection by admission from automatic collection. A
	// forced GC under the already-insufficient address limit can abort in cgo.
	previousGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(previousGC)
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	var virtual uint64
	for _, line := range strings.Split(string(status), "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && f[0] == "VmSize:" {
			virtual, err = strconv.ParseUint(f[1], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			virtual *= 1024
		}
	}
	if virtual == 0 {
		t.Fatal("missing VmSize")
	}
	var orig syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_AS, &orig); err != nil {
		t.Fatal(err)
	}
	limit := orig
	limit.Cur = virtual + (128 << 20)
	if err := syscall.Setrlimit(syscall.RLIMIT_AS, &limit); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := syscall.Setrlimit(syscall.RLIMIT_AS, &orig); err != nil {
			t.Error(err)
		}
	}()
	ctx := context.Background()
	budget := fileops.NewZIPResourceBudget()
	if err := pcv3operation.AdmitZIPWorkingMemory(ctx, budget); !errors.Is(err, fileops.ErrZIPMetadataLimit) {
		t.Fatalf("fixture headroom did not refuse: %v", err)
	}
	manifest, err := captureOperationDeletionManifestWithBudget(ctx, operationInput{mode: "encrypt", inputFiles: []string{source}, onlyFolders: []string{dir}, delete: true}, budget)
	if !errors.Is(err, fileops.ErrZIPMetadataLimit) || manifest != nil {
		t.Fatalf("insufficient fresh headroom still returned usable deletion manifest: manifest=%v error=%v retained=%d", manifest, err, budget.CurrentBytes())
	}
	if budget.CurrentBytes() != 0 {
		t.Fatal("refusal retained manifest charge")
	}
	body, err := os.ReadFile(source)
	if err != nil || string(body) != "preserve" {
		t.Fatalf("source changed: %q %v", body, err)
	}
	manifest, err = captureOperationDeletionManifestWithBudget(ctx, operationInput{delete: false}, budget)
	if manifest != nil || err != nil {
		t.Fatalf("no-delete no-op: %v %v", manifest, err)
	}
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if after.NumGC != before.NumGC {
		t.Fatalf("insufficient address space triggered forced GC: before=%d after=%d", before.NumGC, after.NumGC)
	}
}
