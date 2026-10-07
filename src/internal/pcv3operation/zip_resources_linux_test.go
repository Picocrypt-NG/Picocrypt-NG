//go:build linux && !android

package pcv3operation

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// A real address-space headroom limit exercises the platform observer and the
// production archive follow-up. No injected grant/provider can skip the gate.
func TestArchiveExtractionRefusesInsufficientWorkingMemoryBeforeOutput(t *testing.T) {
	const child = "PICOCRYPT_ZIP_MEMORY_ADMISSION_CHILD"
	const fixture = "PICOCRYPT_ZIP_MEMORY_ADMISSION_FIXTURE"
	mode := os.Getenv(child)
	if mode == "" {
		// Prepare ciphertext once before child admission. A race-instrumented
		// writer retains shadow memory after its KDF; repeating it in each
		// child can consume the real headroom needed by that child's reader.
		ciphertext := archiveActionCiphertext(t, archiveActionPayload(t))
		for _, mode := range []string{"direct", "directory", "saf"} {
			t.Run(mode, func(t *testing.T) {
				command := exec.Command(os.Args[0], "-test.run=^TestArchiveExtractionRefusesInsufficientWorkingMemoryBeforeOutput$", "-test.count=1")
				command.Env = append(os.Environ(), child+"="+mode, fixture+"="+ciphertext)
				if output, err := command.CombinedOutput(); err != nil {
					t.Fatalf("bounded archive subprocess: %v\n%s", err, output)
				}
			})
		}
		return
	}
	stageParent := t.TempDir()
	target := filepath.Join(stageParent, "saved.zip")
	read := archiveActionReadFixture(t, target, os.Getenv(fixture))
	rootPath := t.TempDir()
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	var plan *archiveReadPlan
	watch := -1
	if mode == "directory" {
		plan, err = newArchiveReadPlan(ArchiveExtract, target)
		if err != nil {
			t.Fatal(err)
		}
		defer plan.close()
		watch, err = syscall.InotifyInit1(syscall.IN_NONBLOCK | syscall.IN_CLOEXEC)
		if err != nil {
			t.Fatal(err)
		}
		defer syscall.Close(watch)
		if _, err := syscall.InotifyAddWatch(watch, stageParent, syscall.IN_CREATE); err != nil {
			t.Fatal(err)
		}
	}
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
	defer func() {
		if err := syscall.Setrlimit(syscall.RLIMIT_AS, &original); err != nil {
			t.Error(err)
		}
	}()
	var result *Result
	if mode == "saf" {
		root.Close()
		begin := read.ArchiveFollowUp().BeginSAFWithContext(context.Background())
		if begin.Kind() != ArchiveSAFBeginTerminal || begin.Session() != nil || begin.ReceiptArm() != nil {
			t.Fatal("low headroom issued SAF provider authority")
		}
		result = begin.Result()
	} else if plan == nil {
		result = read.ArchiveFollowUp().Extract(context.Background(), root)
	} else {
		root.Close()
		result = plan.apply(context.Background(), read)
	}
	if result.Diagnostic() != DiagnosticResourceLimit || result.Stage() != StageResourceBudget || result.PublicationAttempted() {
		t.Fatalf("low headroom must refuse before output: %v", result)
	}
	if watch >= 0 {
		var events [4096]byte
		if n, err := syscall.Read(watch, events[:]); n > 0 || err != syscall.EAGAIN {
			t.Fatalf("resource refusal created a directory before failing: events=%d err=%v", n, err)
		}
	}
	for _, directory := range []string{rootPath, stageParent} {
		entries, err := os.ReadDir(directory)
		if err != nil || len(entries) != 0 {
			t.Fatalf("refusal left plaintext/staging in %s: %v, %v", directory, entries, err)
		}
	}
}
