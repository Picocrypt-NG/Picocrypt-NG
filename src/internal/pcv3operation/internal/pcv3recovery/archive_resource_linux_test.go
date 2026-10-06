//go:build linux && !android

package pcv3recovery

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

func TestD1ArchivePreparationFreshMemoryRefusalIsNotPublication(t *testing.T) {
	const child = "PICOCRYPT_RECOVERY_ARCHIVE_LOW_MEMORY"
	if os.Getenv(child) == "" {
		command := exec.Command(os.Args[0], "-test.run=^TestD1ArchivePreparationFreshMemoryRefusalIsNotPublication$", "-test.count=1")
		command.Env = append(os.Environ(), child+"=1")
		if out, err := command.CombinedOutput(); err != nil {
			t.Fatalf("child: %v\n%s", err, out)
		}
		return
	}
	data := recoveryArchiveBytes(t)
	directory := t.TempDir()
	var original syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_AS, &original); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := syscall.Setrlimit(syscall.RLIMIT_AS, &original); err != nil {
			t.Error(err)
		}
	}()
	// Narrow the actual address-space headroom only after authenticated emission,
	// so the production preparation gate must refuse without publication authority.
	result := runWithCoreOptions(context.Background(), &Request{Target: filepath.Join(directory, "archive.zip"), Mode: pcv3.RecoveryModeNormalV3}, recoveryArchiveCore(data, func() error {
		status, err := os.ReadFile("/proc/self/status")
		if err != nil {
			return err
		}
		var virtual uint64
		for _, line := range strings.Split(string(status), "\n") {
			fields := strings.Fields(line)
			if len(fields) == 3 && fields[0] == "VmSize:" {
				virtual, err = strconv.ParseUint(fields[1], 10, 64)
				if err != nil {
					return err
				}
				virtual *= 1024
			}
		}
		if virtual == 0 {
			t.Fatal("missing VmSize")
		}
		limit := original
		limit.Cur = virtual + (128 << 20)
		return syscall.Setrlimit(syscall.RLIMIT_AS, &limit)
	}), ExecutionOptions{PrepareArchive: true})
	if result.Outcome() != pcv3.OutcomeOperationFailed || result.Stage() != pcv3.StageResourceBudget || result.PublicationAttempted() || result.TakeArchiveHandoff() != nil {
		t.Fatalf("fresh memory refusal: outcome=%v stage=%v publication=%v", result.Outcome(), result.Stage(), result.PublicationAttempted())
	}
	if result.PublicationState() != 0 || result.PublicationStage() != pcv3.StageNone || result.PublicationCode() != 0 {
		t.Errorf("pre-publication resource refusal retained publication tuple: %v/%v/%v", result.PublicationState(), result.PublicationStage(), result.PublicationCode())
	}

	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("refusal retained plaintext: %v %v", entries, err)
	}
}
