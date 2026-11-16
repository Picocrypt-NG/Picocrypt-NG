//go:build linux

package volume

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type substitutePreparedChunkDirectoryReporter struct {
	GoldenTestReporter
	onRecombine func()
}

func (r *substitutePreparedChunkDirectoryReporter) SetStatus(status string) {
	if status == "Recombining chunks..." {
		r.onRecombine()
	}
}

func TestPreparedLegacyRecombineRejectsParentFIFOAfterPinningChunkZero(t *testing.T) {
	const child = "PICOCRYPT_PREPARED_FIFO_PARENT_CHILD"
	if root := os.Getenv(child); root != "" {
		selected := filepath.Join(root, "source")
		if err := os.Mkdir(selected, 0o700); err != nil {
			t.Fatal(err)
		}
		base := filepath.Join(selected, "input.pcv")
		original := []byte("selected synthetic legacy chunk")
		for _, path := range []string{base + ".0", base + ".1"} {
			if err := os.WriteFile(path, original, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		prepared, err := PrepareDecryptInput(base+".0", true)
		if err != nil {
			t.Fatal(err)
		}
		defer prepared.Close()
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		renamed := selected + ".selected"
		changed := false
		reporter := &substitutePreparedChunkDirectoryReporter{onRecombine: func() {
			if err := os.Rename(selected, renamed); err != nil {
				t.Fatal(err)
			}
			if err := unix.Mkfifo(selected, 0o600); err != nil {
				t.Fatal(err)
			}
			changed = true
			time.AfterFunc(50*time.Millisecond, cancel)
		}}
		output := filepath.Join(root, "plaintext")
		err = DecryptPrepared(ctx, &DecryptRequest{InputFile: base + ".0", OutputFile: output, Recombine: true, Password: []byte("synthetic"), RSCodecs: newRSCodecsT(t), Reporter: reporter}, prepared)
		if !changed || err == nil || !strings.Contains(err.Error(), "read chunk dir") {
			t.Fatalf("prepared FIFO parent not refused at count boundary: changed=%t err=%v", changed, err)
		}
		cancel()
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatalf("cancellation not completed: %v", ctx.Err())
		}
		for _, path := range []string{output, filepath.Join(renamed, "input.pcv")} {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("refusal retained output %q: %v", path, err)
			}
		}
		for _, suffix := range []string{".0", ".1"} {
			got, err := os.ReadFile(filepath.Join(renamed, "input.pcv") + suffix)
			if err != nil || !bytes.Equal(got, original) {
				t.Fatalf("selected source changed: %q %v", got, err)
			}
		}
		info, err := os.Lstat(selected)
		if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
			t.Fatalf("substituted FIFO changed: %v %v", info, err)
		}
		assertNoPicocryptStages(t, root)
		return
	}
	root := t.TempDir()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPreparedLegacyRecombineRejectsParentFIFOAfterPinningChunkZero$", "-test.v")
	command.Env = append(os.Environ(), child+"="+root)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("prepared FIFO parent blocked or failed: %v context=%v\n%s", err, ctx.Err(), output)
	}
}
