//go:build linux && !android

package pcv3resource

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"syscall"
	"testing"
)

func TestLinuxKDFAddressLimitRefusesBeforeForcedGC(t *testing.T) {
	const child = "PICOCRYPT_KDF_LOW_ADDRESS_SPACE"
	if os.Getenv(child) != "1" {
		command := exec.Command(os.Args[0], "-test.run=^TestLinuxKDFAddressLimitRefusesBeforeForcedGC$", "-test.count=1")
		command.Env = append(os.Environ(), child+"=1", "GOMAXPROCS=32")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("low-address-space child: %v\n%s", err, output)
		}
		return
	}
	previousGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(previousGC)
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	process, ok := parseLinuxProcessMemory(status)
	if !ok {
		t.Fatal("native process memory facts unavailable")
	}
	var original syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_AS, &original); err != nil {
		t.Fatal(err)
	}
	limit := original
	limit.Cur = process.virtual + (128 << 20)
	if err := syscall.Setrlimit(syscall.RLIMIT_AS, &limit); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := syscall.Setrlimit(syscall.RLIMIT_AS, &original); err != nil {
			t.Error(err)
		}
	}()
	// This is admission for the real 1-GiB workspace; no Argon2 work is run.
	admitter := newAdmitter(newPlatformSnapshotProvider())
	for range 2 {
		decision, err := admitter.AdmitKDF(context.Background(), pcv3credential.KDFProfile{MemoryKiB: 1 << 20})
		if err != nil || decision != pcv3credential.KDFAdmissionDeniedInsufficient {
			t.Fatalf("low address space returned decision=%v err=%v", decision, err)
		}
	}
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	if after.NumGC != before.NumGC {
		t.Fatalf("insufficient KDF address space triggered forced GC: before=%d after=%d", before.NumGC, after.NumGC)
	}
}

func TestLinuxKDFAddressPreflightDoesNotReplaceFreshPhysicalAdmission(t *testing.T) {
	fixture := newLinuxSnapshotFixture()
	fixture.limits = "Max address space 4294967296 4294967296 bytes\n"
	fixture.meminfo = "MemTotal: 8388608 kB\nMemAvailable: 4194304 kB\n"
	fixture.cgroupFiles["sys/fs/cgroup/tenant/job/memory.max"] = "2147483648\n"
	provider := fixture.provider(t)
	admitter := newAdmitter(provider)
	profile := pcv3credential.KDFProfile{MemoryKiB: 1 << 20}
	decision, err := admitter.AdmitKDF(context.Background(), profile)
	if err != nil || decision != pcv3credential.KDFAdmissionGranted {
		t.Fatalf("fitting KDF memory refused: decision=%v err=%v", decision, err)
	}
	firstSequence := admitter.lastSequence
	current := filepath.Join(provider.filesystemRootPath, "sys/fs/cgroup/tenant/job/memory.current")
	if err := os.WriteFile(current, []byte("1610612736\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	decision, err = admitter.AdmitKDF(context.Background(), profile)
	if err != nil || decision != pcv3credential.KDFAdmissionDeniedInsufficient {
		t.Fatalf("new cgroup pressure admitted a KDF: decision=%v err=%v", decision, err)
	}
	if firstSequence == 0 || admitter.lastSequence <= firstSequence {
		t.Fatal("KDF admission reused its earlier physical snapshot")
	}
}

func TestLinuxKDFAddressPreflightUnknownFactsPreserveClassification(t *testing.T) {
	fixture := newLinuxSnapshotFixture()
	fixture.limits = "unavailable"
	decision, err := newAdmitter(fixture.provider(t)).AdmitKDF(context.Background(), pcv3credential.KDFProfile{MemoryKiB: 1 << 20})
	if err != nil || decision != pcv3credential.KDFAdmissionDeniedUnknown {
		t.Fatalf("unknown address limit returned decision=%v err=%v", decision, err)
	}
}
