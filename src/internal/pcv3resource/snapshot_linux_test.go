//go:build linux && !android

package pcv3resource

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

type linuxSnapshotFixture struct {
	meminfo     string
	status      string
	limits      string
	cgroup      string
	mountinfo   string
	cgroupFiles map[string]string
}

func newLinuxSnapshotFixture() linuxSnapshotFixture {
	return linuxSnapshotFixture{
		meminfo: "MemTotal: 8192 kB\nMemAvailable: 4096 kB\n",
		status:  "Name:\tfixture\nVmSize:\t1024 kB\nVmRSS:\t256 kB\n",
		limits: "Limit                     Soft Limit           Hard Limit           Units\n" +
			"Max address space         2097152              2097152              bytes\n",
		cgroup:    "0::/tenant/job\n",
		mountinfo: "36 27 0:33 / /sys/fs/cgroup rw,nosuid,nodev,noexec - cgroup2 cgroup2 rw\n",
		cgroupFiles: map[string]string{
			"sys/fs/cgroup/memory.max":                "max\n",
			"sys/fs/cgroup/tenant/memory.max":         "max\n",
			"sys/fs/cgroup/tenant/job/memory.max":     "3145728\n",
			"sys/fs/cgroup/tenant/job/memory.current": "1048576\n",
		},
	}
}

func (fixture linuxSnapshotFixture) provider(t *testing.T) linuxSnapshotProvider {
	t.Helper()
	root := t.TempDir()
	writeLinuxSnapshotFixture(t, root, fixture)
	return linuxSnapshotProvider{
		procRootPath:       filepath.Join(root, "proc"),
		filesystemRootPath: root,
	}
}

func writeLinuxSnapshotFixture(t *testing.T, root string, fixture linuxSnapshotFixture) {
	t.Helper()
	files := map[string]string{
		"proc/meminfo":        fixture.meminfo,
		"proc/self/status":    fixture.status,
		"proc/self/limits":    fixture.limits,
		"proc/self/cgroup":    fixture.cgroup,
		"proc/self/mountinfo": fixture.mountinfo,
	}
	for name, content := range fixture.cgroupFiles {
		files[name] = content
	}
	for name, content := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatalf("create fixture directory: %v", err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatalf("write fixture file: %v", err)
		}
	}
}

func TestLinuxSnapshotProviderUsesMinimumApplicableHeadroom(t *testing.T) {
	provider := newLinuxSnapshotFixture().provider(t)
	snapshot := provider.Snapshot(context.Background())

	if snapshot.source != snapshotSourceLinux || snapshot.state != snapshotStateReady {
		t.Fatalf("snapshot source/state = %v/%v; want Linux/ready", snapshot.source, snapshot.state)
	}
	if snapshot.effectiveAvailable != 1048576 {
		t.Fatalf("effective available = %d; want finite RLIMIT_AS headroom 1048576", snapshot.effectiveAvailable)
	}
	if snapshot.codeOwnedReserve != 262144 {
		t.Fatalf("code-owned reserve = %d; want same-snapshot VmRSS 262144", snapshot.codeOwnedReserve)
	}
	if snapshot.platformThreshold != 0 {
		t.Fatalf("platform threshold = %d; want zero for conservative desktop headroom", snapshot.platformThreshold)
	}
}

func TestLinuxSnapshotProviderResolvesV1MemoryController(t *testing.T) {
	fixture := newLinuxSnapshotFixture()
	fixture.limits = "Limit Soft Limit Hard Limit Units\nMax address space unlimited unlimited bytes\n"
	fixture.cgroup = "5:memory,cpu:/slice\n"
	fixture.mountinfo = "42 27 0:38 / /sys/fs/cgroup/memory rw - cgroup cgroup rw,memory\n"
	fixture.cgroupFiles = map[string]string{
		"sys/fs/cgroup/memory/memory.limit_in_bytes":       "9223372036854771712\n",
		"sys/fs/cgroup/memory/memory.usage_in_bytes":       "1048576\n",
		"sys/fs/cgroup/memory/slice/memory.limit_in_bytes": "3145728\n",
		"sys/fs/cgroup/memory/slice/memory.usage_in_bytes": "1048576\n",
	}

	snapshot := fixture.provider(t).Snapshot(context.Background())
	if snapshot.state != snapshotStateReady {
		t.Fatalf("v1 snapshot state = %v; want ready", snapshot.state)
	}
	if snapshot.effectiveAvailable != 2097152 {
		t.Fatalf("effective available = %d; want v1 headroom 2097152", snapshot.effectiveAvailable)
	}
}

func TestLinuxSnapshotProviderRejectsAmbiguousOrUnreadableFacts(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*linuxSnapshotFixture)
	}{
		{
			name: "duplicate MemAvailable",
			mutate: func(fixture *linuxSnapshotFixture) {
				fixture.meminfo += "MemAvailable: 1 kB\n"
			},
		},
		{
			name: "negative process footprint",
			mutate: func(fixture *linuxSnapshotFixture) {
				fixture.status = "VmSize:\t1024 kB\nVmRSS:\t-1 kB\n"
			},
		},
		{
			name: "kilobyte conversion overflow",
			mutate: func(fixture *linuxSnapshotFixture) {
				fixture.meminfo = "MemTotal: 18446744073709551615 kB\nMemAvailable: 18446744073709551615 kB\n"
			},
		},
		{
			name: "finite address limit below process size",
			mutate: func(fixture *linuxSnapshotFixture) {
				fixture.limits = "Max address space 1048575 1048575 bytes\n"
			},
		},
		{
			name: "cgroup usage exceeds its limit",
			mutate: func(fixture *linuxSnapshotFixture) {
				fixture.cgroupFiles["sys/fs/cgroup/tenant/job/memory.current"] = "3145729\n"
			},
		},
		{
			name: "constrained cgroup without readable usage",
			mutate: func(fixture *linuxSnapshotFixture) {
				delete(fixture.cgroupFiles, "sys/fs/cgroup/tenant/job/memory.current")
			},
		},
		{
			name: "non canonical cgroup path",
			mutate: func(fixture *linuxSnapshotFixture) {
				fixture.cgroup = "0::/tenant/../outside\n"
			},
		},
		{
			name: "duplicate applicable mount",
			mutate: func(fixture *linuxSnapshotFixture) {
				fixture.mountinfo += "37 27 0:33 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw\n"
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newLinuxSnapshotFixture()
			test.mutate(&fixture)
			snapshot := fixture.provider(t).Snapshot(context.Background())
			if snapshot.source != snapshotSourceLinux || snapshot.state != snapshotStateUnconfigured {
				t.Fatalf("snapshot source/state = %v/%v; want Linux/unconfigured", snapshot.source, snapshot.state)
			}
			if snapshot.effectiveAvailable != 0 || snapshot.codeOwnedReserve != 0 {
				t.Fatalf("failed snapshot exposed resource facts: available=%d reserve=%d", snapshot.effectiveAvailable, snapshot.codeOwnedReserve)
			}
		})
	}
}

func TestDesktopResourceProvidersFailClosed(t *testing.T) {
	snapshot := newPlatformSnapshotProvider().Snapshot(context.Background())
	if snapshot.source != snapshotSourceLinux || snapshot.platformThreshold != 0 {
		t.Fatalf("production snapshot source/threshold = %v/%d; want Linux/zero", snapshot.source, snapshot.platformThreshold)
	}
	if snapshot.sequence == 0 || snapshot.observedAt.IsZero() {
		t.Fatalf("production snapshot lacks fresh observation metadata")
	}
	switch snapshot.state {
	case snapshotStateReady:
		if snapshot.effectiveAvailable == 0 || snapshot.codeOwnedReserve == 0 {
			t.Fatalf("ready production snapshot is internally inconsistent")
		}
	case snapshotStateUnconfigured:
		if snapshot.effectiveAvailable != 0 || snapshot.codeOwnedReserve != 0 {
			t.Fatalf("fail-closed production snapshot exposed resource facts")
		}
	default:
		t.Fatalf("production Linux snapshot state = %v; want ready or explicit unconfigured", snapshot.state)
	}
}
