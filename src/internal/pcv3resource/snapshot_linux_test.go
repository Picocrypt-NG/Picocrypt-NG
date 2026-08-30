//go:build linux && !android

package pcv3resource

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type linuxSnapshotFixture struct {
	meminfo     string
	status      string
	limits      string
	cgroup      string
	mountinfo   string
	cgroupDirs  []string
	cgroupFiles map[string]string
	cgroupLinks map[string]string
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
	for _, name := range fixture.cgroupDirs {
		if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(name)), 0o700); err != nil {
			t.Fatalf("create cgroup fixture directory: %v", err)
		}
	}
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
	for name, target := range fixture.cgroupLinks {
		if err := os.Symlink(target, filepath.Join(root, filepath.FromSlash(name))); err != nil {
			t.Fatalf("create cgroup fixture symlink: %v", err)
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

func TestLinuxSnapshotProviderAcceptsSystemdEscapedCgroupPath(t *testing.T) {
	// Desktop sessions launched from escaped app.slice units (terminals,
	// browsers) carry literal systemd "\xHH" sequences in their cgroupfs
	// directory names; admission must resolve that real path instead of
	// failing closed.
	fixture := newLinuxSnapshotFixture()
	fixture.cgroup = "0::/app.slice/app-ghostty\\x2dopen.slice/transient\\x2djob.scope\n"
	fixture.cgroupFiles = map[string]string{
		"sys/fs/cgroup/memory.max":                                                                  "max\n",
		"sys/fs/cgroup/app.slice/memory.max":                                                        "max\n",
		"sys/fs/cgroup/app.slice/app-ghostty\\x2dopen.slice/memory.max":                             "max\n",
		"sys/fs/cgroup/app.slice/app-ghostty\\x2dopen.slice/transient\\x2djob.scope/memory.max":     "3145728\n",
		"sys/fs/cgroup/app.slice/app-ghostty\\x2dopen.slice/transient\\x2djob.scope/memory.current": "1048576\n",
	}

	snapshot := fixture.provider(t).Snapshot(context.Background())
	if snapshot.state != snapshotStateReady {
		t.Fatalf("escaped cgroup path snapshot state = %v; want ready", snapshot.state)
	}
	if snapshot.effectiveAvailable != 1048576 {
		t.Fatalf("effective available = %d; want escaped-path headroom 1048576", snapshot.effectiveAvailable)
	}
}

func TestCleanLinuxCgroupPath(t *testing.T) {
	cases := []struct {
		name  string
		value string
		ok    bool
	}{
		{name: "plain path accepted", value: "/user.slice/user-1000.slice", ok: true},
		{name: "escaped name accepted raw", value: `/app.slice/app-ghostty\x2dopen.slice`, ok: true},
		{name: "NUL rejected", value: "/tenant/\x00x", ok: false},
		{name: "carriage return rejected", value: "/tenant/\rx", ok: false},
		{name: "newline rejected", value: "/tenant/\nx", ok: false},
		{name: "relative path rejected", value: "tenant/job", ok: false},
		{name: "dot element rejected", value: "/tenant/./job", ok: false},
		{name: "dot-dot element rejected", value: "/tenant/../job", ok: false},
		{name: "trailing slash rejected", value: "/tenant/job/", ok: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := cleanLinuxCgroupPath(tc.value)
			if ok != tc.ok {
				t.Fatalf("cleanLinuxCgroupPath(%q) ok = %v; want %v", tc.value, ok, tc.ok)
			}
			if ok && got != tc.value {
				t.Fatalf("cleanLinuxCgroupPath(%q) = %q; want unchanged", tc.value, got)
			}
		})
	}
}

func TestLinuxSnapshotProviderToleratesAbsentV2LimitFiles(t *testing.T) {
	t.Run("root limit file absent keeps descendant limit", func(t *testing.T) {
		// Real systemd cgroup v2 layout: the root cgroup carries no resource
		// control files, descendant limits still apply.
		fixture := newLinuxSnapshotFixture()
		fixture.limits = "Limit Soft Limit Hard Limit Units\nMax address space 4194304 4194304 bytes\n"
		delete(fixture.cgroupFiles, "sys/fs/cgroup/memory.max")
		snapshot := fixture.provider(t).Snapshot(context.Background())
		if snapshot.source != snapshotSourceLinux || snapshot.state != snapshotStateReady {
			t.Fatalf("snapshot source/state = %v/%v; want Linux/ready", snapshot.source, snapshot.state)
		}
		if snapshot.effectiveAvailable != 2097152 {
			t.Fatalf("effective available = %d; want descendant cgroup headroom 2097152", snapshot.effectiveAvailable)
		}
		if snapshot.codeOwnedReserve != 262144 {
			t.Fatalf("code-owned reserve = %d; want same-snapshot VmRSS 262144", snapshot.codeOwnedReserve)
		}
	})
	t.Run("absent limit files mean unconstrained", func(t *testing.T) {
		fixture := newLinuxSnapshotFixture()
		fixture.cgroupDirs = []string{
			"sys/fs/cgroup",
			"sys/fs/cgroup/tenant",
			"sys/fs/cgroup/tenant/job",
		}
		for name := range fixture.cgroupFiles {
			if strings.HasSuffix(name, "memory.max") {
				delete(fixture.cgroupFiles, name)
			}
		}
		snapshot := fixture.provider(t).Snapshot(context.Background())
		if snapshot.state != snapshotStateReady {
			t.Fatalf("snapshot state = %v; want ready", snapshot.state)
		}
		if snapshot.effectiveAvailable != 1048576 {
			t.Fatalf("effective available = %d; want finite RLIMIT_AS headroom 1048576", snapshot.effectiveAvailable)
		}
	})
	t.Run("non-directory level is not an unconstrained cgroup", func(t *testing.T) {
		fixture := newLinuxSnapshotFixture()
		fixture.cgroup = "0::/tenant\n"
		fixture.cgroupFiles = map[string]string{
			"sys/fs/cgroup/memory.max": "max\n",
			"sys/fs/cgroup/tenant":     "not a directory\n",
		}
		snapshot := fixture.provider(t).Snapshot(context.Background())
		if snapshot.source != snapshotSourceLinux || snapshot.state != snapshotStateUnconfigured {
			t.Fatalf("snapshot source/state = %v/%v; want Linux/unconfigured", snapshot.source, snapshot.state)
		}
		if snapshot.effectiveAvailable != 0 || snapshot.codeOwnedReserve != 0 {
			t.Fatalf("non-directory cgroup level exposed resource facts: available=%d reserve=%d", snapshot.effectiveAvailable, snapshot.codeOwnedReserve)
		}
	})
	t.Run("terminal symlink level is not an unconstrained cgroup", func(t *testing.T) {
		fixture := newLinuxSnapshotFixture()
		fixture.cgroup = "0::/tenant\n"
		fixture.cgroupDirs = []string{"sys/fs/cgroup/uncontrolled"}
		fixture.cgroupFiles = map[string]string{
			"sys/fs/cgroup/memory.max": "max\n",
		}
		fixture.cgroupLinks = map[string]string{
			"sys/fs/cgroup/tenant": "uncontrolled",
		}
		snapshot := fixture.provider(t).Snapshot(context.Background())
		if snapshot.source != snapshotSourceLinux || snapshot.state != snapshotStateUnconfigured {
			t.Fatalf("snapshot source/state = %v/%v; want Linux/unconfigured", snapshot.source, snapshot.state)
		}
		if snapshot.effectiveAvailable != 0 || snapshot.codeOwnedReserve != 0 {
			t.Fatalf("terminal-symlink cgroup level exposed resource facts: available=%d reserve=%d", snapshot.effectiveAvailable, snapshot.codeOwnedReserve)
		}
	})
	t.Run("missing limit directory stays fail closed", func(t *testing.T) {
		// The whole cgroup tree absent is an anomaly, not a no-limit policy.
		fixture := newLinuxSnapshotFixture()
		fixture.cgroupFiles = map[string]string{}
		snapshot := fixture.provider(t).Snapshot(context.Background())
		if snapshot.state != snapshotStateUnconfigured {
			t.Fatalf("snapshot state = %v; want unconfigured", snapshot.state)
		}
	})
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
