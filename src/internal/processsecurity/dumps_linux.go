//go:build linux && !android

// Package processsecurity applies executable startup policy. Shared crypto and
// embedding entry points must not change their host process's dump policy.
package processsecurity

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// RestrictDumps disables Linux kernel core dumps and ordinary peer ptrace access
// for this process. Call once before accepting application input; do not restore
// dumpability while secret copies may remain alive.
//
// Flatpak and the packaged Snap executable retain their existing dump policy:
// desktop portals need access to /proc/PID/root. A nil result in these packages
// therefore does not mean dump protection was enabled. Native portal behavior
// must be validated before extending this policy to them.
func RestrictDumps() error {
	if info, err := os.Stat("/.flatpak-info"); err == nil && info.Mode().IsRegular() {
		return nil
	}
	if snapDir := os.Getenv("SNAP"); snapDir != "" {
		// Canonicalize /snap symlinks, including the snapd layout and current
		// revision. An environment variable alone must not exempt a direct binary.
		if snapDir, err := filepath.EvalSymlinks(snapDir); err == nil {
			if executable, err := os.Executable(); err == nil && isSnapExecutable(snapDir, executable) {
				return nil
			}
		}
	}
	return disableDumps(func() error {
		return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
	}, func() (int, error) {
		return unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	})
}

func disableDumps(set func() error, get func() (int, error)) error {
	if err := set(); err != nil {
		return fmt.Errorf("disable process dumps: %w", err)
	}
	state, err := get()
	if err != nil {
		return fmt.Errorf("verify process dump protection: %w", err)
	}
	if state != 0 {
		return fmt.Errorf("process dump protection was not enabled (dumpable=%d)", state)
	}
	return nil
}

// Paths come from the canonical SNAP directory and the kernel's executable
// path. Only the shipped binary in a system snap revision receives the portal
// exemption, including parallel installations of picocrypt-ng.
func isSnapExecutable(snapDir, executable string) bool {
	for _, base := range []string{"/snap/", "/var/lib/snapd/snap/"} {
		if rest, ok := strings.CutPrefix(snapDir, base); ok {
			parts := strings.Split(rest, "/")
			if len(parts) != 2 || parts[1] == "" {
				return false
			}
			name := parts[0]
			instance, parallel := strings.CutPrefix(name, "picocrypt-ng_")
			if name != "picocrypt-ng" && (!parallel || instance == "") {
				return false
			}
			return executable == filepath.Join(snapDir, "bin", "Picocrypt-NG")
		}
	}
	return false
}
