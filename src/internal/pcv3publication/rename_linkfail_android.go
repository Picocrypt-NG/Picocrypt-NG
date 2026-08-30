//go:build android

package pcv3publication

import (
	"errors"

	"golang.org/x/sys/unix"
)

// linkFallbackFailed is the Android last resort for pre-3.15 kernels. Android
// SELinux neverallows untrusted_app link(2) on app_data_file (denial logged as
// avc { link }, observed on the API 24 emulator), so the link(2)+unlink(2)
// fallback always fails with EPERM/EACCES there even though the kernel
// supports hard links. Only for those permission errors, and only after
// renameat2 reported ENOSYS, this rechecks the destination and performs a
// plain renameat(2). Any other link error stays fail-closed.
//
// Semantics kept: an existing destination (any type, symlink included) is
// still refused with EEXIST, and the post-call identity-based classification
// is unchanged.
//
// Semantics weakened on this path and only here: the refusal check and the
// rename are two syscalls, so unlike renameat2(RENAME_NOREPLACE) or
// link(2)+unlink(2) the no-replace decision is not atomic. A process able to
// write the same directory that creates the destination between the check and
// the rename would be replaced. On Android the publish targets live in
// app-private storage (SAF outputs do not use filesystem paths), so only the
// app's own UID can race; this matches the guarantee java.io.File.renameTo
// gives every Android app and is the only primitive the platform exposes on
// kernel < 3.15. Returning fail-closed instead would make PCV3 publication
// entirely unavailable on Android 7 (minSdk 24).
func linkFallbackFailed(parentFD int, oldName, newName string, linkErr error) error {
	if !errors.Is(linkErr, unix.EPERM) && !errors.Is(linkErr, unix.EACCES) {
		return linkErr
	}
	var stat unix.Stat_t
	err := unix.Fstatat(parentFD, newName, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if err == nil {
		return unix.EEXIST
	}
	if !errors.Is(err, unix.ENOENT) {
		return errors.Join(linkErr, err)
	}
	return unix.Renameat(parentFD, oldName, parentFD, newName)
}
