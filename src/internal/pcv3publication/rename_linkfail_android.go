//go:build android

package pcv3publication

// Android filesystems or SELinux policies may deny hard links. Without either
// renameat2(RENAME_NOREPLACE) or linkat, publication must fail closed. Checking
// the destination before an ordinary rename cannot enforce atomic no-replace.
func linkFallbackFailed(_ int, _, _ string, linkErr error) error {
	return linkErr
}
