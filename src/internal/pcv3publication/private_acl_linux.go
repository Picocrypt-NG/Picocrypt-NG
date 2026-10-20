//go:build linux

package pcv3publication

import "os"

func privateDirectoryBackendAvailable() bool      { return true }
func establishPrivateDirectoryACL(*os.File) error { return nil }

// Linux POSIX ACL permissions for non-owners are bounded by the group mask
// already verified in the directory's BSD mode bits.
func directoryACLAllowsTrustedCleanup(*os.File) bool { return true }

func privateDirectoryParentTrusted(*os.File) bool { return true }
