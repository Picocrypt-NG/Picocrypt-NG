//go:build !windows

package pcv3publication

import "os"

func safePublishedRemoval(parent, original *os.File) bool { return trustedCleanupParent(parent) }
func removeOwnedFile(root *os.Root, name string, original *os.File, remove func(*os.Root, string) error) error {
	return remove(root, name)
}

func removePrivateDirectoryHandle(*os.File) error { return os.ErrInvalid }

func safeCapabilityParent(parent *os.File) bool { return trustedCleanupParent(parent) }
