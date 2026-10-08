//go:build !darwin

package fileops

import "os"

// SyncDirectory synchronizes the directory using the platform's file barrier.
func SyncDirectory(parent *os.File) error {
	return parent.Sync()
}
