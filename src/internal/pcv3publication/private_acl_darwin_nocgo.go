//go:build darwin && !cgo

package pcv3publication

import (
	"errors"
	"os"
)

// Darwin extended ACLs override BSD mode bits. The native fd ACL API requires
// the supported CGO build; a pure-Go build must refuse before creating a stage.
func privateDirectoryBackendAvailable() bool         { return false }
func establishPrivateDirectoryACL(*os.File) error    { return errors.ErrUnsupported }
func directoryACLAllowsTrustedCleanup(*os.File) bool { return false }

func privateDirectoryParentTrusted(*os.File) bool { return false }
