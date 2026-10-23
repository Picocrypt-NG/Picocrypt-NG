//go:build windows

package fileops

import (
	"errors"
	"testing"
)

func TestWindowsDirectoryDurabilityRejectsVolatileAndUnclassifiedStorage(t *testing.T) {
	// These are eligibility policy cases, not evidence that a storage device
	// honors flushes. In particular, a RAM disk cannot authorize source deletion.
	for _, test := range []struct {
		name            string
		deviceType      uint32
		characteristics uint32
		driveType       uint32
		want            bool
	}{
		{"fixed disk", 7, 0x20, 3, true},
		{"removable disk", 7, 0x21, 2, true},
		{"remote device reporting fixed", 7, 0x30, 3, false},
		{"virtual volume reporting fixed", 7, 0x60, 3, false},
		{"remote virtual volume", 7, 0x70, 3, false},
		{"RAM disk without virtual flag", 7, 0x20, 6, false},
		{"unknown drive", 7, 0x20, 0, false},
		{"invalid volume root", 7, 0x20, 1, false},
		{"network drive", 7, 0x20, 4, false},
		{"optical drive", 7, 0x20, 5, false},
		{"future drive type", 7, 0x20, 99, false},
		{"unknown device", 0, 0x20, 3, false},
		{"optical device reporting fixed", 2, 0x20, 3, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := windowsDurableVolume(test.deviceType, test.characteristics, test.driveType); got != test.want {
				t.Fatalf("directory durability eligibility = %v; want %v", got, test.want)
			}
		})
	}
}

func TestWindowsDirectoryDriveQueryRequiresVolumeGUIDRoot(t *testing.T) {
	const root = `\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\`
	for _, test := range []struct {
		name string
		path string
		want string
	}{
		{"root", root, root},
		{"nested Unicode directory", root + `owned\данные`, root},
		{"drive letter", `C:\owned`, ""},
		{"UNC", `\\server\share\owned`, ""},
		{"NT path", `\Device\HarddiskVolume1\owned`, ""},
		{"missing root separator", root[:len(root)-1], ""},
		{"invalid GUID", `\\?\Volume{g1234567-89ab-cdef-0123-456789abcdef}\owned`, ""},
		{"empty", "", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := windowsVolumeGUIDRoot(test.path)
			if test.want == "" {
				if !errors.Is(err, errors.ErrUnsupported) || got != "" {
					t.Fatalf("unclassified volume root = %q/%v; want unsupported", got, err)
				}
			} else if err != nil || got != test.want {
				t.Fatalf("volume root = %q/%v; want %q", got, err, test.want)
			}
		})
	}
}
