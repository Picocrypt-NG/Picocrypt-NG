//go:build linux

package fileops

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestOpenRegularReadNoSymlinkRejectsFIFODeviceAndSymlinkWithoutLeaking(t *testing.T) {
	directory := t.TempDir()
	pipe := filepath.Join(directory, "factor.pipe")
	if err := unix.Mkfifo(pipe, 0o600); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(directory, "victim")
	if err := os.WriteFile(victim, []byte("victim unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{pipe, "/dev/null", link, directory} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			done := make(chan error, 1)
			go func() {
				file, err := OpenRegularReadNoSymlink(path)
				if file != nil {
					_ = file.Close()
				}
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("nonregular input accepted")
				}
			case <-time.After(250 * time.Millisecond):
				if path == pipe {
					fd, err := unix.Open(pipe, unix.O_WRONLY|unix.O_NONBLOCK, 0)
					if err != nil {
						t.Fatal(err)
					}
					_ = unix.Close(fd)
					select {
					case <-done:
					case <-time.After(2 * time.Second):
						t.Fatal("FIFO reader remained blocked after peer release")
					}
				}
				t.Fatal("nonregular input admission blocked")
			}
		})
	}
	// Each rejected descriptor for these unique test-owned names must have
	// been closed before the helper returned; inspecting the live descriptors
	// also catches a close omitted after fstat rejects a directory or FIFO.
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if name == directory || name == pipe || name == victim || name == link {
			t.Fatalf("rejected admission leaked descriptor %s for %s", entry.Name(), name)
		}
	}
	got, err := os.ReadFile(victim)
	if err != nil || string(got) != "victim unchanged" {
		t.Fatalf("symlink victim changed: %q, %v", got, err)
	}
}
