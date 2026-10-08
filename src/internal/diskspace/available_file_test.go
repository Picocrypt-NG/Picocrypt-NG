package diskspace

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAvailableFileObservesHeldFilesystemAndRejectsClosedFile(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "held-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	free, err := AvailableFile(file)
	if err != nil || free <= 0 {
		t.Fatalf("held filesystem: %d %v", free, err)
	}
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		if err := os.Rename(file.Name(), filepath.Join(filepath.Dir(file.Name()), "renamed")); err != nil {
			t.Fatal(err)
		}
		if free, err = AvailableFile(file); err != nil || free <= 0 {
			t.Fatalf("renamed held stage: %d %v", free, err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := AvailableFile(file); err == nil {
		t.Fatal("closed held file accepted")
	}
	if _, err := AvailableFile(nil); err == nil {
		t.Fatal("nil held file accepted")
	}
}
