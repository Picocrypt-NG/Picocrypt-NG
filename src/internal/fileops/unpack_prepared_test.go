package fileops

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPreparedZIPUnpackRetainsAdmittedDirectoryAcrossReopen(t *testing.T) {
	data := independentStoredZIP(t, 1, 0)
	dir := t.TempDir()
	path := filepath.Join(dir, "archive.zip")
	out := filepath.Join(dir, "out")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	budget := NewZIPResourceBudget()
	prepared, err := PrepareZIPUnpack(file, out, ZIPReadOptions{Budget: budget})
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.Close()
	copyOwner := *prepared
	// Replace the directory name without changing the inode/extent. A second
	// parse would select evil.txt instead of the independently admitted f000000.
	central := int64(binary.LittleEndian.Uint32(data[len(data)-6:]))
	if _, err := file.WriteAt([]byte("evil.tx"), central+46); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := Unpack(UnpackOptions{ZipFile: reopened, ExtractDir: out, Budget: budget, Prepared: prepared}); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(out, "f000000"))
	if err != nil || len(body) != 1 || body[0] != 0 {
		t.Fatalf("admitted entry lost: %v %v", body, err)
	}
	if _, err := os.Stat(filepath.Join(out, "evil.tx")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("changed directory was reparsed: %v", err)
	}
	if err := copyOwner.Close(); err != nil {
		t.Fatal(err)
	}
	if budget.CurrentBytes() != 0 {
		t.Fatal("copied owner retained or double-released charges")
	}
	if err := Unpack(UnpackOptions{ZipFile: reopened, ExtractDir: out, Budget: budget, Prepared: &copyOwner}); err == nil {
		t.Fatal("copied owner reused consumed metadata")
	}
	if _, err := reopened.Stat(); err != nil {
		t.Fatalf("prepared owner closed borrowed archive: %v", err)
	}
}

func TestPreparedZIPUnpackRejectsChangedSourceDestinationAndBudget(t *testing.T) {
	for _, change := range []string{"identity", "extent", "destination", "budget"} {
		t.Run(change, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "archive.zip")
			out := filepath.Join(dir, "out")
			if err := os.WriteFile(path, independentStoredZIP(t, 1, 0), 0o600); err != nil {
				t.Fatal(err)
			}
			file, err := os.OpenFile(path, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			budget := NewZIPResourceBudget()
			prepared, err := PrepareZIPUnpack(file, out, ZIPReadOptions{Budget: budget})
			if err != nil {
				t.Fatal(err)
			}
			defer prepared.Close()
			selected := file
			selectedOut := out
			selectedBudget := budget
			switch change {
			case "identity":
				replacement := filepath.Join(dir, "foreign.zip")
				if err := os.WriteFile(replacement, independentStoredZIP(t, 1, 0), 0o600); err != nil {
					t.Fatal(err)
				}
				selected, err = os.Open(replacement)
				if err != nil {
					t.Fatal(err)
				}
				defer selected.Close()
			case "extent":
				if err := file.Truncate(1); err != nil {
					t.Fatal(err)
				}
			case "destination":
				selectedOut = filepath.Join(dir, "other")
			case "budget":
				selectedBudget = NewZIPResourceBudget()
			}
			if err := Unpack(UnpackOptions{ZipFile: selected, ExtractDir: selectedOut, Budget: selectedBudget, Prepared: prepared}); err == nil {
				t.Fatal("changed prepared binding was accepted")
			}
			if _, err := os.Stat(selectedOut); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid binding created output: %v", err)
			}
			if budget.CurrentBytes() != 0 {
				t.Fatal("binding refusal retained workspace")
			}
		})
	}
}
