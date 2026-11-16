package ui

import (
	"Picocrypt-NG/internal/fileops"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanFoldersRetainsOriginalDirectoryAuthorityThroughTemporaryArchive(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "selected")
	nested := filepath.Join(root, "nested")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(nested, "document.txt")
	if err := os.WriteFile(source, []byte("original selection"), 0o600); err != nil {
		t.Fatal(err)
	}
	var paths []string
	var identities []fileops.ZIPInputIdentity
	err := scanFolders(context.Background(), []string{root}, func(_ context.Context, batch []scannedFile) error {
		for _, file := range batch {
			paths = append(paths, file.path)
			identities = append(identities, file.identity)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || paths[0] != source {
		t.Fatalf("scan paths=%v", paths)
	}
	if err := os.Rename(root, root+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(root+".original", root); err != nil {
		t.Fatal(err)
	}
	owner, err := fileops.CreateTempZip(context.Background(), fileops.TempZipOptions{Files: paths, InputIdentities: identities, RootDir: root, NearPath: filepath.Join(dir, "result.pcv"), MaxPhysicalBytes: 1 << 20})
	if owner != nil {
		_ = owner.Close()
	}
	if err == nil {
		t.Fatal("folder-drop scan lost original directory authority before archive read")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".picocrypt-") {
			t.Fatalf("archive rejection leaked %s", entry.Name())
		}
	}
}
