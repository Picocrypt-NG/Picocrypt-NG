//go:build linux || android

package pcv3operation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func requireWriteJournalBeforeKDF(t *testing.T, parent string) {
	t.Helper()
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	var private string
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".picocrypt-pcv3-private-") {
			if private != "" {
				t.Fatal("multiple operation directories before KDF")
			}
			private = filepath.Join(parent, entry.Name())
		}
	}
	if private == "" {
		t.Fatal("KDF reached without private cleanup custody")
	}
	directoryInfo, err := os.Lstat(private)
	if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode().Perm() != 0o700 {
		t.Fatalf("private directory identity/mode: %v %v", directoryInfo, err)
	}
	raw, err := os.ReadFile(filepath.Join(private, ".picocrypt-pcv3-stage.journal"))
	if err != nil {
		t.Fatalf("KDF reached before v2 cleanup journal: %v", err)
	}
	type identity struct {
		Device uint64 `json:"device"`
		Inode  uint64 `json:"inode"`
		UID    uint64 `json:"uid"`
		Links  uint64 `json:"links"`
	}
	var record struct {
		Version     int      `json:"version"`
		Stage       string   `json:"stage"`
		Target      string   `json:"target"`
		Parent      identity `json:"parent"`
		Destination identity `json:"destination"`
		File        identity `json:"file"`
	}
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	if record.Version != 2 || record.Stage == "" || filepath.Base(record.Stage) != record.Stage || record.Target != "output" {
		t.Fatalf("wrong pre-KDF recovery binding: %+v", record)
	}
	fileInfo, err := os.Lstat(filepath.Join(private, record.Stage))
	if err != nil || !fileInfo.Mode().IsRegular() || fileInfo.Mode().Perm() != 0o600 {
		t.Fatalf("recorded original stage is unavailable: %v %v", fileInfo, err)
	}
	parentInfo, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, binding := range []struct {
		recorded identity
		actual   os.FileInfo
	}{{record.Parent, directoryInfo}, {record.Destination, parentInfo}, {record.File, fileInfo}} {
		actual, ok := binding.actual.Sys().(*syscall.Stat_t)
		if !ok || actual == nil || binding.recorded.Device != actual.Dev || binding.recorded.Inode != actual.Ino || binding.recorded.UID != uint64(actual.Uid) {
			t.Fatal("pre-KDF journal does not identify the actual owned directory/file")
		}
	}
	if record.File.Links != 1 {
		t.Fatal("pre-KDF journal granted shared-link cleanup authority")
	}
}
