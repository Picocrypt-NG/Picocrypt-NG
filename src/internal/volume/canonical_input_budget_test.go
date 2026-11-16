//go:build linux

package volume

import (
	"Picocrypt-NG/internal/fileops"
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestPrepareZIPAdmitsCanonicalInputMetadataBeforeArchivePhase(t *testing.T) {
	dir := t.TempDir()
	canonical := dir
	for index := range 14 {
		canonical = filepath.Join(canonical, strings.Repeat("d", 220)+strconv.Itoa(index))
	}
	if err := os.MkdirAll(canonical, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(canonical, alias); err != nil {
		t.Fatal(err)
	}
	var paths []string
	for index := range 48 {
		path := filepath.Join(alias, fmt.Sprintf("f%03d", index))
		if err := os.WriteFile(path, []byte{byte(index)}, 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	for _, limited := range []bool{true, false} {
		t.Run(strconv.FormatBool(limited), func(t *testing.T) {
			budget := fileops.NewZIPResourceBudget()
			var baseline uint64
			if limited {
				baseline = budget.LimitBytes() - ((1 << 20) + (160 << 10))
				if err := budget.Reserve(baseline); err != nil {
					t.Fatal(err)
				}
			}
			reporter := &GoldenTestReporter{}
			prepared, err := PrepareEncryptInput(context.Background(), EncryptInputRequest{InputFile: paths[0], InputFiles: paths, OutputFile: filepath.Join(dir, "result.pcv"), PCV3: true, ZIPBudget: budget, Reporter: reporter})
			if limited {
				if prepared != nil {
					defer prepared.Close()
				}
				if !errors.Is(err, fileops.ErrZIPMetadataLimit) || prepared != nil {
					t.Fatalf("canonical admission: prepared=%v err=%v", prepared, err)
				}
				// This public phase starts only after input snapshots have been admitted.
				if strings.Contains(reporter.status, "Compressing") {
					t.Fatalf("unadmitted canonical snapshots reached archive phase: %q", reporter.status)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				defer prepared.Close()
				data, err := io.ReadAll(prepared.Reader())
				if err != nil {
					t.Fatal(err)
				}
				archive, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
				if err != nil {
					t.Fatal(err)
				}
				if len(archive.File) != len(paths) {
					t.Fatalf("archive entries=%d", len(archive.File))
				}
				for index, entry := range archive.File {
					member, err := entry.Open()
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(member)
					if closeErr := member.Close(); err != nil || closeErr != nil || !bytes.Equal(body, []byte{byte(index)}) {
						t.Fatalf("entry%d=%x err=%v close=%v", index, body, err, closeErr)
					}
				}
				if err := prepared.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if budget.CurrentBytes() != baseline {
				t.Fatalf("input preparation retained metadata=%d", budget.CurrentBytes()-baseline)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".picocrypt-") || entry.Name() == "result.pcv" {
					t.Fatalf("preparation left stage/output %q", entry.Name())
				}
			}
		})
	}
}
