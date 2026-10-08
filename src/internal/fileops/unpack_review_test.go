package fileops

import (
	"Picocrypt-NG/internal/util"
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnpackReviewApprovesHighRatioArchiveWithoutChangingDefault(t *testing.T) {
	for _, approve := range []bool{false, true} {
		t.Run(map[bool]string{false: "default ratio guard", true: "reviewed budget"}[approve], func(t *testing.T) {
			extractDir := filepath.Join(t.TempDir(), "out")
			options := UnpackOptions{
				ZipPath:    filepath.Join("testdata", "unpack_high_ratio_above_floor.zip"),
				ExtractDir: extractDir,
			}
			reviews := 0
			if approve {
				options.Review = func(summary ZIPSummary) error {
					reviews++
					if summary != (ZIPSummary{Files: 1, UnpackedBytes: 2 * util.MiB}) {
						t.Fatalf("high-ratio summary = %+v", summary)
					}
					if _, err := os.Lstat(extractDir); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("review happened after output creation: %v", err)
					}
					return nil
				}
			}
			err := Unpack(options)
			if !approve {
				if err == nil || !strings.Contains(err.Error(), "decompression limit exceeded") {
					t.Fatalf("unreviewed high-ratio ZIP error = %v", err)
				}
				requireEmptyExtractionDir(t, extractDir)
				return
			}
			if err != nil || reviews != 1 {
				t.Fatalf("approved extraction err=%v reviews=%d", err, reviews)
			}
			got, err := os.ReadFile(filepath.Join(extractDir, "bomb.txt"))
			if err != nil || !bytes.Equal(got, bytes.Repeat([]byte("A"), 2*util.MiB)) {
				t.Fatalf("approved high-ratio plaintext changed: %v", err)
			}
		})
	}
}

func TestUnpackReviewSummarizesDirectoriesAndEmptyFilesBeforeOutput(t *testing.T) {
	zipPath := filepath.Join(t.TempDir(), "summary.zip")
	payload := []byte("reviewed payload")
	createStoredZipEntriesForUnpackStagingTest(t, zipPath, map[string][]byte{
		"empty-directory/":   {},
		"nested/":            {},
		"nested/payload.txt": payload,
		"empty.txt":          {},
	})
	extractDir := filepath.Join(t.TempDir(), "out")
	reviews := 0
	err := Unpack(UnpackOptions{
		ZipPath: zipPath, ExtractDir: extractDir,
		Review: func(summary ZIPSummary) error {
			reviews++
			if summary != (ZIPSummary{Files: 2, Directories: 2, UnpackedBytes: int64(len(payload))}) {
				t.Fatalf("archive summary = %+v", summary)
			}
			if _, err := os.Lstat(extractDir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("summary review created output first: %v", err)
			}
			return nil
		},
	})
	if err != nil || reviews != 1 {
		t.Fatalf("reviewed archive err=%v reviews=%d", err, reviews)
	}
	for name, want := range map[string][]byte{"nested/payload.txt": payload, "empty.txt": {}} {
		got, err := os.ReadFile(filepath.Join(extractDir, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("reviewed output %s differs: %v", name, err)
		}
	}
	if info, err := os.Stat(filepath.Join(extractDir, "empty-directory")); err != nil || !info.IsDir() {
		t.Fatalf("reviewed empty directory missing: %v", err)
	}
}

func TestUnpackReviewRefusalPanicAndCancellationLeaveNoOutput(t *testing.T) {
	declined := errors.New("archive review declined")
	for _, mode := range []string{"decline", "panic", "cancel before", "cancel after"} {
		t.Run(mode, func(t *testing.T) {
			zipPath := filepath.Join(t.TempDir(), "review.zip")
			createStoredZipForUnpackStagingTest(t, zipPath, "payload.txt", []byte("private plaintext"))
			extractDir := filepath.Join(t.TempDir(), "out")
			reviews := 0
			cancelled := mode == "cancel before"
			err := Unpack(UnpackOptions{
				ZipPath: zipPath, ExtractDir: extractDir,
				Cancel: func() bool { return cancelled },
				Review: func(ZIPSummary) error {
					reviews++
					switch mode {
					case "decline":
						return declined
					case "panic":
						panic("review callback failed")
					case "cancel after":
						cancelled = true
					}
					return nil
				},
			})
			if err == nil {
				t.Fatal("failed or cancelled review allowed extraction")
			}
			if mode == "decline" && !errors.Is(err, declined) {
				t.Fatalf("review refusal was lost: %v", err)
			}
			if strings.HasPrefix(mode, "cancel") && !strings.Contains(err.Error(), "operation cancelled") {
				t.Fatalf("review cancellation cause was lost: %v", err)
			}
			wantReviews := 1
			if mode == "cancel before" {
				wantReviews = 0
			}
			if reviews != wantReviews {
				t.Fatalf("review calls=%d, want %d", reviews, wantReviews)
			}
			if _, err := os.Lstat(extractDir); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("review failure created output or staging: %v", err)
			}
		})
	}
}

func TestUnpackReviewRejectsOverlapBeforePrompt(t *testing.T) {
	reviews := 0
	err := Unpack(UnpackOptions{
		ZipPath:    filepath.Join("testdata", "zip_payload_overlap.zip"),
		ExtractDir: filepath.Join(t.TempDir(), "out"),
		Review: func(ZIPSummary) error {
			reviews++
			return nil
		},
	})
	if err == nil || reviews != 0 {
		t.Fatalf("overlapping ZIP reached approval: err=%v reviews=%d", err, reviews)
	}
}

func TestUnpackReviewForgedShortSizeNeverPublishesAnyEntry(t *testing.T) {
	zipPath := filepath.Join(t.TempDir(), "short.zip")
	first := []byte("first verified entry")
	createStoredZipEntriesForUnpackStagingTest(t, zipPath, map[string][]byte{
		"first.txt": first,
		"last.txt":  []byte("plaintext exceeding the declared one-byte budget"),
	})
	archive, err := os.ReadFile(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	central := bytes.LastIndex(archive, []byte{'P', 'K', 1, 2})
	if central < 0 || central+28 > len(archive) {
		t.Fatal("missing ZIP central header")
	}
	binary.LittleEndian.PutUint32(archive[central+24:central+28], 1)
	if err := os.WriteFile(zipPath, archive, 0o600); err != nil {
		t.Fatal(err)
	}
	extractDir := filepath.Join(t.TempDir(), "out")
	reviews := 0
	err = Unpack(UnpackOptions{
		ZipPath: zipPath, ExtractDir: extractDir,
		Review: func(summary ZIPSummary) error {
			reviews++
			if summary != (ZIPSummary{Files: 2, UnpackedBytes: int64(len(first) + 1)}) {
				t.Fatalf("forged-short archive summary = %+v", summary)
			}
			return nil
		},
	})
	if err == nil || reviews != 1 {
		t.Fatalf("forged-short extraction err=%v reviews=%d", err, reviews)
	}
	requireEmptyExtractionDir(t, extractDir)
}
