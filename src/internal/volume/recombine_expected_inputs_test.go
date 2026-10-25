package volume

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func writeExpectedInputChunks(t *testing.T, data []byte) (string, []os.FileInfo) {
	t.Helper()
	base := filepath.Join(t.TempDir(), "input.pcv")
	infos := make([]os.FileInfo, 2)
	for i, part := range [][]byte{data[:len(data)/2], data[len(data)/2:]} {
		path := base + "." + strconv.Itoa(i)
		if err := os.WriteFile(path, part, 0o600); err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		infos[i], err = file.Stat()
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			t.Fatalf("capture chunk: %v %v", err, closeErr)
		}
	}
	return base, infos
}

func TestVolumeRecombineExpectedInputsRefusesBeforeKDF(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden", "pico_test_v2.txt.pcv"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, want string }{
		{"first_identity", "chunk 0 changed"},
		{"later_identity", "chunk 1 changed"},
		{"first_size", "chunk 0 changed"},
		{"later_size", "chunk 1 changed"},
		{"added_count", "expected 2 chunk identities, found 3"},
		{"deleted_count", "expected 2 chunk identities, found 1"},
		{"empty", "chunk 0 changed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base, expected := writeExpectedInputChunks(t, fixture)
			switch tc.name {
			case "first_identity", "later_identity":
				index := 0
				if tc.name == "later_identity" {
					index = 1
				}
				path := base + "." + strconv.Itoa(index)
				body, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(path, path+".captured"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, body, 0o600); err != nil {
					t.Fatal(err)
				}
			case "first_size", "later_size":
				index := 0
				if tc.name == "later_size" {
					index = 1
				}
				if err := os.Truncate(base+"."+strconv.Itoa(index), expected[index].Size()+1); err != nil {
					t.Fatal(err)
				}
			case "added_count":
				if err := os.WriteFile(base+".2", []byte("late"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "deleted_count":
				if err := os.Rename(base+".1", base+".1.captured"); err != nil {
					t.Fatal(err)
				}
			case "empty":
				expected = []os.FileInfo{}
			}
			entries, err := os.ReadDir(filepath.Dir(base))
			if err != nil {
				t.Fatal(err)
			}
			before := make(map[string][]byte)
			for _, entry := range entries {
				path := filepath.Join(filepath.Dir(base), entry.Name())
				before[path], err = os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			previous := deriveVolumeKey
			deriveVolumeKey = func([]byte, []byte, bool) ([]byte, error) { calls++; return nil, errors.New("unexpected KDF") }
			defer func() { deriveVolumeKey = previous }()
			output := filepath.Join(filepath.Dir(base), "plaintext")
			err = Decrypt(context.Background(), &DecryptRequest{InputFile: base + ".0", OutputFile: output, Password: []byte("test"), RSCodecs: newRSCodecsT(t), Recombine: true, RecombineExpectedInputs: expected})
			if err == nil || !strings.Contains(err.Error(), tc.want) || calls != 0 {
				t.Fatalf("refusal=%v KDF calls=%d; want %q before KDF", err, calls, tc.want)
			}
			for path, want := range before {
				got, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(got, want) {
					t.Fatalf("source changed %s: %v", path, err)
				}
			}
			for _, path := range []string{base, output} {
				if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("refusal left output %s: %v", path, err)
				}
			}
			after, err := os.ReadDir(filepath.Dir(base))
			if err != nil || len(after) != len(before) {
				t.Fatalf("refusal left staging: %v %v", after, err)
			}
		})
	}
}

func TestVolumeRecombineExpectedInputsRequiresRecombine(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("..", "..", "testdata", "golden", "pico_test_v2.txt.pcv"))
	if err != nil {
		t.Fatal(err)
	}
	for _, prepared := range []bool{false, true} {
		t.Run(strconv.FormatBool(prepared), func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "input.pcv")
			if err := os.WriteFile(input, fixture, 0o600); err != nil {
				t.Fatal(err)
			}
			req := &DecryptRequest{InputFile: input, OutputFile: filepath.Join(dir, "plaintext"), Password: []byte("test"), RSCodecs: newRSCodecsT(t), RecombineExpectedInputs: []os.FileInfo{}}
			calls := 0
			previous := deriveVolumeKey
			deriveVolumeKey = func([]byte, []byte, bool) ([]byte, error) { calls++; return nil, errors.New("unexpected KDF") }
			defer func() { deriveVolumeKey = previous }()
			if prepared {
				preparedInput, prepareErr := PrepareDecryptInput(input, false)
				if prepareErr != nil {
					t.Fatal(prepareErr)
				}
				defer preparedInput.Close()
				err = DecryptPrepared(context.Background(), req, preparedInput)
			} else {
				err = Decrypt(context.Background(), req)
			}
			if err == nil || !strings.Contains(err.Error(), "Recombine") || calls != 0 {
				t.Fatalf("inconsistent request=%v KDF calls=%d", err, calls)
			}
			body, readErr := os.ReadFile(input)
			entries, dirErr := os.ReadDir(dir)
			if readErr != nil || !bytes.Equal(body, fixture) || dirErr != nil || len(entries) != 1 {
				t.Fatalf("refusal changed input or left output: %v %v %v", readErr, entries, dirErr)
			}
		})
	}
}

func TestVolumeRecombineExpectedInputsCompatibility(t *testing.T) {
	dir := t.TempDir()
	plain := []byte("expected chunk identities protect the consumed encrypted bytes")
	input := filepath.Join(dir, "original")
	volume := filepath.Join(dir, "original.pcv")
	if err := os.WriteFile(input, plain, 0o600); err != nil {
		t.Fatal(err)
	}
	// TestMain's fast KDF keeps this native pipeline check separate from the
	// frozen production-KDF compatibility case in the desktop package.
	if err := Encrypt(context.Background(), &EncryptRequest{InputFile: input, OutputFile: volume, Password: []byte("test"), RSCodecs: newRSCodecsT(t)}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(volume)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"nil", "unchanged", "borrowed_first_chunk"} {
		t.Run(name, func(t *testing.T) {
			base, expected := writeExpectedInputChunks(t, data)
			req := &DecryptRequest{InputFile: base + ".0", OutputFile: base + ".plaintext", Password: []byte("test"), RSCodecs: newRSCodecsT(t), Recombine: true}
			if name != "nil" {
				req.RecombineExpectedInputs = expected
			}
			if name == "borrowed_first_chunk" {
				prepared, prepareErr := PrepareDecryptInput(req.InputFile, true)
				if prepareErr != nil {
					t.Fatal(prepareErr)
				}
				defer prepared.Close()
				chunkPath := base + ".0"
				movedPath := chunkPath + ".captured"
				original := data[:len(data)/2]
				requireBorrowedChunk := func() {
					t.Helper()
					info, statErr := prepared.file.Stat()
					if statErr != nil || !os.SameFile(expected[0], info) || info.Size() != int64(len(original)) {
						t.Fatalf("borrowed first chunk closed or changed: %v", statErr)
					}
					got := make([]byte, len(original))
					n, readErr := prepared.file.ReadAt(got, 0)
					if readErr != nil || n != len(original) || !bytes.Equal(got, original) {
						t.Fatalf("borrowed first chunk bytes changed: n=%d err=%v", n, readErr)
					}
				}
				wantPathBytes := []byte("unconsumed replacement")
				renameErr := os.Rename(chunkPath, movedPath)
				if renameErr != nil {
					if !windowsPreventedOpenHandleRename(renameErr) {
						t.Fatalf("move borrowed first chunk: %v", renameErr)
					}
					info, statErr := os.Stat(chunkPath)
					if statErr != nil || !os.SameFile(expected[0], info) {
						t.Fatalf("blocked rename changed first chunk identity: %v", statErr)
					}
					if _, statErr := os.Lstat(movedPath); !errors.Is(statErr, os.ErrNotExist) {
						t.Fatalf("blocked rename created moved first chunk: %v", statErr)
					}
					wantPathBytes = original
					got, readErr := os.ReadFile(chunkPath)
					if readErr != nil || !bytes.Equal(got, original) {
						t.Fatalf("blocked rename changed first chunk bytes: %v", readErr)
					}
					t.Logf("OS prevented borrowed first chunk replacement: %v", renameErr)
				} else if err := os.WriteFile(chunkPath, wantPathBytes, 0o600); err != nil {
					t.Fatal(err)
				}
				requireBorrowedChunk()
				err = DecryptPrepared(context.Background(), req, prepared)
				requireBorrowedChunk()
				got, readErr := os.ReadFile(chunkPath)
				if readErr != nil || !bytes.Equal(got, wantPathBytes) {
					t.Fatalf("first chunk pathname bytes changed: %q %v", got, readErr)
				}
			} else {
				err = Decrypt(context.Background(), req)
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(req.OutputFile)
			if err != nil || !bytes.Equal(got, plain) {
				t.Fatalf("plaintext=%q err=%v", got, err)
			}
			if _, err := os.Lstat(base); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("recombined temporary remains: %v", err)
			}
			for i := range 2 {
				if _, err := os.Stat(base + "." + strconv.Itoa(i)); err != nil {
					t.Fatalf("volume reader deleted source: %v", err)
				}
			}
		})
	}
}
