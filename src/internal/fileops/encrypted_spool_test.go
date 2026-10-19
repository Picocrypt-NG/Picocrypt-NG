package fileops

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
)

// A sealed input must support the validation pass and the transport pass without
// ever granting simultaneous plaintext readers or plaintext staging authority.
func TestTempZipSequentialReadersReauthenticate(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "input")
	if err := os.WriteFile(source, []byte("repeatable private input"), 0o600); err != nil {
		t.Fatal(err)
	}
	owner, err := CreateTempZip(context.Background(), TempZipOptions{Files: []string{source}, RootDir: dir, NearPath: filepath.Join(dir, "output"), MaxPhysicalBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	first, err := owner.OpenReader()
	if err != nil {
		t.Fatal(err)
	}
	want, err := io.ReadAll(first)
	if err != nil {
		t.Fatal(err)
	}
	closer, ok := first.(io.Closer)
	if !ok {
		t.Fatal("authenticated reader cannot release its exclusive read session")
	}
	if err := closer.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := owner.OpenReader()
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(second)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("repeat read: %v", err)
	}
}

func TestEncryptedSpoolPrivateDiskAndRepeatableLength(t *testing.T) {
	for _, size := range []int{0, 1, 65536, 65537, 196608} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			owner, err := CreateEncryptedSpool(context.Background(), EncryptedSpoolOptions{NearPath: filepath.Join(t.TempDir(), "out"), MaxPhysicalBytes: 1 << 20})
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			if _, err := owner.OpenReader(); err == nil {
				t.Fatal("unsealed reader accepted")
			}
			plain := bytes.Repeat([]byte("plain secret marker "), (size+19)/20)[:size]
			if n, err := owner.Write(plain); err != nil || n != size {
				t.Fatalf("write=%d %v", n, err)
			}
			physical, err := os.ReadFile(owner.Path())
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(physical, []byte("plain secret marker")) {
				t.Fatal("plaintext reached disk before seal")
			}
			if err := owner.Seal(); err != nil {
				t.Fatal(err)
			}
			if owner.Length() != uint64(size) {
				t.Fatalf("logical size=%d", owner.Length())
			}
			info, err := owner.File().Stat()
			if err != nil {
				t.Fatal(err)
			}
			records := (size + 65535) / 65536
			if records == 0 {
				records = 1
			}
			if info.Size() != int64(size+16*records) || info.Mode().Perm() != 0o600 {
				t.Fatalf("physical metadata=%v", info)
			}
			if _, err := owner.Write([]byte{1}); err == nil {
				t.Fatal("sealed key reused for writing")
			}
			for range 2 {
				reader, err := owner.OpenReader()
				if err != nil {
					t.Fatal(err)
				}
				if _, err := owner.OpenReader(); err == nil {
					t.Fatal("simultaneous reader accepted")
				}
				got, err := io.ReadAll(reader)
				if err != nil || !bytes.Equal(got, plain) {
					t.Fatalf("read=%d %v", len(got), err)
				}
				if err := reader.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestEncryptedSpoolPhysicalBudgetIncludesEveryTag(t *testing.T) {
	owner, err := CreateEncryptedSpool(context.Background(), EncryptedSpoolOptions{NearPath: filepath.Join(t.TempDir(), "out"), MaxPhysicalBytes: 65568})
	if err != nil {
		t.Fatal(err)
	}
	path := owner.Path()
	if _, err := owner.Write(make([]byte, 65537)); err == nil {
		t.Fatal("second record tag bypassed physical disk budget")
	}
	if err := owner.Seal(); err == nil {
		t.Fatal("failed writer was sealed")
	}
	if _, err := owner.OpenReader(); err == nil {
		t.Fatal("failed writer exposed plaintext")
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed stage retained: %v", err)
	}
}

func TestEncryptedSpoolRejectsMutatedPhysicalStream(t *testing.T) {
	for _, mutation := range []string{"tamper", "truncate", "append", "reorder", "final-tag"} {
		t.Run(mutation, func(t *testing.T) {
			owner, err := CreateEncryptedSpool(context.Background(), EncryptedSpoolOptions{NearPath: filepath.Join(t.TempDir(), "out"), MaxPhysicalBytes: 1 << 20})
			if err != nil {
				t.Fatal(err)
			}
			defer owner.Close()
			plain := bytes.Repeat([]byte("distinctive confidential stream"), 7000)
			if _, err := owner.Write(plain); err != nil {
				t.Fatal(err)
			}
			if err := owner.Seal(); err != nil {
				t.Fatal(err)
			}
			ciphertext, err := os.ReadFile(owner.Path())
			if err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "tamper":
				ciphertext[0] ^= 1
			case "truncate":
				ciphertext = ciphertext[:len(ciphertext)-16]
			case "append":
				ciphertext = append(ciphertext, 1)
			case "reorder":
				first := append([]byte(nil), ciphertext[:65552]...)
				copy(ciphertext[:65552], ciphertext[65552:131104])
				copy(ciphertext[65552:131104], first)
			case "final-tag":
				ciphertext[len(ciphertext)-1] ^= 1
			}
			if err := owner.File().Truncate(int64(len(ciphertext))); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.File().WriteAt(ciphertext, 0); err != nil {
				t.Fatal(err)
			}
			reader, err := owner.OpenReader()
			if err == nil {
				var got []byte
				got, err = io.ReadAll(reader)
				if len(got) >= len(plain) {
					t.Fatal("corrupt stream released complete plaintext")
				}
				_ = reader.Close()
			}
			if err == nil || errors.Is(err, io.EOF) {
				t.Fatalf("mutation accepted as completion: %v", err)
			}
		})
	}
}

func TestEncryptedSpoolCancellationWipesAndRevokesActiveReader(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	owner, err := CreateEncryptedSpool(ctx, EncryptedSpoolOptions{NearPath: filepath.Join(t.TempDir(), "out"), MaxPhysicalBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Write(bytes.Repeat([]byte{0x55}, 100000)); err != nil {
		t.Fatal(err)
	}
	if err := owner.Seal(); err != nil {
		t.Fatal(err)
	}
	reader, err := owner.OpenReader()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	scratch := owner.reader.buf[:]
	cancel()
	if _, err := reader.Read(make([]byte, 1)); err == nil {
		t.Fatal("cancelled reader released plaintext")
	}
	if !bytes.Equal(scratch, make([]byte, len(scratch))) {
		t.Fatal("cancelled plaintext scratch retained")
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Read(make([]byte, 1)); err == nil || errors.Is(err, io.EOF) {
		t.Fatal("closed reader usable")
	}
}

func TestEncryptedSpoolRejectsMissingStageDirectoryAuthority(t *testing.T) {
	owner, err := CreateEncryptedSpool(context.Background(), EncryptedSpoolOptions{MaxPhysicalBytes: 1 << 20})
	if owner != nil {
		_ = owner.Close()
	}
	if err == nil {
		t.Fatal("empty NearPath created ciphertext beside the current working directory")
	}
}

func TestEncryptedSpoolReaderCloseWipesAndNextPassAuthenticatesAgain(t *testing.T) {
	owner, err := CreateEncryptedSpool(context.Background(), EncryptedSpoolOptions{NearPath: filepath.Join(t.TempDir(), "out"), MaxPhysicalBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if _, err := owner.Write(bytes.Repeat([]byte{0x66}, 65536)); err != nil {
		t.Fatal(err)
	}
	if err := owner.Seal(); err != nil {
		t.Fatal(err)
	}
	reader, err := owner.OpenReader()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	scratch := owner.reader.buf[:]
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(scratch, make([]byte, len(scratch))) {
		t.Fatal("closing read session retained unread plaintext")
	}
	// Flip an existing byte deterministically, instead of assuming its random value.
	var tag [1]byte
	if _, err := owner.File().ReadAt(tag[:], 65537); err != nil {
		t.Fatal(err)
	}
	tag[0] ^= 1
	if _, err := owner.File().WriteAt(tag[:], 65537); err != nil {
		t.Fatal(err)
	}
	next, err := owner.OpenReader()
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	got, err := io.ReadAll(next)
	if err == nil || len(got) != 0 || errors.Is(err, io.EOF) {
		t.Fatalf("repeat session reused unauthenticated bytes: %d %v", len(got), err)
	}
}

func TestEncryptedSpoolRealWriteFailureNeverSealsOrReusesKey(t *testing.T) {
	owner, err := CreateEncryptedSpool(context.Background(), EncryptedSpoolOptions{NearPath: filepath.Join(t.TempDir(), "out"), MaxPhysicalBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	path := owner.Path()
	if err := owner.File().Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Write(make([]byte, 65537)); err == nil {
		t.Fatal("closed storage accepted a physical write")
	}
	if err := owner.Seal(); err == nil {
		t.Fatal("failed physical writer transferred a sealed object")
	}
	if _, err := owner.Write([]byte("retry under reused key")); err == nil {
		t.Fatal("failed key session restarted")
	}
	if _, err := owner.OpenReader(); err == nil {
		t.Fatal("failed write exposed plaintext reader")
	}
	if err := owner.Close(); err == nil {
		t.Fatal("failed original descriptor close was swallowed")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed write left owned stage: %v", err)
	}
}

func TestEncryptedSpoolKernelDiskFullFailsClosedAndCleansStage(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("kernel ENOSPC injection requires Linux /dev/full")
	}
	full, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer full.Close()
	owner, err := CreateEncryptedSpool(context.Background(), EncryptedSpoolOptions{NearPath: filepath.Join(t.TempDir(), "out"), MaxPhysicalBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	path := owner.Path()
	// Use the existing private Writer boundary with a real kernel ENOSPC source.
	// The owned regular stage remains real and must still be cleaned on failure.
	owner.writer.dst = full
	if _, err := owner.Write(make([]byte, 65537)); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("disk full lost: %v", err)
	}
	if err := owner.Seal(); !errors.Is(err, syscall.ENOSPC) {
		t.Fatalf("disk-full writer sealed or lost cause: %v", err)
	}
	if _, err := owner.OpenReader(); err == nil {
		t.Fatal("disk-full stream exposed plaintext")
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("disk-full stage retained: %v", err)
	}
}

func TestEncryptedSpoolConstructorCancellationReportsOnlyRealCleanupFailure(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(strconv.FormatBool(replace), func(t *testing.T) {
			dir := t.TempDir()
			replacementPath := ""
			owner, err := CreateEncryptedSpool(context.Background(), EncryptedSpoolOptions{NearPath: filepath.Join(dir, "out"), MaxPhysicalBytes: 1 << 20, Cancel: func() bool {
				entries, err := os.ReadDir(dir)
				if err != nil {
					t.Fatal(err)
				}
				if len(entries) == 0 {
					return false
				}
				if len(entries) != 1 {
					t.Fatalf("unexpected construction objects: %v", entries)
				}
				if replace {
					replacementPath = filepath.Join(dir, entries[0].Name())
					if err := os.Rename(replacementPath, replacementPath+".moved"); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(replacementPath, []byte("foreign replacement"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				return true
			}})
			if owner != nil {
				_ = owner.Close()
				t.Error("cancelled constructor transferred an owner")
			}
			if !errors.Is(err, errZIPCancelled) {
				t.Errorf("cancellation cause lost: %v", err)
			}
			if errors.Is(err, ErrEncryptedSpoolCleanupIncomplete) != replace {
				t.Errorf("cleanup uncertainty=%v want=%v: %v", errors.Is(err, ErrEncryptedSpoolCleanupIncomplete), replace, err)
			}
			if replace && replacementPath != "" {
				got, readErr := os.ReadFile(replacementPath)
				if readErr != nil || string(got) != "foreign replacement" {
					t.Fatalf("constructor removed a foreign replacement: %q %v", got, readErr)
				}
			} else {
				entries, listErr := os.ReadDir(dir)
				if listErr != nil || len(entries) != 0 {
					t.Fatalf("clean cancellation left owned stage: %v %v", entries, listErr)
				}
			}
		})
	}
}
