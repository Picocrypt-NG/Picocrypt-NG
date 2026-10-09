package fileops

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestTempZipOwnerRevokesReaderWipesAndPreservesReplacement(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	body := bytes.Repeat([]byte{0x5a}, 100000)
	if e := os.WriteFile(source, body, 0o600); e != nil {
		t.Fatal(e)
	}
	owner, e := CreateTempZip(context.Background(), TempZipOptions{Files: []string{source}, RootDir: dir, NearPath: filepath.Join(dir, "out"), MaxPhysicalBytes: 1 << 20})
	if e != nil {
		t.Fatal(e)
	}
	r, e := owner.OpenReader()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = owner.OpenReader(); e == nil {
		t.Fatal("second reader accepted")
	}
	if _, e = r.Read(make([]byte, 1)); e != nil {
		t.Fatal(e)
	}
	alias := owner.reader.buf[:]
	stage := owner.Path()
	if e = os.Remove(stage); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(stage, []byte("foreign"), 0o600); e != nil {
		t.Fatal(e)
	}
	if e = owner.Close(); e != nil {
		if !strings.Contains(e.Error(), stage) {
			t.Fatalf("cleanup uncertainty lost retained stage path: %v", e)
		}
	} else {
		t.Fatal("replaced owned stage was reported cleaned")
	}
	if repeated := owner.Close(); !errors.Is(repeated, e) {
		t.Fatalf("repeated close lost cleanup uncertainty: %v; want %v", repeated, e)
	}
	if _, e = r.Read(make([]byte, 1)); e == nil || errors.Is(e, io.EOF) {
		t.Fatal("closed reader usable")
	}
	if !bytes.Equal(alias, make([]byte, len(alias))) {
		t.Fatal("unread plaintext not wiped")
	}
	got, e := os.ReadFile(stage)
	if e != nil || string(got) != "foreign" {
		t.Fatal("replacement removed")
	}
	got, e = os.ReadFile(source)
	if e != nil || !bytes.Equal(got, body) {
		t.Fatal("original changed")
	}
}

func TestTempZipBudgetFailureRemovesStageAndPreservesInput(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	body := []byte("preserve this input")
	if e := os.WriteFile(source, body, 0o600); e != nil {
		t.Fatal(e)
	}
	owner, e := CreateTempZip(context.Background(), TempZipOptions{Files: []string{source}, RootDir: dir, NearPath: filepath.Join(dir, "out"), MaxPhysicalBytes: 16})
	if e == nil || owner != nil {
		t.Fatal("budget failure accepted")
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 1 {
		t.Fatalf("residue: %v %v", entries, e)
	}
	got, e := os.ReadFile(source)
	if e != nil || !bytes.Equal(got, body) {
		t.Fatal("source damaged")
	}
}

func TestTempZipFreshObjectsRejectForeignCiphertext(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	if e := os.WriteFile(source, bytes.Repeat([]byte("private"), 20000), 0o600); e != nil {
		t.Fatal(e)
	}
	opts := TempZipOptions{Files: []string{source}, RootDir: dir, NearPath: filepath.Join(dir, "out"), MaxPhysicalBytes: 1 << 20}
	first, e := CreateTempZip(context.Background(), opts)
	if e != nil {
		t.Fatal(e)
	}
	defer first.Close()
	second, e := CreateTempZip(context.Background(), opts)
	if e != nil {
		t.Fatal(e)
	}
	defer second.Close()
	a, e := os.ReadFile(first.Path())
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(second.Path())
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Equal(a, b) {
		t.Fatal("fresh temporary objects reused key")
	}
	if _, e = second.File().WriteAt(a, 0); e != nil {
		t.Fatal(e)
	}
	r, e := second.OpenReader()
	if e != nil {
		t.Fatal(e)
	}
	got, e := io.ReadAll(r)
	if len(got) != 0 || e == nil || errors.Is(e, io.EOF) {
		t.Fatalf("foreign ciphertext accepted: %d %v", len(got), e)
	}
}

func TestTempZipChangedExtentFailsBeforeReaderTransfer(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	if e := os.WriteFile(source, []byte("input"), 0o600); e != nil {
		t.Fatal(e)
	}
	owner, e := CreateTempZip(context.Background(), TempZipOptions{Files: []string{source}, RootDir: dir, NearPath: filepath.Join(dir, "out"), MaxPhysicalBytes: 1 << 20})
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close()
	info, e := owner.File().Stat()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = owner.File().WriteAt([]byte{1}, info.Size()); e != nil {
		t.Fatal(e)
	}
	if _, e = owner.OpenReader(); e == nil {
		t.Fatal("changed extent admitted")
	}
}

func TestTempZipSyncFailureNeverTransfersAndCleansOwnedStage(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	body := []byte("source survives sync failure")
	if e := os.WriteFile(source, body, 0o600); e != nil {
		t.Fatal(e)
	}
	fault := errors.New("sync I/O failure")
	owner, e := createTempZip(context.Background(), TempZipOptions{Files: []string{source}, RootDir: dir, NearPath: filepath.Join(dir, "out"), MaxPhysicalBytes: 1 << 20}, func(f *os.File) error {
		info, e := f.Stat()
		if e != nil || info.Size() == 0 {
			t.Fatal("sync reached before encrypted output")
		}
		return fault
	})
	if owner != nil || !errors.Is(e, fault) {
		t.Fatalf("sync failure transferred owner: %v %v", owner, e)
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 1 {
		t.Fatalf("sync failure left stage: %v %v", entries, e)
	}
	got, e := os.ReadFile(source)
	if e != nil || !bytes.Equal(got, body) {
		t.Fatal("source damaged")
	}
}

func TestTempZipCancellationAfterSyncStillRemovesStage(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	if e := os.WriteFile(source, []byte("input"), 0o600); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	owner, e := createTempZip(ctx, TempZipOptions{Files: []string{source}, RootDir: dir, NearPath: filepath.Join(dir, "out"), MaxPhysicalBytes: 1 << 20}, func(f *os.File) error { e := f.Sync(); cancel(); return e })
	if owner != nil || e == nil {
		t.Fatal("cancel after Sync transferred owner")
	}
	entries, e := os.ReadDir(dir)
	if e != nil || len(entries) != 1 {
		t.Fatalf("cancel after Sync left stage: %v %v", entries, e)
	}
}

func BenchmarkTempStreamBoundedWrite(b *testing.B) {
	for _, size := range []int{1 << 20, 64 << 20} {
		b.Run(strconv.Itoa(size), func(b *testing.B) {
			a, _ := chacha20poly1305.New(tempStreamKey())
			p := tempStreamPlain(65536)
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for range b.N {
				w := newTempStreamWriter(io.Discard, a, math.MaxInt64, nil)
				for done := 0; done < size; done += len(p) {
					if _, e := w.Write(p); e != nil {
						b.Fatal(e)
					}
				}
				if e := w.finish(); e != nil {
					b.Fatal(e)
				}
				w.close()
			}
		})
	}
}

func TestTempZipCopiedOwnerCannotAcquireSecondReadOrCleanupAuthority(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	if e := os.WriteFile(source, []byte("source"), 0o600); e != nil {
		t.Fatal(e)
	}
	owner, e := CreateTempZip(context.Background(), TempZipOptions{Files: []string{source}, RootDir: dir, NearPath: filepath.Join(dir, "out"), MaxPhysicalBytes: 1 << 20})
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close()
	copyOwner := *owner
	if _, e = copyOwner.OpenReader(); e == nil {
		t.Fatal("copied owner acquired read authority")
	}
	if e = copyOwner.Close(); e == nil {
		t.Fatal("copied owner acquired cleanup authority")
	}
	if _, e = owner.OpenReader(); e != nil {
		t.Fatalf("original owner revoked by copy: %v", e)
	}
}

func TestTempZipExtentChangeAfterFinalRecordCannotBecomeEOF(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	if e := os.WriteFile(source, []byte("input"), 0o600); e != nil {
		t.Fatal(e)
	}
	owner, e := CreateTempZip(context.Background(), TempZipOptions{Files: []string{source}, RootDir: dir, NearPath: filepath.Join(dir, "out"), MaxPhysicalBytes: 1 << 20})
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Close()
	r, e := owner.OpenReader()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = io.ReadFull(r, make([]byte, owner.Length())); e != nil {
		t.Fatal(e)
	}
	if e = owner.File().Truncate(0); e != nil {
		t.Fatal(e)
	}
	if _, e = r.Read(make([]byte, 1)); e == nil || errors.Is(e, io.EOF) {
		t.Fatalf("changed final extent accepted: %v", e)
	}
}

func TestTempZipCleanupFailureRemainsDistinctAndPreservesOriginal(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("permission fault requires an unprivileged POSIX process")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	body := []byte("source survives cleanup failure")
	if e := os.WriteFile(source, body, 0o600); e != nil {
		t.Fatal(e)
	}
	defer os.Chmod(dir, 0o700)
	fault := errors.New("final synchronization failure")
	var stage string
	owner, e := createTempZip(context.Background(), TempZipOptions{Files: []string{source}, RootDir: dir, NearPath: filepath.Join(dir, "out"), MaxPhysicalBytes: 1 << 20}, func(f *os.File) error {
		stage = filepath.Join(dir, filepath.Base(f.Name()))
		if e := os.Chmod(dir, 0o500); e != nil {
			t.Fatal(e)
		}
		return fault
	})
	if e2 := os.Chmod(dir, 0o700); e2 != nil {
		t.Fatal(e2)
	}
	if owner != nil || !errors.Is(e, fault) || !errors.Is(e, ErrTempZipCleanupIncomplete) {
		t.Fatalf("cleanup failure lost diagnostic: %v", e)
	}
	if _, e = os.Stat(stage); e != nil {
		t.Fatalf("injected residue was not identified: %v", e)
	}
	if e = os.Remove(stage); e != nil {
		t.Fatal(e)
	}
	got, e := os.ReadFile(source)
	if e != nil || !bytes.Equal(got, body) {
		t.Fatal("cleanup failure changed original")
	}
}
