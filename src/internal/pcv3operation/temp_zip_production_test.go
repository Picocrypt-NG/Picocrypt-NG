//go:build pcv3_production_kdf

package pcv3operation

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3"
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// Real filesystem STREAM preparation feeds the unmodified production KDF and
// Normal/D1 writers. Physical tag bytes must never become logical ZIP bytes.
func TestAuthenticatedTempZIPProductionNormalD1RoundTrip(t *testing.T) {
	for _, mode := range []WriteMode{WriteModeNormal, WriteModeD1} {
		t.Run(map[WriteMode]string{WriteModeNormal: "normal", WriteModeD1: "d1"}[mode], func(t *testing.T) {
			dir := t.TempDir()
			source := filepath.Join(dir, "source.bin")
			plain := bytes.Repeat([]byte("authenticated temporary ZIP input"), 5000)
			if e := os.WriteFile(source, plain, 0o600); e != nil {
				t.Fatal(e)
			}
			target := filepath.Join(dir, "encrypted.pcv")
			owner, e := fileops.CreateTempZip(context.Background(), fileops.TempZipOptions{Files: []string{source}, RootDir: dir, NearPath: target, MaxPhysicalBytes: 1 << 20})
			if e != nil {
				t.Fatal(e)
			}
			defer owner.Close()
			stagePath := owner.Path()
			info, e := owner.File().Stat()
			if e != nil {
				t.Fatal(e)
			}
			if uint64(info.Size()) <= owner.Length() {
				t.Fatal("fixture does not distinguish physical/logical sizes")
			}
			reader, e := owner.OpenReader()
			if e != nil {
				t.Fatal(e)
			}
			suite := pcv3.SuiteStandard
			readMode := ModeReadNormal
			if mode == WriteModeD1 {
				suite = pcv3.SuiteParanoid
				readMode = ModeReadD1
			}
			result := runWriteWithSeams(context.Background(), &WriteRequest{Mode: mode, Suite: suite, PayloadKind: pcv3.PayloadKindArchive, PlaintextLength: owner.Length(), Source: reader, SourceFile: owner.File(), SourcePath: owner.Path(), Target: target, Factors: writeBoundaryFactors()}, ExecutionOptions{}, operationSeams{admitter: &operationTestAdmitter{grant: true}})
			if result.CompletionClass() != CompletionClean {
				t.Fatalf("write: %v %v", result, result.Diagnostic())
			}
			if e = owner.Close(); e != nil {
				t.Fatal(e)
			}
			if _, e = os.Stat(stagePath); !os.IsNotExist(e) {
				t.Fatal("temporary stage remains")
			}
			encrypted, e := os.Open(target)
			if e != nil {
				t.Fatal(e)
			}
			recovered := filepath.Join(dir, "recovered.zip")
			read := runWithSeams(context.Background(), &Request{Mode: readMode, Source: encrypted, Target: recovered, Factors: writeBoundaryFactors()}, operationSeams{admitter: &operationTestAdmitter{grant: true}})
			if mode == WriteModeNormal {
				if read.CompletionClass() != CompletionArchivePending || read.ArchiveFollowUp() == nil {
					t.Fatalf("normal archive read: %v", read)
				}
				follow := read.ArchiveFollowUp()
				defer follow.Close()
				if saved := follow.Publish(context.Background()); saved.CompletionClass() != CompletionClean {
					t.Fatalf("archive save: %v", saved)
				}
			} else if read.CompletionClass() != CompletionClean {
				t.Fatalf("D1 archive read: %v", read)
			}

			zr, e := zip.OpenReader(recovered)
			if e != nil {
				t.Fatal(e)
			}
			defer zr.Close()
			if len(zr.File) != 1 || zr.File[0].Name != "source.bin" {
				t.Fatal("archive structure changed")
			}
			entry, e := zr.File[0].Open()
			if e != nil {
				t.Fatal(e)
			}
			got, e := io.ReadAll(entry)
			entry.Close()
			if e != nil || !bytes.Equal(got, plain) {
				t.Fatal("archive payload changed")
			}
			got, e = os.ReadFile(source)
			if e != nil || !bytes.Equal(got, plain) {
				t.Fatal("original changed")
			}
		})
	}
}

// This adapter forwards every byte from the real authenticated owner. It changes
// the held file only after the last logical byte was returned, so the next read
// is the production writer's final source-EOF probe, not an artificial I/O fault.
type tempZIPTruncateBeforeFinalProbe struct {
	reader    io.Reader
	file      *os.File
	remaining uint64
	truncated bool
	probes    int
}

func (r *tempZIPTruncateBeforeFinalProbe) Read(p []byte) (int, error) {
	if r.truncated && len(p) > 0 {
		r.probes++
	}
	n, e := r.reader.Read(p)
	if n > 0 {
		if uint64(n) > r.remaining {
			return 0, errors.New("test reader exceeded declared logical length")
		}
		r.remaining -= uint64(n)
		if r.remaining == 0 && !r.truncated {
			if truncateErr := r.file.Truncate(0); truncateErr != nil {
				return n, truncateErr
			}
			r.truncated = true
		}
	}
	return n, e
}

func TestAuthenticatedTempZIPProductionRejectsCorruptionBeforePublication(t *testing.T) {
	for _, mode := range []WriteMode{WriteModeNormal, WriteModeD1} {
		for _, fault := range []string{"final tag", "truncate before EOF"} {
			t.Run(map[WriteMode]string{WriteModeNormal: "normal", WriteModeD1: "d1"}[mode]+"/"+fault, func(t *testing.T) {
				dir := t.TempDir()
				source := filepath.Join(dir, "source.bin")
				foreign := filepath.Join(dir, "unrelated.bin")
				sourceBody := bytes.Repeat([]byte("production negative authentic ZIP input"), 5000)
				foreignBody := []byte("unrelated original remains intact")
				paths := []string{source, foreign}
				bodies := [][]byte{sourceBody, foreignBody}
				infos := make([]os.FileInfo, 2)
				hashes := make([][32]byte, 2)
				for i, path := range paths {
					if e := os.WriteFile(path, bodies[i], 0o600); e != nil {
						t.Fatal(e)
					}
					info, e := os.Stat(path)
					if e != nil {
						t.Fatal(e)
					}
					infos[i] = info
					hashes[i] = sha256.Sum256(bodies[i])
				}
				target := filepath.Join(dir, "encrypted.pcv")
				owner, e := fileops.CreateTempZip(context.Background(), fileops.TempZipOptions{Files: []string{source}, RootDir: dir, NearPath: target, MaxPhysicalBytes: 1 << 20})
				if e != nil {
					t.Fatal(e)
				}
				defer owner.Close()
				stagePath := owner.Path()
				physical, e := owner.File().Stat()
				if e != nil {
					t.Fatal(e)
				}
				if uint64(physical.Size()) <= owner.Length() {
					t.Fatal("fixture lacks separate physical and logical extents")
				}
				reader, e := owner.OpenReader()
				if e != nil {
					t.Fatal(e)
				}
				var late *tempZIPTruncateBeforeFinalProbe
				switch fault {
				case "final tag":
					var tag [1]byte
					if _, e = owner.File().ReadAt(tag[:], physical.Size()-1); e != nil {
						t.Fatal(e)
					}
					tag[0] ^= 1
					if _, e = owner.File().WriteAt(tag[:], physical.Size()-1); e != nil {
						t.Fatal(e)
					}
				case "truncate before EOF":
					late = &tempZIPTruncateBeforeFinalProbe{reader: reader, file: owner.File(), remaining: owner.Length()}
					reader = late
				}
				suite := pcv3.SuiteStandard
				if mode == WriteModeD1 {
					suite = pcv3.SuiteParanoid
				}
				result := runWriteWithSeams(context.Background(), &WriteRequest{Mode: mode, Suite: suite, PayloadKind: pcv3.PayloadKindArchive, PlaintextLength: owner.Length(), Source: reader, SourceFile: owner.File(), SourcePath: stagePath, Target: target, Protected: paths, Factors: writeBoundaryFactors()}, ExecutionOptions{}, operationSeams{admitter: &operationTestAdmitter{grant: true}})
				if result.CompletionClass() != CompletionNoOutput || result.PublicationAttempted() || result.PublicationState() != 0 || result.SourceDeletionAllowed() || result.OutputFollowUp() != nil {
					t.Fatalf("corrupt spool obtained publication authority: %v / %v", result, result.Diagnostic())
				}
				if late != nil && (!late.truncated || late.remaining != 0 || late.probes != 1) {
					t.Fatalf("late fault missed exact final probe: truncated=%t remaining=%d probes=%d", late.truncated, late.remaining, late.probes)
				}
				if _, e = os.Lstat(target); !os.IsNotExist(e) {
					t.Fatalf("failed writer published target: %v", e)
				}
				entries, e := os.ReadDir(dir)
				if e != nil {
					t.Fatal(e)
				}
				allowed := map[string]bool{filepath.Base(source): true, filepath.Base(foreign): true, filepath.Base(stagePath): true}
				for _, entry := range entries {
					if !allowed[entry.Name()] {
						t.Fatalf("failed writer left output-stage residue: %s", entry.Name())
					}
				}
				if _, e = owner.File().Stat(); e != nil {
					t.Fatalf("writer closed borrowed spool descriptor: %v", e)
				}
				if e = owner.Close(); e != nil {
					t.Fatal(e)
				}
				if _, e = os.Lstat(stagePath); !os.IsNotExist(e) {
					t.Fatalf("owner left spool residue: %v", e)
				}
				for i, path := range paths {
					body, e := os.ReadFile(path)
					info, statErr := os.Stat(path)
					if e != nil || statErr != nil || !os.SameFile(infos[i], info) || sha256.Sum256(body) != hashes[i] {
						t.Fatal("failed writer changed original or foreign identity/content")
					}
				}
			})
		}
	}
}
