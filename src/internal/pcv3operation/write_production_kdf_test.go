//go:build pcv3_production_kdf

package pcv3operation

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3publication"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"
)

// The admission seam only grants the fixed production profile; all KDF, codec,
// real-file publication, retained transport and reader paths execute unchanged.
func TestWriteProductionKDFNormalAndD1PublishReadableVolumes(t *testing.T) {
	for _, mode := range []WriteMode{WriteModeNormal, WriteModeD1} {
		t.Run(map[WriteMode]string{WriteModeNormal: "normal", WriteModeD1: "d1"}[mode], func(t *testing.T) {
			directory := t.TempDir()
			sourcePath := filepath.Join(directory, "source")
			plaintext := []byte("borrowed logical plaintext survives exact ciphertext publication")
			pinnedBytes := []byte(strings.Repeat("X", len(plaintext)))
			if err := os.WriteFile(sourcePath, pinnedBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			source, err := os.Open(sourcePath)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			suite := pcv3.SuiteStandard
			readMode := ModeReadNormal
			if mode == WriteModeD1 {
				suite = pcv3.SuiteParanoid
				readMode = ModeReadD1
			}
			factors := func() *pcv3credential.FactorRequest {
				return &pcv3credential.FactorRequest{Mode: pcv3credential.CredentialModePasswordOnly, KeyfileMode: pcv3credential.KeyfileModeNone, ExpectedPolicy: pcv3credential.FactorPolicyPasswordOnly, Password: []byte("production writer regression password")}
			}
			target := filepath.Join(directory, "ciphertext")
			// Source is intentionally a separate logical reader, as for encrypted ZIP
			// staging; the pinned descriptor supplies identity, never substituted bytes.
			var lastProgress []uint64
			request := &WriteRequest{Reporter: func(status Status) error {
				if status.Code() == StatusEncrypting {
					lastProgress = status.Args()
				}
				return nil
			}, Mode: mode, Suite: suite, PayloadKind: pcv3.PayloadKindRaw, PlaintextLength: uint64(len(plaintext)), Source: &writeFinalEOFReader{Reader: strings.NewReader(string(plaintext))}, SourceFile: source, SourcePath: sourcePath, Target: target, Factors: factors()}
			result := runWriteWithSeams(context.Background(), request, ExecutionOptions{JournalPrivateStage: true}, operationSeams{admitter: &operationTestAdmitter{grant: true}})
			if result.CompletionClass() != CompletionClean || !result.SourceDeletionAllowed() {
				t.Fatalf("write result=%v diagnostic=%v", result, result.Diagnostic())
			}
			if len(lastProgress) != 2 || lastProgress[0] != uint64(len(plaintext)) || lastProgress[1] != uint64(len(plaintext)) {
				t.Fatalf("logical plaintext progress=%v", lastProgress)
			}
			if _, err := source.Stat(); err != nil {
				t.Fatalf("borrowed source closed: %v", err)
			}
			encrypted, err := os.Open(target)
			if err != nil {
				t.Fatal(err)
			}
			recovered := filepath.Join(directory, "recovered")
			read := runWithSeams(context.Background(), &Request{Mode: readMode, Source: encrypted, Target: recovered, Factors: factors()}, operationSeams{admitter: &operationTestAdmitter{grant: true}})
			if read.CompletionClass() != CompletionClean {
				t.Fatalf("read result=%v", read)
			}
			requireOperationFileBytes(t, recovered, plaintext)
			requireOperationFileBytes(t, sourcePath, pinnedBytes)
			result.WithCleanupWarning()
			if result.SourceDeletionAllowed() || result.CompletionClass() != CompletionWarning {
				t.Fatal("outer cleanup failure did not revoke source deletion")
			}
		})
	}
}

// A frontend progress failure after ciphertext publication must not erase the
// complete ciphertext or authorize deleting the only source plaintext.
func TestWriteProductionKDFSplitReporterFailurePreservesCiphertext(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "ciphertext")
	plaintext := strings.Repeat("split source plaintext", 150)
	factors := func() *pcv3credential.FactorRequest {
		return &pcv3credential.FactorRequest{Mode: pcv3credential.CredentialModePasswordOnly, KeyfileMode: pcv3credential.KeyfileModeNone, ExpectedPolicy: pcv3credential.FactorPolicyPasswordOnly, Password: []byte("split regression password")}
	}
	sawSplit := false
	request := &WriteRequest{Mode: WriteModeNormal, Suite: pcv3.SuiteStandard, PayloadKind: pcv3.PayloadKindRaw, Source: strings.NewReader(plaintext), PlaintextLength: uint64(len(plaintext)), Target: target, Factors: factors(), Split: &WriteSplitOptions{ChunkSize: 1, Unit: fileops.SplitUnitKiB}, Reporter: func(status Status) error {
		if status.Code() == StatusSplitting {
			sawSplit = true
			return errors.New("private frontend callback error")
		}
		return nil
	}}
	result := runWriteWithSeams(context.Background(), request, ExecutionOptions{}, operationSeams{admitter: &operationTestAdmitter{grant: true}})
	if !sawSplit || result.PublicationState() != pcv3publication.StatePublishedDurable || result.SourceDeletionAllowed() || result.CompletionClass() != CompletionWarning {
		t.Fatalf("split callback result=%v saw=%v", result, sawSplit)
	}
	encrypted, err := os.Open(target)
	if err != nil {
		t.Fatalf("complete ciphertext removed: %v", err)
	}
	recovered := filepath.Join(directory, "recovered")
	read := runWithSeams(context.Background(), &Request{Mode: ModeReadNormal, Source: encrypted, Target: recovered, Factors: factors()}, operationSeams{admitter: &operationTestAdmitter{grant: true}})
	if read.CompletionClass() != CompletionClean {
		t.Fatalf("read preserved complete ciphertext=%v", read)
	}
	requireOperationFileBytes(t, recovered, []byte(plaintext))
	if _, err := os.Stat(target + ".0"); !os.IsNotExist(err) {
		t.Fatalf("failed split left partial chunks: %v", err)
	}
}

func TestWriteProductionKDFPublicationCancellationCleansPrivateStage(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "deadline"}[deadline], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				directory := t.TempDir()
				sourcePath := filepath.Join(directory, "source")
				target := filepath.Join(directory, "ciphertext")
				if err := os.WriteFile(sourcePath, []byte("data"), 0o600); err != nil {
					t.Fatal(err)
				}
				source, err := os.Open(sourcePath)
				if err != nil {
					t.Fatal(err)
				}
				defer source.Close()
				ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
				defer cancel()
				reachedPublication := false
				request := &WriteRequest{Mode: WriteModeNormal, Suite: pcv3.SuiteStandard, PayloadKind: pcv3.PayloadKindRaw, Source: source, SourceFile: source, SourcePath: sourcePath, Target: target, PlaintextLength: 4, Factors: writeBoundaryFactors(), Reporter: func(status Status) error {
					if status.Code() == StatusPublishing {
						reachedPublication = true
						if deadline {
							<-ctx.Done()
						} else {
							cancel()
						}
					}
					return nil
				}}
				result := runWriteWithSeams(ctx, request, ExecutionOptions{JournalPrivateStage: true}, operationSeams{admitter: &operationTestAdmitter{grant: true}})
				want := context.Canceled
				if deadline {
					want = context.DeadlineExceeded
				}
				if !reachedPublication || !errors.Is(result, want) || result.PublicationState() != pcv3publication.StateNotPublished || result.SourceDeletionAllowed() {
					t.Fatalf("publication cancellation result=%v diagnostic=%v reached=%v", result, result.Diagnostic(), reachedPublication)
				}
				requireWriteBoundarySourceOnly(t, directory, source)
			})
		})
	}
}

func TestWriteProductionKDFFinalProgressFailureNeverPublishes(t *testing.T) {
	for _, panicCallback := range []bool{false, true} {
		t.Run(map[bool]string{false: "error", true: "panic"}[panicCallback], func(t *testing.T) {
			directory := t.TempDir()
			sourcePath := filepath.Join(directory, "source")
			target := filepath.Join(directory, "ciphertext")
			if err := os.WriteFile(sourcePath, []byte("data"), 0o600); err != nil {
				t.Fatal(err)
			}
			source, err := os.Open(sourcePath)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			request := &WriteRequest{Mode: WriteModeD1, Suite: pcv3.SuiteParanoid, PayloadKind: pcv3.PayloadKindRaw, Source: &writeFinalEOFReader{Reader: strings.NewReader("data")}, SourceFile: source, SourcePath: sourcePath, Target: target, PlaintextLength: 4, Factors: writeBoundaryFactors(), Reporter: func(status Status) error {
				if status.Code() == StatusEncrypting {
					if panicCallback {
						panic("private final-read reporter panic")
					}
					return errors.New("private final-read reporter error")
				}
				return nil
			}}
			result := runWriteWithSeams(context.Background(), request, ExecutionOptions{JournalPrivateStage: true, RetainDurableOutput: true}, operationSeams{admitter: &operationTestAdmitter{grant: true}})
			want := DiagnosticCallbackFailure
			if panicCallback {
				want = DiagnosticCallbackPanic
			}
			if result.Diagnostic() != want || result.SourceDeletionAllowed() || result.OutputFollowUp() != nil {
				t.Fatalf("final progress callback result=%v diagnostic=%v", result, result.Diagnostic())
			}
			requireWriteBoundarySourceOnly(t, directory, source)
		})
	}
}

// A full final buffer may legally carry EOF. Callback errors must be sticky
// without reinterpreting that valid io.Reader success as a source failure.
type writeFinalEOFReader struct{ *strings.Reader }

func (reader *writeFinalEOFReader) Read(buffer []byte) (int, error) {
	n, err := reader.Reader.Read(buffer)
	if reader.Len() == 0 {
		return n, io.EOF
	}
	return n, err
}

func writeBoundaryFactors() *pcv3credential.FactorRequest {
	return &pcv3credential.FactorRequest{Mode: pcv3credential.CredentialModePasswordOnly, KeyfileMode: pcv3credential.KeyfileModeNone, ExpectedPolicy: pcv3credential.FactorPolicyPasswordOnly, Password: []byte("writer boundary password")}
}

func requireWriteBoundarySourceOnly(t *testing.T, directory string, source *os.File) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "source" {
		t.Fatalf("prepublication failure retained output/private staging: %v", entries)
	}
	if _, err := source.Stat(); err != nil {
		t.Fatalf("borrowed source closed: %v", err)
	}
	requireOperationFileBytes(t, source.Name(), []byte("data"))
}
