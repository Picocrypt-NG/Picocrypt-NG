package pcv3operation

import (
	"Picocrypt-NG/internal/fileops"
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Real native/D1 writer, reader, archive handoff, extraction and presentation.
// A short central directory can fit admission while its implicit-parent plan
// cannot; refusal must survive both opaque handoff projections to the frontend.
func TestArchiveResourceRefusalReachesValidFrontendPresentation(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode WriteMode
		kind string
	}{
		{"native_workspace", WriteModeNormal, "workspace"},
		{"D1_workspace", WriteModeD1, "workspace"},
		{"D1_metadata", WriteModeD1, "metadata"},
		{"native_positive", WriteModeNormal, "positive"},
		{"D1_positive", WriteModeD1, "positive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var archive bytes.Buffer
			writer := zip.NewWriter(&archive)
			name := "payload.txt"
			if tc.kind == "workspace" {
				name = strings.Repeat("a/", 12000) + "leaf"
			}
			entry, err := writer.Create(name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := entry.Write([]byte("preserved archive payload")); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			data := archive.Bytes()
			if tc.kind == "metadata" {
				data = archiveResourceZIP64(t, data, math.MaxUint64)
			}
			if tc.kind == "workspace" {
				reader, err := fileops.OpenZIPReader(bytes.NewReader(data), int64(len(data)), fileops.ZIPReadOptions{})
				if err != nil {
					t.Fatalf("fixture must pass reader admission: %v", err)
				}
				reader.Close()
			}
			directory := t.TempDir()
			sourcePath := filepath.Join(directory, "source.zip")
			if err := os.WriteFile(sourcePath, data, 0o600); err != nil {
				t.Fatal(err)
			}
			source, err := os.Open(sourcePath)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			sourceInfo, err := source.Stat()
			if err != nil {
				t.Fatal(err)
			}
			factors := func() *FactorRequest {
				return &FactorRequest{Mode: CredentialModeKeyfilesOnly, ExpectedPolicy: FactorPolicyKeyfilesOnly, KeyfileMode: KeyfileModeUnordered, Keyfiles: []*KeyfileReader{OwnKeyfileReader(io.NopCloser(strings.NewReader("archive resource integration factor")))}}
			}
			suite := SuiteStandard
			readMode := ModeReadNormal
			if tc.mode == WriteModeD1 {
				suite = SuiteParanoid
				readMode = ModeReadD1
			}
			ciphertext := filepath.Join(directory, "ciphertext.pcv")
			write := RunWrite(context.Background(), &WriteRequest{Mode: tc.mode, Suite: suite, PayloadKind: PayloadKindArchive, Source: source, SourceFile: source, SourcePath: sourcePath, PlaintextLength: uint64(len(data)), Target: ciphertext, Factors: factors()})
			requireNativeOperationPublication(t, write)
			encrypted, err := os.Open(ciphertext)
			if err != nil {
				t.Fatal(err)
			}
			defer encrypted.Close()
			encryptedInfo, err := encrypted.Stat()
			if err != nil {
				t.Fatal(err)
			}
			encryptedBytes, err := os.ReadFile(ciphertext)
			if err != nil {
				t.Fatal(err)
			}
			outputParent := t.TempDir()
			target := filepath.Join(outputParent, "extracted.zip")
			result := RunWithOptions(context.Background(), &Request{Mode: readMode, Source: encrypted, Target: target, Factors: factors()}, ExecutionOptions{ArchiveAction: ArchiveExtract})
			if tc.kind == "positive" {
				requireNativeOperationPublication(t, result)
				body, err := os.ReadFile(filepath.Join(outputParent, "extracted", "payload.txt"))
				if err != nil || string(body) != "preserved archive payload" {
					t.Fatalf("positive payload: %q %v", body, err)
				}
			} else {
				if result.Diagnostic() != DiagnosticResourceLimit || result.Stage() != StageResourceBudget || result.CompletionClass() != CompletionNoOutput || result.PublicationAttempted() {
					t.Errorf("resource projection: diagnostic=%v stage=%v class=%v attempted=%v", result.Diagnostic(), result.Stage(), result.CompletionClass(), result.PublicationAttempted())
				}
				entries, err := os.ReadDir(outputParent)
				if err != nil || len(entries) != 0 {
					t.Errorf("refusal retained plaintext: %v %v", entries, err)
				}
			}
			p := result.Presentation()
			rebuilt, err := NewPresentation(PresentationSpec{Outcome: p.Outcome(), Stage: p.Stage(), Code: p.Code(), ForceProvenance: p.ForceProvenance(), D1BootstrapProvenance: p.D1BootstrapProvenance(), DetailStage: p.DetailStage(), PublicationAttempted: p.PublicationAttempted(), PublicationState: p.PublicationState(), PublicationStage: p.PublicationStage(), PublicationCode: p.PublicationCode(), Args: p.Args(), Warnings: p.Warnings(), Diagnostic: p.Diagnostic(), ArchivePending: p.ArchivePending()})
			if err != nil || rebuilt.CompletionClass() != result.CompletionClass() {
				t.Errorf("frontend rejected actual result: %v class=%v", err, rebuilt.CompletionClass())
			}
			if result.ArchiveFollowUp() != nil || result.OutputFollowUp() != nil || result.SourceDeletionAllowed() {
				t.Error("terminal extraction grants unrelated authority")
			}
			if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("raw plaintext archive published: %v", err)
			}
			for _, protected := range []struct {
				path string
				info os.FileInfo
				data []byte
			}{{sourcePath, sourceInfo, data}, {ciphertext, encryptedInfo, encryptedBytes}} {
				info, err := os.Stat(protected.path)
				if err != nil || !os.SameFile(protected.info, info) {
					t.Fatalf("source identity changed: %v", err)
				}
				body, err := os.ReadFile(protected.path)
				if err != nil || !bytes.Equal(body, protected.data) {
					t.Fatalf("source bytes changed: %v", err)
				}
			}
			entries, err := os.ReadDir(directory)
			if err != nil || len(entries) != 2 {
				t.Errorf("source directory retained stage: %v %v", entries, err)
			}
		})
	}
}

func archiveResourceZIP64(t *testing.T, archive []byte, count uint64) []byte {
	t.Helper()
	end := len(archive) - 22
	footer := append([]byte(nil), archive[end:]...)
	var extension [76]byte
	binary.LittleEndian.PutUint32(extension[:], 0x06064b50)
	binary.LittleEndian.PutUint64(extension[4:], 44)
	binary.LittleEndian.PutUint16(extension[12:], 45)
	binary.LittleEndian.PutUint16(extension[14:], 45)
	binary.LittleEndian.PutUint64(extension[24:], count)
	binary.LittleEndian.PutUint64(extension[32:], count)
	binary.LittleEndian.PutUint64(extension[40:], uint64(binary.LittleEndian.Uint32(footer[12:])))
	binary.LittleEndian.PutUint64(extension[48:], uint64(binary.LittleEndian.Uint32(footer[16:])))
	binary.LittleEndian.PutUint32(extension[56:], 0x07064b50)
	binary.LittleEndian.PutUint64(extension[64:], uint64(end))
	binary.LittleEndian.PutUint32(extension[72:], 1)
	binary.LittleEndian.PutUint16(footer[8:], 0xffff)
	binary.LittleEndian.PutUint16(footer[10:], 0xffff)
	binary.LittleEndian.PutUint32(footer[12:], 0xffffffff)
	binary.LittleEndian.PutUint32(footer[16:], 0xffffffff)
	result := append([]byte(nil), archive[:end]...)
	result = append(result, extension[:]...)
	return append(result, footer...)
}
