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
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// These independent fixtures are separate parents so the native macOS lane
// runs each in a fresh process. Every case keeps its real writer and reader.
func TestArchiveResourceNativeWorkspaceRefusalReachesValidFrontendPresentation(t *testing.T) {
	testArchiveResourceFrontendPresentation(t, WriteModeNormal, "workspace")
}

func TestArchiveResourceD1WorkspaceRefusalReachesValidFrontendPresentation(t *testing.T) {
	testArchiveResourceFrontendPresentation(t, WriteModeD1, "workspace")
}

func TestArchiveResourceD1MetadataRefusalReachesValidFrontendPresentation(t *testing.T) {
	testArchiveResourceFrontendPresentation(t, WriteModeD1, "metadata")
}

func TestArchiveResourceNativeExtractionReachesValidFrontendPresentation(t *testing.T) {
	testArchiveResourceFrontendPresentation(t, WriteModeNormal, "positive")
}

func TestArchiveResourceD1ExtractionReachesValidFrontendPresentation(t *testing.T) {
	testArchiveResourceFrontendPresentation(t, WriteModeD1, "positive")
}

// Real native/D1 writer, reader, archive handoff, extraction and presentation.
// A short central directory can fit admission while its implicit-parent plan
// cannot; refusal must survive both opaque handoff projections to the frontend.
func testArchiveResourceFrontendPresentation(t *testing.T, mode WriteMode, kind string) {
	t.Helper()
	fixtureDirectory := os.Getenv("PICOCRYPT_TEST_ARCHIVE_RESOURCE_FIXTURE")
	fixtureWorker := fixtureDirectory != ""
	if fixtureWorker {
		if mode != WriteModeD1 || kind != "metadata" {
			t.Fatal("archive resource fixture worker requires the D1 metadata case")
		}
		t.Cleanup(func() {
			if !t.Failed() && !t.Skipped() {
				t.Log("archive resource fixture writer completed")
			}
		})
	}
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	name := "payload.txt"
	if kind == "workspace" {
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
	if kind == "metadata" {
		data = archiveResourceZIP64(t, data, math.MaxUint64)
	}
	if kind == "workspace" {
		reader, err := fileops.OpenZIPReader(bytes.NewReader(data), int64(len(data)), fileops.ZIPReadOptions{})
		if err != nil {
			t.Fatalf("fixture must pass reader admission: %v", err)
		}
		reader.Close()
	}
	directory := t.TempDir()
	if fixtureWorker {
		directory = fixtureDirectory
	}
	sourcePath := filepath.Join(directory, "source.zip")
	if !fixtureWorker {
		if err := os.WriteFile(sourcePath, data, 0o600); err != nil {
			t.Fatal(err)
		}
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
	if mode == WriteModeD1 {
		suite = SuiteParanoid
		readMode = ModeReadD1
	}
	ciphertext := filepath.Join(directory, "ciphertext.pcv")
	if runtime.GOOS == "darwin" && mode == WriteModeD1 && kind == "metadata" && !fixtureWorker {
		// This malformed-metadata reader case must not inherit the synthetic
		// writer's reusable Go heap. Other D1 cases retain warm write/read coverage.
		runArchiveResourceFixtureWriter(t, directory)
	} else {
		write := RunWrite(context.Background(), &WriteRequest{Mode: mode, Suite: suite, PayloadKind: PayloadKindArchive, Source: source, SourceFile: source, SourcePath: sourcePath, PlaintextLength: uint64(len(data)), Target: ciphertext, Factors: factors()})
		requireNativeOperationPublication(t, write)
	}
	if fixtureWorker {
		return
	}
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
	if kind == "positive" {
		requireNativeOperationPublication(t, result)
		body, err := os.ReadFile(filepath.Join(outputParent, "extracted", "payload.txt"))
		if err != nil || string(body) != "preserved archive payload" {
			t.Fatalf("positive payload: %q %v", body, err)
		}
	} else {
		if result.Diagnostic() != DiagnosticResourceLimit || result.Stage() != StageResourceBudget || result.CompletionClass() != CompletionNoOutput || result.PublicationAttempted() {
			t.Errorf("resource projection: diagnostic=%v stage=%v class=%v attempted=%v", result.Diagnostic(), result.Stage(), result.CompletionClass(), result.PublicationAttempted())
		}
		retainedEmptyDirectory := runtime.GOOS == "windows" && kind == "workspace"
		var warnings []Warning
		if runtime.GOOS == "windows" {
			warnings = []Warning{WarningCleanupIncomplete}
		}
		if !slices.Equal(result.Warnings(), warnings) {
			t.Errorf("resource refusal warnings=%v; want %v", result.Warnings(), warnings)
		}
		requireArchiveRefusalDirectory(t, outputParent, "extracted", retainedEmptyDirectory)
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
}

func runArchiveResourceFixtureWriter(t *testing.T, directory string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Minute)
	if testDeadline, ok := t.Deadline(); ok {
		deadline = testDeadline
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0],
		"-test.run=^TestArchiveResourceD1MetadataRefusalReachesValidFrontendPresentation$",
		"-test.v", "-test.timeout="+time.Until(deadline).String())
	command.Env = append(os.Environ(), "PICOCRYPT_TEST_ARCHIVE_RESOURCE_FIXTURE="+directory)
	command.WaitDelay = time.Second
	output, err := command.CombinedOutput()
	t.Logf("archive resource fixture writer:\n%s", output)
	if err != nil {
		t.Fatalf("archive resource fixture writer failed: %v", err)
	}
	if !bytes.Contains(output, []byte("archive resource fixture writer completed\n")) {
		t.Fatal("archive resource fixture writer did not complete its selected body")
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
