//go:build linux && !android

package pcv3operation

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3publication"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type desktopCrashAdmission struct{}

func (desktopCrashAdmission) AdmitKDF(context.Context, pcv3credential.KDFProfile) (pcv3credential.KDFAdmission, error) {
	os.Exit(0)
	return pcv3credential.KDFAdmissionDenied, nil
}

func TestDesktopCleanupCrashWorker(t *testing.T) {
	parent := os.Getenv("PICOCRYPT_DESKTOP_CLEANUP_TEST_PARENT")
	if parent == "" {
		return
	}
	if route := os.Getenv("PICOCRYPT_DESKTOP_CLEANUP_TEST_ROUTE"); route != "" {
		sourcePath := filepath.Join(parent, "crash-source")
		if err := os.WriteFile(sourcePath, []byte("data"), 0o600); err != nil {
			t.Fatal(err)
		}
		source, err := os.Open(sourcePath)
		if err != nil {
			t.Fatal(err)
		}
		mode := WriteModeNormal
		if route == "d1" {
			mode = WriteModeD1
		}
		result := runWriteWithSeams(context.Background(), &WriteRequest{
			Mode:  mode,
			Suite: SuiteStandard, PayloadKind: PayloadKindRaw, PlaintextLength: 4,
			Source: source, SourceFile: source, SourcePath: sourcePath,
			Target: filepath.Join(parent, "abandoned-output"), Factors: operationPasswordFactors([]byte("password")),
		},
			ExecutionOptions{LinuxDesktopCleanup: true}, operationSeams{admitter: desktopCrashAdmission{}})
		t.Fatalf("writer did not reach the crash admission boundary: %v", result)
	}
	stage, err := pcv3publication.Create(filepath.Join(parent, "abandoned-output"), nil, pcv3publication.PolicyNoReplace)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stage.File().WriteString("abandoned private plaintext"); err != nil {
		t.Fatal(err)
	}
	if err := stage.PersistLeasedCleanupJournal(); err != nil {
		t.Fatal(err)
	}
	// Model process death: the kernel releases its lease, ordinary Go cleanup
	// never runs, and the next operation must recover this private stage.
	os.Exit(0)
}

func seedDesktopCleanupCrash(t *testing.T, parent string, route ...string) string {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestDesktopCleanupCrashWorker$")
	command.Env = append(os.Environ(), "PICOCRYPT_DESKTOP_CLEANUP_TEST_PARENT="+parent)
	if len(route) != 0 {
		command.Env = append(command.Env, "PICOCRYPT_DESKTOP_CLEANUP_TEST_ROUTE="+route[0])
	}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("seed crashed stage: %s %v", output, err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), ".picocrypt-pcv3-private-") {
			return filepath.Join(parent, entry.Name())
		}
	}
	t.Fatal("crash worker did not leave its private operation directory")
	return ""
}

func TestDesktopWriteRecoversOnlySelectedDestinationBeforeKDF(t *testing.T) {
	parent, other := t.TempDir(), t.TempDir()
	orphan := seedDesktopCleanupCrash(t, parent)
	untouched := seedDesktopCleanupCrash(t, other)
	sourcePath := filepath.Join(parent, "source")
	if err := os.WriteFile(sourcePath, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	admitter := &operationTestAdmitter{}
	request := &WriteRequest{
		Mode: WriteModeNormal, Suite: SuiteStandard, PayloadKind: PayloadKindRaw,
		PlaintextLength: 4, Source: source, SourceFile: source, SourcePath: sourcePath,
		Target: filepath.Join(parent, "output"), Factors: operationPasswordFactors([]byte("password")),
	}
	result := runWriteWithSeams(context.Background(), request, ExecutionOptions{LinuxDesktopCleanup: true}, operationSeams{admitter: admitter})
	if admitter.calls != 1 || result.PublicationAttempted() {
		t.Fatalf("cleanup did not reach the KDF refusal without publication: calls=%d result=%v", admitter.calls, result)
	}
	if _, err := os.Lstat(orphan); !os.IsNotExist(err) {
		t.Fatalf("selected parent orphan was not recovered before KDF: %v", err)
	}
	if _, err := os.Stat(untouched); err != nil {
		t.Fatalf("unselected parent changed: %v", err)
	}
	requireOperationFileBytes(t, sourcePath, []byte("data"))
}

func TestDesktopWriteUnprovenCleanupBlocksKDFWithoutDeletingInputs(t *testing.T) {
	parent := t.TempDir()
	orphan := seedDesktopCleanupCrash(t, parent)
	sourcePath := filepath.Join(orphan, "selected-input")
	if err := os.WriteFile(sourcePath, []byte("user plaintext"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	admitter := &operationTestAdmitter{}
	request := &WriteRequest{
		Mode: WriteModeNormal, Suite: SuiteStandard, PayloadKind: PayloadKindRaw,
		PlaintextLength: 14, Source: source, SourceFile: source, SourcePath: sourcePath,
		Target: filepath.Join(parent, "output"), Factors: operationPasswordFactors([]byte("password")),
	}
	result := runWriteWithSeams(context.Background(), request, ExecutionOptions{LinuxDesktopCleanup: true}, operationSeams{admitter: admitter})
	if admitter.calls != 0 || result.SourceDeletionAllowed() || result.PublicationAttempted() {
		t.Fatalf("unsafe cleanup admitted KDF or output: calls=%d result=%v", admitter.calls, result)
	}
	requireOperationFileBytes(t, sourcePath, []byte("user plaintext"))
}

func TestDesktopCleanupProtectsActualSourceAndKeyfileDescriptors(t *testing.T) {
	for _, role := range []string{"source", "keyfile"} {
		t.Run(role, func(t *testing.T) {
			parent := t.TempDir()
			orphan := seedDesktopCleanupCrash(t, parent)
			entries, err := os.ReadDir(orphan)
			if err != nil {
				t.Fatal(err)
			}
			var selected string
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".picocrypt-pcv3-") && entry.Name() != ".picocrypt-pcv3-stage.journal" {
					selected = filepath.Join(orphan, entry.Name())
				}
			}
			file, err := os.Open(selected)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			request := &WriteRequest{
				Mode: WriteModeNormal, Suite: SuiteStandard, PayloadKind: PayloadKindRaw,
				Source: strings.NewReader("data"), PlaintextLength: 4,
				Target: filepath.Join(parent, "output"), Factors: operationPasswordFactors([]byte("password")),
			}
			if role == "source" {
				request.Source, request.SourceFile = file, file
			} else {
				request.Factors = &FactorRequest{
					Mode: CredentialModeKeyfilesOnly, KeyfileMode: KeyfileModeUnordered,
					ExpectedPolicy: FactorPolicyKeyfilesOnly, Keyfiles: []*KeyfileReader{OwnKeyfileReader(file)},
				}
			}
			admitter := &operationTestAdmitter{}
			result := runWriteWithSeams(context.Background(), request, ExecutionOptions{LinuxDesktopCleanup: true}, operationSeams{admitter: admitter})
			if admitter.calls != 0 || result.PublicationAttempted() || result.SourceDeletionAllowed() {
				t.Fatalf("selected %s descriptor did not block cleanup: calls=%d result=%v", role, admitter.calls, result)
			}
			requireOperationFileBytes(t, selected, []byte("abandoned private plaintext"))
		})
	}
}

func TestDesktopReadRecoversSelectedParentBeforeRouting(t *testing.T) {
	parent := t.TempDir()
	orphan := seedDesktopCleanupCrash(t, parent)
	sourcePath := filepath.Join(parent, "input")
	if err := os.WriteFile(sourcePath, []byte("bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	admitter := &operationTestAdmitter{}
	result := runWithSeamsAndOptions(context.Background(), &Request{
		Mode:   ModeReadNormal,
		Source: source, Factors: operationPasswordFactors([]byte("password")), Target: filepath.Join(parent, "output"),
	},
		operationSeams{admitter: admitter}, ExecutionOptions{LinuxDesktopCleanup: true})
	if admitter.calls != 0 || result.PublicationAttempted() {
		t.Fatalf("malformed input granted KDF or output: calls=%d result=%v", admitter.calls, result)
	}
	if _, err := os.Lstat(orphan); !os.IsNotExist(err) {
		t.Fatalf("read did not recover the selected parent: %v", err)
	}
	requireOperationFileBytes(t, sourcePath, []byte("bad"))
}

func TestDesktopWriterCrashAtKDFLeavesRecoverableLeasedStage(t *testing.T) {
	for _, mode := range []string{"normal", "d1"} {
		t.Run(mode, func(t *testing.T) {
			parent := t.TempDir()
			orphan := seedDesktopCleanupCrash(t, parent, mode)
			result := runWriteWithSeams(context.Background(), &WriteRequest{
				Mode:  WriteModeNormal,
				Suite: SuiteStandard, PayloadKind: PayloadKindRaw, PlaintextLength: 4,
				Source: strings.NewReader("data"), Target: filepath.Join(parent, "next-output"),
				Factors: operationPasswordFactors([]byte("password")),
			},
				ExecutionOptions{LinuxDesktopCleanup: true}, operationSeams{admitter: &operationTestAdmitter{}})
			if result.Diagnostic() == DiagnosticCoreFailure {
				t.Fatalf("writer crash left an unproven stage: %v", result)
			}
			if _, err := os.Lstat(orphan); !os.IsNotExist(err) {
				t.Fatalf("%s writer did not durably journal before KDF admission: %v", mode, err)
			}
			requireOperationFileBytes(t, filepath.Join(parent, "crash-source"), []byte("data"))
		})
	}
}
