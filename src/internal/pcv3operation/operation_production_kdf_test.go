//go:build pcv3_production_kdf

package pcv3operation

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3publication"
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

const operationArchiveFixtureRoot = "../pcv3operation/internal/pcv3/testdata/normal"

type operationProductionKDFAdmitter struct {
	calls int
}

func (admitter *operationProductionKDFAdmitter) AdmitKDF(
	_ context.Context,
	_ pcv3credential.KDFProfile,
) (pcv3credential.KDFAdmission, error) {
	admitter.calls++
	return pcv3credential.KDFAdmissionGranted, nil
}

func TestOperationProductionKDFArchiveRequiresExplicitOneShotExtraction(t *testing.T) {
	source := openOperationArchiveFixtureFile(
		t,
		"volumes/normal-standard-combined-ordered-archive-small.pcv",
	)
	password, err := os.ReadFile(filepath.Join(
		operationArchiveFixtureRoot,
		"factors/sha256-2f907a6de331cc77376c52e70ba55765a30be18cd9bc69587585fbb71b80de1d.bin",
	))
	if err != nil {
		_ = source.Close()
		t.Fatalf("read frozen archive password: %v", err)
	}
	keyfiles := []*os.File{
		openOperationArchiveFixtureFile(
			t,
			"factors/sha256-b1f51a511f1da0cd348b8f8598db32e61cb963e5fc69e2b41485bf99590ed75a.bin",
		),
		openOperationArchiveFixtureFile(
			t,
			"factors/sha256-16477688c0e00699c6cfa4497a3612d7e83c532062b64b250fed8908128ed548.bin",
		),
	}
	factors := &pcv3credential.FactorRequest{
		Mode:           pcv3credential.CredentialModePasswordAndKeyfiles,
		KeyfileMode:    pcv3credential.KeyfileModeOrdered,
		ExpectedPolicy: pcv3credential.FactorPolicyPasswordAndKeyfiles,
		Password:       password,
		Keyfiles: []*pcv3credential.KeyfileReader{
			pcv3credential.OwnKeyfileReader(keyfiles[0]),
			pcv3credential.OwnKeyfileReader(keyfiles[1]),
		},
	}
	stageParent := t.TempDir()
	rawTarget := filepath.Join(stageParent, "raw.zip")
	request := &Request{
		Mode:    ModeReadNormal,
		Source:  source,
		Factors: factors,
		Target:  rawTarget,
	}
	admitter := &operationProductionKDFAdmitter{}

	result := runWithSeams(
		context.Background(),
		request,
		operationSeams{admitter: admitter},
	)
	if result == nil {
		t.Fatal("archive operation returned no closed result")
	}
	if result.Outcome() != pcv3.OutcomeSuccess ||
		result.Stage() != pcv3.StageNone ||
		result.Code() != pcv3.CodeSuccess ||
		result.PublicationAttempted() ||
		result.CompletionClass() != CompletionArchivePending {
		t.Fatalf(
			"archive operation = %v/%v/%v attempted=%v class=%v; want authenticated archive pending explicit extraction",
			result.Outcome(), result.Stage(), result.Code(),
			result.PublicationAttempted(), result.CompletionClass(),
		)
	}
	if admitter.calls != 1 {
		t.Fatalf("production KDF admissions = %d; want one real credential derivation", admitter.calls)
	}
	assertOperationRequestTransferred(t, request)
	assertOperationPasswordZero(t, password)
	assertOperationFileClosed(t, source)
	for index, keyfile := range keyfiles {
		if _, err := keyfile.Stat(); err == nil {
			t.Fatalf("archive keyfile %d remained open after credential ownership ended", index)
		}
	}
	assertOperationArchiveStage(t, stageParent, rawTarget, 1)

	followUp := result.ArchiveFollowUp()
	if followUp == nil {
		t.Fatal("authenticated archive result exposed no extraction authority")
	}
	t.Cleanup(func() { _ = followUp.Close() })
	copiedFollowUp := *followUp
	extractPath := t.TempDir()
	extractRoot, err := os.OpenRoot(extractPath)
	if err != nil {
		t.Fatalf("open archive extraction root: %v", err)
	}
	extracted := followUp.Extract(context.Background(), extractRoot)
	if extracted == nil {
		t.Fatal("archive extraction returned no closed result")
	}
	if extracted.Outcome() != pcv3.OutcomeSuccess ||
		extracted.PublicationState() != pcv3publication.StatePublishedDurable ||
		extracted.PublicationCode() != pcv3publication.CodePublishedDurable ||
		extracted.CompletionClass() != CompletionClean ||
		extracted.ArchiveFollowUp() != nil {
		t.Fatalf(
			"archive extraction = %v/%v/%v class=%v follow-up=%v; want one durable terminal publication",
			extracted.Outcome(), extracted.PublicationState(), extracted.PublicationCode(),
			extracted.CompletionClass(), extracted.ArchiveFollowUp(),
		)
	}
	assertOperationRootClosed(t, extractRoot)
	assertOperationArchiveFile(
		t,
		filepath.Join(extractPath, "root.txt"),
		"PCV3 authenticated archive fixture\n",
	)
	assertOperationArchiveFile(
		t,
		filepath.Join(extractPath, "docs", "readme.txt"),
		"Extraction is admitted only after whole-volume authentication.\n",
	)
	entries, err := os.ReadDir(extractPath)
	if err != nil {
		t.Fatalf("read extracted archive root: %v", err)
	}
	names := make([]string, len(entries))
	for index := range entries {
		names[index] = entries[index].Name()
	}
	if !slices.Equal(names, []string{"docs", "root.txt"}) {
		t.Fatalf("extracted archive root = %q; want exact frozen tree", names)
	}
	assertOperationArchiveStage(t, stageParent, rawTarget, 0)
	if result.ArchiveFollowUp() != nil {
		t.Fatal("terminal extraction left the original result authority live")
	}

	assertOperationArchiveReuseDenied(t, followUp, "repeated")
	assertOperationArchiveReuseDenied(t, &copiedFollowUp, "copied")
}

func openOperationArchiveFixtureFile(t *testing.T, relative string) *os.File {
	t.Helper()
	file, err := os.Open(filepath.Join(operationArchiveFixtureRoot, filepath.FromSlash(relative))) // #nosec G304 -- frozen public test fixture
	if err != nil {
		t.Fatalf("open frozen archive fixture %q: %v", relative, err)
	}
	return file
}

func assertOperationArchiveStage(t *testing.T, parent, rawTarget string, wantEntries int) {
	t.Helper()
	if _, err := os.Lstat(rawTarget); !os.IsNotExist(err) {
		t.Fatalf("raw archive target state = %v; want absent", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatalf("read private archive stage parent: %v", err)
	}
	if len(entries) != wantEntries {
		t.Fatalf("private archive stage entries = %d; want %d", len(entries), wantEntries)
	}
}

func assertOperationArchiveFile(t *testing.T, path, want string) {
	t.Helper()
	contents, err := os.ReadFile(path) // #nosec G304 -- test-owned extraction root
	if err != nil {
		t.Fatalf("read extracted archive file %q: %v", filepath.Base(path), err)
	}
	if string(contents) != want {
		t.Fatalf("extracted archive file %q = %q; want frozen content", filepath.Base(path), contents)
	}
}

func assertOperationRootClosed(t *testing.T, root *os.Root) {
	t.Helper()
	if _, err := root.Stat("."); err == nil {
		t.Fatal("archive follow-up returned with its transferred extraction root open")
	}
}

func assertOperationArchiveReuseDenied(t *testing.T, followUp *ArchiveFollowUp, name string) {
	t.Helper()
	path := t.TempDir()
	sentinel := filepath.Join(path, "foreign.txt")
	if err := os.WriteFile(sentinel, []byte("foreign\n"), 0o600); err != nil {
		t.Fatalf("seed %s-use sentinel: %v", name, err)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatalf("open %s-use extraction root: %v", name, err)
	}
	denied := followUp.Extract(context.Background(), root)
	if denied == nil {
		t.Fatalf("%s archive reuse returned no closed denial", name)
	}
	if denied.Outcome() != pcv3.OutcomeOperationFailed ||
		denied.PublicationAttempted() ||
		denied.CompletionClass() != CompletionNoOutput ||
		denied.Diagnostic() != DiagnosticInvalidRequest {
		t.Fatalf(
			"%s archive reuse = %v attempted=%v class=%v diagnostic=%v; want closed no-output denial",
			name, denied.Outcome(), denied.PublicationAttempted(),
			denied.CompletionClass(), denied.Diagnostic(),
		)
	}
	assertOperationRootClosed(t, root)
	assertOperationArchiveFile(t, sentinel, "foreign\n")
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 1 || entries[0].Name() != "foreign.txt" {
		t.Fatalf("%s archive reuse entries = %v, error %v; want only sentinel", name, entries, err)
	}
}
