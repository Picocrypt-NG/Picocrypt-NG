package pcv3

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3publication"
	"archive/zip"
	"bytes"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestArchiveSAFManifestFromAuthenticatedArchiveIsCanonicalAndOneShot(t *testing.T) {
	handoff, stageParent, rawTarget := newNativeArchiveHandoffFixture(t)
	copyOfHandoff := *handoff

	begin := handoff.BeginSAF()
	if begin == nil || begin.Kind() != NativeArchiveSAFBeginSession ||
		begin.Session() == nil || begin.ReceiptArm() == nil || begin.Result() != nil {
		t.Fatalf("SAF begin = %#v; want session plus receipt arm and no terminal", begin)
	}
	expired := copyOfHandoff.BeginSAF()
	if expired == nil || expired.Kind() != NativeArchiveSAFBeginExpired ||
		expired.Session() != nil || expired.ReceiptArm() != nil || expired.Result() != nil {
		t.Fatalf("copied handoff begin = %#v; want closed expired variant", expired)
	}

	session := begin.Session()
	want := []struct {
		name      string
		parent    int
		directory bool
		size      int64
	}{
		{name: "root.txt", parent: -1, size: 35},
		{name: "docs", parent: -1, directory: true},
		{name: "readme.txt", parent: 1, size: 63},
	}
	if session.EntryCount() != len(want) {
		t.Fatalf("manifest entry count = %d; want %d", session.EntryCount(), len(want))
	}
	for index, expected := range want {
		entry := session.Entry(index)
		if entry == nil || entry.Name() != expected.name ||
			entry.ParentIndex() != expected.parent ||
			entry.IsDirectory() != expected.directory || entry.Size() != expected.size {
			t.Fatalf("manifest entry %d = %#v; want %#v", index, entry, expected)
		}
	}
	if session.Entry(-1) != nil || session.Entry(len(want)) != nil {
		t.Fatal("manifest exposed an out-of-range entry")
	}
	if step := session.Attempt(0); step == nil ||
		step.Kind() != NativeArchiveSAFStepRejected || session.AttemptedEver() {
		t.Fatalf("unarmed attempt = %#v attempted-ever=%v; want rejected without provider authority", step, session.AttemptedEver())
	}
	if step := session.ConfirmReceiptPersisted(begin.ReceiptArm()); step == nil ||
		step.Kind() != NativeArchiveSAFStepReady || step.NextIndex() != 0 {
		t.Fatalf("receipt arm = %#v; want ready entry zero", step)
	}
	if step := session.ConfirmReceiptPersisted(begin.ReceiptArm()); step == nil ||
		step.Kind() != NativeArchiveSAFStepRejected {
		t.Fatalf("duplicate receipt arm = %#v; want rejection", step)
	}

	terminal := session.Abort()
	if terminal == nil || terminal.State() != fileops.UnpackStateNotPublished ||
		terminal.AttemptedEver() || terminal.CleanupIncomplete() {
		t.Fatalf("unattempted abort = %#v; want exact not-published cleanup", terminal)
	}
	assertNativeArchiveStage(t, stageParent, rawTarget, 0)
}

func TestArchiveSAFManifestKeepsExplicitEmptyEntriesAndSynthesizesParents(t *testing.T) {
	archive := buildArchiveSAFZIP(t, []archiveSAFZIPEntry{
		{name: "empty/", directory: true},
		{name: "zero.txt"},
		{name: "nested/deep/payload.txt", data: []byte("payload")},
		{name: "nested/deep/explicit-empty/", directory: true},
	})
	handoff, _, _ := newArchiveSAFHandoffFromZIP(t, archive, false)
	begin := handoff.BeginSAF()
	if begin.Kind() != NativeArchiveSAFBeginSession {
		t.Fatalf("manifest begin kind = %v; want session", begin.Kind())
	}
	session := begin.Session()
	want := []struct {
		name      string
		parent    int
		directory bool
		size      int64
	}{
		{name: "empty", parent: -1, directory: true},
		{name: "zero.txt", parent: -1},
		{name: "nested", parent: -1, directory: true},
		{name: "deep", parent: 2, directory: true},
		{name: "payload.txt", parent: 3, size: 7},
		{name: "explicit-empty", parent: 3, directory: true},
	}
	if session.EntryCount() != len(want) {
		t.Fatalf("manifest entry count = %d; want %d", session.EntryCount(), len(want))
	}
	for index, expected := range want {
		entry := session.Entry(index)
		if entry == nil || entry.Name() != expected.name ||
			entry.ParentIndex() != expected.parent ||
			entry.IsDirectory() != expected.directory || entry.Size() != expected.size {
			t.Fatalf("manifest entry %d = %#v; want %#v", index, entry, expected)
		}
	}
	_ = session.Abort()
}

func TestArchiveSAFManifestRejectsUnsafePathsKindsAndCollisionsBeforeProviderAuthority(t *testing.T) {
	invalidPaths := []string{
		string([]byte{'a', 0xff}), "a\x00b", `docs\readme.txt`, "/absolute",
		"C:/absolute", "C:relative", "//server/share", "", ".", "..",
		"a//b", "a/./b", "a/../b", strings.Repeat("x", 256),
		strings.Repeat("a/", 128) + "a",
	}
	for _, name := range invalidPaths {
		t.Run(fmt.Sprintf("path_%x", []byte(name)), func(t *testing.T) {
			assertArchiveSAFManifestRejected(t, []*zip.File{syntheticArchiveSAFFile(name, 0, 0, 0)})
		})
	}

	specialModes := []os.FileMode{
		os.ModeSymlink | 0o777,
		os.ModeNamedPipe | 0o600,
		os.ModeDevice | 0o600,
		os.ModeSocket | 0o600,
	}
	for _, mode := range specialModes {
		t.Run("mode_"+mode.String(), func(t *testing.T) {
			assertArchiveSAFManifestRejected(t, []*zip.File{
				syntheticArchiveSAFFile("special", 0, 0, mode),
			})
		})
	}

	collisions := []struct {
		name  string
		files []*zip.File
	}{
		{
			name: "duplicate file",
			files: []*zip.File{
				syntheticArchiveSAFFile("same", 0, 0, 0),
				syntheticArchiveSAFFile("same", 0, 0, 0),
			},
		},
		{
			name: "duplicate explicit directory",
			files: []*zip.File{
				syntheticArchiveSAFFile("same/", 0, 0, os.ModeDir|0o700),
				syntheticArchiveSAFFile("same/", 0, 0, os.ModeDir|0o700),
			},
		},
		{
			name: "file replaces synthesized directory",
			files: []*zip.File{
				syntheticArchiveSAFFile("same/child", 0, 0, 0),
				syntheticArchiveSAFFile("same", 0, 0, 0),
			},
		},
		{
			name: "file is a later parent",
			files: []*zip.File{
				syntheticArchiveSAFFile("same", 0, 0, 0),
				syntheticArchiveSAFFile("same/child", 0, 0, 0),
			},
		},
	}
	for _, test := range collisions {
		t.Run(test.name, func(t *testing.T) {
			assertArchiveSAFManifestRejected(t, test.files)
		})
	}

	assertArchiveSAFManifestRejected(t, nil)
	assertArchiveSAFManifestRejected(t, []*zip.File{
		syntheticArchiveSAFFile("non-empty-directory/", 1, 1, os.ModeDir|0o700),
	})
}

func TestArchiveSAFManifestRejectsSlashSuffixedSpecialZIPKindsBeforeSession(t *testing.T) {
	specialModes := []os.FileMode{
		os.ModeSymlink | 0o777,
		os.ModeNamedPipe | 0o600,
		os.ModeDevice | 0o600,
		os.ModeSocket | 0o600,
	}
	for _, mode := range specialModes {
		t.Run(mode.String(), func(t *testing.T) {
			archive := buildArchiveSAFZIP(t, []archiveSAFZIPEntry{
				{name: "special/", mode: mode},
			})
			handoff, stageParent, rawTarget := newArchiveSAFHandoffFromZIP(t, archive, false)
			begin := handoff.BeginSAF()
			if begin == nil || begin.Kind() != NativeArchiveSAFBeginTerminal ||
				begin.Session() != nil || begin.ReceiptArm() != nil || begin.Result() == nil {
				t.Fatalf("slash-suffixed special begin = %#v; want terminal without authority", begin)
			}
			if result := begin.Result(); result.State() != fileops.UnpackStateNotPublished ||
				result.AttemptedEver() || result.CleanupIncomplete() {
				t.Fatalf("slash-suffixed special result = %#v; want exact pre-attempt rejection", result)
			}
			assertNativeArchiveStage(t, stageParent, rawTarget, 0)
		})
	}
}

func TestArchiveSAFManifestEnforcesEntryPathAndSizeAggregateBounds(t *testing.T) {
	budget := fileops.NewZIPResourceBudget()
	if err := budget.Reserve(budget.LimitBytes() - 9<<20); err != nil {
		t.Fatal(err)
	}
	before := budget.CurrentBytes()
	files := make([]*zip.File, 1024)
	for index := range files {
		prefix := fmt.Sprintf("%05x", index)
		files[index] = syntheticArchiveSAFFile("a/"+prefix+strings.Repeat("x", 255-len(prefix)), 0, 0, 0)
	}
	manifest, charge, err := buildNativeArchiveSAFManifest(files, fileops.ZIPReadOptions{Budget: budget})
	if err == nil || manifest != nil || charge != 0 || budget.CurrentBytes() != before {
		t.Fatalf("path metadata exceeded working budget or leaked a charge: %v, %d, %v", manifest, charge, err)
	}

	assertArchiveSAFManifestRejected(t, []*zip.File{
		syntheticArchiveSAFFile("first", math.MaxInt64, 1, 0),
		syntheticArchiveSAFFile("second", 1, 1, 0),
	})
	assertArchiveSAFManifestRejected(t, []*zip.File{
		syntheticArchiveSAFFile("oversized", math.MaxUint64, 1, 0),
	})
}

type archiveSAFZIPEntry struct {
	name      string
	data      []byte
	directory bool
	mode      os.FileMode
	method    uint16
}

func buildArchiveSAFZIP(t testing.TB, entries []archiveSAFZIPEntry) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, entry := range entries {
		header := &zip.FileHeader{Name: entry.name, Method: entry.method}
		if header.Method == 0 {
			header.Method = zip.Store
		}
		mode := entry.mode
		if entry.directory {
			mode |= os.ModeDir | 0o700
			if !strings.HasSuffix(header.Name, "/") {
				header.Name += "/"
			}
		} else if mode == 0 {
			mode = 0o600
		}
		header.SetMode(mode)
		body, err := writer.CreateHeader(header)
		if err != nil {
			t.Fatalf("create ZIP entry %q: %v", entry.name, err)
		}
		if _, err := body.Write(entry.data); err != nil {
			t.Fatalf("write ZIP entry %q: %v", entry.name, err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close ZIP fixture: %v", err)
	}
	return buffer.Bytes()
}

func newArchiveSAFHandoffFromZIP(
	t testing.TB,
	archive []byte,
	journal bool,
) (*NativeArchiveHandoff, string, string) {
	t.Helper()
	parent := t.TempDir()
	target := filepath.Join(parent, "raw.zip")
	stage, err := pcv3publication.Create(target, nil, pcv3publication.PolicyNoReplace)
	if err != nil {
		t.Fatalf("create archive stage: %v", err)
	}
	if journal {
		if err := stage.PersistCleanupJournal(); err != nil {
			_ = stage.Cleanup()
			t.Fatalf("persist archive stage journal: %v", err)
		}
	}
	if _, err := stage.File().Write(archive); err != nil {
		_ = stage.Cleanup()
		t.Fatalf("write archive stage: %v", err)
	}
	sink := &nativeReadSink{stage: stage}
	handoff := newNativeArchiveHandoff(newNormalCompletion(PayloadKindArchive, true), sink)
	if handoff == nil {
		_ = stage.Cleanup()
		t.Fatal("authenticated archive did not mint handoff")
	}
	t.Cleanup(func() { _ = handoff.Close() })
	return handoff, parent, target
}

func syntheticArchiveSAFFile(
	name string,
	uncompressed uint64,
	compressed uint64,
	mode os.FileMode,
) *zip.File {
	header := zip.FileHeader{
		Name:               name,
		UncompressedSize64: uncompressed,
		CompressedSize64:   compressed,
	}
	if mode == 0 {
		mode = 0o600
	}
	header.SetMode(mode)
	return &zip.File{FileHeader: header}
}

func assertArchiveSAFManifestRejected(t *testing.T, files []*zip.File) {
	t.Helper()
	if manifest, _, err := buildNativeArchiveSAFManifest(files, fileops.ZIPReadOptions{}); err == nil || manifest != nil {
		t.Fatalf("manifest = %#v, error %v; want closed rejection", manifest, err)
	}
}
