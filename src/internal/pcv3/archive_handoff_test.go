package pcv3

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3publication"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

const normalArchiveFixtureID = "normal-standard-combined-ordered-archive-small"

func TestArchiveFollowUpConsumesAuthenticatedArchiveOnce(t *testing.T) {
	handoff, stageParent, rawTarget := newNativeArchiveHandoffFixture(t)
	copyOfHandoff := *handoff
	if !handoff.Live() {
		t.Fatal("reader-minted archive handoff is not live")
	}
	assertNativeArchiveStage(t, stageParent, rawTarget, 1)

	extractRoot := openNativeArchiveRoot(t)
	result := handoff.Extract(context.Background(), extractRoot)
	if result == nil || result.State() != fileops.UnpackStatePublishedDurable ||
		result.CleanupIncomplete() {
		t.Fatalf("archive extraction result = %#v; want durable with proven cleanup", result)
	}
	if handoff.Live() || copyOfHandoff.Live() || copyOfHandoff.Close() {
		t.Fatal("copied archive handoff retained authority after first consumption")
	}
	assertNativeArchiveStage(t, stageParent, rawTarget, 0)
}

func TestArchiveFollowUpCancelledContextConsumesAndCleansWithoutPublication(t *testing.T) {
	handoff, stageParent, rawTarget := newNativeArchiveHandoffFixture(t)
	copyOfHandoff := *handoff
	extractPath := t.TempDir()
	extractRoot, err := os.OpenRoot(extractPath)
	if err != nil {
		t.Fatalf("open extraction root: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := handoff.Extract(ctx, extractRoot)

	if result == nil || result.State() != fileops.UnpackStateNotPublished ||
		result.CleanupIncomplete() {
		t.Fatalf("cancelled archive extraction result = %#v; want not-published with proven cleanup", result)
	}
	if handoff.Live() || copyOfHandoff.Live() || copyOfHandoff.Close() {
		t.Fatal("cancelled archive extraction retained one-shot authority")
	}
	if _, err := extractRoot.Stat("."); err == nil {
		t.Fatal("cancelled archive extraction left extraction root open")
	}
	entries, err := os.ReadDir(extractPath)
	if err != nil || len(entries) != 0 {
		t.Fatalf("cancelled archive extraction entries = %v, error %v; want empty root", entries, err)
	}
	assertNativeArchiveStage(t, stageParent, rawTarget, 0)
}

func TestArchiveFollowUpDeniesWithoutFilesystemEffects(t *testing.T) {
	tests := []struct {
		name       string
		completion *normalCompletion
	}{
		{name: "nil completion"},
		{name: "zero completion", completion: &normalCompletion{}},
		{name: "authenticated raw", completion: newNormalCompletion(PayloadKindRaw, true)},
		{name: "unsealed archive", completion: newNormalCompletion(PayloadKindArchive, false)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			stageParent := t.TempDir()
			rawTarget := filepath.Join(stageParent, "raw.zip")
			stage, err := pcv3publication.Create(rawTarget, nil, pcv3publication.PolicyNoReplace)
			if err != nil {
				t.Fatalf("create private archive stage: %v", err)
			}
			t.Cleanup(func() { _ = stage.Cleanup() })
			sink := &nativeReadSink{target: rawTarget, stage: stage}
			output := &NativeReadOutput{state: &nativeReadOutputState{
				active: true, disposition: NativePayloadArchive,
				sink: sink, completion: test.completion,
			}}
			if output.Archive() != nil {
				t.Fatal("unauthenticated or wrong-kind completion minted archive authority")
			}
			sink.abortUncommitted()
			assertNativeArchiveStage(t, stageParent, rawTarget, 0)

			extractDir := t.TempDir()
			sentinel := filepath.Join(extractDir, "foreign.txt")
			if err := os.WriteFile(sentinel, []byte("foreign\n"), 0o600); err != nil {
				t.Fatalf("write extraction sentinel: %v", err)
			}
			root, err := os.OpenRoot(extractDir)
			if err != nil {
				t.Fatalf("open extraction root: %v", err)
			}
			if result := (&NativeArchiveHandoff{}).Extract(context.Background(), root); result != nil {
				t.Fatalf("zero archive handoff result = %#v; want denial", result)
			}
			assertArchiveHandoffFile(t, sentinel, "foreign\n")
			entries, err := os.ReadDir(extractDir)
			if err != nil || len(entries) != 1 || entries[0].Name() != "foreign.txt" {
				t.Fatalf("denied extraction entries = %v, error %v; want only sentinel", entries, err)
			}
		})
	}
}

func TestArchiveFollowUpFrozenTreeContent(t *testing.T) {
	handoff, stageParent, rawTarget := newNativeArchiveHandoffFixture(t)
	extractRootPath := t.TempDir()
	root, err := os.OpenRoot(extractRootPath)
	if err != nil {
		t.Fatalf("open extraction root: %v", err)
	}
	result := handoff.Extract(context.Background(), root)
	if result == nil || result.State() != fileops.UnpackStatePublishedDurable ||
		result.CleanupIncomplete() {
		t.Fatalf("frozen archive result = %#v; want durable with proven cleanup", result)
	}
	assertArchiveHandoffFile(t, filepath.Join(extractRootPath, "root.txt"), "PCV3 authenticated archive fixture\n")
	assertArchiveHandoffFile(
		t,
		filepath.Join(extractRootPath, "docs", "readme.txt"),
		"Extraction is admitted only after whole-volume authentication.\n",
	)
	entries, err := os.ReadDir(extractRootPath)
	if err != nil {
		t.Fatalf("read frozen extraction root: %v", err)
	}
	got := make([]string, len(entries))
	for index := range entries {
		got[index] = entries[index].Name()
	}
	if !slices.Equal(got, []string{"docs", "root.txt"}) {
		t.Fatalf("frozen extraction root entries = %q; want exact archive tree", got)
	}
	assertNativeArchiveStage(t, stageParent, rawTarget, 0)
}

func newNativeArchiveHandoffFixture(
	t *testing.T,
) (*NativeArchiveHandoff, string, string) {
	t.Helper()
	fixtures := loadNormalFixtureManifest(t).FixturesByID()
	fixture := requireNormalFixture(t, fixtures, normalArchiveFixtureID)
	volume := readNormalFixtureArtifact(t, fixture.Volume)
	source := newNormalFixtureSource(t, fixture, volume)
	structure := probeNormalBehavior(t, source, int64(len(volume)))
	provider := newNormalFixtureCredentialProvider(t, fixture.Keys)
	stageParent := t.TempDir()
	rawTarget := filepath.Join(stageParent, "raw.zip")
	sink := &nativeReadSink{target: rawTarget}
	var handoff *NativeArchiveHandoff
	result := runNativeReadSession(
		context.Background(),
		source,
		int64(len(volume)),
		structure,
		provider,
		sink,
		func(output *NativeReadOutput) error {
			if output.Disposition() != NativePayloadArchive {
				t.Fatalf("native archive disposition = %v; want archive", output.Disposition())
			}
			handoff = output.Archive()
			if handoff == nil || output.Archive() != nil || output.Publish(context.Background()) != nil {
				t.Fatal("native adapter did not transfer exactly one archive-only authority")
			}
			return nil
		},
	)
	if result.Outcome() != OutcomeSuccess || result.Stage() != StageNone ||
		result.PublicationAttempted() || result.CallbackFailed() || handoff == nil {
		t.Fatalf(
			"native archive result = %v/%v attempted=%v callback-failed=%v handoff=%v; want success pending authority",
			result.Outcome(), result.Stage(), result.PublicationAttempted(), result.CallbackFailed(), handoff,
		)
	}
	entries, err := os.ReadDir(stageParent)
	if err != nil || len(entries) != 1 {
		_ = handoff.Close()
		t.Fatalf("private archive stage entries = %v, error %v; want one", entries, err)
	}
	info, err := entries[0].Info()
	if err != nil || !info.Mode().IsRegular() {
		_ = handoff.Close()
		t.Fatalf("private archive stage identity = %v, error %v", info, err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		_ = handoff.Close()
		t.Fatalf("private archive stage mode = %o; want 0600", info.Mode().Perm())
	}
	t.Cleanup(func() { _ = handoff.Close() })
	return handoff, stageParent, rawTarget
}

func openNativeArchiveRoot(t *testing.T) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatalf("open extraction root: %v", err)
	}
	return root
}

func assertNativeArchiveStage(t *testing.T, parent, rawTarget string, wantEntries int) {
	t.Helper()
	if _, err := os.Lstat(rawTarget); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("raw archive target state = %v; want absent", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatalf("read archive stage parent: %v", err)
	}
	if len(entries) != wantEntries {
		t.Fatalf("archive stage parent entries = %d; want %d", len(entries), wantEntries)
	}
}

func TestNormalReaderCompletionRequiresAuthenticatedTail(t *testing.T) {
	t.Run("fully authenticated archive", func(t *testing.T) {
		_, _, result, completion := readArchiveHandoffFixture(
			t,
			context.Background(),
			normalArchiveFixtureID,
		)
		kind, authenticated := completion.authenticatedPayloadKind()
		if result.Outcome() != OutcomeSuccess || !authenticated || kind != PayloadKindArchive {
			t.Fatalf("healthy tail result/completion = %v/%v/%v; want success/authenticated/archive", result.Outcome(), authenticated, kind)
		}
	})

	t.Run("damaged trailer", func(t *testing.T) {
		_, _, result, completion := readArchiveHandoffFixture(
			t,
			context.Background(),
			"normal-degraded-trailer",
		)
		if result.Outcome() != OutcomeAuthenticatedDegraded || completion == nil {
			t.Fatalf("damaged trailer result/completion = %v/%v; want authenticated-degraded/non-nil", result.Outcome(), completion)
		}
		if _, authenticated := completion.authenticatedPayloadKind(); authenticated {
			t.Fatal("damaged trailer minted a whole-volume authentication capability")
		}
	})

	t.Run("invalid final record", func(t *testing.T) {
		_, _, result, completion := readArchiveHandoffFixture(
			t,
			context.Background(),
			"normal-negative-final",
		)
		if result.Outcome() != OutcomeAuthenticationFailed || result.Stage() != StageFinalRecord || completion != nil {
			t.Fatalf("invalid final result/completion = %v/%v/%v; want authentication-failed/final-record/nil", result.Outcome(), result.Stage(), completion)
		}
	})
}

func readArchiveHandoffFixture(
	t *testing.T,
	ctx context.Context,
	fixtureID string,
) (normalFixture, []byte, *normalReadResult, *normalCompletion) {
	t.Helper()
	fixtures := loadNormalFixtureManifest(t).FixturesByID()
	fixture := requireNormalFixture(t, fixtures, fixtureID)
	volume := readNormalFixtureArtifact(t, fixture.Volume)
	plaintext := readNormalFixturePlaintext(t, fixture.Plaintext)
	source := newNormalFixtureSource(t, fixture, volume)
	sink := &normalFixtureSink{}
	result, completion, _ := runNormalBehaviorRead(t, ctx, fixture, source, int64(len(volume)), sink)
	if result == nil {
		t.Fatal("normal reader returned a nil result")
	}
	t.Cleanup(result.Close)
	if completion != nil && !bytes.Equal(sink.plaintext(), plaintext) {
		t.Fatalf("reader staged %d bytes; want exact %d-byte fixture", len(sink.plaintext()), len(plaintext))
	}
	return fixture, plaintext, result, completion
}

func assertArchiveHandoffFile(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read extracted file %q: %v", path, err)
	}
	if string(got) != want {
		t.Fatalf("extracted file %q = %q; want %q", path, got, want)
	}
}
