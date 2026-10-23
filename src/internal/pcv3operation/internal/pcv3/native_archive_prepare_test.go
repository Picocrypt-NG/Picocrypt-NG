package pcv3

import (
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3resource"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func TestNativePrepareArchiveUsesAuthenticatedPlaintext(t *testing.T) {
	worker := os.Getenv("PICOCRYPT_TEST_NATIVE_ARCHIVE_WORKER")
	fixtureDirectory := os.Getenv("PICOCRYPT_TEST_NATIVE_ARCHIVE_FIXTURES")
	if worker == "" {
		fixtureDirectory = ""
	}
	isolated := runtime.GOOS == "darwin" && worker == ""
	if isolated {
		fixtureDirectory = t.TempDir()
		runNativeArchiveWorker(t, "fixtures", fixtureDirectory)
	}
	if worker != "" && fixtureDirectory == "" {
		t.Fatal("native archive worker requires its fixture directory")
	}
	fixture := requireNormalFixture(t, loadNormalFixtureManifest(t).FixturesByID(), normalArchiveFixtureID)
	zipBytes := readNormalFixturePlaintext(t, fixture.Plaintext)
	factors := func() *pcv3credential.FactorRequest {
		return &pcv3credential.FactorRequest{
			Mode: pcv3credential.CredentialModeKeyfilesOnly, ExpectedPolicy: pcv3credential.FactorPolicyKeyfilesOnly,
			KeyfileMode: pcv3credential.KeyfileModeUnordered,
			Keyfiles:    []*pcv3credential.KeyfileReader{pcv3credential.OwnKeyfileReader(io.NopCloser(bytes.NewReader([]byte("public ZIP preparation factor"))))},
		}
	}
	admitter := &nativeArchiveObservingAdmitter{t: t, delegate: pcv3resource.NewPlatformAdmitter()}
	encode := func(kind PayloadKind, plaintext []byte) []byte {
		t.Helper()
		var encoded bytes.Buffer
		if err := RunNativeNormalWrite(context.Background(), &NativeNormalWriteRequest{
			Suite: SuiteStandard, PayloadKind: kind, PlaintextLength: uint64(len(plaintext)),
			Source: bytes.NewReader(plaintext), Destination: &encoded, Factors: factors(), Admitter: admitter,
		}); err != nil {
			var writeFailure *normalWriteFailure
			if errors.As(err, &writeFailure) {
				t.Logf("normal serialization stage=%v", writeFailure.Stage())
			}
			var pipelineFailure *pcv3credential.PipelineError
			if errors.As(err, &pipelineFailure) && pipelineFailure != nil {
				t.Logf("credential pipeline code=%d stage=%d suite=%d", pipelineFailure.Code, pipelineFailure.Stage, pipelineFailure.Suite)
			}
			t.Fatal(err)
		}
		return encoded.Bytes()
	}
	// Keyfile-only credentials still run the fixed production KDF. On Darwin,
	// separate fixture setup from the independent archive cases: released Go
	// heap pages need not immediately rejoin the OS free-page pool. Mandatory
	// facade tests separately exercise sequential writes and reads in one process.
	ordinaryBytes := []byte("ordinary authenticated file")
	var rawZIP, rawOrdinary, declaredArchive []byte
	if fixtureDirectory == "" || worker == "fixtures" {
		rawZIP = encode(PayloadKindRaw, zipBytes)
		rawOrdinary = encode(PayloadKindRaw, ordinaryBytes)
		declaredArchive = encode(PayloadKindArchive, zipBytes)
		if worker == "fixtures" {
			for name, encoded := range map[string][]byte{
				"raw-zip": rawZIP, "raw-ordinary": rawOrdinary, "declared-archive": declaredArchive,
			} {
				if err := os.WriteFile(filepath.Join(fixtureDirectory, name), encoded, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			t.Log("native archive worker completed: fixtures")
			return
		}
	} else {
		for name, encoded := range map[string]*[]byte{
			"raw-zip": &rawZIP, "raw-ordinary": &rawOrdinary, "declared-archive": &declaredArchive,
		} {
			var err error
			*encoded, err = os.ReadFile(filepath.Join(fixtureDirectory, name))
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Logf("retained serialized fixture lengths: raw ZIP=%d raw ordinary=%d declared archive=%d total=%d", len(rawZIP), len(rawOrdinary), len(declaredArchive), len(rawZIP)+len(rawOrdinary)+len(declaredArchive))
	selected := false
	for index, test := range []struct {
		name       string
		kind       PayloadKind
		prepare    bool
		plaintext  []byte
		encoded    []byte
		archive    bool
		action     string
		corruptTag bool
	}{
		{"raw ZIP without opt-in is a file", PayloadKindRaw, false, zipBytes, rawZIP, false, "", false},
		{"raw ZIP opt-in extracts", PayloadKindRaw, true, zipBytes, rawZIP, true, "extract", false},
		{"raw ZIP opt-in can save unchanged", PayloadKindRaw, true, zipBytes, rawZIP, true, "publish", false},
		{"raw non-ZIP opt-in remains a file", PayloadKindRaw, true, ordinaryBytes, rawOrdinary, false, "", false},
		{"declared archive keeps default handoff", PayloadKindArchive, false, zipBytes, declaredArchive, true, "extract", false},
		{"damaged raw ZIP grants no handoff", PayloadKindRaw, true, zipBytes, rawZIP, false, "", true},
		{"raw ZIP SAF refusal consumes and cleans", PayloadKindRaw, true, zipBytes, rawZIP, true, "saf", false},
	} {
		selector := strconv.Itoa(index)
		if worker != "" && worker != selector {
			continue
		}
		selected = true
		t.Run(test.name, func(t *testing.T) {
			if isolated {
				runNativeArchiveWorker(t, selector, fixtureDirectory)
				return
			}
			if worker != "" {
				t.Cleanup(func() {
					if !t.Failed() && !t.Skipped() {
						t.Logf("native archive worker completed: %s", worker)
					}
				})
			}
			encoded := bytes.Clone(test.encoded)
			if test.corruptTag {
				_, structure, err := Probe(bytes.NewReader(encoded), int64(len(encoded)))
				if err != nil {
					t.Fatal(err)
				}
				// Change a data-record body byte, leaving structural metadata intact.
				encoded[structure.geometries[0].FrontHeaderLength()+int64(recordDescriptorSize)] ^= 1
			}
			parent := t.TempDir()
			target := filepath.Join(parent, "output")
			request := &NativeReadRequest{
				Source: bytes.NewReader(encoded), SourceSize: int64(len(encoded)), Factors: factors(),
				Admitter: admitter, Target: target, PrepareArchive: test.prepare,
			}
			var handoff *NativeArchiveHandoff
			callbacks := 0
			result := RunNativeRead(context.Background(), request, func(output *NativeReadOutput) error {
				callbacks++
				if output.Disposition() == NativePayloadArchive {
					handoff = output.Archive()
				} else {
					requireNativePublication(t, output.Publish(context.Background()))
				}
				return nil
			})
			if request.PrepareArchive {
				t.Fatal("transferred archive option survived")
			}
			if test.corruptTag {
				if result.Outcome() != OutcomeAuthenticationFailed || callbacks != 0 || handoff != nil {
					t.Fatalf("damaged payload result: outcome=%v stage=%v code=%v callbacks=%d handoff=%v; want authentication failure without output authority", result.Outcome(), result.Stage(), result.Code(), callbacks, handoff)
				}
				assertNativeArchiveStage(t, parent, target, 0)
				return
			}
			if result.Outcome() != OutcomeSuccess || callbacks != 1 || (handoff != nil) != test.archive {
				t.Fatalf("archive disposition mismatch: outcome=%v stage=%v code=%v callbacks=%d handoff=%v", result.Outcome(), result.Stage(), result.Code(), callbacks, handoff)
			}
			if !test.archive {
				got, err := os.ReadFile(target)
				if err != nil || !bytes.Equal(got, test.plaintext) {
					t.Fatalf("ordinary plaintext changed: %v", err)
				}
				return
			}
			defer handoff.Close()
			if kind, authenticated := handoff.state.completion.authenticatedPayloadKind(); !authenticated || kind != test.kind {
				t.Fatal("ZIP preparation rewrote authenticated payload metadata")
			}
			assertNativeArchiveStage(t, parent, target, 1)
			switch test.action {
			case "publish":
				publication, cleanup := handoff.Publish(context.Background())
				requireNativePublication(t, publication)
				if !nativeCleanupErrorMatches(t, cleanup) {
					t.Fatalf("prepared ZIP publication failed: %v cleanup=%v", publication, cleanup)
				}
				got, err := os.ReadFile(target)
				if err != nil || !bytes.Equal(got, zipBytes) {
					t.Fatalf("saved ZIP changed: %v", err)
				}
			case "extract":
				root := openNativeArchiveRoot(t)
				path := root.Name()
				extracted := handoff.Extract(context.Background(), root)
				if extracted == nil || extracted.State() != nativeExtractionState(t) || !nativeCleanupMatches(t, extracted) {
					t.Fatalf("prepared ZIP extraction failed: %v", extracted)
				}
				assertArchiveHandoffFile(t, filepath.Join(path, "root.txt"), "PCV3 authenticated archive fixture\n")
				assertNativeArchiveStage(t, parent, target, 0)
			case "saf":
				begin := handoff.BeginSAF()
				if begin.Kind() != NativeArchiveSAFBeginTerminal || begin.Result() == nil || begin.Result().State() != nativeArchiveSAFUnattemptedState(t) || !nativeCleanupMatches(t, begin.Result()) {
					t.Fatal("unsupported raw ZIP SAF action did not cleanly refuse")
				}
				assertNativeArchiveStage(t, parent, target, 0)
			}
			if handoff.Live() {
				t.Fatal("prepared ZIP action retained authority")
			}
			if test.action != "publish" {
				if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("unpublished prepared ZIP appeared at destination: %v", err)
				}
			}
		})
	}
	if worker != "" && !selected {
		t.Fatalf("unknown native archive worker: %q", worker)
	}
}

func runNativeArchiveWorker(t *testing.T, selector, directory string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Minute)
	if testDeadline, ok := t.Deadline(); ok {
		deadline = testDeadline
	}
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0],
		"-test.run=^TestNativePrepareArchiveUsesAuthenticatedPlaintext$",
		"-test.v", "-test.timeout="+time.Until(deadline).String())
	command.Env = append(os.Environ(),
		"PICOCRYPT_TEST_NATIVE_ARCHIVE_WORKER="+selector,
		"PICOCRYPT_TEST_NATIVE_ARCHIVE_FIXTURES="+directory)
	command.WaitDelay = time.Second
	output, err := command.CombinedOutput()
	t.Logf("native archive worker %s:\n%s", selector, output)
	if err != nil {
		t.Fatalf("native archive worker %s failed: %v", selector, err)
	}
	// A Go test binary can exit successfully without matching any test. Require
	// completion from the selected fixture setup or non-skipped archive body.
	if !bytes.Contains(output, []byte("native archive worker completed: "+selector+"\n")) {
		t.Fatalf("native archive worker %s did not complete its selected body", selector)
	}
}

type nativeArchiveObservingAdmitter struct {
	t        *testing.T
	delegate pcv3credential.Admitter
}

func (admitter *nativeArchiveObservingAdmitter) AdmitKDF(ctx context.Context, profile pcv3credential.KDFProfile) (pcv3credential.KDFAdmission, error) {
	decision, err := admitter.delegate.AdmitKDF(ctx, profile)
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	admitter.t.Logf("post-decision actual platform KDF admission=%d (granted=%t); Go memory bytes: HeapAlloc=%d HeapInuse=%d HeapIdle=%d HeapReleased=%d Sys=%d NumGC=%d", decision, decision == pcv3credential.KDFAdmissionGranted, memory.HeapAlloc, memory.HeapInuse, memory.HeapIdle, memory.HeapReleased, memory.Sys, memory.NumGC)
	if runtime.GOOS == "darwin" && decision == pcv3credential.KDFAdmissionDeniedInsufficient {
		probeContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, probe := range []struct {
			label string
			path  string
			args  []string
		}{
			{label: "system vm_stat", path: "/usr/bin/vm_stat"},
			{label: "own-process top MEM (physical footprint)", path: "/usr/bin/top", args: []string{"-l", "1", "-pid", strconv.Itoa(os.Getpid()), "-stats", "pid,mem"}},
		} {
			command := exec.CommandContext(probeContext, probe.path, probe.args...)
			command.WaitDelay = time.Second
			output, probeErr := command.CombinedOutput()
			admitter.t.Logf("post-decision Darwin %s (not provider snapshot; truncated=%t): err=%v\n%s", probe.label, len(output) > 8192, probeErr, output[:min(len(output), 8192)])
		}
	}
	return decision, err
}
