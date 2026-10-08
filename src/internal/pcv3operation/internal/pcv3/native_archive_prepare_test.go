package pcv3

import (
	"Picocrypt-NG/internal/fileops"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3credential"
	"Picocrypt-NG/internal/pcv3operation/internal/pcv3resource"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestNativePrepareArchiveUsesAuthenticatedPlaintext(t *testing.T) {
	fixture := requireNormalFixture(t, loadNormalFixtureManifest(t).FixturesByID(), normalArchiveFixtureID)
	zipBytes := readNormalFixturePlaintext(t, fixture.Plaintext)
	factors := func() *pcv3credential.FactorRequest {
		return &pcv3credential.FactorRequest{
			Mode: pcv3credential.CredentialModeKeyfilesOnly, ExpectedPolicy: pcv3credential.FactorPolicyKeyfilesOnly,
			KeyfileMode: pcv3credential.KeyfileModeUnordered,
			Keyfiles:    []*pcv3credential.KeyfileReader{pcv3credential.OwnKeyfileReader(io.NopCloser(bytes.NewReader([]byte("public ZIP preparation factor"))))},
		}
	}
	admitter := pcv3resource.NewPlatformAdmitter()
	encode := func(kind PayloadKind, plaintext []byte) []byte {
		t.Helper()
		var encoded bytes.Buffer
		if err := RunNativeNormalWrite(context.Background(), &NativeNormalWriteRequest{
			Suite: SuiteStandard, PayloadKind: kind, PlaintextLength: uint64(len(plaintext)),
			Source: bytes.NewReader(plaintext), Destination: &encoded, Factors: factors(), Admitter: admitter,
		}); err != nil {
			t.Fatal(err)
		}
		return encoded.Bytes()
	}
	// Keyfile-only credentials still run the fixed production KDF. Reuse each
	// serialized fixture while each read performs its own credential derivation.
	ordinaryBytes := []byte("ordinary authenticated file")
	rawZIP := encode(PayloadKindRaw, zipBytes)
	rawOrdinary := encode(PayloadKindRaw, ordinaryBytes)
	declaredArchive := encode(PayloadKindArchive, zipBytes)
	for _, test := range []struct {
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
		t.Run(test.name, func(t *testing.T) {
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
					t.Fatalf("damaged payload reached an output action: %v callbacks=%d", result.Outcome(), callbacks)
				}
				assertNativeArchiveStage(t, parent, target, 0)
				return
			}
			if result.Outcome() != OutcomeSuccess || callbacks != 1 || (handoff != nil) != test.archive {
				t.Fatalf("archive disposition mismatch: %v callbacks=%d handoff=%v", result.Outcome(), callbacks, handoff)
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
				if cleanup {
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
				if extracted == nil || extracted.State() != nativeExtractionState() || extracted.CleanupIncomplete() {
					t.Fatalf("prepared ZIP extraction failed: %v", extracted)
				}
				assertArchiveHandoffFile(t, filepath.Join(path, "root.txt"), "PCV3 authenticated archive fixture\n")
				assertNativeArchiveStage(t, parent, target, 0)
			case "saf":
				begin := handoff.BeginSAF()
				if begin.Kind() != NativeArchiveSAFBeginTerminal || begin.Result() == nil || begin.Result().State() != fileops.UnpackStateNotPublished || begin.Result().CleanupIncomplete() {
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
}
