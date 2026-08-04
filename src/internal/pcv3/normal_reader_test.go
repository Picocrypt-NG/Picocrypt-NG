package pcv3

import (
	pcv3crypto "Picocrypt-NG/internal/crypto"
	"Picocrypt-NG/internal/pcv3credential"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const normalPublicFixtureRoot = "testdata/normal"

type normalFixtureManifest struct {
	Fixtures []normalFixture `json:"fixtures"`
}

type normalFixture struct {
	ID          string                    `json:"id"`
	Volume      normalFixtureArtifact     `json:"volume"`
	Plaintext   normalFixturePlaintext    `json:"plaintext"`
	CommentHex  string                    `json:"comment_hex"`
	PayloadRS   bool                      `json:"payload_rs"`
	SessionView *normalFixtureSessionView `json:"session_view"`
	Expected    normalFixtureExpected     `json:"expected"`
	Keys        normalFixtureKeys         `json:"keys"`
}

type normalFixtureArtifact struct {
	File   string `json:"file"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type normalFixturePlaintext struct {
	Kind    string `json:"kind"`
	File    string `json:"file"`
	ByteHex string `json:"byte_hex"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
}

type normalFixtureSessionView struct {
	Phase        string `json:"phase"`
	Trigger      string `json:"trigger"`
	Operation    string `json:"operation"`
	Offset       int64  `json:"offset"`
	ObservedSize int64  `json:"observed_size"`
	ValueHex     string `json:"value_hex"`
}

type normalFixtureExpected struct {
	Outcome               string `json:"outcome"`
	Stage                 string `json:"stage"`
	AuthenticatedCapsules int    `json:"authenticated_capsules"`
	Completion            bool   `json:"completion"`
}

type normalFixtureKeys struct {
	VolumeKey            string `json:"volume_key_hex"`
	PrimaryWrapXChaCha20 string `json:"primary_wrap_xchacha20_hex"`
	BackupWrapXChaCha20  string `json:"backup_wrap_xchacha20_hex"`
	PrimaryWrapSerpent   string `json:"primary_wrap_serpent_hex"`
	BackupWrapSerpent    string `json:"backup_wrap_serpent_hex"`
	PrimaryWrapMAC       string `json:"primary_wrap_mac_hex"`
	BackupWrapMAC        string `json:"backup_wrap_mac_hex"`
	PrimaryReplicaMAC    string `json:"primary_replica_mac_hex"`
	BackupReplicaMAC     string `json:"backup_replica_mac_hex"`
	MetadataMAC          string `json:"metadata_mac_hex"`
	PayloadXChaCha20     string `json:"payload_xchacha20_hex"`
	PayloadSerpent       string `json:"payload_serpent_hex"`
	PayloadMAC           string `json:"payload_mac_hex"`
}

type normalFixtureCredentialAccess struct {
	wrap       [2]capsuleWrapKeys
	replicaMAC [2][32]byte
	volumeKey  [32]byte
	adopted    bool
}

func (access *normalFixtureCredentialAccess) withWrapKeys(
	role CapsuleRole,
	callback func(*capsuleWrapKeys) error,
) error {
	if !isSupportedCapsuleRole(role) || callback == nil {
		return errors.New("pcv3: invalid TEST ONLY wrap-key request")
	}
	keys := access.wrap[role]
	defer keys.close()
	return callback(&keys)
}

func (access *normalFixtureCredentialAccess) withReplicaKey(
	role CapsuleRole,
	volumeKey []byte,
	callback func([]byte) error,
) error {
	if !isSupportedCapsuleRole(role) || callback == nil ||
		!bytes.Equal(volumeKey, access.volumeKey[:]) {
		return errors.New("pcv3: invalid TEST ONLY replica-key request")
	}
	key := access.replicaMAC[role]
	defer pcv3crypto.SecureZero(key[:])
	return callback(key[:])
}

func (access *normalFixtureCredentialAccess) adoptVolumeKey(volumeKey []byte) error {
	defer pcv3crypto.SecureZero(volumeKey)
	if access.adopted || !bytes.Equal(volumeKey, access.volumeKey[:]) {
		return errors.New("pcv3: invalid TEST ONLY VolumeKey adoption")
	}
	access.adopted = true
	return nil
}

func (access *normalFixtureCredentialAccess) close() {
	if access == nil {
		return
	}
	for role := range access.wrap {
		access.wrap[role].close()
		pcv3crypto.SecureZero(access.replicaMAC[role][:])
	}
	pcv3crypto.SecureZero(access.volumeKey[:])
	access.adopted = false
}

type normalFixtureCredentialProvider struct {
	access           normalFixtureCredentialAccess
	metadataMAC      [32]byte
	payloadXChaCha   [32]byte
	payloadSerpent   [32]byte
	payloadMAC       [32]byte
	beforeCredential func()
	credentialCalls  int
	barrierChecks    int
	closeCalls       int
}

func (provider *normalFixtureCredentialProvider) withCredential(
	ctx context.Context,
	_ credentialTuple,
	callback func(capsuleCredentialAccess) error,
) error {
	if ctx == nil || ctx.Err() != nil || callback == nil {
		return errors.New("pcv3: invalid TEST ONLY credential request")
	}
	if provider.beforeCredential != nil {
		provider.barrierChecks++
		provider.beforeCredential()
	}
	provider.credentialCalls++
	return callback(&provider.access)
}

func (provider *normalFixtureCredentialProvider) withKey(
	ctx context.Context,
	request pcv3credential.KeyRequest,
	callback func([]byte) error,
) error {
	if ctx == nil || ctx.Err() != nil || callback == nil ||
		request.Role != pcv3credential.KeyRoleNotReplica || request.OutputBytes != 32 ||
		!provider.access.adopted {
		return errors.New("pcv3: invalid TEST ONLY payload-key request")
	}

	var key [32]byte
	switch request.Label {
	case pcv3credential.KeyLabelVolumeMetadataMAC:
		key = provider.metadataMAC
	case pcv3credential.KeyLabelVolumePayloadXChaCha20:
		key = provider.payloadXChaCha
	case pcv3credential.KeyLabelVolumePayloadSerpent:
		key = provider.payloadSerpent
	case pcv3credential.KeyLabelVolumePayloadMAC:
		key = provider.payloadMAC
	default:
		return errors.New("pcv3: unknown TEST ONLY payload-key request")
	}
	defer pcv3crypto.SecureZero(key[:])
	return callback(key[:])
}

func (provider *normalFixtureCredentialProvider) close() {
	if provider == nil {
		return
	}
	provider.closeCalls++
	provider.access.close()
	pcv3crypto.SecureZero(provider.metadataMAC[:])
	pcv3crypto.SecureZero(provider.payloadXChaCha[:])
	pcv3crypto.SecureZero(provider.payloadSerpent[:])
	pcv3crypto.SecureZero(provider.payloadMAC[:])
}

type normalFixtureSink struct {
	records              [][]byte
	recordAliases        [][]byte
	preAbortRecordCount  int
	preAbortPlaintextLen int
	aborted              bool
}

func (sink *normalFixtureSink) writeVerifiedRecord(
	_ context.Context,
	_ uint64,
	plaintext []byte,
) error {
	staged := make([]byte, len(plaintext))
	copy(staged, plaintext)
	sink.records = append(sink.records, staged)
	sink.recordAliases = append(sink.recordAliases, staged)
	return nil
}

func (sink *normalFixtureSink) abortUncommitted() {
	if sink.aborted {
		return
	}
	sink.preAbortRecordCount = len(sink.records)
	for _, record := range sink.records {
		sink.preAbortPlaintextLen += len(record)
	}
	for _, record := range sink.records {
		pcv3crypto.SecureZero(record)
	}
	sink.records = nil
	sink.aborted = true
}

func (sink *normalFixtureSink) plaintext() []byte {
	var plaintext []byte
	for _, record := range sink.records {
		plaintext = append(plaintext, record...)
	}
	return plaintext
}

func (sink *normalFixtureSink) stagedBytesAreZero() bool {
	for _, record := range sink.recordAliases {
		for _, value := range record {
			if value != 0 {
				return false
			}
		}
	}
	return true
}

var _ normalVolumeSink = (*normalFixtureSink)(nil)

type normalBorrowedSource struct {
	reader     io.ReaderAt
	closeCalls int
}

func (source *normalBorrowedSource) ReadAt(destination []byte, offset int64) (int, error) {
	return source.reader.ReadAt(destination, offset)
}

func (source *normalBorrowedSource) Close() error {
	source.closeCalls++
	return nil
}

type normalSessionViewSource struct {
	canonical       []byte
	session         []byte
	probeStep       int
	probePasses     int
	passesAtSwitch  int
	barrierViolated bool
	switched        bool
	closeCalls      int
}

func (source *normalSessionViewSource) ReadAt(destination []byte, offset int64) (int, error) {
	source.observeProbeRead(offset, len(destination))
	if !source.switched && offset == int64(frontHeaderBase) {
		if source.probePasses < 2 {
			source.barrierViolated = true
		} else {
			source.passesAtSwitch = source.probePasses
			source.switched = true
		}
	}
	view := source.canonical
	if source.switched {
		view = source.session
	}
	return bytes.NewReader(view).ReadAt(destination, offset)
}

func (source *normalSessionViewSource) observeProbeRead(offset int64, length int) {
	if source.switched {
		return
	}
	expected := [...]struct {
		offset int64
		length int
	}{
		{offset: 0, length: discriminatorLength},
		{offset: discriminatorLength, length: preambleRemainderLength},
		{offset: primaryCapsuleOffset, length: int(backupCapsuleLength)},
		{offset: int64(len(source.canonical)) - int64(trailerLength), length: int(trailerLength)},
		{offset: int64(len(source.canonical)) - int64(fixedSuffixLength), length: int(backupCapsuleLength)},
	}
	want := expected[source.probeStep]
	if offset == want.offset && length == want.length {
		source.probeStep++
		if source.probeStep == len(expected) {
			source.probePasses++
			source.probeStep = 0
		}
		return
	}
	if offset == expected[0].offset && length == expected[0].length {
		source.probeStep = 1
		return
	}
	source.probeStep = 0
}

func (source *normalSessionViewSource) Close() error {
	source.closeCalls++
	return nil
}

func TestReadNormalVolume(t *testing.T) {
	manifest := loadNormalFixtureManifest(t)
	fixtures := make(map[string]normalFixture, len(manifest.Fixtures))
	for _, fixture := range manifest.Fixtures {
		fixtures[fixture.ID] = fixture
		fixture := fixture
		t.Run(fixture.ID, func(t *testing.T) {
			volume := readNormalFixtureArtifact(t, fixture.Volume)
			plaintext := readNormalFixturePlaintext(t, fixture.Plaintext)
			source := newNormalFixtureSource(t, fixture, volume)

			route, structure, err := Probe(source, int64(len(volume)))
			if err != nil || route != RouteNormalPCV {
				t.Fatalf("Probe(TEST ONLY volume) = %v, %v; want normal PCV admission", route, err)
			}
			provider := newNormalFixtureCredentialProvider(t, fixture.Keys)
			if session, ok := source.(*normalSessionViewSource); ok {
				provider.beforeCredential = func() {
					if session.probePasses != 2 || session.probeStep != 0 ||
						session.switched || session.passesAtSwitch != 0 ||
						session.barrierViolated {
						t.Errorf(
							"credential callback crossed revalidation barrier at passes %d, partial step %d, switched %v, passes-at-switch %d, violated %v; want exactly external Probe plus one fresh Probe and no session mutation",
							session.probePasses,
							session.probeStep,
							session.switched,
							session.passesAtSwitch,
							session.barrierViolated,
						)
					}
				}
			}
			t.Cleanup(func() {
				if provider.closeCalls == 0 {
					provider.close()
				}
			})
			sink := &normalFixtureSink{}

			result, completion := readNormalVolumeWithProvider(
				context.Background(),
				source,
				int64(len(volume)),
				structure,
				provider,
				sink,
			)

			wantOutcome := normalFixtureOutcome(t, fixture.Expected.Outcome)
			wantStage := normalFixtureStage(t, fixture.Expected.Stage)
			assertNormalFixtureResult(
				t,
				result,
				wantOutcome,
				wantStage,
				fixture.Expected.AuthenticatedCapsules,
			)
			assertNormalCompletion(t, completion, fixture.Expected.Completion)
			assertNormalFixtureComment(t, result, fixture)
			assertNormalResultRedaction(t, result, fixture, volume, plaintext)
			result.Close()
			if comment := result.commentBytes(); comment != nil {
				pcv3crypto.SecureZero(comment)
				t.Fatal("closed normal result retained an authenticated public comment")
			}
			if provider.credentialCalls != 1 {
				t.Fatalf("literal credential-provider calls = %d; want one capsule-auth callback (not production KDF evidence)", provider.credentialCalls)
			}
			if provider.closeCalls != 1 {
				t.Fatalf("literal credential-provider close calls = %d; want one operation-owned cleanup", provider.closeCalls)
			}
			if source.closeCount() != 0 {
				t.Fatalf("borrowed source close calls = %d; want zero", source.closeCount())
			}
			if session, ok := source.(*normalSessionViewSource); ok {
				if session.barrierViolated || session.probePasses != 2 ||
					session.passesAtSwitch != 2 || !session.switched ||
					provider.barrierChecks != 1 {
					t.Fatalf(
						"session-view barrier = passes %d, passes at switch %d, switched %v, violated %v, credential checks %d; want external Probe plus exactly one fresh pre-KDF Probe before credential admission and mutation",
						session.probePasses,
						session.passesAtSwitch,
						session.switched,
						session.barrierViolated,
						provider.barrierChecks,
					)
				}
			}

			if fixture.Expected.Completion {
				if sink.aborted {
					t.Fatal("successful authenticated volume discarded its uncommitted plaintext")
				}
				if got := sink.plaintext(); !bytes.Equal(got, plaintext) {
					t.Fatalf("staged plaintext length/content mismatch: got %d bytes, want exact %d-byte fixture", len(got), len(plaintext))
				}
				return
			}
			wantPreAbort := normalFixturePreAbortPlaintext(t, fixture.ID, plaintext)
			if !sink.aborted || sink.records != nil || !sink.stagedBytesAreZero() {
				t.Fatal("failed volume retained an uncommitted plaintext copy")
			}
			if sink.preAbortPlaintextLen != wantPreAbort {
				t.Fatalf(
					"plaintext staged before abort = %d bytes; want %d for the protected failure boundary",
					sink.preAbortPlaintextLen,
					wantPreAbort,
				)
			}
			wantPreAbortRecords := 0
			if wantPreAbort != 0 {
				wantPreAbortRecords = 1
			}
			if sink.preAbortRecordCount != wantPreAbortRecords {
				t.Fatalf(
					"records staged before abort = %d; want exact %d",
					sink.preAbortRecordCount,
					wantPreAbortRecords,
				)
			}
		})
	}

	t.Run("static appended byte is rejected only after authenticated canonical tail closure", func(t *testing.T) {
		fixture := requireNormalFixture(t, fixtures, "normal-standard-combined-ordered-one")
		volume := readNormalFixtureArtifact(t, fixture.Volume)
		appended := append(append([]byte(nil), volume...), 0xa5)
		source := &normalBorrowedSource{reader: bytes.NewReader(appended)}
		route, structure, err := Probe(source, int64(len(appended)))
		if err != nil || route != RouteNormalPCV {
			t.Fatalf("Probe(TEST ONLY appended source) = %v, %v; want normal PCV admission", route, err)
		}
		provider := newNormalFixtureCredentialProvider(t, fixture.Keys)
		t.Cleanup(func() {
			if provider.closeCalls == 0 {
				provider.close()
			}
		})
		sink := &normalFixtureSink{}

		result, completion := readNormalVolumeWithProvider(
			context.Background(), source, int64(len(appended)), structure, provider, sink,
		)

		assertNormalFixtureResult(t, result, OutcomeAuthenticationFailed, StageTailGeometry, 1)
		assertNormalCompletion(t, completion, false)
		plaintext := readNormalFixturePlaintext(t, fixture.Plaintext)
		assertNormalResultRedaction(t, result, fixture, volume, plaintext)
		result.Close()
		if provider.credentialCalls != 1 {
			t.Fatalf("literal credential-provider calls = %d; want authenticated tail decision", provider.credentialCalls)
		}
		if provider.closeCalls != 1 {
			t.Fatalf("literal credential-provider close calls = %d; want one operation-owned cleanup", provider.closeCalls)
		}
		if !sink.aborted || sink.records != nil || !sink.stagedBytesAreZero() ||
			sink.preAbortPlaintextLen != 1 || sink.preAbortRecordCount != 1 {
			t.Fatal("appended-byte failure retained staged plaintext")
		}
		if source.closeCalls != 0 {
			t.Fatalf("borrowed appended source close calls = %d; want zero", source.closeCalls)
		}
	})

	t.Run("cached structure from another source fails before credential callback", func(t *testing.T) {
		cachedFixture := requireNormalFixture(t, fixtures, "normal-standard-combined-ordered-empty")
		cachedVolume := readNormalFixtureArtifact(t, cachedFixture.Volume)
		cachedSource := &normalBorrowedSource{reader: bytes.NewReader(cachedVolume)}
		_, cachedStructure, err := Probe(cachedSource, int64(len(cachedVolume)))
		if err != nil {
			t.Fatalf("Probe(TEST ONLY cached source): %v", err)
		}

		actualFixture := requireNormalFixture(t, fixtures, "normal-standard-combined-ordered-one")
		actualVolume := readNormalFixtureArtifact(t, actualFixture.Volume)
		actualSource := &normalBorrowedSource{reader: bytes.NewReader(actualVolume)}
		provider := newNormalFixtureCredentialProvider(t, actualFixture.Keys)
		t.Cleanup(func() {
			if provider.closeCalls == 0 {
				provider.close()
			}
		})
		sink := &normalFixtureSink{}

		result, completion := readNormalVolumeWithProvider(
			context.Background(), actualSource, int64(len(actualVolume)), cachedStructure, provider, sink,
		)

		assertNormalFixtureResult(t, result, OutcomeOperationFailed, StageInputIO, 0)
		assertNormalCompletion(t, completion, false)
		actualPlaintext := readNormalFixturePlaintext(t, actualFixture.Plaintext)
		assertNormalResultRedaction(t, result, actualFixture, actualVolume, actualPlaintext)
		result.Close()
		if provider.credentialCalls != 0 {
			t.Fatalf("literal credential-provider callback calls = %d; want zero before cached-source equality", provider.credentialCalls)
		}
		if provider.closeCalls != 1 {
			t.Fatalf("literal credential-provider close calls = %d; want cleanup on pre-KDF mismatch", provider.closeCalls)
		}
		if !sink.aborted || sink.records != nil || !sink.stagedBytesAreZero() ||
			sink.preAbortPlaintextLen != 0 || sink.preAbortRecordCount != 0 {
			t.Fatal("cached-source mismatch did not discard the operation-owned sink")
		}
		if cachedSource.closeCalls != 0 || actualSource.closeCalls != 0 {
			t.Fatalf("borrowed source close calls = cached %d, actual %d; want zero", cachedSource.closeCalls, actualSource.closeCalls)
		}
	})

}

type normalFixtureSource interface {
	io.ReaderAt
	closeCount() int
}

func (source *normalBorrowedSource) closeCount() int {
	return source.closeCalls
}

func (source *normalSessionViewSource) closeCount() int {
	return source.closeCalls
}

func newNormalFixtureSource(
	t *testing.T,
	fixture normalFixture,
	volume []byte,
) normalFixtureSource {
	t.Helper()
	if fixture.SessionView == nil {
		return &normalBorrowedSource{reader: bytes.NewReader(volume)}
	}
	if fixture.SessionView.Phase != "after-pre-kdf-revalidation" {
		t.Fatalf("unsupported TEST ONLY session-view phase %q", fixture.SessionView.Phase)
	}
	if fixture.SessionView.Trigger != "first-metadata-read" {
		t.Fatalf("unsupported TEST ONLY session-view trigger %q", fixture.SessionView.Trigger)
	}

	session := append([]byte(nil), volume...)
	switch fixture.SessionView.Operation {
	case "truncate-at":
		if fixture.SessionView.Offset < 0 || fixture.SessionView.Offset > int64(len(session)) {
			t.Fatalf("invalid TEST ONLY truncate offset %d", fixture.SessionView.Offset)
		}
		session = session[:fixture.SessionView.Offset]
	case "append-byte-at":
		if fixture.SessionView.Offset != int64(len(session)) {
			t.Fatalf("invalid TEST ONLY append offset %d", fixture.SessionView.Offset)
		}
		value := decodeNormalFixtureHex(t, fixture.SessionView.ValueHex, 1)
		session = append(session, value[0])
		pcv3crypto.SecureZero(value)
	default:
		t.Fatalf("unsupported TEST ONLY session-view operation %q", fixture.SessionView.Operation)
	}
	if int64(len(session)) != fixture.SessionView.ObservedSize {
		t.Fatalf("TEST ONLY session-view size = %d; want manifest %d", len(session), fixture.SessionView.ObservedSize)
	}
	return &normalSessionViewSource{canonical: volume, session: session}
}

func loadNormalFixtureManifest(t *testing.T) normalFixtureManifest {
	t.Helper()
	encoded, err := os.ReadFile(filepath.Join(normalPublicFixtureRoot, "manifest.json"))
	if err != nil {
		t.Fatalf("read TEST ONLY normal manifest: %v", err)
	}
	var manifest normalFixtureManifest
	if err := json.Unmarshal(encoded, &manifest); err != nil {
		t.Fatalf("decode TEST ONLY normal manifest: %v", err)
	}
	return manifest
}

func readNormalFixtureArtifact(t *testing.T, artifact normalFixtureArtifact) []byte {
	t.Helper()
	if artifact.File == "" || !filepath.IsLocal(artifact.File) {
		t.Fatalf("invalid TEST ONLY fixture path %q", artifact.File)
	}
	data, err := os.ReadFile(filepath.Join(normalPublicFixtureRoot, artifact.File))
	if err != nil {
		t.Fatalf("read TEST ONLY artifact %q: %v", artifact.File, err)
	}
	assertNormalFixtureBytes(t, artifact.File, data, artifact.Size, artifact.SHA256)
	return data
}

func readNormalFixturePlaintext(t *testing.T, plaintext normalFixturePlaintext) []byte {
	t.Helper()
	var data []byte
	switch plaintext.Kind {
	case "file":
		data = readNormalFixtureArtifact(t, normalFixtureArtifact{
			File: plaintext.File, Size: plaintext.Size, SHA256: plaintext.SHA256,
		})
	case "repeat":
		value := decodeNormalFixtureHex(t, plaintext.ByteHex, 1)
		data = bytes.Repeat(value, int(plaintext.Size))
		pcv3crypto.SecureZero(value)
		assertNormalFixtureBytes(t, "repeated plaintext recipe", data, plaintext.Size, plaintext.SHA256)
	default:
		t.Fatalf("unsupported TEST ONLY plaintext kind %q", plaintext.Kind)
	}
	return data
}

func assertNormalFixtureBytes(
	t *testing.T,
	name string,
	data []byte,
	wantSize int64,
	wantSHA256 string,
) {
	t.Helper()
	if int64(len(data)) != wantSize {
		t.Fatalf("TEST ONLY %s size = %d; want manifest %d", name, len(data), wantSize)
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != wantSHA256 {
		t.Fatalf("TEST ONLY %s SHA-256 does not match manifest", name)
	}
}

func newNormalFixtureCredentialProvider(
	t *testing.T,
	keys normalFixtureKeys,
) *normalFixtureCredentialProvider {
	t.Helper()
	provider := &normalFixtureCredentialProvider{}
	provider.access.volumeKey = decodeNormalFixtureKey(t, keys.VolumeKey, false)
	provider.access.wrap[CapsuleRolePrimary] = capsuleWrapKeys{
		xChaCha20: decodeNormalFixtureKey(t, keys.PrimaryWrapXChaCha20, false),
		serpent:   decodeNormalFixtureKey(t, keys.PrimaryWrapSerpent, true),
		mac:       decodeNormalFixtureKey(t, keys.PrimaryWrapMAC, false),
	}
	provider.access.wrap[CapsuleRoleBackup] = capsuleWrapKeys{
		xChaCha20: decodeNormalFixtureKey(t, keys.BackupWrapXChaCha20, false),
		serpent:   decodeNormalFixtureKey(t, keys.BackupWrapSerpent, true),
		mac:       decodeNormalFixtureKey(t, keys.BackupWrapMAC, false),
	}
	provider.access.replicaMAC[CapsuleRolePrimary] = decodeNormalFixtureKey(t, keys.PrimaryReplicaMAC, false)
	provider.access.replicaMAC[CapsuleRoleBackup] = decodeNormalFixtureKey(t, keys.BackupReplicaMAC, false)
	provider.metadataMAC = decodeNormalFixtureKey(t, keys.MetadataMAC, false)
	provider.payloadXChaCha = decodeNormalFixtureKey(t, keys.PayloadXChaCha20, false)
	provider.payloadSerpent = decodeNormalFixtureKey(t, keys.PayloadSerpent, true)
	provider.payloadMAC = decodeNormalFixtureKey(t, keys.PayloadMAC, false)
	return provider
}

func decodeNormalFixtureKey(t *testing.T, encoded string, optional bool) [32]byte {
	t.Helper()
	var key [32]byte
	if optional && encoded == "" {
		return key
	}
	decoded := decodeNormalFixtureHex(t, encoded, len(key))
	copy(key[:], decoded)
	pcv3crypto.SecureZero(decoded)
	return key
}

func decodeNormalFixtureHex(t *testing.T, encoded string, want int) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != want {
		t.Fatalf("decode TEST ONLY hex: length %d, want %d, error %v", len(decoded), want, err)
	}
	return decoded
}

func normalFixtureOutcome(t *testing.T, encoded string) Outcome {
	t.Helper()
	switch encoded {
	case "success":
		return OutcomeSuccess
	case "authenticated-degraded":
		return OutcomeAuthenticatedDegraded
	case "authentication-failed":
		return OutcomeAuthenticationFailed
	default:
		t.Fatalf("unsupported TEST ONLY outcome %q", encoded)
		return 0
	}
}

func normalFixtureStage(t *testing.T, encoded string) Stage {
	t.Helper()
	switch encoded {
	case "none":
		return StageNone
	case "capsule-rs":
		return StageCapsuleRS
	case "metadata":
		return StageMetadata
	case "descriptor":
		return StageDescriptor
	case "record-auth":
		return StageRecordAuth
	case "final-record":
		return StageFinalRecord
	case "tail-geometry":
		return StageTailGeometry
	default:
		t.Fatalf("unsupported TEST ONLY stage %q", encoded)
		return 0
	}
}

func normalFixturePreAbortPlaintext(
	t *testing.T,
	fixtureID string,
	plaintext []byte,
) int {
	t.Helper()
	switch fixtureID {
	case "normal-negative-descriptor", "normal-negative-record":
		return 0
	case "normal-negative-final", "normal-negative-suffix", "normal-negative-extra-byte":
		return len(plaintext)
	default:
		t.Fatalf("no TEST ONLY pre-abort staging oracle for %q", fixtureID)
		return 0
	}
}

func assertNormalFixtureComment(
	t *testing.T,
	result *normalReadResult,
	fixture normalFixture,
) {
	t.Helper()
	if !fixture.Expected.Completion {
		return
	}
	comment := result.commentBytes()
	defer pcv3crypto.SecureZero(comment)
	if fixture.Expected.Stage == "metadata" {
		if comment != nil {
			t.Fatalf("metadata-damaged result retained %d unauthenticated comment bytes", len(comment))
		}
		return
	}
	want, err := hex.DecodeString(fixture.CommentHex)
	if err != nil {
		t.Fatalf("decode TEST ONLY public comment: %v", err)
	}
	defer pcv3crypto.SecureZero(want)
	if !bytes.Equal(comment, want) {
		t.Fatalf("authenticated public comment mismatch: got %d bytes, want exact %d-byte fixture", len(comment), len(want))
	}
}

func assertNormalResultRedaction(
	t *testing.T,
	result *normalReadResult,
	fixture normalFixture,
	volume []byte,
	plaintext []byte,
) {
	t.Helper()
	want := normalResultRendering(t, result.Outcome())
	renderings := []struct {
		name string
		got  string
		want string
	}{
		{name: "Error", got: result.Error(), want: want},
		{name: "String", got: result.String(), want: want},
		{name: "GoString", got: result.GoString(), want: want},
		{name: "%s", got: fmt.Sprintf("%s", result), want: want},
		{name: "%q", got: fmt.Sprintf("%q", result), want: strconv.Quote(want)},
		{name: "%v", got: fmt.Sprintf("%v", result), want: want},
		{name: "%+v", got: fmt.Sprintf("%+v", result), want: want},
		{name: "%#v", got: fmt.Sprintf("%#v", result), want: want},
		{name: "%x", got: fmt.Sprintf("%x", result), want: want},
		{name: "%X", got: fmt.Sprintf("%X", result), want: want},
	}
	canaries := normalResultCanaries(t, fixture, volume, plaintext)
	for _, rendering := range renderings {
		if rendering.got != rendering.want {
			t.Fatalf("normal result %s rendered %q; want fixed %q", rendering.name, rendering.got, rendering.want)
		}
		for _, canary := range canaries {
			if canary != "" && strings.Contains(rendering.got, canary) {
				t.Fatalf("normal result %s disclosed TEST ONLY canary %q", rendering.name, canary)
			}
		}
	}
}

func normalResultRendering(t *testing.T, outcome Outcome) string {
	t.Helper()
	switch outcome {
	case OutcomeSuccess:
		return "pcv3: normal volume authenticated"
	case OutcomeAuthenticatedDegraded:
		return "pcv3: normal volume authenticated with degraded recovery"
	case OutcomeAuthenticationFailed:
		return "pcv3: credentials incorrect or volume damaged"
	case OutcomeOperationFailed:
		return "pcv3: normal volume operation failed"
	default:
		t.Fatalf("no TEST ONLY fixed rendering for outcome %v", outcome)
		return ""
	}
}

func normalResultCanaries(
	t *testing.T,
	fixture normalFixture,
	volume []byte,
	plaintext []byte,
) []string {
	t.Helper()
	comment, err := hex.DecodeString(fixture.CommentHex)
	if err != nil {
		t.Fatalf("decode TEST ONLY comment canary: %v", err)
	}
	defer pcv3crypto.SecureZero(comment)
	canaries := []string{
		string(comment),
		fixture.CommentHex,
		fixture.Keys.VolumeKey,
		fixture.Keys.PayloadMAC,
	}
	if len(plaintext) >= 8 {
		canaries = append(canaries, hex.EncodeToString(plaintext[:min(16, len(plaintext))]))
	}
	if !fixture.PayloadRS {
		tagEnd := len(volume) - int(fixedSuffixLength)
		tagStart := tagEnd - int(recordTagSize)
		if tagStart < 0 || tagEnd > len(volume) {
			t.Fatalf("TEST ONLY final-tag extent [%d,%d) outside %d-byte volume", tagStart, tagEnd, len(volume))
		}
		canaries = append(canaries, hex.EncodeToString(volume[tagStart:tagEnd]))
	}
	return canaries
}

func assertNormalFixtureResult(
	t *testing.T,
	result *normalReadResult,
	wantOutcome Outcome,
	wantStage Stage,
	wantAuthenticated int,
) {
	t.Helper()
	if result == nil {
		t.Fatal("normal reader returned no typed result")
	}
	if result.Outcome() != wantOutcome || result.Stage() != wantStage ||
		result.AuthenticatedCapsules() != wantAuthenticated {
		t.Fatalf(
			"normal result = %v/%v/%d; want %v/%v/%d",
			result.Outcome(), result.Stage(), result.AuthenticatedCapsules(),
			wantOutcome, wantStage, wantAuthenticated,
		)
	}
	wantCode := CodeSuccess
	switch wantOutcome {
	case OutcomeSuccess:
		wantCode = CodeSuccess
	case OutcomeAuthenticatedDegraded:
		wantCode = CodeAuthenticatedDegraded
	case OutcomeAuthenticationFailed:
		wantCode = CodeAuthenticationFailed
	case OutcomeOperationFailed:
		wantCode = CodeOperationFailed
	default:
		t.Fatalf("no TEST ONLY code mapping for outcome %v", wantOutcome)
	}
	if result.Code() != wantCode {
		t.Fatalf("normal result code = %v; want %v for %v/%v", result.Code(), wantCode, wantOutcome, wantStage)
	}
}

func assertNormalCompletion(t *testing.T, completion *normalCompletion, want bool) {
	t.Helper()
	if (completion != nil) != want {
		t.Fatalf("sealed completion present = %v; want %v", completion != nil, want)
	}
}

func requireNormalFixture(
	t *testing.T,
	fixtures map[string]normalFixture,
	id string,
) normalFixture {
	t.Helper()
	fixture, ok := fixtures[id]
	if !ok {
		t.Fatalf("TEST ONLY fixture %q unavailable", id)
	}
	return fixture
}
