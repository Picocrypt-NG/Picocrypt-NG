package pcv3

import (
	pcencoding "Picocrypt-NG/internal/encoding"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"maps"
	"math"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// Phase 9 Z01-Z06 seed manifest binding. The checked-in public manifest
// testdata/fuzz/phase9-seeds.json freezes exactly the six required fuzz
// targets, their deterministic controls, the referenced frozen artifact
// SHA-256 values, nonempty public seed IDs with canonical-argument SHA-256
// values, and the expected deterministic seam counters. Seeds carry only
// synthetic public format data: no credentials, private vectors, or owner
// paths. The controls below prove every canonical seed reaches its claimed
// production seam; timed fuzzing remains terminal-owned (Plan 09-03 Task 3).

const (
	phase9SeedManifestPath   = "testdata/fuzz/phase9-seeds.json"
	phase9SeedManifestSchema = "picocrypt-ng/phase9-fuzz-seeds@1"
	phase9SeedManifestPkg    = "Picocrypt-NG/internal/pcv3"
)

type phase9ManifestTargetSpec struct {
	id      string
	target  string
	control string
}

var phase9ManifestTargetOrder = [...]phase9ManifestTargetSpec{
	{id: "Z01", target: "FuzzReadStructure", control: "TestPhase9ParserFuzzSeedsReachParser"},
	{id: "Z02", target: "FuzzReadNormalRecords", control: "TestPhase9NormalRecordFuzzSeedsReachEvaluator"},
	{id: "Z03", target: "FuzzAuthenticateCapsules", control: "TestPhase9CapsuleFuzzSeedsReachAuthenticator"},
	{id: "Z04", target: "FuzzRecordRSRecovery", control: "TestPhase9RSFuzzSeedsReachBoundedRetry"},
	{id: "Z05", target: "FuzzReadD1Volume", control: "TestD1FuzzSeedsReachProductionSeams"},
	{id: "Z06", target: "FuzzResolveForceRecords", control: "TestPhase9ForceFuzzSeedsReachAnalysis"},
}

type phase9SeedArtifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type phase9SeedExpectation struct {
	Outcome  string           `json:"outcome"`
	Stage    string           `json:"stage"`
	Detail   string           `json:"detail"`
	Counters map[string]int64 `json:"counters"`
}

type phase9SeedEntry struct {
	ID     string                `json:"id"`
	SHA256 string                `json:"sha256"`
	Expect phase9SeedExpectation `json:"expect"`
}

type phase9SeedTarget struct {
	ID        string               `json:"id"`
	Target    string               `json:"target"`
	Control   string               `json:"control"`
	Seam      string               `json:"seam"`
	Artifacts []phase9SeedArtifact `json:"artifacts"`
	Seeds     []phase9SeedEntry    `json:"seeds"`
}

type phase9SeedManifest struct {
	Schema  string             `json:"schema"`
	Package string             `json:"package"`
	Targets []phase9SeedTarget `json:"targets"`
}

func loadPhase9SeedManifest(t testing.TB) phase9SeedManifest {
	t.Helper()
	encoded, err := os.ReadFile(phase9SeedManifestPath)
	if err != nil {
		t.Fatalf("read TEST ONLY Phase 9 seed manifest: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var manifest phase9SeedManifest
	if err := decoder.Decode(&manifest); err != nil {
		t.Fatalf("decode TEST ONLY Phase 9 seed manifest: %v", err)
	}
	if manifest.Schema != phase9SeedManifestSchema || manifest.Package != phase9SeedManifestPkg {
		t.Fatalf(
			"Phase 9 seed manifest identity = %q/%q; want %q/%q",
			manifest.Schema, manifest.Package, phase9SeedManifestSchema, phase9SeedManifestPkg,
		)
	}
	if len(manifest.Targets) != len(phase9ManifestTargetOrder) {
		t.Fatalf("Phase 9 seed manifest targets = %d; want exactly %d", len(manifest.Targets), len(phase9ManifestTargetOrder))
	}
	for index, spec := range phase9ManifestTargetOrder {
		target := manifest.Targets[index]
		if target.ID != spec.id || target.Target != spec.target || target.Control != spec.control {
			t.Fatalf(
				"Phase 9 seed manifest target %d = %q/%q/%q; want %q/%q/%q",
				index, target.ID, target.Target, target.Control, spec.id, spec.target, spec.control,
			)
		}
		if target.Seam == "" {
			t.Fatalf("Phase 9 seed manifest target %q has no claimed production seam", spec.id)
		}
		if len(target.Seeds) == 0 {
			t.Fatalf("Phase 9 seed manifest target %q has an empty seed set", spec.id)
		}
		seenIDs := map[string]bool{}
		seenDigests := map[string]bool{}
		for _, seed := range target.Seeds {
			if len(seed.ID) <= len(spec.id)+2 || seed.ID[:len(spec.id)+2] != spec.id+"-S" {
				t.Fatalf("Phase 9 seed ID %q does not carry the %q prefix", seed.ID, spec.id)
			}
			if seenIDs[seed.ID] {
				t.Fatalf("Phase 9 seed ID %q is duplicated", seed.ID)
			}
			seenIDs[seed.ID] = true
			if !isPhase9HexDigest(seed.SHA256) {
				t.Fatalf("Phase 9 seed %q SHA-256 %q is not a lowercase hex digest", seed.ID, seed.SHA256)
			}
			if seenDigests[seed.SHA256] {
				t.Fatalf("Phase 9 seed %q duplicates another seed digest", seed.ID)
			}
			seenDigests[seed.SHA256] = true
			if seed.Expect.Outcome == "" || seed.Expect.Stage == "" || len(seed.Expect.Counters) == 0 {
				t.Fatalf("Phase 9 seed %q lacks an outcome, stage, or deterministic counters", seed.ID)
			}
			for name, value := range seed.Expect.Counters {
				if name == "" || value < 0 {
					t.Fatalf("Phase 9 seed %q has an invalid counter %q=%d", seed.ID, name, value)
				}
			}
		}
		for _, artifact := range target.Artifacts {
			requirePhase9Artifact(t, spec.id, artifact)
		}
	}
	return manifest
}

func requirePhase9Artifact(t testing.TB, targetID string, artifact phase9SeedArtifact) {
	t.Helper()
	if artifact.Path == "" || !filepath.IsLocal(artifact.Path) {
		t.Fatalf("Phase 9 target %q artifact path %q is not a local relative path", targetID, artifact.Path)
	}
	contents, err := os.ReadFile(filepath.FromSlash(artifact.Path))
	if err != nil {
		t.Fatalf("read Phase 9 target %q artifact %q: %v", targetID, artifact.Path, err)
	}
	if got := phase9SHA256Hex(contents); got != artifact.SHA256 {
		t.Fatalf("Phase 9 target %q artifact %q SHA-256 = %s; want manifest %s", targetID, artifact.Path, got, artifact.SHA256)
	}
}

func isPhase9HexDigest(encoded string) bool {
	if len(encoded) != 2*sha256.Size {
		return false
	}
	for _, value := range encoded {
		if (value < '0' || value > '9') && (value < 'a' || value > 'f') {
			return false
		}
	}
	return true
}

func requirePhase9Target(t testing.TB, manifest phase9SeedManifest, id string) phase9SeedTarget {
	t.Helper()
	for _, target := range manifest.Targets {
		if target.ID == id {
			return target
		}
	}
	t.Fatalf("Phase 9 seed manifest has no %q target", id)
	return phase9SeedTarget{}
}

// phase9SeedIdentity binds one canonical seed ID to the SHA-256 of its
// canonical argument encoding so the manifest hashes arguments, never source.
type phase9SeedIdentity interface {
	phase9Identity() (id string, digest string)
}

func requirePhase9Seeds(t *testing.T, target phase9SeedTarget, seeds []phase9SeedIdentity) {
	t.Helper()
	if len(seeds) != len(target.Seeds) {
		t.Fatalf("Phase 9 target %q canonical seeds = %d; manifest has %d", target.ID, len(seeds), len(target.Seeds))
	}
	failures := 0
	for index, seed := range seeds {
		id, digest := seed.phase9Identity()
		entry := target.Seeds[index]
		if entry.ID != id || entry.SHA256 != digest {
			failures++
			t.Errorf("PHASE9-ACTUAL %s digest=%s (manifest %s/%s)", id, digest, entry.ID, entry.SHA256)
		}
	}
	if failures != 0 {
		t.Fatalf("Phase 9 target %q has %d seed identity mismatches", target.ID, failures)
	}
}

func requirePhase9Expectation(
	t *testing.T,
	seedID string,
	expect phase9SeedExpectation,
	outcome string,
	stage string,
	detail string,
	counters map[string]int64,
) {
	t.Helper()
	if expect.Outcome == outcome && expect.Stage == stage && expect.Detail == detail &&
		slices.Equal(slices.Sorted(maps.Keys(expect.Counters)), slices.Sorted(maps.Keys(counters))) {
		equal := true
		for name, value := range counters {
			if expect.Counters[name] != value {
				equal = false
				break
			}
		}
		if equal {
			return
		}
	}
	t.Fatalf(
		"PHASE9-ACTUAL %s outcome=%s stage=%s detail=%s counters=%s (manifest %s/%s/%s %s)",
		seedID, outcome, stage, detail, phase9FormatCounters(counters),
		expect.Outcome, expect.Stage, expect.Detail, phase9FormatCounters(expect.Counters),
	)
}

func phase9FormatCounters(counters map[string]int64) string {
	encoded := "{"
	for index, name := range slices.Sorted(maps.Keys(counters)) {
		if index != 0 {
			encoded += ","
		}
		encoded += fmt.Sprintf("%q:%d", name, counters[name])
	}
	return encoded + "}"
}

func phase9SHA256Hex(contents []byte) string {
	digest := sha256.Sum256(contents)
	return hex.EncodeToString(digest[:])
}

// phase9SeedDigest hashes the canonical argument encoding: every argument is
// length-prefixed big-endian and concatenated in f.Add order.
func phase9SeedDigest(parts ...[]byte) string {
	digest := sha256.New()
	var length [8]byte
	for _, part := range parts {
		binary.BigEndian.PutUint64(length[:], uint64(len(part)))
		_, _ = digest.Write(length[:])
		_, _ = digest.Write(part)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func phase9Uint8(value uint8) []byte {
	return []byte{value}
}

func phase9Uint32(value uint32) []byte {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	return encoded[:]
}

func phase9Uint64(value uint64) []byte {
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], value)
	return encoded[:]
}

func phase9StageName(stage Stage) string {
	switch stage {
	case StageNone:
		return "none"
	case StageRouting:
		return "routing"
	case StagePreamble:
		return "preamble"
	case StageCapsuleRS:
		return "capsule-rs"
	case StageCapsuleStructure:
		return "capsule-structure"
	case StageTailGeometry:
		return "tail-geometry"
	case StageInputIO:
		return "input-io"
	case StageCredentialPolicy:
		return "credential-policy"
	case StageWrapAuth:
		return "wrap-auth"
	case StageUnwrap:
		return "unwrap"
	case StageReplicaAuth:
		return "replica-auth"
	case StageKDFRuntime:
		return "kdf-runtime"
	case StageCancellation:
		return "cancellation"
	case StageMetadata:
		return "metadata"
	case StageDescriptor:
		return "descriptor"
	case StageRecordBodyRS:
		return "record-body-rs"
	case StageRecordAuth:
		return "record-auth"
	case StageFinalRecord:
		return "final-record"
	case StageOutputWrite:
		return "output-write"
	case StageD1Bootstrap:
		return "d1-bootstrap"
	case StageD1Body:
		return "d1-body"
	case StageInnerVolume:
		return "inner-volume"
	default:
		return "unknown"
	}
}

// phase9XORWord applies one deterministic 8-byte XOR word at offset modulo the
// data length. A zero word is a defined no-op so canonical pristine seeds and
// generated inputs share one code path.
func phase9XORWord(data []byte, offset uint64, word uint64) {
	if len(data) == 0 || word == 0 {
		return
	}
	start := offset % uint64(len(data))
	for index := uint64(0); index < 8 && start+index < uint64(len(data)); index++ {
		data[start+index] ^= byte(word >> (index * 8))
	}
}

// phase9XORWordPayload confines the deterministic XOR word to the canonical
// payload region so capsule admission remains intact and the record evaluator
// is the component under test.
func phase9XORWordPayload(volume []byte, front uint64, payloadLength uint64, offset uint64, word uint64) {
	if payloadLength == 0 || word == 0 {
		return
	}
	start := front + offset%payloadLength
	for index := uint64(0); index < 8 && start+index < front+payloadLength && start+index < uint64(len(volume)); index++ {
		volume[start+index] ^= byte(word >> (index * 8))
	}
}

// phase9PayloadObserver is a bounded ReaderAt wrapper proving the record
// evaluator reads only canonical descriptor/body extents inside the
// authenticated payload geometry. A 48-byte request is a descriptor read; any
// other request is a body read.
type phase9PayloadObserver struct {
	reader          *bytes.Reader
	base            int64
	end             int64
	maxRequest      int
	violation       string
	descriptorReads int64
	bodyReads       int64
}

var errPhase9PayloadReadBound = errors.New("TEST ONLY Phase 9 payload read bound")

func (observer *phase9PayloadObserver) ReadAt(destination []byte, offset int64) (int, error) {
	if offset < 0 || offset < observer.base ||
		int64(len(destination)) > observer.end-offset || len(destination) > observer.maxRequest {
		observer.violation = fmt.Sprintf("read %d bytes at %d outside [%d,%d)", len(destination), offset, observer.base, observer.end)
		return 0, errPhase9PayloadReadBound
	}
	if len(destination) == int(recordDescriptorSize) {
		observer.descriptorReads++
	} else {
		observer.bodyReads++
	}
	return observer.reader.ReadAt(destination, offset)
}

func (observer *phase9PayloadObserver) assertBounded(t *testing.T) {
	t.Helper()
	if observer.violation != "" {
		t.Fatalf("record evaluator escaped its authenticated payload geometry: %s", observer.violation)
	}
}

// phase9RecordSink is the minimal operation-owned counting sink for record
// seams. It retains no plaintext, only the running public-content digest used
// by the independent frozen-plaintext oracle.
type phase9RecordSink struct {
	records int64
	bytes   int64
	digest  hash.Hash
}

func newPhase9RecordSink() *phase9RecordSink {
	return &phase9RecordSink{digest: sha256.New()}
}

func (sink *phase9RecordSink) writeVerifiedRecord(_ context.Context, _ uint64, plaintext []byte) error {
	sink.records++
	sink.bytes += int64(len(plaintext))
	_, _ = sink.digest.Write(plaintext)
	return nil
}

func (sink *phase9RecordSink) sha256Hex() string {
	return hex.EncodeToString(sink.digest.Sum(nil))
}

// phase9RecordStageSet is the closed failure-stage vocabulary of the record
// evaluator seam reachable from an admitted structure with a live context.
func phase9RecordStageSet(stage Stage) bool {
	switch stage {
	case StageDescriptor, StageRecordBodyRS, StageRecordAuth, StageFinalRecord, StageInputIO:
		return true
	default:
		return false
	}
}

// phase9ClassifyRecordCall reduces one readNormalRecords call to its closed
// outcome, stage, and counters for manifest comparison.
func phase9ClassifyRecordCall(
	t *testing.T,
	err error,
	observer *phase9PayloadObserver,
	sink *phase9RecordSink,
) (outcome string, stage string, counters map[string]int64) {
	t.Helper()
	observer.assertBounded(t)
	counters = map[string]int64{
		"body_reads":       observer.bodyReads,
		"descriptor_reads": observer.descriptorReads,
		"sink_bytes":       sink.bytes,
		"sink_records":     sink.records,
	}
	if err == nil {
		return "verified", "none", counters
	}
	var failure *recordFailure
	if !errors.As(err, &failure) || !phase9RecordStageSet(failure.stage) {
		t.Fatalf("record seam error type/stage = %T/%v; want closed *recordFailure stage", err, err)
	}
	return "typed-failure", phase9StageName(failure.stage), counters
}

// --- Z01 FuzzReadStructure: bounded structure/preamble parser control ---

// phase9StructureSeed mirrors one FuzzReadStructure corpus entry. The target
// keeps its existing inline corpus (reader_fuzz_test.go is outside this
// task's files); the control independently rebuilds the same deterministic
// fixture-derived seeds and proves each one reaches the production parser.
type phase9StructureSeed struct {
	id          string
	data        []byte
	claimedSize int64
}

func (seed phase9StructureSeed) phase9Identity() (string, string) {
	return seed.id, phase9SeedDigest(seed.data, phase9Uint64(uint64(seed.claimedSize)))
}

func phase9Z01Seeds(t testing.TB) []phase9SeedIdentity {
	t.Helper()
	fixture, err := os.ReadFile("testdata/schema1-minimal.pcv")
	if err != nil {
		t.Fatalf("read literal fixture: %v", err)
	}
	seeds := []phase9SeedIdentity{
		phase9StructureSeed{
			id:          "Z01-S01",
			data:        append([]byte(nil), fixture...),
			claimedSize: int64(len(fixture)),
		},
		phase9StructureSeed{
			id: "Z01-S02",
			data: append(
				append([]byte(nil), fixture...),
				fixture[len(fixture)-int(fixedSuffixLength):]...,
			),
			claimedSize: int64(len(fixture)) + int64(fixedSuffixLength),
		},
	}
	for index, boundary := range []int{0, 1, 3, 4, 15, 16, 975, 976, 1223, 1224, 2183, 2184, 2231} {
		seeds = append(seeds, phase9StructureSeed{
			id:          fmt.Sprintf("Z01-S%02d", index+3),
			data:        append([]byte(nil), fixture[:boundary]...),
			claimedSize: int64(boundary),
		})
	}
	for index, offset := range []int{int(primaryCapsuleOffset), len(fixture) - int(fixedSuffixLength), len(fixture) - int(trailerLength)} {
		corrupted := append([]byte(nil), fixture...)
		corrupted[offset] ^= 0xff
		seeds = append(seeds, phase9StructureSeed{
			id:          fmt.Sprintf("Z01-S%02d", index+16),
			data:        corrupted,
			claimedSize: int64(len(corrupted)),
		})
	}
	seeds = append(seeds,
		phase9StructureSeed{id: "Z01-S19", data: append([]byte(nil), fixture...), claimedSize: -1},
		phase9StructureSeed{id: "Z01-S20", data: append([]byte(nil), fixture...), claimedSize: int64(^uint64(0) >> 1)},
	)
	return seeds
}

func TestPhase9ParserFuzzSeedsReachParser(t *testing.T) {
	manifest := loadPhase9SeedManifest(t)
	entry := requirePhase9Target(t, manifest, "Z01")
	seeds := phase9Z01Seeds(t)
	requirePhase9Seeds(t, entry, seeds)

	for index := range seeds {
		canonical := seeds[index].(phase9StructureSeed)
		expect := entry.Seeds[index].Expect
		t.Run(canonical.id, func(t *testing.T) {
			outcome, stage, counters := runPhase9StructureCase(t, canonical)
			requirePhase9Expectation(t, canonical.id, expect, outcome, stage, "", counters)
		})
	}

	// The retained D1 control (TestD1FuzzSeedsReachProductionSeams) owns Z05
	// behavioral reach and lives outside this task's editable files, so the
	// Z01 control additionally binds the Z05 seed identities: the manifest
	// digests must equal the canonical encoding of the exact FuzzReadD1Volume
	// f.Add arguments.
	t.Run("Z05-seed-binding", func(t *testing.T) {
		z05 := requirePhase9Target(t, manifest, "Z05")
		z05Seeds := make([]phase9SeedIdentity, 0, len(d1ReaderFuzzSeeds))
		for index, seed := range d1ReaderFuzzSeeds {
			z05Seeds = append(z05Seeds, phase9D1Seed{
				id:        fmt.Sprintf("Z05-S%02d", index+1),
				payload:   seed.payload,
				mode:      uint8(seed.mode),
				parameter: seed.parameter,
			})
		}
		requirePhase9Seeds(t, z05, z05Seeds)
	})
}

// phase9D1Seed binds one FuzzReadD1Volume corpus entry to its canonical
// digest. Behavioral oracles stay with the retained D1 seed control.
type phase9D1Seed struct {
	id        string
	payload   []byte
	mode      uint8
	parameter uint64
}

func (seed phase9D1Seed) phase9Identity() (string, string) {
	return seed.id, phase9SeedDigest(seed.payload, phase9Uint8(seed.mode), phase9Uint64(seed.parameter))
}

// runPhase9StructureCase executes the production Probe parser on one seed and
// reduces it to its closed route/stage/counter observation. The checks mirror
// the FuzzReadStructure body invariants so the control fails if the target
// returns early, uses a shadow parser, or retains invalid candidates.
func runPhase9StructureCase(
	t *testing.T,
	seed phase9StructureSeed,
) (outcome string, stage string, counters map[string]int64) {
	t.Helper()
	source := &fuzzReaderAt{reader: bytes.NewReader(seed.data)}
	route, structure, probeErr := Probe(source, seed.claimedSize)
	if probeErr != nil {
		var failure Failure
		if !errors.As(probeErr, &failure) {
			t.Fatalf("Probe() error type = %T; want closed pcv3.Failure", probeErr)
		}
	}
	if route == RouteLegacyEligible && structure.CandidateCount() != 0 {
		t.Fatalf("legacy-eligible input retained %d PCV3 candidates", structure.CandidateCount())
	}
	if route == RouteNormalPCV && structure.observedSize != seed.claimedSize {
		t.Fatalf("Structure observed size = %d; want exact claimed size %d", structure.observedSize, seed.claimedSize)
	}
	if structure.CandidateCount() > 2 {
		t.Fatalf("CandidateCount() = %d; fixed bound is 2", structure.CandidateCount())
	}
	seen := [2]bool{}
	for index := range structure.CandidateCount() {
		candidate, ok := structure.CandidateAt(index)
		if !ok || candidate.Role() > CapsuleRoleBackup || seen[candidate.Role()] {
			t.Fatalf("CandidateAt(%d) has invalid or repeated role %v", index, candidate.Role())
		}
		seen[candidate.Role()] = true
		geometry, ok := structure.GeometryAt(index)
		if !ok || geometry.FileSize() < 0 {
			t.Fatalf("candidate %d retained without host-safe canonical geometry", index)
		}
		canonical, deriveErr := DeriveGeometry(candidate, uint64(geometry.FileSize()))
		if deriveErr != nil || canonical != geometry {
			t.Fatalf("candidate %d retained without self-consistent canonical geometry", index)
		}
		if candidate.Role() == CapsuleRoleBackup && geometry.FileSize() != seed.claimedSize {
			t.Fatalf("EOF-relative backup retained without exact observed geometry")
		}
	}
	for _, component := range []Component{ComponentPrimary, ComponentTrailer, ComponentBackup} {
		if issueStage, ok := structure.Issue(component); ok && !isReaderStructuralIssueStage(issueStage) {
			t.Fatalf("Issue(%v) stage = %v; want structural component stage", component, issueStage)
		}
	}
	if source.calls > 5 || source.maxRequest > int(backupCapsuleLength) {
		t.Fatalf("ReaderAt budget = %d calls, max request %d; want <=5 and <=%d", source.calls, source.maxRequest, backupCapsuleLength)
	}
	assertFuzzRequestsDoNotOverlap(t, source.requests)

	counters = map[string]int64{
		"candidates":  int64(structure.CandidateCount()),
		"max_request": int64(source.maxRequest),
		"read_calls":  int64(source.calls),
	}
	if probeErr != nil {
		var failure Failure
		if !errors.As(probeErr, &failure) || failure.Outcome() != OutcomeInvalidStructurePreKDF {
			t.Fatalf("Probe() failure = %v; want invalid-structure classification", probeErr)
		}
		return "invalid-structure", phase9StageName(failure.Stage()), counters
	}
	if route == RouteNormalPCV {
		return "normal-route", "none", counters
	}
	if route != RouteLegacyEligible {
		t.Fatalf("Probe() route = %v without error; want normal or legacy classification", route)
	}
	return "legacy-route", "none", counters
}

// --- Z02 FuzzReadNormalRecords: admitted-structure record evaluator ---

var phase9NormalRecordFixtureIDs = [...]string{
	"normal-standard-password-only-small",
	"normal-standard-combined-unordered-rs-small",
	"normal-paranoid-combined-unordered-rs-small",
}

// phase9PreparedNormalVolume is one frozen public volume admitted once
// through production Probe. Z02 starts every iteration from this admitted
// structure instead of re-probing mutated bytes, so canonical seeds always
// reach the record evaluator.
type phase9PreparedNormalVolume struct {
	fixture   normalFixture
	volume    []byte
	structure Structure
}

func preparePhase9NormalVolume(t testing.TB, id string) *phase9PreparedNormalVolume {
	t.Helper()
	fixture := loadNormalFixtureManifest(t).FixturesByID()[id]
	if fixture.ID != id {
		t.Fatalf("required TEST ONLY normal fixture %q is absent", id)
	}
	volume := readNormalFixtureArtifact(t, fixture.Volume)
	route, structure, err := Probe(bytes.NewReader(volume), int64(len(volume)))
	if err != nil || route != RouteNormalPCV {
		t.Fatalf("Probe(%s) = %v, %v; want normal PCV admission", id, route, err)
	}
	return &phase9PreparedNormalVolume{fixture: fixture, volume: volume, structure: structure}
}

func (prepared *phase9PreparedNormalVolume) payloadGeometry(t testing.TB) (front uint64, payloadLength uint64) {
	t.Helper()
	geometry, ok := prepared.structure.GeometryAt(0)
	if !ok || geometry.FrontHeaderLength() < 0 || geometry.BackupCapsuleOffset() < geometry.FrontHeaderLength() {
		t.Fatalf("fixture %q lacks canonical payload geometry", prepared.fixture.ID)
	}
	return uint64(geometry.FrontHeaderLength()), uint64(geometry.BackupCapsuleOffset() - geometry.FrontHeaderLength())
}

// phase9NormalRecordSeed is one compact Z02 selector tuple. The multi-byte
// frozen volumes stay outside the fuzz arguments; the manifest binds the
// artifact hashes and these argument digests.
type phase9NormalRecordSeed struct {
	id             string
	volumeSelector uint32
	mode           uint8
	firstOffset    uint64
	firstXOR       uint64
	secondOffset   uint64
	secondXOR      uint64
}

func (seed phase9NormalRecordSeed) phase9Identity() (string, string) {
	return seed.id, phase9SeedDigest(
		phase9Uint32(seed.volumeSelector),
		phase9Uint8(seed.mode),
		phase9Uint64(seed.firstOffset),
		phase9Uint64(seed.firstXOR),
		phase9Uint64(seed.secondOffset),
		phase9Uint64(seed.secondXOR),
	)
}

func phase9Z02Seeds() []phase9SeedIdentity {
	// Per fixture: pristine, one 8-byte payload word inside the first record
	// body, and one truncation inside the first record descriptor.
	seeds := make([]phase9SeedIdentity, 0, 3*len(phase9NormalRecordFixtureIDs))
	for index := range phase9NormalRecordFixtureIDs {
		selector := uint32(index)
		base := len(seeds)
		seeds = append(seeds,
			phase9NormalRecordSeed{
				id: fmt.Sprintf("Z02-S%02d", base+1), volumeSelector: selector, mode: 0,
			},
			phase9NormalRecordSeed{
				id: fmt.Sprintf("Z02-S%02d", base+2), volumeSelector: selector, mode: 0,
				firstOffset: 108, firstXOR: 0x0102030405060708,
			},
			phase9NormalRecordSeed{
				id: fmt.Sprintf("Z02-S%02d", base+3), volumeSelector: selector, mode: 1,
				firstOffset: 30,
			},
		)
	}
	return seeds
}

// FuzzReadNormalRecords explores the actual record evaluator starting from
// admitted frozen structures. Mutations are confined to the canonical payload
// region so capsule admission holds and every canonical seed reaches record
// authentication; no-panic is never the oracle.
func FuzzReadNormalRecords(f *testing.F) {
	prepared := make([]*phase9PreparedNormalVolume, 0, len(phase9NormalRecordFixtureIDs))
	for _, id := range phase9NormalRecordFixtureIDs {
		prepared = append(prepared, preparePhase9NormalVolume(f, id))
	}
	for _, seed := range phase9Z02Seeds() {
		canonical := seed.(phase9NormalRecordSeed)
		f.Add(
			canonical.volumeSelector,
			canonical.mode,
			canonical.firstOffset,
			canonical.firstXOR,
			canonical.secondOffset,
			canonical.secondXOR,
		)
	}

	f.Fuzz(func(
		t *testing.T,
		volumeSelector uint32,
		mode uint8,
		firstOffset uint64,
		firstXOR uint64,
		secondOffset uint64,
		secondXOR uint64,
	) {
		runPhase9NormalRecordCase(
			t,
			prepared[uint64(volumeSelector)%uint64(len(prepared))],
			mode,
			firstOffset,
			firstXOR,
			secondOffset,
			secondXOR,
			"",
			nil,
		)
	})
}

func TestPhase9NormalRecordFuzzSeedsReachEvaluator(t *testing.T) {
	manifest := loadPhase9SeedManifest(t)
	entry := requirePhase9Target(t, manifest, "Z02")
	prepared := make([]*phase9PreparedNormalVolume, 0, len(phase9NormalRecordFixtureIDs))
	for _, id := range phase9NormalRecordFixtureIDs {
		prepared = append(prepared, preparePhase9NormalVolume(t, id))
	}
	seeds := phase9Z02Seeds()
	requirePhase9Seeds(t, entry, seeds)

	for index := range seeds {
		canonical := seeds[index].(phase9NormalRecordSeed)
		expect := entry.Seeds[index].Expect
		t.Run(canonical.id, func(t *testing.T) {
			runPhase9NormalRecordCase(
				t,
				prepared[uint64(canonical.volumeSelector)%uint64(len(prepared))],
				canonical.mode,
				canonical.firstOffset,
				canonical.firstXOR,
				canonical.secondOffset,
				canonical.secondXOR,
				canonical.id,
				&expect,
			)
		})
	}
}

// runPhase9NormalRecordCase drives the production record evaluator from the
// admitted frozen structure with the fixture's frozen public keys, then checks
// the closed record-seam invariants. The evaluator reach counters (descriptor
// and body reads) prove the seeds never stop after probe.
func runPhase9NormalRecordCase(
	t *testing.T,
	prepared *phase9PreparedNormalVolume,
	mode uint8,
	firstOffset uint64,
	firstXOR uint64,
	secondOffset uint64,
	secondXOR uint64,
	seedID string,
	expect *phase9SeedExpectation,
) {
	t.Helper()
	front, payloadLength := prepared.payloadGeometry(t)
	volume := bytes.Clone(prepared.volume)
	switch mode % 3 {
	case 1:
		keep := firstOffset % (payloadLength + 1)
		volume = volume[:front+keep]
	case 2:
		volume = append(volume, make([]byte, firstOffset%512)...)
		phase9XORWordPayload(volume, front, payloadLength, firstOffset, firstXOR)
		phase9XORWordPayload(volume, front, payloadLength, secondOffset, secondXOR)
	default:
		phase9XORWordPayload(volume, front, payloadLength, firstOffset, firstXOR)
		phase9XORWordPayload(volume, front, payloadLength, secondOffset, secondXOR)
	}

	// Real capsule authentication on the admitted structure with the frozen
	// public fixture keys. The payload-confined mutations cannot disturb it;
	// a failure here means the admitted-structure precondition broke.
	provider := newNormalFixtureCredentialProvider(t, prepared.fixture.Keys)
	auth := authenticateCapsulesBorrowingProvider(
		context.Background(),
		prepared.structure,
		provider,
		defaultCapsuleAuthSeams(),
	)
	if auth == nil {
		t.Fatal("admitted-structure capsule authentication returned no typed result")
	}
	defer auth.Close()
	defer provider.close()
	if auth.outcome != OutcomeSuccess && auth.outcome != OutcomeAuthenticatedDegraded {
		t.Fatalf("admitted-structure capsule authentication = %v/%v; want success", auth.outcome, auth.stage)
	}
	candidate, ok := prepared.structure.CandidateAt(0)
	if !ok {
		t.Fatal("admitted structure lost its primary candidate")
	}

	maximumRequest, ok := encodedRecordBodyLength(recordPlaintextMax, true)
	if !ok || maximumRequest > uint64(math.MaxInt) {
		t.Fatal("derive TEST ONLY record-body request bound")
	}
	observer := &phase9PayloadObserver{
		reader:     bytes.NewReader(volume),
		base:       int64(front),
		end:        int64(front + payloadLength),
		maxRequest: int(maximumRequest),
	}
	sink := newPhase9RecordSink()
	codecs, err := pcencoding.NewRSCodecs()
	if err != nil {
		t.Fatalf("NewRSCodecs: %v", err)
	}
	verified, err := readNormalRecords(context.Background(), observer, auth, codecs, sink)
	outcome, stage, counters := phase9ClassifyRecordCall(t, err, observer, sink)

	recordCount := int64(candidate.RecordCount())
	plaintextLength := int64(candidate.PlaintextLength())
	maxReads := 2 * (recordCount + 1)
	if observer.descriptorReads+observer.bodyReads > maxReads {
		t.Fatalf("record evaluator reads = %d; canonical bound is %d", observer.descriptorReads+observer.bodyReads, maxReads)
	}
	if sink.records > recordCount || sink.bytes > plaintextLength {
		t.Fatalf("sink retained records/bytes %d/%d beyond canonical %d/%d", sink.records, sink.bytes, recordCount, plaintextLength)
	}
	if err == nil {
		if verified.dataRecords != uint64(recordCount) || verified.plaintextBytes != uint64(plaintextLength) {
			t.Fatalf("successful record verification = %+v; want exact %d/%d accounting", verified, recordCount, plaintextLength)
		}
		if observer.descriptorReads != recordCount+1 || observer.bodyReads != recordCount+1 {
			t.Fatalf(
				"successful record reads = %d descriptors/%d bodies; want exactly %d each",
				observer.descriptorReads, observer.bodyReads, recordCount+1,
			)
		}
		if sink.records != recordCount || sink.bytes != plaintextLength {
			t.Fatalf("successful sink = %d records/%d bytes; want %d/%d", sink.records, sink.bytes, recordCount, plaintextLength)
		}
		if got := sink.sha256Hex(); got != prepared.fixture.Plaintext.SHA256 {
			t.Fatalf("verified plaintext SHA-256 = %s; want frozen public fixture %s", got, prepared.fixture.Plaintext.SHA256)
		}
	} else {
		if verified != (recordVerification{}) {
			t.Fatalf("failed record read returned verification %+v", verified)
		}
		if sink.records == recordCount && sink.bytes == plaintextLength && stage != "final-record" {
			t.Fatalf("full data emission without completion closed at %q; want final-record", stage)
		}
	}
	if expect != nil {
		requirePhase9Expectation(t, seedID, *expect, outcome, stage, "", counters)
	}
}
