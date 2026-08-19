package pcv3

import (
	pcencoding "Picocrypt-NG/internal/encoding"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// Z04 FuzzRecordRSRecovery: bounded Reed-Solomon retry followed by record
// authentication. Frozen public RS mutation payloads are the seed bases; the
// counting seam wrappers only observe the production decode/decrypt functions
// so retry counts and the fast/full-correction source choice stay observable.
// No-panic is never the oracle.

// phase9RSBaseFiles are the frozen public payload bases under
// testdata/records/mutations. Order is manifest-significant.
var phase9RSBaseFiles = [...]string{
	"retry_base.bin",
	"body_repair_4.bin",
	"body_damage_9.bin",
	"body_bad_tag_reencoded.bin",
	"body_bad_padding_reencoded.bin",
	"bad_final_tag_reencoded.bin",
	"descriptor_repair_16.bin",
	"descriptor_damage_33.bin",
	"missing_final.bin",
}

// phase9RSSeed is one compact Z04 selector tuple: a frozen base payload plus
// two optional 8-byte XOR words. The frozen bases stay outside the fuzz
// arguments; the manifest binds their artifact hashes.
type phase9RSSeed struct {
	id           string
	baseSelector uint8
	offset       uint64
	word         uint64
	secondOffset uint64
	secondWord   uint64
}

func (seed phase9RSSeed) phase9Identity() (string, string) {
	return seed.id, phase9SeedDigest(
		phase9Uint8(seed.baseSelector),
		phase9Uint64(seed.offset),
		phase9Uint64(seed.word),
		phase9Uint64(seed.secondOffset),
		phase9Uint64(seed.secondWord),
	)
}

func phase9Z04Seeds() []phase9SeedIdentity {
	seeds := make([]phase9SeedIdentity, 0, len(phase9RSBaseFiles))
	for index := range phase9RSBaseFiles {
		seeds = append(seeds, phase9RSSeed{
			id:           fmt.Sprintf("Z04-S%02d", index+1),
			baseSelector: uint8(index),
		})
	}
	return seeds
}

// phase9RSSeamObserver counts production decode/decrypt invocations. The
// wrappers delegate to the production functions; only observation is added.
type phase9RSSeamObserver struct {
	descriptorDecodes int64
	fastBodyDecodes   int64
	fullBodyDecodes   int64
	decryptCalls      int64
	bodyOrder         []bool
}

func (observer *phase9RSSeamObserver) seams() recordEngineSeams {
	seams := defaultRecordEngineSeams()
	realDescriptor := seams.decodeDescriptor
	seams.decodeDescriptor = func(codecs *pcencoding.RSCodecs, encoded []byte, destination []byte) error {
		observer.descriptorDecodes++
		return realDescriptor(codecs, encoded, destination)
	}
	realBody := seams.decodeBody
	seams.decodeBody = func(codecs *pcencoding.RSCodecs, encoded []byte, destination []byte, fullCorrection bool) error {
		observer.bodyOrder = append(observer.bodyOrder, fullCorrection)
		if fullCorrection {
			observer.fullBodyDecodes++
		} else {
			observer.fastBodyDecodes++
		}
		return realBody(codecs, encoded, destination, fullCorrection)
	}
	realStandard := seams.decryptStandard
	seams.decryptStandard = func(destination, source, key, nonce []byte) error {
		observer.decryptCalls++
		return realStandard(destination, source, key, nonce)
	}
	realParanoid := seams.decryptParanoid
	seams.decryptParanoid = func(destination, source, xKey, nonce, serpentKey, iv []byte) error {
		observer.decryptCalls++
		return realParanoid(destination, source, xKey, nonce, serpentKey, iv)
	}
	return seams
}

// FuzzRecordRSRecovery explores the bounded RS retry and subsequent record
// authentication path on the frozen public RS record fixture. Bounded retry,
// authentication after every decode, and no unverified emission are the
// oracles.
func FuzzRecordRSRecovery(f *testing.F) {
	fixture := phase9RecordFixtureCase(f, "retry_standard_rs")
	bases := make([][]byte, 0, len(phase9RSBaseFiles))
	for _, name := range phase9RSBaseFiles {
		bases = append(bases, phase9RecordMutationFile(f, name))
	}
	for _, seed := range phase9Z04Seeds() {
		canonical := seed.(phase9RSSeed)
		f.Add(
			canonical.baseSelector,
			canonical.offset,
			canonical.word,
			canonical.secondOffset,
			canonical.secondWord,
		)
	}

	f.Fuzz(func(
		t *testing.T,
		baseSelector uint8,
		offset uint64,
		word uint64,
		secondOffset uint64,
		secondWord uint64,
	) {
		runPhase9RSCase(t, fixture, bases, baseSelector, offset, word, secondOffset, secondWord, "", nil)
	})
}

func TestPhase9RSFuzzSeedsReachBoundedRetry(t *testing.T) {
	manifest := loadPhase9SeedManifest(t)
	entry := requirePhase9Target(t, manifest, "Z04")
	fixture := phase9RecordFixtureCase(t, "retry_standard_rs")
	bases := make([][]byte, 0, len(phase9RSBaseFiles))
	for _, name := range phase9RSBaseFiles {
		bases = append(bases, phase9RecordMutationFile(t, name))
	}
	seeds := phase9Z04Seeds()
	requirePhase9Seeds(t, entry, seeds)

	for index := range seeds {
		canonical := seeds[index].(phase9RSSeed)
		expect := entry.Seeds[index].Expect
		t.Run(canonical.id, func(t *testing.T) {
			runPhase9RSCase(
				t,
				fixture,
				bases,
				canonical.baseSelector,
				canonical.offset,
				canonical.word,
				canonical.secondOffset,
				canonical.secondWord,
				canonical.id,
				&expect,
			)
		})
	}
}

// phase9RecordFixtureCase loads one frozen public record fixture case for
// both fuzz setup (testing.F) and controls (testing.T); the record test
// helpers accept only *testing.T.
func phase9RecordFixtureCase(t testing.TB, name string) recordFixtureCase {
	t.Helper()
	contents, err := os.ReadFile("testdata/records/manifest.json")
	if err != nil {
		t.Fatalf("read TEST ONLY record manifest: %v", err)
	}
	var manifest recordFixtureManifest
	if err := json.Unmarshal(contents, &manifest); err != nil {
		t.Fatalf("decode TEST ONLY record manifest: %v", err)
	}
	for _, fixture := range manifest.Cases {
		if fixture.Name == name {
			return fixture
		}
	}
	t.Fatalf("required TEST ONLY record fixture %q is absent", name)
	return recordFixtureCase{}
}

func phase9RecordMutationFile(t testing.TB, name string) []byte {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join("testdata/records/mutations", name))
	if err != nil {
		t.Fatalf("read TEST ONLY record mutation %q: %v", name, err)
	}
	return contents
}

// runPhase9RSCase drives the production record evaluator over one mutated
// frozen payload with the frozen public keys and checks the bounded-retry and
// authentication invariants.
func runPhase9RSCase(
	t *testing.T,
	fixture recordFixtureCase,
	bases [][]byte,
	baseSelector uint8,
	offset uint64,
	word uint64,
	secondOffset uint64,
	secondWord uint64,
	seedID string,
	expect *phase9SeedExpectation,
) {
	t.Helper()
	payload := bytes.Clone(bases[uint64(baseSelector)%uint64(len(bases))])
	phase9XORWord(payload, offset, word)
	phase9XORWord(payload, secondOffset, secondWord)

	auth, borrower := recordFixtureAuthority(t, fixture)
	defer borrower.close()
	defer auth.Close()
	observer := &phase9RSSeamObserver{}
	sink := &recordCollectingSink{}
	reader := &recordTrackingReader{base: int64(fixture.FrontHeaderLength), data: payload}
	verified, err := readNormalRecordsWithSeams(
		context.Background(),
		reader,
		auth,
		recordTestCodecs(t),
		sink,
		observer.seams(),
	)

	requireRecordKeyBorrows(t, borrower, Suite(fixture.Suite))
	assertRecordReadBounds(t, reader, fixture)
	sink.assertBorrowsCleared(t)
	if observer.descriptorDecodes < 1 {
		t.Fatal("record evaluator never decoded a descriptor; seed did not reach the seam")
	}
	if observer.fullBodyDecodes > observer.fastBodyDecodes {
		t.Fatalf("full RS correction passes = %d exceed fast passes = %d; retry is bounded", observer.fullBodyDecodes, observer.fastBodyDecodes)
	}
	for index, full := range observer.bodyOrder {
		if full && (index == 0 || observer.bodyOrder[index-1]) {
			t.Fatalf("full RS correction pass %d did not immediately follow a fast pass: %v", index, observer.bodyOrder)
		}
	}
	if observer.decryptCalls > int64(fixture.RecordCount) {
		t.Fatalf("decrypt calls = %d; canonical data-record bound is %d", observer.decryptCalls, fixture.RecordCount)
	}
	if (observer.decryptCalls == 0) != (len(sink.indexes) == 0) {
		t.Fatalf("decrypt calls = %d but sink emissions = %d; unauthenticated emission or suppressed verified record", observer.decryptCalls, len(sink.indexes))
	}

	detail := "none"
	if err == nil {
		if verified.dataRecords != fixture.RecordCount || verified.plaintextBytes != fixture.PlaintextLength {
			t.Fatalf("successful RS record verification = %+v; want exact %d/%d", verified, fixture.RecordCount, fixture.PlaintextLength)
		}
		if want := recordFixturePlaintext(t, fixture); !bytes.Equal(sink.copied, want) {
			t.Fatal("verified plaintext differs from the independent frozen public fixture")
		}
		if observer.fullBodyDecodes == 0 {
			detail = "fast"
		} else {
			detail = "full-correction"
		}
	} else {
		var failure *recordFailure
		if !errors.As(err, &failure) || !phase9RecordStageSet(failure.stage) {
			t.Fatalf("RS record error type/stage = %T/%v; want closed *recordFailure stage", err, err)
		}
		if verified != (recordVerification{}) {
			t.Fatalf("failed RS record read returned verification %+v", verified)
		}
	}
	if expect != nil {
		outcome := "typed-failure"
		stage := "none"
		if err == nil {
			outcome = "verified"
		} else {
			var failure *recordFailure
			if errors.As(err, &failure) {
				stage = phase9StageName(failure.stage)
			}
		}
		counters := map[string]int64{
			"decrypt_calls":      observer.decryptCalls,
			"descriptor_decodes": observer.descriptorDecodes,
			"fast_body_decodes":  observer.fastBodyDecodes,
			"full_body_decodes":  observer.fullBodyDecodes,
			"sink_records":       int64(len(sink.indexes)),
		}
		requirePhase9Expectation(t, seedID, *expect, outcome, stage, detail, counters)
	}
}
