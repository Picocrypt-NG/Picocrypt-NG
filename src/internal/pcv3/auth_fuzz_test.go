package pcv3

import (
	"context"
	"fmt"
	"testing"
)

// Z03 FuzzAuthenticateCapsules: real capsule authentication and credential
// policy binding with frozen public fixture keys. Mutations act on the
// admitted in-memory structure (capsule fields, credential tuple, preamble),
// so every canonical seed reaches the production authenticator instead of
// being filtered out by probe. Counting wrappers only observe; the fixture
// credential provider, MAC verification, and unwrap seams stay production.

var phase9CapsuleFixtureIDs = [...]string{
	"normal-standard-password-only-small",
	"normal-paranoid-combined-unordered-rs-small",
}

// phase9CapsuleSeed is one compact Z03 selector tuple. The frozen volume and
// keys stay outside the fuzz arguments; the manifest binds their hashes.
type phase9CapsuleSeed struct {
	id                string
	fixtureSelector   uint32
	mode              uint8
	candidateSelector uint8
	offset            uint64
	word              uint64
}

func (seed phase9CapsuleSeed) phase9Identity() (string, string) {
	return seed.id, phase9SeedDigest(
		phase9Uint32(seed.fixtureSelector),
		phase9Uint8(seed.mode),
		phase9Uint8(seed.candidateSelector),
		phase9Uint64(seed.offset),
		phase9Uint64(seed.word),
	)
}

// Z03 mutation modes. Mode 0 is pristine; modes 1-3 tamper authenticated
// capsule bytes; mode 2 additionally re-signs the mutated replica tag with the
// public fixture wrap key so wrap auth passes and replica authentication is
// the seam under test; modes 5-7 bind credential/KDF/preamble policy.
const (
	phase9CapsulePristine uint8 = iota
	phase9CapsuleWrapTag
	phase9CapsuleReplicaTagResigned
	phase9CapsuleWrappedKey
	phase9CapsuleArgonSalt
	phase9CapsuleCredentialMode
	phase9CapsuleKDFProfile
	phase9CapsulePreambleFlags
)

func phase9Z03Seeds() []phase9SeedIdentity {
	// Per fixture: pristine, primary wrap tag, both wrap tags, resigned
	// primary replica tag, primary wrapped VolumeKey, argon salt on both
	// capsules, credential-mode policy, KDF-profile policy, preamble flags.
	type mutation struct {
		mode     uint8
		selector uint8
		word     uint64
	}
	mutations := [...]mutation{
		{mode: phase9CapsulePristine},
		{mode: phase9CapsuleWrapTag, selector: 0, word: 0xa5},
		{mode: phase9CapsuleWrapTag, selector: 2, word: 0xa5},
		{mode: phase9CapsuleReplicaTagResigned, selector: 0, word: 0xa5},
		{mode: phase9CapsuleWrappedKey, selector: 0, word: 0xa5},
		{mode: phase9CapsuleArgonSalt, selector: 2, word: 0xa5},
		{mode: phase9CapsuleCredentialMode, selector: 0, word: 0x02},
		{mode: phase9CapsuleKDFProfile, selector: 0, word: 0x01},
		{mode: phase9CapsulePreambleFlags, word: 0x01},
	}
	seeds := make([]phase9SeedIdentity, 0, len(mutations)*len(phase9CapsuleFixtureIDs))
	for index := range phase9CapsuleFixtureIDs {
		for _, mutation := range mutations {
			seeds = append(seeds, phase9CapsuleSeed{
				id:                fmt.Sprintf("Z03-S%02d", len(seeds)+1),
				fixtureSelector:   uint32(index),
				mode:              mutation.mode,
				candidateSelector: mutation.selector,
				word:              mutation.word,
			})
		}
	}
	return seeds
}

// FuzzAuthenticateCapsules explores capsule authentication and credential
// policy binding over admitted structures with fixed public keys. Every
// canonical seed reaches the production authenticator; typed outcomes, exact
// callback bounds, and no-authority-on-failure are the oracles.
func FuzzAuthenticateCapsules(f *testing.F) {
	prepared := make([]*phase9PreparedNormalVolume, 0, len(phase9CapsuleFixtureIDs))
	for _, id := range phase9CapsuleFixtureIDs {
		prepared = append(prepared, preparePhase9NormalVolume(f, id))
	}
	for _, seed := range phase9Z03Seeds() {
		canonical := seed.(phase9CapsuleSeed)
		f.Add(
			canonical.fixtureSelector,
			canonical.mode,
			canonical.candidateSelector,
			uint64(0),
			canonical.word,
		)
	}

	f.Fuzz(func(
		t *testing.T,
		fixtureSelector uint32,
		mode uint8,
		candidateSelector uint8,
		offset uint64,
		word uint64,
	) {
		runPhase9CapsuleCase(
			t,
			prepared[uint64(fixtureSelector)%uint64(len(prepared))],
			mode,
			candidateSelector,
			offset,
			word,
			"",
			nil,
		)
	})
}

func TestPhase9CapsuleFuzzSeedsReachAuthenticator(t *testing.T) {
	manifest := loadPhase9SeedManifest(t)
	entry := requirePhase9Target(t, manifest, "Z03")
	prepared := make([]*phase9PreparedNormalVolume, 0, len(phase9CapsuleFixtureIDs))
	for _, id := range phase9CapsuleFixtureIDs {
		prepared = append(prepared, preparePhase9NormalVolume(t, id))
	}
	seeds := phase9Z03Seeds()
	requirePhase9Seeds(t, entry, seeds)

	for index := range seeds {
		canonical := seeds[index].(phase9CapsuleSeed)
		expect := entry.Seeds[index].Expect
		t.Run(canonical.id, func(t *testing.T) {
			runPhase9CapsuleCase(
				t,
				prepared[uint64(canonical.fixtureSelector)%uint64(len(prepared))],
				canonical.mode,
				canonical.candidateSelector,
				uint64(0),
				canonical.word,
				canonical.id,
				&expect,
			)
		})
	}
}

// phase9CountingCredentialProvider observes the production capsule engine's
// credential-policy binding without replacing the fixture credential provider.
type phase9CountingCredentialProvider struct {
	inner           *normalFixtureCredentialProvider
	access          *phase9CountingCredentialAccess
	credentialCalls int64
	tuple           credentialTuple
	tupleSeen       bool
	closeCalls      int64
}

func (provider *phase9CountingCredentialProvider) withCredential(
	ctx context.Context,
	tuple credentialTuple,
	callback func(capsuleCredentialAccess) error,
) error {
	provider.credentialCalls++
	provider.tuple = tuple
	provider.tupleSeen = true
	return provider.inner.withCredential(ctx, tuple, func(access capsuleCredentialAccess) error {
		wrapped := &phase9CountingCredentialAccess{inner: access}
		provider.access = wrapped
		return callback(wrapped)
	})
}

func (provider *phase9CountingCredentialProvider) close() {
	provider.closeCalls++
	provider.inner.close()
}

// phase9CountingCredentialAccess counts wrap/replica/adoption callbacks. All
// cryptographic work remains in the fixture access and production MAC/unwrap
// functions.
type phase9CountingCredentialAccess struct {
	inner        capsuleCredentialAccess
	wrapCalls    int64
	replicaCalls int64
	adoptCalls   int64
}

func (access *phase9CountingCredentialAccess) withWrapKeys(
	role CapsuleRole,
	callback func(*capsuleWrapKeys) error,
) error {
	access.wrapCalls++
	return access.inner.withWrapKeys(role, callback)
}

func (access *phase9CountingCredentialAccess) withReplicaKey(
	role CapsuleRole,
	volumeKey []byte,
	callback func([]byte) error,
) error {
	access.replicaCalls++
	return access.inner.withReplicaKey(role, volumeKey, callback)
}

func (access *phase9CountingCredentialAccess) adoptVolumeKey(volumeKey []byte) error {
	access.adoptCalls++
	return access.inner.adoptVolumeKey(volumeKey)
}

// applyPhase9CapsuleMutation derives the mutated admitted structure for one
// Z03 case. candidateSelector % 3 selects the first candidate, the last
// candidate, or all candidates; a zero word is a defined no-op.
func applyPhase9CapsuleMutation(
	structure Structure,
	mode uint8,
	candidateSelector uint8,
	offset uint64,
	word uint64,
	provider *normalFixtureCredentialProvider,
) Structure {
	mutated := structure
	count := int(mutated.candidateCount)
	indexes := make([]int, 0, count)
	switch candidateSelector % 3 {
	case 0:
		indexes = append(indexes, 0)
	case 1:
		indexes = append(indexes, count-1)
	default:
		for index := 0; index < count; index++ {
			indexes = append(indexes, index)
		}
	}
	switch mode % 8 {
	case phase9CapsuleWrapTag:
		for _, index := range indexes {
			phase9XORWord(mutated.candidates[index].wrapTag[:], offset, word)
		}
	case phase9CapsuleReplicaTagResigned:
		for _, index := range indexes {
			candidate := &mutated.candidates[index]
			phase9XORWord(candidate.replicaTag[:], offset, word)
			// Re-sign only the wrap tag with the public fixture wrap MAC key so
			// wrap auth passes and replica authentication decides the outcome.
			tag, err := suiteMACTag(
				candidate.core.suite,
				provider.access.wrap[candidate.Role()].mac[:],
				wrapAuthMessage(*candidate),
			)
			if err == nil {
				copy(candidate.wrapTag[:], tag[:])
			}
		}
	case phase9CapsuleWrappedKey:
		for _, index := range indexes {
			phase9XORWord(mutated.candidates[index].wrappedVolumeKey[:], offset, word)
		}
	case phase9CapsuleArgonSalt:
		for index := 0; index < count; index++ {
			phase9XORWord(mutated.candidates[index].argonSalt[:], offset, word)
		}
	case phase9CapsuleCredentialMode:
		for _, index := range indexes {
			mutated.candidates[index].credentialMode = CredentialMode(uint8(mutated.candidates[index].credentialMode) ^ byte(word))
		}
	case phase9CapsuleKDFProfile:
		for _, index := range indexes {
			mutated.candidates[index].kdfProfile = KDFProfile(uint8(mutated.candidates[index].kdfProfile) ^ byte(word))
		}
	case phase9CapsulePreambleFlags:
		mutated.preamble.featureFlags ^= uint16(word)
	}
	return mutated
}

// runPhase9CapsuleCase executes the production capsule engine on one mutated
// admitted structure and checks the closed authentication invariants.
func runPhase9CapsuleCase(
	t *testing.T,
	prepared *phase9PreparedNormalVolume,
	mode uint8,
	candidateSelector uint8,
	offset uint64,
	word uint64,
	seedID string,
	expect *phase9SeedExpectation,
) {
	t.Helper()
	inner := newNormalFixtureCredentialProvider(t, prepared.fixture.Keys)
	mutated := applyPhase9CapsuleMutation(prepared.structure, mode, candidateSelector, offset, word, inner)
	provider := &phase9CountingCredentialProvider{inner: inner}
	result := authenticateCapsulesWithProvider(
		context.Background(),
		mutated,
		provider,
		defaultCapsuleAuthSeams(),
	)
	if result == nil {
		t.Fatal("capsule authentication returned no typed result")
	}
	defer result.Close()

	candidateCount := int64(mutated.candidateCount)
	var wrapCalls, replicaCalls, adoptCalls int64
	if provider.access != nil {
		wrapCalls = provider.access.wrapCalls
		replicaCalls = provider.access.replicaCalls
		adoptCalls = provider.access.adoptCalls
	}
	if provider.closeCalls != 1 {
		t.Fatalf("capsule provider close calls = %d; want exactly one", provider.closeCalls)
	}
	if provider.credentialCalls > 1 || wrapCalls > candidateCount ||
		replicaCalls > candidateCount || adoptCalls > 1 {
		t.Fatalf(
			"capsule callback bounds = credential %d, wrap %d, replica %d, adopt %d; want <=1/<=%d/<=%d/<=1",
			provider.credentialCalls, wrapCalls, replicaCalls, adoptCalls, candidateCount, candidateCount,
		)
	}
	if provider.tupleSeen && provider.tuple != credentialTupleForCandidate(mutated.candidates[0]) {
		t.Fatal("capsule engine bound a credential tuple that differs from the admitted candidate")
	}

	outcome := phase9AuthOutcomeName(result.outcome)
	stage := phase9StageName(result.stage)
	if _, ok := codeFor(result.outcome, result.stage); !ok {
		t.Fatalf("capsule outcome/stage = %v/%v; not a legal closed mapping", result.outcome, result.stage)
	}
	authenticated := int64(result.AuthenticatedCapsules())
	if authenticated < 0 || authenticated > 2 {
		t.Fatalf("authenticated capsules = %d; closed bound is 0..2", authenticated)
	}
	switch result.outcome {
	case OutcomeSuccess:
		if authenticated != 2 || adoptCalls != 1 {
			t.Fatalf("successful capsule authentication = %d capsules/%d adoptions; want 2/1", authenticated, adoptCalls)
		}
	case OutcomeCredentialsOrDamage, OutcomeInvalidStructurePreKDF:
		if authenticated != 0 || adoptCalls != 0 {
			t.Fatalf("failed capsule authentication retained %d capsules/%d adoptions", authenticated, adoptCalls)
		}
		if result.outcome == OutcomeInvalidStructurePreKDF && provider.credentialCalls != 0 {
			t.Fatalf("pre-KDF structural rejection reached %d credential callbacks", provider.credentialCalls)
		}
	}
	if result.outcome != OutcomeSuccess && result.outcome != OutcomeAuthenticatedDegraded {
		if _, _, ok := authenticatedRecordAuthority(result); ok {
			t.Fatal("failed capsule authentication granted record authority")
		}
	}
	if expect != nil {
		counters := map[string]int64{
			"adopt_calls":       adoptCalls,
			"authenticated":     authenticated,
			"credential_calls":  provider.credentialCalls,
			"replica_key_calls": replicaCalls,
			"wrap_key_calls":    wrapCalls,
		}
		requirePhase9Expectation(t, seedID, *expect, outcome, stage, "", counters)
	}
}

func phase9AuthOutcomeName(outcome Outcome) string {
	switch outcome {
	case OutcomeSuccess:
		return "success"
	case OutcomeAuthenticatedDegraded:
		return "authenticated-degraded"
	case OutcomeCredentialsOrDamage:
		return "credentials-or-damage"
	case OutcomeInvalidStructurePreKDF:
		return "invalid-structure-pre-kdf"
	case OutcomeAmbiguousVolume:
		return "ambiguous-volume"
	case OutcomeOperationFailed:
		return "operation-failed"
	default:
		return "unknown"
	}
}
