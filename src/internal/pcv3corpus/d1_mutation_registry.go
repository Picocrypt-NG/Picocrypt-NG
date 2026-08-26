package pcv3corpus

const d1MutationTimeoutSeconds int64 = 90

// D1MutationContract is the tracked execution authority for one private D1
// semantic mutation. The private plan supplies only the source hash and exact
// before/after transform; callers must take all execution fields from here.
type D1MutationContract struct {
	id, sourcePath, packageName, testName, assertionMarker string
}

var d1MutationRegistry = [...]D1MutationContract{
	{
		id:              "auto-routing",
		sourcePath:      "internal/pcv3/route.go",
		packageName:     "./internal/pcv3",
		testName:        "TestD1WriterRefusalHasNoStageFactorEntropyOrSourceRead",
		assertionMarker: "want closed unsupported code",
	},
	{
		id:              "normal-domain-reuse",
		sourcePath:      "internal/pcv3credential/transcript.go",
		packageName:     "./internal/pcv3credential",
		testName:        "TestD1TranscriptConsumesFactorsOnceAndSeparatesDomains",
		assertionMarker: "did not use the two literal protocol domains",
	},
	{
		id:              "replica-only-anchoring",
		sourcePath:      "internal/pcv3/d1_force.go",
		packageName:     "./internal/pcv3",
		testName:        "TestD1ForceAnchorsRejectFalseAnchorsAndFirstCandidateChoice",
		assertionMarker: "want pre-inner credentials-or-damage/d1-bootstrap/none",
	},
	{
		id:              "first-candidate-choice",
		sourcePath:      "internal/pcv3/d1_force.go",
		packageName:     "./internal/pcv3",
		testName:        "TestD1ForceAnchorsRejectFalseAnchorsAndFirstCandidateChoice",
		assertionMarker: "want ambiguous-volume/d1-body/none with no inner/output",
	},
	{
		id:              "decrypt-before-tag",
		sourcePath:      "internal/pcv3/d1_outer.go",
		packageName:     "./internal/pcv3",
		testName:        "TestD1OuterRejectsTamperBeforePlaintext",
		assertionMarker: "failed authentication modified plaintext destination",
	},
	{
		id:              "kdf-overlap-count",
		sourcePath:      "internal/pcv3credential/outer.go",
		packageName:     "./internal/pcv3credential",
		testName:        "TestD1OuterDerivationIsSequentialAndBounded",
		assertionMarker: "D1 creation roots lost physical bootstrap roles",
	},
	{
		id:              "missing-final",
		sourcePath:      "internal/pcv3/d1_writer.go",
		packageName:     "./internal/pcv3",
		testName:        "TestD1WriterMandatoryFinalShortWriteAndCancellation",
		assertionMarker: "mandatory final tag missing",
	},
	{
		id:              "clear-inner-staging",
		sourcePath:      "internal/pcv3/d1_writer.go",
		packageName:     "./internal/pcv3",
		testName:        "TestD1WriterNeverCreatesClearInnerArtifact",
		assertionMarker: "live D1 stage exposed the clear inner normal preamble",
	},
	{
		id:              "outcome-laundering",
		sourcePath:      "internal/pcv3/d1_force.go",
		packageName:     "./internal/pcv3",
		testName:        "TestD1ForceNestedOutcomePreservesOuterInnerAndRangeTruth",
		assertionMarker: "want authentication-failed/inner-volume/record-auth",
	},
}

func findD1MutationContract(id string) (D1MutationContract, bool) {
	for _, contract := range d1MutationRegistry {
		if contract.id == id {
			return contract, true
		}
	}
	return D1MutationContract{}, false
}

// D1MutationContracts returns the closed tracked registry in canonical order.
func D1MutationContracts() []D1MutationContract {
	return append([]D1MutationContract(nil), d1MutationRegistry[:]...)
}

func (c D1MutationContract) ID() string              { return c.id }
func (c D1MutationContract) SourcePath() string      { return c.sourcePath }
func (c D1MutationContract) Package() string         { return c.packageName }
func (c D1MutationContract) TestName() string        { return c.testName }
func (c D1MutationContract) AssertionMarker() string { return c.assertionMarker }
func (c D1MutationContract) TimeoutSeconds() int64   { return d1MutationTimeoutSeconds }
