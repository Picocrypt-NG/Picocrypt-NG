# EasyCrypt models

This suite checks the five PCV3 core contracts in the
[coverage map](../COVERAGE.md) for Picocrypt NG Normal and D1. It does not
establish that the existing Go, Kotlin, JavaScript or platform implementation
refines them, or prove the concrete cryptographic primitives.

## Run

Install opam and the native build prerequisites, then run from the repository
root:

```sh
uv run --no-project python verification/easycrypt/bootstrap.py
uv run --no-project python -m unittest discover -s verification/easycrypt/tests
uv run --no-project python verification/easycrypt/run.py
```

Setup imports the frozen `toolchain.export` into the dedicated switch named in
`toolchain.json`. It preserves the selected switch and shell configuration. It
does not run the system package manager: native dependency checks still occur
during compilation, and missing prerequisites must be installed separately.
The checked setup uses OCaml 5.4.0, EasyCrypt r2026.10 at commit
`859766e50e936fb9e420fb6fb1ad8824ffb8d83e`, Why3 1.8.2 and Alt-Ergo 2.6.4.

The runner verifies tool identities, checks immutable copies of registered
proof inputs, runs one prover at a time, and records commands, diagnostics,
timings and source hashes under ignored `_build/`. `results.json` reports the
complete registered suite. `--only TARGET` writes a separately labelled partial
report. Source changes during execution invalidate the current-source result.
Generated results and local paths do not belong in commits.

Every positive theory is compiled directly to check its proofs. A separate
import then checks closure at end of file; imports alone normally skip proof
checking. Positive libraries are isolated from intentionally invalid controls
and ambient `EC_IDIRS`/`EC_RDIRS` additions.

## Checked statements

| Model | Statement and assumptions |
| --- | --- |
| `RecordFraming.ec` | Concrete byte-list framing is injective for field widths 32/8/8. Numeric encodings are supplied by `BigEndianFields.ec`; their actual Go implementation correspondence remains separate. |
| `RecordIntegrity.ec` | Fresh structured-record acceptance reduces to a signing-only MAC EUF-CMA forgery. The underlying MAC's security and the authenticated context/key provenance are explicit external obligations. |
| `NormalStream.ec` | For one valid supplied profile and exactly one issuance per position, acceptance of a changed semantic stream reduces to the record/MAC game. Exact count, order and mandatory final-record properties and empty/partial successful cases are proved. |
| `IndexOmissionReplay.ec` | Omitting only the record index permits replay with probability 1 under MAC correctness and lossless key generation. This is an intentionally defective model; production already includes the index. |
| `LifecycleAuthority.ec` | Finite operation traces preserve ordered write/publication/settlement/cleanup prerequisites, revocation and origin separation. Its one-shot event consumes one logical operation authorization, not an individual unlink and not the repeatable Go `SourceDeletionAllowed` predicate. |
| `SafeCastRepresentation.ec` | Over the full `uint64` domain, the typed mathematical source contract for `SafeUint64ToInt64` uniquely determines the reference result. Exact signed narrowing/wrap and boundary/refusal properties are proved. This representation theorem does not itself transport a Go/Gobra proof into EasyCrypt. |
| `CanonicalRecords.ec` | The full `uint64` plaintext-length domain gives the unique ceiling count, at most `2^44` data records. Chunk bounds, complete preceding chunks, last-chunk length conservation and the separate final index are proved. Its quotient/remainder contract is paired with the Gobra source check. |
| `BigEndianFields.ec` | Concrete byte encodings have bounds-qualified BE32/BE64 roundtrips and injectivity. Numeric-octet postconditions uniquely determine BE64 and full-`uint32` BE32, including the trusted header's normalization. The descriptor tail binds its decoded length, final flag and zero reserved bytes. Truncation and reversed-byte counterexamples make the representation limits explicit. |
| `CanonicalProfile.ec` | The canonical count and byte encodings construct a profile satisfying `NormalStream.valid_profile`, with unique sequential indices, exact decoded lengths and a separate empty final record. This discharges the mathematical profile construction, not the actual Go core/descriptor implementation relation. |
| `WordArithmetic.ec` | Concrete full-width sum/product decompositions give exact checked-arithmetic flags and wrapped low-word results on refusal. Source-post predicates uniquely determine the reference wrappers. Positive-divisor ceiling division stays in range and always succeeds. The API models do not prove Go `math/bits` or its compiler intrinsics; the separate source lane checks the three application helper bodies under those interfaces. |
| `RecordDomains.ec` | Prefix/index nonce encodings are injective, and 128-bit Serpent CTR inputs consumed by distinct valid records do not overlap. Parameter-frame postconditions determine the modeled nonce/IV encodings. Normal PCV3 final records consume no stream blocks; D1 outer finals may carry data and use the generic length-bound statements. Buffered unused keystream, key/prefix provenance and full cipher/source correspondence remain separate. |
| `PayloadGeometry.ec` | Normal/RS extents are adjacent and ordered and include the empty final record. Full-width size/offset folds preserve early-zero and final-wrapped refusals; raw offset and host corollaries retain caller/fit premises. Full-`uint32` metadata execution and named-result predicates determine the exact block/header tuple; caller comment admission is separate. Complete Go geometry/caller and filesystem acceptance remain open. |
| `CorePolicy.ec` | Concrete UInt16 masks and full typed core/geometry views give structural policy and canonical count/header bounds. Source-shaped word execution and the exact geometry postcondition join to intrinsic record extents under explicit string, mask, array and scalar interpretations. Unread geometry fields, routing, authentication, EOF and publication remain outside the claim. |
| `NormalConstructor.ec` | The complete success postcondition, taken as a premise, uniquely determines all ten record-expectation fields and the canonical profile slot. Byte/word/shift interpretations remain explicit. A typed empty fixture proves the premise is satisfiable. The actual Go constructor, its completeness and refusal behavior are not proved by this model. |
| `NormalPhysicalEOF.ec` | The Normal reader's two-attempt observation policy rejects any returned byte before considering EOF and exhausts zero-byte/no-error retries. The final tail gate additionally requires equal suffixes and the expected source size. Reader/error behavior, earlier authentication and cancellation checks, source stability, cleanup and publication remain external obligations; this is not a Go implementation proof. |
| `CredentialContext.ec` | Canonical transcript serialization, credential prehash inputs, Normal/D1 schedule fields and D1 root-context inputs are injective under their byte-width/length bounds. Normal root and VolumeID are bound as Extract arguments, separately from `info`. Hash/KDF security, factor admission/canonicalization, randomness and source refinement are not supplied by input injectivity. |
| `D1RecordIntegrity.ec` | The actual profile/index/length/final/ciphertext MAC framing is injective. For one profile and MAC key, fresh admitted-record acceptance reduces to byte-MAC forgery. A supplied valid complete outer profile gives count/order/final properties and changed-stream forgery extraction, including data-bearing and empty finals. Profile/key provenance, bootstrap checks, physical EOF and inner/outer composition remain external. |
| `RecordConfidentiality.ec` | Ciphertext-only MAC postprocessing preserves the underlying nonce-respecting encryption LR advantage for equal-length messages and common public context. Length-preserving keyed preprocessing also preserves the outer encryption bound. Keys are independently sampled ideal values; actual HKDF replacement, source/length refinement and concrete cipher security remain assumptions. D1 context is conservatively public; no CCA or full-container deniability claim follows. |
| `ReadResultAuthority.ec` | Ordered trusted check/result events constrain one-shot Normal callback actions and revocation. Degraded raw output and verified Force recovery retain their intended policy; only exact ordinary success gives modeled archive authority. Publication observations preserve the modeled result. Event/tuple validation, pre-callback preparation failures, D1 emitters and filesystem effects remain outside this interface-policy proof. |

Normal stream/session origin, authenticated read completion and a write
producer's complete-write event are different interfaces. None automatically
establishes public publication or source-deletion authority. The lifecycle model
takes whole-write construction as a producer contract and uses a reduced
publication/custody state space; complete provider retries, indeterminate commit,
filesystem crashes and individual manifest removals remain outside it.

The stream profile's authentication, actual Go logical-core/descriptor and
geometry relations, key provenance, commitment binding, RS/padding, physical
source stability and complete reader/EOF correspondence remain open. The
[source correspondence](../SOURCE-CORRESPONDENCE.md) distinguishes bounded
reviewed contract composition from automatic implementation refinement.
Confidentiality reductions do not discharge their primitive LR or derived-key
independence assumptions. Complete D1 bootstrap/composition, multiple sessions,
legacy compatibility and frontend/platform behavior retain the boundaries in
the coverage map. Source hashes and existing tests do not close these relations.

## Proof discipline

EasyCrypt permits explicit proof admissions in normal batch mode. The local
policy therefore rejects active `admit`, `admitted`, `abort`, checking-mode
pragmas and unregistered axiom declarations in owned proof sources. It ignores
words in nested comments and quoted strings. The reviewed axioms currently are
only MAC correctness and lossless key generation in the replay counterexample.
This syntactic policy does not prove the consistency or adequacy of assumptions;
those still require review. Imported standard theories and the pinned verifier,
Why3 and SMT solver remain part of the trusted toolchain.

Semantic negative controls must fail at a deterministic kernel closing step in
the specified theorem. Parser/import errors, missing tools, solver failures and
timeouts are not accepted. Admission/tagged-axiom and EOF-closure controls and
Python tests check proof-tooling policy;
they are not application-behavior coverage. Other controls exercise index binding,
late cleanup revocation, count/final/order failures of explicit weakened stream
acceptors, numeric count/endian/truncation mistakes, wrapped ceiling arithmetic,
CTR stride overlap, physical final-record omission, RS floor rounding, credential
role omission, D1 index omission and degraded archive authority. The plaintext
wrapper example is a separate semantic leak witness, not a mutation of the
confidentiality reduction or a production exploit. These model controls do
not claim that production was mutated or that the corresponding defect exists
in the application. The separate Gobra lane mutates generated source copies.

## Reuse

Formosa provides useful specifications, proof libraries and implementation
projects. Match the exact algorithm, theorem, assumptions, revision, licence and
toolchain before adding a dependency. [Crypto-specs](https://github.com/formosa-crypto/crypto-specs)
explicitly contains specifications and supporting properties, not security
proofs of concrete implementations. Jasmin/assembly results do not transfer
automatically to Go or to every supported platform. No runtime cryptographic
backend is replaced by this suite.

Useful method references include [EasyCrypt's program logics](https://github.com/EasyCrypt/easycrypt/tree/r2026.10/doc/tactics),
[adversarial complexity and composition](https://adrienkoutsos.fr/papers/ec-complexity-long.pdf),
and [Diodon's model/code/application obligations](https://pm.inf.ethz.ch/publications/ArquintKishorKoenigDoddsKroeningMueller26.pdf).
The latter is methodological guidance, not an established computational
EasyCrypt-to-Go bridge for Picocrypt NG.
