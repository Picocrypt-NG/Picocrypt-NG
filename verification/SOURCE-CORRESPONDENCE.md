# Source correspondence

The [five-block coverage map](COVERAGE.md) gives the source anchors and open
boundaries for the core EasyCrypt models. The detailed arguments below concern
only the bounded Go helper contracts, not all of those model-to-source relations.

This document gives bounded correspondence arguments for Picocrypt NG's
[`SafeUint64ToInt64`](../src/internal/util/safecast.go) and
[`canonicalRecordCount`](../src/internal/pcv3operation/internal/pcv3/capsule.go),
the three [checked arithmetic helpers](../src/internal/pcv3operation/internal/pcv3/arithmetic.go),
the [payload](../src/internal/pcv3operation/internal/pcv3/geometry.go) and
[encoded-body](../src/internal/pcv3operation/internal/pcv3/records.go) length helpers,
the [record-offset helper](../src/internal/pcv3operation/internal/pcv3/records.go),
[metadata geometry](../src/internal/pcv3operation/internal/pcv3/preamble.go),
the [structural core policy](../src/internal/pcv3operation/internal/pcv3/capsule.go)
and [record geometry guard](../src/internal/pcv3operation/internal/pcv3/records.go),
and the D1 [`recordParameters`](../src/internal/pcv3operation/internal/pcv3/d1_outer.go)
constructor.
They combine source and model components with a reviewed contract and
integer-representation argument under the assumptions below. A claim applies
only with passing evidence for the current source and checker. It is not
automatic, fully machine-checked cross-logic refinement or an application-wide
guarantee.

## SafeCast claim

Let `F` be the actual Go function selected by the
[`Gobra lane`](gobra/README.md). Let `U(x)` be the mathematical value of a Go
`uint64`, `I(y)` the mathematical value of a Go `int64`, and preserve Boolean
values unchanged. For every Go `uint64` input `x`, if the invocation normally
returns `F(x) = (y, b)`, the conditional claim is:

```text
(I(y), b) = safe_cast_model(U(x)).
```

This covers the entire input type, including values above `MaxInt64`. It is a
claim about returned scalar values. The current source body is loop-free and
has no I/O or heap mutation; this observation does not turn general partial
correctness into process-level termination, scheduling or availability claims.

Write `N = 2^64`, `M = 2^63 - 1`, and `L = -2^63`. The shared mathematical
objects are:

```text
U64(u) := 0 <= u < N
I64(r) := L <= r <= M

Q(u, r, b) :=
  (b = (u <= M))
  and (b implies 0 <= r and r mod N = u)
  and (not b implies r = 0)

safe_cast_model(u) := if M < u then (0, false) else (u, true).
```

Here `mod` is the nonnegative remainder for positive `N`, used to describe a
conversion to `uint64`. It is not Go's signed `%` operator.

## Checked components

The source lane loads and typechecks the actual package, resolves the real
parameter and result types and `math.MaxInt64`, and binds a generated
comment-annotated copy to the current source snapshot. It checks identical Go
signature/body AST and body bytes and typechecks the generated copy against the
resolved import. The math header supplies only the exact constant.

Both source lanes admit only reviewed scalar syntax and resolved identifiers.
The count projection permits no calls; SafeCast permits only its reviewed
conversion and constant selector. Unreviewed bindings cannot silently become
different builtins when surrounding declarations are omitted. Pre-existing
Gobra preprocessing openers and bare closing markers are rejected by a
conservative raw scan, including their whitespace forms inside ordinary
comments or strings, before adding the owned contracts. Binding checks and
negative-control coordinates use physical file positions, so `//line` and
`/*line ...*/` cannot redirect them. These are source-binding and input
admission checks, not proofs of arbitrary Go transformations.

Gobra verifies the full input domain, the three postconditions corresponding
to `Q`, and a separate derived `I64(r)` postcondition. `--overflow` checks that
an unrepresentable narrowing conversion cannot execute. A guard-disabled
negative control must fail specifically at `int64(v)`; an unrelated failure
cannot satisfy that control. Recorded hashes and negative controls bind and
exercise this check; they do not independently prove tool soundness.

[`SafeCastRepresentation.ec`](easycrypt/models/SafeCastRepresentation.ec)
separately proves:

```text
U64(u) and I64(r) and Q(u, r, b)
  implies (r, b) = safe_cast_model(u).
```

The same module proves the model contract, result ranges, uniqueness and
boundary/refusal properties. Its source contract is a premise of the
representation theorem, not an axiom that the Go implementation satisfies it.

## The reviewed composition step

The following finite argument joins these components:

- The source-binding checks identify the implementation body and resolved
   types to which the successful Gobra result applies. Comment erasure and the
   bounded annotation/import machinery are reviewed parts of this binding.
- Under Gobra's supported-subset semantics and the standard verifier-soundness
   assumption, its accepted proof supplies the checked source contract and
   derived output range. The target function is not trusted or bodyless.
- `U(x)` satisfies `U64` for every actual Go input of this type. This is the
   entire type's representation, not a safe-only caller precondition. The
   derived result-range postcondition supplies `I64` in the verifier's integer
   view; the actual resolved Go result type also has that representation.
- Constants and conversions agree on the relevant paths. In the source body,
   `int64(v)` executes only when `0 <= v <= M`, so it preserves the integer
   value. In the successful postcondition, `0 <= r <= M`, so converting `r`
   back to `uint64` agrees with `r mod N = r`. No identity conversion is assumed
   for out-of-range integers.
- With the same `M`, Boolean interpretation and value embeddings, the checked
   source postconditions imply exactly `Q(U(x), I(y), b)`.
- Applying the checked EasyCrypt representation theorem gives the bounded
   claim above.

The `I64` condition is necessary. Without it, the mathematical pair
`(r, b) = (N, true)` at input zero would satisfy `Q` while differing from the
reference result. It is excluded by an actual checked representation
obligation, not by assuming the desired result.

Go itself wraps out-of-range integer conversions rather than panicking.
Accordingly, the EC guard-disabled model uses signed narrowing and returns
`(L, true)` at `M + 1`. This is different from Gobra's no-overflow checking
mode and from an unbounded-integer model that returns `(M + 1, true)`.

## Canonical record-count claim

Let `G` be the actual `canonicalRecordCount` declaration in
[`capsule.go`](../src/internal/pcv3operation/internal/pcv3/capsule.go). Write
`K = 1048576 = 2^20` and `B = 17592186044416 = 2^44`. For every Go `uint64`
input `x`, if the invocation normally returns `G(x) = y`, the conditional claim
is:

```text
U(y) = canonical_count(U(x)).
```

The count excludes the mandatory final record. Its shared contract is:

```text
U64(length)
0 <= count <= B
length mod K = 0  implies count = length div K
length mod K != 0 implies count = length div K + 1
```

The Gobra lane additionally checks that the count is zero exactly for empty
input. The EC `count_contract` does not need that extra clause: it follows
from the quotient/remainder clauses on the stated domain.

The source-binding checks resolve the actual function and its `uint64` input
and output types. They require `recordPlaintextMax` to be the exact untyped
integer constant `1048576`, with a literal initializer in the watched source
file, and verify each use against that resolved object. An indirect initializer,
shadowing or an unreviewed free binding requires review rather than being
silently replaced by a projected declaration. The positive projection retains
the exact function signature/body AST and body bytes. Its function and constant
are covered by the source snapshot and drift check; no `math/bits` behavior is
assumed.

On the full unsigned domain, both the source contract's division and remainder
have nonnegative numerators and positive divisor `K`, so Go's operations agree
with the EC integer operations. In the implementation, `length - 1` executes
only when the length is positive. Its verified arithmetic does not rely on
wrapping. The contract deliberately avoids a machine-width `count * K`
product: that mathematical upper-cover product reaches `2^64` for the largest
input.

[`CanonicalRecords.ec`](easycrypt/models/CanonicalRecords.ec) proves
`source_contract_refines_count`: `U64(length)` and the count contract imply
`count = canonical_count(length)`. Under the same reviewed source-binding,
numeric interpretation and verifier assumptions as SafeCast, the source proof
supplies this predicate and the EC theorem gives the bounded claim.

The source negative control removes only the subtraction of one and requires
the exact divisible-input postcondition failure. At one full chunk it would
otherwise return two data records instead of one. The EC counterexample and
[`ExtraCountNegative.ec`](easycrypt/controls/ExtraCountNegative.ec) protect the
same off-by-one distinction; unrelated verifier failures do not satisfy either
control.

The EC model also proves minimal cover, full preceding data chunks, last-chunk
length conservation and index bounds. Data-chunk length theorems require
`index < canonical_count(length)`; the separately reachable final index is not
a data index. These scalar and interval results do not establish physical
offset representability, BE encodings, source/session identity, suffix/EOF,
final-record authentication or a complete stream profile.

## Checked arithmetic claims

The source lane includes all three bodies from `arithmetic.go`. With `W = 2^64`
and mathematical input/output embeddings, their source contracts determine:

```text
checkedAdd64(a,b)     = ((a+b) mod W, a+b < W)
checkedMul64(a,b)     = ((a*b) mod W, a*b < W)
checkedCeilDiv64(v,d) = (v div d + (v mod d == 0 ? 0 : 1), true), d > 0.
```

The operands cover the complete `uint64` domain. Ceiling division requires a
positive `uint64` divisor; the actual source panics at divisor zero. A false
Add/Mul flag leaves the wrapped low word, which need not be zero. Callers must
check the flag before using that value. The component does not establish those
caller checks.

All arithmetic cases use `--overflow`. The only bodyless functions in
[`bits.gobra`](gobra/specs/math/bits/bits.gobra) are the standard `Add64` and
`Mul64` interfaces. Their ranges, carry domain and quotient/remainder clauses
match Go's tuple order: sum/carry and high/low respectively. Ghost `integer`
arithmetic describes the full sum/product without machine-width overflow in the
specification. All numerators are nonnegative, so its division/remainder agrees
with the EC operations. This trusts the standard-library API and compiler
intrinsics; it does not verify their implementations. The ceiling helper calls
the same included Add body and its checked contract, not a bodyless application
helper.

There is one explicit source adapter. Gobra reserves the valid Go local name
`low`, so only that `checkedMul64` variable is renamed in the proof copy. Actual
Go type information identifies its one definition and one use, both of the same
`uint64` local. The replacement is fresh among function and contract identifiers,
and generated Go typechecking checks its new binding. Applying only the inverse
two-token rename recovers the original body bytes and executable AST. Add and
Ceil retain their body bytes directly; result-name comments are outside them.
Raw Mul body/AST identity is false and is recorded as such.

This finite, capture-avoiding local alpha-equivalence argument is a reviewed
part of the trusted interface. It is not a general verified Go translator.
Production source identifiers and behavior are unchanged. Syntax, bindings,
literal carry zero and tuple order are admitted only within the reviewed source
subset; new behavior requires review.

`WordArithmetic.add_source_contract_refines_model`,
`mul_source_contract_refines_model` and `ceil_source_contract_refines_model`
prove that these source postconditions determine the corresponding model
results. Model-satisfaction and uniqueness lemmas cover the same domains.
Interpreting the source ghost integers/Booleans and using the reviewed source
adapter gives the bounded conditional correspondence, not a common-kernel proof
transport.

One positive module checks all three bodies together. Three controlled source
copies ignore Add's carry, return Mul's high word or floor the non-exact ceiling.
Each must be rejected at its corresponding postcondition. Native oracles execute
the original source, the positive proof copy and all three defects using actual
standard imports and frozen literal expectations. These are proof-control
conformance checks, not a solver certificate or whole-application coverage.

## Normal/inner length-helper claims

These two helpers describe the Normal PCV3 payload, including a D1 volume's
inner payload. They do not describe the distinct D1 outer stream. Their source
module includes six actual application bodies: the three arithmetic helpers,
`canonicalRecordCount`, `canonicalPayloadLength` and `encodedRecordBodyLength`.
Only the standard bits interfaces remain bodyless. The ghost definitions of
count, encoding, data prefix and total payload have mathematical bodies.

For full `uint64` ciphertext length `c`, plaintext length `n` and supplied count
`k`, write:

```text
W = 2^64
S = c + 64
E = encoded_body_length(rs,c)
D = data_prefix(n,rs)
P = payload_length(n,rs)
V = (k = canonical_count(n) and k < 2^48).

encodedRecordBodyLength(c,rs) = (S >= W ? 0 : E mod W, E < W)
canonicalPayloadLength(n,k,rs) =
  (not V or (rs and D >= W) ? 0 : P mod W, V and P < W).
```

Early refusals explicitly return zero. A final checked multiplication or addition
can instead return a nonzero wrapped word with a false flag. For example, the
encoded RS helper can return `(16,false)` and the RS payload helper `(88,false)`.
Neither clearing every refused result nor returning the mathematical length
modulo `W` on every refused path would match the source.

All typed input domains remain complete; the usual ciphertext bound of 1 MiB
is a derived caller corollary. Success supplies the mathematical length.
Representable total file sizes, header compatibility, source EOF, valid RS data,
allocation and publication need their own contracts. The helper's unsigned fit
test is not a signed host-offset or disk-space guarantee.

The binding checks use the same parsed bytes for all five defining files and
resolve the nine constant types, values, origins and initializer dependencies
through native Go. The original native oracle retains their source expressions;
the proof copy materializes the checked constant values. Full body and lexical
binding checks distinguish the three separate local `ok` variables and use fresh
ghost result names. The earlier finite Mul alpha adapter is reused; no new
runtime-body transformation is introduced.

`PayloadGeometry` supplies the word-execution folds, exact closed forms and
component-form joins for the ghost count/encoded/data/total/valid expressions.
`encoded_body_source_contract_refines_model` and
`payload_source_contract_refines_model` identify the source tuples with those
execution models. The bounded encoded-body and host-bound payload corollaries
retain their caller premises. These are checked mathematical components joined
to the source postconditions through the same reviewed scalar interpretation.

The controlled source defects omit the final record, floor RS rounding or accept
an invalid count. Native original/proof-copy/defect runs use frozen literal
oracles. The payload value 275 for 51 bytes without RS also agrees with the
independent 2395-byte Normal fixture after its fixed header and suffix. Refusal
oracles exercise early zero and late wrapped values. These controls do not claim
a defect in the current application or a solver SAT certificate.

## Record-offset helper claim

`recordOffsetWithinPayload` takes the full by-value `logicalCore`, an RS flag
and a `uint64` index. Its contract covers every typed plaintext length `L`,
supplied count `k` and index `i`. Other core fields remain unconstrained. The
helper does not validate the schema, count, index or relation between the RS
argument and core flags; the constructor must establish those conditions.

With `W = 2^64`, `C = 1048576`, `F = 1114296`, and `D` the mathematical RS data
prefix, the selected offset and early-zero mask are:

```text
b = i < k
O = rs ? (b ? i*F : D(L,true)) : (b ? i*C : L) + i*112
Z = rs ? (not b and (L div C)*F >= W)
       : ((b and i*C >= W) or i*112 >= W)

(result,ok) = (Z ? 0 : O mod W, O < W).
```

In particular, direct RS data multiplication retains its wrapped low word on
refusal. The RS non-data path clears a refused full-prefix multiplication,
but retains the wrapped result of the final partial-record addition. Without
RS, either refused multiplication clears the result; the final sum can wrap.
These distinctions preserve the actual return paths.

The verification module contains seven actual application bodies, reusing the
previous checked helper closure and standard bits interface. The complete
`logicalCore` and defined `Suite:uint16` and `PayloadKind:uint8` declarations
are retained and checked against native Go. Unused fields are not projected
away. Original and inverse-copy binding graphs identify the actual field,
parameter, local and callee objects. The earlier constant and finite Mul alpha
checks remain; fresh ghost output names preserve the source's local scopes.

`PayloadGeometry.record_offset_execution_closed_form` proves the word-model
execution formula. `offset_source_contract_refines_model` gives the conditional
source-contract join. When `k = canonical_count(L)` and `0 <= i <= k`, the
selected mathematical value is the canonical physical record prefix. Success
still needs an explicit fit premise, a successful payload contract or the
appropriate host-geometry bound. Count/index compatibility alone is insufficient.

The controls target the strict final-index boundary, RS data stride and partial
RS accumulation. Native original/proof-copy/defect oracles use complete cores,
including deliberately inconsistent schema/count cases. The checked contract
does not turn those raw successful helper calls into valid volume records.
Caller validation, authentication, signed conversions and complete source/file
acceptance remain separate obligations.

## Metadata-geometry claim

`canonicalMetadataGeometry` is checked over the full Go `uint32` comment-length
domain. Its original named results `blocks`, `frontHeaderLength` and `ok` are
preserved, including their use by the source's short declarations and assignments.
The source body bytes are unchanged. The proof module also contains all three
actual arithmetic helper bodies and the existing finite Mul alpha adapter.
Only the standard bits interfaces are bodyless.

For every `0 <= c <= 2^32-1`, the returned tuple is:

```text
B = (80+c) div 128 + ((80+c) mod 128 == 0 ? 0 : 1)
H = 976 + 136*B
(blocks,frontHeaderLength,ok) = (B,H,true).
```

The complete typed domain gives `1 <= B <= 33554433` and
`1112 <= H <= 4563403864`. The latter can exceed `uint32`, matching the actual
`uint64` result type. The helper itself does not enforce the application's
comment limit. With the separate caller premise `c <= 99999`, its results
satisfy `B <= 782` and `H <= 107328`.

The binding checks resolve the four native `uint64` constants, their initializer
dependencies and both parsed source files. All four application bodies and
local/free bindings are checked against the source or its owned inverse edits.
Original named result objects are distinguished from locals; no ghost result
name changes their scope.

`PayloadGeometry.metadata_execution_matches_geometry` proves that the complete
checked-word execution agrees with the mathematical metadata/header functions.
The source-predicate field, representation, uniqueness and geometry-tuple lemmas
join the exact Go postcondition to that result under the reviewed scalar mapping.
This proves neither comment admission nor core/schema validity at callers.

The source control floors the decoded length before applying ceiling division.
At comment length zero it returns `(0,976,true)`, contradicting the frozen
expectation `(1,1112,true)`. Original and proof-copy native oracles also check
the 48/49 boundary, caller limit and maximum `uint32` input. These are concrete
proof controls, not a solver SAT certificate or a complete metadata-reader proof.

## Structural core and geometry-guard claim

One source unit checks `isSupportedSuite`, `validLogicalCore` and
`recordGeometryMatchesCore` together with six actual dependencies: the three
arithmetic helpers, record count, metadata geometry and payload length. All
nine bodies are present. The full sixteen-field core, eight-field `Geometry`,
defined enum types and two native iota groups are preserved. Native type
information checks the twenty-two constants and the flag-union expression's
compile-time value `uint16(3)`.

The ordinary validators still return one Boolean. A ghost OUT pointer carries
the observation `string(core.magic[:]) == normalDiscriminator`; its permission
is required and returned. The observation is assigned before the original core
guard, and the geometry guard passes it through an owned ghost argument.
Erasing the owned comments and inverting the existing Mul alpha adapter must
recover every original signature, body and native binding graph.

The core contract is an exact structural-policy equivalence, including count
and header formulas. Its raw string, AND-NOT and zero-array comparisons remain
explicit observations. `CorePolicy.ec` interprets them through the exact
`PCV\0` bytes, finite UInt16 mask and eight zero bytes. This interpretation
gives flags `0..3`, with the RS bit selecting modes `1` and `3`. Neither core
acceptance nor these feature values establish routing, KDF policy or
authentication.

The geometry contract is also an equivalence. It requires accepted core
policy, nonnegative stored header/payload/backup offsets, count and RS agreement,
the core's header length, successful exact payload sizing, and successful
checked `header + payload` equal to the stored backup offset. All typed input
values remain covered; no valid-core or matching-geometry precondition is
substituted for the rejection behavior.

`CorePolicy.rgm_word_execution_closed_form` joins the source-shaped checked-word
execution to the postcondition. Under the typed core/geometry mappings and the
four comparison interpretations, `rgm_source_contract_refines_geometry` gives
the concrete policy and intrinsic geometry. The record-extents corollary then
bounds descriptor/body offsets by `MaxInt64`, record ends by the backup offset,
and the final record end exactly at that offset for canonical indices.

This component uses `--nooverflow` for the parametric policy proof. The pinned
frontend leaves the two source bit operations uninterpreted; the overflow-mode
classification fails at those two expressions. Numeric mask semantics come
from the separate finite-word model. The identical arithmetic/count/metadata/
payload bodies retain their mandatory `--overflow` lanes. New signed-to-unsigned
casts follow the explicit nonnegative guards and signed input bounds.

The count control changes only `geometry.recordCount != core.recordCount` to
`==`. It must fail the full geometry postcondition; native original/proof copies
accept the frozen valid count and reject its mismatch, while the mutant reverses
both outcomes. A positive witness deliberately carries metadata block count
`777`, trailer offset `-17` and file size `-99`: those fields are retained but
unchecked by this helper. No complete file size, suffix, EOF, authentication or
publication property follows from its successful result.

## Normal record-expectation representation

`NormalConstructor.ec` models all ten `recordExpectation` fields and the
complete successful-result projection of the intended `expectedRecord`
contract. That projection is a premise, not a theorem about the Go function.
The actual constructor's implementation, completeness and refusal obligations
remain open.

With typed core, geometry, index and result views, the successful-result clauses
uniquely determine the canonical expectation: index/final status, plaintext
offset, ciphertext length, sixteen descriptor bytes, descriptor/body offsets,
encoded body length, nonce and Serpent IV. The descriptor proof uses the BE64
and full-`uint32` BE32 octet representations; the nonce and IV proofs retain
the byte embedding and the explicit Go shift interpretation for Paranoid mode.
Standard mode requires the complete zero IV.

The resulting logical record occupies the corresponding `CanonicalProfile`
slot. Profile validity additionally requires a thirty-two-byte commitment; this
does not establish its provenance or authentication. With the existing
core/geometry comparison interpretations, the independent extent corollary
gives signed offsets, record containment and exact final-record closure at the
backup offset. Complete file/suffix/EOF and publication guarantees do not follow.

A typed empty-core/geometry/reference witness satisfies the full success
projection and consistent comparison observations. This establishes that the
premise is satisfiable; it does not discharge the actual Go source proof.

## D1 parameter-frame claim

The D1 constructor claim concerns its two returned arrays. It assumes a non-nil
receiver and full per-byte permissions to its 16-byte XChaCha prefix and 8-byte
Serpent prefix. Those permissions are returned; the postconditions use the
prefix values at entry. Establishing these ownership and interference premises
at callers is separate work.

For every Go `uint64` index, the source proof supplies all prefix bytes and all
eight numeric bytes of each tail. Let `X` and `S` be the entry prefixes and let
`u` be the integer value of the input. The bounded conditional result is:

```text
nonce = X ++ be64(u)
IV    = S ++ be64((u * 65536) mod 2^64).
```

The source lane preserves the complete receiver/struct declarations and the
executable method AST. Four owned body comments specify addressability and
fractional borrowing for `copy`; erasing exactly those comments recovers the
original body bytes. Two result-name comments are outside the body. Actual Go
type information binds `copy`, array element types, fields and the imported
`encoding/binary.PutUint64`. Input preprocessing markers and adjusted token
positions cannot change that binding.

This constructor uses `--nooverflow` for a **parametric layout proof**. The
verifier's shift is uninterpreted: the same shift expression reaches the call
and its postcondition. This is not a Gobra arithmetic or no-reuse theorem. The
positive input range remains the full `uint64` type. Admission is restricted to
the reviewed constructor's exact statement/dataflow shape; new arithmetic,
parameter or receiver writes, aliases, changed shifts and struct subsets require
review. In particular, unbounded-integer reasoning about `(index*2)/2` would
not describe Go's wrapping behavior and is rejected. The earlier scalar lanes
retain their separate `--overflow` mode.

The standard-library interface is explicit in
[`binary.gobra`](gobra/specs/encoding/binary/binary.gobra). D1 uses `PutUint64`,
with full permissions to an exact eight-byte destination and the eight
byte-value postconditions. This is a trusted native-library API
contract, not a proof of that library's implementation. `Normalize64` and
`Octet` have mathematical bodies. The double signed remainder normalizes every
integer, including negative abstract values, into `0..2^64-1`.

The shared header also specifies `PutUint32` for an exact four-byte destination
and a full `uint32` input. Its byte clauses use `Octet(value,j+4)`.
`BigEndianFields.be32_low_octet64` and
`low_octet64_contract_determines_be32` prove that these clauses determine the
complete BE32 encoding. The length-byte-order control rejects using the low
byte as the first descriptor-length byte. This prepares the standard-library
interface for Normal `expectedRecord`; its caller proof remains open.

The representation join is finite:

- Interpret each Go byte as an EC byte word and use the source prefix/frame
  postconditions as the premises of `parameter_frame_contract`.
- `BigEndianFields.normalize64_mod` proves the normalization identity.
  `be64_octet` and `octet64_contract_determines_be64` identify the complete
  encoding from its eight numeric bytes.
- `RecordDomains.parameter_frame_contract_determines_parameters` joins the
  prefix and tail clauses. Instantiating the abstract shift with Go's unsigned
  shift interpretation gives `parameter_frame_contract_refines_record_parameters`.

The byte embedding, interpretation of the source shift, standard-library
interface and source-language/tool alignment are reviewed bridges, not a common
proof-kernel transport. The component does not check the caller's 48-bit record
limit. Generic counter-separation statements need that limit, a record length
at most 1 MiB, the intended key/session/prefix binding and primitive semantics.
D1 outer final records may contain partial ciphertext; Normal PCV3's empty-final
statements are not used for D1.

The negative control changes the nonce's index to `index+1` and selects index
zero. It checks the frozen byte consequence `nonceOut[23] == 0`, which follows
from the full positive contract at that input. A separate native Go execution
of both generated copies, using the actual imports and zero prefixes, produces
byte zero for the original and byte one for the mutant. This is concrete
proof-control conformance. The Gobra rejection is reported at that byte
postcondition; no solver SAT certificate is claimed. Neither the positive
domain nor its array postconditions are narrowed for this control.

The larger Normal `expectedRecord` function, its geometry/core dependencies,
caller ownership and complete D1 protocol remain outside this component claim.

## Normal EOF observation boundary

[`NormalPhysicalEOF.ec`](easycrypt/models/NormalPhysicalEOF.ec) models the
returned observations in [`normalPhysicalEOF`](../src/internal/pcv3operation/internal/pcv3/normal_reader.go).
It preserves the two-attempt limit and the precedence of a returned byte over
EOF error matching. The caller-tail policy applies only after earlier
authentication, suffix reads and cancellation checks have passed. Eligibility
requires equal suffixes, the expected source size and an exact EOF observation.

Counts and error-match flags are observations supplied by the environment.
The second `errors.Is` call is short-circuited when the first matches; its
unused flag cannot affect the modeled disjunction. The model does not prove
`ReaderAt`, custom error methods, deferred zeroing or the complete Go reader.
An exact observation does not prevent later source mutation or establish
publication authority. This component adds no Go source-contract claim.

## Trust and remaining obligations

Source stability is checked at measured boundaries. The runner fingerprints
the inventory and bytes of non-test Go sources and all `go.mod`/`go.sum` files
under `src/` before loading, after loading and after the jobs. This catches new
binding files and nested module boundaries as well as edits and deletions.
Selected parsed-byte snapshots and conflicting-view checks remain independent
guards. These checks are not an atomic filesystem snapshot or source coverage.

The composition uses a reviewed correspondence between the two contract
languages. A new translator is not required to make this bounded conditional
argument, but that correspondence has not been discharged by a common proof
kernel. The trusted base includes:

- Gobra's frontend, annotation handling and Viper encoding, its verification
  backend and SMT solver, and their applicability to this source subset.
- The source-binding machinery and constant-only import alignment, together
  with the explicit integer and Boolean interpretation just described.
- EasyCrypt, its imported mathematical theories, Why3 and the selected prover.
- Compiler, runtime and platform correctness when transferring the source-level
  conclusion to a particular executable; this lane does not verify that binary.

This is ordinary conditional verification with an explicit trusted interface,
not a requirement to verify every tool's implementation before progressing.
For example, the SCION verification explicitly trusts a manual translation of
its interface specification between Isabelle and Gobra, alongside its tool and
library assumptions. Igloo distinguishes foundational embeddings from the use
of existing program verifiers under an explicit verifier assumption.
Those results motivate the methodology; they do not supply a general
EasyCrypt-to-Gobra soundness theorem for this project.

These component results establish no complete caller behavior, cryptographic
distribution or security bound. Caller ownership, wider aliasing and concurrent
interference, error and cancellation traces, publication, filesystem
and provider behavior, frontend observations and release integrity require
their own applicable contracts and correspondence arguments. A source or
contract change requires renewed evidence and review of the affected mapping.

In particular, using any of these contracts inside a writer, reader or geometry
function requires a separate caller proof. No bounded composition marks
those callers or general model-to-application refinement as proved.

## References

- [Go integer conversions](https://go.dev/ref/spec#Conversions).
- [Go unsigned integer overflow](https://go.dev/ref/spec#Integer_overflow).
- [Go Add64 API](https://pkg.go.dev/math/bits#Add64), [Mul64 API](https://pkg.go.dev/math/bits#Mul64).
- [Gobra: Modular Specification and Verification of Go Programs, CAV 2021](https://arxiv.org/abs/2105.13840).
- [Protocols to Code, CCS 2025, sections 3.5–3.6](https://people.inf.ethz.ch/basin/pubs/acm25_sdp.pdf).
- [Igloo, OOPSLA 2020: verifier assumption and composition](https://people.inf.ethz.ch/basin/pubs/igloo20.pdf).
