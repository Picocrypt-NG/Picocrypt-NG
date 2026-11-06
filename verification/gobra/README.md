# Go source contracts

This lane checks the current Picocrypt NG `SafeUint64ToInt64` and
`canonicalRecordCount`, D1 `recordParameters`, all three `arithmetic.go`
implementations, `canonicalPayloadLength`, `encodedRecordBodyLength` and
`recordOffsetWithinPayload`, `canonicalMetadataGeometry`, `isSupportedSuite`,
`validLogicalCore` and `recordGeometryMatchesCore`.
Verification uses generated copies and the finite local-name
adapter described below; production files are read only.

Run from the repository root with Go 1.27.3, Docker, the pinned dependencies
already in the Go module cache, and the pinned Gobra image already available:

```sh
sh verification/gobra/check.sh
```

The Go entry point is `cmd/source-contracts`; from this directory it can also
be run as `go run ./cmd/source-contracts -repo ../..`. The script places new
compiler output under ignored `_build/` and disables module downloads. It does
not install tools or change Go configuration, profiles or existing containers.

On a cold machine, prepare the pinned tool dependencies with `go mod download`
from this directory. Prepare the actual production package dependencies from
`src/` before the offline check:

```sh
GOTOOLCHAIN=local GOWORK=off GOENV=off GOFLAGS= GOPACKAGESDRIVER=off \
  GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  go list -mod=readonly -deps -export ./internal/util ./internal/pcv3operation/internal/pcv3 > /dev/null
```

This preparation may download versions fixed by `src/go.mod` and `src/go.sum`
and compile dependencies; it does not execute application code. The Gobra image
must also be fetched explicitly using the digest below. The checker never pulls
an image or downloads a module implicitly.

Official `golang.org/x/tools/go/packages` v0.52.0 loads and typechecks the actual
source packages. The loader uses Linux/amd64, CGO disabled, no workspace, no external
package driver, no Go environment file, empty ambient GOFLAGS and no overlay.
It compares the bytes parsed by the loader with the disk snapshot. It resolves
the parameter/result types and the actual `math.MaxInt64` constant through Go
type information. The Gobra math header contains only that exact constant.

Annotations for the original scalar pair use parser positions. Each positive copy must retain identical Go
signature/body AST and identical body bytes. Both cast copies undergo Go
typechecking against the actual loaded math package. The cast negative mutation
wraps the original cast guard condition in `false && (...)`, retaining a valid
Go program and its math import.

The original scalar pair accepts only the reviewed scalar syntax and resolved identifiers.
New calls, free names, shifts or bitwise operations require a source-subset review;
omitting another package declaration cannot silently turn its name into a Go
builtin. Input already containing Gobra opening or closing annotation markers is
rejected, including bare closing markers and frontend-recognized whitespace.
Source binding and diagnostic coordinates use physical file positions; Go line
directives cannot hide identifier bindings or redirect those coordinates.

The cast contract covers **every** Go uint64 input, including values above MaxInt64.
It proves the exact success flag, nonnegative successful result with uint64
cast-back equality, and zero result on refusal. A separate derived postcondition
also proves the complete int64 result range. With `--overflow`, Gobra checks that
the unsafe conversion cannot execute. Go itself wraps out-of-range integer
conversions; the negative control must report overflow specifically at `int64(v)`.
Import, syntax, timeout, OOM and unrelated failures cannot satisfy that control.

For `canonicalRecordCount`, the checker projects the current declaration from
`src/internal/pcv3operation/internal/pcv3/capsule.go` and includes only its exact
resolved `recordPlaintextMax` constant. Go type information checks the constant's
actual use inside the function, including shadowing, and requires its current
integer-literal initializer. The positive function's
signature/body AST and body bytes remain identical. Its contract covers all
uint64 plaintext lengths: it returns the quotient for exact multiples and the
quotient plus one otherwise, with count in `0..2^44` and zero exactly for empty
plaintext. The final record is separate and is not included in this count.
The contract uses quotient/remainder decomposition rather than a machine-width
`count * chunkSize` product, which reaches `2^64` at the largest input.

The second negative copy removes only the subtraction of one. It remains valid
Go and causes an extra data record at positive exact multiples of the chunk
size. The control requires the exact divisible-input postcondition failure;
an overflow diagnostic or unrelated proof failure cannot pass it. Neither
record-count case imports or assumes `math/bits` behavior.

D1 `recordParameters` is a separate **parametric layout** proof. The loader
projects its actual receiver, method and complete `d1OuterKeys` and
`d1OuterCodec` structs from `d1_outer.go`. It checks actual imported packages,
field objects, parameter/local bindings and builtin `copy`. The exact reviewed
body has two zero-initialized arrays, two copies, two standard BE64 writes and
a return. Its only binary operation is the existing `index << 16`. New
arithmetic, aliases, input or field assignments, changed bounds, calls or struct
shapes are rejected before verification. This matters because this lane uses
`--nooverflow`: `(index*2)/2`, for example, would have different Go wraparound
behavior. The four scalar cases retain `--overflow` and their original contracts.

The D1 positive contract covers every uint64 index. It proves all nonce and IV
prefix bytes equal their input values, returns the prefix read permissions, and
proves each eight-byte tail equals its `binary.Octet` specification. No caller
record-index limit is assumed. Four owned body comments make local arrays
addressable and supply copy permissions; two comments outside the body name
results. The checker requires identical executable ASTs including the receiver
and full structs, and exact original body bytes after erasing only those four
body comments. Raw annotated body bytes differ, as the report records.

[specs/encoding/binary/binary.gobra](specs/encoding/binary/binary.gobra) is a
**trusted standard-library interface**, not a proof of Go's BE64 implementation.
The bodyless function used by D1 is standard `PutUint64`. The shared header
also specifies four-byte `PutUint32` writes through `Octet(v,j+4)` for the
Normal descriptor-length interface. EasyCrypt proves that these byte clauses
uniquely determine BE32 on full `uint32` inputs; the Normal constructor's
source proof remains open.
`Normalize64(v) = ((v % 2^64) + 2^64) % 2^64` handles negative mathematical
inputs using Go-style signed remainder. `Octet(v,j)` divides that nonnegative
value by the corresponding eight literal BE weights, then takes remainder 256;
position zero is most significant. The BE64 clauses do not require a smaller
input range.
`integer(byte)` is the numeric byte embedding. The projected `D1Profile` header
contains only its checked underlying uint16 declaration; no application function
is assumed correct.

Gobra's shift remains uninterpreted here. The proof establishes array layout for
that shared shift interpretation; it does not establish shift arithmetic, nonce
injectivity, counter capacity, session/key properties or cryptographic security.
The separate EasyCrypt `BigEndianFields.ec` byte lemmas and `RecordDomains.ec`
arithmetic retain their own checked mathematics. Choosing actual Go shift
semantics, byte embeddings and composing those results remains a reviewed
cross-logic argument, not checked proof transport. D1's final record can carry
partial ciphertext; Normal's empty final record is not a premise here. Callers
must separately establish valid record indices, geometry, ownership and sessions.

The D1 negative changes only the nonce BE64 argument from `index` to `index + 1`.
Its control-only premise `index == 0` and postcondition `nonceOut[23] == 0` are a
concrete consequence of the unchanged positive contract. Other prefix and IV
postconditions remain. The gate requires the exact byte postcondition diagnostic,
with no timeout, OOM, overflow or unrelated failure. It does not label this a SAT
certificate. An independent native Go fixture compiles the same generated copies
against actual imports and invokes them at index zero with a zero-valued receiver.
Its frozen expectation is all-zero nonce and IV: the positive passes, while the
mutant returns nonce byte 23 equal to one and fails. These binaries run under the
same isolated container settings. Compilation writes only generated module/cache
files and disables module downloads. These are proof-control conformance checks,
not application-behavior coverage or application KDF executions.

The arithmetic lane includes the actual bodies of `checkedAdd64`, `checkedMul64`
and `checkedCeilDiv64` together. Their only assumed functions are standard
`math/bits.Add64` and `math/bits.Mul64`, whose explicit interface is in
[specs/math/bits/bits.gobra](specs/math/bits/bits.gobra). Add returns the low
sum followed by carry; Mul returns high word followed by low word. The header
specifies quotient/remainder by `2^64` using ghost mathematical integers, with
word ranges and carry in `0..1`. The actual Add call uses literal zero carry.
The standard-library implementation and compiler intrinsics remain trusted;
this lane proves the three wrappers under that API contract.

All four arithmetic proof cases use `--overflow`. Add and Mul accept every pair
of uint64 inputs, return the low word even on overflow, and set the flag exactly
when the mathematical sum or product fits. Ceil accepts every uint64 value and
every positive uint64 divisor, returns quotient plus one exactly for a nonzero
remainder, stays in uint64 range and always succeeds. Divisor zero is outside
this normal-return contract: the current Go source panics. Caller correctness
must establish the nonzero divisor and appropriate handling of refusal flags.
No application helper is represented by a bodyless contract; Ceil uses the
same included and verified Add body and its full contract.

The pinned Gobra lexer reserves Go's valid local identifier `low`. The proof
copy therefore has one finite, explicit adapter: the `checkedMul64` local named
`low` becomes `pcv3LowWord`. Go type information selects exactly one definition
and one use of the same uint64 local at physical source positions. The fresh
name must not occur among that function's identifiers or contract names.
Generated Go typechecking checks that both tokens resolve to one fresh uint64
local. Only the inverse of those two owned token replacements recovers the exact
original Mul body bytes and signature/body AST; Add and Ceil retain their body
bytes directly. Two result-name comments per function stay outside the bodies.
The report records the two positions, bindings and differing raw Mul body/AST.
This is a reviewed local alpha-equivalence argument within the TCB, not an
automatic Go transformation proof or a claim of raw unchanged-body verification.
No production source identifier is changed.

One positive arithmetic module verifies all three bodies and their full
contracts. Three negative modules retain those contracts and each change one
expression: ignore Add's carry, return Mul's high word, or floor Ceil on a
nonzero remainder. Their required failures are the exact flag, low-word or
ceiling postconditions respectively; timeout, overflow and unrelated failures
cannot satisfy them. Inverse identity checking first undoes only that controlled
expression and then only the two alpha tokens. Native frozen oracles execute
the original Go source, the positive proof copy and all three mutants in the
same sandbox. They check independent literal expectations including
`MaxUint64 + 2 -> (1,false)`, `3 * 7 -> (21,true)`, `129 / 128 -> (2,true)`
for the ceiling wrapper, and the nonzero low word of a refused multiplication.
These are proof-control conformance checks, with no SAT-certificate claim.
`WordArithmetic.ec` separately proves that the corresponding mathematical
contracts determine its reference wrappers; the integer embedding and reviewed
cross-logic composition remain explicit obligations.

The Normal payload helper module contains six actual bodies together: the three
arithmetic wrappers, record count, payload length and encoded record-body length.
Every body has its full contract and is checked with `--overflow`; no application
helper is a bodyless assumption. Ghost functions with bodies define mathematical
count, encoded body, data prefix, total payload and count validity. For `W=2^64`,
the contracts distinguish explicit early refusal from a final checked operation
that returns its wrapped low word:

```text
S(c) = c + 64
E(c,rs) = encoded mathematical body length
D(n,rs) = mathematical data prefix
P(n,rs) = D(n,rs) + (rs ? 184 : 112)
V(n,count) = count == canonical_count(n) && count < 2^48
encoded result = (S(c) >= W ? 0 : E(c,rs) mod W, E(c,rs) < W)
payload result = (!V || (rs && D(n,rs) >= W) ? 0 : P(n,rs) mod W,
                  V && P(n,rs) < W)
```

These contracts cover every uint64 length/count and both RS values. The production
record bound of 1 MiB is a subsequent caller corollary, not an input restriction.
Successful payload sizing alone supplies no header, suffix, signed-host-offset,
EOF, authentication or allocation guarantee. D1's different final-record protocol
is outside these Normal geometry claims.

The module resolves nine constant objects, their exact Go compiler-evaluated
types and values, and every referenced initializer dependency. The closure spans
`arithmetic.go`, `capsule.go`, `geometry.go`, `records.go` and `preamble.go`; all
five snapshots must equal the actual bytes captured by the package parser.
Unknown initializer dependencies are rejected even when their current numeric
value matches. Proof copies materialize compiler-checked constants outside the
bodies, preserving the untyped chunk-size constant and other uint64 types.
Overlapping snapshots from earlier proof lanes must match before any container
runs; later snapshots cannot erase earlier source evidence. Final source and
header drift invalidates the run.

Each target's parameters, globals, callees and lexical locals are resolved through
Go type information. After only the owned control/alpha inverses, the copy must
have the same six body binding graphs and exact body bytes/ASTs.
`canonicalPayloadLength` has three distinct local `ok` objects; its partial-record
block updates its own `ok` and the outer payload length. New result names
`resultValue` and `successFlag` must be absent from every identifier of each target,
including nested locals and referenced globals. This separate check is needed
because Gobrafier names results from comments: choosing `ok` could change a real
short declaration's binding even though ordinary Go ignores those comments.
The existing arithmetic result names and finite Mul alpha adapter remain unchanged.

One positive module verifies all six bodies. Three controls omit the non-RS final
record, floor the encoded RS ceiling, or accept an inconsistent count. Each keeps
the full positive contracts and requires the exact result postcondition failure.
Native fixtures execute original constant expressions and the positive
materialized proof copy against frozen expectations: RS 64/65-byte boundaries,
the public independent container's 275-byte payload, early zero refusals and
wrapped refusals returning 16 or 88. Separate defect fixtures show empty payload
`0` instead of `112`, RS body `136` instead of `272`, and invalid count
`(113,true)` instead of `(0,false)`. These literal checks ground the controls;
they do not prove serialization or whole-application behavior.
`PayloadGeometry.ec` separately proves the ghost formula joins and exact
source-contract representation lemmas. Go/Gobra semantics, constant
materialization, the reviewed alpha mapping and cross-logic composition retain
their stated trusted boundaries.

The offset module adds the actual `recordOffsetWithinPayload` body to that
six-body closure. It copies the complete by-value `logicalCore`, including every
unused field, and the actual defined `Suite` (uint16) and `PayloadKind` (uint8)
declarations. Aliases, generics, field subsets and unreviewed primitive type
bindings are rejected. Original and copied type declarations must retain their
bytes and resolved field/type identities under the reviewed named-type mapping.
The input's other fields remain arbitrary well-typed values. Its three distinct
local `ok` objects and fresh result names receive the same binding checks as the
earlier payload targets; all seven inverse-recovered body graphs must match.

For independent full-uint64 `L=core.plaintextLength`, `k=core.recordCount`, index
`i`, and the explicit Boolean `rs`, let `b=(i<k)`, `M=1048576`, `A=112`,
`F=1114296` and `D=data_prefix(L,true)`. The full helper contract is:

```text
O = rs ? (b ? i*F : D) : (b ? i*M : L) + i*A
early = rs ? (!b && (L/M)*F >= W) : ((b && i*M >= W) || i*A >= W)
(result,ok) = (early ? 0 : O mod W, O < W)
```

Direct RS data multiplication and final partial accumulation retain wrapped low
words on refusal. Only the stated earlier checks clear their refused result.
This differs from the payload helper's partial-prefix failure behavior. The raw
offset helper validates no canonical count, after-final index, schema, record
limit or agreement between `rs` and `core.featureFlags`. The valid-caller
`record_offset` corollary separately requires canonical count, `i<=k` and a
fitting extent. Neither `recordGeometryMatchesCore` nor `expectedRecord` is
assumed correct by this module.

Three controls change only the first non-RS `<` to `<=`, use non-RS overhead as
the RS data width, or omit final partial accumulation while keeping the Go local
used. They require the exact offset result postcondition failure. Original and
proof-copy native fixtures initialize all core fields, deliberately using
noncanonical unused metadata, and check literal final/after-final/independent
count successes plus early-zero and wrapped 101360/40/final-overflow cases.
Separate control fixtures require the observed wrong tuples for those three
defects. These are numeric helper and proof-control checks, not capsule
validation, cipher, serialization or publication proofs. `PayloadGeometry.ec`
separately checks the full-domain offset source predicate, execution reference
and conditional caller joins; the complete Go named-type/field embedding remains
part of the reviewed source correspondence.

The metadata module includes the three real arithmetic wrappers and the actual
`canonicalMetadataGeometry` body. Its existing named outputs `blocks`,
`frontHeaderLength` and `ok` are preserved directly, with no synthetic result
names. Source and inverse-recovered proof copies must bind reads and assignments
to the same named-return/local/free objects. The only changed raw body is the
existing two-token Mul alpha adapter. The four uint64 constants 976, 80, 128 and
136 are checked by actual compiler object/type/value and initializer-dependency
analysis, with the same parsed arithmetic/preamble snapshots, overlap and full
source-context guards.

The metadata contract covers every uint32 comment length, with no 99999 input
cap. It proves `blocks=ceil((80+commentLength)/128)`,
`frontHeaderLength=976+136*blocks` and `ok=true`, including block range
`1..33554433` and header range `1112..4563403864`. The user-facing comment cap
appears only as a derived implication. The maximum header exceeds uint32;
comment admission, safe narrowing and compatibility with the encoded core/header
must be established separately by callers.

One positive four-body module and one ceil-to-floor control run with
`--overflow`. The control must fail the exact metadata block lower-bound
postcondition, not a timeout or unrelated check. Original and positive proof-copy
native fixtures check frozen comments 0, 48, 49, 99999 and MaxUint32; the control
shows `(0,976,true)` for comment zero instead of `(1,1112,true)`. Only the
standard bits API remains a bodyless trusted dependency. The separate
`PayloadGeometry.ec` metadata representation lemmas retain the stated source and
cross-logic correspondence assumptions.

The structural-core and geometry-guard component checks nine actual bodies
together. Its new targets are `isSupportedSuite`, `validLogicalCore` and
`recordGeometryMatchesCore`; all six helper bodies are included rather than
assumed. The exact frozen proof template is admitted only after its owned
comment and Mul alpha inverses recover the current source ASTs, body bytes and
Go binding graphs. The complete core/geometry structs, nominal enum types,
native iota groups and constant types/values/initializer dependencies are
checked. The native flag-union expression must be the typed constant `uint16(3)`.

Both validator APIs keep one ordinary Boolean result. An owned ghost OUT
pointer observes the original magic comparison; its full permission is required
and returned. The real inline caller remains intact after erasing its ghost
argument. The source contracts state exact core policy and geometry agreement,
including rejection paths, rather than assuming valid inputs. Their Go integer
inputs have the stated full type ranges.

This policy component uses `--nooverflow` because the pinned frontend's two
bit operations have opaque encodings. It does not infer their numeric meaning
from the Gobra result. The helper bodies retain separate mandatory overflow
checks; the new signed casts follow nonnegative guards. `CorePolicy.ec` supplies
the finite UInt16 model, typed views, checked-word execution and conditional
representation joins. Raw string, mask, zero-array and RS-bit interpretations
remain explicit bridges.

The count-comparison defect must fail the exact full geometry postcondition;
timeouts, overflow diagnostics and unrelated errors cannot satisfy that control.
Original/proof native copies accept a frozen valid count and reject a mismatch;
the mutant reverses both. The valid witness retains arbitrary unchecked
metadata-block/trailer/file-size fields. Those fields, full file acceptance,
authentication, EOF and publication remain outside the guard's claim.

The source-context guard fingerprints the inventory and streamed SHA-256 of
every non-test `.go` file and every `go.mod`/`go.sum` recursively under the
application's `src/`, including the required top-level module files. It captures this context before package loading,
checks it again after all loaders before proving, and checks it after all proof
and native jobs. Additions and deletions matter: adding another package file can
rebind a builtin without changing any selected function file. New nested module
files can also change package resolution without changing Go source bytes. Such fixtures
reproduced the old selected-file check accepting unchanged bytes while a fresh
loader rejected the new binding. The context guard now rejects that drift.
The existing same-parsed-byte, selected-binding and overlapping-snapshot checks
remain in force.

Context metadata contains relative paths and hashes, not copied source text.
Go source/module inputs must be regular files; source-file and directory
symlinks require scope review. These are checks at measured boundaries, not an
atomic filesystem snapshot. Test Go files, non-Go resources, verification
tooling, the OS, module cache and standard-library implementation are outside
this context fingerprint. Matching context establishes input stability at those
boundaries; it is not behavior coverage for the files being hashed.

The pinned frontend rejects integer-range loops and `clear`. Reader proofs using
those constructs require a supported method before extending this lane. Normal
completion seals based on empty-struct pointers are also excluded pending a
reviewed nil/non-nil representation. Passing local contracts and defect controls
alone does not establish that representation.

The official Gobra image is pinned to
`ghcr.io/viperproject/gobra@sha256:775879e8483561186291653d4c8a818c222eafd38f4b50a42d4b8873eebc9481`.
The runner verifies its RepoDigest and source/revision labels before execution
(source revision `d2c5af5450540c502855e53f4a5af1ba7630c41f`). Each case runs in its
own container with 3 GiB RAM, zero additional swap, two CPUs, user 1000:1000,
read-only root filesystem, no network, all capabilities dropped and
no-new-privileges. Only the generated run directory is bind-mounted read only;
temporary files use a bounded tmpfs. Settings are inspected before execution.
Only the exact containers created by this invocation are removed.

The external execution deadline is 180 seconds for `d1-parameters-wrong-index`
and 90 seconds for every other proof and native control. Silicon's assertion
timeout remains 5000 milliseconds. A deadline, OOM or abnormal container state
cannot satisfy a negative control, even when its log contains the expected
diagnostic. Execution failures include the observed state and log path.

`_build/results.json` and `_build/runs/*/results.json` record input hashes,
signature/body identity, tool pins, actual container settings, commands, terminal
state and proof outcomes. Logs and generated copies stay in the same run folder.
A source change during the run invalidates the result. These generated files are
local evidence, not files to commit.

[SafeCastRepresentation.ec](../easycrypt/models/SafeCastRepresentation.ec)
separately proves `typed_source_contract_refines_model`: under uint64 input and
int64 output representations, the three source postconditions uniquely determine
the reference result. Its int64-output premise has a separately checked Gobra
postcondition in this lane. The [EasyCrypt suite](../easycrypt/README.md) checks
that theorem separately.

The record-count quotient/remainder contract is paired with the separate
`CanonicalRecords.ec` model. Source-level verification and those mathematical
proofs retain their own input/output representation and toolchain assumptions.

This is maintained source-contract evidence plus conditional mathematical
representation lemmas. Go/Gobra frontend semantics, the constant-only math and
standard BE64/math-bits interfaces, the local alpha adapter, integer embeddings and cross-logic composition remain explicit
trusted or open obligations. It does not establish an automatic Go-to-EasyCrypt
simulation, caller correctness, filesystem behavior, cryptographic security or
whole-application refinement. Unit tests here protect proof-tooling policy and
source binding; they are not application-behavior coverage.
