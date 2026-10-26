# Picocrypt NG PCV3 security contract

This maintainer document records the required PCV3 behavior and the
evidence used to review it. New encryption targets PCV3; supported legacy v1/v2
readers remain separate. Experimental PCV3 files have no compatibility promise.
The browser/WASM bridge creates PCV3 and reads supported PCV1/PCV2/PCV3 volumes
in memory. Its feature, size and resource limits are defined separately in
[`API.md`](../API.md#pcv3-operation-boundary).

## Threat model

The application processes attacker-controlled containers, filenames, archive
entries and filesystem races. Storage can fail during writing, closing,
publication or directory synchronization. Android document providers can reject
operations or expose unsupported descriptors. Cancellation can race publication.

The operating system, application binary, randomness source and endpoint while
credentials are in use must be trusted. Secret factors must have sufficient
entropy: known or predictable keyfiles permit offline guessing. PCV3 does not
provide sender identity, external rollback detection, protection after endpoint
compromise, or reliable erasure from SSDs, snapshots and backups. In-memory
zeroing limits the lifetime of owned buffers; it cannot erase copies made by
runtimes or external components.

D1 provides a random-looking container with explicitly selected decoding. It
does not promise anonymity, hidden volumes, size hiding, plausible explanations
for filesystem metadata, or protection against coercion. Comments in ordinary
containers are plaintext metadata and must not be treated as secrets. D1 metadata,
including comments, is encrypted and has no pre-authentication comment preview.

The desktop may display a bounded Normal front-header comment and factor-policy
hint before decryption. Both are explicitly unverified claims and grant no
output, publication, archive or source-deletion authority. A confirmed comment
comes only from the current retained authenticated reader result; the preview is
never promoted. No released comment means the old preview is cleared. Reader
authentication is independent of subsequent publication durability. Exact
factor-policy diagnostics describe header requirements and selected counts, not
which password or keyfile content is wrong.

## Required properties and evidence

| Required property | Evidence that protects it |
| --- | --- |
| Every selected factor protects both D1 layers | Independent full-container vectors and changed, removed and reordered factor cases |
| Unknown parameters and impossible lengths fail before KDF or large allocation | Parser and admission negative cases through production entry points |
| Empty keyfiles are refused for new PCV3 output before KDF | Writer tests with an empty factor and an instrumented KDF boundary; legacy golden reads unchanged |
| Resource shortage never lowers the fixed Argon2id profiles | Admission refusal tests, plus a separate successful real-KDF run without skips |
| Ordinary plaintext appears only after complete authentication | Header, record, final-block, truncation and trailing-data mutations; no published plaintext on failure |
| Unverified Force requires separate consent and cannot become authenticated success | Consent lifecycle and typed-result tests, including cancellation and stale capability use |
| Publication cannot overwrite an existing or competing object | Real filesystem collision and path-substitution tests on each supported OS |
| A result refers to the exact output object | Held-descriptor transfer tests for Normal and D1, stdout and Android provider handoff |
| Source deletion follows the whole operation result | Warning, uncertain, indeterminate, split, archive and cleanup failure tests |
| Secrets and private staging have explicit owners | Cancellation, fault-injection and cleanup tests at real file/process/frontend boundaries |
| Legacy reading remains compatible | Uncached v1/v2 goldens, including keyfile-only deniability with an empty outer password |

The primitive choices, key sizes, domain separation and fixed KDF profiles are
preserved during architecture changes. A cryptographic defect requires a
separate design decision and independent review; a structural refactor is not
authorization to silently alter the construction.

## Recovery trust

`ForcePartial` means the file is not fully verified; data may be missing or
unverified. A damaged or missing final record can make the result incomplete
even when every emitted data range verifies. `ForceUnverified` means integrity
of the whole result is not confirmed; individual inner ranges or the final
record can still verify. Native forensic artifacts retain the exact range and
final states. Frontends must not infer specific missing or unverified bytes
from the whole-result outcome alone.

D1C selected without an outer-record anchor, or using an unauthenticated suite
hint, retains `raw-selected` provenance and the whole result remains unverified.
Later inner MAC success cannot promote that authority. Native paths use the
separate forensic artifact, preserve sources, and grant no ordinary plaintext,
auto-extraction or automatic parsing authority. The browser instead returns
recovered bytes in memory with code `10`, without the native artifact or a
per-range verification report. Those bytes remain untrusted and must not be
automatically opened or parsed. Unverified recovery requires separate consent
and an explicit physical role. Authenticated recovery may return an ordinary
result only under its complete verification contract.

Cryptographic authentication applies to semantic bytes. The systematic fast
RS path may leave parity-only damage unchecked; neither ordinary opening nor
strict `VerifyD1` promises authentication or a full scrub of every physical
byte. Ordinary D1 opening can leave the tail bootstrap unchecked; strict
verification checks both. The construction and frozen password profile are
defined in [Internals.md](../Internals.md#pcv3-cryptography); ownership and
verification report semantics are defined in
[API.md](../API.md#pcv3-operation-boundary).

## Publication and source retention

| Publication state | Result and allowed cleanup |
| --- | --- |
| Not published | No completed output; clean only temporary objects owned by this operation |
| Published durably | Output is available; deletion may be authorized only after every follow-up completes and only when requested by the user |
| Published, durability uncertain | Output remains available with a warning; preserve all sources |
| Publication indeterminate | No ordinary success, repeated publication, rollback or source deletion |

A nil error alone never authorizes source deletion. The common operation owns
that decision and must account for warnings and all follow-ups. Splitting keeps
the full container until every part has confirmed durable publication. A
successful copy to an Android provider proves the handoff completed, not the
durability of the provider's backing storage. Failed ciphertext handoff retains
the exact output for another destination; private plaintext has a separate
cleanup obligation.

## Filesystem ownership and limits

Common ZIP extraction retains cleanup obligations for newly created stages and
directories even when post-creation metadata cannot be read. Both legacy and typed
extractors report `ErrUnpackCleanupIncomplete` when absence of owned residue
cannot be proven. They retain the first observed directory identity and refuse
missing or substituted owned directories. Unknown identity does not authorize
pathname removal; held stage handles are still closed. Cleanup uncertainty does
not itself establish retained plaintext or determine publication state.

Desktop source deletion remains off by default and subject to the existing
whole-operation, kept/unverified and `SourceDeletionAllowed` guards. It removes
only captured sources and empty captured directories. Each removal checks the
captured identity and metadata and removes the basename through one held
immediate parent, preserving ready output and deletion warnings on failure.
Cancellation stops further removal; missing-source success cannot hide a parent
close error. Recombine-with-delete passes the same captured chunk identities
and sizes to the reader, including its prepared chunk-zero descriptor. The
borrowed metadata stays immutable and budgeted through execution and deletion;
it adds no retained per-chunk handles.

Original inputs must remain quiescent from selection through reading and any
requested deletion. Captured metadata is not a byte snapshot and cannot freeze
same-inode writes. Filesystem races remain in scope: pinned parents prevent
later ancestor-path substitution from redirecting the removal, but the final
identity check and leaf removal are separate effects. There is no atomic POSIX
expected-inode unlink guarantee; a leaf substitution between those effects
remains a risk. Endpoint trust does not eliminate this residual race.

These improvements do not cover `StagedFile.RemoveSiblingDirectory` or
`removeOwnedAutoUnzipArchiveAt`; common extraction changes do not harden those
external cleanup paths. They also do not add general Windows exact-source
handles, optional ACL admission, full crash recovery or physical erasure.
Native platform and performance validation remain separate review gates; these
contracts do not establish that every filesystem finding has been resolved.

## Platform and review gates

Native targets are Windows, Linux, macOS and Android starting at Android
8/API 26, with `armeabi-v7a`, `arm64-v8a`, `x86` and `x86_64` APKs. Android
installation support does not guarantee sufficient memory for the fixed 1 GiB
KDF. Per-operation admission may refuse a supported device; 32-bit workspace
segmentation does not guarantee allocation under fragmentation.
Filesystem capabilities must be checked independently of the Android
API level. A path check followed by an ordinary replacing rename is not an
acceptable no-replace publication primitive.

Browser D1 reading requires explicit selection, and Force output remains
unverified. The site must use a fresh worker for each operation, terminate it on
every result or failure, and restore its UI on worker failure. Bounded address
space checks do not guarantee physical RAM; browser OOM may terminate a worker.
The separately deployed website requires checks of its actual built artifact.

Readiness requires real operations on Windows, Linux and macOS (including its
CGO branch), Android API 26 and a current API, and a physical ARM64 phone with
4–6 GiB RAM. Cross-platform creation/opening must compare the original bytes.
Cross-compilation and emulator results cannot replace physical or native OS
evidence. A skipped positive KDF test cannot satisfy a successful-KDF gate.

Review must identify the exact source revision or diff, applicable vectors,
commands and results, failures, expected skips, checks not run, and remaining
limitations. Measure KDF cost separately from file processing, throughput,
allocations and peak memory on the same hardware before and after changes.
Preserve the Reed-Solomon allocation guard and explain any reproducible
performance regression without weakening protection parameters.

The 2024 upstream audit covered commit `7e403a2`. Subsequent v2 changes and PCV3
have separate review scopes. Maintainer review records should identify the
exact cryptographic diff and reviewer. Publication is a separate action with
inspection of the exact outgoing history and artifacts.
