# Picocrypt NG PCV3 security contract

This maintainer document records the required native PCV3 behavior and the
evidence used to review it. New native encryption targets PCV3; supported legacy v1/v2
readers remain separate. Experimental PCV3 files have no compatibility promise.
The browser/WASM contract is unchanged and does not add PCV3 support.

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
containers are plaintext metadata and must not be treated as secrets.

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

## Platform and review gates

Native targets are Windows, Linux, macOS and 64-bit Android starting at Android
8/API 26. Filesystem capabilities must be checked independently of the Android
API level. A path check followed by an ordinary replacing rename is not an
acceptable no-replace publication primitive.

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
