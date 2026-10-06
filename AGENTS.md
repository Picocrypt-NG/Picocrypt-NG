# Important
These rules apply to every task in this project unless explicitly overridden.
Bias: caution over speed on non-trivial work. Use judgment on trivial tasks.

Security, correctness, prevention of data loss or plaintext/key leakage, on-disk
compatibility, and release integrity are hard constraints. When rules conflict,
prioritize: (1) safety, security, and data integrity; (2) explicit task
requirements; (3) public and on-disk contracts and backward compatibility;
(4) applicable sources of truth and verified codebase conventions; (5) simplicity
and minimal scope; (6) speed. A task changes an existing contract only when that
change is explicit and its compatibility or migration consequences are addressed.

## Rule 1 — Think Before Coding
State material assumptions explicitly.
Ask when ambiguity could materially change behavior, compatibility, security,
data, architecture, or acceptance criteria. For minor ambiguity, choose the
safest reasonable assumption, state it, and proceed.
Present multiple interpretations when they would lead to materially different work.
Push back when a simpler approach exists.
Stop when evidence is contradictory or insufficient. Name exactly what's unclear.

## Rule 2 — Simplicity First
Minimum code that solves the problem. Nothing speculative.
No features beyond what was asked. No abstractions for single-use code.
Test: would a senior engineer say this is overcomplicated? If yes, simplify.

## Rule 3 — Surgical Changes
Touch only what you must. Clean up only your own mess.
Don't "improve" adjacent code, comments, or formatting.
Don't refactor what isn't broken. Match existing style.

## Rule 4 — Goal-Driven Execution
Define observable success criteria and loop until they are verified.
Use a goal-oriented plan and adapt it based on verification results.
Follow mandatory security, compatibility, build, signing, and release procedures;
completing a checklist is not itself proof of success.

## Rule 5 — Prefer Executable Evidence
Use model judgment for interpretation, trade-offs, classification, design, and
communication. Use deterministic tools for deterministic questions.
Prefer repository search, parsers, compilers, tests, linters, and scripts over
memory or guesswork. If code can answer, code answers.

## Rule 6 — Token budgets are not advisory
If approaching budget, summarize and start fresh.
Try using subagents.
Surface the breach. Do not silently overrun.

## Rule 7 — Surface conflicts, don't average them
When patterns contradict, prefer the applicable source of truth, frozen-format
and golden compatibility evidence, public contracts, then the tested convention
of the affected module. Recency alone is not authority.
Explain the choice and flag the other pattern for later cleanup.
Do not blend incompatible patterns. Stop on unresolved security or compatibility
conflicts rather than inventing a third convention.

## Rule 8 — Read before you write
Before changing code, read the target, immediate callers and callees, relevant
tests, shared utilities, and the applicable source-of-truth documentation.
Trace affected success, failure, cleanup, and compatibility paths.
For format, credential, or bridge work, check every affected writer, reader, and
frontend boundary. "Looks orthogonal" is dangerous.

## Rule 9 — Tests Protect Production Risks
Every test must protect a named production behavior, invariant, compatibility
contract, or security/release policy and fail on a plausible regression of it.
Before adding a test, identify the system under test, the risk, the oracle, and
the execution lane. Use the lowest reliable level; add a higher-fidelity test
when the risk crosses a real filesystem, process, platform, or frontend boundary.
Make the protected risk and oracle clear through the test name, fixture, action,
and assertions; add a requirement or defect reference only when that intent is
not otherwise obvious.

Prefer production paths and independent or frozen expectations. For security
fixes, cover fail-closed, no-output, and cleanup behavior plus a positive or
compatibility case where applicable. Do not duplicate the production algorithm
as the oracle or add tests solely to increase coverage.

Do not count checks of mocks, prose, arbitrary line or item counts, dependency
versions, file presence, or a test harness as product-behavior coverage. Add such
checks only when that exact property is an explicit compatibility, supply-chain,
release, or audit contract, and classify them separately as tooling or policy
checks. Prefer compiling or executing a public path over scanning source text;
source-structure checks belong in lint/policy lanes and are justified only when
the structure itself is the enforceable contract. Likewise, tests of governance
or evidence tooling and future packages not reached by production entry points
do not establish current product coverage.

Do not delete, disable, or weaken a meaningful test merely to obtain a green
result. For a bug fix, add a regression test when practical and show that it
fails for the defective behavior. Use mutation testing selectively: a surviving
non-equivalent mutant is a candidate gap, not proof of a defect. Do not build a
custom mutation/evidence framework unless an explicit audit requirement justifies
it, and never count its self-tests as product coverage.

## Rule 10 — Checkpoint at Logical Boundaries
Checkpoint after understanding a non-trivial task, after a logical phase, before
a high-risk or irreversible action, after a failed check that changes the plan,
before expanding scope, and before completion.
State what changed, what was verified, exact failures or skips, what remains, and
any new risk. Do not checkpoint routine edits.

## Rule 11 — Match the codebase's conventions, even if you disagree
Conformance > taste inside the codebase.
If you genuinely think a convention is harmful, surface it. Don't fork silently.

## Rule 12 — Fail loud
Never claim broader validation than actually ran.
Report passed, failed, expected skipped, not run, blocked, and uncertain results
separately. An intentional platform or opt-in skip can be valid; a missing
required golden or security fixture is a failure, not a skip.
"Completed" is wrong while required work or verification remains.

# Repository Context
Picocrypt NG is a security-sensitive file encryption app. Treat correctness,
compatibility, privacy, and release integrity as first-class requirements.
Always say "Picocrypt NG" or "Picocrypt-NG" when referring to this project.

## Sources Of Truth
- `README.md`: user-facing product, platform, and feature description.
- `ARCHITECTURE.md`: package map, crypto data flow, audit-critical areas.
- `API.md`: internal API contracts for maintainers.
- `Internals.md`: cryptographic and volume-format details.
- `CLI.md`: command-line behavior and flags.
- `src/README.md`: desktop/CLI source build and Go test notes.
- `android/README.md`: native Android architecture, gomobile, signing, release notes.
- `VERSION`: root release version; keep lockstep with cmd/app/header constants,
  `src/FyneApp.toml`, packaging metadata, and release workflows.
- `Changelog.md`, `SIGNING.md`, `fastlane/`: release-facing metadata.

## Repository Map
- `src/`: main Go module. Honor `src/go.mod` for the required Go version and deps.
- `src/cmd/picocrypt/`: desktop GUI + CLI entry point.
- `src/cmd/wasm/`: browser/WASM entry point.
- `src/mobile/`: gomobile bindings used by the Android app.
- `src/internal/app/`: operation state and progress reporting.
- `src/internal/cli/`: Cobra CLI implementation.
- `src/internal/ui/`: Fyne desktop UI.
- `src/internal/wasm/`: browser bridge behavior and WASM feature limits.
- `src/internal/fileops/`: zip, split, recombine, unpack, path handling.
- `src/internal/encoding/`: Reed-Solomon and padding.
- `src/internal/diskspace/`, `src/internal/distmeta/`,
  `src/internal/workflowpolicy/`: platform, release, and CI policy support.
- `android/`: native Android app using Kotlin/Compose + gomobile AAR.
- `dist/`: tracked packaging metadata for Windows, macOS, Linux, Snap, Flatpak, MIME.
- `.github/workflows/`: release and PR validation workflows.

## Audit-Critical Code
These packages affect cryptography, encrypted volume semantics, or plaintext publication:
- `src/internal/crypto/`
- `src/internal/header/`
- `src/internal/keyfile/`
- `src/internal/volume/`
- `src/internal/pcv3operation/`, including its private implementation packages
- `src/internal/pcv3publication/`, `src/internal/pcv3result/`
- `src/internal/secret/`

For changes there, read immediate callers and relevant docs first. Preserve v1/v2
compatibility, golden vectors, deniability semantics, keyfile behavior, Reed-Solomon
behavior, and verify-first behavior. Use crypto-secure randomness, constant-time
MAC comparison, explicit sensitive-memory zeroing, and existing cleanup patterns.
Never rely on AI confidence for a cryptographic decision.
All audit-critical changes require human review before merge.

Password normalization, Reed-Solomon and padding, archive/path/staging cleanup,
and desktop/CLI/WASM/mobile credential bridges are also security-sensitive when
touched, even when they do not directly define encrypted volume semantics.

## Platform And Feature Notes
- Desktop GUI uses Fyne; CLI-only builds use the `cli` tag.
- Web/WASM is an in-memory bridge (`src/cmd/wasm/`, `src/internal/wasm/`)
  with its own feature contract and a 1 GiB input guard. Check code and tests
  before assuming parity or limits; file/folder/streaming/splitting need bridge
  changes. Account for JS/runtime copy limits when discussing zeroing.
- Android is a native app under `android/`; rebuild the gomobile AAR after Go bridge
  changes. Passwords cross Kotlin to Go as bytes, but Go operation internals may use
  strings as documented.
- Comments stored in volumes are plaintext header data; never describe them as
  secret. Current v2 header auth covers comments, but verify version/format nuance
  before making authentication claims.
- Deniability changes are high risk: random-looking output, comment behavior, manual
  naming, and mode interactions are part of the user-visible contract.
- File associations and packaging metadata are release behavior, not cosmetic files.

## Common Commands
Run commands from `src/` unless noted.
- Default Go suite (serialize KDF-heavy packages): `go test -p 1 -tags migrated_fynedo ./...`
- Separate PCV3 production-KDF checks: `go test -count=1 -p 1 -tags pcv3_production_kdf ./internal/pcv3operation/...`
- Golden compatibility: `go test -count=1 -run '^TestGolden' ./internal/volume`
- CLI package: `go test ./internal/cli`
- Opt-in CLI integration: `PICOCRYPT_RUN_CLI_INTEGRATION=1 go test ./internal/cli`
- Race-sensitive Go work: `CGO_ENABLED=1 go test -tags migrated_fynedo -race -p 1 -timeout 15m ./...`
- Desktop build: `CGO_ENABLED=1 go build -tags migrated_fynedo -ldflags="-s -w" -o Picocrypt-NG ./cmd/picocrypt`
- CLI-only build: `CGO_ENABLED=1 go build -tags cli -ldflags="-s -w" -o Picocrypt-NG-cli ./cmd/picocrypt`
- Android gomobile AAR from `android/`: `./build-gomobile.sh`
- Android app from `android/`: `./build-app`

## Change Discipline
- Make surgical changes. Do not refactor crypto, UI, Android, or packaging while
  solving an unrelated issue.
- When documentation, executable config, and code disagree, apply the Sources Of
  Truth and compatibility evidence above. Current behavior is evidence, not
  automatically intended behavior. Surface the conflict.
- For release/version work, check `VERSION`, `src/cmd/picocrypt/main.go`,
  `src/internal/app/state.go`, `src/internal/header/format.go`,
  `src/internal/distmeta`, packaging metadata, changelog, and workflows together.
- For dependency or library/API questions, use Context7 docs first as required above.
- Keep generated/local artifacts out of commits: build outputs, gomobile AARs unless
  explicitly intended, local signing material, IDE files, and AI-agent state.
- Never include private PCV3 specifications or local planning/AI-agent artifacts in
  GitHub-bound history.
- Do not commit, push, merge, tag, or publish unless explicitly requested. Before
  any authorized publication, inspect the exact outgoing commits and tree for
  secrets, private material, generated artifacts, and unrelated changes.
- If a validation command cannot run, say exactly which command was skipped and why.
