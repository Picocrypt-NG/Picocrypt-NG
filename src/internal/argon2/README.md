# Maintained Argon2 copy

This package copies only `golang.org/x/crypto/argon2` at **v0.58.0**, with
the upstream BSD license in `LICENSE`. `UPSTREAM.json` records the original
SHA-256 of every copied file. BLAKE2b and CPU detection remain dependencies of
the pinned upstream modules; this is not a copy of the entire crypto module.

The differences from that source are limited to:

- `argon2.go`: clear the original typed workspace after all workers join and
  output extraction finishes; clear the initial hash, initialization block,
  and extraction block after their last use. An optional private observer
  retains the original workspace for bounded regression tests; public `Key`
  and `IDKey` always pass nil.
- `blake2b.go`: clear the local expansion buffer after its last use.
  Modified production files follow repository import grouping; an extra upstream
  blank line is removed for the repository formatter.
- `argon2_test.go`: pass nil for the new private observer argument. The upstream
  known-answer values and vector tests are unchanged.
- `cleanup.go`, `cleanup_test.go`, and provenance files: local cleanup helper,
  regression tests, and maintenance information.

All upstream architecture-specific Go and assembly files are unchanged. The
algorithm, version, parameters, borrowed inputs, and independently allocated
output retain the upstream contract. Tests include the upstream frozen vectors
and independent comparisons against the pinned upstream public functions.

Cleanup uses typed `clear`, a noinline boundary, and `runtime.KeepAlive`, following
the shared `secret.SecureZero` pattern. This is best effort for the named buffers
on normal completion. It does not erase BLAKE2b internals, compression/assembly
scratch, registers, compiler/runtime copies, previous swap or dumps, or promise
cleanup after a panic, fatal OOM, process termination, or power loss.

Updating `golang.org/x/crypto` requires reviewing this copy against the new
upstream source, rebasing only these documented differences, and updating
`UPSTREAM.json`. Run the package vectors and cleanup/race checks, application
goldens and production KDF vectors, and supported-platform build lanes. Changes
to this maintained cryptographic code require human review before merge.
