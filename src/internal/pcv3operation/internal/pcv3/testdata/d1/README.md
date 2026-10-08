# Independent PCV3 D1 and Normal conformance fixtures

All passwords, keys, salts, nonces, plaintext, and containers here are public
TEST ONLY data. They must never be used for real encryption.

`reference/generate.py` is a standalone encoder; it imports no Picocrypt NG
implementation and reads no existing container. It independently assembles the
complete Paranoid Normal volume and D1 bootstraps/body from literal inputs.
Cryptographic implementations are argon2-cffi 25.1.0 (Argon2id), PyCryptodome
3.23.0 (XChaCha20), system libgcrypt (Serpent CTR), Python hashlib/HMAC
(SHA3/HKDF), and zfec 1.6.0.0 (Reed-Solomon). The generating libgcrypt version
and generator SHA-256 are recorded in `independent/manifest.json`.

The fixture uses a password and two ordered keyfiles, one short plaintext
record, an empty authenticated comment, and no payload RS. The inner Normal
volume still includes the mandatory capsule, metadata, descriptor and trailer
RS encodings. Both physical D1 bootstraps use distinct salts, nonces and IVs.
`randomness.json` records named public entropy inputs for the production writer
comparison; it is not an output from the production writer.
Every Argon2id call uses version 19, t=8, memory=1048576 KiB, p=8, output=32.

Reproduce into a NEW directory, from this directory:

```sh
uv run reference/generate.py /tmp/pcv3-independent-reproduction
```

Compare generated files against `independent/`; do not overwrite the frozen
oracle when changing production code. Generation runs three 1-GiB KDF calls
sequentially. Run the production reader lane serially from `src/`:

```sh
go test -count=1 -tags pcv3_production_kdf ./internal/pcv3operation/internal/pcv3 -run '^TestIndependent' -v
```

The tagged tests verify standalone Normal and full D1 exact plaintext through
real credential derivation, including D1 Force processing of both bootstraps.
The production full D1 writer, with only its entropy source made deterministic,
must emit exactly these independently authored bytes. This establishes the
opposite direction of compatibility without a current-writer round trip.
The tests also verify that changed passwords and changed, removed, or reordered
keyfiles produce no plaintext callback. Checksums freeze the independent bytes.
These fixtures cover the credential policy and payload geometry described above.
Existing Normal and legacy golden corpora remain separate and unchanged.
