# Frozen STREAM fixtures

These ciphertexts were generated independently of Picocrypt NG's framing code,
by the unmodified `internal/stream.NewWriter` in age v1.2.1, commit
`482cf6fc9babd3ab06f6606762aac10447222201` (BSD-3-Clause).
Reference: https://github.com/FiloSottile/age/tree/482cf6fc9babd3ab06f6606762aac10447222201/internal/stream
Framing: https://c2sp.org/age@v1.1.0#payload

Public test key: bytes 0,1,...,31. The plaintext for N.bin is N bytes,
with byte i equal to i modulo 251. The upstream writer receives that plaintext
in one Write and is then Closed. Files contain payload records only (no age
container or KDF). Picocrypt NG tests both ciphertext equality and decryption.
The generator runs inside the pinned upstream source tree; production neither
imports its internal package nor vendors its implementation.

SHA-256:

```
98082ff61f1317c757770e0ee5ec26bbe8f1d4d7c3f91e4755eb0622f630b8a7  0.bin
974a590d1345c7dfba24d5787d6d52812b8f2cdab825cf09a437a49a3f7600ef  1.bin
42933f4b43dcc78b2fcc7118853e0886382730ea72d916f307a62347d4d8fb3f  196608.bin
a7b0f4516b0fc860f60a63ffe58eee39ef67cf8c4ec94fc00c5e23a05b208938  65535.bin
f61daa204db332a9313296b89067b9f3db883b5a9d80de81b46f9b1e0a100034  65536.bin
f7c5f8501ffdc04e073e5e08dfcaf510b9f10610c832108b3cb963002b4427d9  65537.bin
```
