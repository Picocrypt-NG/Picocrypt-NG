# /// script
# requires-python = ">=3.11"
# dependencies = ["argon2-cffi==25.1.0", "pycryptodome==3.23.0", "zfec==1.6.0.0"]
# ///
"""TEST ONLY independent small PCV3 Paranoid Normal/D1 encoder.

No Picocrypt NG code or existing volume bytes are imported. Three sequential
1-GiB Argon2id calls are required. Requires the system libgcrypt for Serpent.
Run: uv run generate.py OUTPUT_DIRECTORY (directory must not exist).
Deterministic keys/passwords here are public fixtures, never operational keys.
"""

import ctypes
import ctypes.util
import hashlib
import hmac
import json
import pathlib
import struct
import sys

from argon2.low_level import Type, hash_secret_raw
from Crypto.Cipher import ChaCha20
from zfec import Encoder

D = b"Picocrypt-NG/PCV3/"


def u16(n):
    return struct.pack(">H", n)


def u32(n):
    return struct.pack(">I", n)


def u64(n):
    return struct.pack(">Q", n)


def literal(label, size):
    return hashlib.shake_256(b"TEST ONLY independent D1/" + label.encode()).digest(size)


def mac(key, *parts):
    return hmac.new(key, b"".join(parts), hashlib.sha3_512).digest()


def extract(secret, salt):
    return hmac.new(salt, secret, hashlib.sha3_256).digest()


def expand(prk, label, role=255, size=32):
    info = (
        D
        + b"HKDF\0"
        + u16(3)
        + u16(1)
        + u16(2)
        + bytes([role])
        + u16(len(label))
        + label.encode()
    )
    return hmac.new(prk, info + b"\x01", hashlib.sha3_256).digest()[:size]


gcrypt = ctypes.CDLL(ctypes.util.find_library("gcrypt"))
gcrypt.gcry_check_version.restype = ctypes.c_char_p
gcrypt.gcry_check_version.argtypes = [ctypes.c_char_p]
GCRYPT_VERSION = gcrypt.gcry_check_version(None).decode()
gcrypt.gcry_cipher_map_name.argtypes = [ctypes.c_char_p]
gcrypt.gcry_cipher_map_name.restype = ctypes.c_int
gcrypt.gcry_cipher_open.argtypes = [
    ctypes.POINTER(ctypes.c_void_p),
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_uint,
]
gcrypt.gcry_cipher_setkey.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
gcrypt.gcry_cipher_setctr.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
gcrypt.gcry_cipher_encrypt.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_void_p,
    ctypes.c_size_t,
]
gcrypt.gcry_cipher_close.argtypes = [ctypes.c_void_p]


def serpent_ctr(data, key, iv):
    handle = ctypes.c_void_p()

    def check(code):
        if code:
            raise RuntimeError(f"libgcrypt error {code}")

    check(
        gcrypt.gcry_cipher_open(
            ctypes.byref(handle), gcrypt.gcry_cipher_map_name(b"SERPENT256"), 6, 0
        )
    )
    try:
        check(gcrypt.gcry_cipher_setkey(handle, key, len(key)))
        check(gcrypt.gcry_cipher_setctr(handle, iv, len(iv)))
        output = ctypes.create_string_buffer(len(data))
        check(gcrypt.gcry_cipher_encrypt(handle, output, len(data), data, len(data)))
        return output.raw
    finally:
        gcrypt.gcry_cipher_close(handle)


def wrap(data, xkey, nonce, skey, iv):
    return ChaCha20.new(key=xkey, nonce=nonce).encrypt(serpent_ctr(data, skey, iv))


def rs(data, k, n):
    assert len(data) % k == 0
    codec = Encoder(k, n)
    return b"".join(
        b"".join(codec.encode([bytes([x]) for x in data[i : i + k]]))
        for i in range(0, len(data), k)
    )


def kdf(value, salt):
    return hash_secret_raw(value, salt, 8, 1048576, 8, 32, Type.ID, version=19)


def make_normal(normal_input, plaintext):
    salt = literal("inner salt", 16)
    volume_id = literal("volume id", 32)
    volume_key = literal("volume key", 32)
    print("Argon2id inner (1/3)", flush=True)
    credential_root = kdf(normal_input, salt)
    credential_prk = extract(credential_root, volume_id)
    volume_prk = extract(volume_key, volume_id)
    xprefix, sprefix = literal("inner nonce", 16), literal("inner iv", 8)
    core = b"PCV\0" + u16(3) + u16(1) + u16(2) + u16(0) + u32(1112)
    core += (
        volume_id
        + bytes([1, 1, 1, 0])
        + u64(len(plaintext))
        + u64(1)
        + xprefix
        + sprefix
        + u32(0)
    )
    assert len(core) == 96
    commitment = hashlib.sha3_256(D + b"core\0" + core).digest()

    def capsule(role):
        nonce, iv = (
            literal(f"inner wrap nonce {role}", 24),
            literal(f"inner wrap iv {role}", 16),
        )
        encrypted = wrap(
            volume_key,
            expand(credential_prk, "credential/wrap/xchacha20", role),
            nonce,
            expand(credential_prk, "credential/wrap/serpent", role),
            iv,
        )
        prefix = (
            bytes([role, 3, 1, 2]) + u16(2) + b"\0\0" + salt + nonce + iv + encrypted
        )
        replica = mac(
            expand(volume_prk, "volume/replica/mac", role),
            D + b"replica\0",
            core,
            prefix,
        )
        tag = mac(
            expand(credential_prk, "credential/wrap/mac", role),
            D + b"wrap\0",
            core,
            prefix,
            replica,
        )
        return rs(core + prefix + replica + tag, 64, 192)

    metadata = b"PCVM" + u16(1) + u16(1) + bytes(8)
    metadata += mac(
        expand(volume_prk, "volume/metadata/mac"),
        D + b"metadata\0",
        commitment,
        metadata,
    )
    metadata = rs(metadata.ljust(128, b"\0"), 128, 136)
    ciphertext = wrap(
        plaintext,
        expand(volume_prk, "volume/payload/xchacha20"),
        xprefix + u64(0),
        expand(volume_prk, "volume/payload/serpent"),
        sprefix + u64(0),
    )
    records = b""
    for index, data in enumerate([ciphertext, b""]):
        descriptor = u64(index) + u32(len(data)) + bytes([index, 0, 0, 0])
        records += (
            rs(descriptor, 16, 48)
            + data
            + mac(
                expand(volume_prk, "volume/payload/mac"),
                D + b"record\0",
                commitment,
                descriptor,
                data,
            )
        )
    trailer = rs(b"PCVT" + u16(3) + u16(1) + u32(960) + u16(1) + bytes(2), 16, 48)
    return core[:16] + capsule(0) + metadata + records + capsule(1) + trailer


def make_d1(outer_input, inner):
    outer_key = literal("outer key", 32)
    outer_prk = extract(outer_key, hashlib.sha3_256(D + b"outer/root\0").digest())
    clear = b"PCVOUT3\0" + u64(len(inner)) + inner
    assert len(clear) < 1048576
    body = wrap(
        clear,
        expand(outer_prk, "outer/payload/xchacha20"),
        expand(outer_prk, "outer/payload/xnonce-prefix", size=16) + u64(0),
        expand(outer_prk, "outer/payload/serpent"),
        expand(outer_prk, "outer/payload/serpent-prefix", size=8) + u64(0),
    )
    body += mac(
        expand(outer_prk, "outer/payload/mac"),
        D + b"outer/record\0",
        u64(0),
        u32(len(body)),
        b"\x01",
        body,
    )
    bootstraps = []
    for role in range(2):
        salt, nonce, iv = (
            literal(f"outer salt {role}", 16),
            literal(f"outer nonce {role}", 24),
            literal(f"outer iv {role}", 16),
        )
        print(f"Argon2id outer role {role} ({role + 2}/3)", flush=True)
        prk = extract(kdf(outer_input, salt), salt)
        encrypted = wrap(
            outer_key + u64(len(body)),
            expand(prk, "outer/wrap/xchacha20", role),
            nonce,
            expand(prk, "outer/wrap/serpent", role),
            iv,
        )
        prefix = salt + nonce + iv + encrypted
        replica = mac(
            expand(outer_prk, "outer/replica/mac", role),
            D + b"outer/replica\0",
            bytes([role]),
            prefix,
        )
        tag = mac(
            expand(prk, "outer/wrap/mac", role),
            D + b"outer/wrap\0",
            bytes([role]),
            prefix,
            replica,
        )
        bootstraps.append(prefix + replica + tag)
    return bootstraps[0] + body + bootstraps[1]


def main():
    directory = pathlib.Path(sys.argv[1])
    directory.mkdir(parents=True, exist_ok=False)
    password = b"TEST ONLY D1 password"
    factors = [b"TEST ONLY alpha keyfile\n", b"TEST ONLY beta keyfile\n"]
    plaintext = b"Independent PCV3 D1 complete container. TEST ONLY.\n"
    transcript = bytes([1, 3, 1, 0]) + u32(len(password)) + password + u16(2)
    transcript += b"".join(
        hashlib.sha3_256(D + b"keyfile\0" + f).digest() for f in factors
    )
    normal_input = hashlib.sha3_512(D + b"credential/normal\0" + transcript).digest()
    outer_input = hashlib.sha3_512(D + b"credential/outer\0" + transcript).digest()
    normal = make_normal(normal_input, plaintext)
    d1 = make_d1(outer_input, normal)
    files = {
        "normal.pcv": normal,
        "d1.pcv": d1,
        "plaintext.bin": plaintext,
        "password.bin": password,
        "keyfile-alpha.bin": factors[0],
        "keyfile-beta.bin": factors[1],
    }
    # Public deterministic entropy inputs, named independently of writer call order.
    randomness = {
        label: literal(label, size).hex()
        for label, size in [
            ("outer salt 0", 16),
            ("outer salt 1", 16),
            ("outer nonce 0", 24),
            ("outer nonce 1", 24),
            ("outer iv 0", 16),
            ("outer iv 1", 16),
            ("inner salt", 16),
            ("volume id", 32),
            ("volume key", 32),
            ("outer key", 32),
            ("inner nonce", 16),
            ("inner iv", 8),
            ("inner wrap nonce 0", 24),
            ("inner wrap iv 0", 16),
            ("inner wrap nonce 1", 24),
            ("inner wrap iv 1", 16),
        ]
    }
    files["randomness.json"] = (json.dumps(randomness, indent=2) + "\n").encode()
    manifest = {
        "test_only": True,
        "generator_sha256": hashlib.sha256(
            pathlib.Path(__file__).read_bytes()
        ).hexdigest(),
        "libgcrypt_version": GCRYPT_VERSION,
        "kdf": {
            "algorithm": "Argon2id",
            "version": 19,
            "time": 8,
            "memory_kib": 1048576,
            "parallelism": 8,
            "output_bytes": 32,
        },
        "credential_mode": "password-and-keyfiles",
        "keyfile_mode": "ordered",
        "files": {},
    }
    for name, content in files.items():
        (directory / name).write_bytes(content)
        manifest["files"][name] = {
            "size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
