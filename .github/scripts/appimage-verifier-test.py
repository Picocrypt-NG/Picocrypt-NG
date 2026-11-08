"""Release-tooling coverage using an independently signed public AppImage."""

import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / ".github/scripts"
TOOLCHAIN = ROOT / ".github/toolchains/appimage-verifier"
BASH = shutil.which("bash")
FIXTURE_SHA = "ce60140f143b8ad577d89e401c3b6b97a884d1d0a0b5e344cd887f8d2408a7a8"
FIXTURE_URL = "https://github.com/Picocrypt-NG/Picocrypt-NG/releases/download/2.18/Picocrypt-NG-2.18-x86_64.AppImage"
RELEASE_FINGERPRINT = "40D552749B0EB548C79D79F22DD93FE75B45D97F"
OTHER_FINGERPRINT = "E4EC9E0377F2D307F1319E26F1F5FE456F2DFA6B"


def fetch_fixture(variable, url, digest, destination):
    if variable in os.environ:
        source = Path(os.environ[variable])
        if not source.is_file():
            raise AssertionError(f"Required fixture is missing: {source}")
        shutil.copyfile(source, destination)
    else:
        with urllib.request.urlopen(url, timeout=120) as response, destination.open("wb") as output:
            shutil.copyfileobj(response, output)
    actual = hashlib.sha256(destination.read_bytes()).hexdigest()
    if actual != digest:
        raise AssertionError(f"Required fixture SHA-256 mismatch: {destination}")


class AppImageArchiveTests(unittest.TestCase):
    def test_directory_filter_reentry_accepts_one_header_and_refuses_real_duplicates(self):
        for duplicate in ("", "AppDir/usr", "AppDir//usr", "AppDir/./usr"):
            with self.subTest(duplicate=duplicate), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                archive = work / "AppDir.tar"
                with tarfile.open(archive, "w") as output:
                    for name, kind in (("AppDir", tarfile.DIRTYPE),
                                       ("AppDir/usr", tarfile.DIRTYPE),
                                       ("AppDir/usr/application", tarfile.REGTYPE)):
                        member = tarfile.TarInfo(name)
                        member.mode, member.type = 0o755, kind
                        output.addfile(member)
                    if duplicate:
                        member = tarfile.TarInfo(duplicate)
                        member.mode, member.type = 0o755, tarfile.DIRTYPE
                        output.addfile(member)
                destination = work / "unpacked"
                result = subprocess.run([sys.executable, str(SCRIPTS / "extract-appimage-appdir.py"),
                                         str(archive), str(destination)], capture_output=True,
                                        text=True, timeout=30, check=False)
                self.assertEqual(result.returncode == 0, not duplicate, result.stdout + result.stderr)
                if duplicate:
                    self.assertFalse(destination.exists(), "Duplicate archive left signing input")
                else:
                    self.assertTrue((destination / "AppDir/usr/application").is_file())

    def test_signing_input_rejects_escapes_and_duplicate_aliases_before_secrets(self):
        cases = (
            ("application", "AppDir/AppRun", "", "", tarfile.REGTYPE, True),
            ("parent traversal", "AppDir/../../outside", "", "", tarfile.REGTYPE, False),
            ("absolute path", "/outside", "", "", tarfile.REGTYPE, False),
            ("external symlink", "AppDir/AppRun", "../../outside", "", tarfile.SYMTYPE, False),
            ("external hardlink", "AppDir/AppRun", "../outside", "", tarfile.LNKTYPE, False),
            ("duplicate path", "AppDir/value", "", "AppDir/value", tarfile.REGTYPE, False),
            ("duplicate repeated separator", "AppDir/value", "", "AppDir//value", tarfile.REGTYPE, False),
            ("duplicate dot segment", "AppDir/value", "", "AppDir/./value", tarfile.REGTYPE, False),
        )
        for name, path, link, second, kind, want_ok in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                work = Path(temporary)
                archive = work / "AppDir.tar"
                with tarfile.open(archive, "w") as output:
                    for member_name in (path, second) if second else (path,):
                        member = tarfile.TarInfo(member_name)
                        member.mode, member.type, member.linkname = 0o755, kind, link
                        output.addfile(member)
                destination = work / "unpacked"
                result = subprocess.run([sys.executable, str(SCRIPTS / "extract-appimage-appdir.py"),
                                         str(archive), str(destination)], capture_output=True,
                                        text=True, timeout=30, check=False)
                self.assertEqual(result.returncode == 0, want_ok, result.stdout + result.stderr)
                if want_ok:
                    self.assertTrue((destination / "AppDir/AppRun").is_file())
                else:
                    self.assertFalse(destination.exists(), "Rejected archive left partial signing input")
                self.assertFalse((work / "outside").exists(), "Archive wrote outside AppDir")


class AppImageSignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="picocrypt-appimage-tests-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.base = Path(cls.temporary.name)
        cls.fixture = cls.base / "published-2.18.AppImage"
        fetch_fixture("PICOCRYPT_APPIMAGE_TEST_FIXTURE", FIXTURE_URL, FIXTURE_SHA, cls.fixture)
        cls.seed_cache = cls.base / "seed-cache"
        if cache := os.environ.get("PICOCRYPT_APPIMAGE_TEST_CACHE"):
            shutil.copytree(cache, cls.seed_cache, symlinks=True)
        cls.seed_env = os.environ | {"XDG_CACHE_HOME": str(cls.seed_cache)}
        installed = subprocess.run([BASH, str(SCRIPTS / "install-appimage-verifier.sh")],
                                   env=cls.seed_env, capture_output=True, text=True, timeout=1200, check=False)
        if installed.returncode != 0:
            raise AssertionError(installed.stdout + installed.stderr)
        if not re.fullmatch(r"sha256:[0-9a-f]{64}\n", installed.stdout):
            raise AssertionError(f"Installer returned unexpected output: {installed.stdout}")
        cls.image_id = installed.stdout.strip()
        cls.source_lock = json.loads((TOOLCHAIN / "sources.lock.json").read_text())
        cls.original = cls.fixture.read_bytes()
        # Frozen offsets belong to the hash-pinned public fixture, not a local signing algorithm.
        assert cls.original[0xE3D10:].startswith(b"-----BEGIN PGP SIGNATURE-----")
        assert cls.original[0xE4110:].startswith(b"-----BEGIN PGP PUBLIC KEY BLOCK-----")
        assert cls.original[0xE69F8:0xE69FC] == b"hsqs"

    def setUp(self):
        self.assertTrue((SCRIPTS / "verify-appimage.sh").is_file(), "AppImage signature wrapper is missing")
        self.case = tempfile.TemporaryDirectory(dir=self.base)
        self.addCleanup(self.case.cleanup)
        self.directory = Path(self.case.name)
        shutil.copytree(self.seed_cache, self.directory / "cache", symlinks=True)
        self.cache = self.directory / "cache/picocrypt-ng/appimage-verifier"
        self.cached_blob = self.cache / "blobs" / f"{self.source_lock['archives'][0]['sha256']}.blob"
        self.runtime = self.directory / "runtime"
        self.runtime.mkdir(mode=0o700)
        self.env = os.environ | {
            "XDG_CACHE_HOME": str(self.directory / "cache"),
            "TMPDIR": str(self.runtime),
        }

    def invoke(self, fixture=None, *, scripts=SCRIPTS, env=None, extra=()):
        result = subprocess.run(
            [BASH, str(scripts / "verify-appimage.sh"), str(fixture or self.fixture), *extra],
            env=env or self.env, capture_output=True, text=True, timeout=1200, check=False,
        )
        self.assertEqual(list(self.runtime.iterdir()), [], "Verifier left temporary code/keyring behind")
        return result

    def reject(self, name, content, diagnostic="Signature checked for key with fingerprint 2DD93FE75B45D97F: error"):
        fixture = self.directory / f"{name}.AppImage"
        fixture.write_bytes(content)
        fixture.chmod(0o644)
        positive = self.invoke()
        self.assertEqual(positive.returncode, 0, positive.stdout + positive.stderr)
        result = self.invoke(fixture)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(diagnostic, result.stderr)
        self.assertNotIn("Verified AppImage signer:", result.stdout)
        positive = self.invoke()
        self.assertEqual(positive.returncode, 0, positive.stdout + positive.stderr)

    def test_genuine_published_fixture_requires_the_documented_signer(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, f"Verified AppImage signer: {RELEASE_FINGERPRINT}\n")

    def test_authenticated_squashfs_tampering_is_rejected(self):
        changed = bytearray(self.original)
        changed[0xE69F8 + 128] ^= 1
        self.reject("tampered-payload", changed)

    def test_empty_signature_is_rejected(self):
        changed = bytearray(self.original)
        changed[0xE3D10:0xE4110] = bytes(0x400)
        self.reject("empty-signature", changed, "Error: AppImage not signed")

    def test_corrupt_signature_with_an_ambiguous_verifier_error_is_a_tool_fault(self):
        changed = bytearray(self.original)
        changed[0xE3D10 + 100] ^= 1
        fixture = self.directory / "corrupt-signature.AppImage"
        fixture.write_bytes(changed)
        positive = self.invoke()
        self.assertEqual(positive.returncode, 0, positive.stdout + positive.stderr)
        result = self.invoke(fixture)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("unexpected error", result.stderr)
        self.assertNotIn("Verified AppImage signer:", result.stdout)
        positive = self.invoke()
        self.assertEqual(positive.returncode, 0, positive.stdout + positive.stderr)

    def test_parseable_corrupted_signature_value_is_a_crypto_refusal(self):
        home = self.directory / "format-keyring"
        home.mkdir(mode=0o700)
        armored = self.directory / "original-signature.asc"
        armored.write_bytes(self.original[0xE3D10:0xE4110].split(b"\0", 1)[0])
        binary = self.directory / "signature.bin"
        command = ["gpg", "--batch", "--no-options", "--homedir", str(home)]
        converted = subprocess.run([*command, "--output", str(binary), "--dearmor", str(armored)],
                                   capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(converted.returncode, 0, converted.stderr)
        before = subprocess.run([*command, "--list-packets", str(binary)], capture_output=True,
                                text=True, timeout=30, check=False)
        self.assertEqual(before.returncode, 0, before.stderr)
        self.assertEqual(before.stdout.count(":signature packet:"), 1)
        packet = bytearray(binary.read_bytes())
        packet[-1] ^= 1
        binary.write_bytes(packet)
        after = subprocess.run([*command, "--list-packets", str(binary)], capture_output=True,
                               text=True, timeout=30, check=False)
        self.assertEqual(after.returncode, 0, after.stderr)
        self.assertEqual(after.stdout, before.stdout, "Corruption changed packet or issuer metadata")
        changed_armor = self.directory / "corrupted-signature.asc"
        converted = subprocess.run([*command, "--output", str(changed_armor), "--enarmor", str(binary)],
                                   capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(converted.returncode, 0, converted.stderr)
        signature = changed_armor.read_bytes()
        self.assertLessEqual(len(signature), 0x400)
        changed = bytearray(self.original)
        changed[0xE3D10:0xE4110] = signature.ljust(0x400, b"\0")
        self.reject("corrupted-signature-value", changed)

    def test_replaced_embedded_key_cannot_authorize_the_release(self):
        changed = bytearray(self.original)
        other_key = (TOOLCHAIN / "testdata/other-signing-key.asc").read_bytes()
        self.assertLessEqual(len(other_key), 0x2000)
        key_home = self.directory / "inspect-key"
        key_home.mkdir(mode=0o700)
        key_info = subprocess.run(
            ["gpg", "--batch", "--no-options", "--homedir", str(key_home), "--show-keys", "--with-colons",
             str(TOOLCHAIN / "testdata/other-signing-key.asc")],
            capture_output=True, text=True, timeout=30, check=False,
        )
        self.assertEqual(key_info.returncode, 0, key_info.stderr)
        self.assertIn(f"fpr:::::::::{OTHER_FINGERPRINT}:", key_info.stdout)
        changed[0xE4110:0xE6110] = other_key.ljust(0x2000, b"\0")
        self.reject("replaced-key", changed, "warningkey missing")

    def test_truncated_authenticated_payload_is_rejected(self):
        self.reject("truncated-payload", self.original[:-1])

    def test_truncated_elf_header_is_a_tool_fault(self):
        fixture = self.directory / "truncated-header.AppImage"
        fixture.write_bytes(self.original[:64])
        result = self.invoke(fixture)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("validator tool or runtime failed", result.stderr)
        self.assertNotIn("Verified AppImage signer:", result.stdout)

    def configured_copy(self):
        scripts = self.directory / "configured/.github/scripts"
        scripts.mkdir(parents=True)
        toolchain = scripts.parent / "toolchains/appimage-verifier"
        toolchain.parent.mkdir(parents=True)
        shutil.copytree(TOOLCHAIN, toolchain)
        for name in ("install-appimage-verifier.sh", "verify-appimage.sh"):
            shutil.copyfile(SCRIPTS / name, scripts / name)
        return scripts, toolchain / "manifest.json"

    def test_valid_signature_from_the_wrong_expected_signer_is_rejected(self):
        scripts, manifest_path = self.configured_copy()
        manifest = json.loads(manifest_path.read_text())
        manifest["expected_fingerprint"] = OTHER_FINGERPRINT
        manifest_path.write_text(json.dumps(manifest))
        result = self.invoke(scripts=scripts)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("does not match expected", result.stderr)

    def test_missing_source_lock_pin_fails_closed(self):
        scripts, manifest_path = self.configured_copy()
        manifest = json.loads(manifest_path.read_text())
        del manifest["sources_sha256"]
        manifest_path.write_text(json.dumps(manifest))
        result = self.invoke(scripts=scripts)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("manifest", result.stderr)

    def test_package_lock_pin_mismatch_is_rejected(self):
        scripts, manifest_path = self.configured_copy()
        manifest = json.loads(manifest_path.read_text())
        manifest["packages_sha256"] = "0" * 64
        manifest_path.write_text(json.dumps(manifest))
        result = self.invoke(scripts=scripts)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("checksum mismatch", result.stderr)

    def test_mutable_package_source_is_rejected_before_cache_use(self):
        scripts, manifest_path = self.configured_copy()
        lock_path = manifest_path.with_name("os-packages.lock.json")
        lock = json.loads(lock_path.read_text())
        package = lock["packages"][0]
        package["url"] = "https://archive.ubuntu.com/ubuntu/pool/" + package["url"].split("/pool/", 1)[1]
        lock_path.write_text(json.dumps(lock))
        manifest = json.loads(manifest_path.read_text())
        manifest["packages_sha256"] = hashlib.sha256(lock_path.read_bytes()).hexdigest()
        manifest_path.write_text(json.dumps(manifest))
        result = self.invoke(scripts=scripts)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("invalid package lock", result.stderr)

    def test_corrupt_cached_source_is_never_executed(self):
        marker = self.directory / "unverified-code-ran"
        self.cached_blob.write_text(f"#!/bin/sh\ntouch '{marker}'\n")
        self.cached_blob.chmod(0o700)
        result = self.invoke()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("checksum", result.stderr)
        self.assertFalse(marker.exists(), "Unverified cached code ran")

    def test_cached_extracted_code_is_ignored(self):
        cached_executable = self.cache / "squashfs-root/usr/bin/validate"
        cached_executable.parent.mkdir(parents=True)
        marker = self.directory / "cached-code-ran"
        cached_executable.write_text(f"#!/bin/sh\ntouch '{marker}'\nexit 0\n")
        cached_executable.chmod(0o700)
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(marker.exists(), "Cached extracted code ran")

    def test_missing_docker_is_a_failure(self):
        commands = self.directory / "bin"
        commands.mkdir()
        for name in ("bash", "dirname", "realpath", "jq", "timeout", "sha256sum", "mktemp", "cp", "chmod", "rm", "awk", "uname", "mkdir", "curl", "mv", "cat", "grep"):
            path = shutil.which(name)
            if path:
                (commands / name).symlink_to(path)
        result = self.invoke(env=self.env | {"PATH": str(commands)})
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("docker", result.stderr)

    def test_input_cannot_override_the_trusted_fingerprint_or_verifier(self):
        result = self.invoke(extra=(OTHER_FINGERPRINT,))
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("Usage:", result.stderr)

    def test_missing_input_fails_instead_of_being_skipped(self):
        result = self.invoke(self.directory / "missing.AppImage")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_installer_returns_a_scratch_image_id_with_the_fixed_runtime(self):
        result = subprocess.run(
            [BASH, str(SCRIPTS / "install-appimage-verifier.sh")], env=self.env,
            capture_output=True, text=True, timeout=1200, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertRegex(result.stdout, r"^sha256:[0-9a-f]{64}\n$")
        image = subprocess.run(["docker", "image", "inspect", result.stdout.strip()],
                               capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(image.returncode, 0, image.stderr)
        config = json.loads(image.stdout)[0]["Config"]
        self.assertEqual(config["User"], "65532:65532")
        self.assertEqual(config["Entrypoint"], ["/usr/local/bin/validate"])
        self.assertEqual(config["Cmd"], ["/input/AppImage"])

    def test_symlinked_cached_source_is_rejected(self):
        target = self.directory / "valid-source.blob"
        self.cached_blob.replace(target)
        self.cached_blob.symlink_to(target)
        result = self.invoke()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("not a regular file", result.stderr)

    def docker_observer(self, *, fail_start=False):
        commands = self.directory / "observe-docker"
        commands.mkdir()
        record = self.directory / "container-created.json"
        real_docker = shlex.quote(shutil.which("docker"))
        observer = commands / "docker"
        transport_failure = (f"elif [[ $1 == start ]]; then exec {real_docker} --host "
                             f"{shlex.quote('unix://' + str(self.directory / 'missing-engine.sock'))} \"$@\"; "
                             if fail_start else "")
        observer.write_text(
            "#!/usr/bin/env bash\nset -euo pipefail\n"
            f"if [[ $1 == create ]]; then\n  cid=$({real_docker} \"$@\")\n"
            f"  {real_docker} inspect \"$cid\" > {shlex.quote(str(record))}\n"
            "  printf '%s\\n' \"$cid\"\n"
            + transport_failure + f"else exec {real_docker} \"$@\"; fi\n"
        )
        observer.chmod(0o700)
        return self.env | {"PATH": str(commands) + os.pathsep + os.environ["PATH"]}, record

    def test_docker_transport_failure_is_not_a_signature_refusal(self):
        positive = self.invoke()
        self.assertEqual(positive.returncode, 0, positive.stdout + positive.stderr)
        env, record = self.docker_observer(fail_start=True)
        result = self.invoke(env=env)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertNotIn("Verified AppImage signer:", result.stdout)
        cid = json.loads(record.read_text())[0]["Id"]
        remaining = subprocess.run(["docker", "inspect", cid], capture_output=True, text=True, check=False)
        self.assertNotEqual(remaining.returncode, 0, "Failed transport left its owned container")

    def test_build_failure_is_not_a_signature_refusal(self):
        scripts, manifest = self.configured_copy()
        dockerfile = manifest.parent / "Dockerfile"
        dockerfile.write_text(dockerfile.read_text().replace("RUN sha256sum", "RUN exit 17\nRUN sha256sum", 1))
        result = self.invoke(scripts=scripts)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("verifier setup failed", result.stderr)
        self.assertNotIn("Verified AppImage signer:", result.stdout)

    def test_runtime_isolates_the_untrusted_image_parser(self):
        env, record = self.docker_observer()
        result = self.invoke(env=env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        container = json.loads(record.read_text())[0]
        host = container["HostConfig"]
        self.assertEqual(container["Config"]["User"], "65532:65532")
        self.assertTrue(host["ReadonlyRootfs"])
        self.assertEqual(host["NetworkMode"], "none")
        self.assertEqual(host["CapDrop"], ["ALL"])
        self.assertIn("no-new-privileges", host["SecurityOpt"])
        self.assertEqual((host["Memory"], host["MemorySwap"]), (536870912, 536870912))
        self.assertEqual(host["PidsLimit"], 64)
        self.assertEqual(host["NanoCpus"], 1000000000)
        self.assertEqual(container["Config"]["Entrypoint"], ["/usr/local/bin/validate"])
        self.assertEqual(container["Config"]["Cmd"], ["/input/AppImage"])
        self.assertEqual(len(container["Mounts"]), 1)
        self.assertEqual(container["Mounts"][0]["Destination"], "/input/AppImage")
        self.assertFalse(container["Mounts"][0]["RW"])
        for option in ("noexec", "nosuid", "nodev", "mode=0700", "uid=65532", "gid=65532"):
            self.assertIn(option, host["Tmpfs"]["/tmp"])

    def test_runtime_timeout_removes_the_owned_container(self):
        scripts, manifest = self.configured_copy()
        build_script = manifest.parent / "build.sh"
        build_script.write_text(build_script.read_text() +
                               "\nprintf '%s\\n' '#include <unistd.h>' 'int main(void) { for (;;) pause(); }' "
                               "| cc -x c -o /runtime/usr/local/bin/validate -\n")
        env, record = self.docker_observer()
        result = self.invoke(scripts=scripts, env=env)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertNotIn("Verified AppImage signer:", result.stdout)
        self.assertIn("validator timed out", result.stderr)
        cid = json.loads(record.read_text())[0]["Id"]
        remaining = subprocess.run(["docker", "inspect", cid], capture_output=True, text=True, check=False)
        try:
            self.assertNotEqual(remaining.returncode, 0, "Timed-out parser container was left behind")
        finally:
            if remaining.returncode == 0:
                subprocess.run(["docker", "rm", "--force", cid], capture_output=True, check=False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
