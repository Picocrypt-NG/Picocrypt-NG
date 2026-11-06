import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ToolchainCacheIntegrity(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='picocrypt-toolchain-cache-')
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.source = root / 'source'
        self.source.mkdir()
        for name in ('toolchain.json', 'toolchain.export', 'bootstrap.py', 'cache.py', 'run.py', 'policy.py'):
            if (ROOT / name).exists():
                shutil.copyfile(ROOT / name, self.source / name)
        self.opam_root = root / 'opam'
        self.opam_root.mkdir()
        switch = json.loads((self.source / 'toolchain.json').read_text())['switch']
        self.prefix = self.opam_root / switch
        self.receipt = self.opam_root / '.picocrypt-easycrypt-cache.json'
        tools = root / 'tools'
        tools.mkdir()
        opam = tools / 'opam'
        opam.write_text('#!/bin/sh\nprintf "%s\\n" "$TEST_OPAM_ROOT"\n')
        opam.chmod(0o755)
        self.environment = dict(os.environ, TEST_OPAM_ROOT=str(self.opam_root),
                                PATH=str(tools) + os.pathsep + os.environ['PATH'])

    def run_cache(self, mode, success=True):
        result = subprocess.run([sys.executable, str(self.source / 'cache.py'), mode],
                                text=True, capture_output=True, env=self.environment,
                                timeout=10, check=False)
        if success:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        return result

    def install(self):
        (self.prefix / 'bin').mkdir(parents=True)
        executable = self.prefix / 'bin' / 'easycrypt'
        executable.write_text('frozen executable bytes')
        executable.chmod(0o755)
        (self.prefix / 'share' / 'easycrypt').mkdir(parents=True)
        (self.prefix / 'share' / 'easycrypt' / 'Core.ec').write_text('frozen theory')
        return executable

    def test_empty_cache_is_accepted_without_creating_a_receipt(self):
        self.run_cache('check')
        self.assertFalse(self.receipt.exists())

    def test_unchanged_recorded_runtime_is_accepted(self):
        executable = self.install()
        marker = self.opam_root.parent / 'cached-binary-executed'
        self.environment['TEST_CACHED_BINARY_MARKER'] = str(marker)
        executable.write_text('#!/bin/sh\n: > "$TEST_CACHED_BINARY_MARKER"\n')
        (self.prefix / 'bin' / 'alias').symlink_to(executable.name)
        for mode in ('record', 'check'):
            self.run_cache(mode)
            self.assertFalse(marker.exists(), 'Cache validation executed a cached binary.')
        self.assertTrue(self.receipt.is_file())

    def test_changed_library_or_shared_theory_is_rejected(self):
        self.install()
        library = self.prefix / 'lib' / 'easycrypt' / 'theory.ec'
        library.parent.mkdir(parents=True)
        library.write_text('frozen library theory')
        self.run_cache('record')
        for path in (library, self.prefix / 'share' / 'easycrypt' / 'Core.ec'):
            original = path.read_bytes()
            path.write_text('corrupted theory')
            self.run_cache('check', success=False)
            path.write_bytes(original)
            self.run_cache('check')

    def test_runtime_change_addition_removal_and_mode_change_are_rejected(self):
        executable = self.install()
        self.run_cache('record')
        executable.write_text('corrupted executable bytes')
        self.run_cache('check', success=False)
        executable.write_text('frozen executable bytes')
        injected = self.prefix / 'bin' / 'injected'
        injected.write_text('unregistered executable')
        self.run_cache('check', success=False)
        injected.unlink()
        executable.chmod(0o644)
        self.run_cache('check', success=False)
        executable.chmod(0o755)
        executable.unlink()
        self.run_cache('check', success=False)

    def test_changed_symlink_target_is_rejected(self):
        self.install()
        link = self.prefix / 'bin' / 'alias'
        link.symlink_to('easycrypt')
        self.run_cache('record')
        link.unlink()
        link.symlink_to('other')
        self.run_cache('check', success=False)

    def test_missing_or_malformed_receipt_and_missing_prefix_are_rejected(self):
        self.install()
        self.run_cache('check', success=False)
        self.run_cache('record')
        self.receipt.write_text('{')
        self.run_cache('check', success=False)
        self.run_cache('record')
        shutil.rmtree(self.prefix)
        self.run_cache('check', success=False)

    def test_changed_frozen_input_is_rejected(self):
        self.install()
        self.run_cache('record')
        bootstrap = self.source / 'bootstrap.py'
        bootstrap.write_text(bootstrap.read_text() + '\n')
        self.run_cache('check', success=False)

    def test_changed_export_and_relocated_prefix_are_rejected(self):
        self.install()
        self.run_cache('record')
        original = self.source / 'toolchain.export'
        original.write_text(original.read_text() + '\n')
        self.run_cache('check', success=False)
        shutil.copyfile(ROOT / 'toolchain.export', original)
        relocated = self.opam_root.with_name('relocated')
        shutil.move(self.opam_root, relocated)
        self.environment['TEST_OPAM_ROOT'] = str(relocated)
        self.run_cache('check', success=False)


if __name__ == '__main__':
    unittest.main()
