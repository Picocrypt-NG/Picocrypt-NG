import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ProofRunnerIntegration(unittest.TestCase):
    def run_target(self, text, environment=None, extra_theory=None):
        with tempfile.TemporaryDirectory(prefix='picocrypt-proof-runner-') as temporary:
            root = Path(temporary)
            for name in ('run.py', 'policy.py', 'toolchain.json'):
                shutil.copyfile(ROOT / name, root / name)
            (root / 'models').mkdir()
            (root / 'controls').mkdir()
            (root / 'models' / 'Regression.ec').write_text(text)
            positives = [{'id': 'regression', 'source': 'models/Regression.ec'}]
            if extra_theory is not None:
                (root / 'models/Check_regression.ec').write_text(extra_theory)
                positives.append({'id': 'guarded-false', 'source': 'models/Check_regression.ec'})
            (root / 'manifest.json').write_text(json.dumps({
                'axioms': {}, 'positives': positives,
                'negatives': [],
            }))
            result = subprocess.run(['uv', 'run', '--no-project', 'python', str(root / 'run.py')],
                                    text=True, capture_output=True, timeout=60, check=False,
                                    env=environment)
            report = json.loads((root / '_build/results.json').read_text())
            return result, report

    def test_closed_false_theorem_cannot_pass_through_an_unchecked_import(self):
        result, report = self.run_target('require import AllCore.\nlemma unsound : false.\nproof. by done. qed.\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(report['status'], 'finished')
        self.assertFalse(report['passed'])
        self.assertEqual(report['checks'][0]['exit_code'], 1)

    def test_unfinished_theorem_cannot_pass_at_top_level_eof(self):
        result, report = self.run_target('require import AllCore.\nlemma unsound : false.\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(report['status'], 'finished')
        self.assertFalse(report['passed'])
        self.assertEqual(report['checks'][0]['exit_code'], 0)
        self.assertEqual(report['checks'][0]['closure_exit_code'], 1)

    def test_completion_wrapper_cannot_overwrite_a_registered_theory(self):
        result, report = self.run_target(
            'require import AllCore.\nlemma safe : true. proof. trivial. qed.\n',
            extra_theory='require import AllCore.\nlemma unsafe : false. proof. by done. qed.\n',
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(report['status'], 'finished')
        self.assertFalse(report['passed'])
        self.assertFalse(report['checks'][1]['passed'])

    def test_loader_environment_cannot_add_unregistered_theories(self):
        with tempfile.TemporaryDirectory(prefix='picocrypt-untrusted-theory-') as directory:
            (Path(directory) / 'Injected.ec').write_text('axiom unchecked : false.\n')
            environment = dict(os.environ, EC_IDIRS=directory, EC_RDIRS=directory)
            result, report = self.run_target('require import AllCore Injected.\n', environment)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(report['status'], 'finished')
            self.assertFalse(report['passed'])
            self.assertEqual(report['checks'][0]['exit_code'], 1)


if __name__ == '__main__':
    unittest.main()
