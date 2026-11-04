"""Exercise hk policy and real analyzers in disposable repositories."""

import json
import os
import shlex
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class HkIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cache = tempfile.TemporaryDirectory(prefix="picocrypt-hk-tools-")
        cls.addClassCleanup(cls.cache.cleanup)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="picocrypt-hk-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.env = os.environ | {
            "HK_CONFIG_DIR": str(self.root / "user-config"),
            "HK_PKL_CACHE_DIR": str(self.root / "pkl-cache"),
            "HK_CACHE_DIR": str(self.root / "cache"),
            "HK_PKL_OFFLINE": "1",
            "MISE_AUTO_INSTALL": "0",
            "MISE_CACHE_DIR": str(Path(self.cache.name) / "mise"),
            "GOCACHE": str(Path(self.cache.name) / "go"),
            "GOLANGCI_LINT_CACHE": str(Path(self.cache.name) / "golangci-lint"),
            "GOTOOLCHAIN": "local",
        }
        tools = tomllib.loads((ROOT / "mise.toml").read_text())["tools"]
        for tool in ("go", "golangci-lint", "hk", "jouet", "jactionlint", "shellcheck", "ruff"):
            self.env[f"MISE_{tool.upper().replace('-', '_')}_VERSION"] = tools[tool]

    def run_command(self, args, *, cwd=ROOT, input=None):
        return subprocess.run(
            args, cwd=cwd, env=self.env, input=input, capture_output=True,
            text=True, timeout=180, check=False,
        )

    def plan(self, files, hook="check"):
        result = self.run_command(
            ["hk", "run", hook, "--safe", "--plan", "--json", *files],
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        return json.loads(result.stdout)

    def test_commit_hooks_plan_checks_without_fixes(self):
        for hook in ("check", "pre-commit", "pre-push"):
            with self.subTest(hook=hook):
                plan = self.plan(["src/go.mod"], hook)
                self.assertEqual(plan["runType"], "check")
                self.assertTrue(
                    {"go-fmt", "go-vet", "go-lint"}.issubset(
                        step["name"] for step in plan["steps"] if step["status"] == "included"
                    ),
                )

    def test_deleted_go_file_cannot_skip_commit_checks(self):
        fixture = self.root / "deleted"
        (fixture / "src").mkdir(parents=True)
        self.assertEqual(self.run_command(["git", "init", "-q"], cwd=fixture).returncode, 0)
        deleted = fixture / "src/deleted.go"
        deleted.write_text("package fixture\n")
        self.assertEqual(self.run_command(["git", "add", "src/deleted.go"], cwd=fixture).returncode, 0)
        hooks = self.root / "empty-git-hooks"
        hooks.mkdir()
        committed = self.run_command([
            "git", "-c", "user.name=Tooling fixture",
            "-c", "user.email=tooling-fixture@example.invalid",
            "-c", "commit.gpgsign=false", "-c", f"core.hooksPath={hooks}",
            "commit", "-qm", "fixture",
        ], cwd=fixture)
        self.assertEqual(committed.returncode, 0, committed.stderr + committed.stdout)
        self.assertEqual(self.run_command(["git", "rm", "src/deleted.go"], cwd=fixture).returncode, 0)
        staged = self.run_command(["git", "diff", "--cached", "--name-status"], cwd=fixture)
        self.assertEqual(staged.returncode, 0, staged.stderr)
        self.assertEqual(staged.stdout, "D\tsrc/deleted.go\n")
        self.env["HK_FILE"] = str(ROOT / "hk.pkl")
        result = self.run_command(
            ["hk", "run", "pre-commit", "--safe", "--plan", "--json", "--staged"],
            cwd=fixture,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        plan = json.loads(result.stdout)
        self.assertTrue(
            {"go-fmt", "go-vet", "go-lint"}.issubset(
                step["name"] for step in plan["steps"] if step["status"] == "included"
            ),
            plan,
        )

    def fixture(self):
        fixture = self.root / "fixture"
        (fixture / "src").mkdir(parents=True)
        (fixture / ".github/workflows").mkdir(parents=True)
        (fixture / ".github/scripts").mkdir()
        (fixture / "src/go.mod").write_text("module example.com/hk-contract\n\ngo 1.23\n")
        (fixture / "src/main.go").write_text("package fixture\n\nfunc Value() int { return tagged() }\n")
        (fixture / "src/tagged.go").write_text(
            "//go:build migrated_fynedo\n\npackage fixture\n\nfunc tagged() int { return 1 }\n"
        )
        (fixture / "src/.golangci.yml").write_text('version: "2"\nlinters:\n  default: standard\n')
        (fixture / ".github/workflows/check.yml").write_text(
            "name: contract\non:\n  push:\n    branches: [main]\npermissions: {}\n"
            "concurrency:\n  group: ${{ github.workflow }}-${{ github.ref }}\n"
            "  cancel-in-progress: true\njobs:\n  check:\n    runs-on: ubuntu-latest\n"
            "    timeout-minutes: 5\n    steps:\n      - run: echo pass\n"
        )
        for helper in ("lint-go.sh", "lint-workflows.sh"):
            shutil.copyfile(ROOT / ".github/scripts" / helper, fixture / ".github/scripts" / helper)
        tasks = tomllib.loads((ROOT / "mise.toml").read_text())["tasks"]
        commands = []
        for step, task in (("go-fmt", "fmt"), ("go-vet", "vet")):
            body = tasks[task]["run"]
            if "dir" in tasks[task]:
                body = f"cd {shlex.quote(tasks[task]['dir'])}\n{body}"
            argv = ", ".join(json.dumps(arg) for arg in ("bash", "-c", body))
            commands.append(
                f'[{json.dumps(step)}] {{ check {{ command = new Command {{ argv = List({argv}) }} }} }}'
            )
        # SARIF steps retain their production mise exec wrapper and copied helpers.
        # Only fmt/vet task bodies are inlined to avoid trusting a copied mise.toml.
        config = f"amends {json.dumps((ROOT / 'hk.pkl').as_uri())}\nhooks {{\n"
        for hook in ("check", "pre-commit", "pre-push"):
            config += f'  ["{hook}"] {{ steps {{ {"; ".join(commands)} }} }}\n'
        (fixture / "hk.pkl").write_text(config + "}\n")
        self.assertEqual(self.run_command(["git", "init", "-q"], cwd=fixture).returncode, 0)
        self.env["HK_FILE"] = str(fixture / "hk.pkl")
        return fixture

    def test_composite_action_errors_fail_workflow_gate(self):
        fixture = self.fixture()
        action = fixture / ".github/actions/check/action.yml"
        action.parent.mkdir(parents=True)
        valid = (
            "name: check\nruns:\n  using: composite\n  steps:\n"
            "    - shell: bash\n      run: echo pass\n"
        )
        action.write_text(valid)
        command = ["bash", ".github/scripts/lint-workflows.sh"]
        clean = self.run_command(command, cwd=fixture)
        self.assertEqual(clean.returncode, 0, clean.stderr + clean.stdout)
        action.write_text(valid.replace("using: composite", "using: invalid"))
        broken = self.run_command(command, cwd=fixture)
        self.assertNotEqual(broken.returncode, 0, broken.stderr + broken.stdout)
        self.assertIn(".github/actions/check/action.yml", broken.stderr + broken.stdout)

    def test_real_analyzers_report_and_clear_go_and_workflow_findings(self):
        fixture = self.fixture()
        bad_go = fixture / "src/main.go"
        bad_go.write_text(
            'package fixture\n\nimport "fmt"\n\n'
            'func Value() int { fmt.Printf("%d", "wrong"); return tagged() }\n'
        )
        workflow = fixture / ".github/workflows/check.yml"
        good_workflow = workflow.read_text()
        workflow.write_text(good_workflow.replace("branches: [main]", "branch: main"))
        bad = self.run_command(["jouet", "--json", "diag", "check"], cwd=fixture)
        self.assertEqual(bad.returncode, 1, bad.stderr + bad.stdout)
        report = json.loads(bad.stdout)
        raw = json.loads(Path(report["log_path"]).read_text())
        for step in raw["steps"]:
            self.assertFalse(step.get("parse_warnings"), step)
        for step, path, line in (
            ("go-lint", "src/main.go", 5),
            ("workflows", ".github/workflows/check.yml", 4),
        ):
            with self.subTest(step=step):
                self.assertTrue(
                    any(finding["source_step"] == step and finding["file"] == path
                        and finding.get("line") == line and finding.get("message")
                        for finding in report.get("findings", [])),
                    report,
                )
        bad_go.write_text("package fixture\n\nfunc Value() int { return tagged() }\n")
        workflow.write_text(good_workflow)
        clean = self.run_command(["jouet", "--json", "diag", "check"], cwd=fixture)
        self.assertEqual(clean.returncode, 0, clean.stderr + clean.stdout)
        report = json.loads(clean.stdout)
        self.assertEqual(report["status"], "clean")
        for step in json.loads(Path(report["log_path"]).read_text())["steps"]:
            self.assertFalse(step.get("parse_warnings"), step)

    def test_failing_commit_check_preserves_worktree_index_and_stash(self):
        fixture = self.fixture()
        source = fixture / "src/main.go"
        self.assertEqual(self.run_command(["git", "add", "."], cwd=fixture).returncode, 0)
        index_before = (fixture / ".git/index").read_bytes()
        source.write_text("package fixture\n\nfunc Value()int{return tagged()}\n")
        before = source.read_bytes()
        result = self.run_command(
            ["hk", "run", "pre-commit", "--safe", "--staged", "--format", "json"],
            cwd=fixture,
        )
        self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
        steps = json.loads(result.stdout)["steps"]
        self.assertTrue(any(step["name"] == "go-fmt" and step["status"] == "failed" for step in steps))
        self.assertEqual(source.read_bytes(), before)
        self.assertEqual((fixture / ".git/index").read_bytes(), index_before)
        self.assertFalse((fixture / ".git/refs/stash").exists())
        source.write_text("package fixture\n\nfunc Value(\n")
        malformed = self.run_command(
            ["hk", "run", "check", "--safe", "--step", "go-fmt", "--all", "--format", "json"],
            cwd=fixture,
        )
        self.assertNotEqual(malformed.returncode, 0, malformed.stderr + malformed.stdout)
        self.assertTrue(any(
            step["name"] == "go-fmt" and step["status"] == "failed"
            for step in json.loads(malformed.stdout)["steps"]
        ))


if __name__ == "__main__":
    unittest.main()
