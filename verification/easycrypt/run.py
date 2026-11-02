import argparse
import json
import os
import re
import subprocess
import time
from hashlib import sha256
from pathlib import Path

from policy import ProofPolicyError, active_text, check_source

root = Path(__file__).resolve().parent
toolchain = json.loads((root / 'toolchain.json').read_text())
manifest = json.loads((root / 'manifest.json').read_text())
parser = argparse.ArgumentParser(description='Check registered EasyCrypt models and defect controls.')
parser.add_argument('--switch', default=toolchain['switch'])
parser.add_argument('--only', action='append', help='Check a named target; the report is labelled partial.')
args = parser.parse_args()
out = root / '_build'
out.mkdir(exist_ok=True)
run_directory = out / 'runs' / str(time.time_ns())
run_directory.mkdir(parents=True)
snapshots = run_directory / 'inputs'
libraries = run_directory / 'checked-theories'
libraries.mkdir()
destination = out / ('selected-results.json' if args.only else 'results.json')
destination.write_text(json.dumps({'status': 'incomplete', 'passed': False,
                                 'run_directory': str(run_directory)}, indent=2) + '\n')
prefix = ['opam', 'exec', '--switch=' + args.switch, '--', 'easycrypt']
environment = dict(os.environ)
for name in ('EC_IDIRS', 'EC_RDIRS'):
    environment.pop(name, None)
targets = [dict(target, expected_failure=False) for target in manifest['positives']]
targets += [dict(target, expected_failure=True) for target in manifest['negatives']]


def source_path(relative):
    path = (root / relative).resolve()
    if not path.is_relative_to(root) or path.suffix != '.ec':
        raise SystemExit('Proof sources must be .ec files inside verification/easycrypt.')
    return path


registered = {source_path(target['source']) for target in targets}
actual = {path.resolve() for folder in ('models', 'controls') for path in (root / folder).glob('*.ec')}
if actual - registered:
    raise SystemExit('Unregistered EasyCrypt sources: ' + ', '.join(str(path.relative_to(root)) for path in sorted(actual - registered)))
inputs = {path: path.read_bytes() for path in actual}
for path, content in inputs.items():
    copied = snapshots / path.relative_to(root)
    copied.parent.mkdir(parents=True, exist_ok=True)
    copied.write_bytes(content)
for target in manifest['positives']:
    source = source_path(target['source'])
    if source.exists():
        check_source(source.read_text(), manifest['axioms'].get(target['source'], []))
        copied = libraries / source.name
        if copied.exists():
            raise SystemExit('Positive theory filenames must be unique.')
        copied.write_bytes(inputs[source])
if args.only:
    unknown = set(args.only) - {target['id'] for target in targets}
    if unknown:
        raise SystemExit('Unknown target: ' + ', '.join(sorted(unknown)))
    targets = [target for target in targets if target['id'] in args.only]

provenance = {}
for label, command, expected in [
    ('ocaml', ['ocamlc', '-version'], toolchain['ocaml']),
    ('why3', ['why3', '--version'], toolchain['why3']),
    ('alt_ergo', ['alt-ergo', '--version'], toolchain['alt_ergo']),
]:
    result = subprocess.run(prefix[:4] + command, text=True, capture_output=True, check=True, env=environment)
    observed = result.stdout.strip()
    if expected not in observed.split() and observed != 'v' + expected:
        raise SystemExit('Unexpected ' + label + ' version: ' + observed)
    provenance[label] = observed
pins = subprocess.check_output(['opam', 'pin', 'list', '--switch=' + args.switch], text=True, env=environment)
if toolchain['easycrypt_commit'] not in pins:
    raise SystemExit('The switch is not pinned to the required EasyCrypt revision.')
configuration = subprocess.run(prefix + ['config'], cwd=libraries, text=True,
                               capture_output=True, check=True, env=environment)
if 'git-hash: ' + toolchain['easycrypt_release'] not in configuration.stdout + configuration.stderr:
    raise SystemExit('The installed EasyCrypt reports a different source revision.')
if not re.search(r'EasyCrypt configuration file\s+<none>', configuration.stdout + configuration.stderr):
    raise SystemExit('An additional EasyCrypt configuration would make this run non-reproducible.')
if re.search(r'^\s+<(?!system>)[^>]*>@', configuration.stdout + configuration.stderr, re.MULTILINE):
    raise SystemExit('An additional EasyCrypt theory load path would make this run non-reproducible.')
subprocess.run(prefix + ['why3config', '-why3', str(run_directory / 'why3.conf')],
               cwd=libraries, text=True, capture_output=True, check=True, env=environment)

results = []
for target in targets:
    name = target['id']
    if not re.fullmatch(r'[a-z0-9-]+', name):
        raise SystemExit('Invalid target identifier.')
    source = snapshots / source_path(target['source']).relative_to(root)
    if not target['expected_failure']:
        source = libraries / source.name
    text = source.read_text()
    original_hash = sha256(source.read_bytes()).hexdigest()
    allowed_axioms = manifest['axioms'].get(target['source'], [])
    if target.get('kind') == 'tooling-policy':
        rejected = False
        try:
            check_source(text, allowed_axioms)
        except ProofPolicyError as error:
            rejected = target['error_contains'] in str(error)
            (run_directory / (name + '.log')).write_text(str(error) + '\n')
        results.append({'id': name, 'kind': 'tooling-policy', 'passed': rejected,
                        'expected_failure': True, 'original_sha256': original_hash})
        print(f"{name}: {'PASS' if rejected else 'FAIL'} (proof-policy rejection)", flush=True)
        continue
    check_source(text, allowed_axioms)
    if 'replace_once' in target:
        replacement = target['replace_once']
        if text.count(replacement['from']) != 1:
            raise SystemExit('The mutation no longer matches exactly once: ' + name)
        text = text.replace(replacement['from'], replacement['to'])
        source = run_directory / 'mutations' / name / source.name
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text(text)
        check_source(text, allowed_axioms)
    expected_failure = target['expected_failure']
    mode = ['llm', '-lastgoals'] if expected_failure else ['compile', '-no-eco']
    entrypoint = source
    closure_entrypoint = None
    if not expected_failure or target.get('kind') == 'tooling-eof':
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', source.stem):
            raise SystemExit('Invalid EasyCrypt theory filename.')
        closure_entrypoint = run_directory / 'completion' / ('Check_' + name.replace('-', '_') + '.ec')
        closure_entrypoint.parent.mkdir(exist_ok=True)
        closure_entrypoint.write_text('require ' + source.stem + '.\n')
        if target.get('kind') == 'tooling-eof':
            entrypoint = closure_entrypoint
    options = ['-why3', str(run_directory / 'why3.conf'), '-I', str(libraries),
               '-p', 'Alt-Ergo', '-timeout', '5', '-max-provers', '1']
    if target.get('kind') == 'tooling-eof':
        options += ['-I', str(source.parent)]
    command = prefix + mode + options + [str(entrypoint)]
    if not expected_failure and source.read_bytes() != inputs[source_path(target['source'])]:
        raise SystemExit('A staged theory changed before checking: ' + name)
    started = time.monotonic()
    result = subprocess.run(command, cwd=libraries, capture_output=True, text=True,
                            timeout=180, check=False, env=environment)
    diagnostic = result.stdout + result.stderr
    passed = result.returncode == 0
    closure_result = None
    closure_command = None
    if not expected_failure and passed:
        closure_command = prefix + mode + options + [str(closure_entrypoint)]
        closure_result = subprocess.run(closure_command, cwd=libraries, capture_output=True,
                                        text=True, timeout=180, check=False, env=environment)
        diagnostic += closure_result.stdout + closure_result.stderr
        passed = closure_result.returncode == 0
    (run_directory / (name + '.log')).write_text(diagnostic)
    if target.get('kind') == 'tooling-eof':
        passed = (result.returncode == 1 and target['error_contains'] in diagnostic
                  and source.stem in diagnostic)
    elif expected_failure:
        declarations = list(re.finditer(r'^\s*(?:lemma|equiv|phoare)\s+([A-Za-z0-9_]+)', active_text(text), re.MULTILINE))
        wanted = next((i for i, declaration in enumerate(declarations)
                       if declaration.group(1) == target['theorem']), None)
        if wanted is None:
            raise SystemExit('Negative-control theorem not found: ' + name)
        start = text[:declarations[wanted].start()].count('\n') + 1
        end = text[:declarations[wanted + 1].start()].count('\n') + 1 if wanted + 1 < len(declarations) else len(text.splitlines()) + 1
        line = re.search(re.escape(str(source)) + r': line (\d+)', diagnostic)
        failing_tactic = '' if line is None else active_text(text).splitlines()[int(line[1]) - 1].strip()
        passed = (result.returncode == 1 and 'Current goal' in diagnostic
                  and '[by]: cannot close goals' in diagnostic
                  and re.match(r'by (?:done|rewrite)\b', failing_tactic) is not None
                  and line is not None and start <= int(line[1]) < end)
    results.append({'id': name, 'kind': target.get('kind', 'model-defect-control' if expected_failure else 'model-proof'),
                    'passed': passed, 'exit_code': result.returncode,
                    'expected_failure': expected_failure, 'command': command,
                    'source': str(source), 'entrypoint_sha256': sha256(entrypoint.read_bytes()).hexdigest(),
                    'closure_command': closure_command,
                    'closure_exit_code': None if closure_result is None else closure_result.returncode,
                    'seconds': round(time.monotonic() - started, 3),
                    'original_sha256': original_hash, 'checked_sha256': sha256(source.read_bytes()).hexdigest()})
    print(f"{name}: {'PASS' if passed else 'FAIL'} (exit {result.returncode})", flush=True)
    if not passed:
        print(diagnostic[-6000:], flush=True)

unchanged = all(path.read_bytes() == content for path, content in inputs.items())
if not unchanged:
    print('Proof inputs changed during this run; results do not validate the current sources.', flush=True)
report = {'status': 'finished', 'scope': 'selected-targets' if args.only else 'registered-model-suite',
          'run_directory': str(run_directory), 'source_unchanged': unchanged,
          'application_refinement': 'not-established', 'toolchain': toolchain,
          'observed_versions': provenance, 'checks': results,
          'passed': unchanged and all(result['passed'] for result in results)}
destination.write_text(json.dumps(report, indent=2) + '\n')
(run_directory / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
raise SystemExit(0 if report['passed'] else 1)
