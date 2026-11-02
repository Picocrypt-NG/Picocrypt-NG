import argparse
import json
import os
import subprocess
from hashlib import sha256
from pathlib import Path

root = Path(__file__).resolve().parent
toolchain = json.loads((root / 'toolchain.json').read_text())
parser = argparse.ArgumentParser(description='Install the pinned local EasyCrypt toolchain.')
parser.add_argument('--switch', default=toolchain['switch'])
parser.add_argument('--jobs', type=int, default=2)
args = parser.parse_args()
if args.switch == 'default' or '/' in args.switch or args.jobs < 1:
    parser.error('Use a dedicated named switch and a positive job count.')

lock = root / 'toolchain.export'
if sha256(lock.read_bytes()).hexdigest() != toolchain['export_sha256']:
    raise SystemExit('The toolchain export does not match toolchain.json.')


def output(*command):
    return subprocess.check_output(command, text=True).strip()


probe = subprocess.run(['opam', 'var', 'root'], text=True, capture_output=True, check=False)
if probe.returncode == 0:
    opam_root = Path(probe.stdout.strip())
else:
    opam_root = Path(os.environ.get('OPAMROOT', str(Path.home() / '.opam'))).expanduser()
    if probe.returncode != 50 or (opam_root / 'config').exists():
        raise SystemExit(probe.stderr)
if not (opam_root / 'config').exists():
    subprocess.run(['opam', 'init', '--bare', '--no-setup', '--yes'], check=True)


def selected_switch():
    result = subprocess.run(['opam', 'var', 'switch'], text=True, capture_output=True, check=False)
    return result.returncode, result.stdout.strip()


selected = selected_switch()
switches = output('opam', 'switch', 'list', '--short').splitlines()
if args.switch not in switches:
    subprocess.run(['opam', 'switch', 'create', args.switch, '--empty', '--no-switch', '--yes'], check=True)
else:
    version = output('opam', 'exec', '--switch=' + args.switch, '--', 'ocamlc', '-version')
    if version != toolchain['ocaml']:
        raise SystemExit('The existing dedicated switch uses a different OCaml compiler.')

subprocess.run(['opam', 'switch', 'import', str(lock), '--switch=' + args.switch,
                '--yes', '--assume-depexts', '--jobs=' + str(args.jobs)], check=True)
if selected_switch() != selected:
    raise SystemExit('The selected opam switch changed during setup.')
print('Pinned toolchain installed; the selected opam switch was preserved.')
