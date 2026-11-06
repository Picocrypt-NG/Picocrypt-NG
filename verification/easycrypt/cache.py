import argparse
import json
import os
import stat
import subprocess
import tempfile
from hashlib import sha256
from pathlib import Path

RUNTIME = ('bin', 'lib', 'share', 'etc', 'libexec', 'sbin')
INPUTS = ('toolchain.json', 'toolchain.export', 'bootstrap.py', 'cache.py', 'run.py', 'policy.py')


def runtime_files(prefix):
    entries = {}

    def visit(path):
        metadata = path.lstat()
        entry = {'mode': stat.S_IMODE(metadata.st_mode)}
        if stat.S_ISLNK(metadata.st_mode):
            entry.update(kind='symlink', target=os.readlink(path))
        elif stat.S_ISREG(metadata.st_mode):
            entry.update(kind='file', sha256=sha256(path.read_bytes()).hexdigest())
        elif stat.S_ISDIR(metadata.st_mode):
            entry.update(kind='directory')
            for child in sorted(path.iterdir()):
                visit(child)
        else:
            raise ValueError('Unsupported toolchain runtime file: ' + str(path))
        entries[str(path.relative_to(prefix))] = entry

    for name in RUNTIME:
        path = prefix / name
        if path.exists() or path.is_symlink():
            visit(path)
    return entries


def main():
    parser = argparse.ArgumentParser(description='Check or record frozen toolchain cache integrity.')
    parser.add_argument('mode', choices=('check', 'record'))
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    inputs = {name: sha256((root / name).read_bytes()).hexdigest() for name in INPUTS}
    toolchain = json.loads((root / 'toolchain.json').read_text())
    if inputs['toolchain.export'] != toolchain['export_sha256']:
        raise ValueError('The toolchain export does not match toolchain.json.')
    switch = toolchain['switch']
    if switch in ('', '.', '..', 'default') or '/' in switch:
        raise ValueError('A dedicated named toolchain switch is required.')
    opam_root = Path(subprocess.check_output(['opam', 'var', 'root'], text=True).strip())
    if not opam_root.is_absolute():
        raise ValueError('The opam root must be absolute.')
    prefix = opam_root.resolve() / switch
    receipt = opam_root / '.picocrypt-easycrypt-cache.json'
    if prefix.is_symlink() or receipt.is_symlink():
        raise ValueError('The toolchain prefix and receipt must not be symlinks.')
    if args.mode == 'check' and not prefix.exists() and not receipt.exists():
        print('No frozen toolchain cache was restored.')
        return
    if not prefix.is_dir():
        raise ValueError('The frozen toolchain cache prefix is missing.')
    snapshot = {'schema': 1, 'prefix': str(prefix), 'inputs': inputs,
                'runtime': runtime_files(prefix)}
    if args.mode == 'check':
        if not receipt.is_file():
            raise ValueError('The frozen toolchain cache receipt is missing.')
        if json.loads(receipt.read_text()) != snapshot:
            raise ValueError('The frozen toolchain cache integrity check failed.')
        print('Frozen toolchain cache integrity checked.')
        return
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', dir=opam_root, delete=False) as stream:
            temporary = Path(stream.name)
            json.dump(snapshot, stream, sort_keys=True)
            stream.write('\n')
        os.replace(temporary, receipt)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    print('Frozen toolchain cache integrity recorded.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        raise SystemExit('Toolchain cache rejected: ' + str(error)) from error
