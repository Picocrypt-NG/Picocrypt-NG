"""Extract the same-run build artifact before the signing key becomes available."""

import shutil
import sys
import tarfile
from pathlib import Path, PurePosixPath


def main():
    archive, destination = map(Path, sys.argv[1:])
    destination.mkdir(mode=0o700)
    appdir = destination.resolve() / "AppDir"
    seen = set()

    def appdir_filter(member, path):
        member = tarfile.data_filter(member, path)
        if member is not None:
            path = PurePosixPath(member.name)
            if not path.parts or path.parts[0] != "AppDir" or ".." in path.parts:
                raise ValueError(f"Archive path is outside AppDir: {member.name}")
            canonical = str(path)
            if canonical in seen:
                raise ValueError(f"Duplicate AppDir entry: {member.name}")
            seen.add(canonical)
            if not (member.isfile() or member.isdir() or member.issym()):
                raise ValueError(f"Unsupported AppDir entry: {member.name}")
            if member.issym():
                target = (destination / path.parent / member.linkname).resolve()
                if not target.is_relative_to(appdir):
                    raise ValueError(f"AppDir symlink escapes the application: {member.name}")
        return member

    try:
        with tarfile.open(archive, mode="r:") as source:
            source.extractall(destination, filter=appdir_filter)
    except BaseException:
        shutil.rmtree(destination)
        raise


if __name__ == "__main__":
    main()
