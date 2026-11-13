#!/usr/bin/env python3
import hashlib
import sys
import tarfile
from pathlib import PurePosixPath


def contents(package):
    files = {}
    with tarfile.open(package, "r:gz") as chart:
        for member in chart:
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or not path.parts:
                raise ValueError(f"invalid chart path: {member.name}")
            if member.isdir():
                continue
            if not member.isfile():
                raise ValueError(f"chart entry must be a regular file: {member.name}")
            name = str(path)
            if name in files:
                raise ValueError(f"duplicate chart path: {name}")
            with chart.extractfile(member) as stream:
                files[name] = (member.size, hashlib.file_digest(stream, "sha256").digest())
    if not files:
        raise ValueError("chart has no regular files")
    return files


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: compare-chart-packages.py EXPECTED PUBLISHED")
    try:
        if contents(sys.argv[1]) != contents(sys.argv[2]):
            sys.exit("published chart contents differ from the locally built package")
    except (OSError, ValueError, tarfile.TarError) as error:
        sys.exit(str(error))
    print("Published chart files match the locally built package")
