#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-3.0-only
#
# Copyright (C) 2026 Corey Pennycuff
#
# This file is part of Ghoti.io Archive.
#
# Ghoti.io Archive is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3 as
# published by the Free Software Foundation.
"""Fail if this library cannot read the split archives the references write.

    make check-volumes

**A split archive is named by convention and laid out by its writer**, so the
only test that it is read is one made by the writers people use. In the
pinned image this asks Info-ZIP's `zip -s` for a split zip (`name.z01`,
`name.z02`, ..., `name.zip`), the same with `-fz` so the zip64 locator's disk
fields are in play, and 7-Zip's `-v` for a numbered split (`name.7z.001`,
...). Each is opened by `volume_probe` through garc_fs_open() - from the
`.zip`, from the `.z01`, and from the `.001` - and every file it reads is
compared with the file that went in: name, size and CRC-32. The source is
generated here, so the comparison is with the bytes and not with another
reader's idea of them.
"""

import os
import shutil
import subprocess
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import oracle_env  # noqa: E402

# Each case: the split set's starting file, the command that writes it (run in
# the source directory, inside the image), and which references it needs.
# The last field is what every part's name starts with, to count them.
CASES = [
    ("split.zip", ["zip", "-q", "-r", "-s", "64k", "../out/split.zip", "."], "zip",
        "split.z"),
    ("split.z01", None, "zip", "split.z"),
    ("split64.zip", ["zip", "-q", "-r", "-fz", "-s", "64k",
        "../out/split64.zip", "."], "zip", "split64.z"),
    ("split.7z.001", ["7z", "a", "-bso0", "-bsp0", "-mmt=1", "-v50k",
        "../out/split.7z", "."], "sevenzip", "split.7z."),
]


def source_tree(directory):
    """Files that make several parts at 64 KiB: one large and incompressible."""
    files = {}
    state = 12345
    big = bytearray()
    for _ in range(200000):
        state = (state * 1103515245 + 12345) & 0x7FFFFFFF
        big.append(state >> 16 & 0xFF)
    files["big.bin"] = bytes(big)
    files["small.txt"] = b"a small file\n"
    files["dir/middle.txt"] = b"".join(b"line %d\n" % i for i in range(4000))
    files["empty"] = b""
    for name, data in files.items():
        path = os.path.join(directory, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)
    return files


def main(argv):
    if "--probe" not in argv:
        sys.stderr.write("usage: check_volumes.py --probe <path>\n")
        return 2
    probe = argv[argv.index("--probe") + 1]
    work = os.path.join(ROOT, "build", "volumes-check")
    if os.path.exists(work):
        shutil.rmtree(work)
    source = os.path.join(work, "src")
    out = os.path.join(work, "out")
    os.makedirs(source)
    os.makedirs(out)
    files = source_tree(source)
    want = sorted("%s\t%d\t%08x" % (name, len(data), zlib.crc32(data) & 0xFFFFFFFF)
        for name, data in files.items())
    print(oracle_env.provenance(["zip", "sevenzip"]), flush=True)

    failures = []
    checked = 0
    for start, command, tool, prefix in CASES:
        if command:
            made = subprocess.run(oracle_env.command(tool,
                ["sh", "-c", 'cd "$0" && exec "$@"', source] + command,
                scratch=[work]), capture_output=True, stdin=subprocess.DEVNULL)
            if made.returncode != 0:
                failures.append("%s: the reference failed: %s" % (start,
                    made.stderr.decode("utf-8", "replace").strip()))
                continue
        parts = sorted(n for n in os.listdir(out) if n.startswith(prefix))
        if len(parts) < 3:
            failures.append("%s: only %d parts written (%s), so nothing was "
                "split" % (start, len(parts), parts))
            continue
        read = subprocess.run([probe, os.path.join(out, start)],
            capture_output=True, text=True)
        if read.returncode != 0:
            failures.append("%s: %s" % (start, read.stderr.strip()))
            continue
        got = sorted(line for line in read.stdout.splitlines() if line.strip())
        if got != want:
            failures.append("%s: read\n      %s\n    wanted\n      %s"
                % (start, "\n      ".join(got), "\n      ".join(want)))
            continue
        checked += 1

    if failures:
        sys.stderr.write("### check-volumes: a split archive did not read as "
            "it was written ###\n")
        for line in failures:
            sys.stderr.write("  %s\n" % line)
        return 1
    print("check-volumes: %d split sets from zip -s, zip -fz -s and 7z -v, "
        "each read back to every file's size and CRC-32" % checked)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
