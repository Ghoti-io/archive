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
"""Generate the ar and cpio corpus in the pinned container.

    make arcpio-corpus         regenerate tests/data/arcpio/ and the hash list
    make check-arcpio-corpus   regenerate into a scratch directory and compare

The writer is libarchive's bsdtar: it is the one reference in the image that
writes these formats, and it writes no `070702` crc dialect, which the tests
build by hand. GNU `ar` and GNU `cpio` are
not in it, so what only they write - GNU's long-name table, a System V symbol
table, a binary cpio from a real machine - is built byte by byte in the tests
instead, and the corpus says so rather than pretending to cover it.

**The expectation is the source tree**, as for the 7z corpus: `manifest-cpio.tsv`
and `manifest-ar.tsv` are computed from the files that were archived, never from
reading an archive back.

**Determinism.** Every mtime is fixed with `os.utime`, the order is given on the
command line, and the one field that is not deterministic - cpio writes the
file's real inode and device number - is rewritten here to a sequence, after the
reference wrote it. That is the only edit made to a reference's bytes, it changes
no field a reader reports, and it is what lets `check-arcpio-corpus` mean "the
reference still writes this" rather than "the filesystem handed out the same
inodes".
"""

import hashlib
import os
import random
import shutil
import stat
import subprocess
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
CORPUS = os.path.join(ROOT, "tests", "data", "arcpio")
HASHES = os.path.join(HERE, "containers", "CORPUS-ARCPIO")

MTIME = 1000000000


def run(argv, cwd=None, what="", stdin=None):
    finished = subprocess.run(argv, cwd=cwd, capture_output=True,
        stdin=stdin if stdin is not None else subprocess.DEVNULL)
    if finished.returncode != 0:
        raise SystemExit("%s failed (%s):\n%s\n%s" % (argv[0], what,
            finished.stdout.decode(errors="replace"),
            finished.stderr.decode(errors="replace")))
    return finished


def write(base, path, data, mode):
    full = os.path.join(base, path)
    os.makedirs(os.path.dirname(full) or base, exist_ok=True)
    with open(full, "wb") as handle:
        handle.write(data)
    os.chmod(full, mode)


def fix_times(base):
    for here, directories, files in os.walk(base):
        for name in list(directories) + list(files):
            os.utime(os.path.join(here, name), (MTIME, MTIME),
                follow_symlinks=False)
    os.utime(base, (MTIME, MTIME))


LONG = "a-very-long-name-" * 6 + "end.txt"

CPIO_FILES = [
    ("hello.txt", b"hello, archive\n", 0o644),
    ("s1", b"x", 0o644), ("s2", b"xy", 0o644), ("s3", b"xyz", 0o644),
    ("s4", b"wxyz", 0o644),
    ("empty.txt", b"", 0o644),
    ("exec.sh", b"#!/bin/sh\nexit 0\n", 0o755),
    ("private", b"secret\n", 0o600),
    ("sub/deep/nested.txt", b"nested\n", 0o644),
    (LONG, b"a long name\n", 0o644),
    ("random.bin", random.Random(5).randbytes(3001), 0o644),
]

AR_FILES = [
    ("a.txt", b"first\n", 0o644),
    ("fifteen-chars-x", b"15\n", 0o644),
    ("sixteen-chars-xy", b"16\n", 0o644),
    ("long-name-beyond-sixteen-bytes.txt", b"long\n", 0o644),
    ("name with spaces.txt", b"spaces\n", 0o644),
    ("odd", b"odd", 0o644),
    ("even", b"even", 0o755),
    ("empty", b"", 0o644),
    ("bin.dat", random.Random(9).randbytes(3001), 0o600),
]


def cpio_tree(base):
    for path, data, mode in CPIO_FILES:
        write(base, path, data, mode)
    os.makedirs(os.path.join(base, "emptydir"), exist_ok=True)
    os.chmod(os.path.join(base, "emptydir"), 0o755)
    for d in ("sub", "sub/deep"):
        os.chmod(os.path.join(base, d), 0o755)
    os.symlink("hello.txt", os.path.join(base, "link-to-hello"))
    os.mkfifo(os.path.join(base, "fifo"), 0o644)
    fix_times(base)


def ar_tree(base):
    for path, data, mode in AR_FILES:
        write(base, path, data, mode)
    fix_times(base)


def normalise_cpio(path):
    """Replace the inode (and odc's device) the reference took from the disk."""
    data = bytearray(open(path, "rb").read())
    at = 0
    seq = 0
    while at + 6 <= len(data):
        magic = bytes(data[at:at + 6])
        if magic in (b"070701", b"070702"):
            seq += 1
            data[at + 6:at + 14] = b"%08x" % seq
            namesize = int(data[at + 94:at + 102], 16)
            filesize = int(data[at + 54:at + 62], 16)
            name_end = at + 110 + namesize
            name_end += (-name_end) % 4
            at = name_end + filesize + ((-filesize) % 4)
        elif magic == b"070707":
            seq += 1
            data[at + 6:at + 12] = b"000000"
            data[at + 12:at + 18] = b"%06o" % seq
            namesize = int(data[at + 59:at + 65], 8)
            filesize = int(data[at + 65:at + 76], 8)
            at = at + 76 + namesize + filesize
        else:
            break
    open(path, "wb").write(bytes(data))


def generate(destination):
    work = os.path.join(destination, "_work")
    if os.path.exists(work):
        shutil.rmtree(work)
    ctree = os.path.join(work, "cpio")
    atree = os.path.join(work, "ar")
    os.makedirs(ctree)
    os.makedirs(atree)
    cpio_tree(ctree)
    ar_tree(atree)

    names = sorted(os.listdir(ctree))
    for fmt, out in (("odc", "odc.cpio"), ("newc", "newc.cpio"),
            ("bin", "bin.cpio")):
        target = os.path.join(destination, out)
        # The binary dialect has no fifo, so it archives one plain file: all it
        # is for is a header this library recognises and refuses.
        run(["bsdtar", "--format", fmt, "-cf", target]
            + (["hello.txt"] if fmt == "bin" else names), cwd=ctree, what=out)
        if fmt != "bin":
            normalise_cpio(target)

    anames = [p for p, _d, _m in AR_FILES]
    run(["bsdtar", "--format", "ar", "-cf",
        os.path.join(destination, "common.a")] + anames, cwd=atree,
        what="common.a")

    manifest(destination, ctree, atree)
    shutil.rmtree(work)


def manifest(destination, ctree, atree):
    rows = []
    for here, directories, files in os.walk(ctree):
        for entry in directories + files:
            full = os.path.join(here, entry)
            rel = os.path.relpath(full, ctree)
            info = os.lstat(full)
            mode = stat.S_IMODE(info.st_mode)
            if stat.S_ISLNK(info.st_mode):
                target = os.readlink(full)
                rows.append((rel, "symlink", 0, 0, mode, target))
            elif stat.S_ISDIR(info.st_mode):
                rows.append((rel, "directory", 0, 0, mode, ""))
            elif stat.S_ISFIFO(info.st_mode):
                rows.append((rel, "fifo", 0, 0, mode, ""))
            else:
                data = open(full, "rb").read()
                rows.append((rel, "file", len(data), zlib.crc32(data), mode,
                    ""))
    rows.sort()
    with open(os.path.join(destination, "manifest-cpio.tsv"), "w",
            encoding="utf-8") as handle:
        handle.write("# name, type, size, crc32, mode, mtime, link target -\n"
            "# computed from the source tree, not from reading any archive.\n"
            "# Generated by tools/oracle/make_arcpio_corpus.py.\n")
        for name, kind, size, crc, mode, link in rows:
            handle.write("%s\t%s\t%d\t%08x\t%o\t%d\t%s\n"
                % (name, kind, size, crc, mode, MTIME, link))
    with open(os.path.join(destination, "manifest-ar.tsv"), "w",
            encoding="utf-8") as handle:
        handle.write("# name, type, size, crc32, mode, mtime, link target -\n"
            "# in the order the archive was written.\n"
            "# Generated by tools/oracle/make_arcpio_corpus.py.\n")
        for name, data, mode in AR_FILES:
            handle.write("%s\tfile\t%d\t%08x\t%o\t%d\t\n"
                % (name, len(data), zlib.crc32(data), mode, MTIME))


def hashes(destination):
    rows = []
    for name in sorted(os.listdir(destination)):
        path = os.path.join(destination, name)
        if os.path.isfile(path):
            rows.append("%s  %s" % (
                hashlib.sha256(open(path, "rb").read()).hexdigest(), name))
    return rows


def main(argv):
    if os.environ.get("GHOTI_ARCHIVE_ARCPIO_CORPUS_INNER") == "1":
        generate(argv[1])
        return 0

    sys.path.insert(0, HERE)
    import oracle_env

    check_only = "--check" in argv[1:]
    destination = CORPUS
    if check_only:
        destination = os.path.join(ROOT, "build", "arcpio-corpus-check")
        if os.path.exists(destination):
            shutil.rmtree(destination)
    os.makedirs(destination, exist_ok=True)
    print(oracle_env.provenance(["bsdtar"]), flush=True)
    inner = oracle_env.command("bsdtar",
        ["python3", os.path.join(HERE, "make_arcpio_corpus.py"), destination],
        scratch=[destination])
    environment = dict(os.environ, GHOTI_ARCHIVE_ARCPIO_CORPUS_INNER="1")
    if "run" in inner[:2]:
        cut = inner.index("run") + 1
        engine_argv = (inner[:cut]
            + ["--env", "GHOTI_ARCHIVE_ARCPIO_CORPUS_INNER=1"] + inner[cut:])
    else:
        engine_argv = inner
    finished = subprocess.run(engine_argv, env=environment)
    if finished.returncode != 0:
        return finished.returncode

    rows = hashes(destination)
    if not check_only:
        with open(HASHES, "w", encoding="utf-8") as handle:
            handle.write(
                "# sha256 of every generated ar and cpio fixture, so that one\n"
                "# which moved fails `make check-arcpio-corpus` rather than\n"
                "# quietly becoming the new expectation.\n"
                "# Regenerated by `make arcpio-corpus`.\n")
            handle.write("\n".join(rows) + "\n")
        print("ar/cpio corpus: %d files in %s" % (len(rows), destination))
        return 0

    with open(HASHES, "r", encoding="utf-8") as handle:
        want = [line.rstrip("\n") for line in handle
            if line.strip() and not line.startswith("#")]
    if want == rows:
        print("ar/cpio corpus: %d files match containers/CORPUS-ARCPIO"
            % len(rows))
        return 0
    sys.stderr.write("### The regenerated ar/cpio corpus does not match "
        "CORPUS-ARCPIO ###\n")
    want_map = dict(row.split("  ", 1)[::-1] for row in want)
    got_map = dict(row.split("  ", 1)[::-1] for row in rows)
    for name in sorted(set(want_map) | set(got_map)):
        if want_map.get(name) != got_map.get(name):
            sys.stderr.write("  %s: CORPUS-ARCPIO %s, regenerated %s\n"
                % (name, want_map.get(name, "absent"),
                    got_map.get(name, "absent")))
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
