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
"""Generate the 7z corpus in the pinned container.

    make sevenz-corpus         regenerate tests/data/sevenz/ and the hash list
    make check-sevenz-corpus   regenerate into a scratch directory and compare

One writer: 7-Zip is the only 7z writer in the reference image, and 7z has no
second implementation there to disagree with it. What the corpus offers instead
of a second opinion is **the source tree**. `manifest.tsv` is computed from the
files that were archived - their names, types, modes, sizes, times and CRC-32 -
and not from reading the archives back, so a test that compares the library's
reading against it compares it against what went in. `7z t` is run on every
archive as well, and `7z l -slt` is kept as `listing.txt` so that a reference's
reading of the headers is on record beside the library's.

Each archive is written to vary one thing the reader has to get right:

  - the coder: LZMA2 (7-Zip's default), LZMA, bzip2, deflate, deflate64, copy;
  - the filters in front of it: delta, x86 BCJ, ARM64;
  - solid or not, which decides whether a folder holds one file or many;
  - the header: encoded (the default) or plain, which are two code paths;
  - a symlink, which 7z stores as a Unix mode in the attributes and its target
    as the file's data;
  - the other six branch filters (PowerPC, IA-64, ARM, ARM Thumb, SPARC,
    RISC-V), over one file each;
  - BCJ2: four packed streams, in the layout the `-m`/`-mb` switches give,
    with Copy coders so that the four streams sit raw in the pack area, and
    as `-mf=BCJ2` picks it;
  - 7-Zip's AES: the data alone, the header too (`-mhe=on`, whose header is
    AES and LZMA), a one-file archive with `-mhe=on` (whose header is AES
    alone), non-solid (a folder per file, each its own coder), the copy
    coder (so a wrong password reaches a CRC rather than a decoder), and
    BCJ2, which puts an AES coder in front of each of its four streams. The
    password has a character outside the BMP, because 7-Zip keys with
    UTF-16 and that is where a surrogate pair is tested.

**Determinism is the gate.** `-mmt=1` because the thread count would otherwise
change the stream, every mtime fixed with `os.utime`, and the file order given
by a sorted list rather than by readdir. The exception is AES: 7-Zip draws a
random IV for every AES coder, by design, so those archives are listed in
NOT_REPRODUCIBLE and get `-` for a digest. What covers their contents is the
manifest, which is the source tree, and `listing.txt`, which is hashed and
reads the same from every run because none of its fields is the IV.
"""

import hashlib
import os
import random
import shutil
import subprocess
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
CORPUS = os.path.join(ROOT, "tests", "data", "sevenz")
HASHES = os.path.join(HERE, "containers", "CORPUS-SEVENZ")

MTIME = 1000000000
COMPRESSIBLE = b"the same line, over and over\n" * 400

# The password of every AES fixture: an accent (two UTF-16 units' worth of
# UTF-8 that is one unit) and U+1F600 (a surrogate pair). The unit tests carry
# the same string.
PASSWORD = "ghoti-p\u00e4ss-\U0001F600"


def x86_like(seed, size):
    """Bytes with enough E8/E9 call and jump opcodes for BCJ to change them."""
    rng = random.Random(seed)
    out = bytearray()
    while len(out) < size:
        if rng.random() < 0.08:
            out.append(rng.choice((0xE8, 0xE9)))
            out += rng.randrange(0, 0x4000).to_bytes(4, "little")
        else:
            out.append(rng.randrange(256))
    return bytes(out[:size])


def build_tree(base):
    def write(path, data, mode):
        full = os.path.join(base, path)
        os.makedirs(os.path.dirname(full) or base, exist_ok=True)
        with open(full, "wb") as handle:
            handle.write(data)
        os.chmod(full, mode)

    write("hello.txt", b"hello, archive\n", 0o644)
    write("compressible.txt", COMPRESSIBLE, 0o644)
    write("random.bin", random.Random(7).randbytes(5000), 0o600)
    write("program.bin", x86_like(11, 20000), 0o755)
    write("empty.txt", b"", 0o644)
    write("sub/deep/nested.txt", b"nested\n", 0o644)
    write("sub/one", b"x", 0o644)
    write("unicode/éè\U0001F600.txt", b"unicode name\n", 0o644)
    os.makedirs(os.path.join(base, "emptydir"), exist_ok=True)
    os.chmod(os.path.join(base, "emptydir"), 0o755)
    os.chmod(os.path.join(base, "sub"), 0o755)
    os.chmod(os.path.join(base, "sub/deep"), 0o755)
    os.chmod(os.path.join(base, "unicode"), 0o755)
    os.symlink("hello.txt", os.path.join(base, "link-to-hello"))
    for here, directories, files in os.walk(base):
        for name in list(directories) + list(files):
            os.utime(os.path.join(here, name), (MTIME, MTIME),
                follow_symlinks=False)
    os.utime(base, (MTIME, MTIME))


def run(argv, cwd=None, what=""):
    finished = subprocess.run(argv, cwd=cwd, capture_output=True, text=True,
        stdin=subprocess.DEVNULL)
    if finished.returncode != 0:
        raise SystemExit("%s failed (%s):\n%s\n%s" % (argv[0], what,
            finished.stdout.strip(), finished.stderr.strip()))
    return finished


# (fixture, 7z switches, what it is for)
ARCHIVES = [
    ("basic.7z", [],
        "7-Zip's defaults: LZMA2, solid, header encoded with LZMA"),
    ("copy.7z", ["-mx0"], "the copy coder, which is a folder with no codec"),
    ("lzma.7z", ["-m0=lzma"], "LZMA rather than LZMA2: five property bytes"),
    ("bzip2.7z", ["-m0=bzip2"], "bzip2 as the coder"),
    ("deflate.7z", ["-m0=deflate"], "raw deflate as the coder"),
    ("deflate64.7z", ["-m0=deflate64"], "raw deflate64 (a 64 KB window) as the coder"),
    ("nonsolid.7z", ["-ms=off"],
        "one folder per file, so folder CRCs stand in for file CRCs"),
    ("plainhdr.7z", ["-mhc=off"], "an unencoded header"),
    ("delta.7z", ["-m0=delta:4", "-m1=lzma2"], "a delta filter before LZMA2"),
    ("bcj.7z", ["-mf=BCJ"], "the x86 branch filter"),
    ("arm64.7z", ["-mf=ARM64"], "the ARM64 branch filter"),
    ("bcj2.7z", ["-m0=BCJ2", "-m1=LZMA", "-m2=LZMA:d20", "-m3=LZMA:d20",
        "-mb0:1", "-mb0s1:2", "-mb0s2:3"],
        "BCJ2: four packed streams, each of three behind its own LZMA"),
    ("bcj2-copy.7z", ["-m0=BCJ2", "-m1=Copy", "-m2=Copy", "-m3=Copy",
        "-mb0:1", "-mb0s1:2", "-mb0s2:3"],
        "BCJ2 over Copy: its four streams raw, so BCJ2 is tested alone"),
    ("bcj2-mf.7z", ["-mf=BCJ2"], "BCJ2 as -mf picks it: LZMA2 on the main stream"),
    ("aes.7z", ["-p" + PASSWORD], "AES over LZMA2; the header is not encrypted"),
    ("aes-header.7z", ["-p" + PASSWORD, "-mhe=on"],
        "AES on the data and on the header, which is AES and then LZMA"),
    ("aes-nonsolid.7z", ["-p" + PASSWORD, "-ms=off"],
        "AES, a folder per file: one coder each, the same key"),
    ("aes-copy.7z", ["-p" + PASSWORD, "-mx0"],
        "AES over the copy coder: a wrong password is caught by a CRC-32"),
    ("aes-bcj2.7z", ["-p" + PASSWORD, "-mf=BCJ2"],
        "AES in front of each of BCJ2's four packed streams"),
]

# Archives whose bytes are not a function of their inputs, and why. They still
# have a row in CORPUS-SEVENZ, with `-` for the digest, so that one going
# missing fails.
NOT_REPRODUCIBLE = {
    "aes.7z": "7-Zip draws a random IV for every AES coder",
    "aes-header.7z": "a random IV for the data's coder and the header's",
    "aes-header-one.7z": "a random IV for the data's coder and the header's",
    "aes-nonsolid.7z": "a random IV for every folder's coder",
    "aes-copy.7z": "a random IV for the AES coder",
    "aes-bcj2.7z": "a random IV for each of the four AES coders",
}


# The branch filters beyond x86 and ARM64, each over program.bin alone: they exist
# to put every filter id the reader maps in front of a real decoder, and the
# file's bytes are the same whatever the filter, so a reading that goes wrong
# shows as a wrong CRC.
FILTERS = [
    ("ppc.7z", "PPC"), ("ia64.7z", "IA64"), ("arm.7z", "ARM"),
    ("armt.7z", "ARMT"), ("sparc.7z", "SPARC"), ("riscv.7z", "RISCV"),
]


def generate(destination):
    tree = os.path.join(destination, "_tree")
    if os.path.exists(tree):
        shutil.rmtree(tree)
    os.makedirs(tree)
    build_tree(tree)
    # The symlink is archived only into symlink.7z: without -snl 7-Zip follows
    # it and stores the target's bytes under the link's name, which is a file.
    names = sorted(n for n in os.listdir(tree) if n != "link-to-hello")
    for name, flags, _why in ARCHIVES:
        out = os.path.join(destination, name)
        if os.path.exists(out):
            os.unlink(out)
        run(["7z", "a", "-t7z", "-mmt=1", "-bso0", "-bsp0", "-y"] + flags
                + [out] + names,
            cwd=tree, what=name)
    for name, flt in FILTERS:
        out = os.path.join(destination, name)
        if os.path.exists(out):
            os.unlink(out)
        run(["7z", "a", "-t7z", "-mmt=1", "-bso0", "-bsp0", "-y",
                "-mf=" + flt, out, "program.bin"],
            cwd=tree, what=name)
    # One file with -mhe=on: 7-Zip does not compress a header of fewer than two
    # items, so the header's folder is AES alone.
    run(["7z", "a", "-t7z", "-mmt=1", "-bso0", "-bsp0", "-y", "-p" + PASSWORD,
            "-mhe=on", os.path.join(destination, "aes-header-one.7z"),
            "hello.txt"],
        cwd=tree, what="aes-header-one.7z")
    # Symlinks are stored as links only with -snl.
    run(["7z", "a", "-t7z", "-mmt=1", "-bso0", "-bsp0", "-y", "-snl",
            os.path.join(destination, "symlink.7z"), "hello.txt",
            "link-to-hello"],
        cwd=tree, what="symlink.7z")
    manifest(destination, tree)
    for name in sorted(os.listdir(destination)):
        if name.endswith(".7z"):
            run(["7z", "t", "-bso0", "-bsp0", "-p" + PASSWORD,
                    os.path.join(destination, name)],
                what="7z t " + name)
    listing(destination)
    shutil.rmtree(tree)


def manifest(destination, tree):
    rows = []
    for here, directories, files in os.walk(tree):
        for entry in directories + files:
            full = os.path.join(here, entry)
            rel = os.path.relpath(full, tree)
            if os.path.islink(full):
                continue  # symlink.7z only; the test knows its two entries
            elif os.path.isdir(full):
                rows.append((rel, "directory", 0, 0, ""))
            else:
                data = open(full, "rb").read()
                rows.append((rel, "file", len(data), zlib.crc32(data), ""))
    rows.sort()
    with open(os.path.join(destination, "manifest.tsv"), "w",
            encoding="utf-8") as handle:
        handle.write("# name, type, size, crc32, link target - computed from the\n"
            "# source tree, not from reading any archive.\n"
            "# Generated by tools/oracle/make_sevenz_corpus.py.\n")
        for name, kind, size, crc, link in rows:
            mode = os.lstat(os.path.join(tree, name)).st_mode & 0o7777
            handle.write("%s\t%s\t%d\t%08x\t%o\t%d\t%s\n"
                % (name, kind, size, crc, mode, MTIME, link))


def listing(destination):
    with open(os.path.join(destination, "listing.txt"), "w",
            encoding="utf-8") as handle:
        for name in sorted(os.listdir(destination)):
            if not name.endswith(".7z"):
                continue
            finished = run(["7z", "l", "-slt", "-bso1", "-bsp0",
                "-p" + PASSWORD, os.path.join(destination, name)],
                what="7z l " + name)
            handle.write("### %s\n" % name)
            for line in finished.stdout.splitlines():
                if line.startswith(("Path = ", "Size = ", "Packed Size",
                        "CRC = ", "Method = ", "Solid = ", "Blocks = ",
                        "Folder = ", "Attributes = ")) and "/" not in line[:4]:
                    if line.startswith("Path = ") and os.sep in line \
                            and destination in line:
                        continue
                    handle.write(line + "\n")


def hashes(destination):
    rows = []
    for name in sorted(os.listdir(destination)):
        path = os.path.join(destination, name)
        if not os.path.isfile(path):
            continue
        if name in NOT_REPRODUCIBLE:
            rows.append("-  %s" % name)
            continue
        rows.append("%s  %s" % (
            hashlib.sha256(open(path, "rb").read()).hexdigest(), name))
    return rows


def inside_container():
    return os.environ.get("GHOTI_ARCHIVE_SEVENZ_CORPUS_INNER") == "1"


def main(argv):
    if inside_container():
        generate(argv[1])
        return 0

    sys.path.insert(0, HERE)
    import oracle_env

    check_only = "--check" in argv[1:]
    destination = CORPUS
    if check_only:
        destination = os.path.join(ROOT, "build", "sevenz-corpus-check")
        if os.path.exists(destination):
            shutil.rmtree(destination)
    os.makedirs(destination, exist_ok=True)
    print(oracle_env.provenance(["sevenzip"]), flush=True)
    inner = oracle_env.command("sevenzip",
        ["python3", os.path.join(HERE, "make_sevenz_corpus.py"), destination],
        scratch=[destination])
    environment = dict(os.environ, GHOTI_ARCHIVE_SEVENZ_CORPUS_INNER="1")
    if "run" in inner[:2]:
        cut = inner.index("run") + 1
        engine_argv = (inner[:cut]
            + ["--env", "GHOTI_ARCHIVE_SEVENZ_CORPUS_INNER=1"] + inner[cut:])
    else:
        engine_argv = inner
    finished = subprocess.run(engine_argv, env=environment)
    if finished.returncode != 0:
        return finished.returncode

    rows = hashes(destination)
    if not check_only:
        with open(HASHES, "w", encoding="utf-8") as handle:
            handle.write(
                "# sha256 of every generated 7z fixture and its readings, so\n"
                "# that one which moved fails `make check-sevenz-corpus` rather\n"
                "# than quietly becoming the new expectation.\n"
                "# Regenerated by `make sevenz-corpus`.\n")
            handle.write("\n".join(rows) + "\n")
        print("7z corpus: %d files in %s" % (len(rows), destination))
        return 0

    with open(HASHES, "r", encoding="utf-8") as handle:
        want = [line.rstrip("\n") for line in handle
            if line.strip() and not line.startswith("#")]
    if want == rows:
        print("7z corpus: %d files match containers/CORPUS-SEVENZ" % len(rows))
        return 0
    sys.stderr.write("### The regenerated 7z corpus does not match "
        "CORPUS-SEVENZ ###\n")
    want_map = dict(row.split("  ", 1)[::-1] for row in want)
    got_map = dict(row.split("  ", 1)[::-1] for row in rows)
    for name in sorted(set(want_map) | set(got_map)):
        if want_map.get(name) != got_map.get(name):
            sys.stderr.write("  %s: CORPUS-SEVENZ %s, regenerated %s\n"
                % (name, want_map.get(name, "absent"),
                    got_map.get(name, "absent")))
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
