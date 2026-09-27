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
"""Generate the tar corpus in the pinned container, and a manifest from it.

    make corpus         regenerate tests/data/tar/ and the manifest
    make check-corpus   regenerate into a scratch directory and compare

**Why the corpus is generated rather than hand-built.** A corpus written by
hand contains the shapes whoever wrote it thought of, and a reader tested
against it measures that person's imagination - `notes/` records a library that
scored 395/395 against its own corpus with eleven divergences outstanding. These
fixtures are what GNU tar actually writes, in each of the four formats it can
write, which is a population rather than a set of examples.

**Why the expectations come from a third implementation.** The manifest's rows
are Python's `tarfile` reading each archive back, not this library reading it.
Expectations read off the implementation under test are the defect this suite
exists to avoid, and an expectation read off the *writer* is only half better:
GNU tar agreeing with GNU tar says nothing about whether either agrees with the
format. `bsdtar` is the third opinion and `make check-oracle` is where it is
asked; this file's job is to produce the bytes and one reference's reading of
them.

**Determinism is the whole gate.** Two runs of this script must produce
byte-identical archives, or `check-corpus` cannot tell a regenerated corpus from
a changed one. So every input a tar header can carry is fixed: the mtimes, the
owners, the modes, the order, the contents. What is *not* fixed is anything the
container decides - which is why this runs inside it, with TZ and LANG pinned
there rather than here.
"""

import hashlib
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
CORPUS = os.path.join(ROOT, "tests", "data", "tar")
HASHES = os.path.join(HERE, "containers", "CORPUS")

# Fixed for every archive. The epoch second is 2001-09-09T01:46:40Z, chosen
# because it is far from any boundary (no leap second, no DST anywhere, not a
# 32-bit rollover) and because 1000000000 is recognisable in a hex dump when a
# field is read wrongly.
MTIME = 1000000000
UID = 1234
GID = 5678
UNAME = "ghoti"
GNAME = "ghotigroup"


def build_tree(base):
    """The files every archive is made from.

    One tree, so that a difference between two archives is a difference between
    two *formats* rather than between two trees. Each entry is here because a
    tar header field has a way of being read wrongly:
    """
    entries = []

    def write(path, data, mode):
        full = os.path.join(base, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as handle:
            handle.write(data)
        os.chmod(full, mode)
        entries.append(path)

    # A short name and ordinary contents: the case everything else is measured
    # against.
    write("hello.txt", b"hello, archive\n", 0o644)

    # Sizes either side of every padding boundary. A reader that pads wrongly
    # walks into the next header, and the only sizes that catch it are 0, 1,
    # exactly a block, and one over.
    write("sizes/empty", b"", 0o644)
    write("sizes/one", b"x", 0o644)
    write("sizes/block-1", b"a" * 511, 0o644)
    write("sizes/block", b"b" * 512, 0o644)
    write("sizes/block+1", b"c" * 513, 0o644)

    # Modes that are not 0644. A setuid bit is here because extraction must not
    # honour one by default, and a reader that masks the mode on the way *in*
    # would make that untestable later.
    write("modes/executable", b"#!/bin/sh\nexit 0\n", 0o755)
    write("modes/private", b"secret\n", 0o600)
    write("modes/setuid", b"root\n", 0o4755)

    # A directory with nothing in it. Its size field is zero and some writers
    # leave a stale value there, which a reader that seeks by the field follows
    # into the next header.
    os.makedirs(os.path.join(base, "emptydir"), exist_ok=True)
    entries.append("emptydir")

    # A symlink and a hard link. Neither carries data, both carry a target, and
    # a reader that reads the size field for them mis-seeks.
    os.symlink("hello.txt", os.path.join(base, "link-to-hello"))
    entries.append("link-to-hello")
    os.link(os.path.join(base, "hello.txt"), os.path.join(base, "hardlink"))
    entries.append("hardlink")

    # A name that does not fit ustar's 100-byte field and does fit its 155-byte
    # prefix once split at a '/'. This is the one shape that exercises the
    # prefix join, and a reader that ignores the prefix reports the tail of the
    # path as the whole name - a plausible wrong answer rather than an error.
    deep = "/".join(["d" * 24] * 4) + "/leaf.txt"
    write(deep, b"deep\n", 0o644)

    # A name with a non-ASCII byte, which is what makes the two header checksum
    # readings differ: the signed and unsigned sums are equal until a byte above
    # 0x7F appears.
    write("na\xefve.txt", b"latin-1 name\n", 0o644)

    return sorted(entries)


def tar_common(named_owners=False):
    """The flags that make GNU tar's output a function of the tree alone.

    `named_owners` writes the owner *names* as well as the ids. It is off by
    default because --numeric-owner is what makes the archive independent of the
    container's /etc/passwd, and on for one fixture because the uname and gname
    fields are otherwise empty in every archive here - and a field that is empty
    everywhere in the corpus is a field no test can distinguish from one the
    reader never fills in.
    """
    if named_owners:
        owner = ["--owner=%s:%d" % (UNAME, UID),
            "--group=%s:%d" % (GNAME, GID)]
    else:
        owner = ["--owner=%d" % UID, "--group=%d" % GID, "--numeric-owner"]
    return owner + [
        "--mtime=@%d" % MTIME,
        "--sort=name",
        # Without this the archive records whatever the container's umask and
        # the checkout's atime happened to be.
        "--no-acls",
        "--no-selinux",
        "--no-xattrs",
    ]


ARCHIVES = [
    # (file name, tar --format, the paths to include, named owners, what it is
    # for)
    ("v7-basic.tar", "v7", ["hello.txt", "sizes"], False,
        "v7: no magic at all, so the checksum is the only evidence it is a tar"),
    ("ustar-basic.tar", "ustar",
        ["hello.txt", "emptydir", "link-to-hello", "hardlink"], False,
        "ustar: the four member types that carry no data between them"),
    ("ustar-sizes.tar", "ustar", ["sizes"], False,
        "ustar: every size either side of a padding boundary"),
    ("ustar-modes.tar", "ustar", ["modes"], False,
        "ustar: modes that are not 0644, including a setuid bit"),
    ("ustar-owners.tar", "ustar", ["hello.txt"], True,
        "ustar: the uname and gname fields, which --numeric-owner leaves "
        "empty in every other fixture here"),
    ("ustar-prefix.tar", "ustar", ["dddddddddddddddddddddddd"], False,
        "ustar: a name split across the prefix and name fields"),
    ("ustar-nonascii.tar", "ustar", ["na\xefve.txt"], False,
        "ustar: a header byte above 0x7F, which is what makes the two "
        "checksum readings differ"),
    ("gnu-longname.tar", "gnu", ["dddddddddddddddddddddddd"], False,
        "GNU: an 'L' member carrying the next member's name"),
    # pax, split in two because the interesting half and the reproducible half
    # are not the same archive. See PAX_OPTIONS for why atime and ctime have to
    # go, and what that leaves.
    ("pax-basic.tar", "pax", ["hello.txt", "sizes"], False,
        "pax: the format's magic and no extended records at all, which is what "
        "GNU tar writes once the wall-clock records are deleted"),
    ("pax-longname.tar", "pax", ["dddddddddddddddddddddddd"], False,
        "pax: an 'x' member carrying a path= record, which a name too long for "
        "ustar's fields forces"),
]

# **GNU tar's pax output is not reproducible without this, and finding that out
# was what `make check-corpus` is for.** By default it writes `atime` and `ctime`
# records into every extended header, and both are wall-clock readings of when the
# files were created - so two runs of the generator produced two different
# pax-basic.tar, and the gate caught it on its first run.
#
# Deleting them leaves an archive with no extended records at all for short
# names, which is why there are two pax fixtures: that one covers the format's
# magic (pax uses ustar's, so a pax archive of short names reads as ustar and
# should), and pax-longname.tar covers the `x` member itself, forced by a name
# that does not fit the ustar fields.
#
# The alternative - keeping atime and ctime and excluding pax from the hash gate -
# would have meant one fixture nothing could check.
PAX_OPTIONS = ["--pax-option=delete=atime,delete=ctime"]


def generate(destination):
    """Write every archive into `destination`, and return the tree used."""
    scratch = os.path.join(destination, ".tree")
    if os.path.exists(scratch):
        shutil.rmtree(scratch)
    os.makedirs(scratch)
    build_tree(scratch)

    for name, fmt, paths, named_owners, _why in ARCHIVES:
        out = os.path.join(destination, name)
        argv = ["tar", "--create", "--file", out, "--format", fmt]
        argv += tar_common(named_owners)
        if fmt == "pax":
            argv += PAX_OPTIONS
        argv += ["--directory", scratch]
        argv += paths
        finished = subprocess.run(argv, capture_output=True, text=True)
        if finished.returncode != 0:
            raise SystemExit("tar failed for %s:\n%s"
                % (name, finished.stderr.strip()))

    # An empty archive, which GNU tar will not write from an empty file list
    # without being told the list is deliberately empty. It is two zero blocks
    # and nothing else, and it is the one archive that identifies as a tar with
    # no valid header in it at all.
    out = os.path.join(destination, "ustar-empty.tar")
    finished = subprocess.run(
        ["tar", "--create", "--file", out, "--format", "ustar",
            "--files-from", "/dev/null"] + tar_common(),
        capture_output=True, text=True)
    if finished.returncode != 0:
        raise SystemExit("tar failed for the empty archive:\n%s"
            % finished.stderr.strip())

    shutil.rmtree(scratch)


def escape(raw):
    """A byte string as one field: printable ASCII, everything else \\xHH.

    A member name is bytes and can hold a tab, a newline or a NUL, any of which
    would end the field or the line early in a tab-separated file - so the
    manifest would silently describe a different member from the one in the
    archive.
    """
    out = []
    for byte in raw:
        if byte == 0x5C:
            out.append("\\\\")
        elif 0x20 <= byte < 0x7F:
            out.append(chr(byte))
        else:
            out.append("\\x%02X" % byte)
    return "".join(out)


TYPE_NAMES = {
    "REGTYPE": "file",
    "AREGTYPE": "file",
    "CONTTYPE": "file",
    "DIRTYPE": "directory",
    "SYMTYPE": "symlink",
    "LNKTYPE": "hardlink",
    "FIFOTYPE": "fifo",
    "CHRTYPE": "character device",
    "BLKTYPE": "block device",
}


def member_type(info):
    """This library's type name for a tarfile member.

    Mapped from tarfile's own predicates rather than from the typeflag byte, so
    that the manifest says what the *reference* thinks the member is. Reading
    the byte here would make the manifest a second opinion of ours rather than a
    first opinion of theirs.
    """
    if info.isdir():
        return "directory"
    if info.issym():
        return "symlink"
    if info.islnk():
        return "hardlink"
    if info.isfifo():
        return "fifo"
    if info.ischr():
        return "character device"
    if info.isblk():
        return "block device"
    if info.isreg():
        return "file"
    return "other"


def names(destination):
    """Member names as bsdtar lists them, one row per member.

    **Names come from bsdtar and everything else from Python's tarfile, and that
    split is a finding rather than a convenience.** Python's `tarfile` strips the
    trailing slash from a directory member's name: the bytes in the header say
    `sizes/` and it reports `sizes`. GNU tar's `-t` and bsdtar's both print
    `sizes/`, which is what the archive contains.

    So two of three references agree with each other and with the bytes, and the
    third normalises. This library reports what the container said, so it agrees
    with the two - and comparing its names against the one that normalises would
    have meant either a wrong expectation or a tolerance wide enough to hide a
    real truncation. Naming the reference per question is the answer instead:
    bsdtar is asked about names, tarfile about the metadata it does not
    normalise.

    bsdtar's output is bytes, and a name can hold a newline - which would make
    one member look like two. So this asks bsdtar for the names and checks the
    count against tarfile's; a disagreement there means a name contained a
    newline and the row-per-line assumption broke, which is a failure rather
    than something to work around silently.
    """
    rows = [
        "# Member names as bsdtar (libarchive) lists them. Generated by",
        "# tools/oracle/make_corpus.py inside the pinned container; do not edit.",
        "#",
        "# Names are here rather than in manifest.tsv because Python's tarfile",
        "# strips a directory member's trailing slash and bsdtar does not. The",
        "# bytes in the header have the slash, so bsdtar is the reference for a",
        "# name and tarfile for everything else. See names() in the generator.",
        "#",
        "# archive\tindex\tname",
    ]

    for name in sorted(os.listdir(destination)):
        if not name.endswith(".tar"):
            continue
        finished = subprocess.run(["bsdtar", "-tf", os.path.join(destination, name)],
            capture_output=True)
        if finished.returncode != 0:
            raise SystemExit("bsdtar failed on %s:\n%s"
                % (name, finished.stderr.decode("utf-8", "replace").strip()))
        listing = finished.stdout.split(b"\n")
        if listing and listing[-1] == b"":
            listing.pop()
        for index, raw in enumerate(listing):
            rows.append("%s\t%d\t%s" % (name, index, escape(raw)))

    with open(os.path.join(destination, "names.tsv"), "w",
            encoding="utf-8") as handle:
        handle.write("\n".join(rows) + "\n")


def manifest(destination):
    """One line per member, as Python's tarfile reads it.

    The header is a comment naming the reference, because a manifest that does
    not say who wrote it is a set of numbers a later reader will assume came
    from the code it is testing.
    """
    import tarfile

    lines = [
        "# Member metadata as Python's tarfile reads it. Generated by",
        "# tools/oracle/make_corpus.py inside the pinned container; do not edit.",
        "#",
        "# These are the REFERENCE's readings, not this library's. A row this",
        "# library disagrees with is a finding either way round.",
        "#",
        "# archive\tindex\tname\ttype\tsize\tmtime\tmode\tuid\tgid\tuname\tgname\tlink",
    ]

    for name in sorted(os.listdir(destination)):
        if not name.endswith(".tar"):
            continue
        path = os.path.join(destination, name)
        with tarfile.open(path, "r:") as archive:
            index = 0
            for info in archive:
                lines.append("\t".join([
                    name,
                    str(index),
                    escape(info.name.encode("utf-8", "surrogateescape")),
                    member_type(info),
                    str(info.size),
                    str(info.mtime),
                    "0%o" % info.mode,
                    str(info.uid),
                    str(info.gid),
                    escape(info.uname.encode("utf-8", "surrogateescape")),
                    escape(info.gname.encode("utf-8", "surrogateescape")),
                    escape(info.linkname.encode("utf-8", "surrogateescape")),
                ]))
                index += 1

    with open(os.path.join(destination, "manifest.tsv"), "w",
            encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def hashes(destination):
    """sha256 of every archive, so a moved fixture fails rather than passes."""
    rows = []
    for name in sorted(os.listdir(destination)):
        if not (name.endswith(".tar") or name in ("manifest.tsv", "names.tsv")):
            continue
        with open(os.path.join(destination, name), "rb") as handle:
            digest = hashlib.sha256(handle.read()).hexdigest()
        rows.append("%s  %s" % (digest, name))
    return rows


def inside_container():
    """Whether this process is the one running in the pinned image.

    The script re-invokes itself inside the container, and the two halves have
    to be told apart. An environment variable rather than a flag, so that a
    stray argument cannot make the host half do the container half's work
    against the host's own unpinned tar.
    """
    return os.environ.get("GHOTI_ARCHIVE_CORPUS_INNER") == "1"


def main(argv):
    if inside_container():
        destination = argv[1]
        generate(destination)
        manifest(destination)
        names(destination)
        return 0

    sys.path.insert(0, HERE)
    import oracle_env

    check_only = "--check" in argv[1:]
    destination = CORPUS
    if check_only:
        destination = os.path.join(ROOT, "build", "corpus-check")
        if os.path.exists(destination):
            shutil.rmtree(destination)
    os.makedirs(destination, exist_ok=True)

    # All three: tar writes the fixtures, tarfile reads the metadata back, and
    # bsdtar reads the names. Naming them here means an unreachable reference
    # fails before anything is written rather than partway through.
    print(oracle_env.provenance(["tar", "bsdtar", "pytarfile"]), flush=True)

    inner = oracle_env.command("tar",
        ["python3", os.path.join(HERE, "make_corpus.py"), destination],
        scratch=[destination])
    environment = dict(os.environ, GHOTI_ARCHIVE_CORPUS_INNER="1")
    # The engine does not pass the host environment into the container, so the
    # marker has to be given to `docker run` as well as set here. It goes after
    # the `run` subcommand, not before it: the engine rejects an option it has
    # not reached a subcommand for, with a message that reads like a bad flag
    # name rather than a misplaced one.
    if "run" in inner[:2]:
        cut = inner.index("run") + 1
        engine_argv = (inner[:cut]
            + ["--env", "GHOTI_ARCHIVE_CORPUS_INNER=1"] + inner[cut:])
    else:
        # Host mode: no engine, so the environment above is the whole of it.
        engine_argv = inner
    finished = subprocess.run(engine_argv, env=environment)
    if finished.returncode != 0:
        return finished.returncode

    rows = hashes(destination)
    if not check_only:
        with open(HASHES, "w", encoding="utf-8") as handle:
            handle.write(
                "# sha256 of every generated fixture, so that a fixture which\n"
                "# moved fails `make check-corpus` rather than quietly becoming\n"
                "# the new expectation. Regenerated by `make corpus`.\n")
            handle.write("\n".join(rows) + "\n")
        print("corpus: %d files in %s" % (len(rows), destination))
        return 0

    with open(HASHES, "r", encoding="utf-8") as handle:
        want = [line.rstrip("\n") for line in handle
            if line.strip() and not line.startswith("#")]
    if want == rows:
        print("corpus: %d files match containers/CORPUS" % len(rows))
        return 0

    sys.stderr.write("### The regenerated corpus does not match CORPUS ###\n")
    want_map = dict(row.split("  ", 1)[::-1] for row in want)
    got_map = dict(row.split("  ", 1)[::-1] for row in rows)
    for name in sorted(set(want_map) | set(got_map)):
        if want_map.get(name) != got_map.get(name):
            sys.stderr.write("  %s: CORPUS %s, regenerated %s\n"
                % (name, want_map.get(name, "absent"),
                    got_map.get(name, "absent")))
    sys.stderr.write(
        "\nEither the generator changed - in which case `make corpus` and\n"
        "commit both - or the reference moved, which is a finding to triage\n"
        "rather than a hash to update.\n")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
