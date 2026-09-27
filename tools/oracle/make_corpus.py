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

    # A name that fits in no ustar field at all: a single 200-byte component
    # cannot be split at a '/' into a 155-byte prefix and a 100-byte name, so
    # neither field nor any pair of them can hold it. This is what forces GNU's
    # 'L' member and pax's `path=` record, and the length is chosen so that the
    # payload is **longer than one block**: the deepest name here is 611 bytes,
    # so its carrier spans two. A reader that read the payload with a single
    # 512-byte read would pass on every shorter long name and truncate this one -
    # and the existing long-name fixture is 108 bytes, which is one block.
    very_deep = "/".join(["e" * 200] * 3) + "/leaf.txt"
    write(very_deep, b"deeper\n", 0o644)

    # A symlink whose target does not fit the 100-byte linkname field, which is
    # what forces GNU's 'K' member and pax's `linkpath=` record. Separate from
    # the long *name* above and pointed at it, because a reader that implements
    # one mechanism and not the other truncates silently - and a truncated
    # symlink target is a path to somewhere else.
    os.symlink(very_deep, os.path.join(base, "link-to-deep"))
    entries.append("link-to-deep")

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
    ("gnu-longname-blocks.tar", "gnu", ["e" * 200], False,
        "GNU: 'L' payloads longer than one block, 201 to 611 bytes, which a "
        "reader that read the payload with a single block read truncates"),
    ("gnu-longlink.tar", "gnu", ["link-to-hello", "link-to-deep"], False,
        "GNU: a 'K' member carrying a link target too long for the 100-byte "
        "field, beside a symlink whose target fits - so the fixture shows both "
        "the field and the carrier"),
    # pax, split in two because the interesting half and the reproducible half
    # are not the same archive. See PAX_OPTIONS for why atime and ctime have to
    # go, and what that leaves.
    ("pax-basic.tar", "pax", ["hello.txt", "sizes"], False,
        "pax: the format's magic and no extended records at all, which is what "
        "GNU tar writes once the wall-clock records are deleted"),
    ("pax-longname.tar", "pax", ["dddddddddddddddddddddddd"], False,
        "pax: an 'x' member carrying a path= record, which a name too long for "
        "ustar's fields forces"),
    ("pax-longlink.tar", "pax", ["link-to-hello", "link-to-deep"], False,
        "pax: an 'x' member carrying a linkpath= record, beside a symlink whose "
        "target fits the header field - the same pair as gnu-longlink.tar, so "
        "the two mechanisms are compared on one shape"),
]

# pax, continued: the two fixtures that need flags of their own, so they are not
# in the table above.
#
# ("pax-times.tar") A fractional mtime, which is the only way GNU tar emits an
# `mtime=` record at all: with a whole second the header's octal field says the
# same thing and it writes no record. So this is what makes GARC_TIME_PAX_DECIMAL
# and a non-zero nanoseconds field reachable from a real writer rather than only
# from a hand-built header.
PAX_FRACTIONAL_MTIME = "%d.123456789" % MTIME

# ("pax-global.tar") A `g` member, which is the hard one to get a writer to
# produce. `--pax-option=globexthdr.name=` alone does not: GNU tar writes a
# global header only when it has something global to say, and `hdrcharset` is the
# one thing this corpus can give it. What comes out is worth more than the `g`
# alone:
#
#   - a global header whose one record is `hdrcharset=BINARY`, which every member
#     after it inherits;
#   - an `x` member with a `path=` record for the non-ASCII name - written only
#     *because* hdrcharset says the bytes are not UTF-8, so the pair of fixtures
#     (this and pax-longname.tar, which has no hdrcharset) is what separates
#     GARC_NAME_UTF8 from GARC_NAME_UNDECLARED for a name that came from a
#     record;
#   - an `x` member with a `linkpath=` record.
#
# Two things about a global header are not a function of the tree, and
# `make check-corpus` found the second of them:
#
#   - **Its name.** GNU tar's default is `$TMPDIR/GlobalHead.%p.%n`, and `%p` is
#     the process id, so without pinning it the fixture's bytes depend on what pid
#     tar happened to get.
#   - **Its mtime.** `--mtime` sets the *members'* times and a global header is not
#     a member, so it gets a wall-clock reading. Two runs seconds apart produced
#     two different fixtures - the third non-reproducible pax construct this gate
#     has caught, after the atime/ctime records above and GNU tar's sparse member
#     names, which embed a pid the same way and are why sparse is not here.
PAX_GLOBAL_OPTIONS = [
    "--pax-option=globexthdr.name=GlobalHead",
    "--pax-option=globexthdr.mtime=%d" % MTIME,
    "--pax-option=hdrcharset=BINARY",
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


# The malicious corpus, and why every one of these is written by GNU tar rather
# than assembled here.
#
# **A safety predicate tested only against names its author invented measures the
# author's imagination.** That is the argument phase A used to defer this until
# there was an oracle, and it is met by making the *writer* a real tool: every
# name below goes through `tar --transform` with `-P`, so what lands in the header
# is what GNU tar puts there for a caller who asks for that name. `-P` is the flag
# that stops it helpfully stripping a leading `/` or a leading `../`, which is
# itself worth knowing - the default behaviour of the reference is to sanitise,
# and a corpus generated without `-P` would quietly contain nothing hostile at
# all.
#
# Each entry is (source file, stored name, what it is for). The source files are
# n01, n02 ... rather than descriptive, because `--sort=name` orders by the source
# name and a fixed order is what makes the fixture reproducible.
#
# The absolute names point at /tmp rather than /etc: these fixtures are extracted
# inside the container to record what libarchive does with them, and an absolute
# name that *succeeds* writes a file. Where it lands changes nothing about the
# classification and a great deal about what else in the container still works.
MALICIOUS_NAMES = [
    ("n01", "../../../tmp/ghoti-escaped",
        "the classic traversal: leading parent components"),
    ("n02", "/tmp/ghoti-escaped",
        "absolute, which ignores the extraction root rather than climbing out of "
        "it - and which both references *rewrite* rather than refuse"),
    ("n03", "a/../../b",
        "a traversal that starts inside, so a check that only looks at the first "
        "component misses it"),
    ("n04", "a/..",
        "**the discriminating case.** It has a parent component and it resolves "
        "*inside* the root, and the two references disagree about it: Python "
        "accepts it unchanged and libarchive refuses it for containing '..'. A "
        "single safe/unsafe bit would have to pick one of them"),
    ("n05", "./x",
        "a current-directory component, which both references accept - so a "
        "checker that treats any non-ordinary component as an escape is wrong "
        "here"),
    ("n06", "a//b",
        "an empty component, which both references accept"),
    ("n07", "C:\\Windows\\ghoti",
        "a drive letter, which Python accepts unchanged and libarchive strips - "
        "so this one *does* have a reference, and they disagree"),
    ("n08", "\\\\server\\share\\ghoti",
        "a UNC path, which neither reference objects to on a POSIX host"),
    ("n09", "..",
        "the whole name is a parent component"),
    ("n10", "CON",
        "reserved on Windows, ordinary everywhere else. No reference here can "
        "answer it: both run on POSIX"),
    ("n11", "aux.txt",
        "reserved on Windows *with* an extension, which is the form that gets "
        "missed"),
    ("n12", "COM1",
        "the numbered device family"),
    ("n13", "trailing.",
        "Windows strips a trailing dot, so this collides with `trailing`"),
    ("n14", "trailing ",
        "and a trailing space, likewise"),
    ("n15", "esc\x1b[31mred",
        "an ANSI escape in a name, which rewrites a terminal that prints a "
        "listing unescaped"),
    # **These two carry raw bytes, spelled as surrogates.** Written as ordinary
    # `str` they were not hostile at all: `"\x80"` is U+0080, which subprocess
    # encodes to the *well-formed* pair C2 80 on its way to tar, and the fixture
    # then tested a valid name. The surrogate spelling is what Python's
    # `surrogateescape` maps back to a single raw byte, and the assertion in
    # generate_malicious() is what stops the same mistake being made again.
    ("n16", "bad\udc80utf",
        "a byte that no well-formed UTF-8 sequence starts with"),
    ("n17", "over\udcc0\udcaflong",
        "an overlong encoding of '/'. The bytes are not well-formed UTF-8, and a "
        "decoder that accepts them anyway turns this into a separator"),
    ("n18", "a/b/../../../c",
        "descends twice and climbs three times, so the arithmetic has to be a "
        "running depth rather than a count of components"),
]

# Symlink and hardlink targets, which are the half of the problem no per-member
# name check can answer. A symlink to `/` is not an escape by itself; it becomes
# one when a *later* member's path goes through it, and neither member is
# suspicious alone. They are here because phase F needs them, and because the
# check has to be applicable to a *target* as well as to a name.
MALICIOUS_LINKS = [
    ("abs-target", "/tmp/ghoti-escaped", "an absolute link target"),
    ("up-target", "../../..", "a target that climbs out of any root"),
    ("dot-target", "./sibling", "a target that does not escape, as the control"),
]


def generate_malicious(destination, scratch):
    """Write the hostile-name fixtures, all of them through GNU tar."""
    mal = os.path.join(scratch, ".mal")
    if os.path.exists(mal):
        shutil.rmtree(mal)
    os.makedirs(mal)

    # One source file per stored name, and one --transform expression per source.
    transforms = []
    for source, stored, _why in MALICIOUS_NAMES:
        with open(os.path.join(mal, source), "wb") as handle:
            handle.write(b"hostile\n")
        # The replacement goes through sed's s/// so a '&' or a '\' in it would be
        # read as a backreference. Nothing here has one, and this asserts that
        # rather than trusting it - a name that silently arrived mangled would
        # make the fixture test something other than what this table says.
        assert "&" not in stored, stored
        # A name meant to hold bytes that are not well-formed UTF-8 has to be
        # spelled with surrogates, because anything else is encoded on the way to
        # tar and arrives valid. This catches the inverse mistake too: a lone
        # high byte written as a normal character.
        encoded = stored.encode("utf-8", "surrogateescape")
        surrogates = any(0xDC80 <= ord(c) <= 0xDCFF for c in stored)
        assert surrogates or encoded.decode("utf-8", "strict") == stored, (
            "%r encodes to %r, which is not what the table says" % (stored, encoded))
        transforms.append("--transform=s|^%s$|%s|" % (source, stored))

    argv = ["tar", "-P", "--create",
        "--file", os.path.join(destination, "mal-paths.tar"),
        "--format", "ustar"]
    argv += tar_common() + transforms
    argv += ["--directory", mal] + [s for s, _n, _w in MALICIOUS_NAMES]
    finished = subprocess.run(argv, capture_output=True, text=True)
    if finished.returncode != 0:
        raise SystemExit("tar failed for mal-paths.tar:\n%s"
            % finished.stderr.strip())

    # Links, whose targets are the hostile part. Written as real symlinks so that
    # what lands in the linkname field is what GNU tar writes for one.
    links = os.path.join(scratch, ".mallinks")
    if os.path.exists(links):
        shutil.rmtree(links)
    os.makedirs(links)
    with open(os.path.join(links, "sibling"), "wb") as handle:
        handle.write(b"target\n")
    names = ["sibling"]
    for name, target, _why in MALICIOUS_LINKS:
        os.symlink(target, os.path.join(links, name))
        names.append(name)
    # And a hard link, whose target has no string a reader can inspect on the
    # member itself - it names an earlier member of the archive.
    os.link(os.path.join(links, "sibling"), os.path.join(links, "hard"))
    names.append("hard")
    argv = ["tar", "-P", "--create",
        "--file", os.path.join(destination, "mal-links.tar"),
        "--format", "ustar"]
    argv += tar_common() + ["--directory", links] + sorted(names)
    finished = subprocess.run(argv, capture_output=True, text=True)
    if finished.returncode != 0:
        raise SystemExit("tar failed for mal-links.tar:\n%s"
            % finished.stderr.strip())

    # Collisions: two names that differ only in case, and two that differ only in
    # Unicode normalisation. **Neither is detectable from one name**, which is the
    # point - they are here so that phase F has them and so that this library's
    # own tests can say out loud that the check does not claim to find them.
    # Case folding and normalisation need tables this library deliberately does
    # not carry; they are `unicode`'s.
    collide = os.path.join(scratch, ".malcollide")
    if os.path.exists(collide):
        shutil.rmtree(collide)
    os.makedirs(collide)
    for name in ("A.txt", "a.txt",
            b"caf\xc3\xa9".decode("utf-8"), b"cafe\xcc\x81".decode("utf-8")):
        with open(os.path.join(collide, name), "wb") as handle:
            handle.write(b"collide\n")
    argv = ["tar", "-P", "--create",
        "--file", os.path.join(destination, "mal-collisions.tar"),
        "--format", "ustar"]
    argv += tar_common() + ["--directory", collide]
    argv += sorted(os.listdir(collide))
    finished = subprocess.run(argv, capture_output=True, text=True)
    if finished.returncode != 0:
        raise SystemExit("tar failed for mal-collisions.tar:\n%s"
            % finished.stderr.strip())

    # A hostile name too long for the ustar fields, in each format that has a way
    # to carry one. The check must see the name the *carrier* delivered, not the
    # truncated copy in the header behind it - which is the one place a reader
    # that got the carriers wrong would hand a safety check something harmless.
    long_hostile = "../../../" + "/".join(["e" * 80] * 3) + "/tmp/ghoti-escaped"
    with open(os.path.join(mal, "long"), "wb") as handle:
        handle.write(b"hostile\n")
    for fmt, out in (("gnu", "mal-gnu-longpath.tar"),
            ("pax", "mal-pax-longpath.tar")):
        argv = ["tar", "-P", "--create",
            "--file", os.path.join(destination, out), "--format", fmt]
        argv += tar_common()
        if fmt == "pax":
            argv += PAX_OPTIONS
        argv += ["--transform=s|^long$|%s|" % long_hostile]
        argv += ["--directory", mal, "long"]
        finished = subprocess.run(argv, capture_output=True, text=True)
        if finished.returncode != 0:
            raise SystemExit("tar failed for %s:\n%s"
                % (out, finished.stderr.strip()))

    shutil.rmtree(mal)
    shutil.rmtree(links)
    shutil.rmtree(collide)


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

    # pax with a fractional mtime. Separate from the table because it needs a
    # --mtime of its own, which tar_common() fixes for every other fixture.
    out = os.path.join(destination, "pax-times.tar")
    argv = ["tar", "--create", "--file", out, "--format", "pax",
        "--owner=%d" % UID, "--group=%d" % GID, "--numeric-owner",
        "--mtime=@%s" % PAX_FRACTIONAL_MTIME,
        "--sort=name", "--no-acls", "--no-selinux", "--no-xattrs"]
    argv += PAX_OPTIONS + ["--directory", scratch, "hello.txt", "sizes"]
    finished = subprocess.run(argv, capture_output=True, text=True)
    if finished.returncode != 0:
        raise SystemExit("tar failed for pax-times.tar:\n%s"
            % finished.stderr.strip())

    # pax with a global header. See PAX_GLOBAL_OPTIONS for what forces one and
    # why its name has to be pinned.
    out = os.path.join(destination, "pax-global.tar")
    argv = ["tar", "--create", "--file", out, "--format", "pax"]
    argv += tar_common() + PAX_OPTIONS + PAX_GLOBAL_OPTIONS
    argv += ["--directory", scratch, "na\xefve.txt", "link-to-deep"]
    finished = subprocess.run(argv, capture_output=True, text=True)
    if finished.returncode != 0:
        raise SystemExit("tar failed for pax-global.tar:\n%s"
            % finished.stderr.strip())

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

    generate_malicious(destination, scratch)

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


def member_time(info):
    """Seconds and nanoseconds of a member's mtime, as the reference read it.

    **The float is not good enough and the record is.** `info.mtime` is a float,
    which cannot hold a nanosecond: tarfile reads `mtime=1000000000.123456789`
    and reports 1000000000.1234568. The record is in `info.pax_headers['mtime']`
    exactly as the writer spelled it, so that is what this parses, and the float
    is used only where there is no record at all - where the time came from the
    header's octal field and is a whole second by construction.

    Floor rather than truncation toward zero, so that a time before the epoch with
    a fraction has a non-negative nanoseconds part. That is the only reading under
    which seconds + nanoseconds/1e9 equals the value, and it is what this library
    reports - `GARC_Member` has a signed seconds field and an unsigned
    nanoseconds one, so the two have to agree about which way a negative rounds.
    """
    raw = info.pax_headers.get("mtime")
    if raw is None:
        return int(info.mtime), 0
    negative = raw.startswith("-")
    digits = raw.lstrip("+-")
    whole, _, fraction = digits.partition(".")
    seconds = int(whole or "0")
    nanoseconds = int((fraction + "000000000")[:9])
    if negative:
        seconds = -seconds
        if nanoseconds:
            seconds -= 1
            nanoseconds = 1000000000 - nanoseconds
    return seconds, nanoseconds


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
        "# mtime is whole seconds and mtime_ns the sub-second part, because a pax",
        "# `mtime=` record carries nanoseconds and tarfile's own mtime is a float",
        "# that cannot hold one. See member_time() in the generator.",
        "#",
        "# archive\tindex\tname\ttype\tsize\tmtime\tmtime_ns\tmode\tuid\tgid"
        "\tuname\tgname\tlink",
    ]

    for name in sorted(os.listdir(destination)):
        if not name.endswith(".tar"):
            continue
        path = os.path.join(destination, name)
        with tarfile.open(path, "r:") as archive:
            index = 0
            for info in archive:
                seconds, nanoseconds = member_time(info)
                lines.append("\t".join([
                    name,
                    str(index),
                    escape(info.name.encode("utf-8", "surrogateescape")),
                    member_type(info),
                    str(info.size),
                    str(seconds),
                    str(nanoseconds),
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


def verdicts(destination):
    """What each reference would *do* with every member's name.

    **This is the only part of the corpus that records a decision rather than a
    reading**, and it is what turns garc_name_check() from a set of assertions
    about itself into a cross-check. A classifier whose expectations were written
    by the same session that wrote the classifier measures nothing.

    Three columns, because there are three answers and they are not the same
    question:

      - `python_data` is `tarfile.data_filter`, PEP 706's "extract untrusted
        data" policy. Its verdict is **three-valued**: it accepts a name, or
        rewrites it, or raises. That is a finding in itself - an absolute member
        name is *rewritten* rather than refused, so a reader expecting a boolean
        from it would score every absolute path as safe.
      - `python_tar` is `tarfile.tar_filter`, the permissive policy, which is here
        as the control: where the two Python columns differ, the difference is
        policy rather than danger.
      - `libarchive` is whether `bsdtar -x` actually refused the member. It is the
        second opinion on the one case that matters most, because **the two
        references disagree there**: `a/..` has a parent component and resolves
        inside the root, and Python accepts it while libarchive refuses it.

    A per-archive comment records libarchive's *archive-level* messages, the
    "Removing leading '/'" and "Removing leading drive letter" ones. Those are not
    attributable to a member, so they are not a column - but they are the only
    evidence that libarchive treats a drive letter as a hazard at all, which
    Python does not, so they are not dropped either.

    The destination path handed to the Python filters is a fixed literal. The
    verdict for a relative name does not depend on it, and writing it down is
    cheaper than asserting that.
    """
    comments, rows = verdict_rows(destination)
    lines = [
        "# What each reference would DO with each member's name, as opposed to",
        "# what it reads there. Generated by tools/oracle/make_corpus.py inside",
        "# the pinned container; do not edit.",
        "#",
        "# python_data is tarfile.data_filter (PEP 706), whose verdict is three-",
        "# valued: same, rewrite, or a refusal named after its exception.",
        "# python_tar is tarfile.tar_filter, the permissive policy, as the control.",
        "# libarchive is whether `bsdtar -x` refused the member.",
        "#",
        "# These are the REFERENCES' decisions, not this library's. A row this",
        "# library disagrees with is a finding either way round.",
        "#",
        "# archive\tindex\tname\tpython_data\tpython_tar\tlibarchive",
    ]
    lines += comments
    lines += ["\t".join(row) for row in rows]

    with open(os.path.join(destination, "verdicts.tsv"), "w",
            encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def verdict_rows(destination):
    """Ask both references what they would do, and return (comments, rows).

    Separate from verdicts() so that `check-oracle` can ask the same question of
    the committed bytes without a second copy of how it is asked. A checker that
    re-implemented the question would be checking two implementations of it
    against each other rather than the references against the corpus.
    """
    import tarfile

    dest = "/ghoti-dest"
    comments = []
    rows = []

    for name in sorted(os.listdir(destination)):
        if not name.endswith(".tar"):
            continue
        path = os.path.join(destination, name)

        # libarchive first, so its notes land above the rows they describe.
        room = os.path.join("/tmp", "ghoti-extract", name)
        if os.path.exists(room):
            shutil.rmtree(room)
        os.makedirs(room)
        finished = subprocess.run(["bsdtar", "-xf", path], cwd=room,
            capture_output=True)
        refused = set()
        notes = []
        for raw in finished.stderr.split(b"\n"):
            if not raw:
                continue
            if raw.startswith(b"bsdtar: "):
                # An archive-level message, or the delayed-error summary.
                text = raw[len(b"bsdtar: "):]
                if not text.startswith(b"Error exit delayed"):
                    notes.append(escape(text))
                continue
            # A per-member refusal, which libarchive prints as "<name>: <reason>".
            head, _, _tail = raw.partition(b": ")
            refused.add(head)
        if notes:
            comments.append("# %s: libarchive also said: %s"
                % (name, "; ".join(notes)))
        # **What it created, not only what it said.** libarchive prints at most one
        # archive-level "Removing leading ..." message per archive, so in a fixture
        # that has both an absolute name and a drive letter the second rewrite is
        # invisible in stderr - and the drive letter is the only hazard for which
        # libarchive is the *only* reference, because Python accepts it unchanged.
        # The tree it wrote is where that fact lives.
        created = []
        for here, directories, files in os.walk(room):
            relative = os.path.relpath(here, room)
            for entry in sorted(files) + sorted(directories):
                joined = entry if relative == "." else os.path.join(relative, entry)
                created.append(escape(joined.encode("utf-8", "surrogateescape")))
        if created:
            comments.append("# %s: libarchive created: %s"
                % (name, " ".join(sorted(created))))

        with tarfile.open(path, "r:") as archive:
            members = list(archive)

        # The attribution above is by name prefix, so it is checked rather than
        # trusted: every refusal line has to belong to a member of this archive.
        # A line this loop could not place would otherwise vanish, and a vanished
        # refusal reads as libarchive having accepted the member.
        known = {info.name.encode("utf-8", "surrogateescape")
            for info in members}
        stray = refused - known
        if stray:
            raise SystemExit("%s: libarchive refused names that are not members "
                "of it: %r" % (name, sorted(stray)))

        for index, info in enumerate(members):
            try:
                out = tarfile.data_filter(info, dest)
                data = "same" if out.name == info.name else "rewrite"
            except Exception as problem:
                data = type(problem).__name__
            try:
                out = tarfile.tar_filter(info, dest)
                tar = "same" if out.name == info.name else "rewrite"
            except Exception as problem:
                tar = type(problem).__name__
            raw = info.name.encode("utf-8", "surrogateescape")
            rows.append((name, str(index), escape(raw), data, tar,
                "refused" if raw in refused else "extracted"))

        shutil.rmtree(room, ignore_errors=True)

    return comments, rows


def hashes(destination):
    """sha256 of every archive, so a moved fixture fails rather than passes."""
    rows = []
    for name in sorted(os.listdir(destination)):
        if not (name.endswith(".tar")
            or name in ("manifest.tsv", "names.tsv", "verdicts.tsv")):
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
        verdicts(destination)
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
