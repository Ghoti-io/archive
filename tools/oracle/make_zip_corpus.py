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
"""Generate the zip corpus in the pinned container, and three readings of it.

    make zip-corpus         regenerate tests/data/zip/ and the hash list
    make check-zip-corpus   regenerate into a scratch directory and compare

A separate file from make_corpus.py, and separate hash lists, for one mechanical
reason: each generator rewrites its whole list from what it produced, so one
shared list would have to be *merged* by whichever generator ran - and a
generator that preserves lines it did not produce cannot tell a dropped fixture
from a fixture it was not asked for. Two lists, each written whole by one
generator, keeps the denominator honest in both.

**Four writers, not one.** tar's corpus is GNU tar in four formats because GNU
tar is what writes tars. Zip has no such centre: Info-ZIP wrote most of the zip
files in the world, libarchive writes the ones that come out of bsdtar and every
program that links it, 7-Zip writes what neither of the others will, and Python's
zipfile is the only one here that will store a name or a comment of the caller's
choosing. They disagree about what a zip looks like in ways that matter to a
reader, and each disagreement is a fixture:

  - Info-ZIP writes a `UT` extended timestamp (0x5455) and a Unix uid/gid
    (0x7875) by default, and the UT is **nine bytes in the local header and five
    in the central directory** - the same extra field, two lengths, because the
    local copy carries an atime the central one does not. A reader that parses
    one layout in both places gets a wrong time from a real archive that every
    tool on earth accepts. `-X` turns both off, which is what makes a member
    whose only time is the two-second DOS field reachable.
  - libarchive writes a **data descriptor for every member with data**, even
    into a seekable file: the local header's sizes are zero and the real values
    are after the data and in the central directory. This is the fixture for the
    rule the plan states - trust the central directory - and it comes from an
    ordinary tool doing its ordinary thing, not from anything hostile.
  - 7-Zip writes an **NTFS timestamp extra (0x000a) in the central directory
    only**, a `version made by` of 0x033f where Info-ZIP writes 0x031e, and DOS
    attribute bits in the low half of `external_file_attributes` that Info-ZIP
    leaves zero. It is also the only writer here that produces WinZip AES.
  - Python's zipfile is where an arbitrary name, an arbitrary comment, a
    duplicate name, a forced zip64 field and an empty archive come from, because
    every other writer here is a *tool* that declines to do those things.

**The references disagree about whole archives, and that is a committed fact.**
`openings.tsv` records what each of the four does when handed each fixture,
because three of these archives are refused by one reference and accepted by the
other three:

  - an archive comment containing the bytes `PK\\x05\\x06` is refused by Python
    and read correctly by unzip, bsdtar and 7-Zip. Python's `_EndRecData` does an
    `rfind` for the signature, and a signature *inside the comment* is later in
    the file than the real record, so it finds the decoy. This is the exact input
    the plan's "the EOCD scan is bounded" bullet is about, and it is the reason
    this library's scan validates the comment length rather than taking the first
    signature it meets.
  - a zip with bytes in front of it (a self-extracting stub) is refused by 7-Zip
    and by Python, warned about and then read by unzip, and read silently by
    bsdtar.
  - an empty archive - one EOCD record and nothing else - is a warning and exit 1
    from unzip, and zero members from everything else.

A single reference would have made each of those look like a fact about zip.

**Determinism is the whole gate**, as it is for the tar corpus: two runs must
produce byte-identical archives or `check-zip-corpus` cannot tell a regenerated
corpus from a changed one. Every mtime in the tree is set with `os.utime`, every
writer is given its inputs in a fixed order, and **every 7-Zip invocation passes
`-mmt=1`**, because its thread count defaults to the host's core count and a
fixture compressed by twelve threads is not the one compressed by four. All four
writers were checked for run-to-run identity before they were trusted here.
"""

import hashlib
import os
import shutil
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
CORPUS = os.path.join(ROOT, "tests", "data", "zip")
HASHES = os.path.join(HERE, "containers", "CORPUS-ZIP")

# The same epoch second the tar corpus uses, for the same reasons - far from
# every boundary, and recognisable in a hex dump - and one more that is zip's
# own: the DOS date/time field has two-second resolution, and 1000000000 is an
# even second, so the DOS field and the extended one agree exactly. A reader
# getting the DOS conversion wrong by a second has nowhere to hide.
MTIME = 1000000000
# 2001-09-09T01:46:40Z as the six DOS fields. Written out rather than computed
# from MTIME, because computing it here would use the same arithmetic the
# library uses and a shared mistake would cancel.
DOS_DATETIME = (2001, 9, 9, 1, 46, 40)

UID = 1234
GID = 5678
PASSWORD = "ghoti-password"

# Content that deflate actually shrinks. `hello, archive\n` does not: Info-ZIP
# and 7-Zip both fall back to stored when the compressed form would be bigger, so
# an archive built only from short files has no method 8 in it at all - which is
# how a corpus meant to cover deflate ends up covering nothing but stored.
COMPRESSIBLE = b"the same line, over and over\n" * 40


def build_tree(base):
    """The files the zip fixtures are made from, with every mtime fixed."""
    def write(path, data, mode):
        full = os.path.join(base, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as handle:
            handle.write(data)
        os.chmod(full, mode)

    write("hello.txt", b"hello, archive\n", 0o644)
    write("compressible.txt", COMPRESSIBLE, 0o644)

    # Sizes either side of nothing in particular, because zip has no padding -
    # which is itself the point. These are here because the *offsets* in the
    # central directory are absolute, so an off-by-one in a size is an off-by-one
    # in the next member's offset, and a zero-length member is where a reader
    # that seeks by size lands exactly on the next header whether it is right or
    # not.
    write("sizes/empty", b"", 0o644)
    write("sizes/one", b"x", 0o644)
    write("sizes/many", b"y" * 1000, 0o644)

    write("modes/executable", b"#!/bin/sh\nexit 0\n", 0o755)
    write("modes/setuid", b"root\n", 0o4755)

    os.makedirs(os.path.join(base, "emptydir"), exist_ok=True)
    os.symlink("hello.txt", os.path.join(base, "link-to-hello"))

    # Fixed last, and with follow_symlinks=False, so the symlink's own timestamp
    # is set rather than its target's. Info-ZIP stores a symlink's mtime from the
    # link, and a link whose time came from the wall clock would move the fixture.
    for here, directories, files in os.walk(base):
        for name in list(directories) + list(files):
            os.utime(os.path.join(here, name), (MTIME, MTIME),
                follow_symlinks=False)
    os.utime(base, (MTIME, MTIME))


def run(argv, cwd=None, what=""):
    """Run a writer, and fail loudly rather than leaving a short fixture."""
    finished = subprocess.run(argv, cwd=cwd, capture_output=True, text=True)
    if finished.returncode != 0:
        raise SystemExit("%s failed (%s):\n%s\n%s" % (argv[0], what,
            finished.stdout.strip(), finished.stderr.strip()))
    return finished


# Info-ZIP's `zip`, whose flags are what most of the zip files in the world were
# written with. Each entry is (fixture, extra flags, the paths, what it is for).
#
# `-X` is on wherever the fixture is not about the extra fields, because without
# it every member carries a UT and a Ux and the fixture that is *about* the DOS
# time field would not have one.
INFOZIP = [
    ("infozip-stored.zip", ["-0", "-X"],
        ["hello.txt", "sizes/empty", "sizes/one", "sizes/many"],
        "stored members and nothing else: the baseline, with no extra field "
        "in either record and every size held in the fields that hold it"),
    ("infozip-deflate.zip", ["-9", "-X"],
        ["hello.txt", "compressible.txt", "sizes/many"],
        "method 8 beside method 0 in one archive, because Info-ZIP stores what "
        "deflate would not shrink - so the mix is what a real writer produces "
        "and a fixture of one method is not"),
    ("infozip-extras.zip", ["-9"],
        ["hello.txt", "compressible.txt"],
        "Info-ZIP's defaults: a UT extended timestamp (0x5455) that is nine "
        "bytes in the local header and five in the central directory, and a "
        "Unix uid/gid (0x7875). The one fixture where the two records' extra "
        "fields are not the same bytes"),
    ("infozip-unix.zip", ["-y", "-X"],
        ["emptydir/", "link-to-hello", "modes/executable", "modes/setuid",
            "hello.txt"],
        "a directory, a symlink whose data is its target, and modes with an "
        "executable and a setuid bit - all of which live in the high half of "
        "external_file_attributes and are valid only because version made by "
        "says Unix"),
    ("infozip-zip64.zip", ["-fz", "-X"], ["hello.txt", "sizes/one"],
        "zip64 forced on a small archive: both sizes are 0xFFFFFFFF in the "
        "fields and real in a 0x0001 extra field, in the local header as well "
        "as the central directory"),
    ("infozip-crypto.zip", ["-0", "-X", "-P", PASSWORD],
        ["hello.txt", "sizes/one"],
        "ZipCrypto, which phase D reads and will never write. Info-ZIP also "
        "sets general purpose flag bit 3 here, so the sizes are in a data "
        "descriptor as well - two features that arrive together in practice"),
]


def generate_infozip(destination, tree):
    for name, flags, paths, _why in INFOZIP:
        out = os.path.join(destination, name)
        # `zip` names are taken relative to the working directory, and the order
        # on the command line is the order in the archive: an archive whose
        # member order came from readdir would not be reproducible.
        run(["zip", "-q"] + flags + [out] + paths, cwd=tree, what=name)


def generate_bsdtar(destination, tree):
    """libarchive's zip writer, which is the data-descriptor reference."""
    out = os.path.join(destination, "bsdtar-descriptors.zip")
    run(["bsdtar", "--format", "zip", "-cf", out,
            "hello.txt", "compressible.txt", "sizes/empty", "emptydir"],
        cwd=tree, what="bsdtar-descriptors.zip")


# 7-Zip, and the two things only it will write here.
SEVENZIP = [
    ("sevenzip-basic.zip", ["-mm=Deflate"], ["hello.txt", "compressible.txt"],
        "a third writer's idea of a zip: an NTFS timestamp extra (0x000a) in "
        "the central directory and none in the local header, a version made by "
        "of 0x033f, and DOS attribute bits Info-ZIP leaves at zero"),
    # Method 9 is Deflate64, 12 bzip2, 14 LZMA, 98 PPMd. Each is a method this
    # library refuses, and the refusal has to *name the number* - which is only
    # testable against an archive that really contains it. unzip 6.00 refuses
    # LZMA itself, with "need PK compat. v6.3 (can do v4.6)", so the refusal is
    # not this library being conservative.
    ("sevenzip-methods.zip", ["-mm=BZip2"], ["compressible.txt"],
        "method 12, bzip2: a codec-gated refusal that must name the number"),
    ("sevenzip-lzma.zip", ["-mm=LZMA"], ["compressible.txt"],
        "method 14, LZMA - which Info-ZIP's own unzip 6.00 also refuses"),
    ("sevenzip-ppmd.zip", ["-mm=PPMd"], ["compressible.txt"],
        "method 98, PPMd, which no codec in the suite implements"),
    ("sevenzip-deflate64.zip", ["-mm=Deflate64"], ["compressible.txt"],
        "method 9, enhanced deflate: the one refusal that is *nearly* a method "
        "we have, which is why it is here rather than assumed"),
]


def generate_sevenzip(destination, tree):
    for name, flags, paths, _why in SEVENZIP:
        out = os.path.join(destination, name)
        run(["7z", "a", "-tzip", "-mmt=1", "-bso0", "-bsp0"] + flags
                + [out] + paths, cwd=tree, what=name)

    # WinZip AES: method 99, with the real method and the key strength in a
    # 0x9901 extra field. Phase H reads it; until then the refusal has to say
    # AES rather than "unsupported", and this is the archive that proves it does.
    run(["7z", "a", "-tzip", "-mmt=1", "-bso0", "-bsp0",
            "-p" + PASSWORD, "-mem=AES256",
            os.path.join(destination, "sevenzip-aes.zip"), "hello.txt"],
        cwd=tree, what="sevenzip-aes.zip")


def python_info(name, mode=0o644, method=None, comment=None):
    """A ZipInfo with everything a wall clock would otherwise decide."""
    import zipfile
    info = zipfile.ZipInfo(name, DOS_DATETIME)
    # The high half is st_mode, the low half DOS attributes. Python leaves both
    # zero unless told, and a fixture whose mode is zero cannot distinguish a
    # reader that ignores the field from one that reads it.
    info.external_attr = (mode << 16)
    if name.endswith("/"):
        info.external_attr |= 0x10  # The DOS directory bit, as every writer sets.
    info.create_system = 3  # Unix, which is what makes the mode bits meaningful.
    if method is not None:
        info.compress_type = method
    if comment is not None:
        info.comment = comment
    return info


def generate_python(destination):
    """The fixtures no tool here will write, from the module that will."""
    import warnings
    import zipfile

    def archive(name, build, comment=None):
        path = os.path.join(destination, name)
        with warnings.catch_warnings():
            # A duplicate name is a UserWarning from zipfile, and it is exactly
            # what one fixture is for. Silenced rather than avoided.
            warnings.simplefilter("ignore")
            with zipfile.ZipFile(path, "w") as handle:
                build(handle)
                if comment is not None:
                    handle.comment = comment

    # Methods 0, 8, 12 and 14 from a second writer. The refusal for a method
    # must not depend on which program produced it, and 7-Zip's LZMA member and
    # Python's are not the same bytes - Python writes a two-byte LZMA properties
    # header of its own inside the member.
    def methods(handle):
        handle.writestr(python_info("stored.txt", method=zipfile.ZIP_STORED),
            COMPRESSIBLE)
        handle.writestr(python_info("deflated.txt", method=zipfile.ZIP_DEFLATED),
            COMPRESSIBLE)
        handle.writestr(python_info("bzip2.txt", method=zipfile.ZIP_BZIP2),
            COMPRESSIBLE)
        handle.writestr(python_info("lzma.txt", method=zipfile.ZIP_LZMA),
            COMPRESSIBLE)
    archive("python-methods.zip", methods)

    # The UTF-8 flag, and its absence, in one archive. Bit 11 of the general
    # purpose flags is the only thing that ever says anything about a name's
    # encoding, and `GARC_NAME_UNDECLARED` is the answer for every name without
    # it - which is most names in the world, and is not the same as "ASCII".
    def names(handle):
        handle.writestr(python_info("naïve.txt"), b"a non-ASCII name\n")
        handle.writestr(python_info("plain.txt"), b"an ASCII name\n")
    archive("python-names.zip", names)

    # A member comment, and an archive comment holding the EOCD signature with
    # **fewer than 22 bytes behind it**, so no end record can fit there. unzip,
    # bsdtar and 7-Zip all read this archive; Python does not, because its
    # `_EndRecData` takes the last signature in the tail and does not come back
    # for another when the arithmetic fails.
    def comments(handle):
        handle.writestr(
            python_info("hello.txt", comment=b"a member comment"),
            b"hello, archive\n")
        handle.writestr(python_info("plain.txt"), b"no comment\n")
    archive("python-comments.zip", comments,
        comment=b"a decoy follows: PK\x05\x06 and more.")

    # The same archive with the same decoy and **22 bytes behind it**, so the
    # decoy is a whole record's worth of bytes and every field of it can be read.
    # That one difference is the pair, and what it measures is that the four
    # references do not even scan the same way: unzip reads the archive above and
    # refuses this one, 7-Zip reads both, Python refuses both - for two different
    # reasons, "File is not a zip file" there and "Bad offset for central
    # directory" here - and bsdtar reads both. "How far the signature is from the
    # end" is an axis three of the four turn on somewhere, and no single fixture
    # would have shown it.
    #
    # The decoy's own comment-length field is text, so it does not equal the
    # bytes remaining after it, and a scan that checks that keeps going back and
    # finds the real record. This library therefore reads this archive, alone
    # among the five - a disagreement recorded in openings.tsv rather than
    # resolved by agreeing with the majority.
    archive("python-eocd-decoy.zip", comments,
        comment=b"a decoy follows: PK\x05\x06\x00\x00 and 22 bytes after it")

    # A decoy in a *member's data* rather than in the comment: a whole plausible
    # central directory header and end record, stored uncompressed, inside a
    # member of an otherwise ordinary archive. This is the one the plan's "a
    # reader that scans the whole file finds a signature inside member data"
    # bullet is about, and it is the **control**: every reference reads it, so a
    # reader that this archive breaks is broken by its own scan and not by the
    # archive.
    decoy = (b"PK\x01\x02" + b"\x00" * 42 + b"decoy.txt"
        + b"PK\x05\x06" + b"\x00" * 16 + b"\x00\x00")
    def data_decoy(handle):
        handle.writestr(python_info("innocent.txt"), b"before the decoy\n")
        handle.writestr(python_info("decoy-inside.bin",
            method=zipfile.ZIP_STORED), decoy)
        handle.writestr(python_info("after.txt"), b"after the decoy\n")
    archive("python-data-decoy.zip", data_decoy)

    # A comment of the maximum length the field can express. The EOCD scan is
    # bounded by exactly this, so it is the input that separates a bound of
    # 65535 + 22 from any smaller one - and from a scan of the whole file, which
    # would find a signature inside member data.
    def one(handle):
        handle.writestr(python_info("hello.txt"), b"hello, archive\n")
    archive("python-maxcomment.zip", one, comment=b"c" * 65535)

    # Two members with one name. Every reference here accepts it and reports
    # both, which is the answer this library gives too - reporting both and
    # letting the caller decide, rather than silently picking the one some other
    # tool would have picked.
    def dups(handle):
        handle.writestr(python_info("same.txt"), b"first\n")
        handle.writestr(python_info("same.txt"), b"second, and different\n")
    archive("python-dups.zip", dups)

    # An archive with no members: 22 bytes, one EOCD record. unzip calls it a
    # warning and exits 1; the other three read zero members. It is also the
    # smallest possible zip, so it is the lower bound on the backwards scan.
    archive("python-empty.zip", lambda handle: None)

    # zip64 from a second writer, and mixed: one member forced into zip64 fields
    # beside one that is not, so the reader cannot pass by assuming either
    # answer for the whole archive.
    path = os.path.join(destination, "python-zip64.zip")
    with zipfile.ZipFile(path, "w") as handle:
        info = python_info("forced.txt", method=zipfile.ZIP_STORED)
        with handle.open(info, "w", force_zip64=True) as member:
            member.write(b"zip64 by force, not by size\n")
        handle.writestr(python_info("ordinary.txt"), b"no zip64 here\n")

    # Bytes in front of a zip, which is what a self-extracting archive is. The
    # central directory's offsets are then wrong by the length of the stub, and
    # what the references do about that is the disagreement in openings.tsv.
    # Built from a *clean* archive rather than from python-comments.zip, so that
    # a refusal here is attributable to the stub and not to the decoy comment.
    stub = b"#!/bin/sh\necho 'not a real stub'\nexit 0\n"
    with open(os.path.join(destination, "python-names.zip"), "rb") as handle:
        body = handle.read()
    with open(os.path.join(destination, "python-prologue.zip"), "wb") as handle:
        handle.write(stub + body)


def generate(destination):
    """Write every fixture into `destination`."""
    tree = os.path.join(destination, ".tree")
    if os.path.exists(tree):
        shutil.rmtree(tree)
    os.makedirs(tree)
    build_tree(tree)

    generate_infozip(destination, tree)
    generate_bsdtar(destination, tree)
    generate_sevenzip(destination, tree)
    generate_python(destination)

    shutil.rmtree(tree)


def escape(raw):
    """A byte string as one field: printable ASCII, everything else \\xHH.

    The same function as the tar corpus's, and for the same reason: a member name
    is bytes and can hold a tab or a newline, either of which would end a field
    or a line early and make the manifest describe a different member.
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


def fixtures(destination):
    """The fixture names, in the order every reading is emitted in."""
    return sorted(name for name in os.listdir(destination)
        if name.endswith(".zip"))


def extra_ids(raw):
    """The extra field's ids and lengths, as `id/length` pairs.

    The ids and not the contents. What this is for is the fact that Info-ZIP's UT
    is a different *length* in the two records and 7-Zip's NTFS field is in only
    one of them, and both of those are visible in the ids alone. Decoding each
    field's payload would put a second implementation of the extra fields in the
    oracle, which is the thing an oracle must not contain.
    """
    ids = []
    offset = 0
    while offset + 4 <= len(raw):
        identifier, length = struct.unpack_from("<HH", raw, offset)
        ids.append("%04x/%d" % (identifier, length))
        offset += 4 + length
    if offset != len(raw):
        # A trailing fragment is a fact about the archive, not a parse failure to
        # hide: it is what a writer that miscounted leaves, and a reader has to
        # decide what to do with it.
        ids.append("+%d" % (len(raw) - offset))
    return ",".join(ids)


MANIFEST_COLUMNS = ("archive", "index", "name", "size", "csize", "method",
    "crc", "dos_datetime", "flags", "utf8", "mode", "create_system",
    "version_needed", "header_offset", "comment", "extra_ids")


def manifest(destination, out=None):
    """One line per member, as Python's zipfile reads it.

    **Every column here is a field Python reports, not a conclusion it draws.**
    The one exception is `utf8`, which is bit 11 of `flag_bits` given a name -
    and it is named rather than left to be re-derived because it is the whole of
    what any container ever says about a name's encoding.

    Two things are deliberately *not* columns:

      - **A member type.** Python's only predicate is `is_dir()`, which is a test
        on the name's last byte. Whether a member is a symlink is a reading of
        the mode bits in `external_file_attributes`, and that is a decision - so
        it comes from bsdtar in `names.tsv`, which is a reference that makes it.
      - **A time in seconds.** `date_time` is the six DOS fields, and DOS time
        carries no zone at all: turning it into an epoch second requires choosing
        one, which is this library's decision to document rather than a reading to
        copy. The extended timestamp extra fields *are* epoch seconds, and Python
        does not parse them - so the fixture's construction is what pins those,
        and every mtime in the tree is MTIME.

    The archives Python refuses are not in here, and `openings.tsv` is where that
    fact is recorded. A manifest that silently skipped them would make a corpus of
    18 archives look like a corpus of 16.
    """
    import zipfile

    lines = [
        "# Member metadata as Python's zipfile reads it. Generated by",
        "# tools/oracle/make_zip_corpus.py inside the pinned container; do not",
        "# edit.",
        "#",
        "# These are the REFERENCE's readings, not this library's. A row this",
        "# library disagrees with is a finding either way round.",
        "#",
        "# dos_datetime is the six DOS fields as Python reports them, because",
        "# the DOS field carries no time zone and turning it into an epoch",
        "# second is a decision rather than a reading. utf8 is bit 11 of the",
        "# general purpose flags. There is no type column: see manifest() in",
        "# the generator, and names.tsv, which has one from a reference that",
        "# decides it.",
        "#",
        "# An archive this reference refuses is absent from here and present in",
        "# openings.tsv, which is the file that says so.",
        "#",
        "# " + "\t".join(MANIFEST_COLUMNS),
    ]

    for name in fixtures(destination):
        path = os.path.join(destination, name)
        try:
            handle = zipfile.ZipFile(path)
        except Exception:
            continue
        with handle:
            for index, info in enumerate(handle.infolist()):
                lines.append("\t".join([
                    name,
                    str(index),
                    escape(info.orig_filename.encode("utf-8",
                        "surrogateescape")),
                    str(info.file_size),
                    str(info.compress_size),
                    str(info.compress_type),
                    "%08x" % (info.CRC & 0xFFFFFFFF),
                    "%04d-%02d-%02dT%02d:%02d:%02d" % info.date_time,
                    "%04x" % info.flag_bits,
                    "1" if info.flag_bits & 0x800 else "0",
                    "0%o" % ((info.external_attr >> 16) & 0xFFFF),
                    str(info.create_system),
                    str(info.extract_version),
                    str(info.header_offset),
                    escape(info.comment),
                    extra_ids(info.extra),
                ]))

    with open(os.path.join(out or destination, "manifest.tsv"), "w",
            encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def bsdtar_rows(destination):
    """bsdtar's verbose listing, parsed into (archive, index, type, mode, name,
    link).

    **bsdtar is the reference for a member's type, and it is the only one here
    that decides one.** A zip member is a directory because its name ends in `/`
    and a symlink because the mode bits in the high half of
    `external_file_attributes` say so - and the second is a reading of a field
    that is only valid when `version made by` says Unix. libarchive makes that
    decision; Python's zipfile does not make it at all.

    The listing is parsed from the right, because a name is the last field and a
    symlink's is followed by ` -> target`. Every assumption that parse makes is
    asserted rather than trusted: a name with a space in it, or with ` -> ` in
    it, would silently produce a different row.
    """
    rows = []
    for name in fixtures(destination):
        finished = subprocess.run(
            ["bsdtar", "-tvf", os.path.join(destination, name)],
            capture_output=True)
        if finished.returncode != 0:
            # Not a failure here: an archive libarchive refuses has no rows, and
            # openings.tsv is where the refusal is recorded. Recording it in both
            # places would be two spellings of one fact.
            continue
        index = 0
        for raw in finished.stdout.split(b"\n"):
            if not raw:
                continue
            fields = raw.split(None, 8)
            if len(fields) < 9:
                raise SystemExit("%s: bsdtar's listing has %d fields, not 9: %r"
                    % (name, len(fields), raw))
            mode = fields[0]
            remainder = fields[8]
            target = b""
            if b" -> " in remainder:
                remainder, _, target = remainder.partition(b" -> ")
            if b" " in remainder:
                raise SystemExit(
                    "%s: a member name with a space in it breaks this parse: %r"
                    % (name, remainder))
            kind = {0x64: "directory", 0x6C: "symlink", 0x2D: "file"}.get(
                mode[0], "other")
            rows.append((name, str(index), kind, escape(mode), escape(remainder),
                escape(target)))
            index += 1
    return rows


NAMES_COLUMNS = ("archive", "index", "type", "mode", "name", "link")


def names(destination, out=None):
    """Member names, types and modes as bsdtar lists them."""
    rows = bsdtar_rows(destination)
    lines = [
        "# Member names, types and modes as bsdtar (libarchive) lists them.",
        "# Generated by tools/oracle/make_zip_corpus.py inside the pinned",
        "# container; do not edit.",
        "#",
        "# bsdtar rather than Python because a *type* is a decision and Python's",
        "# zipfile does not make one: it offers is_dir(), which is a test on the",
        "# name's last byte, and nothing at all about a symlink. libarchive reads",
        "# the mode bits out of external_file_attributes and decides, which is",
        "# the same thing this library does - so it is the reference that can",
        "# disagree with us.",
        "#",
        "# mode is libarchive's rendering of those bits, which makes it a second",
        "# opinion on the mode as well as the type.",
        "#",
        "# " + "\t".join(NAMES_COLUMNS),
    ]
    lines += ["\t".join(row) for row in rows]
    with open(os.path.join(out or destination, "names.tsv"), "w",
            encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


# What each reference is asked, to decide whether it accepts an archive at all.
# `unzip -t` is the accepted answer to "is this a valid zip"; the other three are
# asked to list, which is the cheapest question that requires reading the
# structure. None of them is asked to extract: what an extractor does with a
# hostile *name* is a different question, it belongs with the malicious corpus,
# and it writes files.
OPENINGS = [
    ("unzip", ["unzip", "-t"]),
    ("bsdtar", ["bsdtar", "-tf"]),
    ("sevenzip", ["7z", "l", "-ba"]),
]

OPENINGS_COLUMNS = ("archive", "reference", "verdict", "exit", "note")

# Words that mark a line as a diagnostic rather than part of a listing. Deliberately
# not "empty": unzip's complaint about an empty archive contains "warning", and a
# match on "empty" would also match every line that merely names
# python-empty.zip - which is how a note ends up quoting the banner instead of the
# problem.
DIAGNOSTIC_WORDS = ("error", "warning", "skipping", "cannot", "not a", "need ",
    "unable", "missing", "is empty")


def diagnostics(finished, name):
    """The diagnostic lines of a reference's output, as one field.

    Every matching line rather than the first, because the first is often the
    least informative: 7-Zip's refusal opens with `ERROR: <name> : <name>` and
    says what is actually wrong two lines later. The banner line and any line
    that is only the fixture's name are dropped, and what is left is joined - so
    a note says what the reference objected to, and an accepted archive's listing
    does not become a note.
    """
    text = (finished.stderr + b"\n" + finished.stdout).decode("utf-8", "replace")
    kept = []
    for line in text.split("\n"):
        line = " ".join(line.split())
        if not line or line.startswith("Archive:  ") or line == name:
            continue
        if line.replace(name, "").strip(" :") == "":
            continue
        lowered = line.lower()
        if any(word in lowered for word in DIAGNOSTIC_WORDS):
            if line not in kept:
                kept.append(line)
    joined = " | ".join(kept)
    # Capped, because a reference that objects to every member of a large archive
    # would otherwise put its whole output in one field. The cap is generous
    # enough that nothing in this corpus reaches it, which is asserted by the
    # fixture that comes closest rather than assumed.
    return joined[:400]


def openings(destination, out=None):
    """What each reference does when handed each archive.

    **This is the file that records a disagreement about a whole archive**, which
    no per-member manifest can hold: three of these fixtures are refused by one
    reference and read correctly by the other three, and a corpus that only
    recorded the readings would have quietly dropped them.

    The verdict is `accepted` or `refused`, from the exit status, plus the exit
    status itself - because unzip distinguishes a warning (1) from a refusal (9)
    and from an unsupported method (81), and collapsing those to a bit would
    lose the difference between "it cannot read this member" and "it cannot read
    this file".
    """
    import zipfile

    rows = []
    for name in fixtures(destination):
        for reference, argv in OPENINGS:
            # **Run from the corpus directory and name the fixture bare.** Every
            # one of these references puts the path it was given into its own
            # diagnostics, so an absolute path would put this checkout's location
            # in the committed file - and the fixture's hash would then depend on
            # where the repository happens to live.
            finished = subprocess.run(argv + [name], cwd=destination,
                capture_output=True)
            rows.append((name, reference,
                "accepted" if finished.returncode == 0 else "refused",
                str(finished.returncode),
                escape(diagnostics(finished, name).encode("utf-8"))))

        # Python is asked in process, because its refusal is an exception rather
        # than an exit status.
        try:
            with zipfile.ZipFile(os.path.join(destination, name)) as handle:
                handle.infolist()
            rows.append((name, "pyzipfile", "accepted", "0", ""))
        except Exception as problem:
            rows.append((name, "pyzipfile", "refused", "-",
                escape(("%s: %s" % (type(problem).__name__, problem))
                    .encode("utf-8"))))

    lines = [
        "# What each reference DOES when handed each archive, as opposed to what",
        "# it reads inside one. Generated by tools/oracle/make_zip_corpus.py",
        "# inside the pinned container; do not edit.",
        "#",
        "# unzip is asked `-t`, which is the accepted answer to whether a zip is",
        "# valid; bsdtar and 7-Zip are asked to list, which is the cheapest",
        "# question that requires reading the structure; Python is asked in",
        "# process, because its refusal is an exception and not an exit status.",
        "#",
        "# The exit status is kept beside the verdict because unzip's are not one",
        "# bit: 1 is a warning it read the archive anyway, 9 is a refusal, and 81",
        "# is a member whose method it does not implement.",
        "#",
        "# These are the REFERENCES' decisions, not this library's. A row this",
        "# library disagrees with is a finding either way round - and three of",
        "# these archives are already a disagreement between the references",
        "# themselves.",
        "#",
        "# " + "\t".join(OPENINGS_COLUMNS),
    ]
    lines += ["\t".join(row) for row in rows]
    with open(os.path.join(out or destination, "openings.tsv"), "w",
            encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


# The three emitters above take an `out` directory separately from the corpus
# they read, which `check_zip_manifest.py` uses to re-derive them from the
# *committed* bytes without writing over the committed readings. A checker that
# re-implemented the questions would be comparing two implementations of them
# rather than the references against the corpus.
READINGS = ("manifest.tsv", "names.tsv", "openings.tsv")

# **Three fixtures are not a function of their inputs, and no flag makes them
# one.** Each is listed here with the reason, and each is hashed as `-` rather
# than dropped: a fixture left out of the list would also be left out of the
# denominator, and `check-corpus-hashes` would stop noticing it had gone.
#
# What checks them instead is `manifest.tsv`, which *is* hashed: every field the
# references read out of these three - name, size, compressed size, CRC, method,
# flags, the extra field ids - is constant, because none of them is the byte that
# moves. So a real change in what these archives contain fails the gate through
# the manifest, and only the salt, the encryption header and the ctime are
# outside it.
NOT_REPRODUCIBLE = {
    "infozip-crypto.zip":
        "ZipCrypto's 12-byte encryption header is random per member by design, "
        "and Info-ZIP seeds its generator from the clock and the pid",
    "sevenzip-aes.zip":
        "WinZip AES uses a random salt per member by design, which is the "
        "whole point of a salt",
    "bsdtar-descriptors.zip":
        "libarchive stores st_ctime in the UT extra field, and ctime cannot be "
        "set: any change to a file's metadata sets it to now",
}


def hashes(destination):
    """sha256 of every fixture and every reading, so a moved one fails.

    A fixture in NOT_REPRODUCIBLE gets `-` instead of a digest: it is still in
    the list, so its absence is still a failure, and what covers its contents is
    the manifest.
    """
    rows = []
    for name in sorted(os.listdir(destination)):
        if not (name.endswith(".zip") or name in READINGS):
            continue
        if name in NOT_REPRODUCIBLE:
            rows.append("-  %s" % name)
            continue
        with open(os.path.join(destination, name), "rb") as handle:
            digest = hashlib.sha256(handle.read()).hexdigest()
        rows.append("%s  %s" % (digest, name))
    return rows


def inside_container():
    """Whether this process is the one running in the pinned image.

    The script re-invokes itself inside the container, and the two halves have to
    be told apart. An environment variable rather than a flag, so that a stray
    argument cannot make the host half do the container half's work against the
    host's own unpinned zip.
    """
    return os.environ.get("GHOTI_ARCHIVE_ZIP_CORPUS_INNER") == "1"


def main(argv):
    if inside_container():
        destination = argv[1]
        generate(destination)
        manifest(destination)
        names(destination)
        openings(destination)
        return 0

    sys.path.insert(0, HERE)
    import oracle_env

    check_only = "--check" in argv[1:]
    destination = CORPUS
    if check_only:
        destination = os.path.join(ROOT, "build", "zip-corpus-check")
        if os.path.exists(destination):
            shutil.rmtree(destination)
    os.makedirs(destination, exist_ok=True)

    # All five, named here so that an unreachable one fails before anything is
    # written rather than partway through.
    print(oracle_env.provenance(
        ["zip", "unzip", "sevenzip", "pyzipfile", "bsdtar"]), flush=True)

    inner = oracle_env.command("zip",
        ["python3", os.path.join(HERE, "make_zip_corpus.py"), destination],
        scratch=[destination])
    environment = dict(os.environ, GHOTI_ARCHIVE_ZIP_CORPUS_INNER="1")
    # The engine does not pass the host environment in, so the marker has to be
    # given to `docker run` as well as set here, and it goes after the `run`
    # subcommand: the engine rejects an option it has not reached a subcommand
    # for, with a message that reads like a bad flag name.
    if "run" in inner[:2]:
        cut = inner.index("run") + 1
        engine_argv = (inner[:cut]
            + ["--env", "GHOTI_ARCHIVE_ZIP_CORPUS_INNER=1"] + inner[cut:])
    else:
        engine_argv = inner
    finished = subprocess.run(engine_argv, env=environment)
    if finished.returncode != 0:
        return finished.returncode

    rows = hashes(destination)
    if not check_only:
        with open(HASHES, "w", encoding="utf-8") as handle:
            handle.write(
                "# sha256 of every generated zip fixture and every reading of\n"
                "# them, so that one which moved fails `make check-zip-corpus`\n"
                "# rather than quietly becoming the new expectation.\n"
                "# Regenerated by `make zip-corpus`.\n"
                "#\n"
                "# A digest of `-` is a fixture whose bytes are not a function\n"
                "# of its inputs - a random salt, a random encryption header, an\n"
                "# unsettable ctime. It stays in the list so that its absence is\n"
                "# still a failure, and manifest.tsv, which is hashed, is what\n"
                "# covers what is inside it. See NOT_REPRODUCIBLE in\n"
                "# tools/oracle/make_zip_corpus.py for which and why.\n")
            handle.write("\n".join(rows) + "\n")
        print("zip corpus: %d files in %s (%d not byte-reproducible, "
            "checked through manifest.tsv instead)"
            % (len(rows), destination, len(NOT_REPRODUCIBLE)))
        return 0

    with open(HASHES, "r", encoding="utf-8") as handle:
        want = [line.rstrip("\n") for line in handle
            if line.strip() and not line.startswith("#")]
    if want == rows:
        print("zip corpus: %d files match containers/CORPUS-ZIP; %d of them are "
            "not byte-reproducible and were compared through manifest.tsv"
            % (len(rows), len(NOT_REPRODUCIBLE)))
        return 0

    sys.stderr.write("### The regenerated zip corpus does not match CORPUS-ZIP ###\n")
    want_map = dict(row.split("  ", 1)[::-1] for row in want)
    got_map = dict(row.split("  ", 1)[::-1] for row in rows)
    for name in sorted(set(want_map) | set(got_map)):
        if want_map.get(name) != got_map.get(name):
            sys.stderr.write("  %s: CORPUS-ZIP %s, regenerated %s\n"
                % (name, want_map.get(name, "absent"),
                    got_map.get(name, "absent")))
    sys.stderr.write(
        "\nEither the generator changed - in which case `make zip-corpus` and\n"
        "commit both - or a reference moved, which is a finding to triage\n"
        "rather than a hash to update.\n")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
