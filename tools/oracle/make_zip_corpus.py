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
"""Generate the zip corpus in the pinned container, and five readings of it.

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
    """Run a writer, and fail loudly rather than leaving a short fixture.

    **Every reference in this file is run with stdin closed**, here and in each
    of the other invocations. An extractor that meets an encrypted member asks
    for a password on the terminal, and with stdin attached to whatever launched
    `make` the generator does not fail - it waits, silently, forever. That is how
    the first run of the verdict half of this corpus ended: three encrypted
    fixtures, and unzip blocked on the first of them with no output at all.
    """
    finished = subprocess.run(argv, cwd=cwd, capture_output=True, text=True,
        stdin=subprocess.DEVNULL)
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
    ("infozip-crypto-deflate.zip", ["-9", "-X", "-P", PASSWORD],
        ["compressible.txt", "hello.txt"],
        "ZipCrypto around *deflate*, which is a different shape from ZipCrypto "
        "around stored: the cipher is outermost and the decoder reads what it "
        "produces, so a reader that decrypts and decompresses in the wrong "
        "order reads the stored fixture correctly and this one not at all. "
        "Info-ZIP falls back to stored for hello.txt, so one archive holds "
        "both layerings"),
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


# The hostile names, each with the reason it is here. **Python's zipfile is the
# writer for all of these**, because it is the only one of the four that stores
# the name it is given: `zip` resolves a path against the filesystem before it
# stores it, and there is no `--transform` to lie to it with. That is a real
# difference from the tar corpus, where GNU tar wrote the hostile fixtures - here
# the writer is not one of the references that reads them back.
#
# The names point at /tmp rather than /etc for the same reason the tar corpus's
# do: these fixtures are extracted inside the container to record what the
# extractors do with them, and an absolute name that *succeeds* writes a file.
MALICIOUS_NAMES = [
    ("../../../tmp/ghoti-escaped",
        "the classic traversal: leading parent components, which every reference "
        "here acts on and no two of them act on the same way"),
    ("/tmp/ghoti-escaped",
        "absolute, which ignores the extraction root rather than climbing out of "
        "it - and which all three references *rewrite* rather than refuse"),
    ("a/../../b",
        "a traversal that starts inside, so a check that only looks at the first "
        "component misses it"),
    ("a/..",
        "a parent component that resolves *inside* the root. libarchive refuses "
        "it for containing '..' at all; Python's zipfile has no policy to apply "
        "and fails on the filesystem instead, which is a different thing and is "
        "why the column below records the exception's name"),
    ("./x",
        "a current-directory component, which is not an escape - so a checker "
        "that treats any non-ordinary component as one is wrong here"),
    ("a//b", "an empty component, which nothing objects to"),
    ("..\\..\\..\\tmp\\ghoti-esc-bs",
        "**the discriminating case, and it is zip's own.** libarchive "
        "translates backslash to slash for a zip member and then refuses this "
        "for containing '..'; unzip and Python store and create it as one "
        "ordinary filename with backslashes in it. Nothing in the tar corpus "
        "separates the references on this axis, and it is the whole reason "
        "GARC_NAME_BACKSLASH and GARC_NAME_WINDOWS_TRAVERSAL are two findings "
        "rather than one"),
    ("a\\..\\..\\b",
        "the same axis starting inside, so the depth arithmetic has to run over "
        "the backslash-separated components too"),
    ("C:\\Windows\\ghoti",
        "a drive letter, which libarchive strips and the other two keep - the "
        "same disagreement the tar corpus found, confirmed for zip"),
    ("\\\\server\\share\\ghoti",
        "a UNC path, which libarchive turns into `server/share/ghoti` and the "
        "other two create verbatim"),
    ("..",
        "the whole name is a parent component. unzip rewrites it to `__`, which "
        "no other reference does and which is why a rewrite target is recorded "
        "rather than a bit"),
    ("CON",
        "reserved on Windows, ordinary everywhere else. No reference here can "
        "answer it: all three run on POSIX"),
    ("aux.txt",
        "reserved on Windows *with* an extension, which is the form that gets "
        "missed"),
    ("COM1", "the numbered device family"),
    ("trailing.",
        "Windows strips a trailing dot, so this collides with `trailing`"),
    ("trailing ", "and a trailing space, likewise"),
    ("esc\x1b[31mred",
        "an ANSI escape in a name, which rewrites a terminal that prints a "
        "listing unescaped"),
    ("a/b/../../../c",
        "descends twice and climbs three times, so the arithmetic has to be a "
        "running depth rather than a count of components"),
]

# **A zip symlink has no link field: the target is the member's data.** So the
# question garc_name_check() exists to ask about a target cannot be asked in zip
# until the member has been read, which is a different order of operations from
# tar and is why these are a fixture rather than a note. Every reference here
# creates all three of these links without a word of complaint.
MALICIOUS_LINKS = [
    ("abs-target", "/tmp/ghoti-escaped", "an absolute link target"),
    ("up-target", "../../..", "a target that climbs out of any root"),
    ("dot-target", "./sibling", "a target that does not escape, as the control"),
]

# Eight bytes, so it replaces an eight-byte ASCII placeholder without moving a
# single offset in the archive. Not well-formed UTF-8 twice over: 0x80 is a
# continuation byte with nothing in front of it, and 0xC0 begins an overlong
# encoding.
MALICIOUS_RAW_NAME = b"bad\x80utf\xc0"


def generate_malicious(destination):
    """The hostile-name fixtures, all of them from Python's zipfile."""
    import warnings
    import zipfile

    path = os.path.join(destination, "mal-paths.zip")
    with zipfile.ZipFile(path, "w") as handle:
        for name, _why in MALICIOUS_NAMES:
            # Asserted rather than trusted: a name that arrived re-encoded would
            # make the fixture test something other than what the table says, and
            # that is exactly the mistake the tar corpus made once - two names
            # meant to hold raw bytes were valid UTF-8 by the time tar saw them.
            assert name.encode("utf-8").decode("utf-8") == name, name
            handle.writestr(python_info(name), b"hostile\n")

    # Symlinks, whose targets are the hostile part. `0o120777` is S_IFLNK with
    # its usual mode; the target is the data, which is what makes a zip symlink a
    # symlink.
    path = os.path.join(destination, "mal-links.zip")
    with zipfile.ZipFile(path, "w") as handle:
        handle.writestr(python_info("sibling"), b"target\n")
        for name, target, _why in MALICIOUS_LINKS:
            handle.writestr(python_info(name, mode=0o120777),
                target.encode("utf-8"))

    # Collisions: two names differing only in case, and two differing only in
    # Unicode normalisation. **Neither is detectable from one name**, which is
    # the point - they are here so that phase F has them and so that this
    # library's tests can say out loud that the check does not claim to find
    # them. Case folding and normalisation need tables this library deliberately
    # does not carry; they are `unicode`'s.
    path = os.path.join(destination, "mal-collisions.zip")
    with zipfile.ZipFile(path, "w") as handle:
        for name in ("A.txt", "a.txt",
                b"caf\xc3\xa9".decode("utf-8"),
                b"cafe\xcc\x81".decode("utf-8")):
            handle.writestr(python_info(name), b"collide\n")

    # A name whose bytes are not well-formed UTF-8, in **two archives that differ
    # only in general purpose flag bit 11** - the flag that is the whole of what a
    # zip ever says about a name's encoding. With it clear the name is cp437 by
    # specification and every reference reads the archive; with it set the archive
    # *claims* UTF-8 about bytes that are not, and Python and libarchive both
    # refuse it while unzip and 7-Zip read it. tar has no flag to lie with, so
    # this axis is zip's alone, and it is two fixtures rather than two members of
    # one because an archive Python cannot open contributes no rows to any
    # per-member reading.
    #
    # Written as an ASCII placeholder and substituted afterwards, because
    # `zipfile` encodes a name before storing it and there is no spelling of a
    # lone 0x80 it will pass through. The placeholder appears exactly twice - once
    # in the local header and once in the central directory - and that count is
    # asserted, because a replacement that hit one record and not the other would
    # produce an archive whose two copies of the name disagree, which is a
    # different fixture testing a different thing.
    placeholder = b"AAAAAAAA"
    assert len(placeholder) == len(MALICIOUS_RAW_NAME)
    for name, lie in (("mal-encodings.zip", False), ("mal-utf8-lie.zip", True)):
        path = os.path.join(destination, name)
        with zipfile.ZipFile(path, "w") as handle:
            handle.writestr(python_info(placeholder.decode("ascii")),
                b"not utf-8\n")
            # A control in the same archive, so that a reference which refuses the
            # hostile name can still be seen to have read the rest of it.
            handle.writestr(python_info("ordinary.txt"), b"control\n")
        with open(path, "rb") as reader:
            raw = reader.read()
        if lie:
            # The flag word sits at a fixed offset from each signature, so it is
            # found from the signature and the placeholder rather than from an
            # extra field's length.
            raw = zip_set_utf8_flag(raw, placeholder)
        if raw.count(placeholder) != 2:
            raise SystemExit("%s: %r appears %d times, not twice"
                % (name, placeholder, raw.count(placeholder)))
        with open(path, "wb") as writer:
            writer.write(raw.replace(placeholder, MALICIOUS_RAW_NAME))
    del warnings


def zip_set_utf8_flag(raw, name):
    """Set general purpose flag bit 11 on the member called @p name.

    Both of its records: the local header, where the flag word is at +6, and the
    central directory entry, where it is at +8. Located from each signature and
    the name that follows it, so nothing here depends on an extra field's length.

    @param raw The whole archive.
    @param name The member's name, as bytes.
    @return The archive with that member's two flag words changed.
    """
    out = bytearray(raw)
    found = 0
    for signature, flag_at, name_at in (
            (b"PK\x03\x04", 6, 30), (b"PK\x01\x02", 8, 46)):
        start = 0
        while True:
            at = out.find(signature, start)
            if at < 0:
                break
            start = at + 4
            if bytes(out[at + name_at:at + name_at + len(name)]) != name:
                continue
            flags = struct.unpack_from("<H", out, at + flag_at)[0]
            struct.pack_into("<H", out, at + flag_at, flags | 0x800)
            found += 1
    if found != 2:
        raise SystemExit(
            "mal-encodings.zip: set the UTF-8 flag on %d records, not 2" % found)
    return bytes(out)


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
    generate_malicious(destination)

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


def name_bytes(info):
    """The member's name as the *archive's bytes*, undoing Python's decode.

    **A zip name with bit 11 clear is cp437 by specification**, and Python
    implements that: `ZipInfo.orig_filename` for such a member is a `str` decoded
    from cp437, so re-encoding it as UTF-8 would put a name in the manifest that
    is in no record of the archive. cp437 is a total, invertible single-byte
    mapping, so encoding back through the codec Python decoded with recovers the
    bytes exactly - which is what a reader reports and therefore what a row this
    library can be compared against has to hold.

    For every name in this corpus that is ASCII the two codecs agree, so this
    changes nothing except for the fixture that is *about* a name which is not
    well-formed UTF-8. Said out loud here because the alternative - a name column
    holding the UTF-8 of a cp437 reading - looks right in every row until one.

    @param info A `ZipInfo`.
    @return The name as it appears in the archive.
    """
    codec = "utf-8" if info.flag_bits & 0x800 else "cp437"
    return info.orig_filename.encode(codec, "surrogateescape")


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
                    escape(name_bytes(info)),
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
            capture_output=True, stdin=subprocess.DEVNULL)
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
            # A space in a name is safe: the split above has a maxsplit, so the
            # ninth field is everything after the seven fixed ones however many
            # spaces it holds. What is *not* safe is a second ` -> ` - the
            # partition above took the first one, and a name containing one would
            # have had its tail read as a link target. The malicious corpus has a
            # name ending in a space on purpose, which is how the older, stricter
            # form of this check was found to be refusing a legitimate name.
            if b" -> " in remainder:
                raise SystemExit(
                    "%s: a member name containing ' -> ' breaks this parse: %r"
                    % (name, remainder))
            kind = {0x64: "directory", 0x6C: "symlink", 0x2D: "file"}.get(
                mode[0], "other")
            # **Through unrender_bsdtar(), so this column holds the archive's
            # bytes.** libarchive prints a byte outside printable ASCII as `\NNN`
            # octal, so without this the row for a name that is not well-formed
            # UTF-8 would hold libarchive's rendering of it - four characters
            # where the archive has one byte - and a reader comparing its own
            # name against this row would disagree with itself.
            rows.append((name, str(index), kind, escape(mode),
                escape(unrender_bsdtar(remainder)),
                escape(unrender_bsdtar(target))))
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
                capture_output=True, stdin=subprocess.DEVNULL)
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


VERDICT_COLUMNS = ("archive", "index", "name", "python", "unzip", "libarchive")

# The verbs unzip prints one of per member, in archive order. `skipping` is in the
# list because a member whose method unzip does not implement still gets a line -
# which keeps the sequence aligned with the members, and a parse that only knew
# the success verbs would silently attribute every later line to the wrong member.
UNZIP_VERBS = {
    b"extracting": "same",
    b"inflating": "same",
    b"linking": "same",
    b"creating": "same",
    b"skipping": "refused",
}


def unrender_bsdtar(field):
    """Undo libarchive's rendering of a non-printable byte in a listing.

    libarchive prints a byte outside printable ASCII as `\\NNN` octal, so the name
    it reports for a member with an ESC in it is not the member's bytes - and a
    comparison against the archive's name would score an unchanged name as a
    rewrite. This is the one place that rendering is undone, and an unknown escape
    is an error rather than a guess: a wrong decode here would be invisible.

    @param field The name as libarchive printed it, as bytes.
    @return The bytes it stands for.
    """
    out = bytearray()
    index = 0
    while index < len(field):
        byte = field[index]
        if byte != 0x5C:
            out.append(byte)
            index += 1
            continue
        if field[index + 1:index + 2] == b"\\":
            out.append(0x5C)
            index += 2
            continue
        digits = field[index + 1:index + 4]
        if len(digits) != 3 or any(d < 0x30 or d > 0x37 for d in digits):
            raise SystemExit("libarchive rendered something this does not "
                "understand: %r" % field)
        out.append(int(digits, 8))
        index += 4
    return bytes(out)


def extractor_verdicts(destination, name, members):
    """Ask unzip and libarchive what they DO with each member of one archive.

    Returns `(unzip, libarchive, comments)`, the first two being lists as long as
    @p members holding one of `same`, `rewrite=<name>` or `refused=<reason>` - or
    `-` where the reference could not open the archive at all, which is a fact
    `openings.tsv` already records and which must not be confused with a verdict.

    **Both references are parsed from an ordered per-member line**, not by
    matching a diagnostic against a name. `bsdtar -xv` prints exactly one
    `x <name>[: <reason>]` line per member, and unzip prints one verb line per
    member on stdout. Matching by name cannot work here: libarchive reports the
    name it *decided*, so the member whose backslashes it translated is not
    findable under the name the archive holds - which is the very member the
    fixture exists for. The line counts are asserted against the member count, so
    a reference that changes its output shape fails loudly rather than shifting
    every verdict by one.
    """
    comments = []

    def room_for(reference):
        where = os.path.join("/tmp", "ghoti-zip-extract", name, reference)
        if os.path.exists(where):
            shutil.rmtree(where)
        os.makedirs(where)
        return where

    # libarchive. One line per member on stderr, plus archive-level notes.
    room = room_for("bsdtar")
    finished = subprocess.run(["bsdtar", "-xvf",
        os.path.join(destination, name)], cwd=room, capture_output=True,
        stdin=subprocess.DEVNULL)
    libarchive = []
    notes = []
    for raw in finished.stderr.split(b"\n"):
        if not raw:
            continue
        if raw.startswith(b"bsdtar: "):
            text = raw[len(b"bsdtar: "):]
            if not text.startswith(b"Error exit delayed"):
                notes.append(escape(text))
            continue
        if not raw.startswith(b"x "):
            raise SystemExit("%s: bsdtar printed a line this parse does not "
                "understand: %r" % (name, raw))
        field, separator, reason = raw[2:].partition(b": ")
        if separator:
            libarchive.append("refused=%s" % escape(reason))
        elif unrender_bsdtar(field) == members[len(libarchive)]:
            libarchive.append("same")
        else:
            libarchive.append("rewrite=%s" % escape(unrender_bsdtar(field)))
    if notes:
        comments.append("# %s: libarchive also said: %s"
            % (name, "; ".join(notes)))
    # **What it created, and not only what it said.** libarchive reports the
    # composed form of a decomposed name, so the two halves of the collision pair
    # land on one path and the second overwrites the first: four members, three
    # files, exit 0, and not a word about it. That is only visible in the tree.
    created = []
    for here, directories, files in os.walk(room):
        relative = os.path.relpath(here, room)
        for entry in sorted(files) + sorted(directories):
            joined = entry if relative == "." else os.path.join(relative, entry)
            created.append(escape(os.fsencode(joined)))
    if created:
        comments.append("# %s: libarchive created: %s"
            % (name, " ".join(sorted(created))))
    if not libarchive:
        libarchive = ["-"] * len(members)
    elif len(libarchive) != len(members):
        raise SystemExit("%s: bsdtar printed %d member lines for %d members"
            % (name, len(libarchive), len(members)))
    shutil.rmtree(room, ignore_errors=True)

    # unzip. One verb line per member on stdout, and a member it gives up on
    # entirely names itself on stderr instead - so those are removed from the
    # sequence before the rest is aligned.
    room = room_for("unzip")
    finished = subprocess.run(["unzip", "-o",
        os.path.join(destination, name)], cwd=room, capture_output=True,
        stdin=subprocess.DEVNULL)
    gave_up = {}
    for raw in finished.stderr.split(b"\n"):
        marker = b"unable to process "
        at = raw.find(marker)
        if at < 0:
            continue
        who = raw[at + len(marker):].rstrip().rstrip(b".")
        gave_up[who] = escape(raw.strip())
    lines = []
    for raw in finished.stdout.split(b"\n"):
        stripped = raw.strip()
        verb, separator, rest = stripped.partition(b": ")
        if not separator or verb not in UNZIP_VERBS:
            continue
        # A `linking:` line carries ` -> <target>` after the name, and every verb
        # pads the name out to a column. Both are display, so both come off here.
        shown = rest.partition(b" -> ")[0].strip()
        lines.append((verb, shown))
    # **What unzip created, from the filesystem rather than from its output.**
    # Its display drops a control byte and its column padding eats a trailing
    # space, so two names in the malicious fixture came back as rewrites of
    # themselves when the verdict was read off the line. The tree is what it
    # actually did; the line is only consulted for a rewrite's target.
    tree = set()
    for here, directories, files in os.walk(room):
        relative = os.path.relpath(here, room)
        for entry in sorted(files) + sorted(directories):
            joined = entry if relative == "." else os.path.join(relative, entry)
            tree.add(os.fsencode(joined))
    unzip = []
    for member in members:
        if member in gave_up:
            unzip.append("refused=%s" % gave_up[member])
            continue
        if not lines:
            unzip = []
            break
        verb, shown = lines.pop(0)
        if UNZIP_VERBS[verb] == "refused":
            unzip.append("refused=%s" % escape(verb))
        elif member.rstrip(b"/") in tree:
            unzip.append("same")
        else:
            unzip.append("rewrite=%s" % escape(shown))
    if lines:
        raise SystemExit("%s: unzip printed %d member lines more than there are "
            "members" % (name, len(lines)))
    if not unzip:
        unzip = ["-"] * len(members)
    if tree:
        comments.append("# %s: unzip created: %s"
            % (name, " ".join(escape(entry) for entry in sorted(tree))))
    shutil.rmtree(room, ignore_errors=True)

    return unzip, libarchive, comments


def verdict_rows(destination):
    """Ask all three references what they would do, and return (comments, rows).

    Separate from verdicts() so that `check-zip-oracle` can ask the same question
    of the committed bytes without a second copy of how it is asked.
    """
    import zipfile

    comments = []
    rows = []
    for name in fixtures(destination):
        path = os.path.join(destination, name)
        try:
            handle = zipfile.ZipFile(path)
        except Exception:
            # An archive Python refuses has no rows here and a row in
            # openings.tsv, which is the file that records a refusal to open.
            continue
        with handle:
            infos = handle.infolist()
            members = [name_bytes(info) for info in infos]
            unzip, libarchive, notes = extractor_verdicts(
                destination, name, members)
            comments += notes

            # Python, in process and member by member, into one room - so that a
            # member whose sanitised name collides with something an earlier
            # member created fails the way it does in a real extraction.
            room = os.path.join("/tmp", "ghoti-zip-extract", name, "python")
            if os.path.exists(room):
                shutil.rmtree(room)
            os.makedirs(room)
            for index, info in enumerate(infos):
                try:
                    out = handle.extract(info, room)
                    relative = os.path.relpath(out, room)
                    python = ("same"
                        if relative.encode("utf-8", "surrogateescape")
                            == members[index].rstrip(b"/")
                        else "rewrite=%s" % escape(
                            relative.encode("utf-8", "surrogateescape")))
                except Exception as problem:
                    # The exception's *name*, because Python's zipfile has no name
                    # policy to report: it drops parent components and leading
                    # separators on the way to a path and then lets the
                    # filesystem answer. An IsADirectoryError here is not a
                    # refusal, and a column that called it one would be claiming
                    # a policy that does not exist.
                    python = type(problem).__name__
                rows.append((name, str(index), escape(members[index]),
                    python, unzip[index], libarchive[index]))
            shutil.rmtree(room, ignore_errors=True)

    return comments, rows


def verdicts(destination, out=None):
    """What each reference would *do* with every member's name.

    **The only part of the zip corpus that records a decision rather than a
    reading**, and what turns garc_name_check() from a set of assertions about
    itself into a cross-check. A classifier whose expectations were written by the
    same session that wrote the classifier measures nothing.

    Three columns, and the important thing about them is that **zip has no
    reference that states a policy.** PEP 706 gave `tarfile` a `data_filter`
    whose verdict is a documented decision; `zipfile` has no equivalent and never
    did. So all three columns here are *actions*: what the reference created, or
    the name of the exception it died of. The difference matters at the point of
    use - Python raising `IsADirectoryError` on `a/..` is the filesystem
    answering, not a policy refusing, and a column that flattened it to "unsafe"
    would credit Python with a check it does not perform.

    What each value means:

      - `same` - the member's own name was created.
      - `rewrite=<name>` - something else was created, and this is what. The
        target is recorded rather than a bit because the targets are the finding:
        unzip turns `..` into `__`, libarchive turns `C:\\Windows\\ghoti` into
        `Windows/ghoti`, and neither is derivable from the other.
      - `refused=<reason>` - the member was not created and the reference said
        why. The reason is kept because not every refusal is about the name: a
        member whose *method* a reference lacks is refused too, and a relation
        about names has to be able to tell them apart.
      - `-` - the reference could not open the archive at all. Not a verdict;
        `openings.tsv` is where that is recorded.
    """
    comments, rows = verdict_rows(destination)
    lines = [
        "# What each reference DOES with each member's name, as opposed to what",
        "# it reads there. Generated by tools/oracle/make_zip_corpus.py inside",
        "# the pinned container; do not edit.",
        "#",
        "# **zip has no reference that states a name policy.** PEP 706 gave",
        "# tarfile a data_filter whose verdict is a decision; zipfile has no",
        "# equivalent. So every column here is an ACTION: same, rewrite=<name>,",
        "# refused=<reason>, or - where the reference could not open the archive.",
        "# A Python exception name is the filesystem answering, not a policy.",
        "#",
        "# The rewrite target is recorded rather than a bit, because the targets",
        "# are the finding: unzip turns `..` into `__`, libarchive translates a",
        "# zip member's backslashes to slashes and then refuses the result for",
        "# containing '..', and neither is derivable from the other.",
        "#",
        "# These are the REFERENCES' decisions, not this library's. A row this",
        "# library disagrees with is a finding either way round.",
        "#",
        "# " + "\t".join(VERDICT_COLUMNS),
    ]
    lines += comments
    lines += ["\t".join(row) for row in rows]
    with open(os.path.join(out or destination, "verdicts.tsv"), "w",
            encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


DECRYPTED_COLUMNS = ("archive", "index", "name", "method", "scheme", "size",
    "python", "unzip", "sevenzip", "plaintext")


def decrypted(destination, out=None):
    """The plaintext of every encrypted member, from three references.

    **This is what makes a ZipCrypto reader measurable instead of
    self-consistent.** A decryption that agrees with itself proves nothing; a
    decryption that produces the same bytes three other programs produce from the
    same archive and the same password is a cross-check. The plaintext is recorded
    as a sha256 and a length rather than as bytes, because one of these members is
    a kilobyte of repeated text and because a digest fails just as loudly.

    The scheme column is mechanical, not a judgement: bit 0 of the general purpose
    flags says a member is encrypted, and method 99 says WinZip AES rather than
    the traditional cipher. It is here because it selects the rows.

    **The AES rows are expected refusals, and that is the point of having them.**
    Python's zipfile and unzip 6.00 both decline method 99; 7-Zip decrypts it. So
    the row for `sevenzip-aes.zip` is a committed expectation for phase H -
    written down now, while the archive is being refused, so that the phase that
    implements it has something to be measured against that this library did not
    write.

    The cipher is deliberately **not** implemented here. An oracle that computed
    the answer the same way the library does would be comparing one
    implementation with itself; every column is a program decrypting the archive.
    """
    import zipfile

    rows = []
    for name in fixtures(destination):
        path = os.path.join(destination, name)
        try:
            handle = zipfile.ZipFile(path)
        except Exception:
            continue
        with handle:
            for index, info in enumerate(handle.infolist()):
                if not (info.flag_bits & 0x0001):
                    continue
                member = name_bytes(info)
                scheme = "aes" if info.compress_type == 99 else "zipcrypto"

                plain = b""
                try:
                    plain = handle.read(info, pwd=PASSWORD.encode("utf-8"))
                    python = digest_of(plain)
                except Exception as problem:
                    python = "refused=%s" % type(problem).__name__

                # unzip and 7-Zip are asked for one member on stdout. Every
                # encrypted member in this corpus has an ordinary name, which is
                # asserted rather than assumed: both of these take the argument as
                # a *pattern*, so a name with a bracket in it would select
                # something else or nothing.
                if any(byte in member for byte in (b"*", b"?", b"[", b"]")):
                    raise SystemExit("%s: %r cannot be named to unzip or 7-Zip "
                        "as a literal" % (name, member))
                text = member.decode("utf-8", "surrogateescape")

                finished = subprocess.run(
                    ["unzip", "-p", "-P", PASSWORD, path, text],
                    capture_output=True, stdin=subprocess.DEVNULL)
                unzip = (digest_of(finished.stdout) if finished.returncode == 0
                    else "refused=%d" % finished.returncode)

                finished = subprocess.run(
                    ["7z", "x", "-so", "-bso0", "-bsp0", "-p" + PASSWORD,
                        path, text],
                    capture_output=True, stdin=subprocess.DEVNULL)
                sevenzip = (digest_of(finished.stdout)
                    if finished.returncode == 0
                    else "refused=%d" % finished.returncode)

                # **The bytes, and only where all three agree.** A digest says
                # three programs produced the same thing; it does not say what,
                # and a test comparing against one cannot say *where* a
                # disagreement is. So the plaintext goes in as well, from Python,
                # and the guard is that the other two produced the same digest -
                # a column filled in from one reference while the others differed
                # would be that reference's answer wearing three programs' names.
                agreed = python == unzip == sevenzip and python.startswith(
                    "sha256:")
                rows.append((name, str(index), escape(member),
                    str(info.compress_type), scheme, str(info.file_size),
                    python, unzip, sevenzip,
                    escape(plain) if agreed else "-"))

    lines = [
        "# The plaintext of every encrypted member, as three references decrypt",
        "# it with the corpus password. Generated by",
        "# tools/oracle/make_zip_corpus.py inside the pinned container; do not",
        "# edit.",
        "#",
        "# A value is `sha256:<digest>/<bytes>` or `refused=<exception or exit",
        "# status>`. The password is the one in PASSWORD in the generator.",
        "#",
        "# The last column is the plaintext itself, and it is filled in only",
        "# where all three references produced the same digest - so a test can",
        "# compare bytes rather than a digest and still be comparing against",
        "# three programs rather than one.",
        "#",
        "# The AES rows are refusals from two of the three references, and they",
        "# are here on purpose: they are a committed expectation for phase H,",
        "# written while this library still refuses method 99, so that the phase",
        "# which implements it is measured against something it did not write.",
        "#",
        "# The cipher is not implemented in this file. Every column is a program",
        "# decrypting the archive, which is the only thing that makes this a",
        "# cross-check rather than a second copy of the answer.",
        "#",
        "# " + "\t".join(DECRYPTED_COLUMNS),
    ]
    lines += ["\t".join(row) for row in rows]
    with open(os.path.join(out or destination, "decrypted.tsv"), "w",
            encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")


def digest_of(data):
    """`sha256:<hex>/<length>`, which fails as loudly as the bytes would."""
    return "sha256:%s/%d" % (hashlib.sha256(data).hexdigest(), len(data))


# Every emitter above takes an `out` directory separately from the corpus
# they read, which `check_zip_manifest.py` uses to re-derive them from the
# *committed* bytes without writing over the committed readings. A checker that
# re-implemented the questions would be comparing two implementations of them
# rather than the references against the corpus.
READINGS = ("manifest.tsv", "names.tsv", "openings.tsv", "verdicts.tsv",
    "decrypted.tsv")

# **Four fixtures are not a function of their inputs, and no flag makes them
# one.** Each is listed here with the reason, and each is hashed as `-` rather
# than dropped: a fixture left out of the list would also be left out of the
# denominator, and `check-corpus-hashes` would stop noticing it had gone.
#
# What checks them instead is `manifest.tsv`, which *is* hashed: every field the
# references read out of these four - name, size, compressed size, CRC, method,
# flags, the extra field ids - is constant, because none of them is the byte that
# moves. `decrypted.tsv` covers the two encrypted ones twice over, because a
# plaintext digest is a function of the member and not of the random header. So a real change in what these archives contain fails the gate through
# the manifest, and only the salt, the encryption header and the ctime are
# outside it.
NOT_REPRODUCIBLE = {
    "infozip-crypto.zip":
        "ZipCrypto's 12-byte encryption header is random per member by design, "
        "and Info-ZIP seeds its generator from the clock and the pid",
    "infozip-crypto-deflate.zip":
        "the same random encryption header, per member, for the same reason as "
        "infozip-crypto.zip",
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
        verdicts(destination)
        decrypted(destination)
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
