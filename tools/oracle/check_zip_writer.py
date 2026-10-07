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
"""Fail if the references disagree with the zip this library writes.

    make check-zip-writer

**The gate whose subject is this library rather than a reference.**
`check-zip-corpus` regenerates the committed fixtures and catches a reference
whose *writing* moved; `check-zip-oracle` re-reads them and catches one whose
*reading* moved. This hands four references bytes the writer produced a moment
ago and asks whether they understand them - which no amount of asserting against
our own buffer can answer, because a shared misunderstanding of a format passes
every one of those assertions. `tests/unit/test_zip_write.cpp` asserts that the
writer agrees with this library's own idea of zip, and that is exactly the
agreement a misunderstanding preserves.

**Everything is compared against the intent, never against another reading.**
`zip_writer_probe write` prints what it meant to put in each archive before any
reference has seen it, including the CRC-32 of each member's intended data - so a
reference's reported CRC is compared against what the bytes *should* checksum to
rather than against what this library computed. Whether that value describes the
bytes is a separate question, and Python's `testzip()` answers it by recomputing
every one of them.

**Each reference is asked the question it can answer faithfully, and which that
is was measured rather than assumed.** Four findings came out of the first run,
and all four shape what is compared:

- **`unzip -Z1` prints a zip member's name as bytes**, including a byte above
  0x7F and a literal backslash. It is therefore the byte-faithful name reference
  here, which is the role `tar --quoting-style=literal` plays for tar - and unlike
  GNU tar it needs no option to do it.
- **libarchive translates a zip member's backslashes to slashes**, so it reports
  `back/slash.txt` for a member named `back\\slash.txt`, and it renders a byte
  outside printable ASCII as `\\NNN` octal. So bsdtar is asked for the *type*, the
  *mode* and the *link target* - decisions Python's `zipfile` does not make - and
  its name is compared only where the intended name has no backslash and no
  high byte. That is a predicate on the input, not a model of libarchive's
  quoting; a wrong model would compare the wrong string and pass.
- **`unzip` 6.00 cannot read method 99, and it is not asked about method 93
  or 14 either.** `aes.zip` is WinZip AES. unzip, bsdtar, Python's `zipfile`
  and both re-writers are not asked about it. 7-Zip is, with the corpus
  password, which is the reference that can check the authentication code.
  `zstd.zip` and `lzma.zip` copy that exception for unzip and bsdtar. 7-Zip is
  asked about both. Python is not asked about zstd. Python is asked about LZMA
  only when it can read those bytes. `bzip2.zip` (method 12) is asked of every
  reference: unzip, bsdtar and Python all read it.
- **`bsdtar --format zip` deflates what it re-writes**, so every member of its
  round trip comes back as method 8 whatever it went in as. The size and the CRC
  are still compared, which makes it the strongest statement in this gate:
  libarchive deflated our bytes and this library inflated them back to the same
  bytes with the same checksum. The method column started as a blanket skip and is
  now a predicate - since the writer learned to deflate, libarchive *agrees* about
  every member we deflated, and the skip applies only to the ones we stored.
- **Python decodes a name with general purpose flag bit 11 clear as cp437**, so
  its name column is re-encoded through the codec the flag selects. Every ASCII
  name is unaffected, which is why this only had to be got right once there was a
  member that was not.
- **A name that is not well-formed UTF-8 must not be flagged UTF-8**, and the
  first run of this gate found that the writer was doing it: Python refused the
  whole archive with a `UnicodeDecodeError` and libarchive skipped the member.
  The flag is a claim about the bytes and the writer now makes it only when it is
  true. That defect was invisible to every test that did not leave the process.

Three stages, and the container boundary is crossed once:

  1. host       zip_writer_probe write   the archives, and the intent rows
  2. container  --inner                  the references read them, and two
                                         re-write what they read
  3. host       zip_writer_probe read    our reading of all three directories

Stage 2 is the only part that needs the pinned image. The probe is linked against
the library under test, so it runs here.
"""

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, HERE)

# The row shape, shared with zip_writer_probe.c.
COLUMNS = ["archive", "index", "name", "type", "size", "mtime", "mode",
    "linkname", "method", "crc"]

# The population this gate measures, asserted rather than counted and reported.
#
# **Measured need, inherited from check-writer.** Making the probe write one member
# fewer was not caught by anything else there and could not have been: the intent
# rows shrink with the corpus, so every comparison still agrees and the gate stays
# green while testing less. These two numbers are the one thing here that has to be
# edited when a fixture is added, which is where somebody says out loud that the
# corpus grew - an accidental shrink has no such edit anywhere.
EXPECTED_ARCHIVES = 10
EXPECTED_MEMBERS = 120

# unzip, bsdtar and Python's zipfile cannot read method 99. 7-Zip can, and it
# is the one reference asked about this archive. The password is the corpus one.
AES_ARCHIVE = "aes.zip"
AES_PASSWORD = "ghoti-password"

# Method 93 and method 14. unzip is not asked. 7-Zip is asked about both.
# Python is not asked about zstd. Python is asked about LZMA only when the
# bytes are ones it accepts, which the inner stage discovers rather than assumes.
ZSTD_ARCHIVE = "zstd.zip"
LZMA_ARCHIVE = "lzma.zip"
NOT_UNZIP = (AES_ARCHIVE, ZSTD_ARCHIVE, LZMA_ARCHIVE)

# What each reference is allowed to say while doing its job, matched whole.
#
# Empty for all four, and that is the measurement: none of them has anything to
# say about what this writer produces. A line appearing here later is the cheapest
# possible notice that a reference only half understands the output, which is why
# this is a table of allowed lines rather than a filter.
ALLOWED_WARNINGS = {
    "unzip": (),
    "bsdtar": (),
    "sevenzip": (),
}

# Columns a round trip through a given re-writer is not asked about, with the
# reason each is there. **A row in this table is a finding about that reference**,
# not a convenience: the alternative of widening the comparison until it passes is
# what having the table makes visible instead.
ROUNDTRIP_SKIP = {
    # **`bsdtar --format zip` deflates.** Every member it re-writes comes back as
    # method 8 where it went in as method 0, which is libarchive choosing a codec
    # and not a loss - and the fact that the *size* and *CRC* columns still agree is
    # the strong half of this round trip: libarchive deflated our bytes and this
    # library inflated them back to the same bytes with the same checksum.
    #
    # **Neither column is skipped wholesale here, and the method stopped being so
    # when the writer learned to deflate.** libarchive deflates, so it *agrees*
    # about a member we deflated and differs about one we stored - which is a
    # sharper statement than "skip the method", and it is `deflated_only()` that
    # makes it. libarchive also translates a backslash and renders a high byte, so
    # the name is compared for every member `bsdtar_verbatim()` accepts and counted
    # for the rest. A member at a time rather than a column at a time, in both
    # cases.
    "bsdtar": (),
    # **Python re-encodes a name it decoded from cp437.** A member whose name is not
    # well-formed UTF-8 has general purpose flag bit 11 clear, so `zipfile` reads it
    # as cp437 and writes it back as UTF-8 with the flag set: `bad\x80utf.txt`
    # becomes `bad\xC3\x87utf.txt`, which is a different member name. That is the
    # same finding the malicious-name corpus recorded about its *extractor*,
    # confirmed here on the writing side, and it is why the name column has a
    # predicate rather than a blanket skip.
    "python": (),
}


def excluding(rows, names):
    """Rows whose archive is not one of @p names.

    `aes.zip`, `zstd.zip` and `lzma.zip` are the archives unzip and bsdtar are
    not asked about. Python drops `aes.zip` and `zstd.zip` always, and
    `lzma.zip` when it could not read it.
    """
    skip = set(names)
    return [row for row in rows if row[0] not in skip]


def rows_from(text):
    """Tab-separated rows as tuples, comments and blank lines dropped."""
    rows = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        parts = line.split("\t")
        while len(parts) < len(COLUMNS):
            parts.append("")
        rows.append(tuple(parts[:len(COLUMNS)]))
    return rows


def by_archive(rows):
    """Rows grouped by their archive column, order preserved."""
    grouped = {}
    for row in rows:
        grouped.setdefault(row[0], []).append(row)
    return grouped


def column(row, name):
    return row[COLUMNS.index(name)]


def describe_row(row):
    return "%s[%s] %s" % (row[0], row[1], column(row, "name"))


def bsdtar_verbatim(escaped):
    """Whether libarchive will report this name unchanged.

    Asked of the *escaped* intent field, which makes it exact: this module's
    escaping renders a literal backslash as two and every byte outside printable
    ASCII as `\\xHH`, and those are the two things libarchive changes about a zip
    member's name - it treats a backslash as a separator and renders a high byte as
    octal. A name with neither is printable ASCII, which it prints as it is.

    A predicate on the input rather than a model of libarchive's output, for the
    reason check_writer.py's `quoting_safe()` gives: a wrong model compares the
    wrong string and passes, where a wrong predicate can only move a name between
    "compared" and "counted", and both counts are printed.
    """
    return "\\" not in escaped


def python_verbatim(escaped):
    """Whether Python's zipfile will re-write this name unchanged.

    A *narrower* condition than libarchive's, and the difference is the point:
    `zipfile` is happy with a backslash - it is an ordinary character in a name -
    and changes only a name it had to decode from cp437, which is any name with a
    byte outside printable ASCII in it. So `back\\slash.txt` is compared here and
    skipped for bsdtar, and `bad\x80utf.txt` is skipped for both.

    Two predicates rather than one union, because a single one would stop comparing
    `back\\slash.txt` against the reference that gets it right.
    """
    return "\\x" not in escaped


def deflated_only(row):
    """Whether this member's intent says deflate.

    The predicate libarchive's round trip needs: `bsdtar --format zip` deflates
    whatever it re-writes, so it agrees about a member we deflated and differs about
    one we stored. Asked of the *intent* row, which is what keeps it a statement
    about the input rather than a model of libarchive's choice.
    """
    return column(row, "method") == "8"


def compare(failures, what, want_rows, got_rows, not_asked=(), finding_skip=(),
        predicates=None):
    """Compare two row lists field by field, index-aligned.

    Aligned by position rather than matched by name on purpose: a member that moved
    is a defect, and matching by name would silently reorder it away.

    **Two kinds of exclusion, counted separately, because they mean different
    things.** @p not_asked is a column this reference has no answer for - Python's
    zipfile has no link target, libarchive prints no CRC - and it is a property of
    the *question*, stated at the call site, so counting it would inflate a figure
    nobody can act on. @p finding_skip and @p predicates are exclusions about a
    *reference's behaviour*, and those are the ones worth watching: the number is
    printed, and a field quietly joining that set is visible.

    @param not_asked Columns this reference cannot answer. Not counted.
    @param finding_skip Columns a reference is known to change for every member.
      Counted.
    @param predicates A column name to a callable taking the *intent* row; when it
      returns false that column is skipped for that member alone, and counted. A
      per-member predicate rather than a whole column wherever a reference changes
      a field for some members and not others - which is stronger, because the
      members it does not change are then compared.
    @return How many fields were compared and how many were skipped as findings.
    """
    predicates = predicates or {}
    compared = 0
    skipped = 0
    want_by = by_archive(want_rows)
    got_by = by_archive(got_rows)
    for archive in sorted(set(want_by) | set(got_by)):
        want = want_by.get(archive, [])
        got = got_by.get(archive, [])
        if len(want) != len(got):
            failures.append("%s: %s has %d members against %d intended"
                % (what, archive, len(got), len(want)))
            continue
        for want_row, got_row in zip(want, got):
            for name in COLUMNS:
                if name in ("archive", "index") or name in not_asked:
                    continue
                if name in finding_skip:
                    skipped += 1
                    continue
                predicate = predicates.get(name)
                if predicate and not predicate(want_row):
                    skipped += 1
                    continue
                compared += 1
                if column(want_row, name) != column(got_row, name):
                    failures.append("%s: %s: %s is %r, intended %r"
                        % (what, describe_row(want_row), name,
                            column(got_row, name), column(want_row, name)))
    return compared, skipped


####################################################################
# Stage 2: inside the container
####################################################################

def inner(directory):
    """Ask the references, and have two of them re-write what they read.

    Runs in the pinned image. Writes files the host half then reads, rather than
    printing them, because several answers on one stream would need a delimiter and
    a delimiter is one more thing to get wrong.
    """
    import zipfile
    import make_zip_corpus

    ours = os.path.join(directory, "ours")
    sources = sorted(n for n in os.listdir(ours) if n.endswith(".zip"))

    warnings = []
    verdicts = []

    # **Whether each reference accepts the archive at all**, which is the first
    # thing the plan asks of this gate. unzip -t and 7z t verify every member's
    # CRC as well; bsdtar is asked to list, which is the cheapest question that
    # requires reading the structure.
    for tool, argv in (("unzip", ["unzip", "-t"]),
            ("bsdtar", ["bsdtar", "-tf"]),
            ("sevenzip", ["7z", "t", "-bso0", "-bsp0"])):
        for name in sources:
            if name in NOT_UNZIP and tool != "sevenzip":
                continue
            command = list(argv)
            if name == AES_ARCHIVE:
                command = ["7z", "t", "-p" + AES_PASSWORD, "-bso0", "-bsp0"]
            finished = subprocess.run(command + [name], cwd=ours,
                capture_output=True, stdin=subprocess.DEVNULL)
            verdicts.append("%s\t%s\t%d" % (tool, name, finished.returncode))
            for raw in finished.stderr.decode("utf-8", "replace").splitlines():
                if raw.strip():
                    warnings.append("%s\t%s\t%s" % (tool, name, raw.strip()))

    # Names, from unzip, which prints them as bytes.
    names = []
    for name in sources:
        if name in NOT_UNZIP:
            continue
        finished = subprocess.run(["unzip", "-Z1", name], cwd=ours,
            capture_output=True, stdin=subprocess.DEVNULL)
        if finished.returncode != 0:
            sys.stderr.write("unzip -Z1 failed on %s\n" % name)
            return 1
        listing = finished.stdout.split(b"\n")
        if listing and listing[-1] == b"":
            listing.pop()
        for index, raw in enumerate(listing):
            names.append("%s\t%d\t%s" % (name, index, make_zip_corpus.escape(raw)))

    # Types, modes and link targets, from libarchive, which is the only reference
    # here that decides them. Its own rows, in the gate's shape, with the columns
    # it cannot answer left empty and skipped by the comparison.
    # bsdtar_rows() walks the whole directory and returns every archive's rows in
    # order, which is the shape this gate wants - and it is the same function
    # make_zip_corpus.py uses for names.tsv, so there is one parse of libarchive's
    # listing in this repository rather than two that can disagree.
    archive_rows = []
    for row in make_zip_corpus.bsdtar_rows(ours):
        # (archive, index, type, mode, name, link) -> the gate's shape.
        archive_rows.append("\t".join([row[0], row[1], row[4], row[2], "", "",
            mode_octal(row[3]), row[5], "", ""]))

    # Metadata, from Python, in the same shape.
    meta = []
    for name in sources:
        if name in (AES_ARCHIVE, ZSTD_ARCHIVE):
            continue
        try:
            handle = zipfile.ZipFile(os.path.join(ours, name))
        except Exception:
            if name == LZMA_ARCHIVE:
                continue
            raise
        with handle:
            try:
                rows = []
                for index, info in enumerate(handle.infolist()):
                    # read() recomputes nothing, so testzip() is asked separately
                    # below; this is here because a member whose data is the wrong
                    # length is a different defect from one whose CRC is wrong.
                    length = len(handle.read(info))
                    # The permission bits only. The type bits are in the same half
                    # and are bsdtar's question, not this one's.
                    mode = (info.external_attr >> 16) & 0o7777
                    rows.append("\t".join([
                        name,
                        str(index),
                        make_zip_corpus.escape(make_zip_corpus.name_bytes(info)),
                        python_type(info),
                        str(info.file_size),
                        str(length),
                        "%04o" % mode,
                        "",
                        str(info.compress_type),
                        "%08x" % (info.CRC & 0xFFFFFFFF),
                    ]))
                bad = handle.testzip()
            except Exception:
                # Opened, but a member is not bytes this Python can decode.
                # LZMA is asked only when it accepts the bytes. Every other
                # archive is one it is required to read.
                if name == LZMA_ARCHIVE:
                    continue
                raise
            meta.extend(rows)
            verdicts.append("pyzipfile\t%s\t%s" % (name, "0" if bad is None
                else "bad:" + bad))

    for filename, lines in (("verdicts.tsv", verdicts), ("warnings.tsv", warnings),
            ("names-unzip.tsv", names), ("rows-bsdtar.tsv", archive_rows),
            ("meta-python.tsv", meta)):
        with open(os.path.join(directory, filename), "w",
                encoding="utf-8") as handle:
            handle.write("\n".join(lines) + ("\n" if lines else ""))

    # And the round trips: read what we wrote, write it out again. A member-level
    # copy in both cases, so nothing is lost to what a file on disk cannot hold.
    bsdtar_out = os.path.join(directory, "rt-bsdtar")
    python_out = os.path.join(directory, "rt-python")
    os.makedirs(bsdtar_out, exist_ok=True)
    os.makedirs(python_out, exist_ok=True)
    for name in sources:
        source = os.path.join(ours, name)
        if name not in NOT_UNZIP:
            finished = subprocess.run(
                ["bsdtar", "--format", "zip", "-cf",
                    os.path.join(bsdtar_out, name), "@" + source],
                capture_output=True, stdin=subprocess.DEVNULL)
            if finished.returncode != 0:
                sys.stderr.write("bsdtar could not re-write %s: %s\n" % (name,
                    finished.stderr.decode("utf-8", "replace").strip()))
                return 1
        if name in (AES_ARCHIVE, ZSTD_ARCHIVE):
            continue
        try:
            with zipfile.ZipFile(source) as reader:
                with zipfile.ZipFile(os.path.join(python_out, name), "w") as writer:
                    for info in reader.infolist():
                        writer.writestr(info, reader.read(info))
        except Exception:
            if name == LZMA_ARCHIVE:
                continue
            raise
    return 0


def mode_octal(escaped_mode):
    """libarchive's `-rwxr-xr-x` rendering as the gate's four octal digits.

    **A translation of a reference's own vocabulary, which is the one kind of
    modelling this gate does.** It is safe in a way a quoting model is not: the
    mapping from ten characters to twelve bits is fixed by POSIX, every bit of it
    is exercised by the probe's corpus - a setuid member, an all-zero member, a
    directory, a symlink and an executable - and a mistake in it fails loudly on
    the first archive rather than passing quietly on one member.

    @param escaped_mode The mode field as bsdtar printed it.
    @return Four octal digits, as the probe prints them.
    """
    text = escaped_mode
    if len(text) < 10:
        return "????"
    bits = 0
    for index, (character, value) in enumerate((
            (text[1], 0o400), (text[2], 0o200), (text[3], 0o100),
            (text[4], 0o40), (text[5], 0o20), (text[6], 0o10),
            (text[7], 0o4), (text[8], 0o2), (text[9], 0o1))):
        if character not in "-":
            bits |= value
        del index
    # The three that overload an execute position: s, S, t, T.
    if text[3] in "sS":
        bits |= 0o4000
    if text[6] in "sS":
        bits |= 0o2000
    if text[9] in "tT":
        bits |= 0o1000
    # A capital letter means the bit is set and the execute bit under it is not,
    # so the execute bit has to come back off.
    if text[3] == "S":
        bits &= ~0o100
    if text[6] == "S":
        bits &= ~0o10
    if text[9] == "T":
        bits &= ~0o1
    return "%04o" % bits


def python_type(info):
    """Python's zipfile has no type, so this is derived from the mode bits.

    Which is a *decision*, and the reason bsdtar answers the type column instead:
    this exists only so Python's rows have the same shape, and the comparison skips
    the column for a symlink - which Python cannot represent at all.
    """
    mode = (info.external_attr >> 16) & 0o170000
    if mode == 0o120000:
        return "symlink"
    if info.is_dir():
        return "directory"
    return "file"


####################################################################
# Stage 1 and 3: on the host
####################################################################

def probe(binary, argv):
    """Run the probe, or die saying what it said."""
    finished = subprocess.run([binary] + argv, capture_output=True, text=True)
    if finished.returncode != 0:
        sys.stderr.write("### zip_writer_probe %s failed ###\n%s%s\n"
            % (" ".join(argv), finished.stdout, finished.stderr))
        raise SystemExit(1)
    if finished.stderr.strip():
        sys.stderr.write(finished.stderr)
    return finished.stdout


def read_directory(binary, directory):
    """Our reading of every archive in one directory, as rows."""
    rows = []
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".zip"):
            continue
        rows += rows_from(probe(binary, ["read", os.path.join(directory, name)]))
    return rows


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", help="path to the zip_writer_probe binary")
    parser.add_argument("--inner", metavar="DIR",
        help="run stage 2 in place (used inside the container)")
    parser.add_argument("--dir", metavar="DIR",
        help="work here instead of a temporary directory, and keep it")
    options = parser.parse_args(argv[1:])

    if options.inner:
        return inner(options.inner)
    if not options.probe:
        parser.error("--probe is required")

    import oracle_env

    try:
        print(oracle_env.provenance(
            ["unzip", "bsdtar", "sevenzip", "pyzipfile"]), flush=True)
    except oracle_env.OracleUnavailable as why:
        sys.stderr.write(
            "### check-zip-writer: the references are not reachable ###\n  %s\n\n"
            "This is a failure and not a skip. A machine with no engine would\n"
            "otherwise look exactly like one where the writer's output is still\n"
            "understood, which is the one thing this gate exists to tell apart.\n"
            % why)
        return 1

    keep = options.dir is not None
    work = options.dir or tempfile.mkdtemp(prefix="garc-zip-writer-")
    ours = os.path.join(work, "ours")
    os.makedirs(ours, exist_ok=True)
    try:
        return run(options.probe, work, ours)
    finally:
        if not keep:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print("check-zip-writer: left the archives in %s" % work)


def run(binary, work, ours):
    """The three stages and every comparison between them."""
    import oracle_env

    purposes = {}
    for line in probe(binary, ["describe"]).splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            purposes[parts[0]] = parts[1]
    intent = rows_from(probe(binary, ["write", ours]))
    written = sorted(n for n in os.listdir(ours) if n.endswith(".zip"))
    if len(written) != EXPECTED_ARCHIVES or len(intent) != EXPECTED_MEMBERS:
        sys.stderr.write(
            "### The probe's corpus is not the one this gate measures ###\n"
            "  zip_writer_probe wrote %d archives and %d members; this gate\n"
            "  expects %d and %d.\n\n"
            "If a fixture was added on purpose, raise EXPECTED_ARCHIVES and\n"
            "EXPECTED_MEMBERS in tools/oracle/check_zip_writer.py in the same\n"
            "commit. If it was not, a member is being dropped - a refusal from\n"
            "garc_writer_add() that the probe reported and nothing else reads,\n"
            "most likely - and every comparison below would still have passed,\n"
            "because the intent rows shrink along with the corpus.\n"
            % (len(written), len(intent), EXPECTED_ARCHIVES, EXPECTED_MEMBERS))
        return 1

    command = oracle_env.command("unzip",
        ["python3", os.path.join(HERE, "check_zip_writer.py"), "--inner", work],
        scratch=work)
    finished = subprocess.run(command)
    if finished.returncode != 0:
        sys.stderr.write(
            "### The references could not read what the writer produced ###\n"
            "That is the gate's own subject failing, not a manifest to "
            "update.\n")
        return 1

    def read_tsv(name):
        with open(os.path.join(work, name), "r", encoding="utf-8") as handle:
            return handle.read()

    failures = []
    counts = []

    # 1. Every reference accepted every archive. unzip -t and 7z t verify every
    #    member's CRC while they are at it, and Python's testzip() recomputes them
    #    all - which is what says the checksums describe the data rather than
    #    merely being in the right fields.
    verdicts = 0
    python_lzma = False
    for line in read_tsv("verdicts.tsv").splitlines():
        tool, name, status = line.split("\t")
        verdicts += 1
        if tool == "pyzipfile" and name == LZMA_ARCHIVE:
            python_lzma = True
        if status != "0":
            failures.append("%s refused %s (%s) - %s"
                % (tool, name, status, purposes.get(name, "?")))
    # Seven archives from unzip, bsdtar and Python, all ten from 7-Zip, and
    # Python's LZMA verdict only when those bytes were ones it accepted.
    shared = EXPECTED_ARCHIVES - len(NOT_UNZIP)
    expected_verdicts = shared * 3 + EXPECTED_ARCHIVES + (1 if python_lzma else 0)
    if verdicts != expected_verdicts:
        failures.append("%d verdicts against %d expected"
            % (verdicts, expected_verdicts))

    # 2. Nothing any of them said while doing it.
    for line in read_tsv("warnings.tsv").splitlines():
        tool, name, text = line.split("\t", 2)
        if text not in ALLOWED_WARNINGS.get(tool, ()):
            failures.append("%s said something about %s: %s" % (tool, name, text))

    # 3. The names, from the reference that prints bytes.
    want_names = by_archive(excluding(intent, NOT_UNZIP))
    got_names = {}
    for line in read_tsv("names-unzip.tsv").splitlines():
        name, _index, printed = line.split("\t")
        got_names.setdefault(name, []).append(printed)
    for archive in sorted(want_names):
        want = [column(row, "name") for row in want_names[archive]]
        got = got_names.get(archive)
        if got is None:
            failures.append("unzip listed no names for %s" % archive)
            continue
        if want != got:
            failures.append("unzip's names for %s are %r, intended %r"
                % (archive, got, want))
    counts.append(("names from unzip", sum(len(v) for v in got_names.values()), 0))

    # 4. libarchive's types, modes and links.
    bsdtar_compared, bsdtar_skipped = compare(failures, "bsdtar",
        excluding(intent, NOT_UNZIP),
        excluding(rows_from(read_tsv("rows-bsdtar.tsv")), NOT_UNZIP),
        not_asked=("size", "mtime", "method", "crc"),
        predicates={"name": lambda row: bsdtar_verbatim(column(row, "name"))})
    counts.append(("fields from bsdtar", bsdtar_compared, bsdtar_skipped))

    # 5. Python's metadata. Its `size` column is the declared size and its `mtime`
    #    column is the *length of the data it read*, which is why the intent's
    #    mtime is not compared here - the shape is shared and the questions are
    #    not. The data length against the declared size is the check that a member
    #    holds what it says.
    python_rows = rows_from(read_tsv("meta-python.tsv"))
    python_skip = [AES_ARCHIVE, ZSTD_ARCHIVE]
    if not any(row[0] == LZMA_ARCHIVE for row in python_rows):
        python_skip.append(LZMA_ARCHIVE)
    py_compared, py_skipped = compare(failures, "pyzipfile",
        excluding(intent, python_skip), python_rows,
        not_asked=("mtime", "type", "linkname"))
    counts.append(("fields from pyzipfile", py_compared, py_skipped))
    for row in python_rows:
        if column(row, "size") != column(row, "mtime"):
            failures.append("pyzipfile: %s: read %s bytes of a %s-byte member"
                % (describe_row(row), column(row, "mtime"),
                    column(row, "size")))

    # 6. Our own reading of what we wrote, which is the round trip that needs no
    #    reference at all - and the one that would pass on its own however wrong
    #    the bytes were, which is why it is sixth rather than first.
    ours_compared, ours_skipped = compare(
        failures, "our own reading", intent, read_directory(binary, ours))
    counts.append(("fields read back by us", ours_compared, ours_skipped))

    # 7. And our reading of what the two re-writers produced. This is where a
    #    reference states byte-exactly what it understood: it wrote the member
    #    again from what it read.
    for label, directory in (("bsdtar", "rt-bsdtar"), ("python", "rt-python")):
        got = read_directory(binary, os.path.join(work, directory))
        verbatim = bsdtar_verbatim if label == "bsdtar" else python_verbatim
        predicates = {"name": lambda row, f=verbatim: f(column(row, "name"))}
        if label == "bsdtar":
            predicates["method"] = deflated_only
            asked = excluding(intent, NOT_UNZIP)
        else:
            skip = [AES_ARCHIVE, ZSTD_ARCHIVE]
            if not any(row[0] == LZMA_ARCHIVE for row in got):
                skip.append(LZMA_ARCHIVE)
            asked = excluding(intent, skip)
        compared, skipped = compare(failures, "%s round trip" % label,
            asked,
            got, finding_skip=ROUNDTRIP_SKIP.get(label, ()),
            predicates=predicates)
        counts.append(("fields after %s re-wrote" % label, compared, skipped))

    if failures:
        sys.stderr.write(
            "### The references disagree with what this library wrote ###\n")
        for line in failures:
            sys.stderr.write("  %s\n" % line)
        sys.stderr.write("\nThe archives, and what each is for:\n")
        for name in sorted(purposes):
            sys.stderr.write("  %-16s %s\n" % (name, purposes[name]))
        sys.stderr.write(
            "\nThis gate's subject is this library's writer. A disagreement here\n"
            "is a finding about what we produce, not an expectation to update -\n"
            "the intent rows come from the writer's own table and every\n"
            "comparison is against them.\n")
        return 1

    print("check-zip-writer: %d archives, %d accepted by unzip, bsdtar and "
        "Python, all of them by 7-Zip, Python %s %s; %s"
        % (EXPECTED_ARCHIVES, shared,
            "accepted" if python_lzma else "was not asked about",
            LZMA_ARCHIVE,
            ", ".join("%d %s" % (count, what) for what, count, _ in counts)))
    skipped_total = sum(skipped for _, _, skipped in counts)
    # Only the exclusions that are findings about a reference. A column a
    # reference has no answer for is not in this number, because a figure that
    # counted those would be dominated by them and nobody could act on it.
    print("  %d fields skipped because a reference changes them, each named in "
        "ROUNDTRIP_SKIP, bsdtar_verbatim(), python_verbatim() or deflated_only()"
        % skipped_total)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
