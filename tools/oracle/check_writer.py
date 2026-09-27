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
"""Fail if the references disagree with what this library's writer produces.

    make check-writer

**The third oracle gate, and it asks the question the other two cannot.**

    check-corpus   regenerates the committed fixtures: catches a reference
                   whose *writing* moved.
    check-oracle   re-reads the committed fixtures: catches a reference whose
                   *reading* moved.
    check-writer   hands the references bytes this library wrote a moment ago:
                   catches *this library's* writing moving away from what they
                   understand.

The first two are about the references. This one is about us, and nothing that
runs on this machine alone can take its place - `tests/unit/test_writer.cpp`
asserts that the writer agrees with this library's own idea of tar, which is
exactly the agreement that a shared misunderstanding preserves.

**Everything is compared against the intent, never against another reading.**
`writer_probe write` prints what it meant to put in each archive before any
reference has seen it. GNU tar and bsdtar are asked for the names, Python's
`tarfile` for the metadata, and this library is asked to read back both its own
output and what two of the references re-wrote. A gate that compared our reading
to theirs would pass whenever both were wrong the same way.

**Each reference is asked the question it can answer faithfully, and which
that is was measured rather than assumed.** Three limitations came out of the
first run of this gate, and all three shape what is compared:

- **`tarfile` strips a directory member's trailing slash**, reporting `notes`
  where the header says `notes/`. Inherited from `make_corpus.py`, which is why
  names are not its question. Its name column is still compared, with that one
  difference removed from both sides for directory members only - so a file name
  that lost a byte still fails.
- **GNU tar's listing is byte-faithful only with `--quoting-style=literal`.** Its
  default escapes a literal backslash as `\\` and a byte with no character in
  the locale as `\377`, so the default would have made this gate compare tar's
  quoting rules against raw bytes. With the option it prints the bytes, and it is
  therefore the reference that answers the name question for every member.
- **bsdtar cannot be asked for raw bytes at all.** libarchive 3.7.4 has no
  quoting option and escapes unconditionally, in every locale - and under
  `LC_ALL=C` it escapes valid UTF-8 as well. So bsdtar's names are compared
  byte-for-byte only where the intended name is made of printable ASCII with no
  backslash, which is `quoting_safe()` below. For the two names that are not, the
  gate does not model libarchive's quoting - a model of a spec is one more thing
  to be wrong - and bsdtar's byte-exact statement about them comes from its round
  trip instead, where it re-writes the member and this library reads the name
  back out of what it wrote.

**A reference's warnings are part of its answer.** GNU tar 1.35 does not
implement `hdrcharset` and says so on stderr while still getting the name right.
That one line is allowed by name; any other output from either listing tool fails
the gate, because a new warning is the cheapest possible notice that this library
has started writing something a reference only half understands.

Three stages, and the container boundary is crossed once:

  1. host       writer_probe write    the archives, and the intent rows
  2. container  --inner               the references read them, and two re-write
  3. host       writer_probe read     our reading of all three directories

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

# The row shape, shared with writer_probe.c. Named here so a failure can say
# which column disagreed rather than printing two tab-separated lines and
# leaving the reader to count.
COLUMNS = ["archive", "index", "name", "type", "size", "mtime", "mtime_ns",
    "mode", "uid", "gid", "uname", "gname", "linkname", "devmajor", "devminor"]

# Columns a round trip through a given re-writer is not asked about.
#
# **Empty, and that is the measurement rather than an omission.** Both
# re-writers carry every column in COLUMNS through unchanged: the fractional and
# negative times, the ids past the octal field, the setuid and sticky bits, the
# device numbers, the long name and the long link target, the non-UTF-8 name and
# its `hdrcharset` record. That was the open question when this gate was written
# and it turned out to have the good answer, so the table stays here with nothing
# in it - a field added later would be a finding about that reference, named in
# place, and the alternative of widening the comparison to absorb it is what this
# table exists to make visible instead.
ROUNDTRIP_SKIP = {}

# The population this gate measures, asserted rather than counted and reported.
#
# **Measured need.** Making the probe write one member fewer per archive was not
# caught by anything else here, and could not have been: the intent rows shrink
# with the corpus, so every comparison still agrees and the gate stays green while
# testing less. A corpus is a denominator, and a denominator nothing checks is one
# that can quietly go to zero.
#
# These two numbers are the one thing here that has to be edited when a fixture is
# added. That is deliberate: the edit is where somebody says out loud that the
# corpus grew, and an accidental shrink has no such edit anywhere.
EXPECTED_ARCHIVES = 13
EXPECTED_MEMBERS = 56

# What a listing reference is allowed to say on stderr, matched whole.
#
# GNU tar 1.35 does not implement `hdrcharset`. It still reads the name out of the
# `path=` record correctly, so this is a warning and not a wrong answer - but it is
# the reason the line is named here rather than filtered by a pattern: a pattern
# that swallowed every "Ignoring unknown extended header keyword" would also
# swallow the next keyword this library starts writing.
ALLOWED_WARNINGS = {
    "tar": ("tar: Ignoring unknown extended header keyword 'hdrcharset'",),
    "bsdtar": (),
}


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


def compare(failures, what, want_rows, got_rows, skip=()):
    """Compare two row lists field by field, index-aligned.

    Aligned by position rather than matched by name on purpose: a member that
    moved is a defect, and matching by name would silently reorder it away.
    """
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
                if name in skip or name in ("archive", "index"):
                    continue
                if column(want_row, name) != column(got_row, name):
                    failures.append("%s: %s: %s is %r, intended %r"
                        % (what, describe_row(want_row), name,
                            column(got_row, name), column(want_row, name)))


def quoting_safe(escaped):
    """Whether a listing tool that escapes will print this name unchanged.

    Asked of the *escaped* intent field, which is convenient and exact: this
    module's escaping already marks the two things libarchive escapes - a literal
    backslash, which arrives here as `\\\\`, and any byte outside printable
    ASCII, which arrives as `\\xHH`. A name with neither is printable ASCII with
    no backslash in it, and every reference prints those as they are.

    This is a predicate on the *input*, not a model of a tool's output, and the
    difference is the point: a wrong model of libarchive's quoting would make the
    gate compare the wrong string and pass. A wrong predicate here can only move
    a name between "compared byte for byte" and "counted but not compared", and
    the count of each is printed so that a name quietly leaving the first group
    is visible.
    """
    return "\\" not in escaped


def compare_names(failures, what, want_rows, got_names, faithful):
    """Compare a listing tool's output against the intended names.

    `got_names` is {archive: [name, ...]} in the order the tool printed them.
    `faithful` says whether this tool prints the bytes: when it does not, only
    the names `quoting_safe()` accepts are compared, and the rest are counted.

    Position, count and order are checked for every member either way. A tool
    that escapes still has to list the right number of members in the right
    order, and that is most of what a listing proves.

    @return The number of names compared byte for byte, and the number skipped.
    """
    compared = 0
    skipped = 0
    want_by = by_archive(want_rows)
    for archive in sorted(want_by):
        want = [column(row, "name") for row in want_by[archive]]
        got = got_names.get(archive)
        if got is None:
            failures.append("%s: %s was not listed at all" % (what, archive))
            continue
        if len(want) != len(got):
            failures.append("%s: %s lists %d names against %d intended"
                % (what, archive, len(got), len(want)))
            continue
        for index, (mine, theirs) in enumerate(zip(want, got)):
            if not faithful and not quoting_safe(mine):
                skipped += 1
                continue
            compared += 1
            if mine != theirs:
                failures.append("%s: %s[%d] reads %s, intended %s"
                    % (what, archive, index, theirs, mine))
    return compared, skipped


####################################################################
# Stage 2: inside the container
####################################################################

def escape(raw):
    """A byte string as one field. The same rule as make_corpus.escape()."""
    import make_corpus
    return make_corpus.escape(raw)


def inner(directory):
    """Ask the references, and have two of them re-write what they read.

    Runs in the pinned image, because that is where the references are. Writes
    three files the host half then reads, rather than printing them, because
    three separate answers on one stream would have to be delimited and a
    delimiter is one more thing to get wrong.
    """
    import tarfile
    import make_corpus

    ours = os.path.join(directory, "ours")
    sources = sorted(n for n in os.listdir(ours) if n.endswith(".tar"))

    # Names, from both listing references.
    #
    # `--quoting-style=literal` is what makes GNU tar's answer the bytes rather
    # than GNU tar's quoting of the bytes. bsdtar has no equivalent - see the
    # module docstring - so it is asked the same way and the host half compares
    # only the names its escaping leaves alone.
    for tool, argv in (("tar", ["tar", "--quoting-style=literal", "-tf"]),
            ("bsdtar", ["bsdtar", "-tf"])):
        lines = []
        warnings = []
        for name in sources:
            finished = subprocess.run(argv + [os.path.join(ours, name)],
                capture_output=True)
            if finished.returncode != 0:
                sys.stderr.write("%s failed on %s: %s\n" % (tool, name,
                    finished.stderr.decode("utf-8", "replace").strip()))
                return 1
            listing = finished.stdout.split(b"\n")
            if listing and listing[-1] == b"":
                listing.pop()
            for index, raw in enumerate(listing):
                lines.append("%s\t%d\t%s" % (name, index, escape(raw)))
            # Everything the tool said on stderr while doing it, which the host
            # half checks against one allowed line. A reference that starts
            # warning about a record this library writes is the cheapest notice
            # there is that it only half understands the output.
            for raw in finished.stderr.decode("utf-8", "replace").splitlines():
                if raw.strip():
                    warnings.append("%s\t%s" % (name, raw.strip()))
        with open(os.path.join(directory, "names-%s.tsv" % tool), "w",
                encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
        with open(os.path.join(directory, "warnings-%s.tsv" % tool), "w",
                encoding="utf-8") as handle:
            handle.write("\n".join(warnings) + ("\n" if warnings else ""))

    # Metadata, from tarfile, in writer_probe's row shape.
    rows = []
    for name in sources:
        with tarfile.open(os.path.join(ours, name), "r:") as archive:
            for index, info in enumerate(archive):
                seconds, nanoseconds = make_corpus.member_time(info)
                rows.append("\t".join([
                    name,
                    str(index),
                    escape(info.name.encode("utf-8", "surrogateescape")),
                    make_corpus.member_type(info),
                    str(info.size),
                    str(seconds),
                    str(nanoseconds),
                    "0%o" % info.mode,
                    str(info.uid),
                    str(info.gid),
                    escape(info.uname.encode("utf-8", "surrogateescape")),
                    escape(info.gname.encode("utf-8", "surrogateescape")),
                    escape(info.linkname.encode("utf-8", "surrogateescape")),
                    str(info.devmajor),
                    str(info.devminor),
                ]))
    with open(os.path.join(directory, "meta-tarfile.tsv"), "w",
            encoding="utf-8") as handle:
        handle.write("\n".join(rows) + "\n")

    # And the round trips: read what we wrote, write it out again.
    tarfile_out = os.path.join(directory, "rt-tarfile")
    bsdtar_out = os.path.join(directory, "rt-bsdtar")
    os.makedirs(tarfile_out, exist_ok=True)
    os.makedirs(bsdtar_out, exist_ok=True)
    for name in sources:
        source = os.path.join(ours, name)
        with tarfile.open(source, "r:") as reader:
            with tarfile.open(os.path.join(tarfile_out, name), "w:",
                    format=tarfile.PAX_FORMAT) as writer:
                for info in reader:
                    payload = (reader.extractfile(info)
                        if info.isreg() else None)
                    writer.addfile(info, payload)
        # libarchive reads an archive as an input to a creation with `@`, which
        # is a member-level copy: no filesystem, so nothing is lost to what a
        # file on disk cannot hold.
        finished = subprocess.run(
            ["bsdtar", "-cf", os.path.join(bsdtar_out, name),
                "--format=pax", "@" + source], capture_output=True)
        if finished.returncode != 0:
            sys.stderr.write("bsdtar could not re-write %s: %s\n" % (name,
                finished.stderr.decode("utf-8", "replace").strip()))
            return 1
    return 0


####################################################################
# Stage 1 and 3: on the host
####################################################################

def probe(binary, argv):
    """Run the probe, or die saying what it said."""
    finished = subprocess.run([binary] + argv, capture_output=True, text=True)
    if finished.returncode != 0:
        sys.stderr.write("### writer_probe %s failed ###\n%s%s\n"
            % (" ".join(argv), finished.stdout, finished.stderr))
        raise SystemExit(1)
    if finished.stderr.strip():
        sys.stderr.write(finished.stderr)
    return finished.stdout


def read_directory(binary, directory):
    """Our reading of every archive in one directory, as rows."""
    rows = []
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".tar"):
            continue
        rows += rows_from(probe(binary, ["read", os.path.join(directory, name)]))
    return rows


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", help="path to the writer_probe binary")
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

    # Caught rather than left to raise. This gate fails closed on an unreachable
    # reference - which is right, and the sibling gates do the same - but a
    # traceback reads as "the tool is broken" when what happened is "the pinned
    # image is not here", and those want different things done about them.
    try:
        print(oracle_env.provenance(["tar", "bsdtar", "pytarfile"]), flush=True)
    except oracle_env.OracleUnavailable as why:
        sys.stderr.write(
            "### check-writer: the references are not reachable ###\n  %s\n\n"
            "This is a failure and not a skip. A machine with no engine would\n"
            "otherwise look exactly like one where the writer's output is still\n"
            "understood, which is the one thing this gate exists to tell apart.\n"
            % why)
        return 1

    keep = options.dir is not None
    work = options.dir or tempfile.mkdtemp(prefix="garc-writer-")
    ours = os.path.join(work, "ours")
    os.makedirs(ours, exist_ok=True)
    try:
        return run(options.probe, work, ours)
    finally:
        if not keep:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print("check-writer: left the archives in %s" % work)


def run(binary, work, ours):
    """The three stages and every comparison between them."""
    import oracle_env

    # Stage 1. `describe` is read for the failure legend below, so the purpose
    # written beside each archive in writer_probe.c is something this gate prints
    # rather than a comment nothing reads.
    purposes = {}
    for line in probe(binary, ["describe"]).splitlines():
        parts = line.split("\t")
        if len(parts) >= 4:
            purposes[parts[0]] = (parts[1], parts[2], parts[3])
    intent = rows_from(probe(binary, ["write", ours]))
    written = sorted(n for n in os.listdir(ours) if n.endswith(".tar"))
    if len(written) != EXPECTED_ARCHIVES or len(intent) != EXPECTED_MEMBERS:
        sys.stderr.write(
            "### The probe's corpus is not the one this gate measures ###\n"
            "  writer_probe wrote %d archives and %d members; this gate expects\n"
            "  %d and %d.\n\n"
            "If a fixture was added on purpose, raise EXPECTED_ARCHIVES and\n"
            "EXPECTED_MEMBERS in tools/oracle/check_writer.py in the same commit.\n"
            "If it was not, a member is being dropped - a refusal from\n"
            "garc_writer_add() that writer_probe reported and nothing else reads,\n"
            "most likely - and every comparison below would still have passed,\n"
            "because the intent rows shrink along with the corpus.\n"
            % (len(written), len(intent), EXPECTED_ARCHIVES, EXPECTED_MEMBERS))
        return 1

    # Stage 2.
    command = oracle_env.command("tar",
        ["python3", os.path.join(HERE, "check_writer.py"), "--inner", work],
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

    # The listing references, on names, and on what they said while answering.
    tallies = {}
    for tool, faithful in (("tar", True), ("bsdtar", False)):
        listing = {}
        for row in rows_from(read_tsv("names-%s.tsv" % tool)):
            listing.setdefault(row[0], []).append(column(row, "name"))
        tallies[tool] = compare_names(
            failures, tool, intent, listing, faithful)
        for line in read_tsv("warnings-%s.tsv" % tool).splitlines():
            if not line.strip():
                continue
            archive, _, said = line.partition("\t")
            if said in ALLOWED_WARNINGS.get(tool, ()):
                continue
            failures.append("%s: %s: unexpected output while listing: %s"
                % (tool, archive, said))

    # tarfile, on everything else. Its one characterised difference from the
    # bytes is the directory trailing slash, which is dropped from both sides of
    # the name comparison for directory members only - so a truncation of a file
    # name is still a failure.
    theirs = rows_from(read_tsv("meta-tarfile.tsv"))
    compare(failures, "tarfile", [strip_dir_slash(r) for r in intent],
        [strip_dir_slash(r) for r in theirs])

    # Us, on our own output: the identity that makes a later failure localisable.
    compare(failures, "ours", intent, read_directory(binary, ours))

    # And the round trips.
    for label, directory in (("tarfile round trip", "rt-tarfile"),
            ("bsdtar round trip", "rt-bsdtar")):
        path = os.path.join(work, directory)
        compare(failures, label, [strip_dir_slash(r) for r in intent],
            [strip_dir_slash(r) for r in read_directory(binary, path)],
            skip=ROUNDTRIP_SKIP.get(directory, ()))

    if failures:
        sys.stderr.write(
            "### The references disagree with what the writer produced ###\n")
        for line in failures:
            sys.stderr.write("  %s\n" % line)
        named = [name for name in sorted(purposes)
            if any(name in line for line in failures)]
        if named:
            sys.stderr.write("\nWhat those archives are for:\n")
            for name in named:
                variant, blocking, purpose = purposes[name]
                padded = (", padded to %s blocks" % blocking
                    if blocking != "0" else "")
                sys.stderr.write("  %s (%s%s): %s\n"
                    % (name, variant, padded, purpose))
        sys.stderr.write(
            "\nEvery row above is compared against the intent the probe printed\n"
            "before any reference saw the archive, so a disagreement is this\n"
            "library's writer, this library's reader, or a reference that no\n"
            "longer understands what it used to. Which of the three is named by\n"
            "the stage: 'ours' is us reading our own bytes, 'tarfile' and the\n"
            "listing tools are them reading ours, and a round trip is us reading\n"
            "what they made of ours.\n")
        return 1

    print("check-writer: %d members across %d archives. Names: tar %d byte for "
        "byte, bsdtar %d byte for byte and %d counted only (its quoting). "
        "tarfile's metadata and both round trips agree on every column."
        % (len(intent), len(written), tallies["tar"][0], tallies["bsdtar"][0],
            tallies["bsdtar"][1]))
    return 0


def strip_dir_slash(row):
    """The row with a directory member's trailing slash removed.

    Python's `tarfile` reports `notes` where the header says `notes/`. That is a
    difference between the reference and the bytes, fully characterised, and it
    is removed from both sides rather than tolerated on one: a file member whose
    name lost a byte still fails.
    """
    if column(row, "type") != "directory":
        return row
    parts = list(row)
    index = COLUMNS.index("name")
    parts[index] = parts[index].rstrip("/")
    return tuple(parts)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
