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
"""Fail if the live references read the committed zip corpus differently.

    make check-zip-oracle

**Distinct from `check-zip-corpus`, and the difference is not pedantry.** That
one regenerates the fixtures and compares the bytes: it catches a reference whose
*writing* moved. This re-reads the committed bytes and compares the readings: it
catches a reference whose *reading* moved. A release can change one without the
other - a fix to how an extra field is parsed changes no output - and a suite that
only regenerated would call that a pass.

It also catches the thing a fixture's hash cannot: a `.tsv` edited by hand to make
a failing test pass. The digests in `containers/CORPUS-ZIP` cover the files as
committed, so a reading edited *and* rehashed satisfies `check-corpus-hashes`.
Asking the references again is the only thing that does not.

**And it is the only gate that covers the three fixtures with no digest.** A
random AES salt, a random ZipCrypto header and an unsettable ctime mean those
three cannot be compared byte for byte; every field the references read out of
them is constant, and this is where that is checked against the committed
readings rather than against a hash of bytes that were always going to move.

The questions are not asked again here. They are the same functions the generator
uses, pointed at the committed corpus with an output directory of their own - a
checker that re-implemented them would be comparing two implementations of the
question rather than the references against the corpus.
"""

import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
CORPUS = os.path.join(ROOT, "tests", "data", "zip")

sys.path.insert(0, HERE)
import make_zip_corpus  # noqa: E402


def rows(path):
    """The data lines of a reading, comments and blanks dropped."""
    out = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            out.append(tuple(line.split("\t")))
    return out


def inner():
    """Ask the references about the committed bytes, and compare."""
    scratch = os.path.join(ROOT, "build", "zip-oracle-check")
    if os.path.exists(scratch):
        shutil.rmtree(scratch)
    os.makedirs(scratch)

    make_zip_corpus.manifest(CORPUS, out=scratch)
    make_zip_corpus.names(CORPUS, out=scratch)
    make_zip_corpus.openings(CORPUS, out=scratch)

    failures = []
    counts = []
    for name, who in (("manifest.tsv", "zipfile"),
            ("names.tsv", "bsdtar"),
            ("openings.tsv", "the references")):
        got = rows(os.path.join(scratch, name))
        want = rows(os.path.join(CORPUS, name))
        counts.append((name, len(got)))
        if got == want:
            continue
        failures.append("%s: %s now produces %d rows against %d committed"
            % (name, who, len(got), len(want)))
        # Every row that is on one side and not the other, in both directions: a
        # row that moved shows up twice, which is what makes the change legible
        # rather than only its count.
        for row in sorted(set(want) ^ set(got)):
            side = "committed" if row in want else who
            failures.append("  %s only: %s" % (side, "\t".join(row)))

    if failures:
        sys.stderr.write(
            "### The live references disagree with the committed readings ###\n")
        for line in failures:
            sys.stderr.write("  %s\n" % line)
        sys.stderr.write(
            "\nA reference that reads the committed bytes differently is a\n"
            "finding to triage, not a reading to rewrite. If a pin was raised\n"
            "deliberately, the new reading is the new expectation and both the\n"
            "pin and the readings belong in that commit with the difference\n"
            "written down.\n")
        return 1

    print("check-zip-oracle: %s still agree"
        % ", ".join("%d rows of %s" % (count, name) for name, count in counts))
    return 0


def main(argv):
    if os.environ.get("GHOTI_ARCHIVE_ZIP_CORPUS_INNER") == "1":
        return inner()

    import oracle_env

    print(oracle_env.provenance(
        ["unzip", "sevenzip", "pyzipfile", "bsdtar"]), flush=True)
    # `zip` itself is not asked anything here - nothing is written - so it is not
    # in the provenance line. It is in the generator's, which is where writing
    # happens.
    command = oracle_env.command("unzip",
        ["python3", os.path.join(HERE, "check_zip_manifest.py")],
        scratch=[os.path.join(ROOT, "build")])
    if "run" in command[:2]:
        cut = command.index("run") + 1
        command = (command[:cut]
            + ["--env", "GHOTI_ARCHIVE_ZIP_CORPUS_INNER=1"] + command[cut:])
    return subprocess.run(command,
        env=dict(os.environ, GHOTI_ARCHIVE_ZIP_CORPUS_INNER="1")).returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv))
