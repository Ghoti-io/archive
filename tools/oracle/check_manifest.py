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
"""Fail if the live references disagree with the committed expectations.

    make check-oracle

**Distinct from `check-corpus`, and the difference is not pedantry.**
`check-corpus` regenerates the fixtures and compares the bytes: it catches a
reference whose *writing* moved. This re-reads the committed bytes and compares
the readings: it catches a reference whose *reading* moved. A tar release can
change one without the other - a fix to how a field is parsed changes no output -
and a suite that only regenerates would call that a pass.

It also catches the thing a fixture's hash cannot: `manifest.tsv` and `names.tsv`
edited by hand to make a failing test pass. The hashes in `containers/CORPUS`
cover the files as committed, so a manifest edited *and* rehashed satisfies
`check-corpus-hashes`. Asking the references again is the only thing that does
not.

This runs inside the pinned image, because that is where the references are.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
CORPUS = os.path.join(ROOT, "tests", "data", "tar")

sys.path.insert(0, HERE)
import make_corpus  # noqa: E402  (the escape and manifest helpers live there)


def read_expected(path, columns):
    """The committed file as a list of tuples, comments dropped."""
    rows = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = line.split("\t")
            while len(parts) < columns:
                parts.append("")
            rows.append(tuple(parts[:columns]))
    return rows


def inner():
    """Ask the references, and compare against what is committed."""
    import tarfile

    failures = []

    # Names, from bsdtar.
    got_names = []
    for name in sorted(os.listdir(CORPUS)):
        if not name.endswith(".tar"):
            continue
        finished = subprocess.run(
            ["bsdtar", "-tf", os.path.join(CORPUS, name)], capture_output=True)
        if finished.returncode != 0:
            failures.append("bsdtar failed on %s: %s"
                % (name, finished.stderr.decode("utf-8", "replace").strip()))
            continue
        listing = finished.stdout.split(b"\n")
        if listing and listing[-1] == b"":
            listing.pop()
        for index, raw in enumerate(listing):
            got_names.append((name, str(index), make_corpus.escape(raw)))

    want_names = read_expected(os.path.join(CORPUS, "names.tsv"), 3)
    if got_names != want_names:
        failures.append("names.tsv: bsdtar now reads %d rows against %d "
            "committed" % (len(got_names), len(want_names)))
        for row in sorted(set(want_names) ^ set(got_names)):
            side = "committed" if row in want_names else "bsdtar"
            failures.append("  %s only: %s" % (side, "\t".join(row)))

    # Metadata, from tarfile.
    got_meta = []
    for name in sorted(os.listdir(CORPUS)):
        if not name.endswith(".tar"):
            continue
        with tarfile.open(os.path.join(CORPUS, name), "r:") as archive:
            for index, info in enumerate(archive):
                got_meta.append((
                    name,
                    str(index),
                    make_corpus.escape(
                        info.name.encode("utf-8", "surrogateescape")),
                    make_corpus.member_type(info),
                    str(info.size),
                    str(make_corpus.member_time(info)[0]),
                    str(make_corpus.member_time(info)[1]),
                    "0%o" % info.mode,
                    str(info.uid),
                    str(info.gid),
                    make_corpus.escape(
                        info.uname.encode("utf-8", "surrogateescape")),
                    make_corpus.escape(
                        info.gname.encode("utf-8", "surrogateescape")),
                    make_corpus.escape(
                        info.linkname.encode("utf-8", "surrogateescape")),
                ))

    want_meta = read_expected(os.path.join(CORPUS, "manifest.tsv"), 13)
    if got_meta != want_meta:
        failures.append("manifest.tsv: tarfile now reads %d rows against %d "
            "committed" % (len(got_meta), len(want_meta)))
        for row in sorted(set(want_meta) ^ set(got_meta)):
            side = "committed" if row in want_meta else "tarfile"
            failures.append("  %s only: %s" % (side, "\t".join(row)))

    if failures:
        sys.stderr.write(
            "### The live references disagree with the committed manifests ###\n")
        for line in failures:
            sys.stderr.write("  %s\n" % line)
        sys.stderr.write(
            "\nA reference that reads the committed bytes differently is a\n"
            "finding to triage, not a manifest to rewrite. If a pin was raised\n"
            "deliberately, the new reading is the new expectation and both the\n"
            "pin and the manifest belong in that commit with the difference\n"
            "written down.\n")
        return 1

    print("check-oracle: %d names and %d metadata rows still agree"
        % (len(got_names), len(got_meta)))
    return 0


def main(argv):
    if os.environ.get("GHOTI_ARCHIVE_CORPUS_INNER") == "1":
        return inner()

    import oracle_env

    print(oracle_env.provenance(["tar", "bsdtar", "pytarfile"]), flush=True)
    command = oracle_env.command("tar",
        ["python3", os.path.join(HERE, "check_manifest.py")])
    if "run" in command[:2]:
        cut = command.index("run") + 1
        command = (command[:cut]
            + ["--env", "GHOTI_ARCHIVE_CORPUS_INNER=1"] + command[cut:])
    return subprocess.run(command,
        env=dict(os.environ, GHOTI_ARCHIVE_CORPUS_INNER="1")).returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv))
