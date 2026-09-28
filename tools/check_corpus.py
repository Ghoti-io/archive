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
"""Fail if a committed corpus is not the bytes its hash list names.

**This gate needs no container, which is why it is in TEST_GATES and
`check-corpus` is not.** Regenerating a corpus needs the pinned image, so a
machine without docker cannot do it - but every machine can hash the files that
are committed, and that is the half that catches the failure worth catching: a
fixture edited by hand, or one that a merge or a `git add -p` dropped half of.

The other half - whether the pinned references still produce these bytes - is
`make check-corpus` and `make check-zip-corpus`, and both are separate and fail
closed without the image.

**Two corpora, two lists, one gate.** Each generator rewrites its own list whole
from what it produced, which is what keeps a dropped fixture visible; this reads
both lists and checks both directions for each, so a fixture in the tree that no
list names is a failure as much as one a list names and the tree does not have.

What this cannot see: a fixture and its hash edited together. Nothing local can;
that is what regenerating is for.

A digest of `-` is a fixture whose bytes are **not** a function of its inputs - a
random AES salt, a random ZipCrypto header, a ctime that cannot be set. Those are
checked for presence here and for their contents through the hashed manifest that
describes them; `NOT_REPRODUCIBLE` in tools/oracle/make_zip_corpus.py says which
and why. The distinction matters in both directions: a `-` that appeared next to
a fixture which *is* reproducible would silently stop checking it, so the gate
prints how many it accepted without a digest.
"""

import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# (what to call it, where the fixtures are, which list names them, which
# extensions belong to it). The extensions are how the "in the tree and named by
# nothing" direction knows what to look at, and they are per corpus because the
# two corpora share a parent directory and nothing else.
CORPORA = (
    ("tar", os.path.join(ROOT, "tests", "data", "tar"),
        os.path.join(HERE, "oracle", "containers", "CORPUS"),
        (".tar", ".tsv")),
    ("zip", os.path.join(ROOT, "tests", "data", "zip"),
        os.path.join(HERE, "oracle", "containers", "CORPUS-ZIP"),
        (".zip", ".tsv")),
)


def check(label, corpus, hashes, extensions):
    """Check one corpus. Returns (failures, checked, unhashed)."""
    failures = []

    if not os.path.exists(hashes):
        return (["%s: %s is missing. It is committed; a checkout without it "
            "cannot check the corpus at all." % (label, hashes)], 0, 0)

    want = {}
    with open(hashes, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            digest, name = line.split("  ", 1)
            want[name] = digest

    if not want:
        return (["%s: %s lists no files, so this gate checks nothing. Run "
            "`make %scorpus` to regenerate it."
            % (label, hashes, "" if label == "tar" else "zip-")], 0, 0)

    checked = 0
    unhashed = 0
    for name, digest in sorted(want.items()):
        path = os.path.join(corpus, name)
        if not os.path.exists(path):
            failures.append("%s/%s: named in the list and not in the tree"
                % (label, name))
            continue
        if digest == "-":
            # Deliberately unhashed; its contents are covered by the manifest.
            unhashed += 1
            continue
        with open(path, "rb") as handle:
            got = hashlib.sha256(handle.read()).hexdigest()
        if got != digest:
            failures.append("%s/%s: list says %s, tree has %s"
                % (label, name, digest, got))
            continue
        checked += 1

    # The other direction, which the loop above cannot see: a fixture in the tree
    # that nothing lists. It would be loaded by a test and never checked for
    # provenance, which is how a hand-built file ends up being treated as a
    # generated one.
    present = {name for name in os.listdir(corpus)
        if name.endswith(extensions)}
    for name in sorted(present - set(want)):
        failures.append("%s/%s: in the tree and named by nothing"
            % (label, name))

    return (failures, checked, unhashed)


def main():
    failures = []
    totals = []
    for label, corpus, hashes, extensions in CORPORA:
        if not os.path.isdir(corpus):
            failures.append("%s: %s is missing" % (label, corpus))
            continue
        problems, checked, unhashed = check(label, corpus, hashes, extensions)
        failures += problems
        totals.append((label, checked, unhashed))

    if failures:
        sys.stderr.write("### A committed corpus does not match its list ###\n")
        for line in failures:
            sys.stderr.write("  %s\n" % line)
        sys.stderr.write(
            "\nThe fixtures are generated, not edited. `make corpus` and\n"
            "`make zip-corpus` rewrite them and their lists, and both belong in\n"
            "the same commit.\n")
        return 1

    print("check-corpus-hashes: %s"
        % ", ".join("%d %s fixtures match%s"
            % (checked, label,
                "" if not unhashed
                else " (+%d listed without a digest, which the manifest covers)"
                    % unhashed)
            for label, checked, unhashed in totals))
    return 0


if __name__ == "__main__":
    sys.exit(main())
