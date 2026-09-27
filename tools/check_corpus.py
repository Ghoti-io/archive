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
"""Fail if the committed corpus is not the bytes containers/CORPUS names.

**This gate needs no container, which is why it is in TEST_GATES and
`check-corpus` is not.** Regenerating the corpus needs the pinned image, so a
machine without docker cannot do it - but every machine can hash the files that
are committed, and that is the half that catches the failure worth catching: a
fixture edited by hand, or one that a merge or a `git add -p` dropped half of.

The other half - whether the pinned references still produce these bytes - is
`make check-corpus`, and it is separate and fails closed without the image.

What this cannot see: a fixture and its hash edited together. Nothing local can;
that is what regenerating is for.
"""

import hashlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CORPUS = os.path.join(ROOT, "tests", "data", "tar")
HASHES = os.path.join(HERE, "oracle", "containers", "CORPUS")


def main():
    if not os.path.exists(HASHES):
        sys.stderr.write(
            "check-corpus-hashes: %s is missing. It is committed; a checkout\n"
            "without it cannot check the corpus at all.\n" % HASHES)
        return 1

    want = {}
    with open(HASHES, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            digest, name = line.split("  ", 1)
            want[name] = digest

    if not want:
        sys.stderr.write(
            "check-corpus-hashes: %s lists no files, so this gate checks\n"
            "nothing. Run `make corpus` to regenerate it.\n" % HASHES)
        return 1

    failures = []
    for name, digest in sorted(want.items()):
        path = os.path.join(CORPUS, name)
        if not os.path.exists(path):
            failures.append("%s: named in CORPUS and not in the tree" % name)
            continue
        with open(path, "rb") as handle:
            got = hashlib.sha256(handle.read()).hexdigest()
        if got != digest:
            failures.append("%s: CORPUS %s, tree %s" % (name, digest, got))

    # The other direction, which the loop above cannot see: a fixture in the tree
    # that nothing lists. It would be loaded by a test and never checked for
    # provenance, which is how a hand-built file ends up being treated as a
    # generated one.
    present = {name for name in os.listdir(CORPUS)
        if name.endswith(".tar") or name.endswith(".tsv")}
    for name in sorted(present - set(want)):
        failures.append("%s: in the tree and not named in CORPUS" % name)

    if failures:
        sys.stderr.write("### The committed corpus does not match CORPUS ###\n")
        for line in failures:
            sys.stderr.write("  %s\n" % line)
        sys.stderr.write(
            "\nThe fixtures are generated, not edited. `make corpus` rewrites\n"
            "both them and CORPUS, and both belong in the same commit.\n")
        return 1

    print("check-corpus-hashes: %d committed fixtures match CORPUS"
        % len(want))
    return 0


if __name__ == "__main__":
    sys.exit(main())
