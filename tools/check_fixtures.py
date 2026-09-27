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
"""Fail if anything a test reads is excluded from the repository.

    make check-fixtures

**The failure this exists for leaves `git status` clean.** A `.gitignore` rule
written for build output also matches an input: a blanket `*` with a negation per
directory stops negating the moment a directory is added, because an excluded
*directory* blocks every negation inside it. The files then work perfectly in the
tree where they were written and are absent from every clone, and nothing says so -
the suite goes red on someone else's machine, for a reason that looks like a broken
checkout.

It has happened twice in this workspace: `regex` lost half of what one of its gates
measured against, and this library's third fuzz harness was added with its seed
directory excluded. The gate is cheap because the question is cheap: git will
answer it per path.

What counts as an input: the committed corpus under `tests/data/`, and the fuzz
seeds under `tests/fuzz/corpus/`. Everything the fuzzer *writes* beside those seeds
is output and is meant to be ignored, so the check is that each input is **either
tracked or trackable**, not that everything present is tracked.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# (directory, predicate) - the inputs, and how to tell one from the output beside
# it. A directory with no predicate means every file in it is an input.
INPUTS = [
    (os.path.join("tests", "data"), None),
    (os.path.join("tests", "fuzz", "corpus"), lambda name: name.endswith(".seed")),
]


def git(arguments, stdin=None):
    """Run git, and tell a result apart from a failure to ask.

    **This wrapper exists because the first version of this gate was blind.** It
    ran `git check-ignore -z -- <paths>`, which git rejects outright - `-z only
    makes sense with --stdin` - and exits 128 for. The caller ignored the return
    code on the reasonable grounds that `check-ignore` exits 1 when nothing
    matches, so a *fatal invocation error* was read as "nothing is ignored" and the
    gate reported 87 inputs and no problems while seeing none of them.

    So: exit 0 and exit 1 are answers, and anything else is this program's fault
    rather than the tree's.
    """
    finished = subprocess.run(["git", "-C", ROOT] + arguments,
        input=stdin, capture_output=True, text=True)
    if finished.returncode not in (0, 1):
        raise SystemExit("check-fixtures: `git %s` failed with %d:\n%s"
            % (" ".join(arguments), finished.returncode,
                finished.stderr.strip()))
    return {entry for entry in finished.stdout.split("\0") if entry}


def tracked(paths):
    """The subset of `paths` git already has in the index.

    Paths as arguments: `ls-files` has no `--stdin`, which is worth a line because
    `check-ignore` below *requires* it for the same `-z`. The two subcommands do not
    take their input the same way, and assuming they did is what produced the first
    version of this file.
    """
    if not paths:
        return set()
    return git(["ls-files", "-z", "--"] + paths)


def ignored(paths):
    """The subset of `paths` git would refuse to add.

    Paths on stdin, because `check-ignore` rejects `-z` without `--stdin` - and
    `-z` is worth having, since a fixture name in this corpus may contain any byte.
    """
    if not paths:
        return set()
    return git(["check-ignore", "-z", "--stdin"], stdin="\0".join(paths))


def main():
    inputs = []
    for directory, predicate in INPUTS:
        full = os.path.join(ROOT, directory)
        if not os.path.isdir(full):
            raise SystemExit("check-fixtures: %s does not exist, so this gate is "
                "measuring nothing" % directory)
        for here, _directories, files in os.walk(full):
            for name in sorted(files):
                if predicate and not predicate(name):
                    continue
                inputs.append(os.path.relpath(os.path.join(here, name), ROOT))

    if not inputs:
        raise SystemExit("check-fixtures: found no inputs at all, which means the "
            "list above no longer matches the tree")

    have = tracked(inputs)
    excluded = ignored(inputs)
    # Trackable is what matters: a file may be new and not yet added, and that is
    # fine. What is not fine is one git would refuse to add at all.
    broken = sorted(path for path in inputs
        if path not in have and path in excluded)

    if broken:
        sys.stderr.write("### Test inputs excluded by .gitignore ###\n")
        for path in broken:
            finished = subprocess.run(
                ["git", "-C", ROOT, "check-ignore", "-v", "--", path],
                capture_output=True, text=True)
            sys.stderr.write("  %s\n    %s\n"
                % (path, finished.stdout.strip() or "(no rule reported)"))
        sys.stderr.write(
            "\nThese work in this tree and would be absent from every clone,\n"
            "with `git status` staying clean. Fix the rule rather than adding\n"
            "the files with --force: the next one added will be excluded too.\n")
        return 1

    print("check-fixtures: %d test inputs, %d tracked, none excluded"
        % (len(inputs), len(have)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
