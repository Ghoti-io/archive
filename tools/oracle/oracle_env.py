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
"""How an oracle is spelled, so that no tool here spells one itself.

Copied from the security library's oracle_env.py, itself from font's, which is
the built-here shape: the image has no upstream digest, so check_pin() runs in
both modes and the version the reference prints is the guarantee. A probe that
exits non-zero is a failure even if its stdout happens to contain the expected
text - an oracle that accepts a crashed probe because the banner looked right is
not a pin. What changed here is the probe table.

`command("tar")` returns the argv prefix that runs the reference, which is
`docker run` into the image built by `containers/tars/Containerfile`.

One thing is different here and worth saying: the three references share one
image, so `command()` returns the same `docker run` for all three - the name
selects the *program*, not the image. That is deliberate (containers/IMAGES),
and it is what makes a disagreement between two of them a fact about the two
implementations rather than about two container builds.

Modes, from GHOTI_ORACLE_MODE:

  container  (default) run the reference in its pinned image
  host                 run a binary of the same name on this machine, and
                       still require it to report the pinned version
"""

import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
IMAGES = os.path.join(HERE, "containers", "IMAGES")

MODE = os.environ.get("GHOTI_ORACLE_MODE", "container")
ENGINE = os.environ.get("GHOTI_CONTAINER_ENGINE", "docker")


class OracleUnavailable(Exception):
    """The reference cannot be reached. Never caught into a skip by a gate
    that was asked to judge."""


# The probe is a program in the image, not a shell one-liner here. A one-liner
# puts a quoting layer between the check and the fact it checks.
PROBE = {
    "tar": (["tar-version"], "tar (GNU tar) 1.35"),
    "bsdtar": (["bsdtar-version"], "libarchive 3.7.4"),
    "pytarfile": (["pytarfile-version"], "Python 3.13.5 tarfile"),
}

# The program each reference is invoked as, where it differs from the name.
# `pytarfile` is a stdlib module rather than a command, so the name and the
# binary are not the same word - and host mode checks the binary's presence,
# which means it has to know which binary.
BINARY = {
    "pytarfile": "python3",
}

_pins = None
_cache = {}


def pins():
    """The IMAGES table: name -> (image, version, description)."""
    global _pins
    if _pins is not None:
        return _pins
    _pins = {}
    if not os.path.exists(IMAGES):
        return _pins
    with open(IMAGES, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 3:
                raise OracleUnavailable(
                    "containers/IMAGES: not three tab-separated fields: %r"
                    % line)
            name, image, version = parts[0], parts[1], parts[2]
            _pins[name] = (image, version, parts[3] if len(parts) > 3 else "")
    return _pins


def _engine_ok():
    if shutil.which(ENGINE) is None:
        raise OracleUnavailable(
            "%s is not on PATH, and GHOTI_ORACLE_MODE is 'container'.\n"
            "Install it, or name a different engine with "
            "GHOTI_CONTAINER_ENGINE." % ENGINE)


def _have_image(image):
    finished = subprocess.run([ENGINE, "image", "exists", image],
        capture_output=True)
    if finished.returncode == 0:
        return True
    finished = subprocess.run([ENGINE, "image", "inspect", image],
        capture_output=True)
    return finished.returncode == 0


def ensure(name):
    """Make the reference runnable, or raise saying what is missing."""
    if MODE == "host":
        binary = BINARY.get(name, PROBE.get(name, ([name], ""))[0][0])
        if shutil.which(binary) is None:
            raise OracleUnavailable(
                "GHOTI_ORACLE_MODE=host and %s is not on PATH" % binary)
        return
    if MODE != "container":
        raise OracleUnavailable("GHOTI_ORACLE_MODE=%r is not a mode" % MODE)
    _engine_ok()
    table = pins()
    if name not in table:
        raise OracleUnavailable(
            "no pin for %r in tools/oracle/containers/IMAGES" % name)
    image = table[name][0]
    if _have_image(image):
        return
    if os.environ.get("GHOTI_ORACLE_PULL", "1") != "1":
        raise OracleUnavailable(
            "image for %s is not present and GHOTI_ORACLE_PULL is off: %s"
            % (name, image))
    # Built here. Pulling a localhost tag does not fetch it from a registry,
    # and a miss must say so rather than hang on a pull of a name that was
    # never published.
    if image.startswith("localhost/"):
        raise OracleUnavailable(
            "image for %s is not present. It is built here, not pulled:\n"
            "  make -C <archive> oracle-build\n  %s" % (name, image))
    sys.stderr.write("oracle: pulling %s\n" % image)
    finished = subprocess.run([ENGINE, "pull", image], capture_output=True,
        text=True)
    if finished.returncode != 0:
        raise OracleUnavailable(
            "could not pull the pinned image for %s.\n  %s\n%s"
            % (name, image, finished.stderr.strip()))


ALIAS = dict(
    pair.split("=", 1)
    for pair in os.environ.get("GHOTI_ORACLE_ALIAS", "").split(",")
    if "=" in pair)


def command(name, argv=None, scratch=None):
    """The argv prefix that runs `name`'s reference.

    The repository is bind-mounted at its own path, read-only. `--network none`
    because a reference that can fetch something mid-run is not the pin.
    `scratch`, if given, is mounted read-write under the same path - which the
    corpus generator needs, since generating a fixture means writing one.
    """
    name = ALIAS.get(name, name)
    ensure(name)
    inner = argv if argv is not None else [PROBE.get(name, ([name],))[0][0]]
    if MODE == "host":
        return list(inner)
    image = pins()[name][0]
    argv_out = [ENGINE, "run", "--rm", "-i",
            "--network", "none",
            "--volume", "%s:%s:ro" % (ROOT, ROOT)]
    for path in ([scratch] if isinstance(scratch, str) else (scratch or [])):
        argv_out += ["--volume", "%s:%s:rw" % (path, path)]
    return argv_out + ["--workdir", ROOT, image] + list(inner)


def version(name):
    """What the reference says it is. Runs it; the answer is cached."""
    name = ALIAS.get(name, name)
    key = ("version", name)
    if key in _cache:
        return _cache[key]
    probe, expect = PROBE.get(name, ([name, "--version"], ""))
    finished = subprocess.run(command(name, probe), capture_output=True,
        text=True)
    # stdout only. An engine banner on stderr must not become part of the
    # version, or a later comparison scores the banner as a disagreement.
    text = finished.stdout.strip().splitlines()
    text = text[0] if text else ""
    if finished.returncode != 0:
        raise OracleUnavailable(
            "%s probe exited %s: %r" % (name, finished.returncode, text))
    if expect and expect not in text:
        raise OracleUnavailable(
            "%s answered %r, which does not contain %r" % (name, text, expect))
    _cache[key] = text
    return text


def check_pin(name):
    """Raise unless the reference's version matches containers/IMAGES.

    Both modes. This image is built here, so a digest of the finished image
    does not exist to trust, and relaxing the check in host mode would leave
    nothing checking anything.
    """
    name = ALIAS.get(name, name)
    table = pins()
    if name not in table:
        return version(name)
    said = table[name][1]
    got = version(name)
    if said not in got:
        raise OracleUnavailable(
            "%s: IMAGES says %s and it answers %r" % (name, said, got))
    return got


def provenance(names):
    """One line naming every reference that answered, and how."""
    where = MODE
    parts = []
    for name in names:
        resolved = ALIAS.get(name, name)
        label = resolved if resolved == name else "%s as %s" % (resolved, name)
        parts.append("%s %s" % (label, check_pin(name)))
    return "oracle(%s): %s" % (where, ", ".join(parts))
