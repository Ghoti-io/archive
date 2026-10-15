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
"""Hand the ar, cpio and shar writers' output to the references.

    make check-arcpio-writer

`arcpio_writer_probe write` produces five files and prints the *intent* - the
members as the probe means them - before any reference has seen a byte; every
reading is compared with that and never with another reading.

  - `files.a`, `newc.cpio`, `odc.cpio`: libarchive's bsdtar lists them (type,
    mode, size, link) and extracts each member's bytes; this library reads them
    back from a pipe; and for the cpio pair 7-Zip is asked to test them. 7-Zip
    is not asked about the ar: it does not read the BSD long-name form.
  - `text.shar`: **run by `sh`** in the container, and the tree it makes is
    compared with the intent - names, types, sizes, bytes, modes, link targets.
    There is no second shar reader: running it is the only meaning a shar has.
  - `uu.shar`: no `uudecode` in the image, so the body is decoded here with
    `binascii`, which is an independent implementation of the same encoding.

Neither reference is asked what it cannot say: bsdtar's listing has no CRC
(extraction supplies it) and a time only to the day.
"""

import binascii
import os
import re
import shutil
import stat
import subprocess
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import oracle_env  # noqa: E402

COLUMNS = ["archive", "name", "type", "size", "mtime", "mode", "link", "crc"]
LISTED = ("files.a", "newc.cpio", "odc.cpio")


def unescape(text):
    out = bytearray()
    i = 0
    while i < len(text):
        c = text[i]
        if c == "\\":
            if text[i + 1] == "\\":
                out.append(0x5C)
                i += 2
            else:
                out.append(int(text[i + 2:i + 4], 16))
                i += 4
        else:
            out += c.encode("ascii")
            i += 1
    return bytes(out)


def rows_from(text):
    rows = []
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != len(COLUMNS):
            raise SystemExit("malformed probe row: %r" % line)
        row = dict(zip(COLUMNS, parts))
        row["name"] = unescape(row["name"])
        row["link"] = unescape(row["link"])
        row["archive"] = os.path.basename(row["archive"])
        rows.append(row)
    return rows


def reference(name, argv, scratch):
    command = oracle_env.command(
        name, ["env", "LC_ALL=C.UTF-8"] + argv, scratch=[scratch])
    return subprocess.run(command, capture_output=True,
        stdin=subprocess.DEVNULL)


def perms(letters):
    value = 0
    for i, ch in enumerate(letters):
        if ch not in "-":
            value |= 1 << (8 - i)
    return value


def crc_of(data):
    return "%08x" % (zlib.crc32(data) & 0xFFFFFFFF)


def compare(failures, what, intent, got, skip=()):
    compared = 0
    if len(intent) != len(got):
        failures.append("%s: %d members against %d intended"
            % (what, len(got), len(intent)))
        return 0
    for want, have in zip(intent, got):
        for key in ("name", "type", "size", "mtime", "mode", "link", "crc"):
            if key in skip or key not in have:
                continue
            compared += 1
            if want[key] != have[key]:
                failures.append("%s: %s: %s is %r, intended %r"
                    % (what, want["name"], key, have[key], want[key]))
    return compared


def main(argv):
    if "--probe" not in argv:
        sys.stderr.write("usage: check_arcpio_writer.py --probe <path>\n")
        return 2
    probe = argv[argv.index("--probe") + 1]
    work = os.path.join(ROOT, "build", "arcpio-writer-check")
    if os.path.exists(work):
        shutil.rmtree(work)
    os.makedirs(work)

    print(oracle_env.provenance(["bsdtar", "sevenzip"]), flush=True)
    written = subprocess.run([probe, "write", work], capture_output=True,
        text=True)
    if written.returncode != 0:
        sys.stderr.write(written.stderr)
        return 1
    intent = rows_from(written.stdout)
    members = {}
    for row in intent:
        members.setdefault(row["archive"], []).append(row)
    failures = []
    compared = 0
    for name in LISTED + ("text.shar", "uu.shar"):
        if name not in members:
            failures.append("the probe wrote no %s" % name)

    pattern = re.compile(
        r"^(.)(.{9})\s+\d+\s+\S+\s+\S+\s+(\d+)\s+\w+\s+\d+\s+\S+\s(.*)$")
    for name in LISTED:
        path = os.path.join(work, name)
        want = members.get(name, [])

        # This library, from a pipe.
        ours = subprocess.run([probe, "read", path], capture_output=True,
            text=True)
        if ours.returncode != 0:
            failures.append("%s: our reader: %s" % (name, ours.stderr.strip()))
        else:
            compared += compare(failures, "ours " + name, want,
                rows_from(ours.stdout))

        listed = reference("bsdtar", ["bsdtar", "-tvf", path], work)
        if listed.returncode != 0 or listed.stderr.strip():
            failures.append("%s: bsdtar -tvf exited %d: %s" % (name,
                listed.returncode,
                listed.stderr.decode("utf-8", "replace").strip()))
            continue
        got = []
        for line in listed.stdout.decode("utf-8").splitlines():
            match = pattern.match(line)
            if not match:
                failures.append("%s: unparseable bsdtar line %r" % (name, line))
                continue
            kind, mode, size, label = match.groups()
            link = b""
            if kind == "l":
                label, link_text = label.split(" -> ", 1)
                link = link_text.encode("utf-8")
            label = label.rstrip("/")
            entry = {
                "name": label.encode("utf-8"),
                "type": {"d": "directory", "l": "symlink",
                    "p": "fifo"}.get(kind, "file"),
                "size": size if kind != "l" else str(len(link)),
                "mode": "%04o" % perms(mode),
                "link": link,
            }
            if kind == "-":
                extracted = reference("bsdtar",
                    ["bsdtar", "-xOf", path, "--", label], work)
                entry["crc"] = crc_of(extracted.stdout)
            elif kind == "l":
                entry["crc"] = crc_of(link)
            else:
                entry["crc"] = "00000000"
            got.append(entry)
        compared += compare(failures, "bsdtar " + name, want, got,
            skip=("mtime",))

        if name.endswith(".cpio"):
            tested = reference("sevenzip", ["7z", "t", "-bso0", "-bsp0", path],
                work)
            if tested.returncode != 0:
                failures.append("%s: 7z t exited %d: %s" % (name,
                    tested.returncode,
                    tested.stderr.decode("utf-8", "replace").strip()))

    # The shell script, run.
    extract = os.path.join(work, "extract")
    os.makedirs(extract)
    ran = reference("bsdtar", ["sh", "-c",
        "cd '%s' && sh ../text.shar" % extract], work)
    if ran.returncode != 0:
        failures.append("running text.shar exited %d: %s" % (ran.returncode,
            ran.stderr.decode("utf-8", "replace").strip()))
    want = {row["name"]: row for row in members.get("text.shar", [])}
    seen = {}
    for here, directories, files in os.walk(extract):
        for entry in directories + files:
            full = os.path.join(here, entry)
            rel = os.path.relpath(full, extract).encode("utf-8")
            info = os.lstat(full)
            if stat.S_ISLNK(info.st_mode):
                target = os.readlink(full).encode("utf-8")
                seen[rel] = ("symlink", str(len(target)), None, target,
                    crc_of(target))
            elif stat.S_ISDIR(info.st_mode):
                seen[rel] = ("directory", "0", "%04o" % stat.S_IMODE(info.st_mode),
                    b"", "00000000")
            else:
                data = open(full, "rb").read()
                seen[rel] = ("file", str(len(data)),
                    "%04o" % stat.S_IMODE(info.st_mode), b"", crc_of(data))
    if set(seen) != set(want):
        failures.append("text.shar made %s, intended %s"
            % (sorted(seen), sorted(want)))
    for rel, row in want.items():
        got = seen.get(rel)
        if not got:
            continue
        for label, have, intended in (("type", got[0], row["type"]),
                ("size", got[1], row["size"]), ("link", got[3], row["link"]),
                ("crc", got[4], row["crc"])):
            compared += 1
            if have != intended:
                failures.append("text.shar: %s: %s is %r, intended %r"
                    % (rel, label, have, intended))
        if got[2] is not None:
            compared += 1
            if got[2] != row["mode"]:
                failures.append("text.shar: %s: mode is %s, intended %s"
                    % (rel, got[2], row["mode"]))

    # The uuencoded script, decoded here.
    body = open(os.path.join(work, "uu.shar"), "rb").read().decode("latin-1")
    decoded = {}
    for match in re.finditer(
            r"uudecode << 'SHAR_END'\nbegin (\d+) (.*?)\n(.*?)\nend\nSHAR_END\n",
            body, re.S):
        mode, name, lines = match.groups()
        data = b"".join(binascii.a2b_uu(line.encode("latin-1"))
            for line in lines.split("\n") if line != "`")
        decoded[name.encode("latin-1")] = (mode, data)
    wanted = {row["name"]: row for row in members.get("uu.shar", [])}
    if set(decoded) != set(wanted):
        failures.append("uu.shar decodes to %s, intended %s"
            % (sorted(decoded), sorted(wanted)))
    for name, row in wanted.items():
        if name not in decoded:
            continue
        mode, data = decoded[name]
        for label, have, intended in (("size", str(len(data)), row["size"]),
                ("crc", crc_of(data), row["crc"]), ("mode", "0" + mode,
                row["mode"])):
            compared += 1
            if have != intended:
                failures.append("uu.shar: %s: %s is %r, intended %r"
                    % (name, label, have, intended))

    if failures:
        sys.stderr.write("### check-arcpio-writer: the references disagree "
            "with the writers ###\n")
        for line in failures:
            sys.stderr.write("  " + line + "\n")
        return 1
    print("check-arcpio-writer: files.a, newc.cpio and odc.cpio listed and "
        "extracted by libarchive (the cpio pair also tested by 7-Zip), "
        "text.shar run by sh, uu.shar decoded; %d fields compared against "
        "the intent" % compared)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
