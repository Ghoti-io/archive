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
"""Hand the 7z writer's archives to the references, and compare what they say.

    make check-sevenz-writer

The writer is the subject and there is no fixture: `sevenz_writer_probe write`
produces six archives of one member list - LZMA2 solid and non-solid, LZMA,
bzip2, deflate and copy - and prints the *intent*, the member list as the probe
means it, before any reference has seen a byte. Every reading is compared with
that intent and never with another reading, because two readers wrong the same
way would agree.

Two references read 7z in the pinned image: 7-Zip, which tests every CRC and
whose long listing gives type, mode, size, CRC and time; and libarchive's
bsdtar, whose listing gives type, mode, size and link target and whose
extraction gives the bytes. This library's own reader is the third reading, in
the same shape.

**Neither reference is asked about what it cannot say.** 7-Zip's listing has no
link target (a symlink's target is its data, so its CRC covers it); bsdtar's
has no CRC and a time only to the day. Those columns are not compared against
that reference, and the gate says so.
"""

import calendar
import os
import re
import subprocess
import sys
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
import oracle_env  # noqa: E402

# libarchive's 7z reader has no deflate64 coder; only 7-Zip is asked about it.
DEFLATE64_ARCHIVE = "deflate64.7z"
EXPECTED_ARCHIVES = 7
EXPECTED_MEMBERS = 13
COLUMNS = ["archive", "name", "type", "size", "mtime", "mode", "link", "crc"]


def unescape(text):
    """The inverse of the probe's print_escaped, to bytes."""
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
        if ch != "-":
            value |= 1 << (8 - i)
    return value


def sevenzip_listing(stdout):
    """Entries from `7z l -slt`, after the archive's own block."""
    blocks = stdout.decode("utf-8").split("\n\n")
    entries = []
    for block in blocks:
        fields = {}
        for line in block.splitlines():
            if " = " in line:
                key, value = line.split(" = ", 1)
                fields[key] = value
        if "Path" in fields and "Attributes" in fields:
            entries.append(fields)
    return entries


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
        sys.stderr.write("usage: check_sevenz_writer.py --probe <path>\n")
        return 2
    probe = argv[argv.index("--probe") + 1]
    work = os.path.join(ROOT, "build", "sevenz-writer-check")
    if os.path.exists(work):
        import shutil
        shutil.rmtree(work)
    os.makedirs(work)

    print(oracle_env.provenance(["sevenzip", "bsdtar"]), flush=True)
    written = subprocess.run([probe, "write", work], capture_output=True,
        text=True)
    if written.returncode != 0:
        sys.stderr.write(written.stderr)
        return 1
    intent = rows_from(written.stdout)
    archives = sorted(n for n in os.listdir(work) if n.endswith(".7z"))
    members = {}
    for row in intent:
        members.setdefault(row["archive"], []).append(row)
    failures = []
    if len(archives) != EXPECTED_ARCHIVES or any(
            len(v) != EXPECTED_MEMBERS for v in members.values()):
        failures.append("the probe wrote %d archives (%s), expected %d of %d "
            "members" % (len(archives), sorted(members), EXPECTED_ARCHIVES,
                EXPECTED_MEMBERS))
    compared = 0

    for name in archives:
        path = os.path.join(work, name)
        want = members.get(name, [])

        # This library, reading what it wrote.
        ours = subprocess.run([probe, "read", path], capture_output=True,
            text=True)
        if ours.returncode != 0:
            failures.append("%s: our reader: %s" % (name, ours.stderr.strip()))
        else:
            got = rows_from(ours.stdout)
            compared += compare(failures, "ours " + name, want, got)

        # 7-Zip: every CRC, then the long listing.
        tested = reference("sevenzip", ["7z", "t", "-bso0", "-bsp0", path], work)
        if tested.returncode != 0 or tested.stderr.strip():
            failures.append("%s: 7z t exited %d: %s" % (name, tested.returncode,
                tested.stderr.decode("utf-8", "replace").strip()))
        listed = reference("sevenzip", ["7z", "l", "-slt", path], work)
        if listed.returncode != 0:
            failures.append("%s: 7z l exited %d" % (name, listed.returncode))
        else:
            got = []
            for fields in sevenzip_listing(listed.stdout):
                attr = fields["Attributes"].split(" ", 1)[1]
                kind = {"d": "directory", "l": "symlink"}.get(attr[0], "file")
                mtime = calendar.timegm(
                    __import__("time").strptime(
                        fields["Modified"].split(".")[0], "%Y-%m-%d %H:%M:%S"))
                got.append({
                    "name": fields["Path"].encode("utf-8"),
                    "type": kind,
                    "size": fields["Size"],
                    "mtime": str(mtime),
                    "mode": "%04o" % perms(attr[1:]),
                    "crc": (fields["CRC"] or "").lower().rjust(8, "0")
                        if fields["CRC"] else "00000000",
                })
            # 7-Zip prints no link column; a directory and an empty file have
            # no CRC, which the intent spells as zero.
            compared += compare(failures, "7-Zip " + name, want, got,
                skip=("link",))

        # libarchive has no deflate64 coder, so it is not asked about that
        # archive: 7-Zip is the one reference there, as it is for the corpus.
        if name == DEFLATE64_ARCHIVE:
            continue

        # libarchive: structure from the listing, bytes from extraction.
        listed = reference("bsdtar", ["bsdtar", "-tvf", path], work)
        if listed.returncode != 0 or listed.stderr.strip():
            failures.append("%s: bsdtar -tvf exited %d: %s" % (name,
                listed.returncode,
                listed.stderr.decode("utf-8", "replace").strip()))
            continue
        got = []
        pattern = re.compile(
            r"^(.)(.{9})\s+\d+\s+\S+\s+\S+\s+(\d+)\s+\w+\s+\d+\s+\S+\s(.*)$")
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
                "type": {"d": "directory", "l": "symlink"}.get(kind, "file"),
                "size": size if kind != "l" else str(len(link)),
                "mode": "%04o" % perms(mode),
                "link": link,
            }
            if kind == "-":
                extracted = reference("bsdtar",
                    ["bsdtar", "-xOf", path, "--", label], work)
                entry["crc"] = "%08x" % (zlib.crc32(extracted.stdout)
                    & 0xFFFFFFFF)
            elif kind == "l":
                entry["crc"] = "%08x" % (zlib.crc32(link) & 0xFFFFFFFF)
            else:
                entry["crc"] = "00000000"
            got.append(entry)
        compared += compare(failures, "bsdtar " + name, want, got,
            skip=("mtime",))

    if failures:
        sys.stderr.write("### check-sevenz-writer: the references disagree "
            "with the writer ###\n")
        for line in failures:
            sys.stderr.write("  " + line + "\n")
        return 1
    print("check-sevenz-writer: %d archives, %d members each, all accepted "
        "by 7-Zip and all but %s by libarchive; %d fields compared against "
        "the intent" % (len(archives), EXPECTED_MEMBERS, DEFLATE64_ARCHIVE,
            compared))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
