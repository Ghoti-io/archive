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
produces ten archives of one member list - LZMA2 solid and non-solid, LZMA,
bzip2, deflate, deflate64 and copy, then three encrypted with 7-Zip's AES
(LZMA2, LZMA2 with the header encrypted too, and copy non-solid) - and prints
the *intent*, the member list as the probe
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
# The probe's encrypted archives and their password (PROBE_PASSWORD there).
# libarchive reads no encrypted 7z, so 7-Zip is the one reference for them, and
# it is asked three more things: that the right password tests clean, that a
# wrong one does not, and - for aes-header.7z - that without one the archive
# cannot even be listed, which is what an encrypted header is for.
ENCRYPTED = {"aes.7z": False, "aes-header.7z": True,
    "aes-copy-nonsolid.7z": False}
PASSWORD = "probe-p\u00e4ss-\U0001F600"
EXPECTED_ARCHIVES = 10
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
    # The self-extractor and the append are about the container, not the
    # cipher, and 7-Zip would stop to ask for a password: unencrypted only.
    plain = [n for n in archives if n not in ENCRYPTED]
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
        secret = ["-p" + PASSWORD] if name in ENCRYPTED else []
        tested = reference("sevenzip",
            ["7z", "t", "-bso0", "-bsp0"] + secret + [path], work)
        if tested.returncode != 0 or tested.stderr.strip():
            failures.append("%s: 7z t exited %d: %s" % (name, tested.returncode,
                tested.stderr.decode("utf-8", "replace").strip()))
        if name in ENCRYPTED:
            wrong = reference("sevenzip",
                ["7z", "t", "-bso0", "-bsp0", "-pnot-the-password", path], work)
            if wrong.returncode == 0:
                failures.append("%s: 7z t passed with the wrong password"
                    % name)
            # No -p at all: stdin is /dev/null, so a 7-Zip that needs a
            # password asks for one, reads nothing, and fails - and one that
            # does not need it lists.
            bare = reference("sevenzip", ["7z", "l", "-slt", path], work)
            if ENCRYPTED[name] and bare.returncode == 0:
                failures.append("%s: 7z listed an encrypted header without "
                    "the password" % name)
            if not ENCRYPTED[name] and (bare.returncode != 0
                    or b"Encrypted = +" not in bare.stdout):
                failures.append("%s: 7z did not list a plain header, or did "
                    "not call its data encrypted" % name)
        listed = reference("sevenzip", ["7z", "l", "-slt"] + secret + [path],
            work)
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
        if name == DEFLATE64_ARCHIVE or name in ENCRYPTED:
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

    # A real self-extractor: 7-Zip's console module for Linux, from the pinned
    # image, with the first archive behind it - which is what `7z a -sfx`
    # writes. Both 7-Zip and this reader must find the archive behind the
    # stub and read it as the intent says.
    sfx_checked = 0
    if plain:
        source = os.path.join(work, plain[0])
        sfx = os.path.join(work, "self-extracting.exe")
        made = reference("sevenzip", ["sh", "-c",
            'cat /usr/lib/7zip/7zCon.sfx "$0" > "$1"', source, sfx], work)
        if made.returncode != 0 or not os.path.exists(sfx):
            failures.append("could not make a self-extractor from %s: %s"
                % (plain[0], made.stderr.decode("utf-8", "replace").strip()))
        else:
            want = members.get(plain[0], [])
            ours = subprocess.run([probe, "read", sfx], capture_output=True,
                text=True)
            if ours.returncode != 0:
                failures.append("self-extractor: our reader: %s"
                    % ours.stderr.strip())
            else:
                got = [dict(row, archive=plain[0])
                    for row in rows_from(ours.stdout)]
                sfx_checked += compare(failures, "ours self-extractor", want, got)
            tested = reference("sevenzip",
                ["7z", "t", "-bso0", "-bsp0", sfx], work)
            if tested.returncode != 0:
                failures.append("self-extractor: 7z t exited %d: %s"
                    % (tested.returncode,
                        tested.stderr.decode("utf-8", "replace").strip()))

    # Appended to where it lies: three of the archives above, and one 7-Zip
    # writes with a BCJ2 folder - four packed streams - and an encoded
    # header, which this library can carry into a new header and not decode.
    # 7-Zip tests each, and its listing must be the old one's members as they
    # were and the appended one after them.
    appended = 0
    made = reference("sevenzip", ["sh", "-c",
        'mkdir -p "$0/ref-src" && cd "$0/ref-src" '
        '&& printf "plain text\\n" > a.txt '
        '&& head -c 40000 /usr/lib/7zip/7zCon.sfx > code.bin '
        '&& cd .. && 7z a -bso0 -bsp0 -mf=BCJ2 -mhc=on ref-bcj2.7z ./ref-src/*',
        work], work)
    if made.returncode != 0:
        failures.append("7-Zip could not write the BCJ2 archive: %s"
            % made.stderr.decode("utf-8", "replace").strip())
    for name in ["lzma2.7z", "lzma2-nonsolid.7z", "bzip2.7z", "ref-bcj2.7z"]:
        source = os.path.join(work, name)
        if not os.path.exists(source):
            failures.append("append: %s was not written" % name)
            continue
        target = os.path.join(work, "appended-" + name)
        with open(source, "rb") as fin, open(target, "wb") as fout:
            fout.write(fin.read())
        before = reference("sevenzip", ["7z", "l", "-slt", target], work)
        added = subprocess.run([probe, "append", target], capture_output=True,
            text=True)
        if added.returncode != 0:
            failures.append("append %s: %s" % (name, added.stderr.strip()))
            continue
        tested = reference("sevenzip", ["7z", "t", "-bso0", "-bsp0", target], work)
        if tested.returncode != 0 or tested.stderr.strip():
            failures.append("appended %s: 7z t exited %d: %s" % (name,
                tested.returncode,
                tested.stderr.decode("utf-8", "replace").strip()))
            continue
        after = reference("sevenzip", ["7z", "l", "-slt", target], work)
        keys = ("Path", "Size", "CRC", "Attributes", "Modified")
        old = [tuple(f.get(k) for k in keys) for f in
            sevenzip_listing(before.stdout)]
        new = [tuple(f.get(k) for k in keys) for f in
            sevenzip_listing(after.stdout)]
        row = rows_from(added.stdout)[0]
        if new[:-1] != old or not new or new[-1][0] != row["name"].decode("utf-8") \
                or new[-1][1] != row["size"] \
                or (new[-1][2] or "").lower().rjust(8, "0") != row["crc"]:
            failures.append("appended %s: 7-Zip lists\n      %s\n    after\n"
                "      %s" % (name, "\n      ".join(map(str, new)),
                    "\n      ".join(map(str, old))))
            continue
        appended += 1

    if failures:
        sys.stderr.write("### check-sevenz-writer: the references disagree "
            "with the writer ###\n")
        for line in failures:
            sys.stderr.write("  " + line + "\n")
        return 1
    if not sfx_checked:
        sys.stderr.write("### check-sevenz-writer: the self-extractor step "
            "compared nothing ###\n")
        return 1
    if appended != 4:
        sys.stderr.write("### check-sevenz-writer: %d of 4 in-place appends "
            "were checked ###\n" % appended)
        return 1
    print("check-sevenz-writer: %d archives, %d members each, all accepted "
        "by 7-Zip and all but %s and the %d encrypted by libarchive; the "
        "encrypted ones refused by 7-Zip under a wrong password, and the one "
        "with an encrypted header unlisted without one; %d fields compared "
        "against the intent, and %d more from %s behind 7-Zip's 7zCon.sfx; "
        "%d appended in place, one of them 7-Zip's own with BCJ2 and an "
        "encoded header, each tested and listed by 7-Zip"
        % (len(archives), EXPECTED_MEMBERS, DEFLATE64_ARCHIVE, len(ENCRYPTED),
            compared, sfx_checked, plain[0], appended))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
