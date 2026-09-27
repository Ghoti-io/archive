/*
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * Copyright (C) 2026 Corey Pennycuff
 *
 * This file is part of Ghoti.io Archive.
 *
 * Ghoti.io Archive is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * Ghoti.io Archive is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file
 *
 * The library half of `make check-writer`: write archives, and read them back.
 *
 * Not an example and not a test. The gate it serves needs three things that
 * neither can give it:
 *
 * **The bytes have to leave the process.** `tests/unit/test_writer.cpp` asserts
 * against the buffer the writer filled, which proves the writer agrees with this
 * library's idea of tar. Whether GNU tar, bsdtar and Python's `tarfile` agree is
 * a question only those programs can answer, and they need a file.
 *
 * **What went in has to be stated separately from what came out.** The member
 * table below is the *intent*, printed in `write` mode before any reference has
 * seen the archive. Every later reading - theirs and ours - is compared against
 * it. A gate that compared our reading against their reading would pass
 * whenever both were wrong in the same way, which is exactly what a shared
 * misunderstanding of a format looks like.
 *
 * **The same rows have to come back after a round trip.** `read` mode prints
 * this library's reading of any archive in the same shape, so the gate can point
 * it at what a reference re-wrote.
 *
 * Usage:
 *   writer_probe write <directory>   write the archives, print the intent rows
 *   writer_probe read <path.tar>     print this library's reading of one archive
 *
 * Both print tab-separated rows with a fifteen-column shape that
 * `tools/oracle/check_writer.py` also builds the references' answers in:
 *
 *   archive index name type size mtime mtime_ns mode uid gid uname gname
 *   linkname devmajor devminor
 *
 * The byte-string columns are escaped the way `make_corpus.py`'s `escape()`
 * escapes them. That is the same rule written twice in two languages, which is
 * worth saying plainly: the protection is not care, it is that the corpus below
 * contains a backslash, a byte above 0x7F and a byte that is not valid UTF-8, so
 * every branch of both spellings runs on every invocation of the gate. A drift
 * between them fails the comparison rather than hiding inside it.
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ghoti.io/archive/archive.h>

/** A member to write, and therefore also a row of expectations. */
typedef struct {
  const char * name;
  size_t name_length; ///< 0 means strlen(name).
  GARC_Member_Type type;
  const char * link_target;
  uint64_t size;
  char fill;                 ///< The byte the member's data is made of.
  int64_t mtime_seconds;
  uint32_t mtime_nanoseconds;
  GARC_Time_Source mtime_source;
  uint32_t mode;
  int mode_valid;
  int64_t uid;
  int64_t gid;
  int ids_valid;
  const char * uname;
  const char * gname;
  uint32_t device_major;
  uint32_t device_minor;
  int device_valid;
} Spec;

/** One archive to write, and what it is for. */
typedef struct {
  const char * file;
  GARC_Tar_Variant variant;
  uint32_t blocking_factor;
  const Spec * members;
  size_t count;
  const char * purpose;
} Archive;

// A time the octal field holds, so that the fixtures which are not about time
// all say the same thing and a difference in them is about something else.
#define WHEN 1000000000

// 120 bytes, a slash, then 90: a name over 100 bytes that the ustar prefix and
// name fields hold between them exactly, so no extended record is needed and a
// 1988 reader gets the whole name. The one below it is one byte longer in the
// tail, which no split can place.
#define A120 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
             "aaaaaaaaaaaaaaaaaaaa"
#define B90  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" \
             "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define C101 "cccccccccccccccccccccccccccccccccccccccccccccccccc" \
             "cccccccccccccccccccccccccccccccccccccccccccccccccc" "c"

static const Spec basic[] = {
  {"hello.txt", 0, GARC_MEMBER_FILE, NULL, 12, 'h',
      WHEN, 0, GARC_TIME_TAR_OCTAL, 0644, 1, 1000, 1000, 1,
      NULL, NULL, 0, 0, 0},
  {"empty.txt", 0, GARC_MEMBER_FILE, NULL, 0, 0,
      WHEN, 0, GARC_TIME_TAR_OCTAL, 0644, 1, 1000, 1000, 1,
      NULL, NULL, 0, 0, 0},
  // The trailing slash is the caller's, and the typeflag is what says this is a
  // directory either way. Both references print the slash; tarfile strips it,
  // which is why names are asked of the other two.
  {"notes/", 0, GARC_MEMBER_DIRECTORY, NULL, 0, 0,
      WHEN, 0, GARC_TIME_TAR_OCTAL, 0755, 1, 1000, 1000, 1,
      NULL, NULL, 0, 0, 0},
  {"notes/link", 0, GARC_MEMBER_SYMLINK, "../hello.txt", 0, 0,
      WHEN, 0, GARC_TIME_TAR_OCTAL, 0777, 1, 1000, 1000, 1,
      NULL, NULL, 0, 0, 0},
  // The target is a member written above it, so an extracting reference has
  // something to link to and the fixture is not about a dangling link.
  {"notes/hard", 0, GARC_MEMBER_HARDLINK, "hello.txt", 0, 0,
      WHEN, 0, GARC_TIME_TAR_OCTAL, 0644, 1, 1000, 1000, 1,
      NULL, NULL, 0, 0, 0},
};

// Either side of the 512-byte padding boundary in both directions, because the
// padding a member owes is the one arithmetic in the writer that a reader only
// notices when the *next* header lands in the wrong place.
static const Spec sizes[] = {
  {"s0", 0, GARC_MEMBER_FILE, NULL, 0, 'x',
      WHEN, 0, GARC_TIME_TAR_OCTAL, 0644, 1, 0, 0, 1, NULL, NULL, 0, 0, 0},
  {"s1", 0, GARC_MEMBER_FILE, NULL, 1, 'x',
      WHEN, 0, GARC_TIME_TAR_OCTAL, 0644, 1, 0, 0, 1, NULL, NULL, 0, 0, 0},
  {"s511", 0, GARC_MEMBER_FILE, NULL, 511, 'x',
      WHEN, 0, GARC_TIME_TAR_OCTAL, 0644, 1, 0, 0, 1, NULL, NULL, 0, 0, 0},
  {"s512", 0, GARC_MEMBER_FILE, NULL, 512, 'x',
      WHEN, 0, GARC_TIME_TAR_OCTAL, 0644, 1, 0, 0, 1, NULL, NULL, 0, 0, 0},
  {"s513", 0, GARC_MEMBER_FILE, NULL, 513, 'x',
      WHEN, 0, GARC_TIME_TAR_OCTAL, 0644, 1, 0, 0, 1, NULL, NULL, 0, 0, 0},
  {"s1023", 0, GARC_MEMBER_FILE, NULL, 1023, 'x',
      WHEN, 0, GARC_TIME_TAR_OCTAL, 0644, 1, 0, 0, 1, NULL, NULL, 0, 0, 0},
  {"s1024", 0, GARC_MEMBER_FILE, NULL, 1024, 'x',
      WHEN, 0, GARC_TIME_TAR_OCTAL, 0644, 1, 0, 0, 1, NULL, NULL, 0, 0, 0},
};

static const Spec names[] = {
  // Splits exactly: prefix 120, name 90. A ustar-only reader sees all of it.
  {A120 "/" B90, 0, GARC_MEMBER_FILE, NULL, 3, 'p',
      WHEN, 0, GARC_TIME_TAR_OCTAL, 0644, 1, 0, 0, 1, NULL, NULL, 0, 0, 0},
  // 101 bytes with no slash at all, so the only way to carry it is a record.
  {C101, 0, GARC_MEMBER_FILE, NULL, 3, 'q',
      WHEN, 0, GARC_TIME_TAR_OCTAL, 0644, 1, 0, 0, 1, NULL, NULL, 0, 0, 0},
  // A link target over the 100-byte field, which needs a linkpath record.
  {"long-link", 0, GARC_MEMBER_SYMLINK, A120 "/" B90, 0, 0,
      WHEN, 0, GARC_TIME_TAR_OCTAL, 0777, 1, 0, 0, 1, NULL, NULL, 0, 0, 0},
  // A backslash and a space, which is what makes the escaping on both sides of
  // this gate run rather than merely exist.
  {"odd \\ name.txt", 0, GARC_MEMBER_FILE, NULL, 2, 'z',
      WHEN, 0, GARC_TIME_TAR_OCTAL, 0644, 1, 0, 0, 1, NULL, NULL, 0, 0, 0},
  // The two bounds of the ustar split, at the byte. 155 and 100 are the prefix
  // and name fields' exact capacities, so this is the longest name a 1988 reader
  // can be given whole; one byte more in either half has no split and must go
  // into a record instead. A bound that is loose by one writes 156 bytes into the
  // 155-byte field and truncates the name silently, which is a wrong path rather
  // than a refused one - and until these three existed, nothing here could tell
  // the difference.
  {"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
      "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
      "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
      "eeeee" "/" "ffffffffffffffffffffffffffffffffffffffffffffffffff"
      "ffffffffffffffffffffffffffffffffffffffffffffffffff", 0, GARC_MEMBER_FILE, NULL, 3, 'e',
      WHEN, 0, GARC_TIME_TAR_OCTAL, 0644, 1, 0, 0, 1, NULL, NULL, 0, 0, 0},
  {"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
      "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
      "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
      "eeeeee" "/" "ffffffffff", 0, GARC_MEMBER_FILE, NULL, 3, 'E',
      WHEN, 0, GARC_TIME_TAR_OCTAL, 0644, 1, 0, 0, 1, NULL, NULL, 0, 0, 0},
  {"gggggggggg/" "hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh"
      "hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh"
      "h", 0, GARC_MEMBER_FILE, NULL, 3, 'g',
      WHEN, 0, GARC_TIME_TAR_OCTAL, 0644, 1, 0, 0, 1, NULL, NULL, 0, 0, 0},
};

static const Spec charsets[] = {
  // Valid UTF-8 and short enough for the name field: no record, so the bytes go
  // out raw and nothing declares an encoding.
  {"na\xC3\xAFve.txt", 0, GARC_MEMBER_FILE, NULL, 4, 'u',
      WHEN, 0, GARC_TIME_TAR_OCTAL, 0644, 1, 0, 0, 1, NULL, NULL, 0, 0, 0},
  // 0xFF is not valid UTF-8, and the name is too long for the field, so a record
  // has to carry it - which is the case that forces hdrcharset=BINARY.
  {C101 "\xFF", 0, GARC_MEMBER_FILE, NULL, 4, 'v',
      WHEN, 0, GARC_TIME_TAR_OCTAL, 0644, 1, 0, 0, 1, NULL, NULL, 0, 0, 0},
};

static const Spec owners[] = {
  {"named.txt", 0, GARC_MEMBER_FILE, NULL, 5, 'n',
      WHEN, 0, GARC_TIME_TAR_OCTAL, 0644, 1, 1234, 5678, 1,
      "ghoti", "ghotigroup", 0, 0, 0},
  // 2097152 is one past the largest value seven octal digits hold, so the field
  // goes base-256 and a record carries the decimal - both saying the same
  // number, which is the writer's rule for every field that overflows.
  {"bigid.txt", 0, GARC_MEMBER_FILE, NULL, 5, 'N',
      WHEN, 0, GARC_TIME_TAR_OCTAL, 0644, 1, 2097152, 4194304, 1,
      "ghoti", "ghotigroup", 0, 0, 0},
  // No ids and no mode, and the fields are deliberately *not* zero underneath:
  // the writer must write zeros because the valid flags are clear, so a writer
  // that read the field and ignored the flag produces 0755 and 4242 here. With
  // zeros in the struct the two behaviours are the same bytes, and a mutation
  // dropping the flag survived the whole gate - a flag has to be given a value it
  // can disagree with before a test can see it at all.
  {"noids.txt", 0, GARC_MEMBER_FILE, NULL, 5, 'o',
      WHEN, 0, GARC_TIME_TAR_OCTAL, 0755, 0, 4242, 4343, 0, NULL, NULL,
      7, 9, 0},
};

static const Spec modes[] = {
  {"m0000", 0, GARC_MEMBER_FILE, NULL, 1, 'm',
      WHEN, 0, GARC_TIME_TAR_OCTAL, 00000, 1, 0, 0, 1, NULL, NULL, 0, 0, 0},
  {"m0600", 0, GARC_MEMBER_FILE, NULL, 1, 'm',
      WHEN, 0, GARC_TIME_TAR_OCTAL, 00600, 1, 0, 0, 1, NULL, NULL, 0, 0, 0},
  {"m0755", 0, GARC_MEMBER_FILE, NULL, 1, 'm',
      WHEN, 0, GARC_TIME_TAR_OCTAL, 00755, 1, 0, 0, 1, NULL, NULL, 0, 0, 0},
  {"m4755", 0, GARC_MEMBER_FILE, NULL, 1, 'm',
      WHEN, 0, GARC_TIME_TAR_OCTAL, 04755, 1, 0, 0, 1, NULL, NULL, 0, 0, 0},
  {"m2755", 0, GARC_MEMBER_FILE, NULL, 1, 'm',
      WHEN, 0, GARC_TIME_TAR_OCTAL, 02755, 1, 0, 0, 1, NULL, NULL, 0, 0, 0},
  {"m1777", 0, GARC_MEMBER_DIRECTORY, NULL, 0, 0,
      WHEN, 0, GARC_TIME_TAR_OCTAL, 01777, 1, 0, 0, 1, NULL, NULL, 0, 0, 0},
};

static const Spec times[] = {
  {"octal", 0, GARC_MEMBER_FILE, NULL, 1, 't',
      WHEN, 0, GARC_TIME_TAR_OCTAL, 0644, 1, 0, 0, 1, NULL, NULL, 0, 0, 0},
  // Asked for as a record even though the seconds fit the field, which is what
  // keeps a member read out of a pax archive saying a record answered for it.
  {"forced-record", 0, GARC_MEMBER_FILE, NULL, 1, 't',
      WHEN, 0, GARC_TIME_PAX_DECIMAL, 0644, 1, 0, 0, 1, NULL, NULL, 0, 0, 0},
  {"fraction", 0, GARC_MEMBER_FILE, NULL, 1, 't',
      WHEN, 123456789, GARC_TIME_PAX_DECIMAL, 0644, 1, 0, 0, 1,
      NULL, NULL, 0, 0, 0},
  // A fraction with leading zeros, which is the only shape that tests the
  // *width* of the printed fraction. 123456789 ns prints the same under `%09llu`
  // and `%06llu`, because a printf width is a minimum and not a truncation - so
  // with only that member here, a mutation from nine digits to six changed
  // nothing and the gate was right to say so.
  {"fraction-leading-zeros", 0, GARC_MEMBER_FILE, NULL, 1, 't',
      WHEN, 123456, GARC_TIME_PAX_DECIMAL, 0644, 1, 0, 0, 1,
      NULL, NULL, 0, 0, 0},
  // Negative, which the octal field cannot hold at all.
  {"before-epoch", 0, GARC_MEMBER_FILE, NULL, 1, 't',
      -1, 0, GARC_TIME_PAX_DECIMAL, 0644, 1, 0, 0, 1, NULL, NULL, 0, 0, 0},
  // Negative with a fraction, where the two halves have to agree about which way
  // the rounding went: seconds floor, nanoseconds non-negative. -2 s + 250000000
  // ns is -1.75 s, and 250000000 is chosen over the obvious 500000000 because a
  // negative fraction is written by counting *downwards* from a second -
  // 1000000000 minus the nanoseconds - and 500000000 is that transform's fixed
  // point. With a half-second here the fixture agreed with a writer that had the
  // subtraction backwards.
  {"before-epoch-fraction", 0, GARC_MEMBER_FILE, NULL, 1, 't',
      -2, 250000000, GARC_TIME_PAX_DECIMAL, 0644, 1, 0, 0, 1,
      NULL, NULL, 0, 0, 0},
  // One past 8589934591, the largest the eleven-digit octal field holds.
  {"after-octal", 0, GARC_MEMBER_FILE, NULL, 1, 't',
      8589934592, 0, GARC_TIME_PAX_DECIMAL, 0644, 1, 0, 0, 1,
      NULL, NULL, 0, 0, 0},
  // No time at all. The writer puts zero in the field, and the row says zero.
  {"no-time", 0, GARC_MEMBER_FILE, NULL, 1, 't',
      0, 0, GARC_TIME_NONE, 0644, 1, 0, 0, 1, NULL, NULL, 0, 0, 0},
};

// A member's extended records are padded out to a 512-byte boundary, and the
// boundary case is a record block that is *already* a multiple of 512 - where the
// padding owed is zero and a writer computing it without the outer modulo adds a
// whole spurious block. Nothing else in this corpus lands there: the records
// happen to be some other length in every one of them, and a mutation that
// dropped that modulo survived the whole gate until these three existed.
//
// One `path=` record is the whole record set for these, since every other field
// fits its header field. The record is `<total> path=<name>\n`, whose total
// counts its own digits, so a 502-byte name makes it exactly 512: 3 digits, a
// space, `path=`, the name, a newline.
static const Spec records[] = {
  {"dddddddddddddddddddddddddddddddddddddddddddddddddd"
      "dddddddddddddddddddddddddddddddddddddddddddddddddd"
      "dddddddddddddddddddddddddddddddddddddddddddddddddd"
      "dddddddddddddddddddddddddddddddddddddddddddddddddd"
      "dddddddddddddddddddddddddddddddddddddddddddddddddd"
      "dddddddddddddddddddddddddddddddddddddddddddddddddd"
      "dddddddddddddddddddddddddddddddddddddddddddddddddd"
      "dddddddddddddddddddddddddddddddddddddddddddddddddd"
      "dddddddddddddddddddddddddddddddddddddddddddddddddd"
      "dddddddddddddddddddddddddddddddddddddddddddddddddd"
      "d", 501, GARC_MEMBER_FILE, NULL, 1, 'r',
      WHEN, 0, GARC_TIME_TAR_OCTAL, 0644, 1, 0, 0, 1, NULL, NULL, 0, 0, 0},
  {"dddddddddddddddddddddddddddddddddddddddddddddddddd"
      "dddddddddddddddddddddddddddddddddddddddddddddddddd"
      "dddddddddddddddddddddddddddddddddddddddddddddddddd"
      "dddddddddddddddddddddddddddddddddddddddddddddddddd"
      "dddddddddddddddddddddddddddddddddddddddddddddddddd"
      "dddddddddddddddddddddddddddddddddddddddddddddddddd"
      "dddddddddddddddddddddddddddddddddddddddddddddddddd"
      "dddddddddddddddddddddddddddddddddddddddddddddddddd"
      "dddddddddddddddddddddddddddddddddddddddddddddddddd"
      "dddddddddddddddddddddddddddddddddddddddddddddddddd"
      "dd", 502, GARC_MEMBER_FILE, NULL, 1, 'r',
      WHEN, 0, GARC_TIME_TAR_OCTAL, 0644, 1, 0, 0, 1, NULL, NULL, 0, 0, 0},
  {"dddddddddddddddddddddddddddddddddddddddddddddddddd"
      "dddddddddddddddddddddddddddddddddddddddddddddddddd"
      "dddddddddddddddddddddddddddddddddddddddddddddddddd"
      "dddddddddddddddddddddddddddddddddddddddddddddddddd"
      "dddddddddddddddddddddddddddddddddddddddddddddddddd"
      "dddddddddddddddddddddddddddddddddddddddddddddddddd"
      "dddddddddddddddddddddddddddddddddddddddddddddddddd"
      "dddddddddddddddddddddddddddddddddddddddddddddddddd"
      "dddddddddddddddddddddddddddddddddddddddddddddddddd"
      "dddddddddddddddddddddddddddddddddddddddddddddddddd"
      "ddd", 503, GARC_MEMBER_FILE, NULL, 1, 'r',
      WHEN, 0, GARC_TIME_TAR_OCTAL, 0644, 1, 0, 0, 1, NULL, NULL, 0, 0, 0},
};

static const Spec specials[] = {
  {"pipe", 0, GARC_MEMBER_FIFO, NULL, 0, 0,
      WHEN, 0, GARC_TIME_TAR_OCTAL, 0644, 1, 0, 0, 1, NULL, NULL, 0, 0, 0},
  {"chardev", 0, GARC_MEMBER_CHAR_DEVICE, NULL, 0, 0,
      WHEN, 0, GARC_TIME_TAR_OCTAL, 0666, 1, 0, 0, 1, NULL, NULL, 1, 3, 1},
  {"blockdev", 0, GARC_MEMBER_BLOCK_DEVICE, NULL, 0, 0,
      WHEN, 0, GARC_TIME_TAR_OCTAL, 0660, 1, 0, 0, 1, NULL, NULL, 8, 16, 1},
};

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

static const Archive archives[] = {
  {"pax-basic.tar", GARC_TAR_PAX, 0, basic, COUNT(basic),
      "the five member types that fit ustar with nothing extended about them"},
  {"pax-sizes.tar", GARC_TAR_PAX, 0, sizes, COUNT(sizes),
      "every size either side of a 512-byte boundary"},
  {"pax-names.tar", GARC_TAR_PAX, 0, names, COUNT(names),
      "the prefix split when it is exact, a record when it is not, a long link "
      "target, and a backslash"},
  {"pax-charsets.tar", GARC_TAR_PAX, 0, charsets, COUNT(charsets),
      "a UTF-8 name in the field, and a non-UTF-8 name in a record, which is "
      "the case that writes hdrcharset=BINARY"},
  {"pax-owners.tar", GARC_TAR_PAX, 0, owners, COUNT(owners),
      "uname and gname, an id past the octal field, and a member with neither"},
  {"pax-modes.tar", GARC_TAR_PAX, 0, modes, COUNT(modes),
      "modes including setuid, setgid and sticky"},
  {"pax-times.tar", GARC_TAR_PAX, 0, times, COUNT(times),
      "a time in the field, a time in a record, a fraction, either side of the "
      "epoch, and no time at all"},
  {"pax-records.tar", GARC_TAR_PAX, 0, records, COUNT(records),
      "a record block of 511, 512 and 513 bytes, so that the padding owed for "
      "an already-aligned one is a case the gate reaches"},
  {"pax-specials.tar", GARC_TAR_PAX, 0, specials, COUNT(specials),
      "a fifo and two devices, which are the members whose size field is not "
      "their content"},
  // The same members with no extended records anywhere: every one of them was
  // chosen to be expressible in 1988, so a difference between this and
  // pax-basic.tar is about records and nothing else.
  {"ustar-basic.tar", GARC_TAR_USTAR, 0, basic, COUNT(basic),
      "ustar: the same members with no records at all"},
  {"ustar-names.tar", GARC_TAR_USTAR, 0, names, 1,
      "ustar: the prefix split, which is the only one of the name cases a "
      "1988 reader can be given"},
  // The 155/100 name on its own, in ustar, where there is no record to fall back
  // on: a bound loose by one byte truncates it and a reader gets a wrong path,
  // with nothing in the archive to say so.
  {"ustar-split-max.tar", GARC_TAR_USTAR, 0, names + 4, 1,
      "ustar: the longest name the prefix and name fields hold between them"},
  // 20 blocks is what GNU tar writes, because 10240 bytes was a tape record.
  {"pax-blocked.tar", GARC_TAR_PAX, 20, basic, COUNT(basic),
      "padded to 10240 bytes, which is GNU tar's blocking factor"},
};

/** Print bytes with everything but printable ASCII escaped. */
static void print_escaped(const char * bytes, size_t length) {
  for (size_t i = 0; i < length; ++i) {
    const unsigned char byte = (unsigned char)bytes[i];
    if (byte == '\\') {
      fputs("\\\\", stdout);
    } else if (byte >= 0x20u && byte < 0x7Fu) {
      putchar((int)byte);
    } else {
      printf("\\x%02X", (unsigned)byte);
    }
  }
}

/** The length of a spec's name, resolving the 0-means-strlen convention. */
static size_t spec_name_length(const Spec * spec) {
  return spec->name_length ? spec->name_length : strlen(spec->name);
}

/**
 * Print one row.
 *
 * @param archive Which archive the row belongs to.
 * @param index The member's position.
 * @param member The member.
 */
static void print_row(
    const char * archive, size_t index, const GARC_Member * member) {
  printf("%s\t%zu\t", archive, index);
  print_escaped(member->name, member->name_length);
  printf("\t%s\t%" PRIu64 "\t%" PRId64 "\t%" PRIu32 "\t0%o\t%" PRId64
      "\t%" PRId64 "\t",
      garc_member_type_string(member->type), member->size,
      member->mtime_seconds, member->mtime_nanoseconds,
      (unsigned)member->mode, member->uid, member->gid);
  print_escaped(member->uname, member->uname_length);
  putchar('\t');
  print_escaped(member->gname, member->gname_length);
  putchar('\t');
  print_escaped(member->link_target, member->link_target_length);
  printf("\t%" PRIu32 "\t%" PRIu32 "\n",
      member->device_major, member->device_minor);
}

/**
 * Turn a spec into the member the writer is given, and the row the gate
 * compares against.
 *
 * The same function fills both, which is the point: an intent row derived
 * separately from the struct that was written would be a second statement of
 * what this program meant, and the two could drift.
 *
 * @param spec The spec.
 * @param out_member Receives the member.
 */
static void spec_to_member(const Spec * spec, GARC_Member * out_member) {
  memset(out_member, 0, sizeof(*out_member));
  out_member->name = spec->name;
  out_member->name_length = spec_name_length(spec);
  out_member->type = spec->type;
  out_member->size = spec->size;
  out_member->mtime_seconds = spec->mtime_seconds;
  out_member->mtime_nanoseconds = spec->mtime_nanoseconds;
  out_member->mtime_source = spec->mtime_source;
  out_member->mode = spec->mode;
  out_member->mode_valid = spec->mode_valid;
  out_member->uid = spec->uid;
  out_member->gid = spec->gid;
  out_member->ids_valid = spec->ids_valid;
  out_member->device_major = spec->device_major;
  out_member->device_minor = spec->device_minor;
  out_member->device_valid = spec->device_valid;
  if (spec->link_target) {
    out_member->link_target = spec->link_target;
    out_member->link_target_length = strlen(spec->link_target);
  }
  if (spec->uname) {
    out_member->uname = spec->uname;
    out_member->uname_length = strlen(spec->uname);
  }
  if (spec->gname) {
    out_member->gname = spec->gname;
    out_member->gname_length = strlen(spec->gname);
  }
}

/**
 * The row a spec expects to read back, which is not quite the member written.
 *
 * Some fields are narrowed rather than copied, and every one of them is the
 * writer's documented behaviour rather than a tolerance:
 *
 * - ::GARC_TIME_NONE writes no time, so the field carries zero and every reader
 *   reports zero whatever seconds were in the struct.
 * - Nanoseconds reach the archive only through an `mtime=` record, so a member
 *   asking for ::GARC_TIME_TAR_OCTAL loses them by construction.
 * - A clear `mode_valid`, `ids_valid` or `device_valid` means the writer puts
 *   zero in those fields whatever the struct holds. Which is why the specs above
 *   put something *other* than zero behind a clear flag: with zero there, a
 *   writer that ignored the flag would produce the same bytes and no test here
 *   could tell the two apart.
 *
 * `mtime_source` itself is deliberately not a column. A time the octal field
 * cannot hold is written as a record whatever was asked, so the field is not a
 * function of the request - and a reference has no opinion about it to be
 * checked against anyway.
 *
 * @param spec The spec.
 * @param out_member Receives the expected reading.
 */
static void spec_to_expected(const Spec * spec, GARC_Member * out_member) {
  spec_to_member(spec, out_member);
  if (!spec->mode_valid) {
    out_member->mode = 0;
  }
  if (!spec->ids_valid) {
    out_member->uid = 0;
    out_member->gid = 0;
  }
  if (!spec->device_valid) {
    out_member->device_major = 0;
    out_member->device_minor = 0;
  }
  if (spec->mtime_source == GARC_TIME_NONE) {
    out_member->mtime_seconds = 0;
    out_member->mtime_nanoseconds = 0;
  } else if (spec->mtime_source != GARC_TIME_PAX_DECIMAL) {
    out_member->mtime_nanoseconds = 0;
  }
}

/** Write through a FILE *, which is the whole of a sink for a file on disk. */
static GARC_Result file_write(void * ctx, const void * buffer, size_t size) {
  FILE * out = (FILE *)ctx;
  return fwrite(buffer, 1, size, out) == size ? GARC_OK : GARC_ERR_IO;
}

/**
 * Write one archive, and print its intent rows.
 *
 * @param directory Where the file goes.
 * @param archive What to write.
 * @return 0 on success.
 */
static int write_archive(const char * directory, const Archive * archive) {
  char path[4096];
  if ((size_t)snprintf(path, sizeof(path), "%s/%s", directory, archive->file)
      >= sizeof(path)) {
    fprintf(stderr, "writer_probe: path too long: %s\n", archive->file);
    return 1;
  }

  FILE * out = fopen(path, "wb");
  if (!out) {
    perror(path);
    return 1;
  }

  GARC_Sink_Callbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.ctx = out;
  callbacks.write = file_write;

  GARC_Sink * sink = NULL;
  if (garc_sink_create_callback(&callbacks, &sink) != GARC_OK) {
    fprintf(stderr, "writer_probe: %s: no sink\n", archive->file);
    fclose(out);
    return 1;
  }

  GARC_Writer_Options options;
  garc_writer_options_default(&options);
  options.tar_variant = archive->variant;
  options.blocking_factor = archive->blocking_factor;

  GARC_Writer * writer = NULL;
  GARC_Result result
      = garc_writer_create(sink, GARC_FORMAT_TAR, &options, &writer);
  if (result != GARC_OK) {
    fprintf(stderr, "writer_probe: %s: %s\n", archive->file,
        garc_result_string(result));
    garc_sink_destroy(sink);
    fclose(out);
    return 1;
  }

  int status = 0;
  for (size_t i = 0; i < archive->count && !status; ++i) {
    const Spec * spec = &archive->members[i];

    GARC_Member member;
    spec_to_member(spec, &member);
    result = garc_writer_add(writer, &member);
    if (result != GARC_OK) {
      fprintf(stderr, "writer_probe: %s: member %zu: %s\n", archive->file, i,
          garc_result_string(result));
      status = 1;
      break;
    }

    uint64_t owed = spec->size;
    while (owed && !status) {
      char chunk[4096];
      const size_t take = owed > sizeof(chunk) ? sizeof(chunk) : (size_t)owed;
      memset(chunk, spec->fill, take);
      result = garc_writer_write(writer, chunk, take);
      if (result != GARC_OK) {
        fprintf(stderr, "writer_probe: %s: member %zu: %s\n", archive->file, i,
            garc_result_string(result));
        status = 1;
        break;
      }
      owed -= take;
    }

    if (!status) {
      GARC_Member expected;
      spec_to_expected(spec, &expected);
      print_row(archive->file, i, &expected);
    }
  }

  if (!status) {
    result = garc_writer_finish(writer);
    if (result != GARC_OK) {
      fprintf(stderr, "writer_probe: %s: finish: %s\n", archive->file,
          garc_result_string(result));
      status = 1;
    }
  }

  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
  if (fclose(out) != 0) {
    perror(path);
    status = 1;
  }
  return status;
}

/**
 * Read one archive and print this library's reading of it.
 *
 * @param path The archive.
 * @return 0 on success.
 */
static int read_archive(const char * path) {
  FILE * file = fopen(path, "rb");
  if (!file) {
    perror(path);
    return 1;
  }
  if (fseek(file, 0, SEEK_END) != 0) {
    perror(path);
    fclose(file);
    return 1;
  }
  const long end = ftell(file);
  if (end < 0 || fseek(file, 0, SEEK_SET) != 0) {
    perror(path);
    fclose(file);
    return 1;
  }
  char * bytes = (char *)malloc((size_t)end ? (size_t)end : 1u);
  if (!bytes) {
    fprintf(stderr, "writer_probe: out of memory reading %s\n", path);
    fclose(file);
    return 1;
  }
  if (fread(bytes, 1, (size_t)end, file) != (size_t)end) {
    fprintf(stderr, "writer_probe: short read of %s\n", path);
    free(bytes);
    fclose(file);
    return 1;
  }
  fclose(file);

  // The basename, so that a row read out of a re-written copy compares against
  // the intent row for the archive it came from.
  const char * slash = strrchr(path, '/');
  const char * label = slash ? slash + 1 : path;

  GARC_Stream * stream = NULL;
  GARC_Result result
      = garc_stream_create_memory(bytes, (size_t)end, &stream);
  if (result != GARC_OK) {
    fprintf(stderr, "writer_probe: %s: %s\n", path,
        garc_result_string(result));
    free(bytes);
    return 1;
  }

  GARC_Archive * archive = NULL;
  result = garc_open(stream, NULL, &archive);
  if (result != GARC_OK) {
    fprintf(stderr, "writer_probe: %s: %s\n", path,
        garc_result_string(result));
    garc_stream_destroy(stream);
    free(bytes);
    return 1;
  }

  size_t index = 0;
  const GARC_Member * member = NULL;
  while ((result = garc_next(archive, &member)) == GARC_OK) {
    print_row(label, index++, member);
  }
  int status = 0;
  if (result != GARC_END) {
    fprintf(stderr, "writer_probe: %s: %s\n", path,
        garc_result_string(result));
    status = 1;
  }

  garc_close(archive);
  garc_stream_destroy(stream);
  free(bytes);
  return status;
}

/** Print what each archive is for, so the gate's output can name it. */
static int describe(void) {
  for (size_t i = 0; i < COUNT(archives); ++i) {
    printf("%s\t%s\t%u\t%s\n", archives[i].file,
        garc_tar_variant_string(archives[i].variant),
        (unsigned)archives[i].blocking_factor, archives[i].purpose);
  }
  return 0;
}

int main(int argc, char ** argv) {
  if (argc == 3 && strcmp(argv[1], "write") == 0) {
    for (size_t i = 0; i < COUNT(archives); ++i) {
      if (write_archive(argv[2], &archives[i]) != 0) {
        return 1;
      }
    }
    return 0;
  }
  if (argc == 3 && strcmp(argv[1], "read") == 0) {
    return read_archive(argv[2]);
  }
  if (argc == 2 && strcmp(argv[1], "describe") == 0) {
    return describe();
  }
  fprintf(stderr,
      "usage: %s write <directory>\n"
      "       %s read <path.tar>\n"
      "       %s describe\n", argv[0], argv[0], argv[0]);
  return 2;
}
