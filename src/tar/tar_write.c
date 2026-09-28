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
 * Writing tar: a ustar header, and an extended record for everything that will
 * not fit in one.
 *
 * **Every field is filled in as ustar, and a record is added only for what ustar
 * cannot say.** So a reader that knows only POSIX.1-1988 gets a correct answer
 * wherever one exists in its vocabulary, and a reader that knows pax gets the
 * exact one. The alternative - writing records for everything and leaving the
 * fields blank, which is legal - produces an archive half the world reads as
 * empty.
 *
 * Three places where the three reference implementations disagree, each measured
 * rather than assumed (`tools/oracle/`), and each decided here with the reason:
 *
 * **The ustar name split.** A name too long for the 100-byte field can often be
 * cut at a `/` into a 155-byte prefix and a 100-byte name, which between them
 * hold up to 255 bytes with no record at all. Of the three references only
 * libarchive does this; GNU tar and Python's `tarfile` write a `path=` record and
 * truncate the field. This writer splits, because the split is not a compromise -
 * it is the ustar format doing the job it has a prefix field for, and it means a
 * ustar-only reader gets the *whole* name rather than the first hundred bytes of
 * it.
 *
 * **What goes in the fields when the split does not fit.** Here libarchive
 * splits anyway, at a slash that leaves the middle of the path out: a 300-byte
 * `f…/g…/h…` is written with `f…` in the prefix and `h…` in the name, so
 * ustar-only reader sees a path with a directory silently missing. GNU tar and
 * `tarfile` truncate to the first 100 bytes. This writer truncates, with
 * libarchive outvoted two to one and the argument going the same way: every
 * answer here is wrong, and a *recognisably* wrong one beats a *plausibly* wrong
 * one. A truncated name puts a file with a mangled name in the right place; a
 * name with a component dropped puts it somewhere else entirely.
 *
 * **The extended header's own name.** GNU tar writes
 * `<dir>/PaxHeaders/<basename>`, libarchive writes `PaxHeader/<basename>`, and
 * `tarfile` writes the constant `././@PaxHeader`. Nothing reads it - it names a
 * carrier, and a carrier is not a member - so the choice is decided by what costs
 * least and surprises least: the constant. It cannot be truncated, it needs no
 * basename arithmetic, it cannot collide with a real path because `././` is not
 * something a filesystem produces, and it is the spelling already in this
 * library's vocabulary from GNU's `././@LongLink`.
 *
 * Reference documents are named in tar_internal.h.
 */

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/name.h>
#include <ghoti.io/archive/tar.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "tar/tar_internal.h"
#include "writer/writer_internal.h"

/** The name every extended header carries; see the file comment for why. */
#define GARC_TAR_PAX_CARRIER_NAME "././@PaxHeader"

/** How much of the checksum field is digits: six, then a NUL and a space. */
#define GARC_TAR_CHKSUM_DIGITS 6u

/**
 * Decimal width of a value, which a pax record's self-referential length needs.
 *
 * @param value The value.
 * @return How many digits it takes to write.
 */
static size_t tar_decimal_width(size_t value) {
  size_t width = 1u;
  while (value >= 10u) {
    value /= 10u;
    width++;
  }
  return width;
}

/**
 * Append one `len SP key = value LF` record to the writer's record buffer.
 *
 * @param writer The writer.
 * @param key Which key.
 * @param value The value bytes; not required to be NUL-terminated.
 * @param value_length How many of them.
 * @return GARC_OK, or GARC_ERR_OOM.
 */
static GARC_Result tar_record_append(GARC_Writer * writer, GARC_Pax_Key key,
    const char * value, size_t value_length) {
  const char * name = garc_tar_pax_key_name(key);
  const size_t key_length = strlen(name);
  // Everything but the length digits: one space, the key, `=`, the value, LF.
  const size_t body = 1u + key_length + 1u + value_length + 1u;

  // **The length counts itself**, so the number of digits depends on the total
  // and the total depends on the number of digits. Iterating to a fixed point
  // rather than adding a digit once: body = 98 needs two digits for 100 and
  // three for 101, and a single correction is one step of exactly this loop.
  size_t digits = tar_decimal_width(body + 1u);
  while (tar_decimal_width(body + digits) != digits) {
    digits = tar_decimal_width(body + digits);
  }
  const size_t total = body + digits;

  GARC_Result result = garc_buffer_grow(
      writer->allocator, &writer->records, writer->records.length + total);
  if (result != GARC_OK) {
    return result;
  }

  char * out = writer->records.bytes + writer->records.length;
  size_t scale = 1u;
  for (size_t i = 1u; i < digits; ++i) {
    scale *= 10u;
  }
  for (size_t i = 0; i < digits; ++i) {
    out[i] = (char)('0' + (char)((total / scale) % 10u));
    scale /= 10u;
  }
  out += digits;
  *out++ = ' ';
  memcpy(out, name, key_length);
  out += key_length;
  *out++ = '=';
  if (value_length) {
    memcpy(out, value, value_length);
    out += value_length;
  }
  *out++ = '\n';
  writer->records.length += total;
  return GARC_OK;
}

/**
 * How much room a record value needs, at most.
 *
 * An int64_t is at most 20 characters with its sign, a fraction adds a point and
 * nine digits, and one more byte is for the NUL snprintf writes. So 40 is more
 * than half again what the widest value takes - which is why there is no arm here
 * for a truncation snprintf would report. An arm no input can reach is worse than
 * absent: it reads as a guard somebody is relying on, and no test can put it in a
 * position to fail. The extremes that would overflow a buffer sized by guesswork
 * - INT64_MIN with and without a fraction - are asserted as record bytes instead.
 */
#define GARC_TAR_RECORD_NUMBER_MAX 40u

/** Append a record whose value is a decimal signed integer. */
static GARC_Result tar_record_int(
    GARC_Writer * writer, GARC_Pax_Key key, int64_t value) {
  char text[GARC_TAR_RECORD_NUMBER_MAX];
  const int written = snprintf(text, sizeof(text), "%lld", (long long)value);
  return tar_record_append(writer, key, text, (size_t)written);
}

/**
 * Append an `mtime=` record, with a fraction when there is one.
 *
 * The seconds are **floored** and the nanoseconds are the distance above that
 * floor, which is the convention on both sides: the reader turns `-1.5` into -2
 * seconds and 500000000 nanoseconds, so writing those back has to produce
 * `-1.5` again and not `-2.5`.
 */
static GARC_Result tar_record_mtime(
    GARC_Writer * writer, int64_t seconds, uint32_t nanoseconds) {
  if (!nanoseconds) {
    return tar_record_int(writer, GARC_PAX_MTIME, seconds);
  }
  char text[GARC_TAR_RECORD_NUMBER_MAX];
  int written;
  if (seconds < 0) {
    // -2 s + 500000000 ns is -1.5 s, so the integer part is one closer to zero
    // than the floor and the fraction is counted downwards from it. Spelled with
    // the magnitude rather than by negating, because -INT64_MIN overflows.
    const uint64_t magnitude = (uint64_t)(-(seconds + 1)) + 1u;
    const uint64_t whole = magnitude - 1u;
    written = snprintf(text, sizeof(text), "-%llu.%09llu",
        (unsigned long long)whole,
        (unsigned long long)(1000000000u - nanoseconds));
  } else {
    written = snprintf(text, sizeof(text), "%lld.%09llu", (long long)seconds,
        (unsigned long long)nanoseconds);
  }
  return tar_record_append(writer, GARC_PAX_MTIME, text, (size_t)written);
}

/** Where a name's bytes go in the header's two fields. */
typedef struct {
  size_t prefix_length; ///< Bytes of the name that go in `prefix`; 0 for none.
  size_t name_offset;   ///< Where the `name` field's bytes start in the name.
  size_t name_length;   ///< How many of them.
  /** Non-zero when the two fields between them hold the whole name. */
  int complete;
} GARC_Tar_Name_Split;

/**
 * Work out how a name goes into `name` and `prefix`.
 *
 * The ustar split is prefix, an implied `/`, then name - so the two fields hold
 * up to 255 bytes between them and the separator itself is not stored. Both parts
 * have to be non-empty, or the name read back gains or loses a slash.
 *
 * **The last usable slash is chosen**, so the name field holds as little as
 * possible. In the ordinary case that is the basename, which is what makes a
 * ustar-only reader's answer read like a path.
 *
 * @param name The name bytes.
 * @param length How many.
 * @return The split. `complete` clear means a `path=` record is needed and the
 *   fields hold the first 100 bytes, which is the truncation the file comment
 *   argues for.
 */
static GARC_Tar_Name_Split tar_split_name(const char * name, size_t length) {
  GARC_Tar_Name_Split split;
  split.prefix_length = 0;
  split.name_offset = 0;
  split.name_length = length < GARC_TAR_LEN_NAME ? length : GARC_TAR_LEN_NAME;
  split.complete = (length <= GARC_TAR_LEN_NAME);
  if (split.complete) {
    return split;
  }

  // Downwards, so the first slash that works is the last one that does.
  for (size_t cut = length; cut-- > 1u;) {
    if (name[cut] != '/') {
      continue;
    }
    const size_t tail = length - cut - 1u;
    if (!tail || tail > GARC_TAR_LEN_NAME || cut > GARC_TAR_LEN_PREFIX) {
      continue;
    }
    split.prefix_length = cut;
    split.name_offset = cut + 1u;
    split.name_length = tail;
    split.complete = 1;
    return split;
  }
  return split;
}

/**
 * Fill in the checksum field over a finished block.
 *
 * The sum is taken with the checksum field read as spaces, and written as six
 * octal digits, a NUL and a space - which is what GNU tar and bsdtar both write,
 * and what every reader has seen most. The unsigned sum is the one written; the
 * signed reading the reader also accepts exists for archives written by compilers
 * where `char` was signed, and both agree for every header this writer produces,
 * because none of its bytes is above 0x7F unless a name or a base-256 field put
 * it there.
 *
 * @param block The 512 bytes, complete but for this field.
 */
static void tar_write_checksum(uint8_t * block) {
  memset(block + GARC_TAR_OFF_CHKSUM, ' ', GARC_TAR_LEN_CHKSUM);
  uint32_t sum = 0;
  for (size_t i = 0; i < GARC_TAR_BLOCK; ++i) {
    sum += (uint32_t)block[i];
  }
  // 512 bytes of 0xFF sum to 130560, which is six octal digits; the field cannot
  // overflow and so needs no check that it did not.
  for (size_t i = GARC_TAR_CHKSUM_DIGITS; i-- > 0u;) {
    block[GARC_TAR_OFF_CHKSUM + i] = (uint8_t)('0' + (sum & 7u));
    sum >>= 3;
  }
  block[GARC_TAR_OFF_CHKSUM + GARC_TAR_CHKSUM_DIGITS] = '\0';
  block[GARC_TAR_OFF_CHKSUM + GARC_TAR_CHKSUM_DIGITS + 1u] = ' ';
}

/** Put the ustar magic and version in a block. */
static void tar_write_magic(uint8_t * block) {
  memcpy(block + GARC_TAR_OFF_MAGIC, "ustar", 5);
  block[GARC_TAR_OFF_MAGIC + 5u] = '\0';
  memcpy(block + GARC_TAR_OFF_VERSION, "00", GARC_TAR_LEN_VERSION);
}

/** Map a member type onto the typeflag byte, or 0 for a type with no spelling. */
static char tar_flag_from_type(GARC_Member_Type type) {
  switch (type) {
    case GARC_MEMBER_FILE:
      return '0';
    case GARC_MEMBER_HARDLINK:
      return '1';
    case GARC_MEMBER_SYMLINK:
      return '2';
    case GARC_MEMBER_CHAR_DEVICE:
      return '3';
    case GARC_MEMBER_BLOCK_DEVICE:
      return '4';
    case GARC_MEMBER_DIRECTORY:
      return '5';
    case GARC_MEMBER_FIFO:
      return '6';
    default:
      // GARC_MEMBER_OTHER, which is a *reading* of a typeflag this library does
      // not name rather than a thing to write - there is no byte to put here -
      // and the COUNT sentinel, which is not a type at all.
      return '\0';
  }
}

/**
 * Whether these bytes are well-formed UTF-8, asked of the name classifier.
 *
 * The classifier already answers it, and asking it rather than writing a second
 * validator is what keeps one answer: a writer that declared UTF-8 by a rule the
 * reader's own finding disagreed with would put a claim in an archive that this
 * library contradicts on the way back in.
 */
static int tar_is_utf8(const char * bytes, size_t length) {
  return (garc_name_check(bytes, length) & GARC_NAME_NOT_UTF8) == 0;
}

/**
 * Refuse what no tar header can carry, before any of it is written.
 *
 * @param member The member.
 * @return GARC_OK, or GARC_ERR_INVALID naming nothing, because every arm here is
 *   the caller's argument being wrong rather than the format falling short.
 */
static GARC_Result tar_check_member(const GARC_Member * member) {
  if (!member->name || !member->name_length) {
    // No writer produces an empty name and the reader refuses one. A header with
    // an empty name field is how an archive says "the name is elsewhere", which
    // is a carrier rather than a member.
    return GARC_ERR_INVALID;
  }
  // A length with no bytes behind it. Checked rather than treated as zero,
  // because the pointer is what gets read and a caller that set one and not the
  // other has said something it did not mean.
  if ((!member->link_target && member->link_target_length)
      || (!member->uname && member->uname_length)
      || (!member->gname && member->gname_length)) {
    return GARC_ERR_INVALID;
  }
  // **A NUL in any of the four byte strings a header carries.** A NUL ends a
  // header field and does not end an extended record, so a value containing one
  // would be two different values depending on which a reader believed - the same
  // refusal the reader makes of a carrier payload with bytes behind its
  // terminator, from the other side.
  //
  // Written as a sweep over all four rather than as a check per field, and the
  // writer's fuzz harness is why: a first version checked the name and the link
  // target and left the owner names, and an owner name of raw bytes came back
  // empty from the round trip within four thousand executions. Four
  // near-identical checks is the shape where the fourth gets forgotten.
  const struct {
    const char * bytes;
    size_t length;
  } strings[] = {
    {member->name, member->name_length},
    {member->link_target, member->link_target_length},
    {member->uname, member->uname_length},
    {member->gname, member->gname_length},
  };
  for (size_t i = 0; i < sizeof(strings) / sizeof(strings[0]); ++i) {
    if (strings[i].length
        && memchr(strings[i].bytes, '\0', strings[i].length)) {
      return GARC_ERR_INVALID;
    }
  }
  if (!tar_flag_from_type(member->type)) {
    return GARC_ERR_INVALID;
  }
  if ((member->type == GARC_MEMBER_SYMLINK
          || member->type == GARC_MEMBER_HARDLINK)
      && (!member->link_target || !member->link_target_length)) {
    // The target is what the member is. A symlink to nothing is not a symlink.
    return GARC_ERR_INVALID;
  }
  if ((member->type == GARC_MEMBER_CHAR_DEVICE
          || member->type == GARC_MEMBER_BLOCK_DEVICE)
      && !member->device_valid) {
    return GARC_ERR_INVALID;
  }
  if (!garc_tar_type_carries_data(member->type) && member->size) {
    // The reader *ignores* a stale size on one of these, because real archives
    // have one. A writer cannot: it would accept the declaration and then refuse
    // every byte the caller tried to write against it.
    return GARC_ERR_INVALID;
  }
  if (member->mtime_nanoseconds
      && member->mtime_source != GARC_TIME_PAX_DECIMAL) {
    // A fraction is what a pax `mtime=` record carries and the only thing that
    // carries one, so a sub-second time from tar's octal field - or from no field
    // at all - says two things at once. The reader never produces it.
    return GARC_ERR_INVALID;
  }
  if (member->mtime_nanoseconds >= 1000000000u) {
    // A whole second belongs in the seconds.
    return GARC_ERR_INVALID;
  }
  return GARC_OK;
}

/**
 * Build the extended records this member needs, into the writer's buffer.
 *
 * Sets `*out_needs_records`. A record is added for exactly what the ustar fields
 * cannot carry, which is why this runs after the fields have been formatted and
 * reads the forms they came out as.
 */
static GARC_Result tar_build_records(GARC_Writer * writer,
    const GARC_Member * member, const GARC_Tar_Name_Split * split,
    GARC_Tar_Number_Form size_form, GARC_Tar_Number_Form mtime_form,
    GARC_Tar_Number_Form uid_form, GARC_Tar_Number_Form gid_form) {
  writer->records.length = 0;

  const int long_link = member->link_target
      && member->link_target_length > GARC_TAR_LEN_LINKNAME;
  const int long_uname = member->uname_length > GARC_TAR_LEN_UNAME;
  const int long_gname = member->gname_length > GARC_TAR_LEN_GNAME;
  const int fractional = member->mtime_source == GARC_TIME_PAX_DECIMAL;

  // **`hdrcharset` first, and only when something in the set is not UTF-8.**
  // POSIX says a record's bytes are UTF-8, so writing a name that is not without
  // saying so would put a claim in the archive that this library's own reader
  // reports back as GARC_NAME_UTF8 - a declaration made by the writer rather
  // than by the data. `BINARY` is the standard way to say "these are bytes", and
  // it applies to the whole set, which is why it is decided over every value in
  // it at once.
  int binary = 0;
  if (!split->complete && !tar_is_utf8(member->name, member->name_length)) {
    binary = 1;
  }
  if (long_link
      && !tar_is_utf8(member->link_target, member->link_target_length)) {
    binary = 1;
  }
  if (long_uname && !tar_is_utf8(member->uname, member->uname_length)) {
    binary = 1;
  }
  if (long_gname && !tar_is_utf8(member->gname, member->gname_length)) {
    binary = 1;
  }
  if (binary) {
    GARC_Result result = tar_record_append(
        writer, GARC_PAX_HDRCHARSET, "BINARY", 6u);
    if (result != GARC_OK) {
      return result;
    }
  }

  // Then in the order the key enum lists them, so that one member's records are
  // the same bytes every time it is written.
  GARC_Result result = GARC_OK;
  if (!split->complete) {
    result = tar_record_append(
        writer, GARC_PAX_PATH, member->name, member->name_length);
  }
  if (result == GARC_OK && long_link) {
    result = tar_record_append(writer, GARC_PAX_LINKPATH, member->link_target,
        member->link_target_length);
  }
  if (result == GARC_OK && long_uname) {
    result = tar_record_append(
        writer, GARC_PAX_UNAME, member->uname, member->uname_length);
  }
  if (result == GARC_OK && long_gname) {
    result = tar_record_append(
        writer, GARC_PAX_GNAME, member->gname, member->gname_length);
  }
  if (result == GARC_OK && size_form != GARC_TAR_NUMBER_OCTAL) {
    // Signed, and that is not a narrowing: the header field's formatter refused
    // anything above INT64_MAX before this was reached, so a size that gets a
    // record is one an int64_t holds.
    result = tar_record_int(writer, GARC_PAX_SIZE, (int64_t)member->size);
  }
  if (result == GARC_OK
      && (fractional || mtime_form != GARC_TAR_NUMBER_OCTAL)) {
    result = tar_record_mtime(
        writer, member->mtime_seconds, member->mtime_nanoseconds);
  }
  if (result == GARC_OK && uid_form != GARC_TAR_NUMBER_OCTAL) {
    result = tar_record_int(writer, GARC_PAX_UID, member->uid);
  }
  if (result == GARC_OK && gid_form != GARC_TAR_NUMBER_OCTAL) {
    result = tar_record_int(writer, GARC_PAX_GID, member->gid);
  }
  return result;
}

/** Write one 512-byte block, checksummed. */
static GARC_Result tar_write_block(GARC_Writer * writer, uint8_t * block) {
  tar_write_checksum(block);
  return garc_sink_write(writer->sink, block, GARC_TAR_BLOCK);
}

/** Write the extended header carrying the records already built. */
static GARC_Result tar_write_carrier(GARC_Writer * writer) {
  uint8_t block[GARC_TAR_BLOCK];
  memset(block, 0, sizeof(block));

  memcpy(block + GARC_TAR_OFF_NAME, GARC_TAR_PAX_CARRIER_NAME,
      sizeof(GARC_TAR_PAX_CARRIER_NAME) - 1u);
  block[GARC_TAR_OFF_TYPEFLAG] = 'x';
  tar_write_magic(block);

  // Mode, owner and time are zero rather than copies of the member's. The carrier
  // is not a file: it has no owner and no modification time, and a reader that
  // extracted it anyway - which is the bug the carrier rules exist to prevent -
  // should not be handed the member's mode to apply to it.
  //
  // Written as the bytes they are rather than through the formatter. Formatting a
  // constant cannot fail, so routing it through a function that reports failure
  // would put four error arms here that no input reaches, and it would leave the
  // spelling of a field this file pins as bytes to another function's choices.
  memcpy(block + GARC_TAR_OFF_MODE, "0000000", GARC_TAR_LEN_MODE - 1u);
  memcpy(block + GARC_TAR_OFF_UID, "0000000", GARC_TAR_LEN_UID - 1u);
  memcpy(block + GARC_TAR_OFF_GID, "0000000", GARC_TAR_LEN_GID - 1u);
  memcpy(block + GARC_TAR_OFF_MTIME, "00000000000", GARC_TAR_LEN_MTIME - 1u);

  GARC_Tar_Number_Form form;
  GARC_Result result = garc_tar_format_uint(block + GARC_TAR_OFF_SIZE,
      GARC_TAR_LEN_SIZE, (uint64_t)writer->records.length, &form);
  if (result != GARC_OK) {
    // A record set larger than INT64_MAX, which needs more memory than any host
    // has. Kept because the formatter reports it and discarding a reported
    // failure is how a writer produces a header with a garbage field.
    return result;
  }

  result = tar_write_block(writer, block);
  if (result != GARC_OK) {
    return result;
  }
  result = garc_sink_write(
      writer->sink, writer->records.bytes, writer->records.length);
  if (result != GARC_OK) {
    return result;
  }
  const uint64_t padding
      = (GARC_TAR_BLOCK - (writer->records.length % GARC_TAR_BLOCK))
      % GARC_TAR_BLOCK;
  return garc_sink_fill(writer->sink, 0, padding);
}

GARC_Result garc_tar_write_member(
    GARC_Writer * writer, const GARC_Member * member) {
  GARC_Result result = tar_check_member(member);
  if (result != GARC_OK) {
    return result;
  }

  uint8_t block[GARC_TAR_BLOCK];
  memset(block, 0, sizeof(block));

  const GARC_Tar_Name_Split split
      = tar_split_name(member->name, member->name_length);
  memcpy(block + GARC_TAR_OFF_NAME, member->name + split.name_offset,
      split.name_length);
  if (split.prefix_length) {
    memcpy(block + GARC_TAR_OFF_PREFIX, member->name, split.prefix_length);
  }

  block[GARC_TAR_OFF_TYPEFLAG] = (uint8_t)tar_flag_from_type(member->type);
  tar_write_magic(block);

  if (member->link_target && member->link_target_length) {
    const size_t take = member->link_target_length > GARC_TAR_LEN_LINKNAME
        ? GARC_TAR_LEN_LINKNAME
        : member->link_target_length;
    memcpy(block + GARC_TAR_OFF_LINKNAME, member->link_target, take);
  }
  if (member->uname && member->uname_length) {
    const size_t take = member->uname_length > GARC_TAR_LEN_UNAME
        ? GARC_TAR_LEN_UNAME
        : member->uname_length;
    memcpy(block + GARC_TAR_OFF_UNAME, member->uname, take);
  }
  if (member->gname && member->gname_length) {
    const size_t take = member->gname_length > GARC_TAR_LEN_GNAME
        ? GARC_TAR_LEN_GNAME
        : member->gname_length;
    memcpy(block + GARC_TAR_OFF_GNAME, member->gname, take);
  }

  // Which encoding each field came out as. size, mtime, uid and gid get a record
  // when octal will not hold them, so their forms are read by
  // tar_build_records(); mode and the device numbers have no pax key in this
  // reader's vocabulary, so a base-256 one is recorded here instead - it still
  // makes the archive something a 1988 reader cannot read, which is what the
  // ustar variant has to refuse.
  GARC_Tar_Number_Form form = GARC_TAR_NUMBER_OCTAL;
  int base256_without_a_record = 0;
  GARC_Tar_Number_Form size_form = GARC_TAR_NUMBER_OCTAL;
  GARC_Tar_Number_Form mtime_form = GARC_TAR_NUMBER_OCTAL;
  GARC_Tar_Number_Form uid_form = GARC_TAR_NUMBER_OCTAL;
  GARC_Tar_Number_Form gid_form = GARC_TAR_NUMBER_OCTAL;

  result = garc_tar_format_uint(block + GARC_TAR_OFF_MODE, GARC_TAR_LEN_MODE,
      member->mode_valid ? member->mode : 0u, &form);
  base256_without_a_record |= (form != GARC_TAR_NUMBER_OCTAL);
  if (result == GARC_OK) {
    result = garc_tar_format_int(block + GARC_TAR_OFF_UID, GARC_TAR_LEN_UID,
        member->ids_valid ? member->uid : 0, &uid_form);
  }
  if (result == GARC_OK) {
    result = garc_tar_format_int(block + GARC_TAR_OFF_GID, GARC_TAR_LEN_GID,
        member->ids_valid ? member->gid : 0, &gid_form);
  }
  if (result == GARC_OK) {
    result = garc_tar_format_uint(
        block + GARC_TAR_OFF_SIZE, GARC_TAR_LEN_SIZE, member->size, &size_form);
  }
  if (result == GARC_OK) {
    result = garc_tar_format_int(block + GARC_TAR_OFF_MTIME,
        GARC_TAR_LEN_MTIME,
        member->mtime_source == GARC_TIME_NONE ? 0 : member->mtime_seconds,
        &mtime_form);
  }
  // The device numbers are written only for a device member. Every other header
  // in the wild leaves them blank, which the reader reads as zero and reports as
  // no device at all; writing `0000000` there instead would be putting a number
  // where the archive has none.
  if (result == GARC_OK && member->device_valid) {
    result = garc_tar_format_uint(block + GARC_TAR_OFF_DEVMAJOR,
        GARC_TAR_LEN_DEVMAJOR, (uint64_t)member->device_major, &form);
    base256_without_a_record |= (form != GARC_TAR_NUMBER_OCTAL);
    if (result == GARC_OK) {
      result = garc_tar_format_uint(block + GARC_TAR_OFF_DEVMINOR,
          GARC_TAR_LEN_DEVMINOR, (uint64_t)member->device_minor, &form);
      base256_without_a_record |= (form != GARC_TAR_NUMBER_OCTAL);
    }
  }
  if (result != GARC_OK) {
    return result;
  }

  result = tar_build_records(
      writer, member, &split, size_form, mtime_form, uid_form, gid_form);
  if (result != GARC_OK) {
    return result;
  }

  // A base-256 field is GNU's extension, not ustar's, so a caller who asked for
  // ustar is told about it the same way they are told about a record: with the
  // status that says the format cannot express this member, rather than with an
  // archive that quietly is not the format they asked for.
  const int needs_pax
      = writer->records.length != 0 || base256_without_a_record;
  if (needs_pax && writer->options.tar_variant != GARC_TAR_PAX) {
    return GARC_ERR_UNSUPPORTED;
  }

  if (writer->records.length) {
    result = tar_write_carrier(writer);
    if (result != GARC_OK) {
      return result;
    }
  }

  result = tar_write_block(writer, block);
  if (result != GARC_OK) {
    return result;
  }

  writer->data_remaining = member->size;
  writer->data_padding
      = (GARC_TAR_BLOCK - (member->size % GARC_TAR_BLOCK)) % GARC_TAR_BLOCK;
  return GARC_OK;
}

GARC_Result garc_tar_write_close_member(GARC_Writer * writer) {
  // Pad the member's data out to the 512-byte block the next header has to start
  // on. The count was computed when the member was added, because the declared
  // size is what decides it and that is what the header already carries.
  return garc_sink_fill(writer->sink, 0, writer->data_padding);
}

GARC_Result garc_tar_write_end(GARC_Writer * writer) {
  // Two zero blocks. One is what a trimmed tail looks like and is not an end
  // marker; the reader says so from the other side.
  GARC_Result result
      = garc_sink_fill(writer->sink, 0, (uint64_t)GARC_TAR_BLOCK * 2u);
  if (result != GARC_OK) {
    return result;
  }
  if (!writer->options.blocking_factor) {
    return GARC_OK;
  }

  // Measured from the **sink's** offset rather than from where this archive
  // started, which matters only for a sink that already held bytes. A blocking
  // factor is about the record structure of the thing being written to - a tape
  // drive's block, historically - so aligning to the output's own offset is what
  // it asks for; aligning to the archive's start would leave the records
  // misaligned in exactly the case the option exists for.
  const uint64_t record
      = (uint64_t)writer->options.blocking_factor * GARC_TAR_BLOCK;
  const uint64_t written = garc_sink_tell(writer->sink);
  return garc_sink_fill(writer->sink, 0, (record - (written % record)) % record);
}
