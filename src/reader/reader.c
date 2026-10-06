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
 * The archive object: what every format's reader shares.
 *
 * Identification, the member cursor, reading a member's data, and the caps that
 * no single format can enforce because they are sums across members.
 */

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/reader.h>
#include <ghoti.io/archive/tar.h>
#include <ghoti.io/cutil/allocator.h>
#include <stdint.h>
#include <string.h>

#include "reader/reader_internal.h"
#include "tar/tar_internal.h"
#include "zip/zip_internal.h"

const char * garc_format_string(GARC_Format format) {
  switch (format) {
    case GARC_FORMAT_UNKNOWN:
      return "unknown";
    case GARC_FORMAT_TAR:
      return "tar";
    case GARC_FORMAT_ZIP:
      return "zip";
    case GARC_FORMAT_COUNT:
    default:
      return "invalid";
  }
}

/**
 * Identify the container, keeping the bytes that were looked at.
 *
 * **Identification does not seek for the formats that can be read without
 * seeking.** Putting the bytes back by seeking to zero would work on a file and
 * fail on a pipe, which would make "tar can be read from a pipe" - the reason
 * this library has a callback stream at all - false for every archive. So the
 * window is kept in the archive and the format reader drains it first.
 *
 * **There are three questions here, not one, and the order is the design.**
 *
 * 1. Is this a tar? Answered from the front, from one block, on any stream.
 * 2. Do the first bytes say zip? A local file header, or an end record for an
 *    archive with no members. This is where a zip on a *pipe* is caught: the
 *    answer is yes and the format cannot be read that way, so it is
 *    ::GARC_ERR_NOT_SEEKABLE rather than ::GARC_ERR_FORMAT - "this is a zip and
 *    I need to seek" rather than "I do not know what this is".
 * 3. Failing both, and only on a seekable stream: is there an end record within
 *    the last 65,557 bytes? That is the only way to find a zip behind a
 *    self-extracting stub, whose first bytes are an executable's.
 *
 * Question 3 comes last because it is the expensive one and because it can say
 * yes about a file whose last bytes merely look like a record - which is exactly
 * what every zip reader does, and what the validating scan in
 * ::garc_zip_locate_eocd() keeps honest.
 */
static GARC_Result reader_identify(GARC_Archive * archive) {
  size_t total = 0;

  while (total < sizeof(archive->peek)) {
    size_t got = 0;
    GARC_Result result = garc_stream_read(archive->stream,
        archive->peek + total, sizeof(archive->peek) - total, &got);
    if (result != GARC_OK) {
      return result;
    }
    if (!got) {
      break;
    }
    total += got;
  }

  archive->peek_length = total;
  archive->peek_consumed = 0;

  if (total == 0u) {
    // A stream of no bytes is not "not a tar", it is nothing at all. Reporting
    // GARC_ERR_FORMAT would say something specific about a file that says
    // nothing, and a caller telling an empty file from a damaged one needs the
    // difference.
    return GARC_ERR_CORRUPT;
  }

  if (garc_tar_identify(archive->peek, total)) {
    archive->format = GARC_FORMAT_TAR;
    return GARC_OK;
  }

  if (garc_zip_identify(archive->peek, total)) {
    if (!garc_stream_is_seekable(archive->stream)) {
      // A zip, and unreadable this way. Saying so by name matters: a caller
      // handed GARC_ERR_FORMAT for a file every other tool opens would go
      // looking for the wrong thing, and the fix - give me a seekable stream -
      // is only discoverable from this status.
      return GARC_ERR_NOT_SEEKABLE;
    }
    archive->format = GARC_FORMAT_ZIP;
    return GARC_OK;
  }

  if (garc_stream_is_seekable(archive->stream)) {
    uint64_t eocd_offset = 0;
    GARC_Result found = garc_zip_locate_eocd(archive, &eocd_offset);
    if (found == GARC_OK) {
      // Found from the end, which is the only way a zip behind a stub can be.
      // The offset is kept rather than looked for twice.
      archive->zip.eocd_offset = eocd_offset;
      archive->zip.eocd_found = 1;
      archive->format = GARC_FORMAT_ZIP;
      return GARC_OK;
    }
    if (found != GARC_ERR_FORMAT) {
      // An I/O or allocation failure while looking. Reported as itself: a caller
      // told "not an archive" because a read failed would go and check the
      // bytes, which are fine.
      return found;
    }
  }

  return GARC_ERR_FORMAT;
}

/**
 * Let the format reader do whatever it needs at open.
 *
 * tar needs nothing: its first header is the next thing in the stream. zip has
 * to read its end record and its central directory's position before it can
 * report a single member, and that work can fail on an input identification
 * already accepted - which is why this is separate from identification rather
 * than folded into it.
 *
 * @param archive The archive.
 * @return ::GARC_OK, or the format's failure.
 */
static GARC_Result reader_open_format(GARC_Archive * archive) {
  if (archive->format != GARC_FORMAT_ZIP) {
    return GARC_OK;
  }
  uint64_t eocd_offset = archive->zip.eocd_offset;
  if (!archive->zip.eocd_found) {
    // Identified from the front, so the end record has not been looked for yet.
    GARC_Result result = garc_zip_locate_eocd(archive, &eocd_offset);
    if (result != GARC_OK) {
      // The first bytes said zip and there is no end record behind them. That is
      // a truncated zip rather than some other format: GARC_ERR_FORMAT here
      // would send a caller looking for the wrong problem.
      return result == GARC_ERR_FORMAT ? GARC_ERR_CORRUPT : result;
    }
  }
  return garc_zip_open(archive, eocd_offset);
}

/**
 * Free whatever the format reader allocated for this archive.
 *
 * A switch rather than a call to every format's release: a release that ran for
 * the format that was not used would be reading a state nothing initialised, and
 * the cost of getting that wrong is a free of an uninitialised pointer rather
 * than a wrong answer. Both formats leave a calloc'd state alone when they
 * allocate nothing, so the switch is about the rule and not about the bytes.
 *
 * @param archive The archive.
 */
static void reader_release(GARC_Archive * archive) {
  switch (archive->format) {
    case GARC_FORMAT_TAR:
      garc_tar_release(archive);
      break;
    case GARC_FORMAT_ZIP:
      garc_zip_release(archive);
      break;
    default:
      // Identification failed, so no format reader has run and there is nothing
      // to release. Reached on the failure path of garc_open().
      break;
  }
}

GARC_Result garc_open(GARC_Stream * stream, const GARC_Limits * limits,
    GARC_Archive ** out_archive) {
  return garc_open_with_allocator(stream, limits, NULL, out_archive);
}

GARC_Result garc_open_with_allocator(GARC_Stream * stream,
    const GARC_Limits * limits, const GARC_Allocator * allocator,
    GARC_Archive ** out_archive) {
  if (!stream || !out_archive) {
    return GARC_ERR_INVALID;
  }

  if (!allocator) {
    allocator = garc_allocator_default();
  }
  GARC_Archive * archive = (GARC_Archive *)gcu_allocator_calloc(
      allocator, 1, sizeof(GARC_Archive));
  if (!archive) {
    return GARC_ERR_OOM;
  }

  archive->stream = stream;
  archive->allocator = allocator;
  // Resolved once, here, so that "NULL means the defaults" is a fact about this
  // function rather than a branch every caller of the limits has to repeat.
  if (limits) {
    archive->limits = *limits;
  } else {
    garc_limits_default(&archive->limits);
  }

  // Before reader_identify(), which reads a block: this is where the archive
  // begins, and after the read it is no longer where the stream is.
  archive->start_offset = garc_stream_tell(stream);

  GARC_Result result = reader_identify(archive);
  if (result == GARC_OK) {
    result = reader_open_format(archive);
  }
  if (result != GARC_OK) {
    // reader_open_format() can have allocated before failing - zip reads its
    // comment into a buffer - so the release runs on this path as well as in
    // garc_close(). A failed open that leaked would leak once per malformed
    // archive, which is exactly the input a caller feeds in a loop.
    reader_release(archive);
    gcu_allocator_free(allocator, archive);
    return result;
  }

  *out_archive = archive;
  return GARC_OK;
}

GARC_Format garc_format(const GARC_Archive * archive) {
  return archive ? archive->format : GARC_FORMAT_UNKNOWN;
}

GARC_Result garc_reader_account(GARC_Archive * archive) {
  const GARC_Limits * limits = &archive->limits;
  const GARC_Member * member = &archive->member;

  // Each cap has its own status. A shared code could not tell a test which one
  // fired, nor a caller which one to raise.
  if (limits->max_name_bytes
      && member->name_length > limits->max_name_bytes) {
    return GARC_ERR_LIMIT_NAME_BYTES;
  }
  if (limits->max_member_bytes && member->size > limits->max_member_bytes) {
    return GARC_ERR_LIMIT_MEMBER_BYTES;
  }
  if (limits->max_members && archive->member_count >= limits->max_members) {
    return GARC_ERR_LIMIT_MEMBERS;
  }
  if (limits->max_total_bytes) {
    // Checked as a subtraction rather than by adding first: the sum of two
    // declared sizes can wrap a 64-bit counter, and a cap defeated by overflow
    // is the shape that reads as a passing gate.
    if (member->size > limits->max_total_bytes - archive->total_declared_bytes) {
      return GARC_ERR_LIMIT_TOTAL_BYTES;
    }
  }

  archive->member_count++;
  archive->total_declared_bytes += member->size;
  archive->have_member = 1;
  return GARC_OK;
}

GARC_Result garc_next(GARC_Archive * archive, const GARC_Member ** out_member) {
  if (!archive || !out_member) {
    return GARC_ERR_INVALID;
  }
  if (archive->at_end) {
    return GARC_END;
  }

  archive->have_member = 0;

  GARC_Result result;
  switch (archive->format) {
    case GARC_FORMAT_TAR:
      result = garc_tar_next(archive);
      break;
    case GARC_FORMAT_ZIP:
      result = garc_zip_next(archive);
      break;
    default:
      // reader_identify() refuses anything else, so reaching this is a bug in
      // this file rather than a fact about the input.
      //
      // **This is one of the lines `make coverage` reports as unexecuted, and it
      // is meant to stay that way.** No input can reach it: identification sets
      // TAR or ZIP and nothing else. Deleting it to make the report read higher
      // would remove the thing that turns a future format added to the enum and
      // not to this switch into a named internal error instead of falling
      // through, and this comment is why the number is not 100%.
      return GARC_ERR_INTERNAL;
  }

  if (result != GARC_OK) {
    // On any failure there is no current member, and the data cursor is cleared
    // so that a caller which ignores the status and calls read_member cannot be
    // handed bytes belonging to a member that was never reported.
    archive->have_member = 0;
    archive->data_remaining = 0;
    archive->data_padding = 0;
    return result;
  }

  *out_member = &archive->member;
  return GARC_OK;
}

/**
 * Put the archive back to the state ::garc_open() left it in.
 *
 * **Per-*walk* state only, and the split is the design rather than an
 * omission.** ::garc_tar_next() already clears everything that belongs to one
 * member at the top of every call - the pending `L`/`K` name, the `x` record set -
 * and says there that it does so for the call which *failed* partway through a
 * carrier. Resetting them here as well would be the same decision written in two
 * places, which is the pair that drifts. What does not belong to a member is
 * this function's: `pax_global`, which ::garc_tar_next() deliberately leaves
 * alone because POSIX keeps a `g` set in force until something replaces it, and
 * which therefore survives to the end of a walk and must not survive past it.
 *
 * Every line below was put in a position to fail before it was kept: removing any
 * one of the seek offset, `pax_global`, `at_end`, `peek_length`, the data cursor
 * or the counts makes a test in `test_find.cpp` fail. Three more were tried here
 * and deleted, because nothing could distinguish them:
 *
 * - `have_member`, and the pending `L`/`K` name, and the `x` record set, are
 *   *per-member* state that ::garc_next() and ::garc_tar_next() clear at the top
 *   of every call - resetting them here is the same decision in two places, and
 *   that is the pair that drifts.
 * - `tar_saw_end_marker` is *derived* state. It is computed from the blocks on
 *   the way to the point where it is read, and a second walk reads the same
 *   blocks, so its value at that point cannot depend on what it was before.
 *
 * `peek_consumed` is the one kept without a test that can see it, and the reason
 * is an invariant rather than caution: it is half of one value.
 *
 * A future format reader adding a `next` of its own inherits the same contract:
 * per-member state is its, per-walk state is here.
 *
 * The `peek` window is emptied rather than refilled. It exists so that the bytes
 * identification consumed can be put back on a stream that cannot seek; this
 * path only runs on one that can, and the format is already known, so there is
 * nothing to identify and nothing to put back.
 *
 * @param archive The archive.
 * @return ::GARC_OK, or the seek's failure.
 */
static GARC_Result reader_rewind(GARC_Archive * archive) {
  GARC_Result result
      = garc_stream_seek(archive->stream, archive->start_offset);
  if (result != GARC_OK) {
    return result;
  }

  // Written as a pair because they are one value: a length with a stale offset
  // beside it is a state no other path in this file produces.
  archive->peek_length = 0;
  archive->peek_consumed = 0;

  archive->at_end = 0;
  archive->data_remaining = 0;
  archive->data_padding = 0;
  archive->data_refusal = GARC_OK;

  // The per-*walk* state each format owns. tar's is the global pax record set;
  // zip's is where in the central directory the cursor is. Neither format's is
  // touched for the other, and what open discovered - zip's base offset, the
  // directory's position - is not touched at all, because a rewind goes back to
  // the start of the archive and not to before it was opened.
  switch (archive->format) {
    case GARC_FORMAT_TAR:
      garc_tar_pax_reset(&archive->tar.pax_global);
      break;
    case GARC_FORMAT_ZIP:
      garc_zip_rewind(archive);
      break;
    default:
      // Unreachable, and kept for the reason the switch in garc_next() gives:
      // identification sets one of the two formats above, so `make coverage`
      // reports this arm as unexecuted on purpose. A third format added to the
      // enum and not to this switch would then silently keep whatever per-walk
      // state it had, which is the bug this arm is here to make impossible to
      // write by omission.
      break;
  }

  // The caps count a walk, and this is a new one. Carrying the counts forward
  // would make garc_find() fail with GARC_ERR_LIMIT_MEMBERS on an archive whose
  // member count is merely *near* max_members, which is a cap firing on the sum
  // of two passes over the same members rather than on anything in the archive.
  archive->member_count = 0;
  archive->total_declared_bytes = 0;

  // The buffers themselves are kept: they are sized to the longest name seen so
  // far and a second walk sees the same names, so freeing them here would make
  // every find reallocate what it is about to need.
  return GARC_OK;
}

GARC_Result garc_find(GARC_Archive * archive, const void * name,
    size_t name_length, const GARC_Member ** out_member) {
  if (!archive || !out_member || (!name && name_length)) {
    return GARC_ERR_INVALID;
  }
  // Asked of the stream before anything is disturbed, so that a refusal leaves
  // the cursor exactly where the caller left it. A find that reset the walk and
  // then discovered it could not seek would be worse than useless on a pipe.
  if (!garc_stream_is_seekable(archive->stream)) {
    return GARC_ERR_NOT_SEEKABLE;
  }

  GARC_Result result = reader_rewind(archive);
  if (result != GARC_OK) {
    return result;
  }

  const GARC_Member * member = NULL;
  while ((result = garc_next(archive, &member)) == GARC_OK) {
    // Bytes, exactly, with no normalisation: this library reports the name the
    // container carries, so a directory written as `notes/` is found under
    // `notes/` and not under `notes`. A find that stripped a slash would be
    // deciding something garc_next() deliberately does not.
    if (member->name_length == name_length
        && (!name_length
            || memcmp(member->name, name, name_length) == 0)) {
      *out_member = member;
      return GARC_OK;
    }
  }
  // GARC_END when the name is not there, which leaves the archive at its end -
  // the same place a completed walk leaves it - or the failure that stopped the
  // walk.
  return result;
}

GARC_Result garc_read_member(GARC_Archive * archive, void * buffer,
    size_t capacity, size_t * out_read) {
  if (!archive || !out_read || (!buffer && capacity)) {
    return GARC_ERR_INVALID;
  }
  if (!archive->have_member) {
    return GARC_ERR_INVALID;
  }
  if (archive->format == GARC_FORMAT_ZIP && archive->data_refusal == GARC_OK) {
    // The zip reader's own read, because a zip member's bytes may have to be
    // decompressed and are checksummed either way. Dispatched here rather than
    // folded into the loop below for the reason garc_next() dispatches: a second
    // format's rules in the format-agnostic function is where the two start
    // borrowing each other's assumptions.
    return garc_zip_read(archive, buffer, capacity, out_read);
  }
  if (archive->data_refusal != GARC_OK) {
    // A member whose metadata was readable and whose bytes are not: a zip member
    // compressed with a method there is no codec for, or encrypted. Answered
    // before the size check below, because a *zero-length* member of such a kind
    // would otherwise read as a successful end of data and a caller would
    // conclude the file was empty. No bytes were produced, so the count is 0
    // rather than whatever the caller last stored there.
    *out_read = 0;
    return archive->data_refusal;
  }

  if (!archive->data_remaining || !capacity) {
    *out_read = 0;
    return GARC_OK;
  }

  // Never more than the member declared. A member that declares less than it
  // contains would otherwise leak the next header's bytes into the caller's
  // buffer, which is a wrong answer rather than an error.
  size_t want = capacity;
  if ((uint64_t)want > archive->data_remaining) {
    want = (size_t)archive->data_remaining;
  }

  size_t got = 0;
  GARC_Result result = garc_stream_read(archive->stream, buffer, want, &got);
  if (result != GARC_OK) {
    return result;
  }
  if (!got) {
    // The container said these bytes were here. Not GARC_ERR_IO: the stream did
    // what it was asked and there was nothing there.
    return GARC_ERR_CORRUPT;
  }

  archive->data_remaining -= (uint64_t)got;
  *out_read = got;
  return GARC_OK;
}

GARC_Result garc_skip_member(GARC_Archive * archive) {
  if (!archive) {
    return GARC_ERR_INVALID;
  }
  if (!archive->have_member) {
    return GARC_ERR_INVALID;
  }
  if (archive->format == GARC_FORMAT_ZIP) {
    // Nothing to read past: the next member's position comes from the central
    // directory rather than from where this member's data ends.
    return garc_zip_skip(archive);
  }
  if (!archive->data_remaining) {
    return GARC_OK;
  }

  GARC_Result result
      = garc_stream_skip(archive->stream, archive->data_remaining);
  if (result != GARC_OK) {
    return result;
  }
  archive->data_remaining = 0;
  return GARC_OK;
}

uint64_t garc_member_count(const GARC_Archive * archive) {
  return archive ? archive->member_count : 0u;
}

uint64_t garc_total_declared_bytes(const GARC_Archive * archive) {
  return archive ? archive->total_declared_bytes : 0u;
}

GARC_Tar_Variant garc_tar_member_variant(const GARC_Archive * archive) {
  if (!archive || archive->format != GARC_FORMAT_TAR) {
    return GARC_TAR_NONE;
  }
  return archive->tar.variant;
}

int garc_tar_member_checksum_was_signed(const GARC_Archive * archive) {
  return archive ? archive->tar.checksum_was_signed : 0;
}

void garc_archive_dump(const GARC_Archive * archive, FILE * out) {
  if (!out) {
    return;
  }
  if (!archive) {
    fprintf(out, "archive: (null)\n");
    return;
  }

  fprintf(out, "archive: format=%s\n", garc_format_string(archive->format));
  if (archive->format == GARC_FORMAT_TAR) {
    fprintf(out, "  tar variant: %s (checksum read as %s)\n",
        garc_tar_variant_string(archive->tar.variant),
        archive->tar.checksum_was_signed ? "signed" : "unsigned");
  }
  if (archive->format == GARC_FORMAT_ZIP) {
    fprintf(out, "  zip: %llu declared members, central directory at %llu"
        " (+%llu bytes)%s\n",
        (unsigned long long)archive->zip.declared_members,
        (unsigned long long)archive->zip.central_offset,
        (unsigned long long)archive->zip.central_size,
        archive->zip.is_zip64 ? ", zip64" : "");
    if (archive->zip.origin != archive->start_offset) {
      fprintf(out, "  zip: %llu bytes in front of the archive\n",
          (unsigned long long)(archive->zip.origin - archive->start_offset));
    }
    if (archive->have_member) {
      fprintf(out, "  zip member: method %u (%s), flags %04x, %llu compressed"
          " bytes, crc %08lx%s\n",
          (unsigned)archive->zip.method,
          garc_zip_method_string(archive->zip.method),
          (unsigned)archive->zip.flags,
          (unsigned long long)archive->zip.compressed_size,
          (unsigned long)archive->zip.crc32,
          archive->zip.encryption == GARC_ZIP_ENCRYPTION_NONE ? ""
              : garc_zip_encryption_string(archive->zip.encryption));
    }
  }
  fprintf(out, "  members: %llu\n", (unsigned long long)archive->member_count);
  fprintf(out, "  declared bytes: %llu\n",
      (unsigned long long)archive->total_declared_bytes);
  fprintf(out, "  data remaining: %llu (+%llu padding)\n",
      (unsigned long long)archive->data_remaining,
      (unsigned long long)archive->data_padding);
  fprintf(out, "  at end: %s\n", archive->at_end ? "yes" : "no");

  if (archive->have_member) {
    garc_member_dump(&archive->member, out);
  } else {
    fprintf(out, "member: (none)\n");
  }
}

void garc_close(GARC_Archive * archive) {
  if (!archive) {
    return;
  }
  // Whatever this archive's format reader allocated. For tar that is a name too
  // long for a header field, so an ordinary tar frees nothing; for zip it is the
  // per-member name and the archive comment, so an ordinary zip does.
  reader_release(archive);
  // The stream is the caller's. This library never frees what it did not
  // allocate, and a close that destroyed it would make the borrowing in
  // garc_open() a lie a caller finds out about as a double free.
  gcu_allocator_free(archive->allocator, archive);
}
