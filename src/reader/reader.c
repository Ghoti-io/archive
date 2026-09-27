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

const char * garc_format_string(GARC_Format format) {
  switch (format) {
    case GARC_FORMAT_UNKNOWN:
      return "unknown";
    case GARC_FORMAT_TAR:
      return "tar";
    case GARC_FORMAT_COUNT:
    default:
      return "invalid";
  }
}

/**
 * Identify the container, keeping the bytes that were looked at.
 *
 * **Identification does not seek.** Putting the bytes back by seeking to zero
 * would work on a file and fail on a pipe, which would make "tar can be read
 * from a pipe" - the reason this library has a callback stream at all - false
 * for every archive. So the window is kept in the archive and the format reader
 * drains it first.
 *
 * The window is one tar block today. zip is identified from its *end*, so when
 * it arrives this grows a second question rather than a second window: "is this
 * a tar" is answered from the front and cheaply, and only a stream that can seek
 * can be asked the other one.
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

  return GARC_ERR_FORMAT;
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

  GARC_Result result = reader_identify(archive);
  if (result != GARC_OK) {
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
    default:
      // reader_identify() refuses anything else, so reaching this is a bug in
      // this file rather than a fact about the input.
      //
      // **This is the one line `make coverage` reports as unexecuted, and it is
      // meant to stay that way.** No input can reach it: the only format
      // identification sets is TAR. Deleting it to make the report read 100%
      // would remove the thing that turns a future format added to the enum and
      // not to this switch into a named internal error instead of falling
      // through - so the number is 99.7% on purpose, and this comment is why.
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

GARC_Result garc_read_member(GARC_Archive * archive, void * buffer,
    size_t capacity, size_t * out_read) {
  if (!archive || !out_read || (!buffer && capacity)) {
    return GARC_ERR_INVALID;
  }
  if (!archive->have_member) {
    return GARC_ERR_INVALID;
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
  return archive->tar_variant;
}

int garc_tar_member_checksum_was_signed(const GARC_Archive * archive) {
  return archive ? archive->tar_checksum_was_signed : 0;
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
        garc_tar_variant_string(archive->tar_variant),
        archive->tar_checksum_was_signed ? "signed" : "unsigned");
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
  // The stream is the caller's. This library never frees what it did not
  // allocate, and a close that destroyed it would make the borrowing in
  // garc_open() a lie a caller finds out about as a double free.
  gcu_allocator_free(archive->allocator, archive);
}
