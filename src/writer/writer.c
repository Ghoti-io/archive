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
 * The format-independent half of building an archive: the member cursor, the
 * data accounting, and the end of the archive.
 *
 * Everything that knows what a tar header looks like is in `src/tar/tar_write.c`,
 * for the reason the reader is split the same way: the next format has the same
 * cursor and none of the header.
 */

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/allocator.h>
#include <ghoti.io/archive/writer.h>
#include <ghoti.io/cutil/allocator.h>
#include <stdint.h>
#include <string.h>

#include "tar/tar_internal.h"
#include "writer/writer_internal.h"

void garc_writer_options_default(GARC_Writer_Options * options) {
  if (!options) {
    return;
  }
  options->tar_variant = GARC_TAR_PAX;
  // No record padding. bsdtar's answer rather than GNU tar's: 10240 bytes was a
  // tape record, every reader accepts either, and this library's archives are
  // built in memory and handed to a caller far more often than they are written
  // to tape.
  options->blocking_factor = 0;
}

/**
 * Finish whatever the current member still owes, so that the sink is positioned
 * at a block boundary.
 *
 * Called by garc_writer_add() before the next header and by garc_writer_finish()
 * before the end marker - the two places a member can close - so the "did the
 * caller deliver what it declared" check has one home rather than two that can
 * disagree.
 *
 * @param writer The writer.
 * @return GARC_OK, GARC_ERR_INVALID when the member is short, or GARC_ERR_IO.
 */
static GARC_Result writer_close_member(GARC_Writer * writer) {
  if (!writer->have_member) {
    return GARC_OK;
  }
  if (writer->data_remaining) {
    // The header already says how many bytes there are, and it has been written.
    // Padding to fit would make the archive claim data it does not have; letting
    // it through would put the next header where a reader is not looking for one.
    return GARC_ERR_INVALID;
  }
  GARC_Result result = garc_sink_fill(writer->sink, 0, writer->data_padding);
  if (result != GARC_OK) {
    return result;
  }
  writer->data_padding = 0;
  writer->have_member = 0;
  return GARC_OK;
}

GARC_Result garc_writer_create(GARC_Sink * sink, GARC_Format format,
    const GARC_Writer_Options * options, GARC_Writer ** out_writer) {
  return garc_writer_create_with_allocator(
      sink, format, options, NULL, out_writer);
}

GARC_Result garc_writer_create_with_allocator(GARC_Sink * sink,
    GARC_Format format, const GARC_Writer_Options * options,
    const GARC_Allocator * allocator, GARC_Writer ** out_writer) {
  if (!out_writer || !sink) {
    return GARC_ERR_INVALID;
  }

  GARC_Writer_Options resolved;
  garc_writer_options_default(&resolved);
  if (options) {
    resolved = *options;
  }

  if (format != GARC_FORMAT_TAR) {
    // GARC_FORMAT_UNKNOWN included: a caller who has not said what to write has
    // not said it, and there is no format to guess at from a sink.
    return format == GARC_FORMAT_UNKNOWN ? GARC_ERR_INVALID
                                         : GARC_ERR_UNSUPPORTED;
  }
  switch (resolved.tar_variant) {
    case GARC_TAR_PAX:
    case GARC_TAR_USTAR:
      break;
    case GARC_TAR_NONE:
      // What a zero-filled options struct holds. Refused rather than treated as
      // the default, so that a caller who meant to choose and forgot is told;
      // NULL is how a caller says they do not mind.
      return GARC_ERR_INVALID;
    default:
      // v7 and GNU. Both are read, neither is written; writer.h says why.
      return GARC_ERR_UNSUPPORTED;
  }

  if (!allocator) {
    allocator = garc_allocator_default();
  }
  GARC_Writer * writer
      = (GARC_Writer *)gcu_allocator_calloc(allocator, 1, sizeof(GARC_Writer));
  if (!writer) {
    return GARC_ERR_OOM;
  }
  writer->sink = sink;
  writer->allocator = allocator;
  writer->format = format;
  writer->options = resolved;

  *out_writer = writer;
  return GARC_OK;
}

GARC_Result garc_writer_add(GARC_Writer * writer, const GARC_Member * member) {
  if (!writer || !member) {
    return GARC_ERR_INVALID;
  }
  if (writer->finished) {
    return GARC_ERR_INVALID;
  }

  GARC_Result result = writer_close_member(writer);
  if (result != GARC_OK) {
    return result;
  }

  result = garc_tar_write_member(writer, member);
  if (result != GARC_OK) {
    // have_member stays clear: a header that was not written describes nothing,
    // and leaving a member open would make the next add() pad for data that has
    // no header in front of it.
    return result;
  }

  writer->member_count++;
  writer->have_member = 1;
  return GARC_OK;
}

GARC_Result garc_writer_write(
    GARC_Writer * writer, const void * data, size_t size) {
  if (!writer || (!data && size)) {
    return GARC_ERR_INVALID;
  }
  if (!writer->have_member || writer->finished) {
    return GARC_ERR_INVALID;
  }
  if ((uint64_t)size > writer->data_remaining) {
    // Refused here rather than at the end: the header is already written and
    // says how long the member is, so these bytes have nowhere to go. Writing
    // them and reporting afterwards would leave the archive unrecoverable.
    return GARC_ERR_INVALID;
  }
  if (!size) {
    return GARC_OK;
  }

  GARC_Result result = garc_sink_write(writer->sink, data, size);
  if (result != GARC_OK) {
    return result;
  }
  writer->data_remaining -= (uint64_t)size;
  return GARC_OK;
}

GARC_Result garc_writer_finish(GARC_Writer * writer) {
  if (!writer || writer->finished) {
    return GARC_ERR_INVALID;
  }

  GARC_Result result = writer_close_member(writer);
  if (result != GARC_OK) {
    return result;
  }

  result = garc_tar_write_end(writer);
  if (result != GARC_OK) {
    return result;
  }
  writer->finished = 1;
  return GARC_OK;
}

uint64_t garc_writer_member_count(const GARC_Writer * writer) {
  return writer ? writer->member_count : 0u;
}

uint64_t garc_writer_data_remaining(const GARC_Writer * writer) {
  return writer ? writer->data_remaining : 0u;
}

void garc_writer_dump(const GARC_Writer * writer, FILE * out) {
  if (!out) {
    return;
  }
  if (!writer) {
    fprintf(out, "GARC_Writer: (null)\n");
    return;
  }
  fprintf(out, "GARC_Writer: format=%s variant=%s blocking=%u\n",
      garc_format_string(writer->format),
      garc_tar_variant_string(writer->options.tar_variant),
      (unsigned)writer->options.blocking_factor);
  fprintf(out, "  members=%llu offset=%llu finished=%d\n",
      (unsigned long long)writer->member_count,
      (unsigned long long)garc_sink_tell(writer->sink), writer->finished);
  if (writer->have_member) {
    fprintf(out, "  member open: %llu data bytes owed, %llu padding\n",
        (unsigned long long)writer->data_remaining,
        (unsigned long long)writer->data_padding);
  }
}

void garc_writer_destroy(GARC_Writer * writer) {
  if (!writer) {
    return;
  }
  const GARC_Allocator * allocator = writer->allocator;
  garc_tar_buffer_free(allocator, &writer->records);
  gcu_allocator_free(allocator, writer);
}
