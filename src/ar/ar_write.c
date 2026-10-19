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
 * The ar writer.
 *
 * **Names are written the way that streams.** GNU's long-name convention puts a
 * table of names in a member that must come *before* the members that point into
 * it, which a writer that learns the names one member at a time cannot do
 * without holding the archive back. BSD's puts the name at the front of its own
 * member's data, which needs nothing but the name. So a name that fits the
 * 16-byte field in the System V form - at most 15 bytes and a closing `/` - is
 * written that way, and every other name is written as `#1/N` followed by its
 * bytes. Every reader takes both; GNU `ar` reads the BSD form too.
 *
 * "Every other name" is more than the long ones: a name containing `/` cannot
 * be a System V name, a name ending in a space would lose it, and a name that
 * begins with `/` or `#1/` would be read as one of the format's own markers.
 * Those are written in the BSD form whatever their length.
 *
 * **Only regular files.** ar has no directory, no link and no device, and a
 * member of another type is ::GARC_ERR_UNSUPPORTED rather than a file that
 * pretends. The sizes are decimal in ten digits, the owner ids six, and a field
 * that does not fit is refused before the header is written.
 */

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/writer.h>
#include <string.h>

#include "ar_internal.h"

/** The eight bytes every ar archive begins with. */
#define AR_MAGIC "!<arch>\n"

/** Write @p value as @p width digits of @p base, left-aligned, space padded. */
static int ar_put(uint8_t * field, size_t width, unsigned base, uint64_t value) {
  char digits[24];
  size_t count = 0;
  do {
    digits[count++] = (char)('0' + (unsigned)(value % base));
    value /= base;
  } while (value);
  if (count > width) {
    return 0;
  }
  memset(field, ' ', width);
  for (size_t i = 0; i < count; ++i) {
    field[i] = (uint8_t)digits[count - 1u - i];
  }
  return 1;
}

GARC_Result garc_ar_write_member(
    GARC_Writer * writer, const GARC_Member * member) {
  if (!member->name || !member->name_length
      || memchr(member->name, '\0', member->name_length)) {
    return GARC_ERR_INVALID;
  }
  if (member->type != GARC_MEMBER_FILE) {
    return GARC_ERR_UNSUPPORTED;
  }

  const int short_form = member->name_length <= 15u
      && !memchr(member->name, '/', member->name_length)
      && member->name[member->name_length - 1u] != ' '
      && !(member->name_length >= 3u && memcmp(member->name, "#1/", 3u) == 0);
  const uint64_t embedded = short_form ? 0u : member->name_length;
  if (member->size > UINT64_MAX - embedded) {
    return GARC_ERR_UNSUPPORTED;
  }
  const uint64_t total = member->size + embedded;

  uint8_t header[60];
  memset(header, ' ', sizeof(header));
  if (short_form) {
    memcpy(header, member->name, member->name_length);
    header[member->name_length] = '/';
  }
  else {
    header[0] = '#';
    header[1] = '1';
    header[2] = '/';
    if (!ar_put(header + 3, 13, 10, embedded)) {
      return GARC_ERR_UNSUPPORTED;
    }
  }
  uint64_t mtime = 0;
  if (member->mtime_source != GARC_TIME_NONE || member->mtime_seconds) {
    if (member->mtime_seconds < 0) {
      return GARC_ERR_INVALID;
    }
    mtime = (uint64_t)member->mtime_seconds;
  }
  const uint64_t uid = member->ids_valid ? (uint64_t)member->uid : 0u;
  const uint64_t gid = member->ids_valid ? (uint64_t)member->gid : 0u;
  if (member->ids_valid && (member->uid < 0 || member->gid < 0)) {
    return GARC_ERR_INVALID;
  }
  const uint64_t mode = 0100000u
      | (member->mode_valid ? (member->mode & 07777u) : 0644u);
  if (!ar_put(header + 16, 12, 10, mtime) || !ar_put(header + 28, 6, 10, uid)
      || !ar_put(header + 34, 6, 10, gid) || !ar_put(header + 40, 8, 8, mode)) {
    return GARC_ERR_INVALID;
  }
  if (!ar_put(header + 48, 10, 10, total)) {
    return GARC_ERR_UNSUPPORTED;
  }
  header[58] = '`';
  header[59] = '\n';

  GARC_Result result = GARC_OK;
  if (!writer->ar.started) {
    result = garc_sink_write(writer->sink, AR_MAGIC, 8u);
    if (result != GARC_OK) {
      return result;
    }
    writer->ar.started = 1;
  }
  result = garc_sink_write(writer->sink, header, sizeof(header));
  if (result == GARC_OK && embedded) {
    result = garc_sink_write(writer->sink, member->name, member->name_length);
  }
  if (result != GARC_OK) {
    return result;
  }
  writer->data_remaining = member->size;
  writer->data_padding = total & 1u;
  return GARC_OK;
}

GARC_Result garc_ar_write_close_member(GARC_Writer * writer) {
  if (!writer->data_padding) {
    return GARC_OK;
  }
  return garc_sink_write(writer->sink, "\n", 1u);
}

GARC_Result garc_ar_write_end(GARC_Writer * writer) {
  if (writer->ar.started) {
    return GARC_OK;
  }
  // An archive of nothing is the magic and nothing else, which every reader
  // takes as an empty one.
  writer->ar.started = 1;
  return garc_sink_write(writer->sink, AR_MAGIC, 8u);
}

void garc_ar_write_release(GARC_Writer * writer) {
  (void)writer;
}
