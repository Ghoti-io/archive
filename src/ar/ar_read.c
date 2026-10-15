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
 * The ar reader.
 *
 * **ar is a flat list of 60-byte headers and their data**, each member padded
 * to an even length with a newline, after an 8-byte magic. It has no directory,
 * no central index and no compression, so it is read straight through, from a
 * pipe if need be.
 *
 * **The format is three formats that share a header.** A name is 16 bytes, and
 * what to do when the real one does not fit is a convention:
 *
 * - *System V and GNU* end a short name with `/` so that names with trailing
 *   spaces survive, put a symbol table in a member called `/`, and keep names
 *   longer than 15 bytes in a member called `//` that later headers point into
 *   as `/offset`.
 * - *BSD* writes `#1/N` and puts the N-byte name at the start of the member's
 *   data, counted in the header's size.
 * - *Common* is neither: the name is the field with trailing spaces removed.
 *
 * All three are read. The symbol tables - `/`, `/SYM64/`, and BSD's
 * `__.SYMDEF` family - are an index for a linker and not files, and are
 * consumed without being reported; so is the `//` table, which is metadata for
 * the members behind it. A member whose name is *really* `__.SYMDEF` after
 * a real member is a file and is reported.
 *
 * **What ar does not have**, and so reports as unset: directories, links, an
 * owner's name, and a time finer than a second. Every member is a regular file.
 */

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/allocator.h>
#include <ghoti.io/archive/reader.h>
#include <string.h>

#include "../core/buffer_internal.h"
#include "../tar/tar_internal.h"
#include "ar_internal.h"

#define AR_MAGIC "!<arch>\n"
#define AR_MAGIC_LENGTH 8u
#define AR_HEADER 60u

/** The most a `//` table may hold, so a hostile size cannot allocate freely. */
#define AR_MAX_TABLE (16u * 1024u * 1024u)

int garc_ar_identify(const uint8_t * bytes, size_t length) {
  return length >= AR_MAGIC_LENGTH && memcmp(bytes, AR_MAGIC, AR_MAGIC_LENGTH) == 0;
}

/**
 * Parse a space-padded decimal or octal field.
 *
 * A blank field is zero, which is what `//` and the symbol tables carry in
 * their mode. Anything but digits and spaces is corrupt.
 */
static GARC_Result ar_number(const uint8_t * field, size_t length,
    unsigned base, uint64_t * out, int * out_blank) {
  size_t end = length;
  while (end && field[end - 1u] == ' ') {
    --end;
  }
  size_t at = 0;
  while (at < end && field[at] == ' ') {
    ++at;
  }
  *out_blank = at == end;
  uint64_t value = 0;
  for (; at < end; ++at) {
    const unsigned digit = (unsigned)field[at] - '0';
    if (digit >= base) {
      return GARC_ERR_CORRUPT;
    }
    if (value > (UINT64_MAX - digit) / base) {
      return GARC_ERR_CORRUPT;
    }
    value = value * base + digit;
  }
  *out = value;
  return GARC_OK;
}

/** Set the name buffer from bytes, with a terminator for convenience. */
static GARC_Result ar_set_name(
    GARC_Archive * archive, const uint8_t * bytes, size_t length) {
  GARC_Buffer * name = &archive->ar.name;
  GARC_Result result = garc_buffer_grow(archive->allocator, name, length);
  if (result != GARC_OK) {
    return result;
  }
  if (length) {
    memcpy(name->bytes, bytes, length);
  }
  name->length = length;
  name->bytes[length] = '\0';
  return GARC_OK;
}

void garc_ar_rewind(GARC_Archive * archive) {
  // The table is rebuilt by the second walk exactly as the first built it, and
  // keeping it would let a header point into bytes the walk has not reached.
  archive->ar.have_table = 0;
  archive->ar.table.length = 0;
  archive->ar.seen_member = 0;
}

void garc_ar_release(GARC_Archive * archive) {
  garc_buffer_free(archive->allocator, &archive->ar.name);
  garc_buffer_free(archive->allocator, &archive->ar.table);
}

/** Read exactly @p count bytes into @p destination; short is corrupt. */
static GARC_Result ar_read_exact(
    GARC_Archive * archive, uint8_t * destination, size_t count) {
  size_t got = 0;
  GARC_Result result = garc_tar_read(archive, destination, count, &got);
  if (result != GARC_OK) {
    return result;
  }
  return got == count ? GARC_OK : GARC_ERR_CORRUPT;
}

GARC_Result garc_ar_next(GARC_Archive * archive) {
  GARC_Ar_State * ar = &archive->ar;
  GARC_Member * member = &archive->member;

  if (archive->data_remaining || archive->data_padding) {
    GARC_Result skipped = garc_reader_discard(
        archive, archive->data_remaining + archive->data_padding);
    archive->data_remaining = 0;
    archive->data_padding = 0;
    if (skipped != GARC_OK) {
      return skipped;
    }
  }

  // The magic is the first thing in the stream, once. Position says whether it
  // has been read, so a second walk after a rewind reads it again.
  if (garc_tar_offset(archive) == archive->start_offset) {
    uint8_t magic[AR_MAGIC_LENGTH];
    GARC_Result result = ar_read_exact(archive, magic, sizeof(magic));
    if (result != GARC_OK) {
      return result;
    }
    if (memcmp(magic, AR_MAGIC, sizeof(magic)) != 0) {
      return GARC_ERR_CORRUPT;
    }
  }

  for (;;) {
    const uint64_t header_offset = garc_tar_offset(archive);
    uint8_t header[AR_HEADER];
    size_t got = 0;
    GARC_Result result = garc_tar_read(archive, header, sizeof(header), &got);
    if (result != GARC_OK) {
      return result;
    }
    if (got == 0) {
      archive->at_end = 1;
      return GARC_END;
    }
    if (got != sizeof(header)) {
      return GARC_ERR_CORRUPT;
    }
    if (header[58] != '`' || header[59] != '\n') {
      return GARC_ERR_CORRUPT;
    }

    uint64_t mtime = 0, uid = 0, gid = 0, mode = 0, size = 0;
    int b_mtime, b_uid, b_gid, b_mode, b_size;
    if (ar_number(header + 16, 12, 10, &mtime, &b_mtime) != GARC_OK
        || ar_number(header + 28, 6, 10, &uid, &b_uid) != GARC_OK
        || ar_number(header + 34, 6, 10, &gid, &b_gid) != GARC_OK
        || ar_number(header + 40, 8, 8, &mode, &b_mode) != GARC_OK
        || ar_number(header + 48, 10, 10, &size, &b_size) != GARC_OK
        || b_size) {
      return GARC_ERR_CORRUPT;
    }

    // The name field with its trailing spaces gone.
    size_t name_length = 16u;
    while (name_length && header[name_length - 1u] == ' ') {
      --name_length;
    }
    const uint8_t * field = header;
    uint64_t data_size = size;
    const uint64_t padding = size & 1u;
    int skip_member = 0;     // Consume the data and report nothing.
    int is_table = 0;        // The `//` member.

    const size_t cap = archive->limits.max_name_bytes
        ? archive->limits.max_name_bytes : (size_t)4096u;

    if (name_length == 2u && field[0] == '/' && field[1] == '/') {
      is_table = 1;
    }
    else if ((name_length == 1u && field[0] == '/')
        || (name_length == 7u && memcmp(field, "/SYM64/", 7u) == 0)) {
      skip_member = 1; // A GNU symbol table.
    }
    else if (name_length > 3u && memcmp(field, "#1/", 3u) == 0) {
      // BSD: the name is the first N bytes of the data.
      uint64_t embedded = 0;
      int blank = 0;
      if (ar_number(field + 3, name_length - 3u, 10, &embedded, &blank) != GARC_OK
          || blank || embedded > size) {
        return GARC_ERR_CORRUPT;
      }
      if (embedded > cap) {
        return GARC_ERR_LIMIT_NAME_BYTES;
      }
      uint8_t buffer[4096];
      if (embedded > sizeof(buffer)) {
        return GARC_ERR_LIMIT_NAME_BYTES;
      }
      result = ar_read_exact(archive, buffer, (size_t)embedded);
      if (result != GARC_OK) {
        return result;
      }
      size_t length = (size_t)embedded;
      while (length && buffer[length - 1u] == '\0') {
        --length;
      }
      result = ar_set_name(archive, buffer, length);
      if (result != GARC_OK) {
        return result;
      }
      data_size = size - embedded;
      if (!ar->seen_member && length >= 9u
          && memcmp(buffer, "__.SYMDEF", 9u) == 0) {
        skip_member = 1; // A BSD symbol table.
      }
      field = NULL;
    }
    else if (name_length > 1u && field[0] == '/' && field[1] >= '0'
        && field[1] <= '9') {
      // GNU: an offset into the `//` table.
      uint64_t offset = 0;
      int blank = 0;
      if (ar_number(field + 1, name_length - 1u, 10, &offset, &blank) != GARC_OK
          || blank || !ar->have_table || offset >= ar->table.length) {
        return GARC_ERR_CORRUPT;
      }
      size_t end = (size_t)offset;
      while (end < ar->table.length && ar->table.bytes[end] != '\n') {
        ++end;
      }
      size_t length = end - (size_t)offset;
      if (length && ar->table.bytes[(size_t)offset + length - 1u] == '/') {
        --length;
      }
      if (length > cap) {
        return GARC_ERR_LIMIT_NAME_BYTES;
      }
      result = ar_set_name(
          archive, (const uint8_t *)ar->table.bytes + offset, length);
      if (result != GARC_OK) {
        return result;
      }
      field = NULL;
    }
    else if (!ar->seen_member && name_length >= 9u
        && memcmp(field, "__.SYMDEF", 9u) == 0) {
      skip_member = 1; // A BSD symbol table with a short name.
    }

    if (is_table) {
      if (size > AR_MAX_TABLE) {
        return GARC_ERR_LIMIT_EXTRA_BYTES;
      }
      result = garc_buffer_grow(archive->allocator, &ar->table, (size_t)size);
      if (result != GARC_OK) {
        return result;
      }
      result = ar_read_exact(archive, (uint8_t *)ar->table.bytes, (size_t)size);
      if (result != GARC_OK) {
        return result;
      }
      ar->table.length = (size_t)size;
      ar->table.bytes[size] = '\0';
      ar->have_table = 1;
      if (padding) {
        result = garc_reader_discard(archive, padding);
        if (result != GARC_OK) {
          return result;
        }
      }
      continue;
    }

    if (skip_member) {
      result = garc_reader_discard(archive, data_size + padding);
      if (result != GARC_OK) {
        return result;
      }
      continue;
    }

    if (field) {
      // A plain name: GNU's trailing slash goes, and nothing else does.
      size_t length = name_length;
      if (length > 1u && field[length - 1u] == '/') {
        --length;
      }
      result = ar_set_name(archive, field, length);
      if (result != GARC_OK) {
        return result;
      }
    }
    if (!ar->name.length) {
      return GARC_ERR_CORRUPT;
    }

    memset(member, 0, sizeof(*member));
    member->name = ar->name.bytes;
    member->name_length = ar->name.length;
    member->type = GARC_MEMBER_FILE;
    member->size = data_size;
    member->mtime_seconds = (int64_t)(mtime > (uint64_t)INT64_MAX
        ? (uint64_t)INT64_MAX : mtime);
    member->mtime_source = b_mtime ? GARC_TIME_NONE : GARC_TIME_UNIX;
    if (!b_mode) {
      member->mode = (uint32_t)(mode & 07777u);
      member->mode_valid = 1;
    }
    if (!b_uid || !b_gid) {
      member->uid = (int64_t)uid;
      member->gid = (int64_t)gid;
      member->ids_valid = 1;
    }
    member->header_offset = header_offset;
    member->data_offset = garc_tar_offset(archive);

    result = garc_reader_account(archive);
    if (result != GARC_OK) {
      return result;
    }
    archive->data_remaining = data_size;
    archive->data_padding = padding;
    ar->seen_member = 1;
    return GARC_OK;
  }
}
