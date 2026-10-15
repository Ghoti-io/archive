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
 * The cpio writer: newc, or odc.
 *
 * Both are streamed. A cpio header carries the size and the name and nothing
 * that is known only afterwards, which is why neither needs a sink that can go
 * back. What the writer remembers is the padding a member still owes: newc
 * aligns the name and the data to four bytes, odc to nothing.
 *
 * **Inodes are numbered here**, from one, because cpio wants each member to have
 * one and a caller has none to give: they are what a reader uses to tell a hard
 * link from a coincidence, and numbering every member distinctly says that
 * none is one. A hard link member is therefore ::GARC_ERR_UNSUPPORTED, as are
 * sockets and ::GARC_MEMBER_OTHER; a symlink's target is written as its data, a
 * device carries its major and minor, and a fifo and a directory carry no data.
 *
 * **The trailer is a member** called `TRAILER!!!`, and the archive is then padded
 * with zeros to a multiple of 512 bytes, which is what every cpio writer does
 * and what a tape wants. Every size is checked against its field before the
 * header goes out, so a refusal writes nothing.
 */

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/writer.h>
#include <string.h>

#include "cpio_internal.h"

#define CPIO_BLOCK 512u

static void put_hex(uint8_t * out, uint64_t value) {
  static const char digits[] = "0123456789abcdef";
  for (int i = 7; i >= 0; --i) {
    out[i] = (uint8_t)digits[value & 0xFu];
    value >>= 4;
  }
}

static void put_octal(uint8_t * out, size_t width, uint64_t value) {
  for (size_t i = width; i-- > 0;) {
    out[i] = (uint8_t)('0' + (value & 7u));
    value >>= 3;
  }
}

/** One header, name and its padding, to the sink. */
static GARC_Result cpio_header(GARC_Writer * writer, uint64_t ino,
    uint64_t mode, uint64_t uid, uint64_t gid, uint64_t nlink, uint64_t mtime,
    uint64_t size, uint64_t rdev_major, uint64_t rdev_minor, const char * name,
    size_t name_length) {
  const int odc = writer->options.cpio_variant == GARC_CPIO_ODC;
  uint8_t header[110];
  size_t length;
  if (!odc) {
    length = 110u;
    memcpy(header, "070701", 6u);
    put_hex(header + 6, ino);
    put_hex(header + 14, mode);
    put_hex(header + 22, uid);
    put_hex(header + 30, gid);
    put_hex(header + 38, nlink);
    put_hex(header + 46, mtime);
    put_hex(header + 54, size);
    put_hex(header + 62, 0u);
    put_hex(header + 70, 0u);
    put_hex(header + 78, rdev_major);
    put_hex(header + 86, rdev_minor);
    put_hex(header + 94, name_length + 1u);
    put_hex(header + 102, 0u);
  }
  else {
    length = 76u;
    memcpy(header, "070707", 6u);
    put_octal(header + 6, 6, 0u);
    put_octal(header + 12, 6, ino);
    put_octal(header + 18, 6, mode);
    put_octal(header + 24, 6, uid);
    put_octal(header + 30, 6, gid);
    put_octal(header + 36, 6, nlink);
    put_octal(header + 42, 6, (rdev_major << 8) | rdev_minor);
    put_octal(header + 48, 11, mtime);
    put_octal(header + 59, 6, name_length + 1u);
    put_octal(header + 65, 11, size);
  }
  GARC_Result result = garc_sink_write(writer->sink, header, length);
  if (result == GARC_OK) {
    result = garc_sink_write(writer->sink, name, name_length);
  }
  if (result == GARC_OK) {
    result = garc_sink_write(writer->sink, "\0\0\0\0", 1u);
  }
  if (result == GARC_OK && !odc) {
    const size_t pad = (4u - ((length + name_length + 1u) & 3u)) & 3u;
    if (pad) {
      result = garc_sink_write(writer->sink, "\0\0\0", pad);
    }
  }
  return result;
}

GARC_Result garc_cpio_write_member(
    GARC_Writer * writer, const GARC_Member * member) {
  const int odc = writer->options.cpio_variant == GARC_CPIO_ODC;
  if (!member->name || !member->name_length
      || memchr(member->name, '\0', member->name_length)) {
    return GARC_ERR_INVALID;
  }
  const uint64_t name_max = odc ? 0777776u : 0xFFFFFFFEu;
  if (member->name_length > name_max) {
    return GARC_ERR_UNSUPPORTED;
  }
  if (member->name_length == 10u && memcmp(member->name, "TRAILER!!!", 10u) == 0) {
    return GARC_ERR_INVALID; // It would end the archive early.
  }

  uint64_t type_bits = 0;
  uint64_t nlink = 1;
  const char * data = NULL;
  uint64_t size = member->size;
  uint64_t major = 0;
  uint64_t minor = 0;
  switch (member->type) {
    case GARC_MEMBER_FILE:
      type_bits = 0100000u;
      break;
    case GARC_MEMBER_DIRECTORY:
      if (member->size) {
        return GARC_ERR_INVALID;
      }
      type_bits = 040000u;
      nlink = 2;
      break;
    case GARC_MEMBER_SYMLINK:
      if (!member->link_target || !member->link_target_length || member->size
          || memchr(member->link_target, '\0', member->link_target_length)) {
        return GARC_ERR_INVALID;
      }
      type_bits = 0120000u;
      data = member->link_target;
      size = member->link_target_length;
      break;
    case GARC_MEMBER_FIFO:
      type_bits = 010000u;
      if (member->size) {
        return GARC_ERR_INVALID;
      }
      break;
    case GARC_MEMBER_CHAR_DEVICE:
    case GARC_MEMBER_BLOCK_DEVICE:
      type_bits = member->type == GARC_MEMBER_CHAR_DEVICE ? 020000u : 060000u;
      if (member->size) {
        return GARC_ERR_INVALID;
      }
      major = member->device_major;
      minor = member->device_minor;
      if (odc ? (major > 0xFFu || minor > 0xFFu)
              : (major > 0xFFFFFFFFu || minor > 0xFFFFFFFFu)) {
        return GARC_ERR_INVALID;
      }
      break;
    default:
      return GARC_ERR_UNSUPPORTED;
  }

  const uint64_t size_max = odc ? 077777777777ull : 0xFFFFFFFFull;
  const uint64_t id_max = odc ? 0777777u : 0xFFFFFFFFu;
  const uint64_t time_max = odc ? 077777777777ull : 0xFFFFFFFFull;
  if (size > size_max) {
    return GARC_ERR_UNSUPPORTED;
  }
  if (member->ids_valid && (member->uid < 0 || member->gid < 0
          || (uint64_t)member->uid > id_max || (uint64_t)member->gid > id_max)) {
    return GARC_ERR_INVALID;
  }
  uint64_t mtime = 0;
  if (member->mtime_source != GARC_TIME_NONE || member->mtime_seconds) {
    if (member->mtime_seconds < 0 || (uint64_t)member->mtime_seconds > time_max) {
      return GARC_ERR_INVALID;
    }
    mtime = (uint64_t)member->mtime_seconds;
  }
  const uint64_t ino = writer->cpio.inode + 1u;
  if (odc && ino > 0777777u) {
    return GARC_ERR_UNSUPPORTED;
  }
  const uint64_t mode = type_bits
      | (member->mode_valid ? (member->mode & 07777u) : 0644u);

  GARC_Result result = cpio_header(writer, ino, mode,
      member->ids_valid ? (uint64_t)member->uid : 0u,
      member->ids_valid ? (uint64_t)member->gid : 0u, nlink, mtime, size, major,
      minor, member->name, member->name_length);
  if (result != GARC_OK) {
    return result;
  }
  ++writer->cpio.inode;
  writer->data_remaining = data ? 0u : size;
  writer->data_padding = odc ? 0u : ((4u - (size & 3u)) & 3u);
  if (data) {
    result = garc_sink_write(writer->sink, data, (size_t)size);
    if (result != GARC_OK) {
      return result;
    }
  }
  return GARC_OK;
}

GARC_Result garc_cpio_write_close_member(GARC_Writer * writer) {
  if (!writer->data_padding) {
    return GARC_OK;
  }
  return garc_sink_write(writer->sink, "\0\0\0", (size_t)writer->data_padding);
}

GARC_Result garc_cpio_write_end(GARC_Writer * writer) {
  GARC_Result result = cpio_header(
      writer, 0u, 0u, 0u, 0u, 1u, 0u, 0u, 0u, 0u, "TRAILER!!!", 10u);
  if (result != GARC_OK) {
    return result;
  }
  const uint64_t written = garc_sink_tell(writer->sink);
  const size_t pad = (size_t)((CPIO_BLOCK - (written % CPIO_BLOCK)) % CPIO_BLOCK);
  static const uint8_t zeros[CPIO_BLOCK] = {0};
  return pad ? garc_sink_write(writer->sink, zeros, pad) : GARC_OK;
}

void garc_cpio_write_release(GARC_Writer * writer) {
  (void)writer;
}
