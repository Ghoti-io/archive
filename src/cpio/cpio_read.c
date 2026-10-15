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
 * The cpio reader.
 *
 * **cpio is a header, a name, and data, repeated, until a member called
 * `TRAILER!!!`.** Three of its dialects are text and are read; the fourth is a
 * binary struct whose byte order is the machine's and is refused by name.
 *
 * - `070701` *newc*, SVR4: thirteen 8-digit hex fields after the magic, the name
 *   padded so that header plus name is a multiple of four, the data padded the
 *   same. This is Linux's initramfs and RPM's payload.
 * - `070702` *crc*: newc, whose `check` field is the sum of the data's bytes.
 *   That sum is checked when a member's last byte is read, as zip checks a CRC.
 * - `070707` *odc*, POSIX: eleven octal fields, no padding at all.
 *
 * **Types come from the mode's high bits,** as in a stat. A symlink's target is
 * its data and is read eagerly into the member, as tar's `linkname` is; a
 * character or block device carries its numbers; a socket is
 * ::GARC_MEMBER_OTHER. A *hard link* is not recognised as one: cpio writes the
 * data once and gives the other names a size of zero, and nothing in a header
 * says which name is the other half, so each is reported as the file it is.
 *
 * **The sizes are 32 bits** in newc and 33 in odc, so a member over 4 GiB cannot
 * exist and nothing here has to widen.
 */

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/allocator.h>
#include <ghoti.io/archive/reader.h>
#include <string.h>

#include "../core/buffer_internal.h"
#include "../tar/tar_internal.h"
#include "cpio_internal.h"

#define CPIO_NEWC_HEADER 110u
#define CPIO_ODC_HEADER 76u
#define CPIO_TRAILER "TRAILER!!!"

int garc_cpio_identify(const uint8_t * bytes, size_t length) {
  return length >= 6u && memcmp(bytes, "07070", 5u) == 0
      && (bytes[5] == '1' || bytes[5] == '2' || bytes[5] == '7');
}

int garc_cpio_identify_binary(const uint8_t * bytes, size_t length) {
  // The binary header's magic is 070707 octal in a 16-bit word, in either byte
  // order. Recognised so that it is refused as unsupported rather than as
  // unknown, which is a different thing for a caller to be told.
  return length >= 2u
      && ((bytes[0] == 0xC7u && bytes[1] == 0x71u)
          || (bytes[0] == 0x71u && bytes[1] == 0xC7u));
}

void garc_cpio_rewind(GARC_Archive * archive) {
  archive->cpio.check_active = 0;
}

void garc_cpio_release(GARC_Archive * archive) {
  garc_buffer_free(archive->allocator, &archive->cpio.name);
  garc_buffer_free(archive->allocator, &archive->cpio.link);
}

static GARC_Result cpio_read_exact(
    GARC_Archive * archive, uint8_t * destination, size_t count) {
  size_t got = 0;
  GARC_Result result = garc_tar_read(archive, destination, count, &got);
  if (result != GARC_OK) {
    return result;
  }
  return got == count ? GARC_OK : GARC_ERR_CORRUPT;
}

/** A fixed-width field of digits in @p base; anything else is corrupt. */
static GARC_Result cpio_field(
    const uint8_t * text, size_t width, unsigned base, uint64_t * out) {
  uint64_t value = 0;
  for (size_t i = 0; i < width; ++i) {
    unsigned digit;
    const uint8_t c = text[i];
    if (c >= '0' && c <= '9') {
      digit = (unsigned)(c - '0');
    }
    else if (c >= 'a' && c <= 'f') {
      digit = (unsigned)(c - 'a') + 10u;
    }
    else if (c >= 'A' && c <= 'F') {
      digit = (unsigned)(c - 'A') + 10u;
    }
    else {
      return GARC_ERR_CORRUPT;
    }
    if (digit >= base) {
      return GARC_ERR_CORRUPT;
    }
    value = value * base + digit;
  }
  *out = value;
  return GARC_OK;
}

GARC_Result garc_cpio_next(GARC_Archive * archive) {
  GARC_Cpio_State * cpio = &archive->cpio;
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
  cpio->check_active = 0;

  const uint64_t header_offset = garc_tar_offset(archive);
  uint8_t header[CPIO_NEWC_HEADER];
  size_t got = 0;
  GARC_Result result = garc_tar_read(archive, header, 6u, &got);
  if (result != GARC_OK) {
    return result;
  }
  if (got == 0) {
    // A stream that ends where a header would begin, without the trailer. Some
    // writers stop there, and every reader that has been handed one accepts it.
    archive->at_end = 1;
    return GARC_END;
  }
  if (got != 6u || memcmp(header, "07070", 5u) != 0) {
    return GARC_ERR_CORRUPT;
  }
  int odc = 0;
  if (header[5] == '1') {
    cpio->variant = 0;
  }
  else if (header[5] == '2') {
    cpio->variant = 1;
  }
  else if (header[5] == '7') {
    cpio->variant = 2;
    odc = 1;
  }
  else {
    return GARC_ERR_CORRUPT;
  }

  uint64_t mode = 0, uid = 0, gid = 0, mtime = 0, size = 0, namesize = 0;
  uint64_t rdev_major = 0, rdev_minor = 0, check = 0;
  size_t header_length;
  if (!odc) {
    header_length = CPIO_NEWC_HEADER;
    result = cpio_read_exact(archive, header + 6u, header_length - 6u);
    if (result != GARC_OK) {
      return result;
    }
    uint64_t f[13];
    for (unsigned i = 0; i < 13u; ++i) {
      if (cpio_field(header + 6u + 8u * i, 8u, 16u, &f[i]) != GARC_OK) {
        return GARC_ERR_CORRUPT;
      }
    }
    mode = f[1];
    uid = f[2];
    gid = f[3];
    mtime = f[5];
    size = f[6];
    rdev_major = f[9];
    rdev_minor = f[10];
    namesize = f[11];
    check = f[12];
  }
  else {
    header_length = CPIO_ODC_HEADER;
    result = cpio_read_exact(archive, header + 6u, header_length - 6u);
    if (result != GARC_OK) {
      return result;
    }
    uint64_t dev, ino, nlink, rdev;
    if (cpio_field(header + 6, 6, 8, &dev) != GARC_OK
        || cpio_field(header + 12, 6, 8, &ino) != GARC_OK
        || cpio_field(header + 18, 6, 8, &mode) != GARC_OK
        || cpio_field(header + 24, 6, 8, &uid) != GARC_OK
        || cpio_field(header + 30, 6, 8, &gid) != GARC_OK
        || cpio_field(header + 36, 6, 8, &nlink) != GARC_OK
        || cpio_field(header + 42, 6, 8, &rdev) != GARC_OK
        || cpio_field(header + 48, 11, 8, &mtime) != GARC_OK
        || cpio_field(header + 59, 6, 8, &namesize) != GARC_OK
        || cpio_field(header + 65, 11, 8, &size) != GARC_OK) {
      return GARC_ERR_CORRUPT;
    }
    rdev_major = rdev >> 8;
    rdev_minor = rdev & 0xFFu;
  }

  if (!namesize) {
    return GARC_ERR_CORRUPT;
  }
  const size_t cap = archive->limits.max_name_bytes
      ? archive->limits.max_name_bytes : (size_t)4096u;
  if (namesize - 1u > cap) {
    return GARC_ERR_LIMIT_NAME_BYTES;
  }
  result = garc_buffer_grow(archive->allocator, &cpio->name, (size_t)namesize);
  if (result != GARC_OK) {
    return result;
  }
  result = cpio_read_exact(archive, (uint8_t *)cpio->name.bytes, (size_t)namesize);
  if (result != GARC_OK) {
    return result;
  }
  if (cpio->name.bytes[namesize - 1u] != '\0') {
    return GARC_ERR_CORRUPT;
  }
  cpio->name.length = (size_t)namesize - 1u;
  cpio->name.bytes[cpio->name.length] = '\0';
  if (memchr(cpio->name.bytes, '\0', cpio->name.length)) {
    return GARC_ERR_CORRUPT;
  }
  if (!odc) {
    const size_t pad = (4u - ((header_length + (size_t)namesize) & 3u)) & 3u;
    if (pad) {
      result = garc_reader_discard(archive, pad);
      if (result != GARC_OK) {
        return result;
      }
    }
  }

  if (cpio->name.length == sizeof(CPIO_TRAILER) - 1u
      && memcmp(cpio->name.bytes, CPIO_TRAILER, sizeof(CPIO_TRAILER) - 1u) == 0) {
    archive->at_end = 1;
    return GARC_END;
  }
  if (!cpio->name.length) {
    return GARC_ERR_CORRUPT;
  }

  const size_t data_pad = odc ? 0u : (size_t)((4u - (size & 3u)) & 3u);

  memset(member, 0, sizeof(*member));
  member->name = cpio->name.bytes;
  member->name_length = cpio->name.length;
  member->size = size;
  member->mtime_seconds = (int64_t)mtime;
  member->mtime_source = GARC_TIME_UNIX;
  member->mode = (uint32_t)(mode & 07777u);
  member->mode_valid = 1;
  member->uid = (int64_t)uid;
  member->gid = (int64_t)gid;
  member->ids_valid = 1;
  member->header_offset = header_offset;
  member->data_offset = garc_tar_offset(archive);

  switch (mode & 0170000u) {
    case 0100000u:
    case 0u:
      member->type = GARC_MEMBER_FILE;
      break;
    case 0040000u:
      member->type = GARC_MEMBER_DIRECTORY;
      break;
    case 0120000u:
      member->type = GARC_MEMBER_SYMLINK;
      break;
    case 0020000u:
    case 0060000u:
      member->type = (mode & 0170000u) == 0020000u ? GARC_MEMBER_CHAR_DEVICE
                                                    : GARC_MEMBER_BLOCK_DEVICE;
      member->device_major = (uint32_t)rdev_major;
      member->device_minor = (uint32_t)rdev_minor;
      member->device_valid = 1;
      break;
    case 0010000u:
      member->type = GARC_MEMBER_FIFO;
      break;
    default:
      member->type = GARC_MEMBER_OTHER;
      break;
  }

  if (member->type == GARC_MEMBER_SYMLINK) {
    if (size > cap) {
      return GARC_ERR_LIMIT_NAME_BYTES;
    }
    result = garc_buffer_grow(archive->allocator, &cpio->link, (size_t)size);
    if (result != GARC_OK) {
      return result;
    }
    if (size) {
      result = cpio_read_exact(archive, (uint8_t *)cpio->link.bytes, (size_t)size);
      if (result != GARC_OK) {
        return result;
      }
    }
    cpio->link.length = (size_t)size;
    cpio->link.bytes[size] = '\0';
    member->link_target = cpio->link.bytes;
    member->link_target_length = cpio->link.length;
    // The data has been consumed into the link, so there is nothing for a caller
    // to read, and the padding behind it is still owed.
    member->size = 0;
    size = 0;
  }

  result = garc_reader_account(archive);
  if (result != GARC_OK) {
    return result;
  }
  archive->data_remaining = size;
  archive->data_padding = data_pad;
  if (cpio->variant == 1 && size) {
    cpio->check = (uint32_t)check;
    cpio->running = 0;
    cpio->check_active = 1;
  }
  return GARC_OK;
}

GARC_Result garc_cpio_read(GARC_Archive * archive, void * buffer,
    size_t capacity, size_t * out_read) {
  GARC_Cpio_State * cpio = &archive->cpio;
  *out_read = 0;
  if (!archive->data_remaining || !capacity) {
    if (!archive->data_remaining && cpio->check_active) {
      cpio->check_active = 0;
      if (cpio->running != cpio->check) {
        return GARC_ERR_CORRUPT;
      }
    }
    return GARC_OK;
  }
  size_t want = capacity;
  if ((uint64_t)want > archive->data_remaining) {
    want = (size_t)archive->data_remaining;
  }
  size_t got = 0;
  GARC_Result result = garc_tar_read(archive, (uint8_t *)buffer, want, &got);
  if (result != GARC_OK) {
    return result;
  }
  if (!got) {
    return GARC_ERR_CORRUPT;
  }
  if (cpio->check_active) {
    for (size_t i = 0; i < got; ++i) {
      cpio->running += ((const uint8_t *)buffer)[i];
    }
  }
  archive->data_remaining -= got;
  *out_read = got;
  return GARC_OK;
}
