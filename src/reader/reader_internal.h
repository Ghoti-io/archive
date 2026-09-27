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
 * The archive object, shared by the generic reader and each format's reader.
 */

#ifndef GHOTI_IO_GARC_SRC_READER_READER_INTERNAL_H
#define GHOTI_IO_GARC_SRC_READER_READER_INTERNAL_H

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/reader.h>
#include <ghoti.io/archive/tar.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Storage for a ustar member's name.
 *
 * 155 bytes of prefix, a separator, 100 bytes of name, and a NUL. **Fixed
 * rather than growable on purpose**: no name a v7 or ustar header can express
 * is longer, so a growable buffer here would be growth code that nothing in
 * this phase could exercise - and untested growth code is worse than a
 * restructure later. GNU's `L` member and pax's `path=` record are unbounded in
 * the format and are what make a growable buffer necessary; the phase that
 * reads them is the phase that can test it.
 */
#define GARC_TAR_NAME_STORAGE 257u

/** Storage for a link target: 100 bytes and a NUL, for the same reason. */
#define GARC_TAR_LINK_STORAGE 101u

/** Storage for a user or group name: ustar's 32 bytes and a NUL. */
#define GARC_TAR_OWNER_STORAGE 33u

struct GARC_Archive {
  /** The stream, borrowed. The caller destroys it; garc_close() does not. */
  GARC_Stream * stream;
  /** Allocator for this object. */
  const GARC_Allocator * allocator;
  /** The caps, resolved at open so that NULL means the defaults exactly once. */
  GARC_Limits limits;
  /** Which container. */
  GARC_Format format;

  /** The member garc_next() last handed out. */
  GARC_Member member;
  /** Non-zero when @ref member is meaningful. */
  int have_member;
  /** Non-zero once the end of the archive has been reached. */
  int at_end;

  /** Members handed out, which max_members is compared against. */
  uint64_t member_count;
  /** Sum of declared sizes, which max_total_bytes is compared against. */
  uint64_t total_declared_bytes;

  /** Bytes of the current member's data not yet read. */
  uint64_t data_remaining;
  /** Bytes of padding after the current member's data. */
  uint64_t data_padding;

  /** Which of tar's formats the current member's header was. */
  GARC_Tar_Variant tar_variant;
  /** Non-zero when the signed reading of the header checksum was the match. */
  int tar_checksum_was_signed;
  /** Non-zero once a zero block has been seen, which is the end marker. */
  int tar_saw_end_marker;

  /**
   * Bytes read by identification and not yet consumed by the format reader.
   *
   * Identifying a container means looking at its first bytes, and putting them
   * back is the part a non-seekable stream cannot do. Seeking back to zero
   * would work on a file and fail on a pipe - which would make "tar can be read
   * from a pipe", the reason this library has a callback stream at all, false.
   * So the bytes are kept here and the format reader drains them before it
   * reads anything.
   */
  uint8_t peek[GARC_TAR_BLOCK];
  /** How many of @ref peek are still to be consumed. */
  size_t peek_length;
  /** How many of @ref peek have been consumed. */
  size_t peek_consumed;

  char name_storage[GARC_TAR_NAME_STORAGE];
  char link_storage[GARC_TAR_LINK_STORAGE];
  char uname_storage[GARC_TAR_OWNER_STORAGE];
  char gname_storage[GARC_TAR_OWNER_STORAGE];
};

/**
 * Account for one member against the caps, and add it to the running totals.
 *
 * Called by a format reader once it has filled in the member, and before the
 * member is handed to the caller. Each cap has its own status, so this returns
 * the one that fired rather than a shared code.
 *
 * @param archive The archive.
 * @return GARC_OK, or the specific GARC_ERR_LIMIT_* that fired.
 */
GARC_Result garc_reader_account(GARC_Archive * archive);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GARC_SRC_READER_READER_INTERNAL_H
