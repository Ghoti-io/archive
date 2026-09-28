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
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Storage for a ustar member's name.
 *
 * 155 bytes of prefix, a separator, 100 bytes of name, and a NUL. Fixed,
 * because no name a v7 or ustar *header* can express is longer - and an
 * ordinary archive is then walked with no allocation per member at all, which
 * is what makes ::GARC_Member's borrowing worth having.
 *
 * A name GNU's `L` member or pax's `path=` record carries is unbounded in the
 * format and cannot live here. Those go in ::GARC_Tar_Buffer instead, so the
 * allocation happens for the archives that need one and not for every archive.
 */
#define GARC_TAR_NAME_STORAGE 257u

/** Storage for a link target: 100 bytes and a NUL, for the same reason. */
#define GARC_TAR_LINK_STORAGE 101u

/** Storage for a user or group name: ustar's 32 bytes and a NUL. */
#define GARC_TAR_OWNER_STORAGE 33u

/**
 * A growable byte buffer for a string the header fields cannot bound.
 *
 * Bytes, a length and a capacity, rather than a C string: what it holds is a
 * member name, and a member name is attacker-controlled bytes that may contain
 * anything. A NUL is written one past @ref length as a convenience for a
 * debugger, and nothing reads it.
 */
typedef struct {
  /** The bytes, or NULL before the first use. */
  char * bytes;
  /** How many of them are in use. */
  size_t length;
  /** How many were allocated, which is at least @ref length + 1. */
  size_t capacity;
} GARC_Tar_Buffer;

/**
 * The pax record keys this reader acts on.
 *
 * pax is an open vocabulary - real writers emit `SCHILY.*`, `LIBARCHIVE.*` and
 * GNU's own `GNU.*` keys - so an unknown key is *ignored* rather than refused:
 * refusing would refuse most of what they produce. The one exception is
 * `GNU.sparse.*`, refused by name, because there the member's data is a sparse
 * map rather than its contents and ignoring the records hands a caller the map
 * as the file.
 */
typedef enum {
  GARC_PAX_PATH = 0,   ///< `path=`, replacing the header's name.
  GARC_PAX_LINKPATH,   ///< `linkpath=`, replacing the link target.
  GARC_PAX_UNAME,      ///< `uname=`.
  GARC_PAX_GNAME,      ///< `gname=`.
  GARC_PAX_SIZE,       ///< `size=`, decimal, for what the octal field cannot hold.
  GARC_PAX_MTIME,      ///< `mtime=`, decimal, with a fraction.
  GARC_PAX_UID,        ///< `uid=`, decimal.
  GARC_PAX_GID,        ///< `gid=`, decimal.
  GARC_PAX_HDRCHARSET, ///< `hdrcharset=`, saying what the records' bytes are.
  GARC_PAX_KEY_COUNT
} GARC_Pax_Key;

/**
 * One set of pax records: an `x` member's, or the accumulated `g` ones.
 *
 * The values stay in @ref records as the writer spelled them, and the table holds
 * **offsets rather than pointers** so that appending a second header's records -
 * which can move the allocation - does not invalidate what an earlier one said.
 * That is what makes POSIX's rule for global records implementable: a later `g`
 * overrides each key individually rather than replacing the set.
 *
 * `have[k]` with a @ref length of zero is not the same as `!have[k]`. A record
 * with an empty value *deletes* the key, which is how an `x` header suppresses a
 * global one, so the two states have to be distinguishable.
 */
typedef struct {
  /** The raw record bytes, appended to and never rewound within a set. */
  GARC_Tar_Buffer records;
  /** Where each key's value starts in @ref records. */
  size_t offset[GARC_PAX_KEY_COUNT];
  /** How long each key's value is; zero means the key was deleted. */
  size_t length[GARC_PAX_KEY_COUNT];
  /** Whether the key appeared at all. */
  int have[GARC_PAX_KEY_COUNT];
} GARC_Tar_Pax;

/**
 * An archive being read.
 *
 * Opaque to callers: ::garc_open() hands back a pointer and every accessor is a
 * function, so the layout here is free to change without a consumer rebuild.
 */
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
   *
   * The window is one block, and a format reader consumes a whole block before it
   * reports a member - so by the time garc_read_member() or garc_skip_member()
   * can be called there is nothing left in it. That is why those two may go to
   * the stream directly while everything inside the tar reader goes through
   * garc_tar_read() and garc_tar_skip().
   */
  uint8_t peek[GARC_TAR_BLOCK];
  /** How many of @ref peek are still to be consumed. */
  size_t peek_length;
  /** How many of @ref peek have been consumed. */
  size_t peek_consumed;

  /**
   * @name Where a member's strings live between calls
   *
   * A member's name is lent to the caller until the next ::garc_next(), so it
   * has to outlive the header block it was read from. These are sized to the
   * longest a ustar header can express - 100 plus a `/` plus 155 for a split
   * name - so the common case allocates nothing; a longer one goes to the heap
   * buffer below.
   * @{
   */
  char name_storage[GARC_TAR_NAME_STORAGE];   ///< Name, plus its terminator.
  char link_storage[GARC_TAR_LINK_STORAGE];   ///< Link target, plus terminator.
  char uname_storage[GARC_TAR_OWNER_STORAGE]; ///< Owner name, plus terminator.
  char gname_storage[GARC_TAR_OWNER_STORAGE]; ///< Group name, plus terminator.
  /** @} */

  /**
   * A name carried in front of the header rather than in it.
   *
   * GNU writes an `L` member whose data is the next member's name; pax writes a
   * `path=` record. Both are unbounded in the format, so this is where a name
   * too long for @ref name_storage goes. Allocated on first use and **kept
   * across members**, because an archive of long names would otherwise allocate
   * and free once per member; freed by garc_tar_release().
   */
  GARC_Tar_Buffer long_name;
  /** The same for a link target: GNU's `K` member, pax's `linkpath=`. */
  GARC_Tar_Buffer long_link;
  /**
   * Non-zero when @ref long_name holds a name for the header being read.
   *
   * Cleared at the start of every garc_tar_next(), so a carrier member whose
   * read failed cannot leave a name to be applied to some later header. The
   * *storage* is not cleared with it; only the claim on it is.
   */
  int have_long_name;
  /** The same for @ref long_link. */
  int have_long_link;

  /**
   * Records from an `x` member, which apply to the next member only.
   *
   * Reset at the start of every garc_tar_next(), for the same reason
   * @ref have_long_name is: a set left behind by a failed step would otherwise be
   * applied to whatever header a caller reached next.
   */
  GARC_Tar_Pax pax_next;
  /**
   * Records from `g` members, which apply until a later record replaces them.
   *
   * Not reset per member, and appended to rather than replaced, because POSIX
   * overrides a global record **per key**: a second `g` naming `mtime` does not
   * clear a first one's `path`.
   */
  GARC_Tar_Pax pax_global;
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
