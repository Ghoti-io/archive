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
 * One member of an archive: what the container said about it.
 *
 * **Every field here is what the container declared, not what this library
 * believes.** A member's `size` is the size the header gave; whether that many
 * bytes were actually there is a separate answer, reported when the data is
 * read. That distinction is the whole reason a reader can say *the archive
 * lied* rather than quietly agreeing with it.
 *
 * Two refusals are built into the field list, and both will be proposed again:
 *
 * **Names are bytes plus a declaration, never transcoded.** ZIP stores names as
 * bytes with one flag bit meaning "UTF-8" and no declaration at all meaning,
 * historically, CP437. tar's are bytes with no declaration ever. So a name is
 * ::GARC_Member.name, ::GARC_Member.name_length and
 * ::GARC_Member.name_encoding - the third saying what the *container* claimed,
 * including that it claimed nothing. Transcoding is the caller's, and doing it
 * here would mean depending on `unicode` to read a tarball.
 *
 * And a claim is about the *field the name came from*, not about the archive: in
 * one pax file a name from a `path=` record is ::GARC_NAME_UTF8, because POSIX
 * says those records are UTF-8, while a name from the header's own field beside
 * it is ::GARC_NAME_UNDECLARED, because nothing has ever said anything about
 * those bytes.
 *
 * **Times are epoch seconds plus provenance, never normalised.** ZIP's MS-DOS
 * field has two-second resolution; extra fields carry better ones; tar's is
 * octal seconds and pax's is decimal with a fraction. So a time is seconds,
 * nanoseconds where the container had them, and
 * ::GARC_Member.mtime_source saying which field answered. Normalising would
 * mean depending on `chron`.
 */

#ifndef GHOTI_IO_GARC_MEMBER_H
#define GHOTI_IO_GARC_MEMBER_H

#include <ghoti.io/archive/core.h>
#include <ghoti.io/archive/macros.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief What kind of thing a member is.
 *
 * The container's own vocabulary mapped onto one set. A typeflag this library
 * recognises as a type but does not name becomes ::GARC_MEMBER_OTHER rather
 * than being reported as a file, because extracting an unknown type as a
 * regular file is how a reader invents data.
 */
typedef enum {
  GARC_MEMBER_FILE = 0,     ///< A regular file.
  GARC_MEMBER_DIRECTORY,    ///< A directory.
  GARC_MEMBER_SYMLINK,      ///< A symbolic link; the target is `link_target`.
  GARC_MEMBER_HARDLINK,     ///< A hard link; the target is `link_target`.
  GARC_MEMBER_FIFO,         ///< A named pipe.
  GARC_MEMBER_CHAR_DEVICE,  ///< A character device; see `device_major`.
  GARC_MEMBER_BLOCK_DEVICE, ///< A block device; see `device_major`.
  GARC_MEMBER_OTHER,        ///< A type the container names and this does not.
  GARC_MEMBER_TYPE_COUNT
} GARC_Member_Type;

/**
 * @brief What the container said about the encoding of a member's name.
 *
 * Not a guess, and never the result of sniffing the bytes. ::GARC_NAME_UTF8
 * means the container carried a flag or a record asserting it;
 * ::GARC_NAME_UNDECLARED means it carried none, which is the usual case and is
 * not the same as "probably ASCII".
 */
typedef enum {
  GARC_NAME_UNDECLARED = 0, ///< The container made no statement.
  GARC_NAME_UTF8,           ///< The container asserted UTF-8.
  GARC_NAME_ENCODING_COUNT
} GARC_Name_Encoding;

/**
 * @brief Which field a member's modification time came from.
 *
 * Kept because the fields do not agree: a tar written by GNU tar carries the
 * same time twice, octal in the header and decimal in a pax record, and they
 * can differ. A caller comparing two archives needs to know which it is
 * looking at, and a test asserting a time has to say which field it asserted.
 */
typedef enum {
  GARC_TIME_NONE = 0,     ///< The container carried no time.
  GARC_TIME_TAR_OCTAL,    ///< tar's header field, whole seconds.
  GARC_TIME_PAX_DECIMAL,  ///< A pax `mtime=` record, with a fraction.
  /**
   * zip's MS-DOS date and time field: two-second resolution, and **no time
   * zone at all**.
   *
   * The library converts it as if it were UTC, because every alternative is
   * worse - reading the host's zone would make one archive answer two ways - and
   * this value is how a caller knows that is what happened. It is the only time
   * many zips carry: `zip -X` writes nothing else.
   */
  GARC_TIME_ZIP_DOS,
  /** zip's 0x5455 extended timestamp: epoch seconds, unambiguously UTC. */
  GARC_TIME_ZIP_UNIX,
  /**
   * zip's 0x000a NTFS field: 100-nanosecond intervals since 1601, UTC.
   *
   * The only timestamp in a zip with sub-second precision, so it is preferred
   * over the other two where a writer produced it - 7-Zip does, in the central
   * directory only.
   */
  GARC_TIME_ZIP_NTFS,
  GARC_TIME_SOURCE_COUNT
} GARC_Time_Source;

/**
 * @brief One member of an archive.
 *
 * **Borrowed, and valid only until the next ::garc_next().** The struct and
 * every pointer in it belong to the archive; a caller that wants a name after
 * moving on copies it. This is what makes walking an archive allocation-free
 * per member, and it is the shape a caller gets wrong once, so it is said here
 * and again on ::garc_next().
 *
 * `name` and `link_target` are **not guaranteed NUL-terminated** and may
 * contain any byte including NUL - a member name is bytes, and a hostile
 * archive will put a NUL in the middle of one to make a C caller see a shorter
 * name than the library did. Use the paired length. A convenience pointer is
 * still NUL-terminated where this library allocated the storage, which is not
 * something to rely on.
 */
typedef struct GARC_Member {
  /** Member name, as bytes. Not necessarily NUL-terminated; see above. */
  const char * name;
  /** Length of @ref name in bytes. */
  size_t name_length;
  /** What the container declared about @ref name's encoding. */
  GARC_Name_Encoding name_encoding;

  /** Link target for a symlink or hard link, as bytes; NULL otherwise. */
  const char * link_target;
  /** Length of @ref link_target in bytes; 0 when there is none. */
  size_t link_target_length;

  /** What kind of thing this is. */
  GARC_Member_Type type;

  /**
   * Uncompressed size **as the container declared it**.
   *
   * Not a measurement. A directory or a symlink declares zero and may not; a
   * hostile archive declares anything at all. Reading the member is what finds
   * out, and a read that ends early is ::GARC_ERR_CORRUPT.
   */
  uint64_t size;

  /** Modification time in seconds since the epoch; 0 when there is none. */
  int64_t mtime_seconds;
  /** Sub-second part of the modification time, where the container had one. */
  uint32_t mtime_nanoseconds;
  /** Which field @ref mtime_seconds came from. */
  GARC_Time_Source mtime_source;

  /** Permission and type bits as the container carried them. */
  uint32_t mode;
  /** Non-zero when @ref mode is meaningful. */
  int mode_valid;

  /** Owning user id. */
  int64_t uid;
  /** Owning group id. */
  int64_t gid;
  /** Non-zero when @ref uid and @ref gid are meaningful. */
  int ids_valid;

  /** Owning user name as bytes, or NULL. */
  const char * uname;
  /** Length of @ref uname. */
  size_t uname_length;
  /** Owning group name as bytes, or NULL. */
  const char * gname;
  /** Length of @ref gname. */
  size_t gname_length;

  /** Device major number, for a device member. */
  uint32_t device_major;
  /** Device minor number, for a device member. */
  uint32_t device_minor;
  /** Non-zero when the device numbers are meaningful. */
  int device_valid;

  /**
   * Offset in the stream at which this member's header began.
   *
   * For diagnostics, and for a caller keeping its own index. Meaningful even on
   * a stream that cannot seek, because the stream counts its own position.
   *
   * Where a format puts a member's metadata in *front* of its header - tar does,
   * for a name or a link target too long for the header's fields - this is the
   * offset of the first of those blocks rather than of the header itself, because
   * that is the offset the member can be re-read from. Starting at the header
   * would produce the truncated name the format put there.
   */
  uint64_t header_offset;
  /** Offset at which this member's data begins. */
  uint64_t data_offset;
} GARC_Member;

/**
 * @brief Name for a member type, for messages and dumps.
 *
 * @param type The type.
 * @return A static string, never NULL.
 */
GARC_API const char * garc_member_type_string(GARC_Member_Type type);

/**
 * @brief Name for a name-encoding declaration.
 *
 * @param encoding The declaration.
 * @return A static string, never NULL.
 */
GARC_API const char * garc_name_encoding_string(GARC_Name_Encoding encoding);

/**
 * @brief Name for a time source.
 *
 * @param source The source.
 * @return A static string, never NULL.
 */
GARC_API const char * garc_time_source_string(GARC_Time_Source source);

/**
 * @brief Write a human-readable description of a member.
 *
 * For debugging and for tests. Bytes that are not printable ASCII are escaped,
 * so that a hostile name cannot move the cursor, clear the screen, or end the
 * line early in whatever is reading the output - a dump is something a person
 * looks at, and a member name is attacker-controlled.
 *
 * @param member The member. NULL writes a line saying so.
 * @param out Destination. NULL is ignored.
 */
GARC_API void garc_member_dump(const GARC_Member * member, FILE * out);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GARC_MEMBER_H
