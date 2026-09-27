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
 * What is specific to tar.
 *
 * **There is no such thing as "tar".** There are four formats sharing a
 * 512-byte header, and a reader that handles one and calls it done
 * mis-reports the others without ever erroring:
 *
 * | variant | names | sizes | how it says so |
 * | --- | --- | --- | --- |
 * | v7 | 100 bytes | octal | nothing at all; the checksum is the only evidence |
 * | ustar (POSIX.1-1988) | 100 bytes + a 155-byte prefix | octal, 11 digits, so 8 GB | `magic` is `ustar\0`, `version` `00` |
 * | GNU | an `L` member carrying the next member's name | base-256 when the high bit is set | `magic` is `ustar  \0` |
 * | pax (POSIX.1-2001) | an `x`/`g` member of `len key=value\n` records | a `size=` record, decimal | an `x` member before the one it describes |
 *
 * The variant is reported per *member*, not per archive, because it changes
 * within one: GNU tar writes pax records in front of ustar headers, so the same
 * file contains members of two variants. ::garc_tar_member_variant() answers
 * for the member ::garc_next() last handed out.
 *
 * It is here rather than on ::GARC_Member because the member struct is the one
 * thing every format shares, and a field whose meaning depends on which format
 * filled it in is the shape that goes wrong when the second format arrives.
 */

#ifndef GHOTI_IO_GARC_TAR_H
#define GHOTI_IO_GARC_TAR_H

#include <ghoti.io/archive/core.h>
#include <ghoti.io/archive/macros.h>
#include <ghoti.io/archive/reader.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The size of a tar header, and the unit every tar offset is a multiple of. */
#define GARC_TAR_BLOCK 512u

/**
 * @brief Which of tar's four formats a member's header was.
 */
typedef enum {
  GARC_TAR_NONE = 0, ///< No tar member has been read.
  GARC_TAR_V7,       ///< No magic field at all; pre-POSIX.
  GARC_TAR_USTAR,    ///< POSIX.1-1988.
  GARC_TAR_GNU,      ///< GNU's extensions.
  GARC_TAR_PAX,      ///< POSIX.1-2001 extended records applied.
  GARC_TAR_VARIANT_COUNT
} GARC_Tar_Variant;

/**
 * @brief Name for a tar variant, for messages and dumps.
 *
 * @param variant The variant.
 * @return A static string, never NULL.
 */
GARC_API const char * garc_tar_variant_string(GARC_Tar_Variant variant);

/**
 * @brief Which variant the current member's header was.
 *
 * @param archive The archive. NULL, or one that is not a tar, returns
 *   ::GARC_TAR_NONE.
 * @return The variant of the member ::garc_next() last returned.
 */
GARC_API GARC_Tar_Variant garc_tar_member_variant(const GARC_Archive * archive);

/**
 * @brief Whether the current member's header checksum was a signed sum.
 *
 * The checksum is computed over the header with the checksum field read as
 * spaces, and historically some writers summed the bytes as signed chars and
 * some as unsigned. Both are accepted, because refusing either rejects real
 * archives; this reports which one matched, so that a corpus can show it has
 * one of each rather than assuming it does.
 *
 * @param archive The archive. NULL returns 0.
 * @return Non-zero when the signed interpretation was the one that matched.
 */
GARC_API int garc_tar_member_checksum_was_signed(const GARC_Archive * archive);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GARC_TAR_H
