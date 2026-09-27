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
 * The tar reader's private surface.
 *
 * Reference documents:
 *   - POSIX.1-1988 (ustar), IEEE Std 1003.1-1988, the `ustar` Interchange
 *     Format.
 *   - POSIX.1-2001 (pax), IEEE Std 1003.1-2001, the `pax` Interchange Format.
 *   - GNU tar manual, "Basic Tar Format", for the `L`, `K` and base-256
 *     extensions, which are not in either standard.
 */

#ifndef GHOTI_IO_GARC_SRC_TAR_TAR_INTERNAL_H
#define GHOTI_IO_GARC_SRC_TAR_TAR_INTERNAL_H

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/tar.h>
#include <stdint.h>

#include "reader/reader_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @name Field offsets in a tar header block
 *
 * Named rather than written as numbers at each use. Every one of these is read
 * byte by byte with explicit shifts; there is no struct overlay, because a
 * struct over a 512-byte record is a promise about padding that the compiler
 * does not have to keep.
 * @{
 */
#define GARC_TAR_OFF_NAME 0u
#define GARC_TAR_LEN_NAME 100u
#define GARC_TAR_OFF_MODE 100u
#define GARC_TAR_LEN_MODE 8u
#define GARC_TAR_OFF_UID 108u
#define GARC_TAR_LEN_UID 8u
#define GARC_TAR_OFF_GID 116u
#define GARC_TAR_LEN_GID 8u
#define GARC_TAR_OFF_SIZE 124u
#define GARC_TAR_LEN_SIZE 12u
#define GARC_TAR_OFF_MTIME 136u
#define GARC_TAR_LEN_MTIME 12u
#define GARC_TAR_OFF_CHKSUM 148u
#define GARC_TAR_LEN_CHKSUM 8u
#define GARC_TAR_OFF_TYPEFLAG 156u
#define GARC_TAR_OFF_LINKNAME 157u
#define GARC_TAR_LEN_LINKNAME 100u
#define GARC_TAR_OFF_MAGIC 257u
#define GARC_TAR_LEN_MAGIC 6u
#define GARC_TAR_OFF_VERSION 263u
#define GARC_TAR_LEN_VERSION 2u
#define GARC_TAR_OFF_UNAME 265u
#define GARC_TAR_LEN_UNAME 32u
#define GARC_TAR_OFF_GNAME 297u
#define GARC_TAR_LEN_GNAME 32u
#define GARC_TAR_OFF_DEVMAJOR 329u
#define GARC_TAR_LEN_DEVMAJOR 8u
#define GARC_TAR_OFF_DEVMINOR 337u
#define GARC_TAR_LEN_DEVMINOR 8u
#define GARC_TAR_OFF_PREFIX 345u
#define GARC_TAR_LEN_PREFIX 155u
/** @} */

/**
 * Whether these 512 bytes look like the start of a tar archive.
 *
 * Detection is the checksum, not the magic: v7 tar has no magic field at all,
 * so a reader that requires one rejects an entire variant. The magic is what
 * tells ustar from GNU once the block is known to be a header.
 *
 * @param block 512 bytes.
 * @return Non-zero when the block's checksum validates under either the signed
 *   or the unsigned reading.
 */
int garc_tar_block_is_header(const uint8_t * block);

/**
 * Whether these bytes are the start of a tar archive.
 *
 * A valid header, or an end-of-archive marker - `tar cf empty.tar -T /dev/null`
 * writes two zero blocks and nothing else, and an empty archive is still an
 * archive.
 *
 * @param block The bytes.
 * @param length How many there are; fewer than a block is never a tar.
 * @return Non-zero when this is a tar.
 */
int garc_tar_identify(const uint8_t * block, size_t length);

/**
 * Read the next member from a tar stream.
 *
 * Fills in `archive->member` and the tar state, accounts the member against the
 * caps, and leaves the stream positioned at the member's data.
 *
 * @param archive The archive.
 * @return GARC_OK with a member, GARC_END at the end-of-archive marker, or a
 *   failure.
 */
GARC_Result garc_tar_next(GARC_Archive * archive);

/**
 * Parse an unsigned numeric header field.
 *
 * Handles both encodings a tar field can carry, because every size field needs
 * both and adding the second later means touching all of them:
 *
 *   - **Octal**, optionally with leading spaces, terminated by NUL, by space,
 *     by both, or by neither when the digits fill the field exactly. An empty
 *     field - all NULs or all spaces - is zero.
 *   - **Base-256**, GNU's extension, when the high bit of the first byte is
 *     set: 0x80 introduces a big-endian magnitude in the remaining bytes.
 *
 * @param field The field bytes.
 * @param length The field length.
 * @param out_value Receives the value.
 * @return GARC_OK, or GARC_ERR_CORRUPT for a byte that is neither.
 */
GARC_Result garc_tar_parse_uint(
    const uint8_t * field, size_t length, uint64_t * out_value);

/**
 * Parse a signed numeric header field.
 *
 * As garc_tar_parse_uint(), and additionally accepts base-256's negative form,
 * where a leading 0xFF introduces a two's-complement value. A time before the
 * epoch is the reason that form exists.
 *
 * @param field The field bytes.
 * @param length The field length.
 * @param out_value Receives the value.
 * @return GARC_OK, or GARC_ERR_CORRUPT.
 */
GARC_Result garc_tar_parse_int(
    const uint8_t * field, size_t length, int64_t * out_value);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GARC_SRC_TAR_TAR_INTERNAL_H
