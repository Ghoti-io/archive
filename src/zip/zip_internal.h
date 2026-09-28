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
 * The zip reader's private surface.
 *
 * Reference documents:
 *   - PKWARE APPNOTE.TXT 6.3.10, the .ZIP File Format Specification, for every
 *     record and every field named here.
 *   - APPNOTE section 4.5 for the extra field ids: 0x0001 zip64, 0x000a NTFS,
 *     0x5455 extended timestamp, 0x7875 Unix uid/gid, 0x9901 WinZip AES.
 */

#ifndef GHOTI_IO_GARC_SRC_ZIP_ZIP_INTERNAL_H
#define GHOTI_IO_GARC_SRC_ZIP_ZIP_INTERNAL_H

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/zip.h>
#include <stdint.h>

// GARC_Zip_State lives in reader_internal.h, beside tar's, because GARC_Archive
// holds one and needs the complete type. This header is what the zip reader's
// own translation units share with each other.
#include "reader/reader_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/** The fixed part of a local file header, before the name. */
#define GARC_ZIP_LOCAL_HEADER_SIZE 30u

/** The fixed part of a central directory entry, before the name. */
#define GARC_ZIP_CENTRAL_ENTRY_SIZE 46u

/** The end-of-central-directory record, with no comment. */
#define GARC_ZIP_EOCD_SIZE 22u

/** The zip64 end-of-central-directory locator, which sits before the EOCD. */
#define GARC_ZIP_ZIP64_LOCATOR_SIZE 20u

/** The fixed part of the zip64 end-of-central-directory record. */
#define GARC_ZIP_ZIP64_EOCD_SIZE 56u

/**
 * How far back from the end of the stream the end record can be.
 *
 * 22 bytes of record plus the largest comment its 16-bit length field can
 * describe. **This is the bound, and it is the whole reason the scan is a scan
 * rather than a search**: a reader that looked further would find an end-record
 * signature inside a member's data, which `python-data-decoy.zip` contains on
 * purpose.
 */
#define GARC_ZIP_EOCD_SEARCH_MAX (GARC_ZIP_EOCD_SIZE + 65535u)

/**
 * Read a 16-bit little-endian field.
 *
 * Shifts over bytes rather than a cast over memory: little-endian is a fact
 * about the *format*, so a reader that copied into a `uint16_t` would be right
 * only on a little-endian host and would raise a strict-aliasing question as
 * well.
 *
 * @param bytes At least two readable bytes.
 * @return The value.
 */
uint16_t garc_zip_le16(const uint8_t * bytes);

/**
 * Read a 32-bit little-endian field.
 *
 * @param bytes At least four readable bytes.
 * @return The value.
 */
uint32_t garc_zip_le32(const uint8_t * bytes);

/**
 * Read a 64-bit little-endian field.
 *
 * @param bytes At least eight readable bytes.
 * @return The value.
 */
uint64_t garc_zip_le64(const uint8_t * bytes);

/**
 * Convert an MS-DOS date and time to seconds since the epoch, as UTC.
 *
 * **The field carries no time zone, so this is a decision rather than a
 * reading**, and ::GARC_TIME_ZIP_DOS on the member is how a caller knows which
 * decision was made. Every alternative is worse: reading the host's zone makes
 * one archive answer two ways, and declining to convert leaves
 * ::GARC_Member.mtime_seconds unfillable for the many archives that carry
 * nothing else.
 *
 * An out-of-range field is refused rather than converted. A date of zero, which
 * is what a writer with nothing to say puts there, has month 0 and day 0, and the
 * arithmetic would answer with a date that does not exist.
 *
 * @param date The date field: year from 1980 in the top 7 bits, month, day.
 * @param time The time field: hour, minute, and the second divided by two.
 * @param out_seconds Receives the value on success.
 * @return ::GARC_OK, or ::GARC_ERR_CORRUPT for a field out of range.
 */
GARC_Result garc_zip_dos_to_epoch(
    uint16_t date, uint16_t time, int64_t * out_seconds);

/**
 * Convert a Windows FILETIME to seconds and nanoseconds since the epoch.
 *
 * A FILETIME is 100-nanosecond intervals since 1601-01-01 UTC, which is what the
 * 0x000a extra field carries and the only timestamp in a zip with sub-second
 * precision. Exact on both sides of 1970: the fraction counts forward from the
 * whole second in both cases, which is the same reading the pax `mtime=` parser
 * settled on.
 *
 * @param filetime The value.
 * @param out_seconds Receives whole seconds, negative before 1970.
 * @param out_nanoseconds Receives the sub-second part, always forward.
 * @return ::GARC_OK.
 */
GARC_Result garc_zip_filetime_to_epoch(uint64_t filetime,
    int64_t * out_seconds, uint32_t * out_nanoseconds);

/**
 * Whether these first bytes are a zip's.
 *
 * Only the front, and only cheaply: a local file header, an end record for an
 * archive with no members, or a zip64 end record. **A zip behind a stub answers
 * no**, which is not a failure of this function - the other half of
 * identification is the backwards scan, which needs a seekable stream, and
 * separating the two is what lets ::garc_open() say ::GARC_ERR_NOT_SEEKABLE for a
 * zip on a pipe rather than ::GARC_ERR_FORMAT.
 *
 * @param bytes The first bytes of the stream.
 * @param length How many there are.
 * @return Non-zero when these are the first bytes of a zip.
 */
int garc_zip_identify(const uint8_t * bytes, size_t length);

/**
 * Whether a seekable stream ends with something that reads as a zip.
 *
 * The backwards scan, validating each candidate record rather than taking the
 * last signature: the comment length has to account for exactly the bytes after
 * the record. Leaves the stream position where it found it.
 *
 * @param archive The archive, whose stream must be seekable.
 * @param out_offset Receives the absolute offset of the end record on success.
 * @return ::GARC_OK with an offset, ::GARC_ERR_FORMAT when there is no such
 *   record, or an I/O or allocation failure.
 */
GARC_Result garc_zip_locate_eocd(GARC_Archive * archive, uint64_t * out_offset);

/**
 * Read the end record, the zip64 records behind it if any, and settle the base
 * offset.
 *
 * Called by ::garc_open() once the format is known. On failure the caller frees
 * the archive, so anything allocated here is released by ::garc_zip_release().
 *
 * @param archive The archive.
 * @param eocd_offset Where ::garc_zip_locate_eocd() found the end record.
 * @return ::GARC_OK, ::GARC_ERR_CORRUPT, ::GARC_ERR_UNSUPPORTED for a
 *   multi-disk archive, or an I/O or allocation failure.
 */
GARC_Result garc_zip_open(GARC_Archive * archive, uint64_t eocd_offset);

/**
 * Step to the next central directory entry and describe it.
 *
 * @param archive The archive.
 * @return ::GARC_OK with ::GARC_Archive.member filled in, ::GARC_END after the
 *   last declared entry, or a failure.
 */
GARC_Result garc_zip_next(GARC_Archive * archive);

/**
 * Put the walk back to the first entry, leaving what open discovered alone.
 *
 * @param archive The archive.
 */
void garc_zip_rewind(GARC_Archive * archive);

/**
 * Free everything the zip reader allocated for this archive.
 *
 * @param archive The archive.
 */
void garc_zip_release(GARC_Archive * archive);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GARC_SRC_ZIP_ZIP_INTERNAL_H
