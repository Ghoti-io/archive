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
 * What the 7z reader shares with the rest of the library.
 *
 * The reader's own state is opaque (`struct GARC_SevenZ`, defined in
 * sevenz_read.c) because it is a graph of folders, coders and substreams that
 * nothing outside the reader has a reason to touch. The archive holds a pointer.
 */

#ifndef GHOTI_IO_GARC_SRC_SEVENZ_SEVENZ_INTERNAL_H
#define GHOTI_IO_GARC_SRC_SEVENZ_SEVENZ_INTERNAL_H

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/core.h>
#include <stddef.h>
#include <stdint.h>

#include "reader/reader_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/** The six signature bytes, then a two-byte version, then the start header. */
#define GARC_SEVENZ_SIGNATURE_SIZE 6u

/** Signature, version, and the start header's 24 bytes plus its own CRC. */
#define GARC_SEVENZ_START_SIZE 32u

/**
 * Whether the first bytes are a 7z signature header.
 *
 * Six bytes decide it, and that is all identification looks at: a 7z found
 * behind a self-extracting stub is not looked for, because the format's header
 * is at the end and the stub's length is nobody's to guess.
 *
 * @param bytes The first bytes of the stream.
 * @param length How many there are.
 * @return Non-zero when they begin a 7z.
 */
int garc_sevenz_identify(const uint8_t * bytes, size_t length);

/**
 * Read the signature header, the header it points at, and build the member
 * list. Everything the format puts in the header is parsed here, so a walk
 * after this reads no metadata.
 *
 * @param archive The archive, positioned anywhere; the stream must seek.
 * @return ::GARC_OK, or the failure.
 */
GARC_Result garc_sevenz_open(GARC_Archive * archive);

/**
 * Find a 7z behind a self-extracting stub.
 *
 * Only when the first bytes are an executable's (PE, ELF or Mach-O) - which is
 * what a self-extractor is, and what keeps an arbitrary file from being
 * scanned - and only within ::GARC_SEVENZ_SFX_SCAN bytes. A signature counts
 * only when the start header after it checks: its CRC, a major version of 0,
 * and a next header that lies inside the stream.
 *
 * @param archive The archive, whose stream can seek and whose first bytes are
 *   in its peek buffer.
 * @param out_offset Receives the signature's offset from the start of the
 *   archive.
 * @return ::GARC_OK, ::GARC_ERR_FORMAT when there is none, or the stream's
 *   failure. The stream's position is unspecified after.
 */
GARC_Result garc_sevenz_locate_sfx(GARC_Archive * archive, uint64_t * out_offset);

/** How far into a file the self-extractor scan looks for the signature. */
#define GARC_SEVENZ_SFX_SCAN (8u * 1024u * 1024u)

/**
 * Advance to the next member.
 *
 * @param archive The archive.
 * @return ::GARC_OK with the member filled in, ::GARC_END, or a failure.
 */
GARC_Result garc_sevenz_next(GARC_Archive * archive);

/**
 * Read the current member's bytes.
 *
 * @param archive The archive.
 * @param buffer Destination.
 * @param capacity Its size.
 * @param out_read Receives the count; 0 at the end of the member.
 * @return ::GARC_OK or a failure.
 */
GARC_Result garc_sevenz_read(GARC_Archive * archive, void * buffer,
    size_t capacity, size_t * out_read);

/**
 * Give up the current member.
 *
 * @param archive The archive.
 * @return ::GARC_OK.
 */
GARC_Result garc_sevenz_skip(GARC_Archive * archive);

/**
 * Put the walk back at the first member.
 *
 * @param archive The archive.
 */
void garc_sevenz_rewind(GARC_Archive * archive);

/**
 * Free everything the reader allocated.
 *
 * @param archive The archive.
 */
void garc_sevenz_release(GARC_Archive * archive);

/**
 * The number of folders and of members, for ::garc_archive_dump().
 *
 * @param archive The archive.
 * @param out_folders Receives the folder count.
 * @param out_files Receives the entry count.
 */
void garc_sevenz_counts(
    const GARC_Archive * archive, uint64_t * out_folders, uint64_t * out_files);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GARC_SRC_SEVENZ_SEVENZ_INTERNAL_H
