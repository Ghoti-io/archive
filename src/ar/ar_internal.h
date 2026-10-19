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
 * What the ar reader and writer share with the rest of the library.
 */

#ifndef GHOTI_IO_GARC_SRC_AR_AR_INTERNAL_H
#define GHOTI_IO_GARC_SRC_AR_AR_INTERNAL_H

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/core.h>
#include <stddef.h>
#include <stdint.h>

#include "reader/reader_internal.h"
#include "writer/writer_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Whether the first bytes begin this format. */
int garc_ar_identify(const uint8_t * bytes, size_t length);

/** Advance to the next member. */
GARC_Result garc_ar_next(GARC_Archive * archive);

/** Forget the walk, keeping nothing the next walk will not rebuild. */
void garc_ar_rewind(GARC_Archive * archive);

/** Free what the reader allocated. */
void garc_ar_release(GARC_Archive * archive);

/**
 * Begin a member: write its 60-byte header, preceded by whatever carries a name
 * the System V field cannot hold.
 *
 * @param writer The writer.
 * @param member The member; a regular file, because ar holds nothing else.
 * @return ::GARC_OK, ::GARC_ERR_INVALID for a name or size ar cannot carry,
 *   ::GARC_ERR_UNSUPPORTED for a type it cannot hold, or the sink's failure.
 */
GARC_Result garc_ar_write_member(
    GARC_Writer * writer, const GARC_Member * member);

/**
 * End the current member: write the newline that pads its data to an even
 * offset, when it needs one. The declared size was checked by the generic writer.
 *
 * @param writer The writer.
 * @return ::GARC_OK or the sink's failure.
 */
GARC_Result garc_ar_write_close_member(GARC_Writer * writer);

/**
 * Finish the archive. ar has no end marker; the only thing written is the magic,
 * and only when no member was, so that an empty archive is not empty bytes.
 *
 * @param writer The writer.
 * @return ::GARC_OK or the sink's failure.
 */
GARC_Result garc_ar_write_end(GARC_Writer * writer);

/**
 * Free what the writer allocated.
 *
 * @param writer The writer.
 */
void garc_ar_write_release(GARC_Writer * writer);

#ifdef __cplusplus
}
#endif

#endif
