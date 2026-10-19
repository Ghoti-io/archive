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
 * What the cpio reader and writer share with the rest of the library.
 */

#ifndef GHOTI_IO_GARC_SRC_CPIO_CPIO_INTERNAL_H
#define GHOTI_IO_GARC_SRC_CPIO_CPIO_INTERNAL_H

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
int garc_cpio_identify(const uint8_t * bytes, size_t length);

/** Whether the first bytes are the binary header, which is refused by name. */
int garc_cpio_identify_binary(const uint8_t * bytes, size_t length);

/** Advance to the next member. */
GARC_Result garc_cpio_next(GARC_Archive * archive);

/** Forget the walk, keeping nothing the next walk will not rebuild. */
void garc_cpio_rewind(GARC_Archive * archive);

/** Free what the reader allocated. */
void garc_cpio_release(GARC_Archive * archive);

/**
 * Begin a member: write its header and name in the writer's dialect (newc or odc),
 * padded as that dialect requires.
 *
 * @param writer The writer.
 * @param member The member: a file, directory, symlink, device or fifo.
 * @return ::GARC_OK, ::GARC_ERR_INVALID for a name, size or number the dialect's
 *   fields cannot hold, ::GARC_ERR_UNSUPPORTED for a type it has no mode for, or
 *   the sink's failure.
 */
GARC_Result garc_cpio_write_member(
    GARC_Writer * writer, const GARC_Member * member);

/**
 * End the current member: write the zero bytes that pad its data, when the
 * dialect pads (newc does, to four bytes; odc does not). The declared size was
 * checked by the generic writer.
 *
 * @param writer The writer.
 * @return ::GARC_OK or the sink's failure.
 */
GARC_Result garc_cpio_write_close_member(GARC_Writer * writer);

/**
 * Finish the archive: write the `TRAILER!!!` entry and pad to a 512-byte block.
 *
 * @param writer The writer.
 * @return ::GARC_OK or the sink's failure.
 */
GARC_Result garc_cpio_write_end(GARC_Writer * writer);

/**
 * Free what the writer allocated.
 *
 * @param writer The writer.
 */
void garc_cpio_write_release(GARC_Writer * writer);

/** Read a member's bytes, checking the crc variant's sum at the end. */
GARC_Result garc_cpio_read(GARC_Archive * archive, void * buffer,
    size_t capacity, size_t * out_read);

#ifdef __cplusplus
}
#endif

#endif
