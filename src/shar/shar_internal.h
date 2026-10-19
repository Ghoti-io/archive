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
 * What the shar writer shares with the writer.
 */

#ifndef GHOTI_IO_GARC_SRC_SHAR_SHAR_INTERNAL_H
#define GHOTI_IO_GARC_SRC_SHAR_SHAR_INTERNAL_H

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/core.h>

#include "writer/writer_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Begin a member: write the script lines that create it. The first member also
 * writes the script's header.
 *
 * @param writer The writer.
 * @param member A file, directory or symlink.
 * @return ::GARC_OK, ::GARC_ERR_INVALID for a name or link target that cannot be
 *   quoted on one line, ::GARC_ERR_UNSUPPORTED for a type a script cannot make,
 *   or the sink's failure.
 */
GARC_Result garc_shar_write_member(
    GARC_Writer * writer, const GARC_Member * member);

/**
 * Write file data: `X`-prefixed text lines, or uuencoded bytes.
 *
 * @param writer The writer.
 * @param data The bytes.
 * @param size How many.
 * @return ::GARC_OK, ::GARC_ERR_UNSUPPORTED for a NUL in text mode, or the sink's
 *   failure.
 */
GARC_Result garc_shar_write_data(
    GARC_Writer * writer, const void * data, size_t size);

/**
 * End the current member: finish its body and emit its `chmod`.
 *
 * @param writer The writer.
 * @return ::GARC_OK, ::GARC_ERR_UNSUPPORTED for text data with no final newline,
 *   or the sink's failure.
 */
GARC_Result garc_shar_write_close_member(GARC_Writer * writer);

/**
 * Finish the script with `exit 0`.
 *
 * @param writer The writer.
 * @return ::GARC_OK or the sink's failure.
 */
GARC_Result garc_shar_write_end(GARC_Writer * writer);

/**
 * Free what the writer allocated.
 *
 * @param writer The writer.
 */
void garc_shar_write_release(GARC_Writer * writer);

#ifdef __cplusplus
}
#endif

#endif
