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
 * Codec internals, shared by the implementation and its tests.
 */

#ifndef GHOTI_IO_GARC_SRC_CODEC_CODEC_INTERNAL_H
#define GHOTI_IO_GARC_SRC_CODEC_CODEC_INTERNAL_H

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/core.h>
#include <ghoti.io/compress/errors.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Map a `compress` status onto this library's.
 *
 * **Declared here rather than left static so that a test can enumerate every
 * row.** It is a translation table, and three of its eight rows are all a caller
 * of the public API can provoke - a corrupt stream, an unknown method, and the
 * decoder's output cap. The other five would be a wrong status arriving
 * silently: `GCOMP_ERR_MEMORY` reported as an internal error rather than
 * ::GARC_ERR_OOM is a caller who retries instead of freeing something. A table
 * whose rows no test reads is a table that gets one wrong.
 *
 * `GCOMP_ERR_LIMIT` is the row worth naming. In a `finish()` loop it means "more
 * to give, no room" and the callers handle it before reaching here; anywhere else
 * it is a cap in the decoder's options, which is a refusal with a status of its
 * own. Collapsing the two would make a decompression bomb and a small buffer the
 * same answer.
 *
 * @param status What `compress` said.
 * @return The equivalent ::GARC_Result.
 */
GARC_Result garc_codec_result(gcomp_status_t status);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GARC_SRC_CODEC_CODEC_INTERNAL_H
