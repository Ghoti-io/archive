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

#include <ghoti.io/archive/allocator.h>
#include <ghoti.io/archive/core.h>
#include <ghoti.io/archive/stream.h>
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

/**
 * A decoder over one member's compressed range, with everything it owns.
 *
 * Three objects a caller would otherwise have to hold and tear down in order: a
 * bounded view of the compressed bytes, the options carrying the output cap, and
 * the decompressing stream over them. Bundled here rather than in the zip reader
 * so that **this file stays the only one that knows `compress` exists** - the
 * reader asks for a decoder by a method *name* and reads bytes out of a
 * ::GARC_Stream, which is the same shape as reading a stored member.
 */
typedef struct GARC_Member_Codec GARC_Member_Codec;

/**
 * Create a decoder over the next @p compressed_length bytes of @p inner.
 *
 * @p inner is borrowed and is read from wherever it is: the caller seeks to the
 * member's data first. Nothing is read here, so a member whose data is never read
 * costs one allocation and no I/O.
 *
 * **@p max_output is the member's declared uncompressed size, and it moves the
 * cap in both directions.** A zip says how big each member is before any of its
 * bytes are read, so the exact bound is available - tighter than `compress`'s
 * default of 512 MiB for the small members a bomb hides among, and *looser* for
 * the legitimate member that is bigger than 512 MiB, which the default would
 * refuse. Passing no options at all would therefore be wrong twice over. Zero
 * means no cap, which is only right for a member that declares nothing.
 *
 * @param allocator For the objects created here. NULL uses the default.
 * @param inner Where the compressed bytes come from.
 * @param method A `compress` method name, e.g. `"deflate"`.
 * @param compressed_length How many bytes of @p inner belong to this member.
 * @param max_output The declared uncompressed size, or 0 for no cap.
 * @param out_codec Receives the decoder on success.
 * @return ::GARC_OK, ::GARC_ERR_UNSUPPORTED for a method `compress` does not
 *   have, ::GARC_ERR_INVALID, or ::GARC_ERR_OOM.
 */
GARC_Result garc_member_codec_create(const GARC_Allocator * allocator,
    GARC_Stream * inner, const char * method, uint64_t compressed_length,
    uint64_t max_output, GARC_Member_Codec ** out_codec);

/**
 * The stream the decoded bytes come out of.
 *
 * @param codec The decoder.
 * @return Its output stream, owned by @p codec.
 */
GARC_Stream * garc_member_codec_stream(GARC_Member_Codec * codec);

/**
 * Destroy a decoder and everything it owns. NULL is ignored.
 *
 * @param codec The decoder.
 */
void garc_member_codec_destroy(GARC_Member_Codec * codec);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GARC_SRC_CODEC_CODEC_INTERNAL_H
