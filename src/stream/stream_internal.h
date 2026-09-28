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
 * Stream internals, shared by the stream implementation and the readers.
 */

#ifndef GHOTI_IO_GARC_SRC_STREAM_STREAM_INTERNAL_H
#define GHOTI_IO_GARC_SRC_STREAM_STREAM_INTERNAL_H

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/allocator.h>
#include <ghoti.io/archive/stream.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A memory stream is a callback stream whose callbacks are this file's, over
 * these two fields. One read path serves both kinds, which is the point: a
 * second path that only the in-memory tests exercise is a path that rots,
 * and every test in this library is in memory.
 */
struct GARC_Stream {
  GARC_Stream_Callbacks cb; ///< The callbacks. `read` is never NULL.
  /**
   * Bytes consumed so far, counted here rather than asked of the callbacks.
   * A non-seekable source cannot be asked, and a parser needs the offset to
   * report where a corrupt header was.
   */
  uint64_t pos;
  const GARC_Allocator * allocator; ///< Allocator for the stream itself.
  const uint8_t * mem_data; ///< Borrowed buffer, for a memory stream.
  size_t mem_size;          ///< Its length.
  /**
   * How to tear down `cb.ctx`, or NULL when it is borrowed.
   *
   * A caller's `ctx` is theirs. A `ctx` this library allocated - the decoder
   * and staging buffer of a decompressing stream - is freed through this, so
   * that ::garc_stream_destroy() stays one function that frees what the stream
   * owns without knowing what kind of stream it is.
   */
  void (*owned_destroy)(GARC_Stream * stream);
};

/**
 * Create a stream over the next @p length bytes of another stream.
 *
 * A **bounded view**: it reads from @p inner at wherever @p inner happens to be
 * and reports the end of the stream after @p length bytes, whatever @p inner has
 * left. No seek and no size, for the same reason a decompressing stream has
 * neither - it is a window onto something else's position, and offering a seek
 * would mean deciding what a seek means for the thing behind it.
 *
 * @p inner is **borrowed**: it must outlive the returned stream, and
 * ::garc_stream_destroy() does not destroy it.
 *
 * It exists because a zip member's compressed data is a *range* inside a file,
 * and the decompressing stream in codec.c decompresses until its input ends -
 * so without a bound it would read the next member's local header as more
 * deflate data. A short read from @p inner before the bound is reached is the end
 * of this stream too; whether that is a truncated member is the caller's
 * question, because only the caller knows how many bytes were owed.
 *
 * @param inner Where the bytes come from.
 * @param length How many of them belong to this view.
 * @param allocator Allocator for the stream and its state. NULL uses the
 *   default.
 * @param out_stream Receives the stream on success.
 * @return ::GARC_OK, ::GARC_ERR_INVALID, or ::GARC_ERR_OOM.
 */
GARC_Result garc_stream_create_slice_with_allocator(GARC_Stream * inner,
    uint64_t length, const GARC_Allocator * allocator,
    GARC_Stream ** out_stream);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GARC_SRC_STREAM_STREAM_INTERNAL_H
