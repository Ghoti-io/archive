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

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GARC_SRC_STREAM_STREAM_INTERNAL_H
