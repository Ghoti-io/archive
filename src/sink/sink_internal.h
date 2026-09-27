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
 * Sink internals, shared by the sink implementation and the writers.
 */

#ifndef GHOTI_IO_GARC_SRC_SINK_SINK_INTERNAL_H
#define GHOTI_IO_GARC_SRC_SINK_SINK_INTERNAL_H

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/sink.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A memory sink is a callback sink whose callback is this file's, over the three
 * buffer fields. One write path serves both kinds, for the reason the stream
 * gives for its own: a second path that only the in-memory tests exercise is a
 * path that rots, and every test in this library writes to memory.
 */
struct GARC_Sink {
  GARC_Sink_Callbacks cb; ///< The callbacks. `write` is never NULL.
  /**
   * Bytes accepted so far, counted here rather than asked of the callback.
   * A socket cannot be asked, and a writer needs the figure to know where the
   * next padding boundary is.
   */
  uint64_t pos;
  const GARC_Allocator * allocator; ///< Allocator for the sink and its buffer.
  uint8_t * mem_bytes;              ///< Owned buffer, for a memory sink.
  size_t mem_length;                ///< How many of them are in use.
  size_t mem_capacity;              ///< How many were allocated.
};

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GARC_SRC_SINK_SINK_INTERNAL_H
