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
 * One stream made of several, end to end: a split 7z's `.001`, `.002` and
 * so on, or a split zip's `.z01` ... `.zip`.
 *
 * The parts are borrowed. When every part can seek and knows its size, the
 * whole can too, and ::garc_stream_part_offset() says where each part
 * starts - which a split zip needs, because its offsets count from the start
 * of the part they are in. Otherwise the parts are read in order, once.
 */

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/allocator.h>
#include <ghoti.io/archive/stream.h>
#include <ghoti.io/cutil/allocator.h>
#include <stdint.h>
#include <string.h>

#include "stream_internal.h"

/** The state of a concatenating stream. */
struct GARC_Stream_Concat {
  const GARC_Allocator * allocator; ///< For this state.
  GARC_Stream ** parts;             ///< Borrowed, in order.
  uint64_t * starts;                ///< Each part's offset in the whole.
  size_t count;                     ///< How many parts.
  size_t current;                   ///< The part the next read comes from.
  uint64_t current_at;              ///< How far into it that read is.
  int seekable;                     ///< Every part seeks and knows its size.
  int owns_parts;                   ///< Destroy the parts with the whole.
  uint64_t total;                   ///< The whole's size, when seekable.
};

static GARC_Result stream_concat_read(
    void * ctx, void * buffer, size_t size, size_t * out_read) {
  GARC_Stream_Concat * concat = (GARC_Stream_Concat *)ctx;
  *out_read = 0;
  while (concat->current < concat->count) {
    GARC_Stream * part = concat->parts[concat->current];
    size_t want = size;
    if (concat->seekable) {
      const uint64_t length = (concat->current + 1u < concat->count
              ? concat->starts[concat->current + 1u] : concat->total)
          - concat->starts[concat->current];
      const uint64_t left = length - concat->current_at;
      if ((uint64_t)want > left) {
        want = (size_t)left;
      }
    }
    size_t got = 0;
    if (want) {
      GARC_Result result = garc_stream_read(part, buffer, want, &got);
      if (result != GARC_OK) {
        return result;
      }
    }
    if (got) {
      concat->current_at += (uint64_t)got;
      *out_read = got;
      return GARC_OK;
    }
    if (concat->seekable && want) {
      // A part that ends before the size it reported: every offset after it
      // would be wrong, so this is the stream failing, not the end.
      return GARC_ERR_IO;
    }
    // This part is done; the next starts at its own beginning.
    concat->current++;
    concat->current_at = 0;
    if (concat->seekable && concat->current < concat->count) {
      GARC_Result result = garc_stream_seek(concat->parts[concat->current], 0);
      if (result != GARC_OK) {
        return result;
      }
    }
  }
  return GARC_OK;
}

static GARC_Result stream_concat_seek(void * ctx, uint64_t offset) {
  GARC_Stream_Concat * concat = (GARC_Stream_Concat *)ctx;
  if (offset > concat->total) {
    return GARC_ERR_IO;
  }
  // The last part that starts at or before the offset; the end is the end of
  // the last part.
  size_t index = concat->count - 1u;
  while (index > 0 && concat->starts[index] > offset) {
    --index;
  }
  GARC_Result result
      = garc_stream_seek(concat->parts[index], offset - concat->starts[index]);
  if (result != GARC_OK) {
    return result;
  }
  concat->current = index;
  concat->current_at = offset - concat->starts[index];
  return GARC_OK;
}

static GARC_Result stream_concat_size(void * ctx, uint64_t * out_size) {
  *out_size = ((const GARC_Stream_Concat *)ctx)->total;
  return GARC_OK;
}

static void stream_concat_free(GARC_Stream_Concat * concat) {
  const GARC_Allocator * allocator = concat->allocator;
  gcu_allocator_free(allocator, concat->parts);
  gcu_allocator_free(allocator, concat->starts);
  gcu_allocator_free(allocator, concat);
}

static void stream_concat_destroy(GARC_Stream * stream) {
  GARC_Stream_Concat * concat = (GARC_Stream_Concat *)stream->cb.ctx;
  // The parts are the caller's and are not touched - unless they were handed
  // over, which only this library's own fs layer does.
  if (concat->owns_parts) {
    for (size_t i = 0; i < concat->count; ++i) {
      garc_stream_destroy(concat->parts[i]);
    }
  }
  stream_concat_free(concat);
}

void garc_stream_concat_own_parts(GARC_Stream * stream) {
  if (stream && stream->concat) {
    stream->concat->owns_parts = 1;
  }
}

GARC_Result garc_stream_create_concat(GARC_Stream * const * parts,
    size_t count, GARC_Stream ** out_stream) {
  return garc_stream_create_concat_with_allocator(parts, count, NULL, out_stream);
}

GARC_Result garc_stream_create_concat_with_allocator(GARC_Stream * const * parts,
    size_t count, const GARC_Allocator * allocator, GARC_Stream ** out_stream) {
  if (!parts || !count || !out_stream || count > SIZE_MAX / sizeof(uint64_t)) {
    return GARC_ERR_INVALID;
  }
  for (size_t i = 0; i < count; ++i) {
    if (!parts[i]) {
      return GARC_ERR_INVALID;
    }
  }
  if (!allocator) {
    allocator = garc_allocator_default();
  }
  GARC_Stream_Concat * concat = (GARC_Stream_Concat *)gcu_allocator_calloc(
      allocator, 1, sizeof(*concat));
  if (!concat) {
    return GARC_ERR_OOM;
  }
  concat->allocator = allocator;
  concat->count = count;
  concat->parts = (GARC_Stream **)gcu_allocator_calloc(
      allocator, count, sizeof(*concat->parts));
  concat->starts = (uint64_t *)gcu_allocator_calloc(
      allocator, count, sizeof(*concat->starts));
  if (!concat->parts || !concat->starts) {
    stream_concat_free(concat);
    return GARC_ERR_OOM;
  }
  concat->seekable = 1;
  uint64_t at = 0;
  for (size_t i = 0; i < count; ++i) {
    concat->parts[i] = parts[i];
    concat->starts[i] = at;
    uint64_t size = 0;
    if (!garc_stream_is_seekable(parts[i])
        || garc_stream_size(parts[i], &size) != GARC_OK || size > UINT64_MAX - at) {
      concat->seekable = 0;
      continue;
    }
    at += size;
  }
  concat->total = at;

  GARC_Stream_Callbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.ctx = concat;
  callbacks.read = stream_concat_read;
  if (concat->seekable) {
    callbacks.seek = stream_concat_seek;
    callbacks.size = stream_concat_size;
  }
  GARC_Stream * stream = NULL;
  GARC_Result result = garc_stream_create_callback_with_allocator(
      &callbacks, allocator, &stream);
  if (result == GARC_OK && concat->seekable) {
    // The whole starts at the first part's start, wherever the caller left it.
    result = garc_stream_seek(parts[0], 0);
  }
  if (result != GARC_OK) {
    garc_stream_destroy(stream);
    stream_concat_free(concat);
    return result;
  }
  stream->owned_destroy = stream_concat_destroy;
  stream->concat = concat;
  *out_stream = stream;
  return GARC_OK;
}

size_t garc_stream_part_count(const GARC_Stream * stream) {
  if (!stream) {
    return 0;
  }
  return stream->concat ? stream->concat->count : 1u;
}

GARC_Result garc_stream_part_offset(
    const GARC_Stream * stream, size_t index, uint64_t * out_offset) {
  if (!stream || !out_offset || index >= garc_stream_part_count(stream)) {
    return GARC_ERR_INVALID;
  }
  if (!stream->concat) {
    *out_offset = 0;
    return GARC_OK;
  }
  if (!stream->concat->seekable) {
    return GARC_ERR_NOT_SEEKABLE;
  }
  *out_offset = stream->concat->starts[index];
  return GARC_OK;
}
