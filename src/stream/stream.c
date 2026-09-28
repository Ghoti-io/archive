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
 * The byte stream every reader reads through.
 *
 * A memory stream is built as a callback stream over the borrowed buffer, so
 * there is one read path rather than two. Two paths would mean the one the
 * tests exercise and the one a caller uses are different code, and every test
 * in this library reads from memory.
 */

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/allocator.h>
#include <ghoti.io/archive/stream.h>
#include <ghoti.io/cutil/allocator.h>
#include <stdint.h>
#include <string.h>

#include "stream_internal.h"

/** Chunk used to discard bytes on a stream that cannot seek. */
#define GARC_SKIP_CHUNK 4096u

static GARC_Result stream_mem_read(
    void * ctx, void * buffer, size_t size, size_t * out_read) {
  GARC_Stream * stream = (GARC_Stream *)ctx;
  size_t remaining = stream->mem_size - (size_t)stream->pos;
  size_t take = size < remaining ? size : remaining;
  if (take) {
    memcpy(buffer, stream->mem_data + (size_t)stream->pos, take);
  }
  *out_read = take;
  return GARC_OK;
}

static GARC_Result stream_mem_seek(void * ctx, uint64_t offset) {
  GARC_Stream * stream = (GARC_Stream *)ctx;
  // Landing exactly on the end is legal - that is where a completed read
  // leaves the stream - and one byte past it is not.
  if (offset > (uint64_t)stream->mem_size) {
    return GARC_ERR_IO;
  }
  return GARC_OK;
}

static GARC_Result stream_mem_size(void * ctx, uint64_t * out_size) {
  const GARC_Stream * stream = (const GARC_Stream *)ctx;
  *out_size = (uint64_t)stream->mem_size;
  return GARC_OK;
}

static GARC_Result stream_alloc(const GARC_Allocator * allocator,
    GARC_Stream ** out_stream) {
  // Resolved here rather than left NULL, so that destroy frees through the
  // same allocator create used even when the caller passed none.
  if (!allocator) {
    allocator = garc_allocator_default();
  }
  GARC_Stream * stream = (GARC_Stream *)gcu_allocator_calloc(
      allocator, 1, sizeof(GARC_Stream));
  if (!stream) {
    return GARC_ERR_OOM;
  }
  stream->allocator = allocator;
  *out_stream = stream;
  return GARC_OK;
}

GARC_Result garc_stream_create_memory(
    const void * data, size_t size, GARC_Stream ** out_stream) {
  return garc_stream_create_memory_with_allocator(
      data, size, NULL, out_stream);
}

GARC_Result garc_stream_create_memory_with_allocator(const void * data,
    size_t size, const GARC_Allocator * allocator,
    GARC_Stream ** out_stream) {
  if (!out_stream || (!data && size)) {
    return GARC_ERR_INVALID;
  }

  GARC_Stream * stream = NULL;
  GARC_Result result = stream_alloc(allocator, &stream);
  if (result != GARC_OK) {
    return result;
  }

  stream->mem_data = (const uint8_t *)data;
  stream->mem_size = size;
  // ctx is the stream itself, which is how the three callbacks above reach
  // mem_data and pos.
  stream->cb.ctx = stream;
  stream->cb.read = stream_mem_read;
  stream->cb.seek = stream_mem_seek;
  stream->cb.size = stream_mem_size;

  *out_stream = stream;
  return GARC_OK;
}

GARC_Result garc_stream_create_callback(
    const GARC_Stream_Callbacks * callbacks, GARC_Stream ** out_stream) {
  return garc_stream_create_callback_with_allocator(
      callbacks, NULL, out_stream);
}

GARC_Result garc_stream_create_callback_with_allocator(
    const GARC_Stream_Callbacks * callbacks, const GARC_Allocator * allocator,
    GARC_Stream ** out_stream) {
  if (!out_stream || !callbacks || !callbacks->read) {
    return GARC_ERR_INVALID;
  }

  GARC_Stream * stream = NULL;
  GARC_Result result = stream_alloc(allocator, &stream);
  if (result != GARC_OK) {
    return result;
  }

  // Copied, so the caller's struct need not outlive this call. ctx inside it
  // is borrowed and must; the header says so.
  stream->cb = *callbacks;

  *out_stream = stream;
  return GARC_OK;
}

GARC_Result garc_stream_read(
    GARC_Stream * stream, void * buffer, size_t size, size_t * out_read) {
  if (!stream || !out_read || (!buffer && size)) {
    return GARC_ERR_INVALID;
  }
  if (!size) {
    *out_read = 0;
    return GARC_OK;
  }

  size_t got = 0;
  GARC_Result result = stream->cb.read(stream->cb.ctx, buffer, size, &got);
  if (result != GARC_OK) {
    return result;
  }
  // A callback that claims more than it was asked for would move pos past the
  // data it actually wrote, which reads later as a truncated archive a long
  // way from the cause. Refuse it where it happens.
  if (got > size) {
    return GARC_ERR_INTERNAL;
  }
  stream->pos += (uint64_t)got;
  *out_read = got;
  return GARC_OK;
}

GARC_Result garc_stream_read_exact(
    GARC_Stream * stream, void * buffer, size_t size) {
  if (!stream || (!buffer && size)) {
    return GARC_ERR_INVALID;
  }

  uint8_t * out = (uint8_t *)buffer;
  size_t remaining = size;
  while (remaining) {
    size_t got = 0;
    GARC_Result result = garc_stream_read(stream, out, remaining, &got);
    if (result != GARC_OK) {
      return result;
    }
    if (!got) {
      // The caller asked for a fixed-size structure and the stream ended
      // inside it. That is a truncated archive, not an ordinary end of input.
      return GARC_ERR_CORRUPT;
    }
    out += got;
    remaining -= got;
  }
  return GARC_OK;
}

GARC_Result garc_stream_skip(GARC_Stream * stream, uint64_t count) {
  if (!stream) {
    return GARC_ERR_INVALID;
  }
  if (!count) {
    return GARC_OK;
  }
  if (count > UINT64_MAX - stream->pos) {
    // A declared length that overflows the offset is a lie about the
    // container, and reporting it as corrupt beats wrapping round to a
    // plausible offset.
    return GARC_ERR_CORRUPT;
  }

  uint64_t target = stream->pos + count;

  // When the length is knowable, check it first. A seek past the end succeeds
  // on an ordinary file, so without this a skip driven by a lying length would
  // be reported at the next read instead of here.
  if (stream->cb.size) {
    uint64_t total = 0;
    GARC_Result result = stream->cb.size(stream->cb.ctx, &total);
    if (result != GARC_OK) {
      return result;
    }
    if (target > total) {
      return GARC_ERR_CORRUPT;
    }
  }

  if (stream->cb.seek) {
    GARC_Result result = stream->cb.seek(stream->cb.ctx, target);
    if (result != GARC_OK) {
      return result;
    }
    stream->pos = target;
    return GARC_OK;
  }

  // Not seekable: read and discard. A short read here means the stream ended
  // inside a region the container said was there.
  uint8_t scratch[GARC_SKIP_CHUNK];
  while (stream->pos < target) {
    uint64_t want = target - stream->pos;
    size_t chunk = want < (uint64_t)sizeof(scratch)
        ? (size_t)want
        : sizeof(scratch);
    size_t got = 0;
    GARC_Result result = garc_stream_read(stream, scratch, chunk, &got);
    if (result != GARC_OK) {
      return result;
    }
    if (!got) {
      return GARC_ERR_CORRUPT;
    }
  }
  return GARC_OK;
}

uint64_t garc_stream_tell(const GARC_Stream * stream) {
  return stream ? stream->pos : 0u;
}

GARC_Result garc_stream_size(
    const GARC_Stream * stream, uint64_t * out_size) {
  if (!stream || !out_size) {
    return GARC_ERR_INVALID;
  }
  if (!stream->cb.size) {
    return GARC_ERR_UNSUPPORTED;
  }
  return stream->cb.size(stream->cb.ctx, out_size);
}

int garc_stream_is_seekable(const GARC_Stream * stream) {
  return (stream && stream->cb.seek) ? 1 : 0;
}

GARC_Result garc_stream_seek(GARC_Stream * stream, uint64_t offset) {
  if (!stream) {
    return GARC_ERR_INVALID;
  }
  if (!stream->cb.seek) {
    return GARC_ERR_UNSUPPORTED;
  }
  GARC_Result result = stream->cb.seek(stream->cb.ctx, offset);
  if (result != GARC_OK) {
    return result;
  }
  stream->pos = offset;
  return GARC_OK;
}

void garc_stream_destroy(GARC_Stream * stream) {
  if (!stream) {
    return;
  }
  // Before the stream itself, because the hook reads fields of it.
  if (stream->owned_destroy) {
    stream->owned_destroy(stream);
  }
  gcu_allocator_free(stream->allocator, stream);
}
