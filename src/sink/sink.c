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
 * The byte sink every writer writes through.
 *
 * A memory sink is built as a callback sink over an owned buffer, so there is
 * one write path rather than two - the arrangement the stream uses, for the
 * reason it gives.
 */

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/allocator.h>
#include <ghoti.io/archive/sink.h>
#include <ghoti.io/cutil/allocator.h>
#include <stdint.h>
#include <string.h>

#include "sink_internal.h"

/**
 * First capacity a memory sink allocates.
 *
 * One tar record, which is the smallest thing any writer in this library
 * produces: the end-of-archive marker plus its padding is 10240 bytes by
 * default, so a sink that starts smaller reallocs on the way to *every*
 * archive, including an empty one.
 */
#define GARC_SINK_INITIAL 10240u

/** Bytes of padding written per call by garc_sink_fill(). One tar block. */
#define GARC_SINK_FILL_CHUNK 512u

/**
 * Make room for @p extra more bytes in a memory sink's buffer.
 *
 * Two capacities are tried, and the second is not only a fallback for a
 * geometric growth that would overflow. It is what lets a sink finish an archive
 * on a host that cannot spare twice the room it already holds - and, because a
 * refused allocation is a code path rather than a theoretical one, it is the arm
 * the failing allocator can reach. An overflow-only fallback would be
 * unreachable on any 64-bit host, which is a line no test can put in a position
 * to fail.
 */
static GARC_Result sink_mem_reserve(GARC_Sink * sink, size_t extra) {
  // Live only where size_t is 32 bits: holding SIZE_MAX bytes needs SIZE_MAX
  // bytes of memory, so a 64-bit host reaches the allocator's refusal first.
  if (extra > (size_t)-1 - sink->mem_length) {
    return GARC_ERR_OOM;
  }
  size_t needed = sink->mem_length + extra;
  if (needed <= sink->mem_capacity) {
    return GARC_OK;
  }

  size_t wanted = needed;
  if (sink->mem_capacity <= ((size_t)-1) / 2u) {
    size_t doubled = sink->mem_capacity * 2u;
    if (doubled < GARC_SINK_INITIAL) {
      doubled = GARC_SINK_INITIAL;
    }
    if (doubled > wanted) {
      wanted = doubled;
    }
  }

  uint8_t * bytes = (uint8_t *)gcu_allocator_realloc(
      sink->allocator, sink->mem_bytes, wanted);
  if (!bytes && wanted != needed) {
    // The geometric size was refused; ask for exactly what this write needs.
    // realloc leaves the old block alone on failure, so mem_bytes is still
    // ours and still holds everything written so far.
    wanted = needed;
    bytes = (uint8_t *)gcu_allocator_realloc(
        sink->allocator, sink->mem_bytes, wanted);
  }
  if (!bytes) {
    return GARC_ERR_OOM;
  }

  sink->mem_bytes = bytes;
  sink->mem_capacity = wanted;
  return GARC_OK;
}

static GARC_Result sink_mem_write(
    void * ctx, const void * buffer, size_t size) {
  GARC_Sink * sink = (GARC_Sink *)ctx;
  GARC_Result result = sink_mem_reserve(sink, size);
  if (result != GARC_OK) {
    return result;
  }
  memcpy(sink->mem_bytes + sink->mem_length, buffer, size);
  sink->mem_length += size;
  return GARC_OK;
}

static GARC_Result sink_alloc(
    const GARC_Allocator * allocator, GARC_Sink ** out_sink) {
  // Resolved here rather than left NULL, so that destroy frees through the
  // same allocator create used even when the caller passed none.
  if (!allocator) {
    allocator = garc_allocator_default();
  }
  GARC_Sink * sink
      = (GARC_Sink *)gcu_allocator_calloc(allocator, 1, sizeof(GARC_Sink));
  if (!sink) {
    return GARC_ERR_OOM;
  }
  sink->allocator = allocator;
  *out_sink = sink;
  return GARC_OK;
}

GARC_Result garc_sink_create_memory(GARC_Sink ** out_sink) {
  return garc_sink_create_memory_with_allocator(NULL, out_sink);
}

GARC_Result garc_sink_create_memory_with_allocator(
    const GARC_Allocator * allocator, GARC_Sink ** out_sink) {
  if (!out_sink) {
    return GARC_ERR_INVALID;
  }

  GARC_Sink * sink = NULL;
  GARC_Result result = sink_alloc(allocator, &sink);
  if (result != GARC_OK) {
    return result;
  }

  // ctx is the sink itself, which is how the callback above reaches the buffer.
  sink->cb.ctx = sink;
  sink->cb.write = sink_mem_write;

  *out_sink = sink;
  return GARC_OK;
}

GARC_Result garc_sink_create_callback(
    const GARC_Sink_Callbacks * callbacks, GARC_Sink ** out_sink) {
  return garc_sink_create_callback_with_allocator(callbacks, NULL, out_sink);
}

GARC_Result garc_sink_create_callback_with_allocator(
    const GARC_Sink_Callbacks * callbacks, const GARC_Allocator * allocator,
    GARC_Sink ** out_sink) {
  if (!out_sink || !callbacks || !callbacks->write) {
    return GARC_ERR_INVALID;
  }

  GARC_Sink * sink = NULL;
  GARC_Result result = sink_alloc(allocator, &sink);
  if (result != GARC_OK) {
    return result;
  }

  // Copied, so the caller's struct need not outlive this call. ctx inside it
  // is borrowed and must; the header says so.
  sink->cb = *callbacks;

  *out_sink = sink;
  return GARC_OK;
}

GARC_Result garc_sink_write(
    GARC_Sink * sink, const void * buffer, size_t size) {
  if (!sink || (!buffer && size)) {
    return GARC_ERR_INVALID;
  }
  if (!size) {
    return GARC_OK;
  }

  GARC_Result result = sink->cb.write(sink->cb.ctx, buffer, size);
  if (result != GARC_OK) {
    // pos is not advanced. A write is all-or-nothing, so a failed one wrote
    // nothing, and a caller that retries after clearing whatever blocked its
    // callback gets an archive rather than one with a hole in it.
    return result;
  }
  sink->pos += (uint64_t)size;
  return GARC_OK;
}

GARC_Result garc_sink_fill(GARC_Sink * sink, uint8_t byte, uint64_t count) {
  if (!sink) {
    return GARC_ERR_INVALID;
  }

  // Set once for the whole fill rather than once per chunk, and the whole of it
  // rather than only the part the first write needs: filling 512 bytes to write
  // 3 costs nothing measurable, and sizing the memset to the write is the kind
  // of arithmetic that is wrong for one input.
  uint8_t chunk[GARC_SINK_FILL_CHUNK];
  memset(chunk, byte, sizeof(chunk));

  while (count) {
    size_t take = count < (uint64_t)sizeof(chunk) ? (size_t)count
                                                  : sizeof(chunk);
    GARC_Result result = garc_sink_write(sink, chunk, take);
    if (result != GARC_OK) {
      return result;
    }
    count -= (uint64_t)take;
  }
  return GARC_OK;
}

uint64_t garc_sink_tell(const GARC_Sink * sink) {
  return sink ? sink->pos : 0u;
}

GARC_Result garc_sink_data(
    const GARC_Sink * sink, const void ** out_data, size_t * out_size) {
  if (!sink || !out_data || !out_size) {
    return GARC_ERR_INVALID;
  }
  // Which kind of sink this is, asked of the thing that decides it rather than
  // of a flag beside it: a flag can disagree with the callback it describes and
  // this cannot.
  if (sink->cb.write != sink_mem_write) {
    return GARC_ERR_UNSUPPORTED;
  }
  // Non-NULL even before the first write, so that a caller need not special-case
  // an empty archive. Reading zero bytes through it is legal and reading one is
  // not, which is what the paired length is for.
  *out_data = sink->mem_bytes ? (const void *)sink->mem_bytes : (const void *)"";
  *out_size = sink->mem_length;
  return GARC_OK;
}

GARC_Result garc_sink_finish(GARC_Sink * sink) {
  if (!sink) {
    return GARC_ERR_INVALID;
  }
  // A memory sink and a caller's callback sink have no end-of-stream work, and
  // answering GARC_OK rather than GARC_ERR_UNSUPPORTED is deliberate: a caller
  // that writes an archive through whichever sink it was handed should be able
  // to end it the same way every time, and a status that meant "this kind of
  // sink does not need finishing" would have to be distinguished from a real
  // failure at every call site.
  if (!sink->owned_finish) {
    return GARC_OK;
  }
  return sink->owned_finish(sink);
}

void garc_sink_destroy(GARC_Sink * sink) {
  if (!sink) {
    return;
  }
  // Before the sink itself, because the hook reads fields of it. Note that this
  // does *not* finish an unfinished stream: see garc_sink_finish().
  if (sink->owned_destroy) {
    sink->owned_destroy(sink);
  }
  const GARC_Allocator * allocator = sink->allocator;
  gcu_allocator_free(allocator, sink->mem_bytes);
  gcu_allocator_free(allocator, sink);
}
