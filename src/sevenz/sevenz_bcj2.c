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
 * BCJ2, decoded: 7-Zip's four-stream x86 branch converter (method 03 03 01 1B).
 *
 * **Where this came from.** BCJ2 has no published specification; 7-Zip's
 * public-domain LZMA SDK is its only definition. Under a clean-room exception
 * Corey made on 2026-10-21, a describer read that source and wrote a prose
 * description with no code in it, `notes/archive/BCJ2-DESCRIPTION.md` in the
 * workspace. This file was written from that description and checked against
 * 7-Zip's behaviour; its author has not read the source.
 *
 * **What is decoded.** MAIN is every byte of the original except the
 * displacements that were converted. After each byte copied from it, an E8, an
 * E9, or an 80 to 8F after a 0F is a candidate, and one bit is decoded for it
 * from the range-coded stream, even when it is the last byte. A 1 means the
 * next four output bytes are a displacement: a big-endian absolute address
 * from CALL (for E8) or JUMP (for the rest), less the position just past those
 * four bytes, written little-endian and not scanned. The bit's probability is
 * one of 258: one per previous byte for E8, one for E9, one for 0F 8x.
 *
 * **What is checked.** That the range coder's first byte is 0 and its code is
 * not all ones; and, when the declared output is complete, that every one of
 * the four inputs is exactly used up and the code has come back to 0. 7-Zip's
 * reader requires the same of an archive, so a stream that passes here is one
 * it accepts.
 */

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/cutil/allocator.h>
#include <stdint.h>
#include <string.h>

#include "sevenz/sevenz_internal.h"
#include "stream/stream_internal.h"

/** Bytes buffered from MAIN, which is most of the input. */
#define BCJ2_MAIN_BUFFER 65536u

/** Bytes buffered from each of CALL, JUMP and the range coder. */
#define BCJ2_SIDE_BUFFER 4096u

/** Probabilities are 11 bits; this is one, and every one starts at half of it. */
#define BCJ2_PROB_ONE 2048u

/** The adaptation shift. */
#define BCJ2_MOVE_BITS 5u

/** Below this the range takes another byte. */
#define BCJ2_TOP (1u << 24)

/** The probability slot every E9 shares. */
#define BCJ2_SLOT_E9 1u
/** The probability slot every 0F 8x shares. */
#define BCJ2_SLOT_JCC 0u
/** The first of E8's 256 slots, one for each byte before it. */
#define BCJ2_SLOT_E8 2u
/** The slots in all: 258. */
#define BCJ2_SLOTS (BCJ2_SLOT_E8 + 256u)

/** One of the four inputs, with a buffer in front of it. */
typedef struct {
  GARC_Stream * stream; ///< Borrowed.
  uint8_t * buffer;     ///< What has been read and not used.
  size_t capacity;      ///< Size of @ref buffer.
  size_t pos;           ///< The next unused byte.
  size_t len;           ///< Bytes of @ref buffer filled.
  int ended;            ///< The stream has reported its end.
} Bcj2_Input;

/** A BCJ2 decoder: its inputs, its range coder and where its output is. */
typedef struct {
  const GARC_Allocator * allocator; ///< For this state.
  Bcj2_Input in[4];      ///< MAIN, CALL, JUMP, range coder.
  uint64_t out_size;     ///< What the folder says this decodes to.
  uint64_t out_done;     ///< Bytes given out so far.
  uint32_t position;     ///< Output bytes so far, modulo 2^32.
  uint32_t range;        ///< The range coder's range.
  uint32_t code;         ///< The range coder's code.
  int started;           ///< Whether the coder's five bytes have been read.
  int finished;          ///< Whether the end checks have passed.
  uint8_t prev;          ///< The last byte written: the scanning context.
  uint8_t pending[4];    ///< A converted displacement not yet given out.
  unsigned npending;     ///< Bytes of it left.
  uint16_t prob[BCJ2_SLOTS]; ///< P(not converted), out of ::BCJ2_PROB_ONE.
} Bcj2;

/** Refill an input's buffer; leaves it empty only at the stream's end. */
static GARC_Result bcj2_fill(Bcj2_Input * in) {
  in->pos = 0;
  in->len = 0;
  while (!in->ended && !in->len) {
    size_t got = 0;
    GARC_Result result
        = garc_stream_read(in->stream, in->buffer, in->capacity, &got);
    if (result != GARC_OK) {
      return result;
    }
    if (!got) {
      in->ended = 1;
    }
    in->len = got;
  }
  return GARC_OK;
}

/** One byte; ::GARC_ERR_CORRUPT when the input has none left. */
static GARC_Result bcj2_byte(Bcj2_Input * in, uint8_t * out) {
  if (in->pos == in->len) {
    GARC_Result result = bcj2_fill(in);
    if (result != GARC_OK) {
      return result;
    }
    if (!in->len) {
      return GARC_ERR_CORRUPT;
    }
  }
  *out = in->buffer[in->pos++];
  return GARC_OK;
}

/** Whether an input is used up: nothing buffered and nothing more to read. */
static GARC_Result bcj2_exhausted(Bcj2_Input * in, int * out) {
  if (in->pos == in->len) {
    GARC_Result result = bcj2_fill(in);
    if (result != GARC_OK) {
      return result;
    }
  }
  *out = in->pos == in->len;
  return GARC_OK;
}

static GARC_Result bcj2_start(Bcj2 * d) {
  uint8_t first = 0;
  GARC_Result result = bcj2_byte(&d->in[3], &first);
  if (result != GARC_OK) {
    return result;
  }
  if (first != 0u) {
    return GARC_ERR_CORRUPT;
  }
  d->code = 0;
  for (unsigned i = 0; i < 4u; ++i) {
    uint8_t b = 0;
    result = bcj2_byte(&d->in[3], &b);
    if (result != GARC_OK) {
      return result;
    }
    d->code = (d->code << 8) | b;
  }
  if (d->code == 0xFFFFFFFFu) {
    return GARC_ERR_CORRUPT;
  }
  d->range = 0xFFFFFFFFu;
  for (unsigned i = 0; i < BCJ2_SLOTS; ++i) {
    d->prob[i] = (uint16_t)(BCJ2_PROB_ONE / 2u);
  }
  d->started = 1;
  return GARC_OK;
}

/** Decode one decision bit with the probability in slot @p slot. */
static GARC_Result bcj2_bit(Bcj2 * d, unsigned slot, int * out_bit) {
  uint16_t * p = &d->prob[slot];
  const uint32_t bound = (d->range >> 11) * (uint32_t)*p;
  if (d->code < bound) {
    d->range = bound;
    *p = (uint16_t)(*p + ((BCJ2_PROB_ONE - *p) >> BCJ2_MOVE_BITS));
    *out_bit = 0;
  }
  else {
    d->range -= bound;
    d->code -= bound;
    *p = (uint16_t)(*p - (*p >> BCJ2_MOVE_BITS));
    *out_bit = 1;
  }
  if (d->range < BCJ2_TOP) {
    uint8_t b = 0;
    GARC_Result result = bcj2_byte(&d->in[3], &b);
    if (result != GARC_OK) {
      return result;
    }
    d->range <<= 8;
    d->code = (d->code << 8) | b;
  }
  return GARC_OK;
}

/** The checks for a complete output: every input used up, and code 0. */
static GARC_Result bcj2_finish(Bcj2 * d) {
  if (d->npending || d->code != 0u) {
    return GARC_ERR_CORRUPT;
  }
  for (unsigned i = 0; i < 4u; ++i) {
    int done = 0;
    GARC_Result result = bcj2_exhausted(&d->in[i], &done);
    if (result != GARC_OK) {
      return result;
    }
    if (!done) {
      return GARC_ERR_CORRUPT;
    }
  }
  d->finished = 1;
  return GARC_OK;
}

/** Act on a candidate just written: decode its bit and, on 1, its target. */
static GARC_Result bcj2_candidate(Bcj2 * d, uint8_t b, uint8_t before) {
  unsigned slot = BCJ2_SLOT_JCC;
  if (b == 0xE8u) {
    slot = BCJ2_SLOT_E8 + before;
  }
  else if (b == 0xE9u) {
    slot = BCJ2_SLOT_E9;
  }
  int bit = 0;
  GARC_Result result = bcj2_bit(d, slot, &bit);
  if (result != GARC_OK || !bit) {
    return result;
  }
  Bcj2_Input * from = b == 0xE8u ? &d->in[1] : &d->in[2];
  uint32_t absolute = 0;
  for (unsigned i = 0; i < 4u; ++i) {
    uint8_t v = 0;
    result = bcj2_byte(from, &v);
    if (result != GARC_OK) {
      return result;
    }
    absolute = (absolute << 8) | v;
  }
  /* The position is already past the opcode, so the base is four more. */
  const uint32_t relative = absolute - (d->position + 4u);
  d->pending[0] = (uint8_t)relative;
  d->pending[1] = (uint8_t)(relative >> 8);
  d->pending[2] = (uint8_t)(relative >> 16);
  d->pending[3] = (uint8_t)(relative >> 24);
  d->npending = 4u;
  d->position += 4u;
  d->prev = d->pending[3];
  return GARC_OK;
}

static GARC_Result bcj2_read(
    void * ctx, void * buffer, size_t size, size_t * out_read) {
  Bcj2 * d = (Bcj2 *)ctx;
  uint8_t * out = (uint8_t *)buffer;
  size_t n = 0;
  *out_read = 0;
  GARC_Result result = GARC_OK;
  if (!d->started) {
    result = bcj2_start(d);
    if (result != GARC_OK) {
      return result;
    }
  }
  while (n < size && d->out_done < d->out_size) {
    if (d->npending) {
      out[n++] = d->pending[4u - d->npending];
      --d->npending;
      ++d->out_done;
      continue;
    }
    Bcj2_Input * main = &d->in[0];
    if (main->pos == main->len) {
      result = bcj2_fill(main);
      if (result != GARC_OK) {
        return result;
      }
      if (!main->len) {
        return GARC_ERR_CORRUPT; /* MAIN ended before the output did */
      }
    }
    /* Copy plain bytes until a candidate, which is copied too. */
    size_t room = size - n;
    const uint64_t owed = d->out_size - d->out_done;
    if ((uint64_t)room > owed) {
      room = (size_t)owed;
    }
    size_t avail = main->len - main->pos;
    if (avail > room) {
      avail = room;
    }
    const uint8_t * src = main->buffer + main->pos;
    uint8_t prev = d->prev;
    size_t i = 0;
    int candidate = 0;
    uint8_t before = 0;
    while (i < avail) {
      const uint8_t b = src[i];
      out[n + i] = b;
      ++i;
      if (b == 0xE8u || b == 0xE9u || (prev == 0x0Fu && (b & 0xF0u) == 0x80u)) {
        before = prev;
        prev = b;
        candidate = 1;
        break;
      }
      prev = b;
    }
    main->pos += i;
    n += i;
    d->out_done += i;
    d->position += (uint32_t)i;
    d->prev = prev;
    if (candidate) {
      result = bcj2_candidate(d, prev, before);
      if (result != GARC_OK) {
        return result;
      }
      if (d->npending && d->out_done + d->npending > d->out_size) {
        return GARC_ERR_CORRUPT; /* a displacement past the declared end */
      }
    }
  }
  if (d->out_done == d->out_size && !d->finished) {
    result = bcj2_finish(d);
    if (result != GARC_OK) {
      return result;
    }
  }
  *out_read = n;
  return GARC_OK;
}

static void bcj2_destroy(GARC_Stream * stream) {
  Bcj2 * d = (Bcj2 *)stream->cb.ctx;
  for (unsigned i = 0; i < 4u; ++i) {
    gcu_allocator_free(d->allocator, d->in[i].buffer);
  }
  gcu_allocator_free(d->allocator, d);
}

GARC_Result garc_sevenz_bcj2_stream_create(const GARC_Allocator * allocator,
    GARC_Stream * const in[4], uint64_t out_size, GARC_Stream ** out_stream) {
  Bcj2 * d = (Bcj2 *)gcu_allocator_calloc(allocator, 1, sizeof(Bcj2));
  if (!d) {
    return GARC_ERR_OOM;
  }
  d->allocator = allocator;
  d->out_size = out_size;
  for (unsigned i = 0; i < 4u; ++i) {
    d->in[i].stream = in[i];
    d->in[i].capacity = i == 0u ? BCJ2_MAIN_BUFFER : BCJ2_SIDE_BUFFER;
    d->in[i].buffer
        = (uint8_t *)gcu_allocator_malloc(allocator, d->in[i].capacity);
    if (!d->in[i].buffer) {
      for (unsigned j = 0; j < i; ++j) {
        gcu_allocator_free(allocator, d->in[j].buffer);
      }
      gcu_allocator_free(allocator, d);
      return GARC_ERR_OOM;
    }
  }

  GARC_Stream_Callbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.ctx = d;
  callbacks.read = bcj2_read;
  GARC_Stream * stream = NULL;
  GARC_Result result = garc_stream_create_callback_with_allocator(
      &callbacks, allocator, &stream);
  if (result != GARC_OK) {
    for (unsigned i = 0; i < 4u; ++i) {
      gcu_allocator_free(allocator, d->in[i].buffer);
    }
    gcu_allocator_free(allocator, d);
    return result;
  }
  stream->owned_destroy = bcj2_destroy;
  *out_stream = stream;
  return GARC_OK;
}
