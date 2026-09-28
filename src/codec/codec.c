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
 * A codec in front of a stream, and behind a sink. The only file in this
 * library that knows `compress` exists.
 *
 * Both directions are an impedance match and nothing else. `compress` is a
 * *push* API - hand it an input buffer and an output buffer and it moves what
 * it can - and this library's stream is a *pull* API, so the decompressing
 * stream has to keep the compressed bytes it has been given but not yet used.
 * The sink direction needs no such staging, because both sides are pushes.
 *
 * Three behaviours of `compress` 0.0.0 were measured before this was written,
 * because all three decide the shape of the loops below:
 *
 * 1. **`update()` may consume input and produce nothing.** Every codec here
 *    buffers at least a block, so "no output" never means "no more data".
 * 2. **The last block can arrive from `finish()` rather than `update()`.** With
 *    an output buffer smaller than one block, zstd yields *everything* from
 *    finish. So a reader that stopped when update went quiet would read zero
 *    bytes from a small `.tar.zst` and call it an empty archive.
 * 3. **Concatenated members are read by zstd and not by gzip, lz4 or zlib** -
 *    the last three stop after the first and leave the rest of the input
 *    unconsumed. That asymmetry is why unconsumed input is a refusal here; see
 *    codec.h.
 */

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/allocator.h>
#include <ghoti.io/archive/codec.h>
#include <ghoti.io/compress/registry.h>
#include <ghoti.io/compress/stream.h>
#include <ghoti.io/cutil/allocator.h>
#include <stdint.h>
#include <string.h>

#include "codec_internal.h"

#include "../sink/sink_internal.h"
#include "../stream/stream_internal.h"

/**
 * Staging size for both directions.
 *
 * One tar record at GNU's blocking factor, which is the unit the writer on the
 * other side of a compressing sink deals in, and a size every codec here is
 * happy to be fed and drained in.
 */
#define GARC_CODEC_BUFFER 10240u

// Not static: see codec_internal.h for why a translation table is exposed.
GARC_Result garc_codec_result(gcomp_status_t status) {
  switch (status) {
    case GCOMP_OK:
      return GARC_OK;
    case GCOMP_ERR_INVALID_ARG:
      return GARC_ERR_INVALID;
    case GCOMP_ERR_MEMORY:
      return GARC_ERR_OOM;
    case GCOMP_ERR_LIMIT:
      return GARC_ERR_LIMIT_CODEC_BYTES;
    case GCOMP_ERR_CORRUPT:
      return GARC_ERR_CORRUPT;
    case GCOMP_ERR_UNSUPPORTED:
      return GARC_ERR_UNSUPPORTED;
    case GCOMP_ERR_IO:
      return GARC_ERR_IO;
    case GCOMP_ERR_INTERNAL:
    default:
      return GARC_ERR_INTERNAL;
  }
}

////////////////////////////////////////////////////////////////////////
// Decompressing stream
////////////////////////////////////////////////////////////////////////

/** State of a decompressing stream, owned by it. */
typedef struct {
  GARC_Stream * inner;              ///< Borrowed: where compressed bytes come from.
  gcomp_decoder_t * decoder;        ///< Owned.
  const GARC_Allocator * allocator; ///< For this struct and its buffer.
  uint8_t * staged;                 ///< Compressed bytes read but not consumed.
  size_t staged_length;             ///< How many are in it.
  size_t staged_offset;             ///< How many of those the decoder has taken.
  int inner_done;                   ///< The inner stream returned zero bytes.
  int finishing;                    ///< Draining gcomp_decoder_finish().
  int complete;                     ///< finish() said the stream is complete.
} Codec_Stream;

/**
 * Read decompressed bytes.
 *
 * @param ctx The ::Codec_Stream.
 * @param buffer Destination.
 * @param size Its capacity.
 * @param out_read Receives the number of bytes produced; 0 at end of stream.
 * @return ::GARC_OK or a failure.
 */
static GARC_Result codec_stream_read(
    void * ctx, void * buffer, size_t size, size_t * out_read) {
  Codec_Stream * state = (Codec_Stream *)ctx;
  *out_read = 0;
  // No guard on a zero @p size: garc_stream_read() answers that before it calls
  // a callback, so one here is a line no test can put in a position to run.

  for (;;) {
    if (state->complete) {
      // Zero bytes, which is this library's end of stream. Reached only after
      // finish() said the codec stream was whole, so a truncated one is a
      // failure above rather than a short archive here.
      return GARC_OK;
    }

    if (state->finishing) {
      gcomp_buffer_t out = {buffer, size, 0};
      gcomp_status_t status = gcomp_decoder_finish(state->decoder, &out);
      *out_read = out.used;
      if (status == GCOMP_OK) {
        state->complete = 1;
        return GARC_OK;
      }
      if (status != GCOMP_ERR_LIMIT) {
        return garc_codec_result(status);
      }
      // GCOMP_ERR_LIMIT here is "more to give, nowhere to put it", so the
      // caller's buffer is full and the next call continues. A limit that
      // produced nothing would be a decoder with no room in a buffer it was
      // given room in, which is not a state to loop on.
      if (!*out_read) {
        return GARC_ERR_INTERNAL;
      }
      return GARC_OK;
    }

    if (state->staged_offset == state->staged_length && !state->inner_done) {
      size_t got = 0;
      GARC_Result result = garc_stream_read(
          state->inner, state->staged, GARC_CODEC_BUFFER, &got);
      if (result != GARC_OK) {
        return result;
      }
      state->staged_length = got;
      state->staged_offset = 0;
      if (!got) {
        state->inner_done = 1;
      }
    }

    gcomp_buffer_t in = {state->staged + state->staged_offset,
        state->staged_length - state->staged_offset, 0};
    gcomp_buffer_t out = {buffer, size, 0};
    gcomp_status_t status
        = gcomp_decoder_update(state->decoder, &in, &out);
    if (status != GCOMP_OK) {
      return garc_codec_result(status);
    }
    state->staged_offset += in.used;
    if (out.used) {
      *out_read = out.used;
      return GARC_OK;
    }

    // Nothing came out. If nothing went in either, the decoder has finished
    // with what it holds - which is the end of the input, or trailing bytes it
    // will never take. Either way the next move is finish(), whose job includes
    // validating the trailer.
    if (!in.used) {
      if (state->staged_offset < state->staged_length) {
        // Input the decoder will not consume, after a stream it considers done:
        // a second concatenated member, which three of the four codecs here do
        // not read. Refused rather than ignored, because ignoring it hands the
        // tar reader a silently short archive. See codec.h.
        return GARC_ERR_CORRUPT;
      }
      if (state->inner_done) {
        state->finishing = 1;
      }
    }
    // Otherwise input was consumed and produced nothing, which is normal: the
    // codec is filling a block. Go round again.
  }
}

/**
 * Tear down a decompressing stream's state.
 *
 * @param stream The stream.
 */
static void codec_stream_destroy(GARC_Stream * stream) {
  // No null check on the ctx: this hook is installed only after the state exists
  // and is cleared by nothing, so a guard here could never run.
  Codec_Stream * state = (Codec_Stream *)stream->cb.ctx;
  gcomp_decoder_destroy(state->decoder);
  // The inner stream is borrowed and is not touched.
  gcu_allocator_free(state->allocator, state->staged);
  gcu_allocator_free(state->allocator, state);
}

GARC_Result garc_stream_create_decompress(GARC_Stream * inner,
    const char * method, gcomp_options_t * options,
    GARC_Stream ** out_stream) {
  return garc_stream_create_decompress_with_allocator(
      inner, method, options, NULL, out_stream);
}

GARC_Result garc_stream_create_decompress_with_allocator(GARC_Stream * inner,
    const char * method, gcomp_options_t * options,
    const GARC_Allocator * allocator, GARC_Stream ** out_stream) {
  if (!inner || !method || !out_stream) {
    return GARC_ERR_INVALID;
  }
  if (!allocator) {
    allocator = garc_allocator_default();
  }

  Codec_Stream * state = (Codec_Stream *)gcu_allocator_calloc(
      allocator, 1, sizeof(Codec_Stream));
  if (!state) {
    return GARC_ERR_OOM;
  }
  state->allocator = allocator;
  state->inner = inner;
  state->staged
      = (uint8_t *)gcu_allocator_malloc(allocator, GARC_CODEC_BUFFER);
  if (!state->staged) {
    gcu_allocator_free(allocator, state);
    return GARC_ERR_OOM;
  }

  gcomp_status_t status = gcomp_decoder_create(
      gcomp_registry_default(), method, options, &state->decoder);
  if (status != GCOMP_OK) {
    gcu_allocator_free(allocator, state->staged);
    gcu_allocator_free(allocator, state);
    return garc_codec_result(status);
  }

  // No seek and no size, which is the honest answer for a codec stream and is
  // the same shape as a pipe. The reader already handles it.
  GARC_Stream_Callbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.ctx = state;
  callbacks.read = codec_stream_read;

  GARC_Stream * stream = NULL;
  GARC_Result result = garc_stream_create_callback_with_allocator(
      &callbacks, allocator, &stream);
  if (result != GARC_OK) {
    gcomp_decoder_destroy(state->decoder);
    gcu_allocator_free(allocator, state->staged);
    gcu_allocator_free(allocator, state);
    return result;
  }
  stream->owned_destroy = codec_stream_destroy;

  *out_stream = stream;
  return GARC_OK;
}

////////////////////////////////////////////////////////////////////////
// One member's decoder
////////////////////////////////////////////////////////////////////////

/**
 * What one member's decoder owns: a bounded view, a cap, and the decoder.
 *
 * Declared here rather than in the header because nothing outside this file has a
 * reason to reach into it - the zip reader holds a pointer and reads bytes out of
 * ::garc_member_codec_stream(), which is the same shape as reading a stored
 * member from the archive's own stream.
 */
struct GARC_Member_Codec {
  const GARC_Allocator * allocator; ///< For this object.
  GARC_Stream * slice;              ///< Owned: the bounded compressed range.
  GARC_Stream * stream;             ///< Owned: the decompressing stream.
  /**
   * Owned, and kept for the decoder's whole life rather than freed after
   * creation.
   *
   * `gcomp_decoder_create()` is handed a pointer to these and says nothing about
   * whether it copies what it needs. Keeping them is a few dozen bytes per member
   * being read; freeing them on the strength of an assumption is a dangling
   * pointer that would show up as a wrong limit rather than as a crash.
   */
  gcomp_options_t * options;
};

GARC_Result garc_member_codec_create(const GARC_Allocator * allocator,
    GARC_Stream * inner, const char * method, uint64_t compressed_length,
    uint64_t max_output, GARC_Member_Codec ** out_codec) {
  if (!inner || !method || !out_codec) {
    return GARC_ERR_INVALID;
  }
  if (!allocator) {
    allocator = garc_allocator_default();
  }

  GARC_Member_Codec * codec = (GARC_Member_Codec *)gcu_allocator_calloc(
      allocator, 1, sizeof(GARC_Member_Codec));
  if (!codec) {
    return GARC_ERR_OOM;
  }
  codec->allocator = allocator;

  GARC_Result result = garc_stream_create_slice_with_allocator(
      inner, compressed_length, allocator, &codec->slice);
  if (result != GARC_OK) {
    garc_member_codec_destroy(codec);
    return result;
  }

  if (max_output) {
    // The two arms below are `compress`'s allocator failing, not this library's,
    // so nothing here can provoke them - `make coverage` reports both as
    // unexecuted and they stay. A cap that silently failed to be set would leave
    // the decoder on its 512 MiB default, which is the wrong answer for a big
    // member and an invisible one for a small one.
    if (gcomp_options_create(&codec->options) != GCOMP_OK) {
      garc_member_codec_destroy(codec);
      return GARC_ERR_OOM;
    }
    // The declared size, exactly. A member that expands past what its own
    // container said it holds is refused by the decoder, which is a tighter
    // answer than any ratio and needs no guess - and it arrives as
    // GARC_ERR_LIMIT_CODEC_BYTES, which says whose cap it was.
    if (gcomp_options_set_uint64(
            codec->options, "limits.max_output_bytes", max_output)
        != GCOMP_OK) {
      garc_member_codec_destroy(codec);
      return GARC_ERR_OOM;
    }
  }

  result = garc_stream_create_decompress_with_allocator(
      codec->slice, method, codec->options, allocator, &codec->stream);
  if (result != GARC_OK) {
    garc_member_codec_destroy(codec);
    return result;
  }

  *out_codec = codec;
  return GARC_OK;
}

GARC_Stream * garc_member_codec_stream(GARC_Member_Codec * codec) {
  return codec ? codec->stream : NULL;
}

void garc_member_codec_destroy(GARC_Member_Codec * codec) {
  if (!codec) {
    return;
  }
  // Outermost first: the decompressing stream holds the decoder, which reads
  // through the slice. Destroying the slice first would leave the decoder's
  // teardown reading a freed pointer - which it does not do today, and which is
  // not something to rely on.
  garc_stream_destroy(codec->stream);
  garc_stream_destroy(codec->slice);
  gcomp_options_destroy(codec->options);
  gcu_allocator_free(codec->allocator, codec);
}

////////////////////////////////////////////////////////////////////////
// Compressing sink
////////////////////////////////////////////////////////////////////////

/** State of a compressing sink, owned by it. */
typedef struct {
  GARC_Sink * inner;                ///< Borrowed: where compressed bytes go.
  gcomp_encoder_t * encoder;        ///< Owned.
  const GARC_Allocator * allocator; ///< For this struct and its buffer.
  uint8_t * packed;                 ///< Where the encoder's output lands.
  int finished;                     ///< garc_sink_finish() has completed.
} Codec_Sink;

/**
 * Compress @p size bytes and pass whatever comes out to the inner sink.
 *
 * All of them or none, which is this library's sink contract: a partial write
 * would leave the codec's state and the inner sink's bytes describing different
 * amounts of input, and there is no way back from that.
 *
 * @param ctx The ::Codec_Sink.
 * @param buffer The bytes.
 * @param size How many.
 * @return ::GARC_OK or a failure.
 */
static GARC_Result codec_sink_write(
    void * ctx, const void * buffer, size_t size) {
  Codec_Sink * state = (Codec_Sink *)ctx;
  if (state->finished) {
    // The trailer has gone out. Anything written now would be bytes after the
    // end of the codec stream, which no decoder would return.
    return GARC_ERR_INVALID;
  }

  gcomp_buffer_t in = {buffer, size, 0};
  while (in.used < size) {
    gcomp_buffer_t out = {state->packed, GARC_CODEC_BUFFER, 0};
    const size_t before = in.used;
    gcomp_status_t status
        = gcomp_encoder_update(state->encoder, &in, &out);
    if (status != GCOMP_OK) {
      return garc_codec_result(status);
    }
    if (out.used) {
      GARC_Result result
          = garc_sink_write(state->inner, state->packed, out.used);
      if (result != GARC_OK) {
        return result;
      }
    }
    if (!out.used && in.used == before) {
      // Neither consumed nor produced, with input still in hand: the encoder
      // cannot make progress in a buffer it was given 10240 bytes of, which is
      // this library's invariant failing rather than the caller's mistake.
      return GARC_ERR_INTERNAL;
    }
  }
  return GARC_OK;
}

/**
 * Write the codec's trailer.
 *
 * @param sink The sink.
 * @return ::GARC_OK or a failure.
 */
static GARC_Result codec_sink_finish(GARC_Sink * sink) {
  Codec_Sink * state = (Codec_Sink *)sink->cb.ctx;
  if (state->finished) {
    return GARC_OK;
  }

  for (;;) {
    gcomp_buffer_t out = {state->packed, GARC_CODEC_BUFFER, 0};
    gcomp_status_t status = gcomp_encoder_finish(state->encoder, &out);
    if (out.used) {
      GARC_Result result
          = garc_sink_write(state->inner, state->packed, out.used);
      if (result != GARC_OK) {
        return result;
      }
    }
    if (status == GCOMP_OK) {
      break;
    }
    if (status != GCOMP_ERR_LIMIT) {
      return garc_codec_result(status);
    }
    // GCOMP_ERR_LIMIT is "more to give", so go round with a drained buffer. A
    // limit that produced nothing cannot be made progress on by draining.
    if (!out.used) {
      return GARC_ERR_INTERNAL;
    }
  }
  state->finished = 1;
  return GARC_OK;
}

/**
 * Tear down a compressing sink's state.
 *
 * @param sink The sink.
 */
static void codec_sink_destroy(GARC_Sink * sink) {
  // No null check on the ctx, for the reason codec_stream_destroy() gives.
  Codec_Sink * state = (Codec_Sink *)sink->cb.ctx;
  gcomp_encoder_destroy(state->encoder);
  // The inner sink is borrowed and is not touched - nor finished, which is why
  // garc_sink_finish() exists as a call a caller makes.
  gcu_allocator_free(state->allocator, state->packed);
  gcu_allocator_free(state->allocator, state);
}

GARC_Result garc_sink_create_compress(GARC_Sink * inner, const char * method,
    gcomp_options_t * options, GARC_Sink ** out_sink) {
  return garc_sink_create_compress_with_allocator(
      inner, method, options, NULL, out_sink);
}

GARC_Result garc_sink_create_compress_with_allocator(GARC_Sink * inner,
    const char * method, gcomp_options_t * options,
    const GARC_Allocator * allocator, GARC_Sink ** out_sink) {
  if (!inner || !method || !out_sink) {
    return GARC_ERR_INVALID;
  }
  if (!allocator) {
    allocator = garc_allocator_default();
  }

  Codec_Sink * state
      = (Codec_Sink *)gcu_allocator_calloc(allocator, 1, sizeof(Codec_Sink));
  if (!state) {
    return GARC_ERR_OOM;
  }
  state->allocator = allocator;
  state->inner = inner;
  state->packed
      = (uint8_t *)gcu_allocator_malloc(allocator, GARC_CODEC_BUFFER);
  if (!state->packed) {
    gcu_allocator_free(allocator, state);
    return GARC_ERR_OOM;
  }

  gcomp_status_t status = gcomp_encoder_create(
      gcomp_registry_default(), method, options, &state->encoder);
  if (status != GCOMP_OK) {
    gcu_allocator_free(allocator, state->packed);
    gcu_allocator_free(allocator, state);
    return garc_codec_result(status);
  }

  GARC_Sink_Callbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.ctx = state;
  callbacks.write = codec_sink_write;
  // **No `patch`, and not because it would be hard.** A codec's output for a byte
  // depends on every byte before it, so no offset in the compressed stream
  // corresponds to a field in the uncompressed one - there is nothing for an
  // offset to mean. garc_sink_is_seekable() therefore says no, and a zip writer
  // wrapping one of these puts its sizes in a data descriptor.

  GARC_Sink * sink = NULL;
  GARC_Result result = garc_sink_create_callback_with_allocator(
      &callbacks, allocator, &sink);
  if (result != GARC_OK) {
    gcomp_encoder_destroy(state->encoder);
    gcu_allocator_free(allocator, state->packed);
    gcu_allocator_free(allocator, state);
    return result;
  }
  sink->owned_finish = codec_sink_finish;
  sink->owned_destroy = codec_sink_destroy;

  *out_sink = sink;
  return GARC_OK;
}
