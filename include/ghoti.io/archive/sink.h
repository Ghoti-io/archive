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
 * Byte sink for the Ghoti.io Archive library: where a writer puts its bytes.
 *
 * The mirror of ::GARC_Stream, and deliberately a **separate type** rather than
 * that one with a `write` callback added. Four of ::GARC_Stream's five
 * operations mean nothing here - there is nothing to read, nothing to skip, and
 * a sink's length is what it has been given rather than something to ask about -
 * so one struct would be one required callback and four optional ones whose
 * absence meant four different things. `GARC_Stream`'s `read` is *required*, and it
 * would have to stop being so.
 *
 * Three differences from the read side, each of which is the format's answer
 * rather than a choice:
 *
 * **A short write is a failure, where a short read is not.** Reading fewer bytes
 * than asked for is the end of the stream, which is ordinary; there is no
 * corresponding end of a sink. So ::GARC_Sink_Callbacks.write is all-or-nothing
 * and reports no count - a callback that can only take some of the bytes has
 * failed, and saying so with a count would make every caller write the same
 * retry loop and one of them would get it wrong.
 *
 * **A memory sink owns its buffer, where a memory stream borrows one.** The
 * bytes a reader reads already exist; the bytes a writer writes do not, and
 * their number is not known until the archive is finished - a tar member's
 * header is 512 bytes plus a name whose length decides whether a pax record
 * joins it. So ::garc_sink_create_memory() allocates and grows, and
 * ::garc_sink_data() lends the result back for as long as the sink lives.
 *
 * **There is no `seek`, and that is this cut rather than the design.** tar is
 * append-only: every byte is written once, in order, and nothing is patched
 * afterwards. zip is not - a streamed local header carries zeros where the sizes
 * go and either a data descriptor after the data or a seek back to fill them in -
 * so a `seek` callback and a `garc_sink_is_seekable()` to go with it arrive with
 * the writer that reads them. A field nothing reads is worse than an absent one,
 * because it reads as a promise.
 */

#ifndef GHOTI_IO_GARC_SINK_H
#define GHOTI_IO_GARC_SINK_H

#include <ghoti.io/archive/core.h>
#include <ghoti.io/archive/macros.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Opaque write sink.
 */
typedef struct GARC_Sink GARC_Sink;

/**
 * @brief The callback a caller supplies to send bytes anywhere.
 *
 * `write` is required and is the whole interface. ::GARC_Sink_Callbacks.ctx is
 * passed to it and is never inspected or freed by this library; its lifetime is
 * the caller's and it must outlive the sink.
 */
typedef struct GARC_Sink_Callbacks {
  /**
   * Write all @p size bytes from @p buffer.
   *
   * All of them or none: return ::GARC_OK only when every byte has been
   * accepted, and ::GARC_ERR_IO otherwise. There is no count, because there is
   * no partial success a caller of this library could do anything with - see the
   * file comment.
   *
   * Called with @p size of zero at most as often as the caller asks for it;
   * this library never does.
   *
   * Required.
   */
  GARC_Result (*write)(void * ctx, const void * buffer, size_t size);

  /** Passed to `write`. Borrowed; must outlive the sink. */
  void * ctx;
} GARC_Sink_Callbacks;

/**
 * @brief Create a sink that collects bytes in memory.
 *
 * The buffer belongs to the sink: it grows as needed, ::garc_sink_data() lends
 * it back, and ::garc_sink_destroy() frees it. Nothing is allocated until the
 * first write, so a sink that is created and destroyed unused costs one small
 * object.
 *
 * @param out_sink Receives the new sink on success.
 * @return ::GARC_OK, ::GARC_ERR_INVALID, or ::GARC_ERR_OOM.
 */
GARC_API GARC_Result garc_sink_create_memory(GARC_Sink ** out_sink);

/**
 * @brief Create a memory sink using a given allocator.
 *
 * @param allocator Allocator for the sink and its buffer. NULL uses the
 *   default.
 * @param out_sink Receives the new sink on success.
 * @return ::GARC_OK, ::GARC_ERR_INVALID, or ::GARC_ERR_OOM.
 */
GARC_API GARC_Result garc_sink_create_memory_with_allocator(
    const GARC_Allocator * allocator, GARC_Sink ** out_sink);

/**
 * @brief Create a sink that writes through a caller-supplied callback.
 *
 * This is how an archive reaches a file, a socket, or a compressor: the caller
 * owns the handle and this library never sees it. The callbacks struct is
 * copied, so it need not outlive this call; ::GARC_Sink_Callbacks.ctx is
 * borrowed and must.
 *
 * @param callbacks The callbacks. `write` is required.
 * @param out_sink Receives the new sink on success.
 * @return ::GARC_OK, ::GARC_ERR_INVALID when @p callbacks or its `write` is
 *   NULL, or ::GARC_ERR_OOM.
 */
GARC_API GARC_Result garc_sink_create_callback(
    const GARC_Sink_Callbacks * callbacks, GARC_Sink ** out_sink);

/**
 * @brief Create a callback sink using a given allocator.
 *
 * @param callbacks The callbacks. `write` is required.
 * @param allocator Allocator for the sink object. NULL uses the default.
 * @param out_sink Receives the new sink on success.
 * @return ::GARC_OK, ::GARC_ERR_INVALID, or ::GARC_ERR_OOM.
 */
GARC_API GARC_Result garc_sink_create_callback_with_allocator(
    const GARC_Sink_Callbacks * callbacks, const GARC_Allocator * allocator,
    GARC_Sink ** out_sink);

/**
 * @brief Write bytes to the sink.
 *
 * All of them or none. A memory sink fails only when the allocator does; a
 * callback sink fails when the callback says so.
 *
 * @param sink The sink.
 * @param buffer The bytes. May be NULL only when @p size is 0.
 * @param size How many.
 * @return ::GARC_OK, ::GARC_ERR_INVALID, ::GARC_ERR_OOM, or ::GARC_ERR_IO
 *   from the callback.
 */
GARC_API GARC_Result garc_sink_write(
    GARC_Sink * sink, const void * buffer, size_t size);

/**
 * @brief Write @p count copies of one byte.
 *
 * Every archive format pads, and tar pads more than most: a member's data is
 * rounded up to 512 bytes, the archive ends in two zero blocks, and the whole
 * thing is padded to a record. Writing that through ::garc_sink_write() would
 * mean either a caller-side buffer of zeros at every call site or one write per
 * byte, so the loop lives here once.
 *
 * @param sink The sink.
 * @param byte The byte to repeat.
 * @param count How many times. Zero is a successful no-op, because "pad to a
 *   boundary you are already on" is the common case and not a special one.
 * @return ::GARC_OK, ::GARC_ERR_INVALID, ::GARC_ERR_OOM, or ::GARC_ERR_IO.
 */
GARC_API GARC_Result garc_sink_fill(
    GARC_Sink * sink, uint8_t byte, uint64_t count);

/**
 * @brief How many bytes have been written.
 *
 * Counted by this library rather than asked of the callback, so it is meaningful
 * for every sink - which is what lets a writer compute padding without knowing
 * what it is writing to. This is also the offset a member's header landed at,
 * for a caller keeping its own index.
 *
 * @param sink The sink. NULL returns 0.
 * @return Bytes accepted so far. A failed write contributes nothing.
 */
GARC_API uint64_t garc_sink_tell(const GARC_Sink * sink);

/**
 * @brief Borrow a memory sink's bytes.
 *
 * Valid until the next write to the sink, which may move the buffer, and until
 * ::garc_sink_destroy(), which frees it. A caller keeping the bytes copies
 * them.
 *
 * @param sink The sink.
 * @param out_data Receives a pointer to the bytes. Non-NULL even when the
 *   length is zero, so that a caller need not special-case an empty archive.
 *   Required.
 * @param out_size Receives the length. Required.
 * @return ::GARC_OK, ::GARC_ERR_INVALID, or ::GARC_ERR_UNSUPPORTED for a
 *   callback sink - whose bytes are the caller's and were never held here. That
 *   is deliberately not an empty buffer: a sink holding no bytes and a sink that
 *   never holds any are different facts, and one pointer cannot carry both.
 */
GARC_API GARC_Result garc_sink_data(
    const GARC_Sink * sink, const void ** out_data, size_t * out_size);

/**
 * @brief End whatever this sink has to end.
 *
 * A memory sink and a callback sink have nothing to end and return ::GARC_OK, so
 * a caller can call this unconditionally after the last write and does not have
 * to know which kind of sink it was handed. **A compressing sink writes its
 * codec's trailer here** - see codec.h - and without this call the inner sink
 * holds a truncated stream that some decoders accept and others reject.
 *
 * Not folded into ::garc_sink_destroy() on purpose: that returns `void`, and a
 * failure it had to swallow would turn a failed write of the last few bytes into
 * an archive that looks finished.
 *
 * Not folded into ::garc_writer_finish() either. A writer ends the *archive*,
 * which is the end-of-archive marker and its padding; the sink is borrowed, and
 * a writer that finished a sink it did not create would be ending something its
 * caller may still want to write to.
 *
 * Idempotent where it does anything: calling it twice is safe.
 *
 * @param sink The sink.
 * @return ::GARC_OK, ::GARC_ERR_INVALID when @p sink is NULL, or whatever the
 *   underlying write or codec reported.
 */
GARC_API GARC_Result garc_sink_finish(GARC_Sink * sink);

/**
 * @brief Destroy a sink. NULL is ignored.
 *
 * Frees a memory sink's buffer. A callback sink's `ctx` is not touched; closing
 * whatever it wraps is the caller's, and a sink that closed a caller's file
 * descriptor would be a sink that cannot be used twice.
 *
 * Does **not** finish an unfinished sink; see ::garc_sink_finish() for why.
 *
 * @param sink The sink.
 */
GARC_API void garc_sink_destroy(GARC_Sink * sink);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GARC_SINK_H
