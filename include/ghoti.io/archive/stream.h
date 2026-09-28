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
 * Byte-stream abstraction for the Ghoti.io Archive library.
 *
 * Three things about this stream differ from its siblings in `model` and
 * `image`, and each is a decision rather than an omission.
 *
 * **There is no `garc_stream_create_file()`.** This library does not open,
 * create, or write a file, and phases A through E never will; the filesystem
 * layer is phase F, opt-in, in a header of its own. Every well-known archive
 * vulnerability is a path vulnerability - zip-slip, a symlink whose target
 * escapes the extraction root, a hardlink doing the same with no target
 * string to inspect - and a library that hands the caller a name and a byte
 * range cannot commit one. A caller reading an archive from disk opens the
 * file and supplies a ::GARC_Stream_Callbacks, which is four lines and keeps
 * the property. See `notes/archive/PLAN.md` section 1.
 *
 * **Offsets and sizes are `uint64_t`, not `size_t`.** A zip64 archive may be
 * larger than 4 GiB and declare a member that is, and `size_t` is 32 bits on
 * a 32-bit host. Using it would make those archives unreadable on exactly the
 * platforms where the check matters, with an overflow rather than a refusal.
 * Buffer lengths stay `size_t`, because a buffer is a real object in this
 * process and an offset is a number in a file.
 *
 * **Seekability is a property the caller can ask about.** tar is a cursor
 * over a stream and can be read from a pipe; zip is read backwards from its
 * end and cannot. One stream type serves both, and the format asks
 * ::garc_stream_is_seekable() rather than discovering the answer from a
 * failed seek.
 */

#ifndef GHOTI_IO_GARC_STREAM_H
#define GHOTI_IO_GARC_STREAM_H

#include <ghoti.io/archive/core.h>
#include <ghoti.io/archive/macros.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Opaque read stream.
 */
typedef struct GARC_Stream GARC_Stream;

/**
 * @brief The callbacks a caller supplies to read bytes from anywhere.
 *
 * `read` is required. `seek` and `size` are optional, and what they mean by
 * their absence is the point of the struct: a stream with no `seek` is not
 * seekable, and one with no `size` does not know its length. Neither is an
 * error, and a format that needs what is missing refuses with
 * ::GARC_ERR_UNSUPPORTED rather than guessing.
 *
 * Every callback receives `ctx` as its first argument. The library never
 * inspects or frees `ctx`; its lifetime is the caller's, and it must
 * outlive the stream.
 */
typedef struct GARC_Stream_Callbacks {
  /**
   * Read up to @p size bytes into @p buffer.
   *
   * Reading fewer bytes than asked for means the end of the stream, and is
   * not a failure. Write the count to `*out_read` and return ::GARC_OK.
   * Return ::GARC_ERR_IO for a real read failure.
   *
   * Required.
   */
  GARC_Result (*read)(
      void * ctx, void * buffer, size_t size, size_t * out_read);

  /**
   * Seek to an absolute offset from the start of the stream.
   *
   * Return ::GARC_ERR_IO when the offset cannot be reached. NULL means the
   * stream is not seekable, which is a property rather than a failure;
   * ::garc_stream_is_seekable() reports it.
   */
  GARC_Result (*seek)(void * ctx, uint64_t offset);

  /**
   * Total length of the stream in bytes.
   *
   * NULL means the length is not knowable - a pipe, or a stream still being
   * produced - and ::garc_stream_size() then answers
   * ::GARC_ERR_UNSUPPORTED. That is deliberately not "zero": a stream of no
   * bytes and a stream of unknown length are different facts, and one
   * integer cannot carry both.
   */
  GARC_Result (*size)(void * ctx, uint64_t * out_size);

  /** Passed to every callback above. Borrowed; must outlive the stream. */
  void * ctx;
} GARC_Stream_Callbacks;

/**
 * @brief Create a stream over a caller-owned buffer.
 *
 * The buffer is borrowed, not copied: it must outlive the stream. A memory
 * stream is always seekable and always knows its size.
 *
 * @param data Bytes to read. May be NULL only when @p size is 0.
 * @param size Number of bytes.
 * @param out_stream Receives the new stream on success.
 * @return ::GARC_OK, ::GARC_ERR_INVALID, or ::GARC_ERR_OOM.
 */
GARC_API GARC_Result garc_stream_create_memory(
    const void * data, size_t size, GARC_Stream ** out_stream);

/**
 * @brief Create a stream over a caller-owned buffer, using a given allocator.
 *
 * @param data Bytes to read. May be NULL only when @p size is 0.
 * @param size Number of bytes.
 * @param allocator Allocator for the stream object. NULL uses the default.
 * @param out_stream Receives the new stream on success.
 * @return ::GARC_OK, ::GARC_ERR_INVALID, or ::GARC_ERR_OOM.
 */
GARC_API GARC_Result garc_stream_create_memory_with_allocator(
    const void * data, size_t size, const GARC_Allocator * allocator,
    GARC_Stream ** out_stream);

/**
 * @brief Create a stream that reads through caller-supplied callbacks.
 *
 * This is how an archive on disk, on a socket, or inside another archive is
 * read: the caller owns the handle and this library never sees it. The
 * callbacks struct is copied, so it need not outlive this call;
 * ::GARC_Stream_Callbacks.ctx is borrowed and must.
 *
 * @param callbacks The callbacks. `read` is required.
 * @param out_stream Receives the new stream on success.
 * @return ::GARC_OK, ::GARC_ERR_INVALID when @p callbacks or its `read` is
 *   NULL, or ::GARC_ERR_OOM.
 */
GARC_API GARC_Result garc_stream_create_callback(
    const GARC_Stream_Callbacks * callbacks, GARC_Stream ** out_stream);

/**
 * @brief Create a callback stream using a given allocator.
 *
 * @param callbacks The callbacks. `read` is required.
 * @param allocator Allocator for the stream object. NULL uses the default.
 * @param out_stream Receives the new stream on success.
 * @return ::GARC_OK, ::GARC_ERR_INVALID, or ::GARC_ERR_OOM.
 */
GARC_API GARC_Result garc_stream_create_callback_with_allocator(
    const GARC_Stream_Callbacks * callbacks, const GARC_Allocator * allocator,
    GARC_Stream ** out_stream);

/**
 * @brief Read up to @p size bytes.
 *
 * Reading fewer bytes than asked for is not an error; it means the stream is
 * at its end. Check `*out_read`.
 *
 * @param stream The stream.
 * @param buffer Destination.
 * @param size Maximum bytes to read.
 * @param out_read Receives the number of bytes actually read. Required.
 * @return ::GARC_OK, ::GARC_ERR_INVALID, or ::GARC_ERR_IO from the callback.
 */
GARC_API GARC_Result garc_stream_read(
    GARC_Stream * stream, void * buffer, size_t size, size_t * out_read);

/**
 * @brief Read exactly @p size bytes, or fail.
 *
 * A header is a fixed number of bytes and a short read of one is a truncated
 * archive rather than a normal end of stream, so this exists to keep every
 * parser from writing the same loop and the same mistake. A short read is
 * reported as ::GARC_ERR_CORRUPT; the stream is left wherever the read
 * stopped.
 *
 * @param stream The stream.
 * @param buffer Destination.
 * @param size Exact number of bytes to read.
 * @return ::GARC_OK, ::GARC_ERR_INVALID, ::GARC_ERR_IO, or
 *   ::GARC_ERR_CORRUPT on a short read.
 */
GARC_API GARC_Result garc_stream_read_exact(
    GARC_Stream * stream, void * buffer, size_t size);

/**
 * @brief Advance the read position by @p count bytes without keeping them.
 *
 * Seeks when the stream can, and reads and discards when it cannot, so that
 * a format skipping over a member's data works the same on a pipe and on a
 * file. A skip is always driven by a length the container declared, so running
 * off the end means the container lied, and this reports it as
 * ::GARC_ERR_CORRUPT rather than leaving it to be noticed later.
 *
 * **It can only promise that where the end is knowable.** When the stream
 * reports a size, the target is checked against it first - which matters
 * precisely because a seek past the end of an ordinary file *succeeds*, so
 * without the check a lying length would be reported at the next read instead
 * of here. When the stream does not report a size and cannot seek, the discard
 * loop finds the end and says so. The one case left is a stream that can seek
 * and does not know its length: there the answer is whatever the caller's
 * `seek` gives - ::GARC_ERR_IO if it refuses, ::GARC_OK if it accepts - and the
 * truncation surfaces at the next read. Supplying a `size` callback is what
 * closes that gap.
 *
 * **Where a failed skip leaves the offset depends on the shape, and cannot
 * not.** A seekable stream is left exactly where it was, so a caller may
 * retry. A non-seekable one cannot be: the discard loop has already consumed
 * the bytes it read, and they are gone. ::garc_stream_tell() then reports how
 * far it got, which is the useful number - it is where the archive ran out.
 * This was found by the fuzz harness on its first run, asserting a single rule
 * for both paths; two paths meant to be interchangeable have to say where they
 * are not.
 *
 * @param stream The stream.
 * @param count Bytes to skip.
 * @return ::GARC_OK, ::GARC_ERR_INVALID, ::GARC_ERR_IO, or
 *   ::GARC_ERR_CORRUPT.
 */
GARC_API GARC_Result garc_stream_skip(GARC_Stream * stream, uint64_t count);

/**
 * @brief Current read offset, in bytes from the start.
 *
 * Counted by this library rather than asked of the callbacks, so it is
 * meaningful on a non-seekable stream too.
 *
 * @param stream The stream. NULL returns 0.
 * @return Bytes consumed so far.
 */
GARC_API uint64_t garc_stream_tell(const GARC_Stream * stream);

/**
 * @brief Total size of the stream.
 *
 * @param stream The stream.
 * @param out_size Receives the size on success. Required.
 * @return ::GARC_OK, ::GARC_ERR_INVALID, or ::GARC_ERR_UNSUPPORTED when the
 *   stream does not know its length. See ::GARC_Stream_Callbacks.size for why
 *   that is not reported as zero.
 */
GARC_API GARC_Result garc_stream_size(
    const GARC_Stream * stream, uint64_t * out_size);

/**
 * @brief Whether the stream can seek.
 *
 * A format that reads its index from the end of the archive - zip does -
 * checks this and refuses a stream that cannot, rather than finding out from
 * a failed seek halfway in.
 *
 * @param stream The stream. NULL returns 0.
 * @return Non-zero when ::garc_stream_seek() can be used.
 */
GARC_API int garc_stream_is_seekable(const GARC_Stream * stream);

/**
 * @brief Seek to an absolute offset from the start.
 *
 * @param stream The stream.
 * @param offset Offset from the start.
 * @return ::GARC_OK, ::GARC_ERR_INVALID, ::GARC_ERR_UNSUPPORTED on a
 *   non-seekable stream, or ::GARC_ERR_IO when the offset cannot be reached.
 */
GARC_API GARC_Result garc_stream_seek(GARC_Stream * stream, uint64_t offset);

/**
 * @brief Destroy a stream. NULL is ignored.
 *
 * The borrowed buffer or callback context is not touched.
 *
 * @param stream The stream.
 */
GARC_API void garc_stream_destroy(GARC_Stream * stream);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GARC_STREAM_H
