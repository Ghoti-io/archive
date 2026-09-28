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
 * `tar.gz`, `tar.zst`, `tar.lz4`: a codec in front of a stream, or behind a
 * sink.
 *
 * ```c
 * GARC_Stream * file = NULL;                       // the compressed bytes
 * garc_stream_create_callback(&callbacks, &file);
 *
 * GARC_Stream * tar = NULL;
 * garc_stream_create_decompress(file, "gzip", NULL, &tar);
 *
 * GARC_Archive * archive = NULL;
 * garc_open(tar, NULL, &archive);                  // an ordinary tar from here
 * ```
 *
 * **There is no new container here, and that is the whole point.** A `.tar.gz`
 * is not a format this library reads; it is a gzip stream whose contents are a
 * tar. So the composition is two objects wrapping two objects, no code in
 * `src/tar/` knows it happened, and the reader on the far side cannot tell the
 * difference. Five decisions in that, each of which could have gone the other
 * way:
 *
 * **The method is a string, not a ::GARC_Format or an enum of its own.**
 * `"gzip"`, `"zstd"`, `"lz4"`, `"zlib"` - whatever `compress` has a method for,
 * spelled the way `compress` spells it and passed straight through to
 * `gcomp_decoder_create()`. An enum here would be this library keeping a second
 * copy of another library's list of codecs, and the copy would be the one that
 * went stale when a codec was added next door. `gcomp_detect()` also answers in
 * these strings, so a caller that sniffs its input has the name already.
 *
 * **Nothing is detected.** A caller says which codec, and a stream whose bytes
 * are gzip handed to ::garc_open() directly is still ::GARC_ERR_FORMAT rather
 * than being quietly unwrapped. Sniffing is a policy decision - which magic
 * numbers count, what to do when two match - and it belongs where a *name*
 * exists to corroborate it, which is the filesystem layer. `gcomp_detect()` is
 * public, so a caller who wants it today has it in two lines.
 *
 * **Trailing bytes after a complete codec stream are ::GARC_ERR_CORRUPT.**
 * RFC 1952 allows gzip members to be concatenated, and `cat a.gz b.gz` and
 * `pigz` both produce that. Measured against `compress` 0.0.0: **zstd decodes
 * every frame, and gzip, lz4 and zlib stop after the first and leave the rest
 * unconsumed.** Stopping quietly would hand the tar reader the first member's
 * worth of bytes and nothing else - a *silently short archive*, which is the
 * worst of the three possible answers. Refusing says what happened. Reading a
 * second member is `compress`'s to offer, not something to work around here.
 *
 * **A compressing sink has to be finished, and ::garc_sink_finish() is how.**
 * The trailer a codec writes at the end is written there, and writing it can
 * fail, which is why it is not done in ::garc_sink_destroy() - that returns
 * `void` and a failure it swallowed would produce a truncated archive that some
 * decoders accept. The order is ::garc_writer_finish() and then
 * ::garc_sink_finish(): the writer ends the tar, the sink ends the codec
 * stream. A writer does not do it, because the sink is borrowed and this
 * library does not finish what it did not create.
 *
 * **::garc_sink_tell() on a compressing sink counts *uncompressed* bytes.**
 * That offset is what a writer pads from, so it has to be the tar stream's own
 * position; the compressed length is the inner sink's answer to the same
 * question. Two sinks, two offsets, each held by the object that knows it.
 *
 * One property falls out rather than being designed: a decompressing stream has
 * no `seek` and no `size`, because a codec stream has neither cheaply. Those
 * callbacks are optional (see stream.h), so this is the same situation as
 * reading a tar from a pipe, which the reader already handles - no new code and
 * no new refusal. It is also why a compressed tar can never gain an index.
 */

#ifndef GHOTI_IO_GARC_CODEC_H
#define GHOTI_IO_GARC_CODEC_H

#include <ghoti.io/archive/core.h>
#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/allocator.h>
#include <ghoti.io/archive/sink.h>
#include <ghoti.io/archive/stream.h>
#include <ghoti.io/compress/options.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create a stream that decompresses another stream.
 *
 * @p inner is **borrowed**: it must outlive the returned stream, and
 * ::garc_stream_destroy() does not destroy it, because this library never frees
 * what it did not allocate. The decoder the returned stream holds *is* owned,
 * and destroying the stream destroys it.
 *
 * @param inner Where the compressed bytes come from.
 * @param method A `compress` method name: `"gzip"`, `"zstd"`, `"lz4"`,
 *   `"zlib"`. Passed through unexamined; see the file comment for why this is
 *   not an enum.
 * @param options `compress` options for the decoder, or NULL for its defaults -
 *   which include a cap on output bytes, so a decompression bomb is refused
 *   without the caller asking. A cap reached is ::GARC_ERR_LIMIT_CODEC_BYTES.
 * @param out_stream Receives the stream on success.
 * @return ::GARC_OK, ::GARC_ERR_INVALID for a NULL argument,
 *   ::GARC_ERR_UNSUPPORTED for a method `compress` does not have, or
 *   ::GARC_ERR_OOM.
 */
GARC_API GARC_Result garc_stream_create_decompress(GARC_Stream * inner,
    const char * method, gcomp_options_t * options, GARC_Stream ** out_stream);

/**
 * @brief Create a decompressing stream using a given allocator.
 *
 * The allocator is this library's, for the stream and its staging buffer. The
 * decoder allocates through `compress`'s own, which is what @p options is for.
 *
 * @param inner Where the compressed bytes come from.
 * @param method A `compress` method name.
 * @param options `compress` options for the decoder, or NULL.
 * @param allocator Allocator for the stream and its buffer. NULL uses the
 *   default.
 * @param out_stream Receives the stream on success.
 * @return As ::garc_stream_create_decompress().
 */
GARC_API GARC_Result garc_stream_create_decompress_with_allocator(
    GARC_Stream * inner, const char * method, gcomp_options_t * options,
    const GARC_Allocator * allocator, GARC_Stream ** out_stream);

/**
 * @brief Create a sink that compresses into another sink.
 *
 * @p inner is **borrowed**, as above. The encoder is owned.
 *
 * ::garc_sink_finish() must be called before the inner sink's bytes are a
 * complete codec stream; see the file comment.
 *
 * @param inner Where the compressed bytes go.
 * @param method A `compress` method name: `"gzip"`, `"zstd"`, `"lz4"`,
 *   `"zlib"`.
 * @param options `compress` options for the encoder - the compression level
 *   lives here - or NULL for its defaults.
 * @param out_sink Receives the sink on success.
 * @return ::GARC_OK, ::GARC_ERR_INVALID for a NULL argument,
 *   ::GARC_ERR_UNSUPPORTED for a method `compress` does not have, or
 *   ::GARC_ERR_OOM.
 */
GARC_API GARC_Result garc_sink_create_compress(GARC_Sink * inner,
    const char * method, gcomp_options_t * options, GARC_Sink ** out_sink);

/**
 * @brief Create a compressing sink using a given allocator.
 *
 * @param inner Where the compressed bytes go.
 * @param method A `compress` method name.
 * @param options `compress` options for the encoder, or NULL.
 * @param allocator Allocator for the sink and its buffer. NULL uses the
 *   default.
 * @param out_sink Receives the sink on success.
 * @return As ::garc_sink_create_compress().
 */
GARC_API GARC_Result garc_sink_create_compress_with_allocator(GARC_Sink * inner,
    const char * method, gcomp_options_t * options,
    const GARC_Allocator * allocator, GARC_Sink ** out_sink);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GARC_CODEC_H
