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
 * Extracting an archive into a directory, and packing a directory into an
 * archive.
 *
 * **Opt-in, and not part of the reader or the writer.** Those still never
 * open a file. This header is not included by archive.h. A caller who does
 * not extract does not link a use of the filesystem into the question of
 * whether a name was safe.
 *
 * **A clean name is not permission to write.** ::garc_name_check() classifies
 * bytes. Containment is the canonical path of each parent after the links
 * this call has created, and the final component is created only once that
 * parent is still inside the root. `gcu_path_canonicalize()` cannot be asked
 * about a path that does not exist yet, which is why the check is the parent.
 *
 * ::GARC_NAME_ESCAPES, a NUL, and an empty name are refused with no flag.
 * ::GARC_NAME_PORTABILITY is refused unless ::GARC_FS_ALLOW_PORTABLE_NAMES
 * is set, and a `..` that leaves the root is still an escape when it is.
 * Symbolic links and hard links are refused unless ::GARC_FS_ALLOW_LINKS is
 * set, and a link target must still resolve inside the root. A hard link may
 * only name a path this extract has already claimed.
 *
 * The first refusal stops the call. Members already written stay, later
 * members are not written, and the root is not deleted. A path that already
 * exists is a refusal, and whatever is there is left unchanged. Two members
 * whose canonical paths are one path are a refusal of the second. Modes are
 * the archive mode with setuid, setgid and sticky cleared; there is no flag
 * that keeps those bits. On Windows the mode is not applied.
 *
 * **On Windows, some portability findings are not portability questions**, and
 * ::GARC_FS_ALLOW_PORTABLE_NAMES does not allow them: a reserved device name
 * (`CON` would write the member to the console), a component ending in a dot
 * or a space (stripped, so two names reach one file), a backslash traversal, a
 * control byte, and any of `:*?"<>|` in a member name - a `:` would open an
 * alternate data stream. A symbolic link member is ::GARC_ERR_REFUSED there
 * even with ::GARC_FS_ALLOW_LINKS, because cutil does not create one on
 * Windows.
 *
 * Packing stores a symlink as a symlink and does not follow it. A hard link
 * whose other name is inside the tree is a hard link member; one whose other
 * name is outside is a refusal. If the writer cannot store a hard link, that
 * status is the result of the pack.
 *
 * **Files as streams and sinks.** ::garc_fs_stream_open() reads a file,
 * seekably and with its size known, so every format can be read from it.
 * ::garc_fs_sink_create() writes one, and it can patch, so a zip or 7z writer
 * needs no glue. A sink never writes the destination in place. It writes a
 * temporary file in the destination's directory, and ::garc_sink_finish()
 * renames that over the destination. A sink destroyed without being finished
 * removes the temporary file and leaves the destination as it was. Paths are
 * UTF-8 on every platform, and offsets are 64-bit on every platform.
 *
 * **Opening by path detects compression.** ::garc_fs_open() tries the
 * containers first. If none matches, it asks `compress` which codec wrote the
 * first bytes. gzip, bzip2, xz, zstd and lz4 have magic numbers and are
 * accepted. zlib's two header bytes are a guess, about one random pair in
 * 992, so they are not trusted. brotli and `.lzma` have no magic, and the file
 * name decides for them only when ::GARC_FS_NAME_HINT is set. The core
 * ::garc_open() still detects nothing; detection is this layer's policy.
 *
 * @code
 * GARC_Archive * archive = NULL;
 * if (garc_fs_open("backup.tar.xz", NULL, NULL, 0, &archive) == GARC_OK) {
 *   const GARC_Member * member;
 *   while (garc_next(archive, &member) == GARC_OK) {
 *     // ...
 *   }
 *   garc_close(archive); // closes the file too
 * }
 *
 * GARC_Sink * sink = NULL;
 * GARC_Writer * writer = NULL;
 * garc_fs_sink_create("out.tar.gz", "gzip", NULL, 0, &sink);
 * garc_writer_create(sink, GARC_FORMAT_TAR, NULL, &writer);
 * // ... garc_writer_add() and garc_writer_write() ...
 * garc_writer_finish(writer);
 * garc_sink_finish(sink); // the codec's trailer, then the rename
 * garc_writer_destroy(writer);
 * garc_sink_destroy(sink);
 * @endcode
 */

#ifndef GHOTI_IO_GARC_FS_H
#define GHOTI_IO_GARC_FS_H

#include <ghoti.io/archive/codec.h>
#include <ghoti.io/archive/core.h>
#include <ghoti.io/archive/macros.h>
#include <ghoti.io/archive/name.h>
#include <ghoti.io/archive/reader.h>
#include <ghoti.io/archive/writer.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create symbolic links and hard links.
 *
 * Without it, either member is ::GARC_ERR_REFUSED and not created. With it,
 * the target must still stay inside the root, and a hard link must name a
 * path this extract already claimed.
 */
#define GARC_FS_ALLOW_LINKS ((uint32_t)1u << 0)

/**
 * @brief Allow names ::garc_name_check() reports as ::GARC_NAME_PORTABILITY.
 *
 * That set includes a parent component, so `a/..` is refused unless this is
 * set. A `..` that leaves the root is ::GARC_NAME_ESCAPES and is still
 * refused. The flag does not make an absolute path, a drive, or a UNC path
 * legal.
 */
#define GARC_FS_ALLOW_PORTABLE_NAMES ((uint32_t)1u << 1)

/**
 * @brief Rename into place without asking the disk to commit first.
 *
 * For ::garc_fs_sink_create(). By default a finished sink asks the operating
 * system to commit the file before the rename, so a power loss leaves either
 * the old file or the whole new one. With this flag, a crash soon after
 * finishing can leave the new name pointing at an incomplete file on some
 * filesystems. Faster, and right for scratch output.
 */
#define GARC_FS_NO_SYNC ((uint32_t)1u << 2)

/**
 * @brief Let the file name decide a codec the bytes cannot.
 *
 * For ::garc_fs_open(). brotli and `.lzma` have no magic number. With this
 * flag, a name ending in `.br` or `.tbr` is read as brotli and one ending in
 * `.lzma` or `.tlzma` as `.lzma`, compared without case. It is consulted
 * only after the bytes have failed to say, so it never overrides a magic
 * number. `.tlz` is not on the list, because lzip uses it too.
 */
#define GARC_FS_NAME_HINT ((uint32_t)1u << 3)

/**
 * @brief Open a file as a stream.
 *
 * The stream can seek and knows its size, which are what zip and 7z need. It
 * owns the file, and ::garc_stream_destroy() closes it.
 *
 * @param path The file. UTF-8. Not NULL.
 * @param out_stream Receives the stream on success.
 * @return ::GARC_OK, ::GARC_ERR_NOT_FOUND, ::GARC_ERR_ACCESS,
 *   ::GARC_ERR_INVALID for a NULL argument or a directory, ::GARC_ERR_OOM, or
 *   ::GARC_ERR_IO.
 */
GARC_API GARC_Result garc_fs_stream_open(
    const char * path, GARC_Stream ** out_stream);

/**
 * @brief Open a file as a stream, using a given allocator.
 *
 * @param path The file. UTF-8. Not NULL.
 * @param allocator Allocator for the stream. NULL uses the default.
 * @param out_stream Receives the stream on success.
 * @return As ::garc_fs_stream_open().
 */
GARC_API GARC_Result garc_fs_stream_open_with_allocator(const char * path,
    const GARC_Allocator * allocator, GARC_Stream ** out_stream);

/**
 * @brief Create a sink that writes a file, compressed or not.
 *
 * The bytes go to a temporary file in @p path's directory, which must exist.
 * ::garc_sink_finish() writes the codec's trailer if there is a codec, then
 * renames the temporary file over @p path. An existing file at @p path is
 * replaced, and keeps its permissions. A new one gets what the platform gives
 * a new file. ::garc_sink_destroy() without a finish removes the temporary
 * file and leaves @p path untouched.
 *
 * With @p method NULL the sink can patch, so any writer can use it. With a
 * method the sink is a compressing one, and it cannot patch: a tar writer
 * works through it, and a zip writer uses data descriptors.
 *
 * @param path The file to create or replace. UTF-8. Not NULL.
 * @param method A `compress` method name such as `"gzip"`, or NULL for none.
 * @param options `compress` options for the encoder, or NULL. Ignored when
 *   @p method is NULL.
 * @param flags Zero or ::GARC_FS_NO_SYNC. Any other bit is
 *   ::GARC_ERR_INVALID.
 * @param out_sink Receives the sink on success.
 * @return ::GARC_OK, ::GARC_ERR_NOT_FOUND when the directory does not exist,
 *   ::GARC_ERR_ACCESS, ::GARC_ERR_INVALID, ::GARC_ERR_UNSUPPORTED for a method
 *   `compress` does not have, ::GARC_ERR_OOM, or ::GARC_ERR_IO. A commit
 *   that fails is ::GARC_ERR_ACCESS or ::GARC_ERR_IO from ::garc_sink_finish(),
 *   and a second finish is ::GARC_ERR_INVALID.
 */
GARC_API GARC_Result garc_fs_sink_create(const char * path,
    const char * method, gcomp_options_t * options, uint32_t flags,
    GARC_Sink ** out_sink);

/**
 * @brief Create a file sink, using a given allocator.
 *
 * @param path The file to create or replace. UTF-8. Not NULL.
 * @param method A `compress` method name, or NULL for none.
 * @param options `compress` options for the encoder, or NULL.
 * @param flags Zero or ::GARC_FS_NO_SYNC.
 * @param allocator Allocator for the sink and its state. NULL uses the
 *   default.
 * @param out_sink Receives the sink on success.
 * @return As ::garc_fs_sink_create().
 */
GARC_API GARC_Result garc_fs_sink_create_with_allocator(const char * path,
    const char * method, gcomp_options_t * options, uint32_t flags,
    const GARC_Allocator * allocator, GARC_Sink ** out_sink);

/**
 * @brief Open an archive file, detecting compression around it.
 *
 * The containers are tried first, on the file itself. If none matches, the
 * codec is detected as the file comment says, and the containers are tried
 * again on the decompressed bytes. Only one layer is removed, so a `.tar.gz.gz`
 * is not opened. A compressed archive cannot seek, so ::garc_find() on it is
 * ::GARC_ERR_NOT_SEEKABLE, and a zip or 7z inside a codec cannot be read at
 * all.
 *
 * The archive owns the file and any decompressing stream, and ::garc_close()
 * closes both.
 *
 * @param path The file. UTF-8. Not NULL.
 * @param limits Caps on the archive, or NULL for the defaults.
 * @param options `compress` options for a decoder, or NULL. Its defaults cap the
 *   decompressed bytes at 512 MiB, and a larger compressed archive needs a
 *   higher cap here; reaching it is ::GARC_ERR_LIMIT_CODEC_BYTES.
 * @param flags Zero or ::GARC_FS_NAME_HINT. Any other bit is
 *   ::GARC_ERR_INVALID.
 * @param out_archive Receives the archive on success.
 * @return ::GARC_OK; ::GARC_ERR_FORMAT when neither the file nor its
 *   decompressed bytes are an archive this library reads; otherwise as
 *   ::garc_fs_stream_open() and ::garc_open().
 */
GARC_API GARC_Result garc_fs_open(const char * path, const GARC_Limits * limits,
    gcomp_options_t * options, uint32_t flags, GARC_Archive ** out_archive);

/**
 * @brief Open an archive file, using a given allocator.
 *
 * @param path The file. UTF-8. Not NULL.
 * @param limits Caps on the archive, or NULL for the defaults.
 * @param options `compress` options for a decoder, or NULL.
 * @param flags Zero or ::GARC_FS_NAME_HINT.
 * @param allocator Allocator for the archive and its streams. NULL uses the
 *   default.
 * @param out_archive Receives the archive on success.
 * @return As ::garc_fs_open().
 */
GARC_API GARC_Result garc_fs_open_with_allocator(const char * path,
    const GARC_Limits * limits, gcomp_options_t * options, uint32_t flags,
    const GARC_Allocator * allocator, GARC_Archive ** out_archive);

/**
 * @brief Extract the archive's remaining members into @p root.
 *
 * @p root must already exist and be a directory. The walk starts at the
 * archive's current member, so a caller who has already stepped has already
 * chosen where extraction begins; the usual call is on an archive just
 * opened.
 *
 * @param archive The archive to read. Not NULL.
 * @param root The directory to write into. Not NULL.
 * @param flags Zero, or a combination of ::GARC_FS_ALLOW_LINKS and
 *   ::GARC_FS_ALLOW_PORTABLE_NAMES. Any other bit is ::GARC_ERR_INVALID.
 * @return ::GARC_OK, ::GARC_ERR_REFUSED, ::GARC_ERR_INVALID, ::GARC_ERR_OOM,
 *   ::GARC_ERR_NOT_FOUND when @p root does not exist, ::GARC_ERR_ACCESS,
 *   ::GARC_ERR_IO, or whatever failure ::garc_next() or ::garc_read_member()
 *   stopped on.
 */
GARC_API GARC_Result garc_fs_extract(GARC_Archive * archive, const char * root,
    uint32_t flags);

/**
 * @brief Pack the tree at @p root into an open writer.
 *
 * Does not finish the writer. A symlink is stored as a symlink, including
 * one whose target is outside the tree, and the outside file's bytes are not
 * read. A hard link to a path inside the tree is a hard link member. A hard
 * link to a path outside it is ::GARC_ERR_REFUSED. A fifo, a device, or any
 * other type is ::GARC_ERR_REFUSED. If the writer cannot store a hard link,
 * that status is returned and the pack stops.
 *
 * @param writer The writer to add members to. Not NULL.
 * @param root The directory to read. Not NULL. It must already exist.
 * @param flags As ::garc_fs_extract(). The link and portability flags do not
 *   change what a pack stores: a symlink is always a symlink. Unknown bits
 *   are still ::GARC_ERR_INVALID.
 * @return ::GARC_OK, ::GARC_ERR_REFUSED, ::GARC_ERR_INVALID, ::GARC_ERR_OOM,
 *   ::GARC_ERR_NOT_FOUND when @p root does not exist, ::GARC_ERR_ACCESS for a
 *   file or directory that cannot be read, ::GARC_ERR_IO, or the writer's own
 *   status when it cannot store a member.
 */
GARC_API GARC_Result garc_fs_pack(GARC_Writer * writer, const char * root,
    uint32_t flags);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GARC_FS_H
