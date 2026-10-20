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
 * control byte, and a colon, asterisk, question mark, double quote, angle
 * bracket or vertical bar in a member name - a colon would open an alternate
 * data stream. A symbolic link member is ::GARC_ERR_REFUSED there
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
 * @brief Append to an uncompressed tar where it ends, instead of rewriting it.
 *
 * For ::garc_fs_update_begin(). See there for what it gives up.
 */
#define GARC_FS_IN_PLACE ((uint32_t)1u << 4)

/**
 * @brief An archive file being changed: deleted from, added to, renamed in.
 *
 * Made by ::garc_fs_update_begin(), which hands back two halves - a reader
 * over the archive as it is, and a writer for what it will be - and ended by
 * ::garc_fs_update_commit() or ::garc_fs_update_destroy().
 */
typedef struct GARC_Fs_Update GARC_Fs_Update;

/**
 * @brief Begin changing an archive file.
 *
 * **By default the archive is rewritten**, which works for every format this
 * library both reads and writes. ::garc_fs_update_archive() walks the archive as
 * it is; each member the caller wants kept goes to the writer with
 * ::garc_fs_update_keep(), each it does not is passed over, and new members go
 * to ::garc_fs_update_writer() as to any writer. So deleting is not keeping,
 * replacing is not keeping plus adding, renaming is
 * ::garc_writer_copy_member() with a new name, and appending is
 * ::garc_fs_update_keep_rest() plus adding. The writer writes a temporary file
 * beside the archive, and ::garc_fs_update_commit() renames it over the
 * original, so until then - and if anything fails - the original is exactly as
 * it was.
 *
 * A kept zip member is copied as stored, with ::GARC_COPY_RAW: nothing is
 * recompressed, an encrypted one needs no password, and a method this library
 * cannot write survives. A compressed tar is written back through the codec it
 * was read through. A kept 7z member is decoded and encoded again, because 7z's
 * members share their compressed streams; one this library cannot decode (BCJ2,
 * encrypted) is refused by ::garc_fs_update_keep() before anything is written,
 * and the caller decides.
 *
 * **With ::GARC_FS_IN_PLACE**, for an uncompressed tar only, nothing is
 * rewritten: the writer starts where the archive's end marker was, as `tar -r`
 * does, and ::garc_fs_update_archive() is NULL. That is quick for a large
 * archive and it is **not atomic**. If the process dies partway, the members
 * that were there are still read, and the one being written is cut short. A
 * destroy without a commit writes the end marker back where it was, so an
 * abandoned append leaves the archive reading as it did. A tar with a pax global
 * header is refused in place, because the header would apply to the appended
 * members too.
 *
 * @param path The archive. UTF-8. Not NULL.
 * @param limits Caps for reading it, or NULL for the defaults.
 * @param options For the writer, or NULL for the defaults. The format is the
 *   archive's whatever is set here, and the options apply to what the writer
 *   writes: new members, and kept members of formats that are re-encoded.
 * @param flags Zero, or ::GARC_FS_IN_PLACE, ::GARC_FS_NO_SYNC and
 *   ::GARC_FS_NAME_HINT. Any other bit is ::GARC_ERR_INVALID.
 * @param out_update Receives the update.
 * @return ::GARC_OK; ::GARC_ERR_UNSUPPORTED for ::GARC_FS_IN_PLACE on anything
 *   but an uncompressed tar, or for a format this library does not write;
 *   otherwise as ::garc_fs_open() and ::garc_fs_sink_create().
 */
GARC_API GARC_Result garc_fs_update_begin(const char * path,
    const GARC_Limits * limits, const GARC_Writer_Options * options,
    uint32_t flags, GARC_Fs_Update ** out_update);

/**
 * @brief Begin changing an archive file, using a given allocator.
 *
 * @param path The archive. UTF-8. Not NULL.
 * @param limits Caps for reading it, or NULL.
 * @param options For the writer, or NULL.
 * @param flags As ::garc_fs_update_begin().
 * @param allocator Allocator for everything the update holds. NULL uses the
 *   default.
 * @param out_update Receives the update.
 * @return As ::garc_fs_update_begin().
 */
GARC_API GARC_Result garc_fs_update_begin_with_allocator(const char * path,
    const GARC_Limits * limits, const GARC_Writer_Options * options,
    uint32_t flags, const GARC_Allocator * allocator,
    GARC_Fs_Update ** out_update);

/**
 * @brief The archive as it is, to walk with ::garc_next().
 *
 * @param update The update.
 * @return The reader, owned by the update; NULL for an in-place append.
 */
GARC_API GARC_Archive * garc_fs_update_archive(GARC_Fs_Update * update);

/**
 * @brief The writer for what the archive will be.
 *
 * Add members to it as to any writer. Do not finish it:
 * ::garc_fs_update_commit() does.
 *
 * @param update The update.
 * @return The writer, owned by the update.
 */
GARC_API GARC_Writer * garc_fs_update_writer(GARC_Fs_Update * update);

/**
 * @brief Keep the reader's current member, unchanged.
 *
 * ::garc_writer_copy_member() with ::GARC_COPY_RAW for zip and plainly for the
 * rest, so nothing is changed that can be kept as it was.
 *
 * @param update A rewriting update.
 * @return As ::garc_writer_copy_member(); ::GARC_ERR_INVALID for an in-place one.
 */
GARC_API GARC_Result garc_fs_update_keep(GARC_Fs_Update * update);

/**
 * @brief Keep every member the reader has not reached yet.
 *
 * The walk, from where it is to the end, with ::garc_fs_update_keep() for each.
 * Appending to a rewritten archive is this, then the new members.
 *
 * @param update A rewriting update.
 * @return ::GARC_OK when the walk ended, or the first failure.
 */
GARC_API GARC_Result garc_fs_update_keep_rest(GARC_Fs_Update * update);

/**
 * @brief Finish the archive and put it in place.
 *
 * Finishes the writer, closes the original - which Windows needs before
 * anything is renamed over it - and renames the new file over it. An in-place
 * append is finished, synced unless ::GARC_FS_NO_SYNC, and closed. The update is
 * spent either way: destroy it.
 *
 * @param update The update.
 * @return ::GARC_OK, or what the writer or the rename failed with, in which
 *   case the original is unchanged (for a rewrite).
 */
GARC_API GARC_Result garc_fs_update_commit(GARC_Fs_Update * update);

/**
 * @brief Release an update, abandoning it if it was not committed.
 *
 * A rewrite's temporary file is removed. An in-place append's end marker is
 * written back where the original's was.
 *
 * @param update The update. NULL is accepted.
 */
GARC_API void garc_fs_update_destroy(GARC_Fs_Update * update);

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
 * ::GARC_ERR_NOT_SEEKABLE. A zip inside a codec is read from the front, as
 * zip.h describes for any stream that cannot seek; a 7z inside one cannot be
 * read at all.
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
 * Every member's data is read to the reader's end, which is where a zip
 * member's CRC-32 or AES tag is checked, so a damaged member is a failure
 * and not a file. A sparse member is written with its holes left as holes:
 * each 4 KiB block of zeros, aligned to the file's offsets, is sought over
 * rather than written. The bytes are the same either way.
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
 * Does not finish the writer. Each file is streamed from disk rather than read
 * whole. A file with holes - where the filesystem says so, through
 * `gcu_file_next_data()` - is written as a sparse member when the writer can
 * write one (tar with ::GARC_TAR_PAX, the default), so the archive holds its
 * data and not its holes; every other writer gets the file's real content. A
 * file that shrinks while it is being packed is ::GARC_ERR_IO, because its
 * header already gave its size. A symlink is stored as a symlink, including
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
