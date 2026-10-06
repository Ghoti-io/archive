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
 * Building an archive: add a member, write its bytes, finish.
 *
 * ```c
 * GARC_Sink * sink = NULL;
 * garc_sink_create_memory(&sink);
 *
 * GARC_Writer * writer = NULL;
 * garc_writer_create(sink, GARC_FORMAT_TAR, NULL, &writer);
 *
 * GARC_Member member;
 * memset(&member, 0, sizeof(member));
 * member.name = "notes.txt";
 * member.name_length = 9;
 * member.type = GARC_MEMBER_FILE;
 * member.size = 5;
 * member.mode = 0644;
 * member.mode_valid = 1;
 *
 * garc_writer_add(writer, &member);
 * garc_writer_write(writer, "hello", 5);
 * garc_writer_finish(writer);          // the end-of-archive marker
 * ```
 *
 * Four decisions in that, each of which could have gone the other way:
 *
 * **The member a writer is given is ::GARC_Member, the same struct the reader
 * hands out.** A separate `GARC_Member_Spec` was the tidier design and would
 * have cost every archive-copying caller a translation step - and copying an
 * archive is the main thing a reader and a writer are used for together. The
 * price is that two fields are inputs to nothing: ::GARC_Member.header_offset
 * and ::GARC_Member.data_offset are where a member *was*, and a writer decides
 * where it goes. They are ignored, and that is said here rather than left to be
 * discovered.
 *
 * **A member's size is declared before its bytes, and writing a different
 * number of them is an error.** tar puts the size in the header, which is
 * written before the data, so the size cannot be discovered by writing - and a
 * writer that padded or truncated to fit would produce an archive whose header
 * lies. ::garc_writer_add() and ::garc_writer_finish() both refuse while a
 * member is short, with ::GARC_ERR_INVALID: the caller said how many bytes there
 * would be. ::garc_writer_data_remaining() is how many are still owed.
 *
 * **There are no limits here.** ::GARC_Limits caps a *reader*, which allocates
 * on a declaration it did not make; a writer allocates on its caller's own
 * request, so a cap would be this library second-guessing the program that
 * called it. What the caps exist to prevent cannot happen on this side. The
 * property worth having instead is that an archive this library writes is one it
 * reads back under the default caps, and that is a test rather than a field.
 *
 * **::GARC_Member.mtime_source is an input as well as a report, and it is the one
 * field a round trip cannot always keep.** ::GARC_TIME_NONE writes no time at
 * all; ::GARC_TIME_PAX_DECIMAL asks for an extended record even when the seconds
 * would fit the header field, so that a member read out of a pax archive and
 * written back into one still says a record answered for it. But a time the octal
 * field *cannot* hold - anything negative, or above 8589934591 - can only be
 * written as a record, so it reads back as ::GARC_TIME_PAX_DECIMAL whatever was
 * asked. The writer's fuzz harness found that on its first run, which is the
 * argument for saying it here.
 *
 * **Nothing is normalised.** A directory's trailing slash is the caller's to
 * include or leave out, and the typeflag is what says it is a directory either
 * way. This is the writing half of the reader's rule that a member reports what
 * the container said: a writer that appended a slash, stripped a leading `./`,
 * or rewrote a name that ::garc_name_check() has findings about would be
 * deciding something the caller is better placed to decide - and phase F's
 * extraction layer is where that decision belongs.
 */

#ifndef GHOTI_IO_GARC_WRITER_H
#define GHOTI_IO_GARC_WRITER_H

#include <ghoti.io/archive/core.h>
#include <ghoti.io/archive/macros.h>
#include <ghoti.io/archive/member.h>
#include <ghoti.io/archive/reader.h>
#include <ghoti.io/archive/sink.h>
#include <ghoti.io/archive/tar.h>
#include <ghoti.io/archive/zip.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief An archive being built.
 */
typedef struct GARC_Writer GARC_Writer;

/**
 * @brief How an archive is to be written.
 *
 * Pass NULL wherever this is accepted to use ::garc_writer_options_default(),
 * which is pax with no record padding.
 *
 * **A zero-filled struct is not the defaults, and that is deliberate.**
 * ::GARC_Tar_Variant's zero is ::GARC_TAR_NONE, which names no format, so a
 * caller who zeroes this and passes it gets ::GARC_ERR_INVALID rather than
 * whatever this library happens to prefer. The lazy path is NULL; the explicit
 * path says what it wants. A zero that silently meant "pax" would make the
 * variant field unreadable at the call site.
 */
typedef struct GARC_Writer_Options {
  /**
   * Which of tar's formats to write.
   *
   * ::GARC_TAR_PAX is the default and is what GNU tar and bsdtar both write
   * today. ::GARC_TAR_USTAR writes the same headers and **refuses** anything
   * that would need an extended record - a name over 255 bytes, a size over
   * 8 GiB, a time before the epoch, a sub-second time - with
   * ::GARC_ERR_UNSUPPORTED naming the member. That is the point of having it: a
   * caller who needs an archive a 1988 reader can read wants to be told, rather
   * than handed one with records in it.
   *
   * ::GARC_TAR_V7 and ::GARC_TAR_GNU are refused. v7 cannot express a member's
   * type, its owner's name, or a name over 100 bytes, and nothing reads only v7;
   * GNU's `L` and `K` carriers are read here because archives contain them, and
   * writing them would be choosing a vendor extension over the standard that
   * replaced it.
   */
  GARC_Tar_Variant tar_variant;

  /**
   * Pad the archive out to a multiple of this many 512-byte blocks.
   *
   * Zero writes the two zero blocks that end an archive and nothing more, which
   * is what bsdtar does and is the default. 20 is what GNU tar writes, because
   * 10240 bytes was a tape record; every reader accepts either, and a caller
   * writing to a tape drive or matching another tool's output byte for byte is
   * the reason this is a knob rather than a constant.
   */
  uint32_t blocking_factor;

  /**
   * Where a zip member's CRC-32 and compressed size go. Ignored for tar.
   *
   * ::GARC_ZIP_SIZES_AUTO is the default and asks the sink. See
   * ::GARC_Zip_Sizes, which is where the choice is argued.
   */
  GARC_Zip_Sizes zip_sizes;

  /**
   * Which method a zip member's data is written with. Ignored for tar.
   *
   * ::GARC_ZIP_METHOD_STORED is the default, and only
   * ::GARC_ZIP_METHOD_DEFLATE is accepted beside it - every other value is
   * refused by ::garc_writer_create() with ::GARC_ERR_UNSUPPORTED, including the
   * ones this library can *read*. Reading a method means having a decoder for
   * it; writing one means choosing to produce it, and a zstd or an LZMA member
   * is refused by enough readers that a caller should have to name it rather
   * than inherit it.
   *
   * **Stored is the default because zero is stored.** Every other field in this
   * struct is written so that a zero-filled options struct behaves like the
   * defaults or is refused outright, and ::GARC_ZIP_METHOD_STORED is 0 - so a
   * default of deflate would make this the one field where a caller who
   * memset their options gets something other than what NULL would have given
   * them. A caller who wants their bytes compressed says so in one assignment,
   * and that assignment is visible in their code.
   *
   * Two things are decided per member rather than by this field, because the
   * format decides them:
   *
   * - **A member with no data is stored** whatever this says. Deflating nothing
   *   produces a two-byte empty final block, so the choice is between a member
   *   that occupies 0 bytes and one that occupies 2, and every reference writes
   *   the first. A directory reaches that by having no data; an empty file
   *   reaches it by declaring none.
   * - **A symlink is stored.** Its target is its data - zip has no link field -
   *   and a target is a path: short enough that deflate rarely helps, and needed
   *   by every reader that wants to know what the link points at. This library's
   *   own reader reads a target eagerly only when it is stored, which is a
   *   deliberate limit argued where it is written, and every symlink every
   *   reference in the corpus wrote is stored too. So this is not a concession to
   *   our own reader: it is what a zip symlink looks like.
   * - **A member whose data does not compress is still deflated.** The method is
   *   in a local header written before the first byte of data arrives, so there
   *   is no point at which it could be changed back. `zip` stores such a member
   *   instead, which it can because it has the whole file on disk before it
   *   writes anything; a streaming writer does not. The cost is deflate's
   *   stored-block overhead, five bytes per 65535.
   */
  GARC_Zip_Method zip_method;

  /**
   * Password for WinZip AES, or NULL when the archive is not encrypted.
   *
   * NULL with ::zip_password_length 0 is no encryption, which is what a
   * zero-filled struct does and what NULL options do. A non-NULL pointer with
   * length 0 is an empty password and does encrypt. NULL with a non-zero
   * length is ::GARC_ERR_INVALID from ::garc_writer_create(). The bytes are
   * copied into the writer; the caller may free them when create returns.
   *
   * A directory is never encrypted. A file, an empty file, and a symlink
   * target are, when this is set. ZipCrypto is not produced.
   */
  const void * zip_password;

  /**
   * Length of ::zip_password in bytes.
   *
   * Zero with a NULL ::zip_password is no encryption. Zero with a non-NULL
   * pointer is an empty password.
   */
  size_t zip_password_length;

  /**
   * AES key size in bits for an encrypted member.
   *
   * 0, 128, 192 or 256. 0 means 256 when a password is set, and means nothing
   * when it is not. Any other value is ::GARC_ERR_INVALID from
   * ::garc_writer_create(). Ignored for tar. A zero-filled struct leaves this
   * 0, so an unencrypted archive stays unencrypted.
   */
  uint32_t zip_aes_bits;

  /**
   * Write zip64 fields on every member, whether or not they are needed.
   *
   * **Off by default, and the default is the rule the format wants**: a zip64
   * field appears only for a value that does not fit its 32-bit slot, because an
   * archive that carries them unnecessarily is refused by some old readers. So
   * this is not a knob to reach for.
   *
   * It exists because the threshold needs a test on both sides of it and the
   * upper side is a 4 GiB member. `zip -fz` exists for the same reason, and
   * `infozip-zip64.zip` in the corpus is what it produced: two small members with
   * their size fields marked and a zip64 extra carrying the real values. Ignored
   * for tar.
   */
  int zip_force_zip64;
} GARC_Writer_Options;

/**
 * @brief Fill in the default options.
 *
 * @param options Structure to populate. NULL is ignored.
 */
GARC_API void garc_writer_options_default(GARC_Writer_Options * options);

/**
 * @brief Create a writer over a sink.
 *
 * The sink is **borrowed**: it must outlive the writer, and
 * ::garc_writer_destroy() does not destroy it, because this library never frees
 * what it did not allocate. Nothing is written until the first
 * ::garc_writer_add().
 *
 * @param sink Where the bytes go.
 * @param format Which container to write: ::GARC_FORMAT_TAR or
 *   ::GARC_FORMAT_ZIP.
 * @param options How to write it. NULL uses ::garc_writer_options_default().
 * @param out_writer Receives the writer on success.
 * @return ::GARC_OK, ::GARC_ERR_INVALID, ::GARC_ERR_OOM,
 *   ::GARC_ERR_UNSUPPORTED for a format or a variant this library does not
 *   write, or ::GARC_ERR_NOT_SEEKABLE when ::GARC_ZIP_SIZES_LOCAL is asked of a
 *   sink that cannot be patched.
 */
GARC_API GARC_Result garc_writer_create(GARC_Sink * sink, GARC_Format format,
    const GARC_Writer_Options * options, GARC_Writer ** out_writer);

/**
 * @brief Create a writer using a given allocator.
 *
 * @param sink Where the bytes go.
 * @param format Which container to write.
 * @param options How to write it. NULL uses the defaults.
 * @param allocator Allocator for the writer and its buffers. NULL uses the
 *   default.
 * @param out_writer Receives the writer on success.
 * @return As ::garc_writer_create().
 */
GARC_API GARC_Result garc_writer_create_with_allocator(GARC_Sink * sink,
    GARC_Format format, const GARC_Writer_Options * options,
    const GARC_Allocator * allocator, GARC_Writer ** out_writer);

/**
 * @brief Begin a member: write its metadata, and any records it needs.
 *
 * The previous member's data is padded out first, so a caller never pads. The
 * member struct is **read and not kept**; every byte it points at is copied
 * before this returns.
 *
 * What is refused, and why each is a refusal rather than a repair:
 *
 * - **An empty name**, and a name or link target containing a NUL. No writer
 *   produces either and no filesystem holds one, and a NUL in particular would
 *   make the header field and the extended record disagree about where the name
 *   ends - a member whose name depends on which reader is asked, which is the
 *   same thing the reader refuses a carrier payload for.
 * - **::GARC_MEMBER_OTHER**, which is a *reading* of a typeflag this library
 *   does not name rather than a thing to write. There is no byte to put in the
 *   field.
 * - **A non-zero size on a member that carries no data** - a directory, a
 *   symlink, a fifo, a device. The reader ignores a stale size there because
 *   real archives have one; a writer that ignored it would accept a caller's
 *   declaration and then not let them write the bytes.
 * - **A symlink or hard link with no target**, and a device with
 *   ::GARC_Member.device_valid clear. Both are the member's defining field.
 * - **A value no field can hold**: a size at or above 2^63, a device number
 *   over 2^62. These are the ranges ::garc_next() refuses from the other side.
 *
 * @param writer The writer.
 * @param member What to write. Borrowed for the duration of the call;
 *   `header_offset` and `data_offset` are ignored.
 * @return ::GARC_OK, ::GARC_ERR_INVALID for one of the refusals above or while
 *   the previous member is still short of its declared size,
 *   ::GARC_ERR_UNSUPPORTED when the chosen variant cannot express the member,
 *   ::GARC_ERR_OOM, or ::GARC_ERR_IO from the sink.
 */
GARC_API GARC_Result garc_writer_add(
    GARC_Writer * writer, const GARC_Member * member);

/**
 * @brief Write some of the current member's data.
 *
 * Call as often as convenient; the writer counts. Writing more than the member
 * declared is ::GARC_ERR_INVALID, and the bytes are not written - a header that
 * says one length and a body that is another is an archive no reader can
 * recover, so it is refused at the call that would have done it rather than at
 * the end.
 *
 * @param writer The writer.
 * @param data The bytes. May be NULL only when @p size is 0.
 * @param size How many.
 * @return ::GARC_OK, ::GARC_ERR_INVALID when there is no current member, when
 *   it carries no data, or when this would exceed the declared size, or
 *   ::GARC_ERR_IO.
 */
GARC_API GARC_Result garc_writer_write(
    GARC_Writer * writer, const void * data, size_t size);

/**
 * @brief Finish the archive: pad, write the end marker, pad again.
 *
 * Two zero blocks, then out to ::GARC_Writer_Options.blocking_factor. After
 * this the writer accepts nothing more.
 *
 * **Not called by ::garc_writer_destroy(), and that is the point.** Finishing
 * can fail, a destructor cannot report it, and a destructor that finished
 * silently would turn an abandoned archive into a complete-looking one. So
 * destroying without finishing leaves a truncated archive on purpose, which is
 * how a caller abandons a write.
 *
 * @param writer The writer.
 * @return ::GARC_OK, ::GARC_ERR_INVALID when a member is still short of its
 *   declared size or the archive is already finished, or ::GARC_ERR_IO.
 */
GARC_API GARC_Result garc_writer_finish(GARC_Writer * writer);

/**
 * @brief How many members have been added.
 *
 * @param writer The writer. NULL returns 0.
 * @return Members begun by ::garc_writer_add(). An extended-record member is
 *   metadata and is not counted, for the reason ::garc_member_count() does not
 *   count one either.
 */
GARC_API uint64_t garc_writer_member_count(const GARC_Writer * writer);

/**
 * @brief How many bytes the current member still owes.
 *
 * Zero when there is no member, or when the current one is complete. Exposed so
 * that a test can assert the boundary rather than only the refusal either side
 * of it, and so that a caller streaming from a source of unknown length can tell
 * how far off its own declaration was before ::garc_writer_add() tells it.
 *
 * @param writer The writer. NULL returns 0.
 * @return Bytes still to be written for the current member.
 */
GARC_API uint64_t garc_writer_data_remaining(const GARC_Writer * writer);

/**
 * @brief Write a human-readable description of the writer's state.
 *
 * @param writer The writer. NULL writes a line saying so.
 * @param out Destination. NULL is ignored.
 */
GARC_API void garc_writer_dump(const GARC_Writer * writer, FILE * out);

/**
 * @brief Destroy a writer. NULL is ignored.
 *
 * Does not finish the archive and does not touch the sink; see
 * ::garc_writer_finish().
 *
 * @param writer The writer.
 */
GARC_API void garc_writer_destroy(GARC_Writer * writer);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GARC_WRITER_H
