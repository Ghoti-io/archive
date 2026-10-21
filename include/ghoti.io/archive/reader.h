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
 * Walking an archive: open it, step through its members, read the ones you
 * want.
 *
 * ```c
 * GARC_Limits limits;
 * garc_limits_default(&limits);
 *
 * GARC_Archive * archive = NULL;
 * if (garc_open(stream, &limits, &archive) != GARC_OK) { return; }
 *
 * const GARC_Member * member = NULL;
 * GARC_Result result;
 * while ((result = garc_next(archive, &member)) == GARC_OK) {
 *   if (wanted(member)) {
 *     char buffer[4096];
 *     size_t got = 0;
 *     while (garc_read_member(archive, buffer, sizeof(buffer), &got) == GARC_OK
 *         && got) {
 *       consume(buffer, got);
 *     }
 *   }
 * }
 * // result is GARC_END on a complete archive, or an error.
 * ```
 *
 * Three decisions in that loop, each of which could have gone the other way:
 *
 * **::garc_next() is a cursor, not an index**, even for a format that has an
 * index. A cursor is the only thing tar can offer - it has no directory, and it
 * can be read from a pipe - and one API both formats satisfy is worth more than
 * two that fit each perfectly. Random access is then an *addition* for the
 * formats that can support it, not a second mode.
 *
 * **Unread data is skipped for you.** Calling ::garc_next() again without
 * having read the current member's bytes is normal and cheap; the reader steps
 * over them, seeking when the stream can and discarding when it cannot. A
 * caller is never required to read data it does not want in order to reach the
 * next member.
 *
 * **::garc_read_member() fills a caller buffer.** There is no
 * allocate-and-return in this cut. compress added `gcomp_decode_alloc()` after
 * the bounded form existed and the order mattered: the bounded form is the one
 * a caller with a size limit can use, and the allocating one is a convenience
 * built on it rather than the other way round.
 */

#ifndef GHOTI_IO_GARC_READER_H
#define GHOTI_IO_GARC_READER_H

#include <ghoti.io/archive/core.h>
#include <ghoti.io/archive/macros.h>
#include <ghoti.io/archive/member.h>
#include <ghoti.io/archive/stream.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Which container an archive is.
 */
typedef enum {
  GARC_FORMAT_UNKNOWN = 0, ///< Not a container this library reads.
  GARC_FORMAT_TAR,         ///< A tar stream, in any of its variants.
  GARC_FORMAT_ZIP,         ///< A zip, which is read from its end backwards.
  GARC_FORMAT_SEVENZ,      ///< A 7z, whose header is at the end of the file.
  GARC_FORMAT_AR,          ///< A Unix ar archive: 60-byte headers, even padding.
  GARC_FORMAT_CPIO,        ///< cpio: newc, crc or odc; never the binary one.
  GARC_FORMAT_SHAR,        ///< A shell archive. Written, and never read.
  GARC_FORMAT_COUNT
} GARC_Format;

/**
 * @brief Name for a format, for messages and dumps.
 *
 * @param format The format.
 * @return A static string, never NULL.
 */
GARC_API const char * garc_format_string(GARC_Format format);

/**
 * @brief An archive being walked.
 */
typedef struct GARC_Archive GARC_Archive;

/**
 * @brief Open an archive over a stream.
 *
 * The container is identified from its first bytes. The stream is **borrowed**:
 * it must outlive the archive, and ::garc_close() does not destroy it, because
 * this library never frees what it did not allocate.
 *
 * @param stream The stream, positioned at the start of the archive.
 * @param limits Caps to apply. NULL uses ::garc_limits_default().
 * @param out_archive Receives the archive on success.
 * @return ::GARC_OK, ::GARC_ERR_INVALID, ::GARC_ERR_OOM,
 *   ::GARC_ERR_FORMAT when the bytes are not a container this library reads,
 *   or ::GARC_ERR_IO.
 */
GARC_API GARC_Result garc_open(GARC_Stream * stream, const GARC_Limits * limits,
    GARC_Archive ** out_archive);

/**
 * @brief Open an archive using a given allocator.
 *
 * @param stream The stream, positioned at the start of the archive.
 * @param limits Caps to apply. NULL uses ::garc_limits_default().
 * @param allocator Allocator for the archive and its buffers. NULL uses the
 *   default.
 * @param out_archive Receives the archive on success.
 * @return As ::garc_open().
 */
GARC_API GARC_Result garc_open_with_allocator(GARC_Stream * stream,
    const GARC_Limits * limits, const GARC_Allocator * allocator,
    GARC_Archive ** out_archive);

/**
 * @brief Which container this archive is.
 *
 * @param archive The archive. NULL returns ::GARC_FORMAT_UNKNOWN.
 * @return The format.
 */
GARC_API GARC_Format garc_format(const GARC_Archive * archive);

/**
 * @brief Give the archive a password, for what is encrypted in it.
 *
 * Zip and 7z take one; any other format is ::GARC_ERR_INVALID. The password is
 * copied and wiped when the archive is closed. It takes a length rather than
 * a string, and an empty password is a legitimate argument, distinct from
 * never having called this. Calling it again replaces the password, which is
 * how a caller tries a second one.
 *
 * **Zip.** ZipCrypto is read rather than trusted, and WinZip AES is read. The
 * traditional PKWARE cipher is keyed by three 32-bit words derived from these
 * bytes at this call; AES derives per member, because each member has its own
 * salt. ::garc_zip_member_encryption() says which scheme a member uses, and
 * it can be asked before this is called. The metadata is readable without a
 * password and is not affected by a wrong one, so this changes only what
 * ::garc_read_member() can do with an encrypted member, and it may be called
 * at any point in a walk. Three statuses can then come back from
 * ::garc_read_member(), and they are three because the cipher makes them
 * distinguishable to different degrees:
 *
 * - ::GARC_ERR_PASSWORD_REQUIRED - no password was set. Unambiguous.
 * - ::GARC_ERR_PASSWORD_REJECTED - the encryption header's single check byte
 *   disagreed, before any data was read. Catches 255 wrong passwords in 256; the
 *   only other cause is a corrupt encryption header.
 * - ::GARC_ERR_PASSWORD_OR_CORRUPT - ZipCrypto's CRC-32 disagreed after the
 *   check byte agreed, a WinZip AES HMAC disagreed after the 2-byte verifier
 *   agreed, or an encrypted LZMA member's codec header did not parse or ran
 *   out. **A 16-bit verifier can pass for a wrong password, once in 65536**,
 *   and ZipCrypto has no tag at all, so a wrong password and a damaged member
 *   are the same observation. The status names both rather than guessing.
 *   AE-2 does not treat a stored CRC of 0 as this failure; AE-1 still checks
 *   the CRC, and a mismatch after a matching HMAC is damage to the plaintext
 *   (::GARC_ERR_CORRUPT).
 *
 * **7z.** 7-Zip's AES is read: AES-256-CBC keyed by SHA-256 over the password
 * as UTF-16LE, so @p password is taken as **UTF-8** and converted, and bytes
 * that are not UTF-8 are ::GARC_ERR_INVALID. There is no check value of any
 * kind, so a wrong password is seen only when what is behind the cipher
 * fails to decode or a CRC-32 disagrees, and that is
 * ::GARC_ERR_PASSWORD_OR_CORRUPT from ::garc_read_member(); the walk goes on.
 * A member whose folder is encrypted and no password set is
 * ::GARC_ERR_PASSWORD_REQUIRED from ::garc_read_member().
 *
 * **An encrypted 7z header** (7-Zip's `-mhe=on`) hides the names, so
 * ::garc_open() succeeds and ::garc_next() is ::GARC_ERR_PASSWORD_REQUIRED
 * until a password decodes the header. That happens in this call, which then
 * returns what decoding it returned: ::GARC_ERR_PASSWORD_OR_CORRUPT for a
 * wrong password, after which another may be tried. Each try costs a key
 * derivation, 2^19 SHA-256 rounds as 7-Zip writes it.
 *
 * **Writing ZipCrypto is refused permanently**, and not for want of code: no
 * option name makes shipping a cipher known to be broken honest. A password on
 * a zip writer produces WinZip AES.
 *
 * @param archive The archive.
 * @param password The password bytes. May be NULL only when @p length is 0.
 * @param length Its length in bytes.
 * @return ::GARC_OK; ::GARC_ERR_INVALID for a NULL archive, an archive that
 *   is not a zip or a 7z, a NULL @p password with a non-zero @p length, or a
 *   7z password that is not UTF-8; ::GARC_ERR_OOM; or, for a 7z whose header
 *   is encrypted, what decoding the header returned.
 */
GARC_API GARC_Result garc_set_password(
    GARC_Archive * archive, const void * password, size_t length);

/**
 * @brief Step to the next member.
 *
 * Any of the current member's data that was not read is skipped. The member
 * handed back is **borrowed and valid only until the next call** to this
 * function or to ::garc_close(); a caller keeping a name copies it.
 *
 * @param archive The archive.
 * @param out_member Receives the member on ::GARC_OK. Untouched otherwise.
 * @return ::GARC_OK with a member, ::GARC_END at the end of the archive -
 *   which is **not** an error, see ::garc_result_is_error() - or a failure:
 *   ::GARC_ERR_CORRUPT, ::GARC_ERR_UNSUPPORTED, ::GARC_ERR_IO,
 *   ::GARC_ERR_OOM, one of the `GARC_ERR_LIMIT_*` codes, or
 *   ::GARC_ERR_INVALID.
 */
GARC_API GARC_Result garc_next(
    GARC_Archive * archive, const GARC_Member ** out_member);

/**
 * @brief Find a member by name, from the start of the archive.
 *
 * **This is a scan, and the name says `find` because that is what a caller
 * wants, not because there is an index.** tar has no index and cannot gain one:
 * the only way to know whether a name is present is to read every header until
 * it is. So this rewinds to where the archive began and walks forward, and the
 * cost is linear in the members before the match. It exists so that the walk is
 * written once, correctly - resetting a pax global record set on the way back is
 * easy to forget - rather than in every caller.
 *
 * **A stream that cannot seek gets ::GARC_ERR_NOT_SEEKABLE, and every
 * compressed archive is in that case permanently.** A `tar.gz` is a codec stream
 * with no seek (see codec.h), so there is no way back to the start and no index
 * to consult instead; random access into one means decompressing it to find the
 * offsets, which is not something a library should do behind a caller's back.
 * Walk it with ::garc_next() instead, or decompress it to something seekable
 * first. The refusal is checked before anything moves, so a refused find leaves
 * the cursor exactly where it was.
 *
 * On ::GARC_OK the member is current, exactly as if ::garc_next() had returned
 * it: ::garc_read_member() reads its bytes and ::garc_next() continues after it.
 * The name is matched **byte for byte with no normalisation**, so a directory
 * the archive spells `notes/` is found under `notes/` and not under `notes`.
 *
 * Two things a second walk changes, both documented rather than hidden:
 * ::garc_member_count() is reset and counts this walk, so after a successful
 * find it is the matched member's position; and the caps in ::GARC_Limits apply
 * to the scan from zero rather than to the sum of every pass.
 *
 * @param archive The archive.
 * @param name The name to match. May be NULL only when @p name_length is 0.
 * @param name_length Its length in bytes.
 * @param out_member Receives the member on ::GARC_OK. Untouched otherwise.
 * @return ::GARC_OK with a member, ::GARC_END when the archive holds no such
 *   name - which is **not** an error - ::GARC_ERR_NOT_SEEKABLE on a stream that
 *   cannot be rewound, ::GARC_ERR_INVALID, or whatever failure stopped the walk.
 */
GARC_API GARC_Result garc_find(GARC_Archive * archive, const void * name,
    size_t name_length, const GARC_Member ** out_member);

/**
 * @brief Read some of the current member's data.
 *
 * Call repeatedly until `*out_read` is zero, which is the end of the member.
 * Never reads past the member's declared size, so a member that declares less
 * than it contains cannot leak the next header's bytes into a caller's buffer.
 *
 * A member whose data ends before its declared size is ::GARC_ERR_CORRUPT: the
 * container said the bytes were there.
 *
 * @param archive The archive.
 * @param buffer Destination.
 * @param capacity Size of @p buffer.
 * @param out_read Receives the number of bytes read; 0 at the end of the
 *   member. Required.
 * @return ::GARC_OK, ::GARC_ERR_INVALID when there is no current member,
 *   ::GARC_ERR_CORRUPT on a truncated member, or ::GARC_ERR_IO.
 */
GARC_API GARC_Result garc_read_member(GARC_Archive * archive, void * buffer,
    size_t capacity, size_t * out_read);

/**
 * @brief Skip the rest of the current member's data.
 *
 * ::garc_next() does this anyway; this is for a caller that wants the failure
 * separately, or that is walking without stepping.
 *
 * @param archive The archive.
 * @return ::GARC_OK, ::GARC_ERR_INVALID, ::GARC_ERR_CORRUPT, or
 *   ::GARC_ERR_IO.
 */
GARC_API GARC_Result garc_skip_member(GARC_Archive * archive);

/**
 * @brief How many members have been handed out so far.
 *
 * The count ::GARC_Limits.max_members is compared against, exposed so a test
 * can assert the cap fired at the boundary rather than merely that it fired.
 *
 * @param archive The archive. NULL returns 0.
 * @return Members returned by ::garc_next() so far.
 */
GARC_API uint64_t garc_member_count(const GARC_Archive * archive);

/**
 * @brief How many bytes stand in front of the archive, inside the stream.
 *
 * A self-extracting stub, usually: an executable with the archive behind it.
 * For a zip it is ::garc_zip_base_offset(). For a 7z it is the stub a 7-Zip
 * self-extractor puts in front of the signature header, found by scanning the
 * first 8 MiB of a file that starts like an executable (PE, ELF or Mach-O).
 * 0 for every other format, and for an archive with nothing in front of it.
 * Counted from where the stream was when ::garc_open() was called.
 *
 * @param archive The archive. NULL returns 0.
 * @return The stub's length in bytes.
 */
GARC_API uint64_t garc_base_offset(const GARC_Archive * archive);

/**
 * @brief The running total of declared member sizes.
 *
 * What ::GARC_Limits.max_total_bytes is compared against. This is the cap no
 * codec can enforce, because each member decodes within its own expansion limit
 * and it is the *count* of members that multiplies.
 *
 * @param archive The archive. NULL returns 0.
 * @return Sum of the declared sizes of every member handed out so far.
 */
GARC_API uint64_t garc_total_declared_bytes(const GARC_Archive * archive);

/**
 * @brief Write a human-readable description of the archive's state.
 *
 * The format, the variant where the format has them, the counts the limits are
 * compared against, and the current member if there is one.
 *
 * @param archive The archive. NULL writes a line saying so.
 * @param out Destination. NULL is ignored.
 */
GARC_API void garc_archive_dump(const GARC_Archive * archive, FILE * out);

/**
 * @brief Close an archive. NULL is ignored.
 *
 * Does not touch the stream, which the caller owns.
 *
 * @param archive The archive.
 */
GARC_API void garc_close(GARC_Archive * archive);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GARC_READER_H
