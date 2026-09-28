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
 * What is specific to zip.
 *
 * **A zip is read backwards, and that is the whole shape of it.** The End Of
 * Central Directory record is at the end of the file; it says where the central
 * directory is; the central directory's entries say where each member's local
 * header is. Every value this library reports about a member comes from the
 * **central directory**, and the local header is consulted for exactly one
 * thing: where the member's data starts, which only it can say because its name
 * and extra fields are sized independently of the central directory's.
 *
 * That is not a preference. A streamed zip writes zeroes for the sizes in the
 * local header and the real values after the data - libarchive does it for every
 * member, into a seekable file - so a reader that believed the local header
 * would report a size of zero for archives every tool on earth reads correctly.
 * And where the two disagree deliberately, the central directory is what every
 * real tool follows, which makes trusting the local header an ambiguity attack
 * waiting for a reader to write.
 *
 * Three consequences a caller meets:
 *
 * **A zip needs a seekable stream, and a zip on a pipe is refused by name.**
 * ::GARC_ERR_NOT_SEEKABLE, from ::garc_open(), for a stream whose first bytes
 * are a zip signature and which cannot seek. tar can be read from a pipe
 * because a tar is a sequence of headers from the front; a zip cannot, because
 * the answer to "what members are in this" is at the other end of the file.
 * There is no streaming mode here, and adding one would mean reading the local
 * headers, which is the thing that cannot be trusted.
 *
 * **A zip must end where the stream ends.** The scan for the end record starts
 * at the end and goes back at most 65,557 bytes, which is the largest a record
 * plus its comment can be. Bytes *before* the archive are fine and common - a
 * self-extracting stub is exactly that - and ::garc_zip_base_offset() reports
 * how many there were. Bytes *after* it are not: an archive with a megabyte of
 * anything appended cannot be found by any reader that follows the format, and
 * this one reports ::GARC_ERR_FORMAT rather than scanning the whole file, where
 * it would find a signature inside a member's data.
 *
 * **What a member is compressed with is a number, and a refusal names it.**
 * Methods 0 (stored) and 8 (deflate) are the ones that matter; 9, 12, 14, 93 and
 * 98 exist and are refused with ::GARC_ERR_UNSUPPORTED, and
 * ::garc_zip_member_method() plus ::garc_zip_method_string() say which, so the
 * refusal is a to-do list rather than a dead end. The same is true of
 * encryption: ::garc_zip_member_encryption() distinguishes the broken cipher
 * from the sound one, because "unsupported" alone cannot tell a caller whether
 * a password would help.
 *
 * **A password is set on the archive, and ZipCrypto is read but never written.**
 * ::garc_zip_set_password() decrypts the traditional PKWARE cipher, which is
 * broken - about a dozen known plaintext bytes recover its keys - and is still
 * what a great many archives in the world use. WinZip AES is phase H's, and
 * until then a member using it is refused with ::garc_zip_member_encryption()
 * saying AES, so the refusal names what a caller would have to wait for.
 *
 * **Nothing about a zip's metadata is encrypted, at any password strength.**
 * Names, sizes, times, modes and the whole directory structure are in the clear
 * in both zip schemes. A caller who needs to hide *which files exist* cannot do
 * it with a zip, and should not infer confidentiality the format does not offer.
 */

#ifndef GHOTI_IO_GARC_ZIP_H
#define GHOTI_IO_GARC_ZIP_H

#include <ghoti.io/archive/core.h>
#include <ghoti.io/archive/macros.h>
#include <ghoti.io/archive/reader.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief The compression methods zip defines and this library has an opinion
 *   about.
 *
 * **Not an enum a member's method is reported as.** The method is a 16-bit
 * number in the archive, any value can appear in one, and an enum would either
 * lose the value or need a `GARC_ZIP_METHOD_OTHER` that a caller then has to
 * work around. ::garc_zip_member_method() returns the number; these are names
 * for the ones a message or a test wants to spell.
 */
typedef enum {
  GARC_ZIP_METHOD_STORED = 0,    ///< No compression. Read.
  GARC_ZIP_METHOD_SHRUNK = 1,    ///< PKWARE shrink. Refused.
  GARC_ZIP_METHOD_REDUCED_1 = 2, ///< PKWARE reduce, factor 1. Refused.
  GARC_ZIP_METHOD_REDUCED_2 = 3, ///< Factor 2. Refused.
  GARC_ZIP_METHOD_REDUCED_3 = 4, ///< Factor 3. Refused.
  GARC_ZIP_METHOD_REDUCED_4 = 5, ///< Factor 4. Refused.
  GARC_ZIP_METHOD_IMPLODED = 6,  ///< PKWARE implode. Refused.
  GARC_ZIP_METHOD_DEFLATE = 8,   ///< RFC 1951, which compress implements.
  GARC_ZIP_METHOD_DEFLATE64 = 9, ///< Enhanced deflate. Refused; not RFC 1951.
  GARC_ZIP_METHOD_BZIP2 = 12,    ///< Refused; no codec.
  GARC_ZIP_METHOD_LZMA = 14,     ///< Refused; no codec.
  GARC_ZIP_METHOD_ZSTD = 93,     ///< Refused today; compress has the codec.
  GARC_ZIP_METHOD_XZ = 95,       ///< Refused; no codec.
  GARC_ZIP_METHOD_PPMD = 98,     ///< Refused; no codec.
  GARC_ZIP_METHOD_AES = 99       ///< WinZip AES; the real method is in 0x9901.
} GARC_Zip_Method;

/**
 * @brief Where a written member's CRC-32 and compressed size go.
 *
 * **Neither is known when the local header is written**, so a zip writer has two
 * ways out and they produce different bytes: leave zeros in the header and write
 * the real values in a *data descriptor* after the data, with general purpose flag
 * bit 3 set; or go back and fill the header in once the data is done. Both are
 * valid and every reader takes either - the central directory carries the real
 * values in both cases, which is why this library's reader consults the local
 * header for one thing only.
 *
 * The choice is exposed because it is a property of the archive a caller may need
 * to control, not merely a route the bytes take. A consumer that reads a zip as a
 * stream needs the descriptors; a consumer that refuses them - and some old tools
 * do - needs the other form.
 */
typedef enum {
  /**
   * Fill the local header in when the sink can, use a descriptor when it cannot.
   *
   * The default, and the only value that never refuses: it asks
   * ::garc_sink_is_seekable() and writes whichever form that sink supports. A
   * memory sink patches; a pipe or a compressing sink gets descriptors.
   */
  GARC_ZIP_SIZES_AUTO = 0,
  /**
   * Always write a data descriptor, even into a sink that could be patched.
   *
   * What libarchive does for every member, which is why `bsdtar-descriptors.zip`
   * in the corpus has local headers saying a size of zero where its central
   * directory says fifteen. Useful for producing an archive that can be read
   * without seeking, and for testing that this library reads its own.
   */
  GARC_ZIP_SIZES_DESCRIPTOR,
  /**
   * Always fill the local header in; refuse a sink that cannot be patched.
   *
   * ::GARC_ERR_NOT_SEEKABLE from ::garc_writer_create(), by name, because the
   * caller asked for something this sink cannot do rather than for a feature this
   * library lacks.
   */
  GARC_ZIP_SIZES_LOCAL,
  GARC_ZIP_SIZES_COUNT
} GARC_Zip_Sizes;

/**
 * @brief Name for a size discipline, for messages and dumps.
 *
 * @param sizes The discipline.
 * @return A static string, never NULL.
 */
GARC_API const char * garc_zip_sizes_string(GARC_Zip_Sizes sizes);

/**
 * @brief How a member is encrypted, where it is.
 *
 * Two schemes rather than a bit, because they are not the same answer to a
 * caller. ZipCrypto is broken - a dozen known plaintext bytes recover the keys,
 * and a zip is full of known bytes - and this library will read it and will
 * never write it. WinZip AES is sound, and needs a cryptographic library this
 * one does not yet depend on. "Unsupported" alone cannot tell a caller which of
 * those they are looking at, nor whether supplying a password could ever help.
 */
typedef enum {
  GARC_ZIP_ENCRYPTION_NONE = 0, ///< Not encrypted.
  GARC_ZIP_ENCRYPTION_ZIPCRYPTO, ///< The traditional PKWARE cipher. Broken.
  GARC_ZIP_ENCRYPTION_AES,       ///< WinZip AES, method 99 with a 0x9901 field.
  GARC_ZIP_ENCRYPTION_COUNT
} GARC_Zip_Encryption;

/**
 * @brief Name for a compression method, for messages and dumps.
 *
 * @param method The method number, as the archive carried it.
 * @return A static string, never NULL. A number with no name is "unknown".
 */
GARC_API const char * garc_zip_method_string(uint16_t method);

/**
 * @brief Name for an encryption scheme, for messages and dumps.
 *
 * @param encryption The scheme.
 * @return A static string, never NULL.
 */
GARC_API const char * garc_zip_encryption_string(
    GARC_Zip_Encryption encryption);

/**
 * @brief The current member's compression method, as the central directory
 *   carried it.
 *
 * @param archive The archive. NULL, or one that is not a zip, returns 0 -
 *   which is ::GARC_ZIP_METHOD_STORED, so ask ::garc_format() rather than
 *   reading a method from an archive that may not be a zip.
 * @return The method number of the member ::garc_next() last returned.
 */
GARC_API uint16_t garc_zip_member_method(const GARC_Archive * archive);

/**
 * @brief The current member's general purpose bit flags.
 *
 * Bit 0 is "encrypted", bit 3 "the sizes are in a data descriptor", bit 11
 * "the name and comment are UTF-8". The rest are the compression level hints
 * and method-specific bits, which this library does not act on.
 *
 * @param archive The archive. NULL or not a zip returns 0.
 * @return The flags of the member ::garc_next() last returned.
 */
GARC_API uint16_t garc_zip_member_flags(const GARC_Archive * archive);

/**
 * @brief The current member's compressed size, from the central directory.
 *
 * ::GARC_Member.size is the *uncompressed* size, because that is the one a
 * caller reading the member needs. This is the other one, for a caller
 * measuring an archive rather than reading it.
 *
 * @param archive The archive. NULL or not a zip returns 0.
 * @return The number of bytes the member occupies in the archive.
 */
GARC_API uint64_t garc_zip_member_compressed_size(
    const GARC_Archive * archive);

/**
 * @brief The CRC-32 the central directory declares for the current member.
 *
 * Declared, not verified: nothing has been read yet when ::garc_next() returns.
 * A member whose data does not match this is a member whose data does not match
 * it, which is answered when the data is read.
 *
 * @param archive The archive. NULL or not a zip returns 0.
 * @return The declared CRC-32.
 */
GARC_API uint32_t garc_zip_member_crc32(const GARC_Archive * archive);

/**
 * @brief The `version made by` field of the current member.
 *
 * The high byte is the host system - 0 is FAT/DOS, 3 is Unix, 10 is NTFS - and
 * the low byte is ten times the zip specification version. **It is the high byte
 * that decides whether ::GARC_Member.mode means anything**: the mode bits live
 * in the top half of `external_file_attributes`, and on an archive made by a
 * DOS or Windows writer that half is zero rather than absent. A reader that
 * reads mode bits unconditionally invents permissions of 0000 for every member
 * of a Windows-made zip.
 *
 * @param archive The archive. NULL or not a zip returns 0.
 * @return The field, host system in the high byte.
 */
GARC_API uint16_t garc_zip_member_version_made_by(
    const GARC_Archive * archive);

/**
 * @brief The `external file attributes` field of the current member, whole.
 *
 * The low byte is the DOS attribute bits, of which 0x10 is "directory" and is
 * how a zip written on Windows says so; the high 16 bits are a Unix `st_mode`
 * where the host system says Unix. Reported unmasked because this library
 * reports what the container said.
 *
 * @param archive The archive. NULL or not a zip returns 0.
 * @return The field.
 */
GARC_API uint32_t garc_zip_member_external_attributes(
    const GARC_Archive * archive);

/**
 * @brief How the current member is encrypted, if it is.
 *
 * @param archive The archive. NULL or not a zip returns
 *   ::GARC_ZIP_ENCRYPTION_NONE.
 * @return The scheme.
 */
GARC_API GARC_Zip_Encryption garc_zip_member_encryption(
    const GARC_Archive * archive);

/**
 * @brief Give the archive a password, for members that are encrypted.
 *
 * **ZipCrypto only, and it is read rather than trusted.** The traditional
 * PKWARE cipher is keyed by three 32-bit words derived from these bytes; this
 * call derives them and **does not keep the password**, which is why it takes a
 * length rather than a string and why an empty password is a legitimate
 * argument. WinZip AES (method 99) is not decrypted in this cut and a password
 * makes no difference to it - ::garc_zip_member_encryption() is what says which
 * scheme a member uses, and it can be asked before this is called.
 *
 * **The metadata is readable without a password and is not affected by a wrong
 * one.** So this changes nothing about walking the archive; it changes only what
 * ::garc_read_member() can do with an encrypted member, and it may be called at
 * any point in a walk. Calling it again replaces the password, which is how a
 * caller tries a second one after ::GARC_ERR_PASSWORD_REJECTED.
 *
 * Three statuses can then come back from ::garc_read_member(), and they are three
 * because the cipher makes them distinguishable to different degrees:
 *
 * - ::GARC_ERR_PASSWORD_REQUIRED - no password was set. Unambiguous.
 * - ::GARC_ERR_PASSWORD_REJECTED - the encryption header's single check byte
 *   disagreed, before any data was read. Catches 255 wrong passwords in 256; the
 *   only other cause is a corrupt encryption header.
 * - ::GARC_ERR_PASSWORD_OR_CORRUPT - the member was decrypted and its CRC-32
 *   disagreed. **ZipCrypto has no authentication tag, so a wrong password and a
 *   damaged member are the same observation** and the status names both rather
 *   than guessing.
 *
 * **Writing ZipCrypto is refused permanently**, and not for want of code: no
 * option name makes shipping a cipher known to be broken honest. A caller who
 * needs to *produce* an encrypted zip waits for WinZip AES.
 *
 * @param archive The archive.
 * @param password The password bytes. May be NULL only when @p length is 0.
 * @param length Its length in bytes.
 * @return ::GARC_OK, or ::GARC_ERR_INVALID for a NULL archive, an archive that
 *   is not a zip, or a NULL @p password with a non-zero @p length.
 */
GARC_API GARC_Result garc_zip_set_password(
    GARC_Archive * archive, const void * password, size_t length);

/**
 * @brief How many bytes of extra field the central directory gave this member.
 *
 * What ::GARC_Limits.max_extra_bytes is compared against, exposed so a test can
 * assert the cap fired at the boundary rather than merely that it fired. This is
 * the central directory's count; the local header's is usually different and is
 * not this.
 *
 * @param archive The archive. NULL or not a zip returns 0.
 * @return The length of the member's extra field in the central directory.
 */
GARC_API size_t garc_zip_member_extra_length(const GARC_Archive * archive);

/**
 * @brief Whether the current member's metadata needed a zip64 extra field.
 *
 * A size, a compressed size or a local header offset that does not fit its
 * 32-bit field is written as `0xFFFFFFFF`, with the real value in a 0x0001
 * extra field. This says that happened for this member, which is not the same
 * as the *archive* being a zip64 one: `zip -fz` writes zip64 fields for a
 * fifteen-byte member, and a 5 GB archive can hold members that need none.
 *
 * @param archive The archive. NULL or not a zip returns 0.
 * @return Non-zero when a 0x0001 extra field supplied a value.
 */
GARC_API int garc_zip_member_used_zip64(const GARC_Archive * archive);

/**
 * @brief How far into the stream the archive's own offsets are measured from.
 *
 * Zero for an ordinary zip. Non-zero when there are bytes in front of the
 * archive that its central directory does not count - a self-extracting stub is
 * the usual reason - in which case every offset in the file is short by this
 * much and a reader that ignored it would seek into the stub.
 *
 * It is *discovered*, not declared: the end record says how big the central
 * directory is and where it claims to be, and the difference between that claim
 * and where it actually turned out to be is this. That makes it the one number
 * here this library worked out rather than read, which is why it is reported
 * rather than silently applied.
 *
 * Note that it is relative to where ::garc_open() was given the stream, not to
 * the start of the file: an archive inside another one is at a non-zero stream
 * offset without having a stub at all.
 *
 * @param archive The archive. NULL or not a zip returns 0.
 * @return Bytes between the start of the archive and where its offsets count
 *   from.
 */
GARC_API uint64_t garc_zip_base_offset(const GARC_Archive * archive);

/**
 * @brief How many members the end record said the archive holds.
 *
 * The declared count, which is what the walk is bounded by. A central directory
 * that runs out early is ::GARC_ERR_CORRUPT rather than a shorter archive.
 *
 * @param archive The archive. NULL or not a zip returns 0.
 * @return The declared number of central directory entries.
 */
GARC_API uint64_t garc_zip_declared_members(const GARC_Archive * archive);

/**
 * @brief Whether the archive carries a zip64 end record.
 *
 * Distinct from ::garc_zip_member_used_zip64(), which is about one member's
 * fields. An archive has these records when its own counts or its central
 * directory's position do not fit the 32-bit fields - or when a writer was told
 * to produce them anyway, which `zip -fz` does for a fifteen-byte archive. A
 * member can need zip64 fields in an archive that has no zip64 end record, and
 * the other way round, so the two questions are two functions.
 *
 * @param archive The archive. NULL or not a zip returns 0.
 * @return Non-zero when a zip64 end record supplied the counts.
 */
GARC_API int garc_zip_has_zip64_end_record(const GARC_Archive * archive);

/**
 * @brief The archive comment, as bytes.
 *
 * Borrowed, and valid until ::garc_close(). Never NUL-terminated as a promise:
 * a comment is bytes, and the one in `python-comments.zip` deliberately contains
 * an end-of-central-directory signature.
 *
 * @param archive The archive. NULL or not a zip returns NULL.
 * @param out_length Receives the length in bytes. Required.
 * @return The comment bytes, or NULL when there is no comment.
 */
GARC_API const char * garc_zip_archive_comment(
    const GARC_Archive * archive, size_t * out_length);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GARC_ZIP_H
