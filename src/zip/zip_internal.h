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
 * The zip reader's private surface.
 *
 * Reference documents:
 *   - PKWARE APPNOTE.TXT 6.3.10, the .ZIP File Format Specification, for every
 *     record and every field named here.
 *   - APPNOTE section 4.5 for the extra field ids: 0x0001 zip64, 0x000a NTFS,
 *     0x5455 extended timestamp, 0x7875 Unix uid/gid, 0x9901 WinZip AES.
 */

#ifndef GHOTI_IO_GARC_SRC_ZIP_ZIP_INTERNAL_H
#define GHOTI_IO_GARC_SRC_ZIP_ZIP_INTERNAL_H

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/zip.h>
#include <ghoti.io/security/aes_ctr.h>
#include <ghoti.io/security/hmac.h>
#include <stdint.h>

// GARC_Zip_State lives in reader_internal.h, beside tar's, because GARC_Archive
// holds one and needs the complete type. This header is what the zip reader's
// own translation units share with each other.
#include "reader/reader_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/** The fixed part of a local file header, before the name. */
#define GARC_ZIP_LOCAL_HEADER_SIZE 30u

/** The fixed part of a central directory entry, before the name. */
#define GARC_ZIP_CENTRAL_ENTRY_SIZE 46u

/** The end-of-central-directory record, with no comment. */
#define GARC_ZIP_EOCD_SIZE 22u

/** The zip64 end-of-central-directory locator, which sits before the EOCD. */
#define GARC_ZIP_ZIP64_LOCATOR_SIZE 20u

/** The fixed part of the zip64 end-of-central-directory record. */
#define GARC_ZIP_ZIP64_EOCD_SIZE 56u

/**
 * How far back from the end of the stream the end record can be.
 *
 * 22 bytes of record plus the largest comment its 16-bit length field can
 * describe. **This is the bound, and it is the whole reason the scan is a scan
 * rather than a search**: a reader that looked further would find an end-record
 * signature inside a member's data, which `python-data-decoy.zip` contains on
 * purpose.
 */
#define GARC_ZIP_EOCD_SEARCH_MAX (GARC_ZIP_EOCD_SIZE + 65535u)

/**
 * Read a 16-bit little-endian field.
 *
 * Shifts over bytes rather than a cast over memory: little-endian is a fact
 * about the *format*, so a reader that copied into a `uint16_t` would be right
 * only on a little-endian host and would raise a strict-aliasing question as
 * well.
 *
 * @param bytes At least two readable bytes.
 * @return The value.
 */
uint16_t garc_zip_le16(const uint8_t * bytes);

/**
 * Read a 32-bit little-endian field.
 *
 * @param bytes At least four readable bytes.
 * @return The value.
 */
uint32_t garc_zip_le32(const uint8_t * bytes);

/**
 * Read a 64-bit little-endian field.
 *
 * @param bytes At least eight readable bytes.
 * @return The value.
 */
uint64_t garc_zip_le64(const uint8_t * bytes);

/**
 * Write a 16-bit little-endian field.
 *
 * The mirror of ::garc_zip_le16, and shifts for the same reason: little-endian is
 * a fact about the format, so a `memcpy` from a `uint16_t` would be right on one
 * host and wrong on another.
 *
 * @param bytes Two bytes of destination.
 * @param value The value.
 */
void garc_zip_put16(uint8_t * bytes, uint16_t value);

/**
 * Write a 32-bit little-endian field.
 *
 * @param bytes Four bytes of destination.
 * @param value The value.
 */
void garc_zip_put32(uint8_t * bytes, uint32_t value);

/**
 * Write a 64-bit little-endian field.
 *
 * @param bytes Eight bytes of destination.
 * @param value The value.
 */
void garc_zip_put64(uint8_t * bytes, uint64_t value);

/**
 * Convert an epoch second to the two MS-DOS fields, clamping where it must.
 *
 * The inverse of ::garc_zip_dos_to_epoch, and lossy in three ways the field
 * cannot avoid: before 1980 and after 2107 it clamps, and an odd second rounds
 * down. **The return value is how the caller knows**, which is what lets the
 * writer decide whether an extended timestamp field is worth the bytes.
 *
 * @param seconds Seconds since the epoch, signed.
 * @param out_date Receives the DOS date field.
 * @param out_time Receives the DOS time field.
 * @return Non-zero when the two fields carry @p seconds exactly.
 */
int garc_zip_epoch_to_dos(
    int64_t seconds, uint16_t * out_date, uint16_t * out_time);

/**
 * Convert an MS-DOS date and time to seconds since the epoch, as UTC.
 *
 * **The field carries no time zone, so this is a decision rather than a
 * reading**, and ::GARC_TIME_ZIP_DOS on the member is how a caller knows which
 * decision was made. Every alternative is worse: reading the host's zone makes
 * one archive answer two ways, and declining to convert leaves
 * ::GARC_Member.mtime_seconds unfillable for the many archives that carry
 * nothing else.
 *
 * An out-of-range field is refused rather than converted. A date of zero, which
 * is what a writer with nothing to say puts there, has month 0 and day 0, and the
 * arithmetic would answer with a date that does not exist.
 *
 * @param date The date field: year from 1980 in the top 7 bits, month, day.
 * @param time The time field: hour, minute, and the second divided by two.
 * @param out_seconds Receives the value on success.
 * @return ::GARC_OK, or ::GARC_ERR_CORRUPT for a field out of range.
 */
GARC_Result garc_zip_dos_to_epoch(
    uint16_t date, uint16_t time, int64_t * out_seconds);

/**
 * Convert a Windows FILETIME to seconds and nanoseconds since the epoch.
 *
 * A FILETIME is 100-nanosecond intervals since 1601-01-01 UTC, which is what the
 * 0x000a extra field carries and the only timestamp in a zip with sub-second
 * precision. Exact on both sides of 1970: the fraction counts forward from the
 * whole second in both cases, which is the same reading the pax `mtime=` parser
 * settled on.
 *
 * @param filetime The value.
 * @param out_seconds Receives whole seconds, negative before 1970.
 * @param out_nanoseconds Receives the sub-second part, always forward.
 * @return ::GARC_OK.
 */
GARC_Result garc_zip_filetime_to_epoch(uint64_t filetime,
    int64_t * out_seconds, uint32_t * out_nanoseconds);

/**
 * Whether these first bytes are a zip's.
 *
 * Only the front, and only cheaply: a local file header, an end record for an
 * archive with no members, or a zip64 end record. **A zip behind a stub answers
 * no**, which is not a failure of this function - the other half of
 * identification is the backwards scan, which needs a seekable stream, and
 * separating the two is what lets ::garc_open() say ::GARC_ERR_NOT_SEEKABLE for a
 * zip on a pipe rather than ::GARC_ERR_FORMAT.
 *
 * @param bytes The first bytes of the stream.
 * @param length How many there are.
 * @return Non-zero when these are the first bytes of a zip.
 */
int garc_zip_identify(const uint8_t * bytes, size_t length);

/**
 * Whether a seekable stream ends with something that reads as a zip.
 *
 * The backwards scan, validating each candidate record rather than taking the
 * last signature: the comment length has to account for exactly the bytes after
 * the record. Leaves the stream position where it found it.
 *
 * @param archive The archive, whose stream must be seekable.
 * @param out_offset Receives the absolute offset of the end record on success.
 * @return ::GARC_OK with an offset, ::GARC_ERR_FORMAT when there is no such
 *   record, or an I/O or allocation failure.
 */
GARC_Result garc_zip_locate_eocd(GARC_Archive * archive, uint64_t * out_offset);

/**
 * Read the end record, the zip64 records behind it if any, and settle the base
 * offset.
 *
 * Called by ::garc_open() once the format is known. On failure the caller frees
 * the archive, so anything allocated here is released by ::garc_zip_release().
 *
 * @param archive The archive.
 * @param eocd_offset Where ::garc_zip_locate_eocd() found the end record.
 * @return ::GARC_OK, ::GARC_ERR_CORRUPT, ::GARC_ERR_UNSUPPORTED for a
 *   multi-disk archive, or an I/O or allocation failure.
 */
GARC_Result garc_zip_open(GARC_Archive * archive, uint64_t eocd_offset);

/** ZipCrypto's encryption header, which sits in front of a member's data. */
#define GARC_ZIP_CRYPT_HEADER_SIZE 12u

/**
 * Derive the three ZipCrypto keys from a password.
 *
 * ZipCrypto needs only these words afterwards. The password is still kept by
 * the reader, because WinZip AES derives a key per member from that member's
 * salt and cannot do it at this call.
 *
 * @param keys Receives the three words.
 * @param password The password bytes. May be NULL only when @p length is 0.
 * @param length Its length.
 */
void garc_zip_crypt_derive(uint32_t keys[3], const void * password,
    size_t length);

/**
 * Decrypt @p length bytes in place, advancing the keys.
 *
 * @param keys The cipher state, updated as it goes.
 * @param data Ciphertext in, plaintext out.
 * @param length How many bytes.
 */
void garc_zip_crypt_decrypt(uint32_t keys[3], uint8_t * data, size_t length);

/**
 * Whether a decrypted encryption header's check byte agrees.
 *
 * @param header The 12 decrypted bytes.
 * @param crc32 The member's declared CRC-32.
 * @param dos_time The member's DOS time field.
 * @param have_descriptor Whether general purpose flag bit 3 is set.
 * @return Non-zero when the password is probably right. See zip_crypt.c for
 *   which convention applies when, and why both are accepted.
 */
int garc_zip_crypt_header_ok(const uint8_t header[GARC_ZIP_CRYPT_HEADER_SIZE],
    uint32_t crc32, uint16_t dos_time, int have_descriptor);

/**
 * Create a stream that decrypts what it reads from @p inner.
 *
 * @p inner is **borrowed** and is read from wherever it is. No seek and no size,
 * because the keystream depends on the plaintext already produced: there is no
 * position in this stream a reader can return to.
 *
 * @param allocator For the stream and its state. NULL uses the default.
 * @param inner Where the ciphertext comes from.
 * @param keys The cipher state, copied, with the encryption header already mixed
 *   in.
 * @param out_stream Receives the stream on success.
 * @return ::GARC_OK, ::GARC_ERR_INVALID, or ::GARC_ERR_OOM.
 */
GARC_Result garc_zip_crypt_stream_create(const GARC_Allocator * allocator,
    GARC_Stream * inner, const uint32_t keys[3], GARC_Stream ** out_stream);

/** WinZip AES authentication code length, the first bytes of HMAC-SHA-1. */
#define GARC_ZIP_AES_AUTH_LEN 10u

/** Password verifier length in a WinZip AES member. */
#define GARC_ZIP_AES_VERIFIER_LEN 2u

/**
 * Salt, verifier and authentication code for a WinZip AES strength.
 *
 * Strength 1, 2 and 3 are AES-128, AES-192 and AES-256. Any other value,
 * including 0, returns 0: there is no salt length to subtract, and the caller
 * refuses the member before it asks for a password.
 *
 * @param strength The 0x9901 strength byte.
 * @return Salt plus 2 plus 10, or 0 when @p strength is not 1, 2 or 3.
 */
size_t garc_zip_aes_framing(uint8_t strength);

/**
 * The 0x9901 strength byte for a key size in bits.
 *
 * @param bits 128, 192 or 256.
 * @return 1, 2 or 3, or 0 when @p bits is none of those.
 */
uint8_t garc_zip_aes_strength(uint32_t bits);

/**
 * Derive the AES key, the HMAC key and the 2-byte verifier.
 *
 * PBKDF2-HMAC-SHA1, 1000 iterations. The derived material is split into the
 * AES key, the HMAC key of the same length, then the verifier. The derived
 * block is wiped before this returns. The caller wipes @p aes_key and
 * @p hmac_key.
 *
 * @param password Password bytes. NULL only when @p password_len is 0.
 * @param password_len Its length. Zero is an empty password.
 * @param salt The member's salt.
 * @param salt_len 8, 12 or 16.
 * @param aes_key Receives @p key_len bytes.
 * @param key_len 16, 24 or 32, matching @p salt_len.
 * @param hmac_key Receives @p key_len bytes.
 * @param verifier Receives the 2-byte verifier.
 * @return ::GARC_OK, or ::GARC_ERR_INTERNAL when the derivation refuses.
 */
GARC_Result garc_zip_aes_derive(const void * password, size_t password_len,
    const uint8_t * salt, size_t salt_len, uint8_t * aes_key, size_t key_len,
    uint8_t * hmac_key, uint8_t verifier[GARC_ZIP_AES_VERIFIER_LEN]);

/**
 * Whether two verifiers are equal.
 *
 * Compared with gsec_equal(). The length is the 2-byte verifier.
 *
 * @param expected The derived verifier.
 * @param actual The verifier from the member.
 * @return Non-zero when they match.
 */
int garc_zip_aes_verifier_matches(
    const uint8_t expected[GARC_ZIP_AES_VERIFIER_LEN],
    const uint8_t actual[GARC_ZIP_AES_VERIFIER_LEN]);

/**
 * Whether an HMAC-SHA-1 of @p ciphertext matches the first 10 bytes of @p tag.
 *
 * The full digest is 20 bytes. This does not ask `security` for a truncated
 * HMAC; it computes the digest and compares the prefix with gsec_equal().
 * An empty ciphertext is a NULL @p ciphertext with @p ciphertext_len 0.
 *
 * @param hmac_key The HMAC key.
 * @param key_len Its length.
 * @param ciphertext The ciphertext, and nothing else. Not the salt or the
 *   verifier.
 * @param ciphertext_len Its length.
 * @param tag The authentication code from the member.
 * @param tag_len Its length. Anything other than 10 does not match.
 * @return Non-zero when the prefix matches.
 */
int garc_zip_aes_auth_matches(const uint8_t * hmac_key, size_t key_len,
    const uint8_t * ciphertext, size_t ciphertext_len, const uint8_t * tag,
    size_t tag_len);

/**
 * A decrypting view of one WinZip AES member.
 *
 * @p inner is borrowed and is positioned at the first ciphertext byte. The
 * stream reads only @p ciphertext_len bytes of ciphertext from it, then the
 * 10-byte authentication code. HMAC failure does not fail the read that
 * delivered the plaintext: it clears @p auth_ok, and the call that reports the
 * member is over is what returns the status. @p auth_ok is set to 1 only when
 * the code matches. It is left 0 until then, including when the ciphertext is
 * not yet finished.
 *
 * @param allocator For the stream. NULL uses the default.
 * @param inner Where the ciphertext and the authentication code come from.
 * @param aes_key The AES key. Copied, and not wiped here.
 * @param hmac_key The HMAC key. Copied, and not wiped here.
 * @param key_len 16, 24 or 32.
 * @param ciphertext_len How many ciphertext bytes follow. Zero still reads the
 *   authentication code on the first read that asks for data; an empty member
 *   checks the code in the setup instead and does not create a stream.
 * @param auth_ok Set to 1 when the authentication code matches. Required.
 * @param out_stream Receives the stream on success.
 * @return ::GARC_OK, ::GARC_ERR_INVALID, or ::GARC_ERR_OOM.
 */
GARC_Result garc_zip_aes_stream_create(const GARC_Allocator * allocator,
    GARC_Stream * inner, const uint8_t * aes_key, const uint8_t * hmac_key,
    size_t key_len, uint64_t ciphertext_len, int * auth_ok,
    GARC_Stream ** out_stream);

/**
 * Key material for one member being written.
 *
 * Opaque. Salt and verifier are written by the caller from @p prefix. The
 * object holds the CTR context and the HMAC, and wipes both when it is
 * finished or destroyed.
 */
typedef struct GARC_Zip_Aes GARC_Zip_Aes;

/**
 * Draw a salt, derive the keys, and start CTR and HMAC for one member.
 *
 * The counter is the 16-byte little-endian integer 1. @p prefix receives the
 * salt and then the 2-byte verifier, which is what the member's data starts
 * with. The derived key block is wiped before this returns.
 *
 * @param allocator For the object. NULL uses the default.
 * @param password Password bytes. NULL only when @p password_len is 0.
 * @param password_len Its length.
 * @param strength 1, 2 or 3.
 * @param prefix Receives salt and verifier. Must hold 18 bytes.
 * @param prefix_cap Capacity of @p prefix.
 * @param prefix_len Receives how many bytes were written.
 * @param out Receives the object on success.
 * @return ::GARC_OK, ::GARC_ERR_INVALID, ::GARC_ERR_IO when the salt cannot be
 *   drawn, or ::GARC_ERR_OOM.
 */
GARC_Result garc_zip_aes_begin(const GARC_Allocator * allocator,
    const void * password, size_t password_len, uint8_t strength,
    uint8_t * prefix, size_t prefix_cap, size_t * prefix_len,
    GARC_Zip_Aes ** out);

/**
 * Encrypt one slice and absorb the ciphertext into the HMAC.
 *
 * @param aes A live object from ::garc_zip_aes_begin().
 * @param in Plaintext. NULL only when @p n is 0.
 * @param out Ciphertext. May be @p in.
 * @param n How many bytes.
 * @return ::GARC_OK, or ::GARC_ERR_INVALID.
 */
GARC_Result garc_zip_aes_encrypt(
    GARC_Zip_Aes * aes, const void * in, void * out, size_t n);

/**
 * A copy of the CTR and HMAC, so a failed sink write can put them back.
 *
 * The copy holds key material. Wipe it with ::garc_zip_aes_checkpoint_wipe()
 * when the write succeeded, or with ::garc_zip_aes_restore() when it did not.
 */
typedef struct GARC_Zip_Aes_Checkpoint {
  GSEC_Aes_Ctr ctr; ///< CTR state, including unused keystream.
  GSEC_Hmac hmac;   ///< HMAC state, including the outer pad.
} GARC_Zip_Aes_Checkpoint;

/**
 * Copy the CTR and HMAC from before a chunk is encrypted.
 *
 * @param aes A live writer object.
 * @param saved Receives the copy.
 */
void garc_zip_aes_checkpoint(
    const GARC_Zip_Aes * aes, GARC_Zip_Aes_Checkpoint * saved);

/**
 * Put the CTR and HMAC back and wipe the copy.
 *
 * @param aes The writer object the failed write advanced.
 * @param saved The copy from ::garc_zip_aes_checkpoint(). Wiped.
 */
void garc_zip_aes_restore(GARC_Zip_Aes * aes, GARC_Zip_Aes_Checkpoint * saved);

/**
 * Wipe a checkpoint that is no longer needed.
 *
 * @param saved The copy. NULL is ignored.
 */
void garc_zip_aes_checkpoint_wipe(GARC_Zip_Aes_Checkpoint * saved);

/**
 * Finish the HMAC and wipe the keys.
 *
 * Writes the first 10 bytes of the digest. The object is finished and must
 * still be destroyed.
 *
 * @param aes A live object.
 * @param tag Receives ::GARC_ZIP_AES_AUTH_LEN bytes.
 * @return ::GARC_OK, or ::GARC_ERR_INVALID.
 */
GARC_Result garc_zip_aes_finish(GARC_Zip_Aes * aes, uint8_t tag[GARC_ZIP_AES_AUTH_LEN]);

/**
 * Wipe and free an AES writer object. NULL is ignored.
 *
 * Safe after ::garc_zip_aes_finish(), and safe when finish was not called.
 *
 * @param aes The object.
 */
void garc_zip_aes_destroy(GARC_Zip_Aes * aes);

/**
 * Read some of the current member's data, decompressing where it has to.
 *
 * The same contract as ::garc_read_member(), which dispatches here: the bytes are
 * the member's *uncompressed* data, never more than it declared, and a member
 * whose data ends early is ::GARC_ERR_CORRUPT.
 *
 * **The call that returns zero bytes is where the CRC verdict arrives.** A
 * checksum covers a whole member, so it cannot be reported on the call that hands
 * over the last of the data - the caller would lose those bytes to an error
 * return. It is reported on the next call instead, which is the one that says the
 * member is over.
 *
 * @param archive The archive.
 * @param buffer Destination.
 * @param capacity Its size.
 * @param out_read Receives the count; 0 at the end of the member.
 * @return ::GARC_OK, ::GARC_ERR_CORRUPT for a truncated member or a CRC that
 *   does not match, ::GARC_ERR_LIMIT_CODEC_BYTES for a member that expands past
 *   what it declared, or a stream failure.
 */
GARC_Result garc_zip_read(
    GARC_Archive * archive, void * buffer, size_t capacity, size_t * out_read);

/**
 * Abandon the rest of the current member's data.
 *
 * **Nothing is read and nothing is sought**, because in a zip nothing depends on
 * where the stream is: the next member's position comes from the central
 * directory. So this drops the decoder and the byte count, and - deliberately -
 * the CRC verdict with them, since a member that was not read has no checksum to
 * compare against.
 *
 * @param archive The archive.
 * @return ::GARC_OK.
 */
GARC_Result garc_zip_skip(GARC_Archive * archive);

/**
 * Step to the next central directory entry and describe it.
 *
 * @param archive The archive.
 * @return ::GARC_OK with ::GARC_Archive.member filled in, ::GARC_END after the
 *   last declared entry, or a failure.
 */
GARC_Result garc_zip_next(GARC_Archive * archive);

/**
 * The most bytes deflate can turn @p size bytes into.
 *
 * `gcomp_encode_bound()` for the deflate method, with its three failure modes
 * collapsed into `UINT64_MAX` - the answer that is safe for all of them, since the
 * one caller is asking whether a 32-bit field can be promised to hold the result.
 *
 * **The zip writer decides a member's zip64 fields on this rather than on the
 * declared size**, because the local header is written before the data and a
 * compressed size that crossed 4 GiB afterwards would have nowhere to go.
 *
 * Asked of `compress` rather than spelled here, and the first version did spell it:
 * RFC 1951's own worst case is five bytes per 65535-byte stored block, and
 * compress's encoder reserves rather more than that. A remembered constant was
 * below the implementation's real bound for every size over 65534, which a test
 * comparing the two found immediately - and which is exactly the shape of failure
 * that makes a bound worth asking for rather than deriving.
 *
 * @param size The uncompressed size.
 * @return The bound, saturating at `UINT64_MAX`.
 */
uint64_t garc_zip_deflate_bound(uint64_t size);

/**
 * Put the walk back to the first entry, leaving what open discovered alone.
 *
 * @param archive The archive.
 */
void garc_zip_rewind(GARC_Archive * archive);

/**
 * Free everything the zip reader allocated for this archive.
 *
 * @param archive The archive.
 */
void garc_zip_release(GARC_Archive * archive);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GARC_SRC_ZIP_ZIP_INTERNAL_H
