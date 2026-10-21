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
 * What the 7z reader shares with the rest of the library.
 *
 * The reader's own state is opaque (`struct GARC_SevenZ`, defined in
 * sevenz_read.c) because it is a graph of folders, coders and substreams that
 * nothing outside the reader has a reason to touch. The archive holds a pointer.
 */

#ifndef GHOTI_IO_GARC_SRC_SEVENZ_SEVENZ_INTERNAL_H
#define GHOTI_IO_GARC_SRC_SEVENZ_SEVENZ_INTERNAL_H

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/core.h>
#include <stddef.h>
#include <stdint.h>

#include "reader/reader_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/** The six signature bytes, then a two-byte version, then the start header. */
#define GARC_SEVENZ_SIGNATURE_SIZE 6u

/** Signature, version, and the start header's 24 bytes plus its own CRC. */
#define GARC_SEVENZ_START_SIZE 32u

/**
 * Whether the first bytes are a 7z signature header.
 *
 * Six bytes decide it, and that is all identification looks at: a 7z found
 * behind a self-extracting stub is not looked for, because the format's header
 * is at the end and the stub's length is nobody's to guess.
 *
 * @param bytes The first bytes of the stream.
 * @param length How many there are.
 * @return Non-zero when they begin a 7z.
 */
int garc_sevenz_identify(const uint8_t * bytes, size_t length);

/**
 * Read the signature header, the header it points at, and build the member
 * list. Everything the format puts in the header is parsed here, so a walk
 * after this reads no metadata.
 *
 * @param archive The archive, positioned anywhere; the stream must seek.
 * @return ::GARC_OK, or the failure.
 */
GARC_Result garc_sevenz_open(GARC_Archive * archive);

/**
 * Find a 7z behind a self-extracting stub.
 *
 * Only when the first bytes are an executable's (PE, ELF or Mach-O) - which is
 * what a self-extractor is, and what keeps an arbitrary file from being
 * scanned - and only within ::GARC_SEVENZ_SFX_SCAN bytes. A signature counts
 * only when the start header after it checks: its CRC, a major version of 0,
 * and a next header that lies inside the stream.
 *
 * @param archive The archive, whose stream can seek and whose first bytes are
 *   in its peek buffer.
 * @param out_offset Receives the signature's offset from the start of the
 *   archive.
 * @return ::GARC_OK, ::GARC_ERR_FORMAT when there is none, or the stream's
 *   failure. The stream's position is unspecified after.
 */
GARC_Result garc_sevenz_locate_sfx(GARC_Archive * archive, uint64_t * out_offset);

/** How far into a file the self-extractor scan looks for the signature. */
#define GARC_SEVENZ_SFX_SCAN (8u * 1024u * 1024u)

/**
 * Advance to the next member.
 *
 * @param archive The archive.
 * @return ::GARC_OK with the member filled in, ::GARC_END, or a failure.
 */
GARC_Result garc_sevenz_next(GARC_Archive * archive);

/**
 * Read the current member's bytes.
 *
 * @param archive The archive.
 * @param buffer Destination.
 * @param capacity Its size.
 * @param out_read Receives the count; 0 at the end of the member.
 * @return ::GARC_OK or a failure.
 */
GARC_Result garc_sevenz_read(GARC_Archive * archive, void * buffer,
    size_t capacity, size_t * out_read);

/**
 * Give up the current member.
 *
 * @param archive The archive.
 * @return ::GARC_OK.
 */
GARC_Result garc_sevenz_skip(GARC_Archive * archive);

/**
 * Put the walk back at the first member.
 *
 * @param archive The archive.
 */
void garc_sevenz_rewind(GARC_Archive * archive);

/**
 * Free everything the reader allocated.
 *
 * @param archive The archive.
 */
void garc_sevenz_release(GARC_Archive * archive);

/**
 * The number of folders and of members, for ::garc_archive_dump().
 *
 * @param archive The archive.
 * @param out_folders Receives the folder count.
 * @param out_files Receives the entry count.
 */
void garc_sevenz_counts(
    const GARC_Archive * archive, uint64_t * out_folders, uint64_t * out_files);

/**
 * Decode one UTF-8 sequence, strictly: no overlong forms, no surrogates,
 * nothing past U+10FFFF. Shared by the writer's names and the reader's
 * passwords, which must agree on what UTF-8 is.
 *
 * @param p The bytes.
 * @param left How many there are.
 * @param cp Receives the code point.
 * @return The sequence's length, or 0 when it is malformed or cut short.
 */
size_t garc_sevenz_utf8_decode(const uint8_t * p, size_t left, uint32_t * cp);

/**
 * The 7z half of ::garc_set_password(): convert the password to the UTF-16LE
 * 7-Zip keys with, keep it, and decode the header if it was waiting for one.
 *
 * @param archive A 7z. The caller has checked it, and @p password against
 *   @p length.
 * @param password The password, UTF-8.
 * @param length Its length in bytes.
 * @return ::GARC_OK; ::GARC_ERR_INVALID for bytes that are not UTF-8;
 *   ::GARC_ERR_OOM; or, when the header is encrypted and this password does
 *   not decode it, what decoding it returned.
 */
GARC_Result garc_sevenz_set_password(
    GARC_Archive * archive, const void * password, size_t length);

/**
 * Whether the current member is encrypted: its folder has an AES coder, or
 * the header it was listed in was.
 *
 * @param archive A 7z, positioned on a member.
 * @return Non-zero when it is.
 */
int garc_sevenz_member_encrypted(const GARC_Archive * archive);

/**
 * A password as 7-Zip keys with it, and the last key derived from it.
 *
 * Deriving a key costs 2^19 SHA-256 compressions by default, and a non-solid
 * archive has one AES coder per folder, each normally with the same salt and
 * cost; so the last key is kept and reused when they match.
 */
typedef struct {
  uint8_t * utf16;      ///< The password in UTF-16LE, no terminator. Owned.
  size_t utf16_len;     ///< Its length in bytes.
  int have_key;         ///< Whether @ref key is valid for the fields below.
  uint8_t power;        ///< The cycle power @ref key was derived with.
  uint8_t salt[16];     ///< The salt it was derived with.
  size_t salt_len;      ///< Bytes of @ref salt in use.
  uint8_t key[32];      ///< The key.
  uint64_t rounds_spent; ///< Derivation rounds spent since the password was set.
  uint64_t rounds_cap;  ///< ::GARC_Limits.max_key_rounds; 0 is none.
} GARC_SevenZ_Password;

/**
 * A stream that decrypts 7-Zip's AES coder.
 *
 * @param allocator For the stream and its state.
 * @param inner The ciphertext. Borrowed.
 * @param props The coder's property bytes.
 * @param props_len Their length.
 * @param password The password; its key cache is updated.
 * @param out_size The plaintext's size, from the folder's unpack sizes.
 * @param out_stream Receives the stream.
 * @return ::GARC_OK, ::GARC_ERR_OOM, ::GARC_ERR_UNSUPPORTED for properties
 *   this library does not decode, ::GARC_ERR_CORRUPT for properties that are
 *   not 7-Zip's, or ::GARC_ERR_LIMIT_KEY_ROUNDS when deriving the key would
 *   pass the password's cap.
 */
GARC_Result garc_sevenz_aes_stream_create(const GARC_Allocator * allocator,
    GARC_Stream * inner, const uint8_t * props, size_t props_len,
    GARC_SevenZ_Password * password, uint64_t out_size,
    GARC_Stream ** out_stream);

/**
 * A stream that decodes BCJ2 from its four inputs.
 *
 * @param allocator For the stream and its state.
 * @param in The main, call, jump and range-coder streams, in that order.
 *   Borrowed.
 * @param out_size The decoded size, from the folder's unpack sizes.
 * @param out_stream Receives the stream.
 * @return ::GARC_OK or ::GARC_ERR_OOM.
 */
GARC_Result garc_sevenz_bcj2_stream_create(const GARC_Allocator * allocator,
    GARC_Stream * const in[4], uint64_t out_size, GARC_Stream ** out_stream);

/** One coder of a carried folder, as the header lists it. */
typedef struct {
  uint8_t id[8];      ///< The method id, most significant byte first.
  uint8_t id_len;     ///< Bytes of @ref id in use.
  uint32_t num_in;    ///< Streams it consumes.
  uint32_t num_out;   ///< Streams it produces.
  uint32_t props_off; ///< Into ::GARC_SevenZ_Carry.props.
  uint32_t props_len; ///< Its property bytes.
} GARC_SevenZ_Carry_Coder;

/** One folder of an archive being appended to, as its header lists it. */
typedef struct {
  uint32_t coder0;  ///< First coder, into ::GARC_SevenZ_Carry.coders.
  uint32_t ncoders; ///< Its coders.
  uint32_t bind0;   ///< First bind pair (two numbers each), into binds.
  uint32_t nbind;   ///< Its bind pairs.
  uint32_t packed0; ///< First packed in-stream index, into packed.
  uint32_t npacked; ///< Its packed streams.
  uint32_t unpack0; ///< First out-stream size, into unpack_sizes.
  uint32_t nout;    ///< Its out streams.
  uint32_t nsub;    ///< Members it holds.
  int has_crc;      ///< Whether it has a folder CRC-32.
  uint32_t crc;     ///< That CRC-32.
} GARC_SevenZ_Carry_Folder;

/** One entry of the file table of an archive being appended to. */
typedef struct {
  uint32_t name_off; ///< Into ::GARC_SevenZ_Carry.names, UTF-8.
  uint32_t name_len; ///< Its bytes.
  uint8_t flags;     ///< The ::GARC_SEVENZ_CARRY_EMPTY_STREAM family.
  uint64_t mtime;    ///< FILETIME ticks, with ::GARC_SEVENZ_CARRY_HAS_MTIME.
  uint32_t attrib;   ///< The attribute word, with ::GARC_SEVENZ_CARRY_HAS_ATTRIB.
} GARC_SevenZ_Carry_File;

#define GARC_SEVENZ_CARRY_EMPTY_STREAM 1u ///< No stream: a directory or empty file.
#define GARC_SEVENZ_CARRY_EMPTY_FILE 2u   ///< An empty stream that is a file.
#define GARC_SEVENZ_CARRY_ANTI 4u         ///< An empty stream that is an anti-item.
#define GARC_SEVENZ_CARRY_HAS_MTIME 8u    ///< Has a modification time.
#define GARC_SEVENZ_CARRY_HAS_ATTRIB 16u  ///< Has an attribute word.

/**
 * What an archive's header says, in the form a writer can say it again: the
 * tables an in-place append keeps and adds to (::garc_fs_update_begin()).
 *
 * Everything the reader keeps of a header, which is everything this library
 * reads: the packed streams, every folder's coders as they were, their sizes
 * and CRC-32s, how they divide into members, and the file table's names,
 * empty-stream, empty-file and anti bits, modification times and attributes.
 * Not carried, as the reader does not keep them: creation and access times,
 * a packed stream's own CRC-32, and archive properties.
 */
typedef struct GARC_SevenZ_Carry {
  /** Where the packed streams end, counted from the end of the start header. */
  uint64_t data_end;
  uint32_t num_pack;         ///< Packed streams.
  uint64_t * pack_sizes;     ///< Their sizes.
  uint32_t num_folders;      ///< Folders.
  GARC_SevenZ_Carry_Folder * folders; ///< The folders.
  GARC_SevenZ_Carry_Coder * coders;   ///< Every folder's coders.
  uint32_t * binds;          ///< Every bind pair: in-stream, then out-stream.
  uint32_t * packed;         ///< Every folder's packed in-stream indices.
  uint8_t * props;           ///< Every coder's properties.
  uint64_t * unpack_sizes;   ///< Every folder's out-stream sizes.
  uint64_t num_sub;          ///< Members with a stream, across the folders.
  uint64_t * sub_sizes;      ///< Each one's size.
  uint8_t * sub_has_crc;     ///< Whether each has a CRC-32.
  uint32_t * sub_crc;        ///< Each one's CRC-32.
  uint64_t num_files;        ///< Entries in the file table.
  GARC_SevenZ_Carry_File * files; ///< The entries.
  char * names;              ///< Their names, UTF-8, end to end.
} GARC_SevenZ_Carry;

/**
 * Copy an open 7z's header tables for an in-place append.
 *
 * @param archive A 7z, open.
 * @param allocator Where the copy is allocated.
 * @param out Receives the copy, freed with ::garc_sevenz_carry_free().
 * @return ::GARC_OK, ::GARC_ERR_OOM, or ::GARC_ERR_INVALID for an archive
 *   that is not a 7z.
 */
GARC_Result garc_sevenz_carry(const GARC_Archive * archive,
    const GARC_Allocator * allocator, GARC_SevenZ_Carry ** out);

/** Free a ::GARC_SevenZ_Carry; NULL is allowed. */
void garc_sevenz_carry_free(GARC_SevenZ_Carry * carry,
    const GARC_Allocator * allocator);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GARC_SRC_SEVENZ_SEVENZ_INTERNAL_H
