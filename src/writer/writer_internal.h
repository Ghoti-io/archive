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
 * The writer object, shared by the generic writer and each format's writer.
 */

#ifndef GHOTI_IO_GARC_SRC_WRITER_WRITER_INTERNAL_H
#define GHOTI_IO_GARC_SRC_WRITER_WRITER_INTERNAL_H

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/writer.h>
#include <stddef.h>
#include <stdint.h>

#include <ghoti.io/compress/options.h>
#include <ghoti.io/compress/stream.h>

#include "core/buffer_internal.h"
#include "reader/reader_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * What only the zip writer looks at.
 *
 * A named member rather than a union arm beside a tar one, for the reason
 * ::GARC_Zip_State gives on the reading side: nothing in C stops one format's
 * writer filling one arm and another reading the other, and the saving is a few
 * dozen bytes on an object a caller allocates once per archive.
 */
typedef struct {
  /**
   * Every central directory entry written so far, concatenated.
   *
   * **A zip's directory cannot be written until every member's offset is known**,
   * so it is accumulated here and emitted by garc_zip_write_end(). That is a
   * property of the format rather than a choice: the end record points at the
   * directory and the directory points back at the local headers. The cost is
   * about 46 bytes plus a name per member, held until the archive is finished,
   * and it is worth saying out loud because tar's writer holds nothing at all.
   */
  GARC_Buffer central;
  /** How many entries are in @ref central. */
  uint64_t entries;

  /**
   * The encoder, created for the first member that needs one.
   *
   * **One encoder for the archive, reset between members**, not one per member:
   * every member is an independent stream, which is what
   * gcomp_encoder_reset() produces, and a zip of ten thousand small files would
   * otherwise allocate and free a window ten thousand times. NULL until a
   * compressed member arrives, so an archive of stored members allocates
   * nothing. The method is the archive's, so the encoder is never asked to
   * change codecs between members.
   */
  gcomp_encoder_t * encoder;
  /**
   * Options the encoder was created with, kept for its whole life.
   *
   * NULL for deflate and zstd. LZMA sets `lzma.raw` and nothing else, so the
   * encoder's defaults stay the ones the zip header claims. `compress` keeps
   * the pointer; freeing it at create would be a guess.
   */
  gcomp_options_t * encoder_options;
  /**
   * Where @ref encoder's output lands on its way to the sink. Owned.
   *
   * Allocated with the encoder and freed with it. A fixed size rather than a
   * growable buffer, because the encoder is asked to fill it repeatedly until it
   * has nothing left - the same arrangement the compressing sink uses, for the
   * same reason.
   */
  uint8_t * packed;

  /**
   * @name The member being written
   * @{
   */
  /** Where its local header starts, as an offset from the first byte written. */
  uint64_t local_offset;
  /** Where its local header's CRC-32 field starts, for the patching form. */
  uint64_t crc_offset;
  /** Where its local header's zip64 extra payload starts, or 0 for none. */
  uint64_t zip64_offset;
  /** CRC-32 of the data written so far, unfinalized. */
  uint32_t running_crc;
  /** Bytes the member occupies in the archive, which for stored is its size. */
  uint64_t compressed;
  /** Its declared uncompressed size. */
  uint64_t declared;
  /** Its general purpose flags, as written. */
  uint16_t flags;
  /** Its method, as written. */
  uint16_t method;
  /** Its DOS date field, as written. */
  uint16_t dos_date;
  /** Its DOS time field, as written. */
  uint16_t dos_time;
  /** Its `external file attributes`, as written. */
  uint32_t external_attributes;
  /** Its name, copied because the central entry needs it at finish. */
  GARC_Buffer name;
  /**
   * Its *central* extra field, built when the member was added.
   *
   * Not the same bytes as the local header's: the zip64 payload is 8 bytes here
   * against 16 there, because the compressed size is known by the time the
   * directory is written. Built at add rather than at close so that the rule
   * deciding what goes in it lives in one place.
   */
  GARC_Buffer extra;
  /** Whether this member's records carry zip64 fields. */
  int used_zip64;
  /**
   * Whether this member is WinZip AES.
   *
   * A directory is never encrypted. A file, an empty file and a symlink are,
   * when @ref password has been set. The header method is then 99 and
   * @ref method stays the real compression method.
   */
  int aes;
  /** Non-zero once any member of this archive was written as AES. */
  int wrote_aes;
  /**
   * Non-zero once a cleartext member needed version 46.
   *
   * Bzip2. An AES member does not set it: its version stays 51.
   */
  int needs_46;
  /**
   * Non-zero once a cleartext member needed version 63.
   *
   * Zstd and LZMA. An AES member does not set it: its version stays 51.
   */
  int needs_63;
  /** The password, copied at create and wiped on release. NULL when unset. */
  uint8_t * password;
  /** Length of @ref password. Zero with @ref have_password is an empty password. */
  size_t password_length;
  /** Whether a password was set. Distinct from a zero @ref password_length. */
  int have_password;
  /** 1, 2 or 3 when @ref have_password is set. 0 otherwise. */
  uint8_t aes_strength;
  /**
   * CTR and HMAC for the member being written, or NULL.
   *
   * Owned. Wiped by finish and by release.
   */
  struct GARC_Zip_Aes * aes_state;
  /** @} */
} GARC_Zip_Write_State;

/**
 * An archive being written.
 *
 * Opaque to callers, for the reason ::GARC_Archive gives.
 */
struct GARC_Writer {
  /** The sink, borrowed. The caller destroys it; garc_writer_destroy() does
   *  not. */
  GARC_Sink * sink;
  /** Allocator for this object and its buffer. */
  const GARC_Allocator * allocator;
  /** Which container. */
  GARC_Format format;
  /** The options, resolved at create so that NULL means the defaults once. */
  GARC_Writer_Options options;

  /** Members begun, which garc_writer_member_count() reports. */
  uint64_t member_count;
  /** Bytes of the current member's data still owed by the caller. */
  uint64_t data_remaining;
  /**
   * Bytes of padding owed once the data is complete.
   *
   * Computed when the member is added rather than when it is closed, because the
   * declared size is what decides it and the declaration is what the header
   * already carries. Written by the next garc_writer_add() or by
   * garc_writer_finish(), so that a caller never pads.
   */
  uint64_t data_padding;
  /** Non-zero while a member is open. */
  int have_member;
  /** Non-zero once the end-of-archive marker has been written. */
  int finished;

  /**
   * The extended records for the member being added.
   *
   * One buffer reused across members rather than one per member: an archive of
   * long names would otherwise allocate and free once each. Its length is reset
   * at the start of every member, so nothing a previous member needed can leak
   * into the next one's header - the same reason the reader resets its `x` set.
   */
  GARC_Buffer records;

  /** What only the zip writer looks at. Meaningless for any other format. */
  GARC_Zip_Write_State zip;
};

/**
 * Write one member's metadata: its extended records, if it needs any, then its
 * header block.
 *
 * Leaves the sink positioned at the member's data and fills in
 * @ref GARC_Writer.data_remaining and @ref GARC_Writer.data_padding.
 *
 * @param writer The writer.
 * @param member What to write.
 * @return GARC_OK, or the failure garc_writer_add() reports.
 */
GARC_Result garc_tar_write_member(
    GARC_Writer * writer, const GARC_Member * member);

/**
 * Finish the current tar member: write whatever padding its size owes.
 *
 * A hook beside the zip one rather than inline in writer.c, so that neither
 * format's rule for closing a member lives in the file that has no format in it.
 *
 * @param writer The writer.
 * @return GARC_OK, or GARC_ERR_IO.
 */
GARC_Result garc_tar_write_close_member(GARC_Writer * writer);

/**
 * Copy a zip writer's password and resolve its AES strength.
 *
 * @param writer The writer.
 * @param password Password bytes. NULL only when @p length is 0, which is an
 *   empty password and still encrypts.
 * @param length Its length.
 * @param bits 128, 192 or 256. Already resolved from a 0 meaning 256.
 * @return ::GARC_OK, ::GARC_ERR_INVALID, or ::GARC_ERR_OOM.
 */
GARC_Result garc_zip_write_adopt_password(GARC_Writer * writer,
    const void * password, size_t length, uint32_t bits);

/**
 * Write one zip member's local header, and remember what its directory entry and
 * its descriptor will need.
 *
 * @param writer The writer.
 * @param member What to write.
 * @return GARC_OK, or the failure garc_writer_add() reports.
 */
GARC_Result garc_zip_write_member(
    GARC_Writer * writer, const GARC_Member * member);

/**
 * Write some of the current zip member's data, and account for it.
 *
 * Separate from the tar path because the bytes are counted twice here - once as
 * the caller's uncompressed total and once as what the archive holds - and
 * because every one of them goes through the CRC.
 *
 * @param writer The writer.
 * @param data The bytes.
 * @param size How many.
 * @return GARC_OK, or GARC_ERR_IO.
 */
GARC_Result garc_zip_write_data(
    GARC_Writer * writer, const void * data, size_t size);

/**
 * Finish the current zip member: its descriptor or its patched header, then its
 * central directory entry.
 *
 * @param writer The writer.
 * @return GARC_OK, GARC_ERR_OOM, or GARC_ERR_IO.
 */
GARC_Result garc_zip_write_close_member(GARC_Writer * writer);

/**
 * Write the central directory, the zip64 records if the archive needs them, and
 * the end record.
 *
 * @param writer The writer.
 * @return GARC_OK, or GARC_ERR_IO.
 */
GARC_Result garc_zip_write_end(GARC_Writer * writer);

/**
 * Free what the zip writer allocated. Called by garc_writer_destroy().
 *
 * @param writer The writer.
 */
void garc_zip_write_release(GARC_Writer * writer);

/**
 * Write the end-of-archive marker and whatever padding the options ask for.
 *
 * @param writer The writer.
 * @return GARC_OK, or GARC_ERR_IO.
 */
GARC_Result garc_tar_write_end(GARC_Writer * writer);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GARC_SRC_WRITER_WRITER_INTERNAL_H
