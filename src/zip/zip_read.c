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
 * Reading a zip: the end record, the central directory, and one look at each
 * local header.
 *
 * **Every value reported about a member comes from the central directory.** The
 * local header is read for exactly one thing - where the member's data starts -
 * because its name and extra field are sized independently of the central
 * directory's and only it can say how long they are. libarchive writes zeroes for
 * the sizes in every local header it produces, so a reader that believed them
 * would report a size of zero for archives every tool reads correctly; and where
 * the two disagree deliberately, following the central directory is what every
 * real tool does.
 *
 * The zip accessors live here rather than in `reader.c`, which is where tar's
 * are. tar's predate there being a second format; a per-format accessor in the
 * format-agnostic file is one more place a third format would have to touch.
 */

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/codec.h>
#include <ghoti.io/archive/zip.h>
#include <ghoti.io/compress/crc32.h>
#include <ghoti.io/compress/options.h>
#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/security/secret.h>
#include <stdint.h>
#include <string.h>

#include "codec/codec_internal.h"
#include "core/buffer_internal.h"
#include "reader/reader_internal.h"
#include "stream/stream_internal.h"
#include "tar/tar_internal.h"
#include "zip/zip_internal.h"

/** Local file header. */
static const uint8_t ZIP_SIG_LOCAL[4] = {'P', 'K', 3, 4};
/** Central directory entry. */
static const uint8_t ZIP_SIG_CENTRAL[4] = {'P', 'K', 1, 2};
/** End of central directory. */
static const uint8_t ZIP_SIG_EOCD[4] = {'P', 'K', 5, 6};
/** Zip64 end of central directory record. */
static const uint8_t ZIP_SIG_ZIP64_EOCD[4] = {'P', 'K', 6, 6};
/** Zip64 end of central directory locator. */
static const uint8_t ZIP_SIG_ZIP64_LOCATOR[4] = {'P', 'K', 6, 7};

/** The value a 32-bit field holds when the real one is in a zip64 extra. */
#define ZIP_MARKER32 0xFFFFFFFFu
/** The same for a 16-bit field. */
#define ZIP_MARKER16 0xFFFFu

/** General purpose flag bit 0: the member is encrypted. */
#define ZIP_FLAG_ENCRYPTED 0x0001u
/** Bit 3: the sizes are zero here and correct in a data descriptor. */
#define ZIP_FLAG_DATA_DESCRIPTOR 0x0008u
/** Method 6 (implode): set means an 8 KiB dictionary, clear 4 KiB. */
#define ZIP_FLAG_IMPLODE_8K 0x0002u
/** Method 6 (implode): set means a literal tree, clear means literals are plain. */
#define ZIP_FLAG_IMPLODE_LITERALS 0x0004u
/** Bit 11: the name and comment are UTF-8. */
#define ZIP_FLAG_UTF8 0x0800u
/** General purpose bit 1 for method 14: the stream ends in an end marker. */
#define ZIP_FLAG_LZMA_EOS 0x0002u

/** Host system 3 in `version made by`: the mode bits mean something. */
#define ZIP_HOST_UNIX 3u

/** The DOS attribute bit that says "directory", in the low byte of the attrs. */
#define ZIP_DOS_ATTR_DIRECTORY 0x10u

/**
 * Read exactly @p size bytes from an absolute offset.
 *
 * Every read in this file is a seek and a read, because a zip is not read in
 * order: the end record is at the end, the central directory is before it, and
 * each member's local header is somewhere in front of that. This is why the
 * format needs a seekable stream at all.
 *
 * @param archive The archive.
 * @param offset Absolute stream offset.
 * @param buffer Destination.
 * @param size How many bytes, exactly.
 * @return ::GARC_OK, ::GARC_ERR_CORRUPT when the bytes are not there, or the
 *   stream's failure.
 */
static GARC_Result zip_read_at(GARC_Archive * archive, uint64_t offset,
    void * buffer, size_t size) {
  GARC_Result result = garc_stream_seek(archive->stream, offset);
  if (result != GARC_OK) {
    return result;
  }
  result = garc_stream_read_exact(archive->stream, buffer, size);
  if (result == GARC_ERR_CORRUPT) {
    // read_exact says CORRUPT for a short read, which is the right answer here
    // too: the archive said these bytes were there.
    return GARC_ERR_CORRUPT;
  }
  return result;
}

int garc_zip_identify(const uint8_t * bytes, size_t length) {
  if (!bytes || length < 4u) {
    return 0;
  }
  // A local header first, which is every ordinary zip; an end record, which is
  // an archive with no members; or a zip64 end record, which is what a writer
  // that put no local headers in front of it would leave. A spanned-archive
  // marker (`PK\x07\x08` as the first record) is deliberately not here: this
  // library refuses multi-disk archives, and identifying one only to refuse it
  // later would be worse than not claiming it.
  return memcmp(bytes, ZIP_SIG_LOCAL, 4) == 0
      || memcmp(bytes, ZIP_SIG_EOCD, 4) == 0
      || memcmp(bytes, ZIP_SIG_ZIP64_EOCD, 4) == 0;
}

GARC_Result garc_zip_locate_eocd(
    GARC_Archive * archive, uint64_t * out_offset) {
  uint64_t size = 0;
  GARC_Result result = garc_stream_size(archive->stream, &size);
  if (result != GARC_OK) {
    return result;
  }
  const uint64_t start = archive->start_offset;
  if (size < start + GARC_ZIP_EOCD_SIZE) {
    // Not enough room for the smallest possible zip, which is 22 bytes of end
    // record and nothing else.
    return GARC_ERR_FORMAT;
  }

  // The window: at most a record plus the largest comment its length field can
  // describe, and never before the archive began.
  uint64_t window_start = start;
  if (size - start > GARC_ZIP_EOCD_SEARCH_MAX) {
    window_start = size - GARC_ZIP_EOCD_SEARCH_MAX;
  }
  const size_t window_length = (size_t)(size - window_start);

  uint8_t * window
      = (uint8_t *)gcu_allocator_malloc(archive->allocator, window_length);
  if (!window) {
    return GARC_ERR_OOM;
  }
  result = zip_read_at(archive, window_start, window, window_length);
  if (result != GARC_OK) {
    gcu_allocator_free(archive->allocator, window);
    return result;
  }

  // **Backwards, and every candidate is validated rather than taken.** The
  // signature can appear inside the archive comment - `python-comments.zip` and
  // `python-eocd-decoy.zip` both put one there - so what makes a candidate the
  // record is that its comment length accounts for exactly the bytes after it.
  // Python's zipfile takes the last signature in the tail and gives up when the
  // arithmetic fails, which is why it cannot read either of those two.
  int found = 0;
  size_t at = window_length - GARC_ZIP_EOCD_SIZE;
  for (;;) {
    if (memcmp(window + at, ZIP_SIG_EOCD, 4) == 0) {
      const uint16_t comment_length = garc_zip_le16(window + at + 20u);
      if ((uint64_t)at + GARC_ZIP_EOCD_SIZE + comment_length
          == (uint64_t)window_length) {
        *out_offset = window_start + at;
        found = 1;
        break;
      }
    }
    if (at == 0u) {
      break;
    }
    --at;
  }

  gcu_allocator_free(archive->allocator, window);
  return found ? GARC_OK : GARC_ERR_FORMAT;
}

/**
 * Read the zip64 end record behind the locator, and take the real counts.
 *
 * The locator says where the record is, in the archive's own offsets - which are
 * the offsets whose base is not known yet, because that base is what the record
 * is being read to settle. So two candidates are tried: the offset as written,
 * for an archive with nothing in front of it, and the 56 bytes immediately before
 * the locator, which is where the record sits in every archive that has one. A
 * signature at either is the record.
 *
 * @param archive The archive.
 * @param locator_offset Absolute offset of the 20-byte locator.
 * @param out_offset Receives the absolute offset of the zip64 end record.
 * @param out_entries Receives the entry count.
 * @param out_size Receives the central directory's size.
 * @param out_central Receives the central directory's declared offset.
 * @return ::GARC_OK, ::GARC_ERR_CORRUPT, ::GARC_ERR_UNSUPPORTED for a
 *   multi-disk archive, or a stream failure.
 */
static GARC_Result zip_read_zip64(GARC_Archive * archive,
    uint64_t locator_offset, uint64_t * out_offset, uint64_t * out_entries,
    uint64_t * out_size, uint64_t * out_central) {
  uint8_t locator[GARC_ZIP_ZIP64_LOCATOR_SIZE];
  GARC_Result result
      = zip_read_at(archive, locator_offset, locator, sizeof(locator));
  if (result != GARC_OK) {
    return result;
  }

  const uint32_t locator_disk = garc_zip_le32(locator + 4u);
  const uint64_t declared = garc_zip_le64(locator + 8u);
  const uint32_t total_disks = garc_zip_le32(locator + 16u);
  if (locator_disk != 0u || total_disks > 1u) {
    return GARC_ERR_UNSUPPORTED;
  }

  uint8_t record[GARC_ZIP_ZIP64_EOCD_SIZE];
  uint64_t candidates[2];
  size_t candidate_count = 0;
  candidates[candidate_count++] = archive->start_offset + declared;
  if (locator_offset >= archive->start_offset + GARC_ZIP_ZIP64_EOCD_SIZE) {
    candidates[candidate_count++]
        = locator_offset - GARC_ZIP_ZIP64_EOCD_SIZE;
  }

  // A failure at one candidate is not the answer, because the whole point of
  // there being two is that the first may be unreadable. But it is not nothing
  // either: if no candidate works, the reason the *first* one failed is a better
  // answer than "corrupt", and a seek that failed on a broken disk must not be
  // reported as a bad archive. Found by the seek sweep in
  // tests/unit/test_zip_structure.cpp, which had this arm answering
  // GARC_ERR_CORRUPT for a stream whose seeks were failing.
  GARC_Result deferred = GARC_OK;
  for (size_t i = 0; i < candidate_count; ++i) {
    result = zip_read_at(archive, candidates[i], record, sizeof(record));
    if (result != GARC_OK) {
      if (deferred == GARC_OK && result != GARC_ERR_CORRUPT) {
        // A short read is "the record is not there", which is what trying the
        // next candidate is for. Anything else is the stream failing.
        deferred = result;
      }
      continue;
    }
    if (memcmp(record, ZIP_SIG_ZIP64_EOCD, 4) != 0) {
      continue;
    }
    const uint32_t disk = garc_zip_le32(record + 16u);
    const uint32_t central_disk = garc_zip_le32(record + 20u);
    const uint64_t entries_here = garc_zip_le64(record + 24u);
    const uint64_t entries_total = garc_zip_le64(record + 32u);
    if (disk != 0u || central_disk != 0u || entries_here != entries_total) {
      return GARC_ERR_UNSUPPORTED;
    }
    *out_offset = candidates[i];
    *out_entries = entries_total;
    *out_size = garc_zip_le64(record + 40u);
    *out_central = garc_zip_le64(record + 48u);
    return GARC_OK;
  }
  // A locator with no record behind it. Not GARC_ERR_FORMAT: the end record was
  // found and is a zip's, so this is a zip whose zip64 half is broken - unless
  // the reason nothing could be read was the stream, in which case that is the
  // answer.
  return deferred != GARC_OK ? deferred : GARC_ERR_CORRUPT;
}

/**
 * Whether a zip64 locator signature before the end record is really the tail of
 * the central directory.
 *
 * The locator is the 20 bytes before the end record, and so is the end of the
 * last central directory entry when there is no zip64 record: a name ending
 * `PK\6\7` and sixteen bytes more puts the signature exactly there. This
 * library's writer once wrote such archives; Python's zipfile reads the same
 * position the same way.
 *
 * Answered only when nothing in the end record asks for zip64, and only when the
 * 32-bit fields alone place a central directory signature where the directory
 * would start with no zip64 record in between. A real zip64 archive puts 76
 * bytes of records between its directory and its end record, so the 32-bit
 * view of it finds no signature there, and a broken zip64 half stays an error
 * rather than being read past - two readers seeing two directories in one file
 * is the thing to avoid.
 *
 * @param archive The archive.
 * @param eocd_offset Where the end record is.
 * @param entries The end record's entry count.
 * @param central_size Its central directory size.
 * @param central_declared Its central directory offset.
 * @return Non-zero when the signature is directory bytes.
 */
static int zip_locator_is_directory_bytes(GARC_Archive * archive,
    uint64_t eocd_offset, uint16_t entries, uint64_t central_size,
    uint64_t central_declared) {
  if (entries == ZIP_MARKER16 || central_size == ZIP_MARKER32
      || central_declared == ZIP_MARKER32 || !entries) {
    return 0;
  }
  if (central_size < GARC_ZIP_ZIP64_LOCATOR_SIZE
      || central_size > eocd_offset - archive->start_offset) {
    return 0;
  }
  uint8_t signature[4];
  if (zip_read_at(archive, eocd_offset - central_size, signature, 4u)
      != GARC_OK) {
    return 0;
  }
  return memcmp(signature, ZIP_SIG_CENTRAL, 4) == 0;
}

GARC_Result garc_zip_open(GARC_Archive * archive, uint64_t eocd_offset) {
  GARC_Zip_State * zip = &archive->zip;

  uint8_t eocd[GARC_ZIP_EOCD_SIZE];
  GARC_Result result = zip_read_at(archive, eocd_offset, eocd, sizeof(eocd));
  if (result != GARC_OK) {
    return result;
  }

  const uint16_t disk = garc_zip_le16(eocd + 4u);
  const uint16_t central_disk = garc_zip_le16(eocd + 6u);
  const uint16_t entries_here = garc_zip_le16(eocd + 8u);
  const uint16_t entries_total = garc_zip_le16(eocd + 10u);
  uint64_t central_size = garc_zip_le32(eocd + 12u);
  uint64_t central_declared = garc_zip_le32(eocd + 16u);
  const uint16_t comment_length = garc_zip_le16(eocd + 20u);
  uint64_t entries = entries_total;

  // **A multi-disk archive is refused by name.** Every field above is per-disk,
  // the members are split across files this stream does not have, and a reader
  // that ignored the disk numbers would report the last disk's members as the
  // whole archive - a wrong answer rather than a failure.
  if (disk != 0u || central_disk != 0u || entries_here != entries_total) {
    return GARC_ERR_UNSUPPORTED;
  }

  zip->eocd_offset = eocd_offset;
  // Where the central directory ends, which is what the base offset is computed
  // from. The zip64 record, when there is one, sits between the directory and
  // the locator, so it moves this.
  uint64_t central_end = eocd_offset;

  // The zip64 locator, if any, is the 20 bytes immediately before the end
  // record. Looked for whenever there is room, not only when a field holds the
  // 0xFFFFFFFF marker: `zip -fz` writes the zip64 records for an archive whose
  // 32-bit fields would all have fitted, and a reader that only looked when a
  // marker was present would read that archive's 32-bit counts - which are
  // right, so it would pass, until the one where they are not.
  if (eocd_offset >= archive->start_offset + GARC_ZIP_ZIP64_LOCATOR_SIZE) {
    const uint64_t locator_offset = eocd_offset - GARC_ZIP_ZIP64_LOCATOR_SIZE;
    uint8_t maybe[4];
    result = zip_read_at(archive, locator_offset, maybe, sizeof(maybe));
    if (result != GARC_OK) {
      return result;
    }
    if (memcmp(maybe, ZIP_SIG_ZIP64_LOCATOR, 4) == 0) {
      uint64_t record_offset = 0;
      result = zip_read_zip64(archive, locator_offset, &record_offset, &entries,
          &central_size, &central_declared);
      if (result == GARC_OK) {
        zip->is_zip64 = 1;
        central_end = record_offset;
      }
      else if ((result != GARC_ERR_CORRUPT && result != GARC_ERR_UNSUPPORTED)
          || !zip_locator_is_directory_bytes(archive, eocd_offset, entries_total,
              central_size, central_declared)) {
        return result;
      }
      // Otherwise the four bytes were the end of the last directory entry -
      // a name or an extra field that happens to end "PK\6\7" and sixteen bytes
      // more - and the 32-bit fields are the archive's, read as they are.
      result = GARC_OK;
    }
  }

  if (!zip->is_zip64
      && (central_size == ZIP_MARKER32 || central_declared == ZIP_MARKER32
          || entries == ZIP_MARKER16)) {
    // A field says "ask zip64" and there is no zip64 record to ask. Reading the
    // marker as a value would report a 4 GiB central directory.
    return GARC_ERR_CORRUPT;
  }

  if (central_size > central_end - archive->start_offset) {
    return GARC_ERR_CORRUPT;
  }
  const uint64_t central_actual = central_end - central_size;
  if (central_actual < archive->start_offset + central_declared) {
    // The directory claims to start further into the archive than it can, which
    // is what a truncated or spliced file looks like from here.
    return GARC_ERR_CORRUPT;
  }

  // **The base offset is discovered, not declared.** The directory says where it
  // is; where it actually turned out to be is `central_actual`; the difference is
  // how many bytes sit in front of the archive without being counted - a
  // self-extracting stub, usually. Every offset in the file is then short by
  // this much, which is why it is applied to the local header offsets rather than
  // merely reported.
  zip->origin = central_actual - central_declared;
  zip->central_offset = central_actual;
  zip->central_size = central_size;
  zip->declared_members = entries;

  if (comment_length) {
    result = garc_buffer_grow(archive->allocator, &zip->comment,
        comment_length);
    if (result != GARC_OK) {
      return result;
    }
    result = zip_read_at(archive, eocd_offset + GARC_ZIP_EOCD_SIZE,
        zip->comment.bytes, comment_length);
    if (result != GARC_OK) {
      return result;
    }
    zip->comment.length = comment_length;
    zip->comment.bytes[comment_length] = '\0';
  }

  garc_zip_rewind(archive);

  // The peek window is emptied rather than drained. It exists so that the bytes
  // identification read can be given back to a stream that cannot seek; this
  // format requires one that can, and every read below seeks first, so there is
  // nothing to give back.
  archive->peek_length = 0;
  archive->peek_consumed = 0;
  return GARC_OK;
}

/**
 * What one member's extra field said, on top of the fixed fields.
 *
 * Read from the **central directory's** copy only. The local header carries extra
 * fields too, and they are not the same bytes - Info-ZIP's extended timestamp is
 * nine bytes there and five here, because the local copy also carries an access
 * time - so a reader that parsed one layout in both places would get a wrong
 * answer out of an archive every tool accepts. One authority, consistently.
 */
typedef struct {
  int64_t mtime_seconds;      ///< The best time any field carried.
  uint32_t mtime_nanoseconds; ///< Its sub-second part, which only NTFS has.
  /** Which field the time came from, and so which of them won. */
  GARC_Time_Source mtime_source;
  int64_t uid;                ///< From a 0x7875 field.
  int64_t gid;                ///< Likewise.
  int ids_valid;              ///< Whether there was such a field.
  /** The method a WinZip AES member would have had, from its 0x9901 field. */
  uint16_t aes_real_method;
  /** 1 is AE-1, 2 is AE-2. Meaningful when @ref have_aes is set. */
  uint16_t aes_version;
  /** 1, 2 or 3. Meaningful when @ref have_aes is set. */
  uint8_t aes_strength;
  int have_aes;               ///< Whether a vendor-AE 0x9901 field was present.
  int have_zip64;             ///< Whether a 0x0001 field was present at all.
} Zip_Extra;

/**
 * Parse the extra fields this library acts on.
 *
 * A field it does not know is skipped by its own length, which is the only way
 * to walk the list: the ids are an open vocabulary and a reader that refused
 * unknown ones would refuse most real archives. A field whose length runs past
 * the end of the block stops the walk - what is left is not a field, and
 * guessing would mean reading the next member's name as a timestamp.
 *
 * @param bytes The extra field block from the central directory entry.
 * @param length Its length.
 * @param sizes The four values a 0x0001 zip64 field can replace, in place.
 * @param out What was found.
 * @return ::GARC_OK, or ::GARC_ERR_CORRUPT for a zip64 field too short for the
 *   values its markers promised.
 */
static GARC_Result zip_parse_extra(const uint8_t * bytes, size_t length,
    uint64_t * size, uint64_t * compressed_size, uint64_t * local_offset,
    int * used_zip64, Zip_Extra * out) {
  size_t at = 0;
  while (at + 4u <= length) {
    const uint16_t id = garc_zip_le16(bytes + at);
    const uint16_t payload = garc_zip_le16(bytes + at + 2u);
    at += 4u;
    if ((uint64_t)at + payload > (uint64_t)length) {
      // A field that claims more than the block holds. The block ends here as
      // far as anything can tell, and the remaining bytes are not fields.
      break;
    }
    const uint8_t * value = bytes + at;

    switch (id) {
      case 0x0001u: {
        out->have_zip64 = 1;
        // Zip64. The values are present **only for the fields that hold the
        // marker**, in this order, which is what makes a 16-byte field in one
        // archive and a 28-byte one in another both correct. A reader that took
        // them positionally reads a compressed size as an uncompressed one on
        // every archive where only one field overflowed.
        size_t offset = 0;
        if (*size == ZIP_MARKER32) {
          if (offset + 8u > payload) {
            return GARC_ERR_CORRUPT;
          }
          *size = garc_zip_le64(value + offset);
          offset += 8u;
          *used_zip64 = 1;
        }
        if (*compressed_size == ZIP_MARKER32) {
          if (offset + 8u > payload) {
            return GARC_ERR_CORRUPT;
          }
          *compressed_size = garc_zip_le64(value + offset);
          offset += 8u;
          *used_zip64 = 1;
        }
        if (*local_offset == ZIP_MARKER32) {
          if (offset + 8u > payload) {
            return GARC_ERR_CORRUPT;
          }
          *local_offset = garc_zip_le64(value + offset);
          offset += 8u;
          *used_zip64 = 1;
        }
        break;
      }
      case 0x000au: {
        // NTFS timestamps: four reserved bytes, then tagged attributes, of which
        // tag 1 is three FILETIMEs. The most precise time a zip can carry, so it
        // wins over the other two - and 7-Zip writes it in the central directory
        // and nothing in the local header.
        size_t offset = 4u;
        while (offset + 4u <= (size_t)payload) {
          const uint16_t tag = garc_zip_le16(value + offset);
          const uint16_t tag_size = garc_zip_le16(value + offset + 2u);
          offset += 4u;
          if ((uint64_t)offset + tag_size > (uint64_t)payload) {
            break;
          }
          if (tag == 0x0001u && tag_size >= 8u) {
            garc_zip_filetime_to_epoch(garc_zip_le64(value + offset),
                &out->mtime_seconds, &out->mtime_nanoseconds);
            out->mtime_source = GARC_TIME_ZIP_NTFS;
          }
          offset += tag_size;
        }
        break;
      }
      case 0x5455u: {
        // The extended timestamp: a flags byte, then the times whose bits are
        // set, in mtime/atime/ctime order. In the central directory only mtime
        // is present whatever the flags say, which is the discrepancy the
        // corpus's `infozip-extras.zip` exists for - so this reads the first
        // time when bit 0 is set and does not look for the others.
        if (payload >= 5u && (value[0] & 0x01u)) {
          if (out->mtime_source != GARC_TIME_ZIP_NTFS) {
            out->mtime_seconds = (int32_t)garc_zip_le32(value + 1u);
            out->mtime_nanoseconds = 0;
            out->mtime_source = GARC_TIME_ZIP_UNIX;
          }
        }
        break;
      }
      case 0x7875u: {
        // Unix uid and gid, new style: a version byte, then each id as a length
        // and that many little-endian bytes. Variable width because it was
        // designed after the 16-bit one ran out, so a fixed read is wrong on the
        // archives that needed it.
        if (payload >= 3u && value[0] == 1u) {
          size_t offset = 1u;
          uint64_t values[2] = {0u, 0u};
          int ok = 1;
          for (size_t which = 0; which < 2u; ++which) {
            if (offset >= (size_t)payload) {
              ok = 0;
              break;
            }
            const uint8_t width = value[offset++];
            if (width > 8u || (uint64_t)offset + width > (uint64_t)payload) {
              ok = 0;
              break;
            }
            uint64_t accumulated = 0;
            for (size_t byte = 0; byte < width; ++byte) {
              accumulated |= (uint64_t)value[offset + byte] << (8u * byte);
            }
            offset += width;
            values[which] = accumulated;
          }
          if (ok) {
            out->uid = (int64_t)values[0];
            out->gid = (int64_t)values[1];
            out->ids_valid = 1;
          }
        }
        break;
      }
      case 0x9901u: {
        // WinZip AES: version, vendor `AE`, strength, and the real method.
        // Method 99 replaced that method in the header. A field whose vendor
        // is not AE is not this scheme.
        if (payload >= 7u && value[2] == (uint8_t)'A' && value[3] == (uint8_t)'E') {
          out->aes_version = garc_zip_le16(value);
          out->aes_strength = value[4];
          out->aes_real_method = garc_zip_le16(value + 5u);
          out->have_aes = 1;
        }
        break;
      }
      default:
        break;
    }
    at += payload;
  }
  return GARC_OK;
}

/**
 * Find where a member's data starts, and check the two records agree.
 *
 * The local header is the only place the data offset can come from: its name and
 * extra field have their own lengths, and the central directory's are usually
 * different. While it is being read, two things are checked - the signature, and
 * the name. A local header whose name is not the central directory's is an
 * archive saying two different things about which member this is, which is the
 * shape of every zip ambiguity attack, and refusing it costs nothing real: no
 * writer in the corpus disagrees with itself.
 *
 * The sizes in the local header are **not** read. They are zero in every member
 * libarchive writes.
 *
 * @param archive The archive.
 * @param local_absolute Absolute offset of the local header.
 * @param out_data Receives the absolute offset of the member's data.
 * @return ::GARC_OK, ::GARC_ERR_CORRUPT, or a stream failure.
 */
static GARC_Result zip_find_data(GARC_Archive * archive,
    uint64_t local_absolute, uint64_t * out_data) {
  const GARC_Zip_State * zip = &archive->zip;
  uint8_t header[GARC_ZIP_LOCAL_HEADER_SIZE];
  GARC_Result result
      = zip_read_at(archive, local_absolute, header, sizeof(header));
  if (result != GARC_OK) {
    return result;
  }
  if (memcmp(header, ZIP_SIG_LOCAL, 4) != 0) {
    return GARC_ERR_CORRUPT;
  }
  const uint16_t name_length = garc_zip_le16(header + 26u);
  const uint16_t extra_length = garc_zip_le16(header + 28u);

  if (name_length != zip->name.length) {
    return GARC_ERR_CORRUPT;
  }
  if (name_length) {
    // Compared in the caller's own buffer rather than a second one: the name is
    // already here, and a stack array would have to be 65,535 bytes.
    uint8_t chunk[256];
    size_t remaining = name_length;
    size_t offset = 0;
    result = garc_stream_seek(archive->stream,
        local_absolute + GARC_ZIP_LOCAL_HEADER_SIZE);
    if (result != GARC_OK) {
      return result;
    }
    while (remaining) {
      const size_t want = remaining < sizeof(chunk) ? remaining : sizeof(chunk);
      result = garc_stream_read_exact(archive->stream, chunk, want);
      if (result != GARC_OK) {
        return result;
      }
      if (memcmp(chunk, zip->name.bytes + offset, want) != 0) {
        return GARC_ERR_CORRUPT;
      }
      offset += want;
      remaining -= want;
    }
  }

  *out_data = local_absolute + GARC_ZIP_LOCAL_HEADER_SIZE + name_length
      + extra_length;
  return GARC_OK;
}

/**
 * Decide what kind of thing a member is.
 *
 * Three sources, in this order, and the order is the answer to a real
 * disagreement:
 *
 * 1. **A name ending in `/` is a directory.** This is the convention every tool
 *    follows and the only one a DOS-made archive has.
 * 2. **The DOS directory attribute**, for a writer that set the bit and left the
 *    slash off.
 * 3. **The Unix mode bits**, but only when `version made by` says Unix - which is
 *    where a symlink is distinguishable at all, since zip has no type field.
 *    On a Windows-made archive that half of the field is zero rather than absent,
 *    so reading it unconditionally would report every member as type 0 with a
 *    mode of 0000.
 *
 * There is no hard link in zip, so ::GARC_MEMBER_HARDLINK is never reported here.
 */
static GARC_Member_Type zip_member_type(const GARC_Zip_State * zip) {
  if (zip->name.length && zip->name.bytes[zip->name.length - 1u] == '/') {
    return GARC_MEMBER_DIRECTORY;
  }
  if (zip->external_attributes & ZIP_DOS_ATTR_DIRECTORY) {
    return GARC_MEMBER_DIRECTORY;
  }
  if ((zip->version_made_by >> 8) != ZIP_HOST_UNIX) {
    return GARC_MEMBER_FILE;
  }
  switch ((zip->external_attributes >> 16) & 0xF000u) {
    case 0xA000u:
      return GARC_MEMBER_SYMLINK;
    case 0x4000u:
      return GARC_MEMBER_DIRECTORY;
    case 0x1000u:
      return GARC_MEMBER_FIFO;
    case 0x2000u:
      return GARC_MEMBER_CHAR_DEVICE;
    case 0x6000u:
      return GARC_MEMBER_BLOCK_DEVICE;
    case 0x8000u:
    case 0x0000u:
      // 0x8000 is a regular file; zero is a writer that put a bare permission
      // mask in the field, which Python's zipfile does by default. Both are
      // files, and neither is "unknown".
      return GARC_MEMBER_FILE;
    default:
      // A type this library does not name. Reported as OTHER rather than as a
      // file, because extracting an unknown type as a regular file is how a
      // reader invents data.
      return GARC_MEMBER_OTHER;
  }
}

/**
 * Read a symlink's target, which in zip is the member's data.
 *
 * zip has no link name field: a symlink is a member whose *contents* are the
 * target. So the target cannot be reported without reading data, and this reads
 * it eagerly for the case where that is cheap and certain - stored, unencrypted,
 * and no longer than a name is allowed to be. Anything else leaves
 * ::GARC_Member.link_target NULL, and the caller reads the member like any other.
 *
 * The alternative was to leave every zip symlink without a target, which would
 * make the phase F safety layer unable to ask the question it exists to ask.
 *
 * @param archive The archive.
 * @param data_offset Where the member's data starts.
 * @return ::GARC_OK, having filled in the link buffer or deliberately not, or a
 *   failure that belongs to the archive rather than to the link.
 */
static GARC_Result zip_read_link_target(
    GARC_Archive * archive, uint64_t data_offset) {
  GARC_Zip_State * zip = &archive->zip;
  const size_t cap = archive->limits.max_name_bytes
      ? archive->limits.max_name_bytes : (size_t)65535u;
  if (zip->method != GARC_ZIP_METHOD_STORED
      || zip->encryption != GARC_ZIP_ENCRYPTION_NONE
      || !archive->member.size || archive->member.size > cap) {
    return GARC_OK;
  }
  const size_t length = (size_t)archive->member.size;
  GARC_Result result = garc_buffer_grow(archive->allocator, &zip->link, length);
  if (result != GARC_OK) {
    return result;
  }
  result = zip_read_at(archive, data_offset, zip->link.bytes, length);
  if (result != GARC_OK) {
    return result;
  }
  zip->link.length = length;
  zip->link.bytes[length] = '\0';
  archive->member.link_target = zip->link.bytes;
  archive->member.link_target_length = length;
  return GARC_OK;
}

/** Method 14's header is two length fields, then five property bytes. */
#define ZIP_LZMA_PROPS_SIZE 5u
/** Method 14 starts with this many bytes: the version, the properties size and the properties. */
#define ZIP_LZMA_HEADER_SIZE (4u + ZIP_LZMA_PROPS_SIZE)

/**
 * Unpack a properties byte into lc, lp and pb.
 *
 * The byte is `(pb * 5 + lp) * 9 + lc`. A value that does not fit those
 * ranges is not a properties byte.
 *
 * @param byte The first properties byte.
 * @param lc Receives the literal context bits.
 * @param lp Receives the literal position bits.
 * @param pb Receives the position bits.
 * @return Non-zero when the byte is a properties byte.
 */
static int zip_lzma_props_decode(
    uint8_t byte, int64_t * lc, int64_t * lp, int64_t * pb) {
  unsigned value = byte;
  if (value >= 9u * 5u * 5u) {
    return 0;
  }
  *lc = (int64_t)(value % 9u);
  value /= 9u;
  *lp = (int64_t)(value % 5u);
  *pb = (int64_t)(value / 5u);
  return 1;
}

/**
 * Read exactly @p size bytes, or report a header that ran out.
 *
 * A short read is ::GARC_ERR_CORRUPT: the caller is reading a header whose
 * length the archive already declared, and ending early means the header is
 * not there.
 *
 * @param stream Where the bytes come from, already positioned.
 * @param buffer Destination.
 * @param size How many.
 * @return ::GARC_OK, ::GARC_ERR_CORRUPT, or what the stream returned.
 */
static GARC_Result zip_read_exact(
    GARC_Stream * stream, void * buffer, size_t size) {
  uint8_t * out = (uint8_t *)buffer;
  size_t got_total = 0;
  while (got_total < size) {
    size_t got = 0;
    const GARC_Result result = garc_stream_read(
        stream, out + got_total, size - got_total, &got);
    if (result != GARC_OK) {
      return result;
    }
    if (!got) {
      return GARC_ERR_CORRUPT;
    }
    got_total += got;
  }
  return GARC_OK;
}

/**
 * The `compress` method name for a zip method number, or NULL.
 *
 * **The one place a zip method number becomes a codec name**, and the reason the
 * codec layer takes a string: a second enum here would be a copy of compress's
 * list of methods, and the copy goes stale.
 *
 * Each row is exact rather than approximate. Method 8 is RFC 1951
 * *raw* - no zlib header and no gzip wrapper - which is `compress`'s `"deflate"`
 * and not its `"zlib"`; reading one as the other fails on the first two bytes.
 * Method 9 is `"deflate64"`, which is *not* RFC 1951 - a 64 KB window, a
 * different length code 285 and two more distance codes - and is its own codec
 * for exactly that reason: pointing it at the deflate decoder would produce
 * plausible wrong bytes for the members that use the extensions.
 * Method 12 is a bare bzip2 stream. Method 95 is a complete `.xz` file. Method 93 is a zstd frame. Method 14 is
 * `"lzma"`, but the bytes are not a `.lzma` file: a header comes first and the
 * rest is raw, which the caller says with the `lzma.*` keys rather than with
 * this name.
 *
 * Methods 1 to 6 are PKWARE's earliest, read only: 1 is `"shrink"`, 2 to 5 are
 * `"reduce"` (the factor is the method number less one), and 6 is `"implode"`.
 * All three are raw streams with no end marker, so the caller also gives the
 * decoder what the container knows - see zip_legacy_keys().
 *
 * @param method The method number from the central directory.
 * @return A method name, or NULL when this library has no codec for it.
 */
static const char * zip_codec_name(uint16_t method) {
  switch (method) {
    case GARC_ZIP_METHOD_SHRUNK:
      return "shrink";
    case GARC_ZIP_METHOD_REDUCED_1:
    case GARC_ZIP_METHOD_REDUCED_2:
    case GARC_ZIP_METHOD_REDUCED_3:
    case GARC_ZIP_METHOD_REDUCED_4:
      return "reduce";
    case GARC_ZIP_METHOD_IMPLODED:
      return "implode";
    case GARC_ZIP_METHOD_DEFLATE:
      return "deflate";
    case GARC_ZIP_METHOD_DEFLATE64:
      return "deflate64";
    case GARC_ZIP_METHOD_BZIP2:
      return "bzip2";
    case GARC_ZIP_METHOD_LZMA:
      return "lzma";
    case GARC_ZIP_METHOD_ZSTD:
      return "zstd";
    case GARC_ZIP_METHOD_XZ:
      return "xz";
    default:
      return NULL;
  }
}

/**
 * What reduce and implode need from the container, or nothing.
 *
 * @param method The real method number.
 * @param flags The member's general purpose flags.
 * @param size The member's declared uncompressed size.
 * @param out Filled in; zeroed for every other method.
 * @return Non-zero when @p out holds keys the decoder needs.
 */
static int zip_legacy_keys(
    uint16_t method, uint16_t flags, uint64_t size, GARC_Member_Legacy * out) {
  memset(out, 0, sizeof(*out));
  out->uncompressed_size = size;
  if (method >= GARC_ZIP_METHOD_REDUCED_1
      && method <= GARC_ZIP_METHOD_REDUCED_4) {
    out->reduce_factor = (int64_t)method - (int64_t)GARC_ZIP_METHOD_SHRUNK;
    return 1;
  }
  if (method == GARC_ZIP_METHOD_IMPLODED) {
    out->implode_dictionary = (flags & ZIP_FLAG_IMPLODE_8K) ? 8192u : 4096u;
    out->implode_literal_tree = (flags & ZIP_FLAG_IMPLODE_LITERALS) != 0;
    return 1;
  }
  return 0;
}

/**
 * Prepare a ZipCrypto member's data, or refuse it.
 *
 * Reads the 12-byte encryption header, decrypts it, and checks its one check
 * byte; on agreement it builds the decrypting view the rest of the setup reads
 * through. Everything it refuses is refused on the *data* - the member's name,
 * size, time and mode are in the clear whatever the password - so a wrong
 * password does not stop the walk and ::garc_next() never returns one of these
 * statuses.
 *
 * **The header is read only when a password has been set.** Without one the
 * answer is already known, and a listing of an encrypted archive is the common
 * case: paying one seek and one 12-byte read per member to reach a conclusion
 * that needed neither would be a cost with nothing on the other side of it.
 *
 * @param archive The archive.
 * @param data_offset Where the member's data starts, encryption header included.
 * @param dos_time The member's DOS time field, which is the check byte's other
 *   possible source.
 * @param out_source Receives the stream the member's bytes come from.
 * @return ::GARC_OK - whether or not the member was refused, which
 *   ::GARC_Archive.data_refusal carries - or an I/O or allocation failure.
 *   **Never a structural refusal**: the caller has already made those, because
 *   they must not depend on whether a password was supplied.
 */
static GARC_Result zip_setup_zipcrypto(GARC_Archive * archive,
    uint64_t data_offset, uint16_t dos_time, GARC_Stream ** out_source) {
  GARC_Zip_State * zip = &archive->zip;

  if (!zip->have_password) {
    archive->data_refusal = GARC_ERR_PASSWORD_REQUIRED;
    return GARC_OK;
  }
  uint8_t header[GARC_ZIP_CRYPT_HEADER_SIZE];
  GARC_Result result = zip_read_at(archive, data_offset, header, sizeof(header));
  if (result != GARC_OK) {
    return result;
  }

  // From the archive's keys rather than in place: every member starts from the
  // same password-derived state, and the header mixes this member's 12 bytes into
  // a copy of it.
  uint32_t keys[3];
  memcpy(keys, zip->crypt_keys, sizeof(keys));
  garc_zip_crypt_decrypt(keys, header, sizeof(header));
  if (!garc_zip_crypt_header_ok(header, zip->crc32, dos_time,
          (zip->flags & ZIP_FLAG_DATA_DESCRIPTOR) != 0)) {
    archive->data_refusal = GARC_ERR_PASSWORD_REJECTED;
    return GARC_OK;
  }

  // The stream is left where zip_read_at() put it, which is one byte past the
  // header - so the decrypting view reads the ciphertext from its first byte
  // without a seek of its own, and the keys it is given are the ones the header
  // produced.
  result = garc_zip_crypt_stream_create(
      archive->allocator, archive->stream, keys, &zip->crypt);
  if (result != GARC_OK) {
    return result;
  }
  *out_source = zip->crypt;
  return GARC_OK;
}

/**
 * Check a WinZip AES member and, when it has ciphertext, install its stream.
 *
 * The caller has already refused a compressed size shorter than the framing,
 * and has already refused an unknown strength or version and an unsupported
 * real method. An empty ciphertext is authenticated here, because a later read
 * of zero bytes never calls the stream.
 *
 * @param archive The archive.
 * @param data_offset Where the salt begins.
 * @param compressed_size The compressed size, framing included.
 * @param out_source Set to the decrypting stream when there is ciphertext.
 * @return ::GARC_OK, with @ref GARC_Archive::data_refusal set when the password
 *   is missing or the verifier disagrees. A read failure is returned as itself.
 */
static GARC_Result zip_setup_aes(GARC_Archive * archive, uint64_t data_offset,
    uint64_t compressed_size, GARC_Stream ** out_source) {
  GARC_Zip_State * zip = &archive->zip;
  if (!zip->have_password) {
    archive->data_refusal = GARC_ERR_PASSWORD_REQUIRED;
    return GARC_OK;
  }

  size_t salt_len = 16u;
  size_t key_len = 32u;
  if (zip->aes_strength == 1u) {
    salt_len = 8u;
    key_len = 16u;
  }
  else if (zip->aes_strength == 2u) {
    salt_len = 12u;
    key_len = 24u;
  }

  uint8_t prefix[18];
  GARC_Result result
      = zip_read_at(archive, data_offset, prefix, salt_len + 2u);
  if (result != GARC_OK) {
    return result;
  }

  uint8_t aes_key[32];
  uint8_t hmac_key[32];
  uint8_t verifier[GARC_ZIP_AES_VERIFIER_LEN];
  result = garc_zip_aes_derive(zip->password_length ? zip->password : NULL,
      zip->password_length, prefix, salt_len, aes_key, key_len, hmac_key,
      verifier);
  if (result != GARC_OK) {
    gsec_wipe(prefix, sizeof(prefix));
    gsec_wipe(aes_key, sizeof(aes_key));
    gsec_wipe(hmac_key, sizeof(hmac_key));
    return result;
  }
  const int matches
      = garc_zip_aes_verifier_matches(verifier, prefix + salt_len);
  gsec_wipe(verifier, sizeof(verifier));
  gsec_wipe(prefix, sizeof(prefix));
  if (!matches) {
    gsec_wipe(aes_key, sizeof(aes_key));
    gsec_wipe(hmac_key, sizeof(hmac_key));
    archive->data_refusal = GARC_ERR_PASSWORD_REJECTED;
    return GARC_OK;
  }

  const uint64_t ciphertext = compressed_size - (uint64_t)salt_len - 2u
      - (uint64_t)GARC_ZIP_AES_AUTH_LEN;
  if (!ciphertext) {
    uint8_t tag[GARC_ZIP_AES_AUTH_LEN];
    result = zip_read_at(
        archive, data_offset + salt_len + 2u, tag, sizeof(tag));
    if (result != GARC_OK) {
      gsec_wipe(aes_key, sizeof(aes_key));
      gsec_wipe(hmac_key, sizeof(hmac_key));
      return result;
    }
    zip->aes_auth_ok = garc_zip_aes_auth_matches(
        hmac_key, key_len, NULL, 0u, tag, sizeof(tag));
    gsec_wipe(tag, sizeof(tag));
    gsec_wipe(aes_key, sizeof(aes_key));
    gsec_wipe(hmac_key, sizeof(hmac_key));
    return GARC_OK;
  }

  result = garc_zip_aes_stream_create(archive->allocator, archive->stream,
      aes_key, hmac_key, key_len, ciphertext, &zip->aes_auth_ok, &zip->crypt);
  gsec_wipe(aes_key, sizeof(aes_key));
  gsec_wipe(hmac_key, sizeof(hmac_key));
  if (result != GARC_OK) {
    return result;
  }
  *out_source = zip->crypt;
  return GARC_OK;
}

GARC_Result garc_zip_read(
    GARC_Archive * archive, void * buffer, size_t capacity, size_t * out_read) {
  GARC_Zip_State * zip = &archive->zip;
  if (zip->streaming) {
    return garc_zip_stream_read(archive, buffer, capacity, out_read);
  }

  if (!archive->data_remaining) {
    *out_read = 0;
    // Uncompressed size 0 returns here before any read of the decrypting
    // stream. The HMAC is checked in setup only when the ciphertext is empty
    // too. A compressed member can declare no output and still have
    // ciphertext, and that tag has to be checked before a successful read.
    if (zip->aes_version && zip->crypt && !zip->aes_auth_ok) {
      uint8_t discard[4096];
      for (;;) {
        size_t drained = 0;
        const GARC_Result pulled = garc_stream_read(
            zip->crypt, discard, sizeof(discard), &drained);
        gsec_wipe(discard, sizeof(discard));
        if (pulled != GARC_OK) {
          return pulled;
        }
        if (!drained) {
          break;
        }
      }
    }
    if (zip->crc_active) {
      // **The verdict, on the call that says the member is over.** Cleared first,
      // so a caller that keeps calling gets the answer once rather than on every
      // call, and so that a second read after a refusal does not re-refuse.
      zip->crc_active = 0;
      if (zip->aes_version) {
        // The HMAC is the authentication. A 16-bit verifier can pass for the
        // wrong password, once in 65536, so a tag that does not match is not
        // named as either cause. AE-2 stores a CRC of 0 and does not check it;
        // a stored 0 is not a mismatch. AE-1 still falls through to the CRC.
        if (!zip->aes_auth_ok) {
          return GARC_ERR_PASSWORD_OR_CORRUPT;
        }
        if (zip->aes_version >= 2u) {
          return GARC_OK;
        }
      }
      if (gcomp_crc32_finalize(zip->running_crc) != zip->crc32) {
        // ZipCrypto has no authentication tag, so a key that got past the
        // check byte and a damaged ciphertext are the same observation.
        // AE-1's HMAC already matched; a CRC that disagrees after that is
        // damage to the plaintext, which is ::GARC_ERR_CORRUPT.
        if (zip->aes_version) {
          return GARC_ERR_CORRUPT;
        }
        return zip->crypt ? GARC_ERR_PASSWORD_OR_CORRUPT : GARC_ERR_CORRUPT;
      }
    }
    return GARC_OK;
  }
  if (!capacity) {
    *out_read = 0;
    return GARC_OK;
  }

  // Never more than the member declared. For a stored member the bytes come
  // straight from the archive's stream, where the next member's header is just
  // behind this one's data; for a compressed member they come out of the decoder,
  // which has the same cap in its own options.
  size_t want = capacity;
  if ((uint64_t)want > archive->data_remaining) {
    want = (size_t)archive->data_remaining;
  }

  // Outermost first. A member can be decrypted, decompressed, both or neither,
  // and the bytes a caller gets always come from the outermost of the three.
  GARC_Stream * source = archive->stream;
  if (zip->crypt) {
    source = zip->crypt;
  }
  if (zip->codec) {
    source = garc_member_codec_stream(zip->codec);
  }
  size_t got = 0;
  GARC_Result result = garc_stream_read(source, buffer, want, &got);
  if (result != GARC_OK) {
    return result;
  }
  if (!got) {
    // The container said these bytes were here. For a compressed member this is
    // also what a deflate stream that ended early looks like from out here, and
    // both are the same answer: the archive lied about its size.
    return GARC_ERR_CORRUPT;
  }

  zip->running_crc
      = gcomp_crc32_update(zip->running_crc, (const uint8_t *)buffer, got);
  archive->data_remaining -= (uint64_t)got;
  *out_read = got;
  return GARC_OK;
}

GARC_Result garc_zip_skip(GARC_Archive * archive) {
  if (archive->zip.streaming) {
    return garc_zip_stream_skip(archive);
  }
  garc_member_codec_destroy(archive->zip.codec);
  archive->zip.codec = NULL;
  garc_stream_destroy(archive->zip.crypt);
  archive->zip.crypt = NULL;
  archive->zip.crc_active = 0;
  archive->data_remaining = 0;
  return GARC_OK;
}

GARC_Result garc_zip_next(GARC_Archive * archive) {
  if (archive->zip.streaming) {
    return garc_zip_stream_next(archive);
  }
  GARC_Zip_State * zip = &archive->zip;

  if (zip->entries_seen >= zip->declared_members) {
    archive->at_end = 1;
    return GARC_END;
  }

  // Per-member state, cleared at the top of every call for the reason the tar
  // reader gives for doing the same: a call that fails part way must not leave
  // anything of this member to be applied to the next one.
  // The previous member's decoder, before anything else: it holds a slice of the
  // stream this call is about to seek, so keeping it alive across the seek would
  // leave an object whose view of the position is wrong.
  garc_member_codec_destroy(zip->codec);
  zip->codec = NULL;
  // After the codec, which holds a slice of this: the decoder is the outer object
  // and destroying the inner one first would leave its teardown reading freed
  // memory. The same order as codec.c's own, for the same reason.
  garc_stream_destroy(zip->crypt);
  zip->crypt = NULL;
  zip->crc_active = 0;
  zip->running_crc = GCOMP_CRC32_INIT;

  zip->name.length = 0;
  zip->link.length = 0;
  zip->extra.length = 0;
  zip->method = 0;
  zip->flags = 0;
  zip->version_made_by = 0;
  zip->external_attributes = 0;
  zip->crc32 = 0;
  zip->compressed_size = 0;
  zip->local_offset = 0;
  zip->extra_length = 0;
  zip->used_zip64 = 0;
  zip->encryption = GARC_ZIP_ENCRYPTION_NONE;
  zip->aes_version = 0;
  zip->aes_strength = 0;
  zip->aes_method = 0;
  zip->aes_auth_ok = 0;

  uint8_t entry[GARC_ZIP_CENTRAL_ENTRY_SIZE];
  GARC_Result result = zip_read_at(archive, zip->cursor, entry, sizeof(entry));
  if (result != GARC_OK) {
    return result;
  }
  if (memcmp(entry, ZIP_SIG_CENTRAL, 4) != 0) {
    // The end record said there were this many entries. One of them is not
    // there, which is a corrupt archive rather than a shorter one.
    return GARC_ERR_CORRUPT;
  }

  zip->version_made_by = garc_zip_le16(entry + 4u);
  zip->version_needed = garc_zip_le16(entry + 6u);
  zip->flags = garc_zip_le16(entry + 8u);
  zip->method = garc_zip_le16(entry + 10u);
  const uint16_t dos_time = garc_zip_le16(entry + 12u);
  const uint16_t dos_date = garc_zip_le16(entry + 14u);
  zip->crc32 = garc_zip_le32(entry + 16u);
  uint64_t compressed_size = garc_zip_le32(entry + 20u);
  uint64_t size = garc_zip_le32(entry + 24u);
  const uint16_t name_length = garc_zip_le16(entry + 28u);
  const uint16_t extra_length = garc_zip_le16(entry + 30u);
  const uint16_t comment_length = garc_zip_le16(entry + 32u);
  const uint16_t disk_start = garc_zip_le16(entry + 34u);
  zip->internal_attributes = garc_zip_le16(entry + 36u);
  zip->external_attributes = garc_zip_le32(entry + 38u);
  uint64_t local_offset = garc_zip_le32(entry + 42u);
  zip->dos_time = dos_time;
  zip->dos_date = dos_date;
  zip->comment_length = comment_length;
  zip->comment_offset = zip->cursor + GARC_ZIP_CENTRAL_ENTRY_SIZE + name_length
      + extra_length;

  if (disk_start != 0u && disk_start != ZIP_MARKER16) {
    // A member on another disk, in an archive whose end record said one disk.
    return GARC_ERR_UNSUPPORTED;
  }

  // The caps that apply before anything is allocated for this member. The name
  // one is checked again by garc_reader_account() against the member's reported
  // length, and this check is the one that stops a 64 KB allocation for a name
  // the caller has already said it will not accept.
  if (archive->limits.max_name_bytes
      && name_length > archive->limits.max_name_bytes) {
    return GARC_ERR_LIMIT_NAME_BYTES;
  }
  if (archive->limits.max_extra_bytes
      && extra_length > archive->limits.max_extra_bytes) {
    return GARC_ERR_LIMIT_EXTRA_BYTES;
  }
  zip->extra_length = extra_length;

  const uint64_t entry_end = (uint64_t)zip->cursor + GARC_ZIP_CENTRAL_ENTRY_SIZE
      + name_length + extra_length + comment_length;
  if (entry_end > zip->central_offset + zip->central_size) {
    // This entry runs past the end of the directory the end record described.
    return GARC_ERR_CORRUPT;
  }

  if (name_length) {
    result = garc_buffer_grow(archive->allocator, &zip->name, name_length);
    if (result != GARC_OK) {
      return result;
    }
    result = zip_read_at(archive, zip->cursor + GARC_ZIP_CENTRAL_ENTRY_SIZE,
        zip->name.bytes, name_length);
    if (result != GARC_OK) {
      return result;
    }
    zip->name.bytes[name_length] = '\0';
  }
  zip->name.length = name_length;

  Zip_Extra extra;
  memset(&extra, 0, sizeof(extra));
  if (extra_length) {
    result = garc_buffer_grow(archive->allocator, &zip->extra, extra_length);
    if (result != GARC_OK) {
      return result;
    }
    result = zip_read_at(archive,
        zip->cursor + GARC_ZIP_CENTRAL_ENTRY_SIZE + name_length,
        zip->extra.bytes, extra_length);
    if (result != GARC_OK) {
      return result;
    }
    zip->extra.length = extra_length;
    result = zip_parse_extra((const uint8_t *)zip->extra.bytes, extra_length,
        &size, &compressed_size, &local_offset, &zip->used_zip64, &extra);
    if (result != GARC_OK) {
      return result;
    }
  }

  if (size == ZIP_MARKER32 || compressed_size == ZIP_MARKER32
      || local_offset == ZIP_MARKER32) {
    // A field asked for a zip64 value that no 0x0001 field supplied. Taking the
    // marker as the value would report a member of exactly 4 GiB minus one.
    return GARC_ERR_CORRUPT;
  }

  zip->compressed_size = compressed_size;
  zip->local_offset = local_offset;

  if (zip->flags & ZIP_FLAG_ENCRYPTED) {
    zip->encryption = (zip->method == GARC_ZIP_METHOD_AES && extra.have_aes)
        ? GARC_ZIP_ENCRYPTION_AES
        : GARC_ZIP_ENCRYPTION_ZIPCRYPTO;
  }
  if (zip->encryption == GARC_ZIP_ENCRYPTION_AES) {
    // method stays 99. garc_zip_member_method() reports that, and the codec
    // is chosen from the real method below.
    zip->aes_version = extra.aes_version;
    zip->aes_strength = extra.aes_strength;
    zip->aes_method = extra.aes_real_method;
  }

  // Where the member's data is. The offsets in the file count from the archive's
  // origin, which is where a stub in front of it ends.
  const uint64_t local_absolute = zip->origin + local_offset;
  if (local_absolute < archive->start_offset
      || local_absolute >= zip->central_offset) {
    // A local header outside the archive, or inside the central directory. Both
    // are how a hand-edited offset points a reader somewhere it should not go.
    return GARC_ERR_CORRUPT;
  }

  GARC_Member * member = &archive->member;
  memset(member, 0, sizeof(*member));
  // Never NULL: an empty name is "", as every other reader gives it.
  member->name = zip->name.length ? zip->name.bytes : "";
  member->name_length = zip->name.length;
  // **Bit 11 is the only thing that ever says anything about a name's
  // encoding**, and its absence is GARC_NAME_UNDECLARED rather than "probably
  // CP437": the historical default is a claim about what a writer meant, and
  // this library reports what the container said.
  member->name_encoding = (zip->flags & ZIP_FLAG_UTF8) ? GARC_NAME_UTF8
      : GARC_NAME_UNDECLARED;
  member->size = size;
  member->type = zip_member_type(zip);

  if (extra.mtime_source != GARC_TIME_NONE) {
    member->mtime_seconds = extra.mtime_seconds;
    member->mtime_nanoseconds = extra.mtime_nanoseconds;
    member->mtime_source = extra.mtime_source;
  }
  else {
    int64_t seconds = 0;
    if (garc_zip_dos_to_epoch(dos_date, dos_time, &seconds) == GARC_OK) {
      member->mtime_seconds = seconds;
      member->mtime_source = GARC_TIME_ZIP_DOS;
    }
    // Otherwise GARC_TIME_NONE, which says the archive carried no usable time -
    // see garc_zip_dos_to_epoch() for why an out-of-range field is not one.
  }

  if ((zip->version_made_by >> 8) == ZIP_HOST_UNIX) {
    const uint32_t mode = (zip->external_attributes >> 16) & 0xFFFFu;
    if (mode) {
      member->mode = mode;
      member->mode_valid = 1;
    }
  }
  if (extra.ids_valid) {
    member->uid = extra.uid;
    member->gid = extra.gid;
    member->ids_valid = 1;
  }

  member->header_offset = local_absolute;

  uint64_t data_offset = 0;
  result = zip_find_data(archive, local_absolute, &data_offset);
  if (result != GARC_OK) {
    return result;
  }
  // **A member's data has to fit between its header and the central directory.**
  // Without this, a stored member that declares more bytes than sit between the
  // two would be handed the directory's own bytes as its contents. The CRC check
  // would catch it afterwards - and "afterwards" means a caller who ignored the
  // status has already been given them.
  if (compressed_size > zip->central_offset
      || data_offset > zip->central_offset - compressed_size) {
    return GARC_ERR_CORRUPT;
  }
  member->data_offset = data_offset;

  if (member->type == GARC_MEMBER_SYMLINK) {
    result = zip_read_link_target(archive, data_offset);
    if (result != GARC_OK) {
      return result;
    }
  }

  result = garc_reader_account(archive);
  if (result != GARC_OK) {
    return result;
  }

  // **The data cursor counts uncompressed bytes owed to the caller**, which for a
  // stored member is also the number of bytes left in the stream. A compressed
  // member's stream position is the decoder's business, and the caller's count is
  // the declared size either way.
  archive->data_remaining = size;
  archive->data_padding = 0;
  archive->data_refusal = GARC_OK;

  // Method 99 stays in zip->method so garc_zip_member_method() keeps reporting
  // it. The codec is the real method from 0x9901.
  const uint16_t body = zip->encryption == GARC_ZIP_ENCRYPTION_AES
      ? zip->aes_method : zip->method;
  const char * codec_name = zip_codec_name(body);

  uint64_t payload = compressed_size;
  GARC_Stream * source = archive->stream;

  // **Every structural check happens before the password, and none of them
  // depends on it.** An encrypted member is at least its own framing long, and
  // a stored member's two sizes are one number; both are facts about the
  // archive rather than about the caller's secret, so both are checked whether
  // or not one was supplied.
  //
  // This is a defect the fuzz harness found, by walking one archive twice - once
  // with a password and once without - and comparing the members. The length check
  // used to live inside the ZipCrypto setup, which runs only when a password is
  // set, so the same archive was a corrupt one to a caller who had the password
  // and a walkable one to a caller who did not. A refusal that arrives only for
  // some callers is worse than either answer.
  int aes_known = 0;
  if (zip->encryption == GARC_ZIP_ENCRYPTION_ZIPCRYPTO) {
    if (compressed_size < GARC_ZIP_CRYPT_HEADER_SIZE) {
      return GARC_ERR_CORRUPT;
    }
    payload = compressed_size - GARC_ZIP_CRYPT_HEADER_SIZE;
  }
  else if (zip->encryption == GARC_ZIP_ENCRYPTION_AES) {
    const size_t framing = garc_zip_aes_framing(zip->aes_strength);
    aes_known = framing != 0u
        && (zip->aes_version == 1u || zip->aes_version == 2u);
    if (aes_known && compressed_size < (uint64_t)framing) {
      return GARC_ERR_CORRUPT;
    }
    if (aes_known) {
      payload = compressed_size - (uint64_t)framing;
    }
  }
  if ((zip->encryption != GARC_ZIP_ENCRYPTION_AES || aes_known)
      && body == GARC_ZIP_METHOD_STORED && payload != size) {
    // Stored means the two sizes are one number - the *payload*, which for an
    // encrypted member is the compressed size less its framing. A member that
    // says otherwise describes something the method cannot do, and both numbers
    // are things a reader seeks by. An AES member whose strength or version is
    // not one this library reads is refused as unsupported below, and that
    // refusal is not turned into a size check against the unadjusted payload.
    return GARC_ERR_CORRUPT;
  }
  if ((zip->encryption != GARC_ZIP_ENCRYPTION_AES || aes_known)
      && body == GARC_ZIP_METHOD_LZMA
      && payload < (uint64_t)ZIP_LZMA_HEADER_SIZE) {
    // Method 14's nine-byte header is a fact about the archive's sizes, the
    // same way an encrypted member's framing is. Checked here so a short
    // payload stops the walk for every caller rather than only one who set a
    // password and reached the decrypting parse below.
    return GARC_ERR_CORRUPT;
  }

  // **The real method is answered before the password, and the order is the
  // point.** A member this library has no codec for is refused whatever the
  // password, so asking for one first would send a caller to a prompt and then
  // refuse them anyway.
  if (zip->encryption == GARC_ZIP_ENCRYPTION_AES && !aes_known) {
    archive->data_refusal = GARC_ERR_UNSUPPORTED;
  }
  else if (body != GARC_ZIP_METHOD_STORED && !codec_name) {
    archive->data_refusal = GARC_ERR_UNSUPPORTED;
  }
  else if (zip->encryption == GARC_ZIP_ENCRYPTION_ZIPCRYPTO) {
    result = zip_setup_zipcrypto(archive, data_offset, dos_time, &source);
    if (result != GARC_OK) {
      return result;
    }
  }
  else if (zip->encryption == GARC_ZIP_ENCRYPTION_AES) {
    result = zip_setup_aes(archive, data_offset, compressed_size, &source);
    if (result != GARC_OK) {
      return result;
    }
  }

  if (archive->data_refusal != GARC_OK) {
    // Already refused: a method with no codec, or an encrypted member with no
    // password or a password the verifier rejected. Nothing below applies, and
    // in particular no decoder is created - a member whose bytes a caller cannot
    // have does not need one, and creating it would decompress ciphertext.
  }
  else if (body == GARC_ZIP_METHOD_STORED) {
    if (source == archive->stream) {
      // Only when the bytes come straight from the archive. An encrypted member's
      // stream has already been positioned past the encryption header, and
      // seeking the archive underneath a decrypting view would move it back.
      result = garc_stream_seek(archive->stream, data_offset);
      if (result != GARC_OK) {
        return result;
      }
    }
    zip->crc_active = 1;
  }
  else {
    // A codec, necessarily: the arm above this chain refused every method that is
    // neither stored nor named by zip_codec_name(), so reaching here means
    // codec_name is set. Written as a plain `else` rather than as a condition that
    // is always true, which would leave a branch no input can take.
    if (source == archive->stream) {
      // Seek first: the decoder reads from wherever the stream is, and it reads
      // lazily, so this is the only moment the position is known to be right.
      result = garc_stream_seek(archive->stream, data_offset);
      if (result != GARC_OK) {
        return result;
      }
    }
    GARC_Member_Lzma lzma_keys;
    const GARC_Member_Lzma * lzma = NULL;
    uint64_t codec_length = payload;
    if (body == GARC_ZIP_METHOD_LZMA) {
      // Version, properties size, five property bytes, then raw LZMA. Any
      // version word is accepted: 7-Zip writes 0x0119 and Python writes
      // 0x0409. A properties size other than 5 is corrupt on a clear member.
      //
      // **When the member is encrypted, a header that does not parse is a data
      // refusal rather than a walk failure.** The bytes come from the
      // decrypting stream, so a wrong password that slipped the check byte, a
      // damaged header, and a stream that ends inside a header the sizes said
      // was there are the same observation - the same reason a CRC
      // disagreement after ZipCrypto is ::GARC_ERR_PASSWORD_OR_CORRUPT.
      // Returning ::GARC_ERR_CORRUPT from next() here used to stop the walk
      // for a caller with a password and not for one without, which is how
      // the fuzz harness found it. The short-payload check above already
      // refused a header that cannot fit as structure. An I/O error is still
      // a failure of the walk: the stream did not end, it failed.
      uint8_t prefix[4];
      result = zip_read_exact(source, prefix, sizeof(prefix));
      if (result != GARC_OK) {
        if (zip->encryption != GARC_ZIP_ENCRYPTION_NONE
            && result == GARC_ERR_CORRUPT) {
          archive->data_refusal = GARC_ERR_PASSWORD_OR_CORRUPT;
        }
        else {
          return result;
        }
      }
      else {
        const uint16_t props_size = garc_zip_le16(prefix + 2u);
        if (props_size != ZIP_LZMA_PROPS_SIZE) {
          if (zip->encryption != GARC_ZIP_ENCRYPTION_NONE) {
            archive->data_refusal = GARC_ERR_PASSWORD_OR_CORRUPT;
          }
          else {
            return GARC_ERR_CORRUPT;
          }
        }
        else {
          uint8_t props[ZIP_LZMA_PROPS_SIZE];
          result = zip_read_exact(source, props, sizeof(props));
          if (result != GARC_OK) {
            if (zip->encryption != GARC_ZIP_ENCRYPTION_NONE
                && result == GARC_ERR_CORRUPT) {
              archive->data_refusal = GARC_ERR_PASSWORD_OR_CORRUPT;
            }
            else {
              return result;
            }
          }
          else if (!zip_lzma_props_decode(
                       props[0], &lzma_keys.lc, &lzma_keys.lp, &lzma_keys.pb)) {
            if (zip->encryption != GARC_ZIP_ENCRYPTION_NONE) {
              archive->data_refusal = GARC_ERR_PASSWORD_OR_CORRUPT;
            }
            else {
              return GARC_ERR_CORRUPT;
            }
          }
          else {
            lzma_keys.dict_size = garc_zip_le32(props + 1u);
            lzma_keys.uncompressed_size = size;
            lzma = &lzma_keys;
            codec_length = payload - (uint64_t)ZIP_LZMA_HEADER_SIZE;
          }
        }
      }
    }
    if (archive->data_refusal == GARC_OK) {
      GARC_Member_Legacy legacy_keys;
      const GARC_Member_Legacy * legacy
          = zip_legacy_keys(body, zip->flags, size, &legacy_keys)
          ? &legacy_keys : NULL;
      result = garc_member_codec_create(archive->allocator, source, codec_name,
          codec_length, size, lzma, legacy, &zip->codec);
      if (result != GARC_OK) {
        // A method compress does not have after all, or no memory. Either way the
        // member's metadata is still good, so this is a refusal on the *data*
        // rather than a failure of the walk - the same answer a codec-gated method
        // gets, arrived at from the other direction.
        if (result != GARC_ERR_OOM) {
          archive->data_refusal = result;
          zip->codec = NULL;
        }
        else {
          return result;
        }
      }
      else {
        zip->crc_active = 1;
      }
    }
  }

  zip->cursor = entry_end;
  zip->entries_seen++;
  return GARC_OK;
}

void garc_zip_rewind(GARC_Archive * archive) {
  // The decoder belongs to a member, and a rewind leaves no current member - so
  // it goes here as well as at the top of garc_zip_next(). Both are needed: a
  // rewind that kept it would leave an object holding a slice of a stream the
  // rewind has just moved, and garc_zip_next() clears it for the walk that does
  // not start with a rewind.
  garc_member_codec_destroy(archive->zip.codec);
  archive->zip.codec = NULL;
  garc_stream_destroy(archive->zip.crypt);
  archive->zip.crypt = NULL;
  archive->zip.crc_active = 0;
  archive->zip.aes_version = 0;
  archive->zip.aes_strength = 0;
  archive->zip.aes_method = 0;
  archive->zip.aes_auth_ok = 0;
  archive->zip.cursor = archive->zip.central_offset;
  archive->zip.entries_seen = 0;
  // The password is not cleared here. It is the archive's, like the base offset
  // and the comment, and a garc_find() that forgot it would refuse a member the
  // same walk had just read.
}

void garc_zip_release(GARC_Archive * archive) {
  GARC_Zip_State * zip = &archive->zip;
  garc_zip_stream_release(archive);
  garc_member_codec_destroy(zip->codec);
  zip->codec = NULL;
  garc_stream_destroy(zip->crypt);
  zip->crypt = NULL;
  // The password and the derived keys are wiped: both are the caller's secret
  // for this archive, and garc_close() is the last moment anything here can do
  // that. ZipCrypto keys are still derived at set_password; the password is
  // kept beside them because an AES member's salt is not known until then.
  if (zip->password && zip->password_length) {
    gsec_wipe(zip->password, zip->password_length);
  }
  gcu_allocator_free(archive->allocator, zip->password);
  zip->password = NULL;
  zip->password_length = 0;
  gsec_wipe(zip->crypt_keys, sizeof(zip->crypt_keys));
  zip->have_password = 0;
  GARC_Buffer * const buffers[4] = {
    &zip->comment,
    &zip->name,
    &zip->extra,
    &zip->link,
  };
  for (size_t i = 0; i < 4u; ++i) {
    garc_buffer_free(archive->allocator, buffers[i]);
  }
}

const char * garc_zip_method_string(uint16_t method) {
  switch (method) {
    case GARC_ZIP_METHOD_STORED:
      return "stored";
    case GARC_ZIP_METHOD_SHRUNK:
      return "shrunk";
    case GARC_ZIP_METHOD_REDUCED_1:
      return "reduced, factor 1";
    case GARC_ZIP_METHOD_REDUCED_2:
      return "reduced, factor 2";
    case GARC_ZIP_METHOD_REDUCED_3:
      return "reduced, factor 3";
    case GARC_ZIP_METHOD_REDUCED_4:
      return "reduced, factor 4";
    case GARC_ZIP_METHOD_IMPLODED:
      return "imploded";
    case GARC_ZIP_METHOD_DEFLATE:
      return "deflate";
    case GARC_ZIP_METHOD_DEFLATE64:
      return "enhanced deflate (deflate64)";
    case GARC_ZIP_METHOD_BZIP2:
      return "bzip2";
    case GARC_ZIP_METHOD_LZMA:
      return "lzma";
    case GARC_ZIP_METHOD_ZSTD:
      return "zstd";
    case GARC_ZIP_METHOD_XZ:
      return "xz";
    case GARC_ZIP_METHOD_PPMD:
      return "ppmd";
    case GARC_ZIP_METHOD_AES:
      return "WinZip AES";
    default:
      // Every method number is a valid field value, so this is the answer for
      // most of them rather than an error case.
      return "unknown";
  }
}

const char * garc_zip_encryption_string(GARC_Zip_Encryption encryption) {
  switch (encryption) {
    case GARC_ZIP_ENCRYPTION_NONE:
      return "none";
    case GARC_ZIP_ENCRYPTION_ZIPCRYPTO:
      return "ZipCrypto (broken)";
    case GARC_ZIP_ENCRYPTION_AES:
      return "WinZip AES";
    case GARC_ZIP_ENCRYPTION_COUNT:
    default:
      return "unknown";
  }
}

/**
 * The zip state of an archive that is a zip, or NULL.
 *
 * Every accessor below goes through this, so "NULL, or not a zip, answers the
 * zero value" is written once. A caller that needs to tell "this member's method
 * is 0" from "this is not a zip" asks ::garc_format().
 */
static const GARC_Zip_State * zip_state(const GARC_Archive * archive) {
  if (!archive || archive->format != GARC_FORMAT_ZIP) {
    return NULL;
  }
  return &archive->zip;
}

uint16_t garc_zip_member_method(const GARC_Archive * archive) {
  const GARC_Zip_State * zip = zip_state(archive);
  return zip ? zip->method : 0u;
}

uint16_t garc_zip_member_flags(const GARC_Archive * archive) {
  const GARC_Zip_State * zip = zip_state(archive);
  return zip ? zip->flags : 0u;
}

uint64_t garc_zip_member_compressed_size(const GARC_Archive * archive) {
  const GARC_Zip_State * zip = zip_state(archive);
  return zip ? zip->compressed_size : 0u;
}

uint32_t garc_zip_member_crc32(const GARC_Archive * archive) {
  const GARC_Zip_State * zip = zip_state(archive);
  return zip ? zip->crc32 : 0u;
}

uint16_t garc_zip_member_version_made_by(const GARC_Archive * archive) {
  const GARC_Zip_State * zip = zip_state(archive);
  return zip ? zip->version_made_by : 0u;
}

uint32_t garc_zip_member_external_attributes(const GARC_Archive * archive) {
  const GARC_Zip_State * zip = zip_state(archive);
  return zip ? zip->external_attributes : 0u;
}

GARC_Result garc_zip_set_password(
    GARC_Archive * archive, const void * password, size_t length) {
  if (!archive || archive->format != GARC_FORMAT_ZIP) {
    return GARC_ERR_INVALID;
  }
  if (!password && length) {
    return GARC_ERR_INVALID;
  }
  GARC_Zip_State * zip = &archive->zip;
  uint8_t * copy = NULL;
  if (length) {
    copy = (uint8_t *)gcu_allocator_malloc(archive->allocator, length);
    if (!copy) {
      return GARC_ERR_OOM;
    }
    memcpy(copy, password, length);
  }
  if (zip->password && zip->password_length) {
    gsec_wipe(zip->password, zip->password_length);
  }
  gcu_allocator_free(archive->allocator, zip->password);
  zip->password = copy;
  zip->password_length = length;
  // ZipCrypto keys are still derived here. AES derives per member, from this
  // copy and that member's salt. An empty password is a copy of length 0.
  garc_zip_crypt_derive(zip->crypt_keys, password, length);
  zip->have_password = 1;
  return GARC_OK;
}

GARC_Zip_Encryption garc_zip_member_encryption(const GARC_Archive * archive) {
  const GARC_Zip_State * zip = zip_state(archive);
  return zip ? zip->encryption : GARC_ZIP_ENCRYPTION_NONE;
}

size_t garc_zip_member_extra_length(const GARC_Archive * archive) {
  const GARC_Zip_State * zip = zip_state(archive);
  return zip ? zip->extra_length : 0u;
}

int garc_zip_member_used_zip64(const GARC_Archive * archive) {
  const GARC_Zip_State * zip = zip_state(archive);
  return zip ? zip->used_zip64 : 0;
}

uint64_t garc_zip_base_offset(const GARC_Archive * archive) {
  const GARC_Zip_State * zip = zip_state(archive);
  return zip ? zip->origin - archive->start_offset : 0u;
}

int garc_zip_has_zip64_end_record(const GARC_Archive * archive) {
  const GARC_Zip_State * zip = zip_state(archive);
  return zip ? zip->is_zip64 : 0;
}

uint64_t garc_zip_declared_members(const GARC_Archive * archive) {
  const GARC_Zip_State * zip = zip_state(archive);
  return zip ? zip->declared_members : 0u;
}

const char * garc_zip_archive_comment(
    const GARC_Archive * archive, size_t * out_length) {
  if (!out_length) {
    return NULL;
  }
  const GARC_Zip_State * zip = zip_state(archive);
  if (!zip || !zip->comment.length) {
    *out_length = 0;
    return NULL;
  }
  *out_length = zip->comment.length;
  return zip->comment.bytes;
}

GARC_Result garc_zip_raw_entry(
    const GARC_Archive * archive, GARC_Zip_Raw_Entry * out) {
  const GARC_Zip_State * zip = &archive->zip;
  memset(out, 0, sizeof(*out));
  out->version_made_by = zip->version_made_by;
  out->version_needed = zip->version_needed;
  out->flags = zip->flags;
  out->method = zip->method;
  out->dos_time = zip->dos_time;
  out->dos_date = zip->dos_date;
  out->crc32 = zip->crc32;
  out->compressed_size = zip->compressed_size;
  out->size = archive->member.size;
  out->internal_attributes = zip->internal_attributes;
  out->external_attributes = zip->external_attributes;
  out->extra = (const uint8_t *)zip->extra.bytes;
  out->extra_length = zip->extra.length;
  out->name = (const uint8_t *)zip->name.bytes;
  out->name_length = zip->name.length;
  out->comment_length = zip->comment_length;
  return GARC_OK;
}

GARC_Result garc_zip_raw_comment(
    GARC_Archive * archive, uint8_t * buffer, size_t length) {
  if (length != archive->zip.comment_length) {
    return GARC_ERR_INTERNAL;
  }
  return length ? zip_read_at(archive, archive->zip.comment_offset, buffer,
                      length)
                : GARC_OK;
}

GARC_Result garc_zip_raw_read(
    GARC_Archive * archive, uint64_t at, void * buffer, size_t length) {
  if (at > archive->zip.compressed_size
      || (uint64_t)length > archive->zip.compressed_size - at) {
    return GARC_ERR_INTERNAL;
  }
  return zip_read_at(archive, archive->member.data_offset + at,
      (uint8_t *)buffer, length);
}

////////////////////////////////////////////////////////////////////////
// Streaming: a zip read from a stream that cannot seek
////////////////////////////////////////////////////////////////////////
//
// A zip's index is at its end, so a reader that cannot seek has only the local
// headers, in order. They are enough to walk the members, with three limits that
// are the format's and not this reader's:
//
// - **A local header knows less than a directory entry.** No external
//   attributes, so no Unix mode and no symlink type: a member is a directory when
//   its name ends in `/` and a file otherwise, and a symlink reads as a file whose
//   data is its target.
// - **A member with a data descriptor has no sizes in its header.** Its end is
//   where its codec says the compressed stream ends - deflate, deflate64, LZMA
//   with an end marker, zstd - and the descriptor after it is read and checked
//   against what was decoded. A stored member with a descriptor has no end that
//   anything marks, and is refused by name. bzip2 and xz with one are refused
//   too: compress's decoders for those read concatenated streams and offer no way
//   to stop at the first, so the descriptor would be taken for a second stream.
// - **Encrypted members are listed and not read.** ZipCrypto and WinZip AES are
//   set up here by offset, and AES's check is at the member's end.
//
// **The local headers are not trusted to be the archive.** The central
// directory is read when the walk reaches it, and every member the walk
// reported is checked against its entry: the name byte for byte, the offset,
// the method, the encryption scheme and AES's real method, the CRC and both
// sizes. Then the end records: the count, the directory's size and offset, the
// disks, and that the archive ends where its comment does - every refusal
// garc_zip_open() makes of them. A disagreement is an error from the garc_next()
// that reaches the directory, which is the walk's verdict - two readers seeing
// two archives in one file is the attack this closes. fuzz_zip compares the two
// walks of every input, and each of those checks was added for a case it found.

/** What the walk saw of one member, to check against the directory. */
typedef struct {
  uint64_t name_at;     ///< Where its name starts in the kept names.
  uint64_t offset;      ///< Where its local header began.
  uint64_t compressed;  ///< Its stored size, measured for a descriptor member.
  uint64_t size;        ///< Its uncompressed size, likewise.
  uint32_t crc;         ///< Its CRC-32, likewise.
  uint32_t name_length; ///< Its name's length.
  uint16_t method;      ///< Its method.
  uint16_t aes_method;  ///< Its real method, for a WinZip AES member.
  int encryption;       ///< Its GARC_Zip_Encryption, from the local header.
} Zip_Stream_Record;

/**
 * Room for @p needed bytes in a buffer that grows by one member at a time.
 *
 * Doubling, because garc_buffer_grow() asks for exactly what it is told and a
 * walk over a million members would otherwise copy its records a million times.
 */
static GARC_Result zs_grow(
    const GARC_Allocator * allocator, GARC_Buffer * buffer, size_t needed) {
  if (buffer->capacity > needed) {
    return GARC_OK;
  }
  size_t wanted = buffer->capacity < SIZE_MAX / 2u ? buffer->capacity * 2u : needed;
  if (wanted < needed) {
    wanted = needed;
  }
  return garc_buffer_grow(allocator, buffer, wanted);
}

/** The archive's bytes in order: what was given back first, then the stream. */
static GARC_Result zs_seq_read(
    void * ctx, void * buffer, size_t size, size_t * out_read) {
  GARC_Archive * archive = (GARC_Archive *)ctx;
  GARC_Zip_State * zip = &archive->zip;
  const size_t held = zip->pushback.length - zip->pushback_offset;
  if (held) {
    const size_t take = held < size ? held : size;
    memcpy(buffer, zip->pushback.bytes + zip->pushback_offset, take);
    zip->pushback_offset += take;
    if (zip->pushback_offset == zip->pushback.length) {
      zip->pushback.length = 0;
      zip->pushback_offset = 0;
    }
    zip->position += take;
    *out_read = take;
    return GARC_OK;
  }
  GARC_Result result = garc_tar_read(archive, (uint8_t *)buffer, size, out_read);
  if (result == GARC_OK) {
    zip->position += *out_read;
  }
  return result;
}

/** Give bytes back, to be read again before anything else. */
static GARC_Result zs_give_back(
    GARC_Archive * archive, const uint8_t * bytes, size_t length) {
  GARC_Zip_State * zip = &archive->zip;
  if (!length) {
    return GARC_OK;
  }
  const size_t held = zip->pushback.length - zip->pushback_offset;
  GARC_Result result = garc_buffer_grow(
      archive->allocator, &zip->pushback, held + length);
  if (result != GARC_OK) {
    return result;
  }
  // The held bytes move up and the new ones go in front of them; `bytes` may be
  // the codec's own staging buffer, never this one, so the two cannot overlap.
  memmove(zip->pushback.bytes + length, zip->pushback.bytes + zip->pushback_offset,
      held);
  memcpy(zip->pushback.bytes, bytes, length);
  zip->pushback.length = held + length;
  zip->pushback_offset = 0;
  zip->position -= length;
  return GARC_OK;
}

static GARC_Result zs_read_exact(GARC_Archive * archive, void * buffer, size_t length) {
  size_t have = 0;
  while (have < length) {
    size_t got = 0;
    GARC_Result result
        = zs_seq_read(archive, (uint8_t *)buffer + have, length - have, &got);
    if (result != GARC_OK) {
      return result;
    }
    if (!got) {
      return GARC_ERR_CORRUPT;
    }
    have += got;
  }
  return GARC_OK;
}

static GARC_Result zs_discard(GARC_Archive * archive, uint64_t count) {
  uint8_t scratch[4096];
  while (count) {
    const size_t want = count < sizeof(scratch) ? (size_t)count : sizeof(scratch);
    GARC_Result result = zs_read_exact(archive, scratch, want);
    if (result != GARC_OK) {
      return result;
    }
    count -= want;
  }
  return GARC_OK;
}

/** Tear down the current member's slice and decoder. */
static void zs_drop_member(GARC_Archive * archive) {
  GARC_Zip_State * zip = &archive->zip;
  garc_member_codec_destroy(zip->codec);
  zip->codec = NULL;
  garc_stream_destroy(zip->s_decoder);
  zip->s_decoder = NULL;
  gcomp_options_destroy(zip->s_options);
  zip->s_options = NULL;
  garc_stream_destroy(zip->s_slice);
  zip->s_slice = NULL;
}

GARC_Result garc_zip_stream_open(GARC_Archive * archive) {
  GARC_Zip_State * zip = &archive->zip;
  zip->streaming = 1;
  GARC_Stream_Callbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.read = zs_seq_read;
  callbacks.ctx = archive;
  return garc_stream_create_callback_with_allocator(
      &callbacks, archive->allocator, &zip->seq);
}

/**
 * Read and check the descriptor after a member whose codec found its end.
 *
 * The signature is optional and every writer here writes it; without it the
 * first word is the CRC. Sizes are 64-bit when the local header had a zip64
 * field, which is APPNOTE's rule for telling the two layouts apart.
 */
static GARC_Result zs_read_descriptor(GARC_Archive * archive) {
  GARC_Zip_State * zip = &archive->zip;
  uint8_t word[4];
  GARC_Result result = zs_read_exact(archive, word, sizeof(word));
  if (result != GARC_OK) {
    return result;
  }
  uint32_t crc = garc_zip_le32(word);
  if (word[0] == 'P' && word[1] == 'K' && word[2] == 7u && word[3] == 8u) {
    result = zs_read_exact(archive, word, sizeof(word));
    if (result != GARC_OK) {
      return result;
    }
    crc = garc_zip_le32(word);
  }
  uint64_t compressed = 0;
  uint64_t size = 0;
  if (zip->s_zip64) {
    uint8_t sizes[16];
    result = zs_read_exact(archive, sizes, sizeof(sizes));
    compressed = garc_zip_le64(sizes);
    size = garc_zip_le64(sizes + 8u);
  }
  else {
    uint8_t sizes[8];
    result = zs_read_exact(archive, sizes, sizeof(sizes));
    compressed = garc_zip_le32(sizes);
    size = garc_zip_le32(sizes + 4u);
  }
  if (result != GARC_OK) {
    return result;
  }
  zip->crc32 = crc;
  if (compressed != zip->compressed_size || size != zip->s_produced) {
    return GARC_ERR_CORRUPT;
  }
  return GARC_OK;
}

/**
 * Finish the current member: read to its end, check what ends it, record it.
 *
 * Called by the next garc_next() and by garc_skip_member(), so a member is
 * finished once whichever comes first.
 */
static GARC_Result zs_finish_member(GARC_Archive * archive) {
  GARC_Zip_State * zip = &archive->zip;
  if (!zip->s_open) {
    return GARC_OK;
  }
  if (zip->s_stuck != GARC_OK) {
    // A member whose end cannot be found: nothing after it can be reached.
    return zip->s_stuck;
  }
  GARC_Result result = GARC_OK;
  if (zip->s_dir_descriptor) {
    zip->s_produced = 0;
    result = zs_read_descriptor(archive);
  }
  else if (zip->s_descriptor) {
    // Decoded to its end even unread, because the codec is what finds the end.
    uint8_t scratch[4096];
    size_t got = 0;
    while (!zip->s_data_done && result == GARC_OK) {
      result = garc_zip_stream_read(archive, scratch, sizeof(scratch), &got);
    }
  }
  else {
    zs_drop_member(archive);
    const uint64_t used = zip->position - zip->s_data_start;
    if (used > zip->compressed_size) {
      return GARC_ERR_INTERNAL;
    }
    result = zs_discard(archive, zip->compressed_size - used);
  }
  zs_drop_member(archive);
  if (result != GARC_OK) {
    return result;
  }
  // What the walk saw, for the directory to agree with.
  Zip_Stream_Record record;
  memset(&record, 0, sizeof(record));
  // The name itself rather than a hash of it: a hash an archive can collide
  // would let the walk hand over one name while the directory says another,
  // which is the disagreement this record exists to catch.
  record.name_at = zip->s_names.length;
  record.name_length = (uint32_t)zip->name.length;
  result = zs_grow(archive->allocator, &zip->s_names,
      zip->s_names.length + zip->name.length);
  if (result != GARC_OK) {
    return result;
  }
  if (zip->name.length) {
    memcpy(zip->s_names.bytes + zip->s_names.length, zip->name.bytes,
        zip->name.length);
  }
  zip->s_names.length += zip->name.length;
  record.offset = zip->s_local_offset;
  record.compressed = zip->compressed_size;
  record.size = zip->s_descriptor ? zip->s_produced : archive->member.size;
  record.crc = zip->crc32;
  record.method = zip->method;
  record.encryption = (int)zip->encryption;
  record.aes_method = zip->encryption == GARC_ZIP_ENCRYPTION_AES
      ? zip->aes_method : 0u;
  result = zs_grow(archive->allocator, &zip->records,
      (zip->record_count + 1u) * sizeof(record));
  if (result != GARC_OK) {
    return result;
  }
  memcpy(zip->records.bytes + zip->record_count * sizeof(record), &record,
      sizeof(record));
  zip->record_count++;
  zip->records.length = zip->record_count * sizeof(record);
  zip->s_open = 0;
  return GARC_OK;
}

/**
 * The central directory, read at the end and checked against the walk.
 *
 * Everything garc_zip_open() would refuse in the end records is refused here
 * too, and everything they declare - how many members, how large the directory
 * is and where it starts - must be what the walk measured. A streamed walk is
 * only as good as this check: an end record left unchecked would let an archive
 * whose seekable reading is refused be read to the end from a pipe.
 */
static GARC_Result zs_check_directory(GARC_Archive * archive) {
  GARC_Zip_State * zip = &archive->zip;
  size_t seen = 0;
  const uint64_t central_start = zip->position;
  uint64_t central_end = UINT64_MAX;
  int have_zip64 = 0;
  uint64_t z64_entries = 0;
  uint64_t z64_size = 0;
  uint64_t z64_offset = 0;
  uint64_t z64_at = 0;
  int have_locator = 0;
  for (;;) {
    const uint64_t at = zip->position;
    uint8_t sig[4];
    GARC_Result result = zs_read_exact(archive, sig, sizeof(sig));
    if (result != GARC_OK) {
      return result;
    }
    if (memcmp(sig, ZIP_SIG_CENTRAL, 4) == 0) {
      if (central_end != UINT64_MAX) {
        return GARC_ERR_CORRUPT; // a directory entry after the end records
      }
      uint8_t entry[GARC_ZIP_CENTRAL_ENTRY_SIZE];
      memcpy(entry, sig, 4);
      result = zs_read_exact(archive, entry + 4, sizeof(entry) - 4u);
      if (result != GARC_OK) {
        return result;
      }
      if (seen >= zip->record_count) {
        return GARC_ERR_CORRUPT; // a member the walk never met
      }
      const uint16_t name_length = garc_zip_le16(entry + 28u);
      const uint16_t extra_length = garc_zip_le16(entry + 30u);
      const uint16_t comment_length = garc_zip_le16(entry + 32u);
      result = garc_buffer_grow(archive->allocator, &zip->name, name_length);
      if (result == GARC_OK) {
        result = zs_read_exact(archive, zip->name.bytes, name_length);
      }
      if (result == GARC_OK) {
        result = garc_buffer_grow(archive->allocator, &zip->extra, extra_length);
      }
      if (result == GARC_OK) {
        result = zs_read_exact(archive, zip->extra.bytes, extra_length);
      }
      if (result == GARC_OK) {
        result = zs_discard(archive, comment_length);
      }
      if (result != GARC_OK) {
        return result;
      }
      uint64_t compressed = garc_zip_le32(entry + 20u);
      uint64_t size = garc_zip_le32(entry + 24u);
      uint64_t offset = garc_zip_le32(entry + 42u);
      int used_zip64 = 0;
      Zip_Extra extra;
      memset(&extra, 0, sizeof(extra));
      result = zip_parse_extra((const uint8_t *)zip->extra.bytes, extra_length,
          &size, &compressed, &offset, &used_zip64, &extra);
      if (result != GARC_OK) {
        return result;
      }
      Zip_Stream_Record record;
      memcpy(&record, zip->records.bytes + seen * sizeof(record), sizeof(record));
      // The encryption the directory describes, by the rule the seekable
      // reader applies to it: a pipe that decided from the local header alone
      // could call a member AES that every other reader calls ZipCrypto.
      const uint16_t central_flags = garc_zip_le16(entry + 8u);
      const uint16_t central_method = garc_zip_le16(entry + 10u);
      int central_encryption = GARC_ZIP_ENCRYPTION_NONE;
      if (central_flags & ZIP_FLAG_ENCRYPTED) {
        central_encryption
            = (central_method == GARC_ZIP_METHOD_AES && extra.have_aes)
            ? GARC_ZIP_ENCRYPTION_AES : GARC_ZIP_ENCRYPTION_ZIPCRYPTO;
      }
      const uint16_t central_aes_method
          = central_encryption == GARC_ZIP_ENCRYPTION_AES
          ? extra.aes_real_method : 0u;
      if (garc_zip_le16(entry + 34u) != 0u) {
        return GARC_ERR_UNSUPPORTED; // on another disk, as garc_zip_open() says
      }
      if (record.name_length != name_length
          || (name_length
              && memcmp(zip->s_names.bytes + record.name_at, zip->name.bytes,
                     name_length) != 0)
          || record.offset != offset || record.method != garc_zip_le16(entry + 10u)
          || record.crc != garc_zip_le32(entry + 16u)
          || record.compressed != compressed || record.size != size
          || record.encryption != central_encryption
          || record.aes_method != central_aes_method) {
        return GARC_ERR_CORRUPT;
      }
      ++seen;
      continue;
    }
    if (memcmp(sig, ZIP_SIG_ZIP64_EOCD, 4) == 0) {
      if (have_zip64 || have_locator) {
        return GARC_ERR_CORRUPT;
      }
      uint8_t record[GARC_ZIP_ZIP64_EOCD_SIZE];
      memcpy(record, sig, 4);
      result = zs_read_exact(archive, record + 4, sizeof(record) - 4u);
      if (result != GARC_OK) {
        return result;
      }
      // The record's own size counts what follows its first twelve bytes.
      const uint64_t declared = garc_zip_le64(record + 4u);
      if (declared < GARC_ZIP_ZIP64_EOCD_SIZE - 12u
          || declared - (GARC_ZIP_ZIP64_EOCD_SIZE - 12u) > ZIP_MARKER16) {
        return GARC_ERR_CORRUPT;
      }
      const uint32_t disk = garc_zip_le32(record + 16u);
      const uint32_t central_disk = garc_zip_le32(record + 20u);
      const uint64_t entries_here = garc_zip_le64(record + 24u);
      z64_entries = garc_zip_le64(record + 32u);
      if (disk != 0u || central_disk != 0u || entries_here != z64_entries) {
        return GARC_ERR_UNSUPPORTED;
      }
      z64_size = garc_zip_le64(record + 40u);
      z64_offset = garc_zip_le64(record + 48u);
      result = zs_discard(archive, declared - (GARC_ZIP_ZIP64_EOCD_SIZE - 12u));
      if (result != GARC_OK) {
        return result;
      }
      have_zip64 = 1;
      z64_at = at;
      central_end = at;
      continue;
    }
    if (memcmp(sig, ZIP_SIG_ZIP64_LOCATOR, 4) == 0) {
      if (!have_zip64 || have_locator) {
        return GARC_ERR_CORRUPT;
      }
      uint8_t locator[GARC_ZIP_ZIP64_LOCATOR_SIZE];
      memcpy(locator, sig, 4);
      result = zs_read_exact(archive, locator + 4, sizeof(locator) - 4u);
      if (result != GARC_OK) {
        return result;
      }
      if (garc_zip_le32(locator + 4u) != 0u || garc_zip_le32(locator + 16u) > 1u) {
        return GARC_ERR_UNSUPPORTED;
      }
      if (garc_zip_le64(locator + 8u) != z64_at) {
        return GARC_ERR_CORRUPT;
      }
      have_locator = 1;
      continue;
    }
    if (memcmp(sig, ZIP_SIG_EOCD, 4) == 0) {
      if (have_zip64 != have_locator) {
        return GARC_ERR_CORRUPT;
      }
      if (central_end == UINT64_MAX) {
        central_end = at;
      }
      uint8_t eocd[GARC_ZIP_EOCD_SIZE];
      memcpy(eocd, sig, 4);
      result = zs_read_exact(archive, eocd + 4, sizeof(eocd) - 4u);
      if (result != GARC_OK) {
        return result;
      }
      const uint16_t disk = garc_zip_le16(eocd + 4u);
      const uint16_t central_disk = garc_zip_le16(eocd + 6u);
      const uint16_t entries_here = garc_zip_le16(eocd + 8u);
      const uint16_t entries_total = garc_zip_le16(eocd + 10u);
      if (disk != 0u || central_disk != 0u || entries_here != entries_total) {
        return GARC_ERR_UNSUPPORTED;
      }
      uint64_t entries = entries_total;
      uint64_t central_size = garc_zip_le32(eocd + 12u);
      uint64_t central_offset = garc_zip_le32(eocd + 16u);
      if (have_zip64) {
        // As garc_zip_open() reads it: the zip64 record's values are the
        // archive's whenever it is there, marker or not.
        entries = z64_entries;
        central_size = z64_size;
        central_offset = z64_offset;
      }
      else if (entries == ZIP_MARKER16 || central_size == ZIP_MARKER32
          || central_offset == ZIP_MARKER32) {
        return GARC_ERR_CORRUPT; // "ask zip64" with no zip64 record
      }
      if (seen != zip->record_count || entries != (uint64_t)seen) {
        return GARC_ERR_CORRUPT; // a member the directory does not list
      }
      if (central_size != central_end - central_start
          || central_offset != central_start) {
        return GARC_ERR_CORRUPT;
      }
      // The comment is kept, as garc_zip_open() keeps it. And the archive
      // must end where it does: the seekable reader cannot find an end record
      // with anything after its comment, so a pipe that ignored what followed
      // would read to the end an archive every other reading refuses.
      const uint16_t comment_length = garc_zip_le16(eocd + 20u);
      result = garc_buffer_grow(archive->allocator, &zip->comment, comment_length);
      if (result == GARC_OK) {
        result = zs_read_exact(archive, zip->comment.bytes, comment_length);
      }
      if (result != GARC_OK) {
        return result;
      }
      zip->comment.length = comment_length;
      zip->comment.bytes[comment_length] = '\0';
      uint8_t after = 0;
      size_t got = 0;
      result = zs_seq_read(archive, &after, 1u, &got);
      if (result != GARC_OK) {
        return result;
      }
      if (got) {
        return GARC_ERR_FORMAT;
      }
      zip->declared_members = entries;
      zip->is_zip64 = have_zip64;
      archive->at_end = 1;
      return GARC_END;
    }
    return GARC_ERR_CORRUPT;
  }
}

GARC_Result garc_zip_stream_next(GARC_Archive * archive) {
  GARC_Zip_State * zip = &archive->zip;
  GARC_Result result = zs_finish_member(archive);
  if (result != GARC_OK) {
    return result;
  }

  uint8_t header[GARC_ZIP_LOCAL_HEADER_SIZE];
  result = zs_read_exact(archive, header, 4u);
  if (result != GARC_OK) {
    return result;
  }
  if (memcmp(header, ZIP_SIG_CENTRAL, 4) == 0
      || memcmp(header, ZIP_SIG_EOCD, 4) == 0
      || memcmp(header, ZIP_SIG_ZIP64_EOCD, 4) == 0) {
    result = zs_give_back(archive, header, 4u);
    if (result != GARC_OK) {
      return result;
    }
    return zs_check_directory(archive);
  }
  if (memcmp(header, ZIP_SIG_LOCAL, 4) != 0) {
    return GARC_ERR_CORRUPT;
  }
  const uint64_t local_offset = zip->position - 4u;
  result = zs_read_exact(archive, header + 4, sizeof(header) - 4u);
  if (result != GARC_OK) {
    return result;
  }

  zip->version_needed = garc_zip_le16(header + 4u);
  zip->flags = garc_zip_le16(header + 6u);
  zip->method = garc_zip_le16(header + 8u);
  zip->dos_time = garc_zip_le16(header + 10u);
  zip->dos_date = garc_zip_le16(header + 12u);
  zip->crc32 = garc_zip_le32(header + 14u);
  uint64_t compressed_size = garc_zip_le32(header + 18u);
  uint64_t size = garc_zip_le32(header + 22u);
  const uint16_t name_length = garc_zip_le16(header + 26u);
  const uint16_t extra_length = garc_zip_le16(header + 28u);
  zip->version_made_by = 0;
  zip->external_attributes = 0;
  zip->internal_attributes = 0;
  zip->comment_length = 0;
  zip->encryption = GARC_ZIP_ENCRYPTION_NONE;
  zip->aes_version = 0;
  zip->aes_strength = 0;
  zip->aes_method = 0;
  zip->crc_active = 0;
  zip->running_crc = GCOMP_CRC32_INIT;

  if (archive->limits.max_name_bytes
      && name_length > archive->limits.max_name_bytes) {
    return GARC_ERR_LIMIT_NAME_BYTES;
  }
  if (archive->limits.max_extra_bytes
      && extra_length > archive->limits.max_extra_bytes) {
    return GARC_ERR_LIMIT_EXTRA_BYTES;
  }
  result = garc_buffer_grow(archive->allocator, &zip->name, name_length);
  if (result == GARC_OK) {
    result = zs_read_exact(archive, zip->name.bytes, name_length);
  }
  if (result != GARC_OK) {
    return result;
  }
  zip->name.bytes[name_length] = '\0';
  zip->name.length = name_length;
  result = garc_buffer_grow(archive->allocator, &zip->extra, extra_length);
  if (result == GARC_OK) {
    result = zs_read_exact(archive, zip->extra.bytes, extra_length);
  }
  if (result != GARC_OK) {
    return result;
  }
  zip->extra.length = extra_length;
  zip->extra_length = extra_length;
  uint64_t unused_offset = 0;
  Zip_Extra extra;
  memset(&extra, 0, sizeof(extra));
  zip->used_zip64 = 0;
  result = zip_parse_extra((const uint8_t *)zip->extra.bytes, extra_length,
      &size, &compressed_size, &unused_offset, &zip->used_zip64, &extra);
  if (result != GARC_OK) {
    return result;
  }
  zip->s_descriptor = (zip->flags & ZIP_FLAG_DATA_DESCRIPTOR) != 0;
  // APPNOTE: a descriptor's sizes are 64-bit when the local header has a zip64
  // field, whatever that field holds.
  zip->s_zip64 = zip->used_zip64 || extra.have_zip64;
  if (!zip->s_descriptor && (size == ZIP_MARKER32 || compressed_size == ZIP_MARKER32)) {
    return GARC_ERR_CORRUPT;
  }
  zip->compressed_size = zip->s_descriptor ? 0u : compressed_size;
  zip->local_offset = local_offset;
  zip->s_local_offset = local_offset;
  zip->s_data_start = zip->position;
  zip->s_produced = 0;
  zip->s_data_done = 0;
  zip->s_stuck = GARC_OK;
  if (zip->flags & ZIP_FLAG_ENCRYPTED) {
    zip->encryption = (zip->method == GARC_ZIP_METHOD_AES && extra.have_aes)
        ? GARC_ZIP_ENCRYPTION_AES : GARC_ZIP_ENCRYPTION_ZIPCRYPTO;
  }
  if (zip->encryption == GARC_ZIP_ENCRYPTION_AES) {
    // As the seekable reader records them, so the accessors answer the same.
    zip->aes_version = extra.aes_version;
    zip->aes_strength = extra.aes_strength;
    zip->aes_method = extra.aes_real_method;
  }

  GARC_Member * member = &archive->member;
  memset(member, 0, sizeof(*member));
  // Never NULL: an empty name is "", as every other reader gives it.
  member->name = zip->name.length ? zip->name.bytes : "";
  member->name_length = zip->name.length;
  member->name_encoding = (zip->flags & ZIP_FLAG_UTF8) ? GARC_NAME_UTF8
      : GARC_NAME_UNDECLARED;
  member->type = (name_length && zip->name.bytes[name_length - 1u] == '/')
      ? GARC_MEMBER_DIRECTORY : GARC_MEMBER_FILE;
  member->size = zip->s_descriptor ? 0u : size;
  member->size_unknown = zip->s_descriptor && member->type == GARC_MEMBER_FILE;
  if (extra.mtime_source != GARC_TIME_NONE) {
    member->mtime_seconds = extra.mtime_seconds;
    member->mtime_nanoseconds = extra.mtime_nanoseconds;
    member->mtime_source = extra.mtime_source;
  }
  else {
    int64_t seconds = 0;
    if (garc_zip_dos_to_epoch(zip->dos_date, zip->dos_time, &seconds) == GARC_OK) {
      member->mtime_seconds = seconds;
      member->mtime_source = GARC_TIME_ZIP_DOS;
    }
  }
  if (extra.ids_valid) {
    member->uid = extra.uid;
    member->gid = extra.gid;
    member->ids_valid = 1;
  }
  member->header_offset = local_offset;
  member->data_offset = zip->position;

  archive->data_remaining = member->size;
  archive->data_padding = 0;
  archive->data_refusal = GARC_OK;
  zip->s_open = 1;

  const char * codec_name = zip_codec_name(zip->method);
  GARC_Member_Legacy no_legacy;
  zip->s_dir_descriptor = 0;
  if (member->type == GARC_MEMBER_DIRECTORY
      && !(zip->s_descriptor && zip->method != GARC_ZIP_METHOD_STORED)) {
    // A directory has no data, so a stored one's descriptor follows its header
    // at once and is read there. One with a codec (Java writes an empty deflate
    // stream for every directory of a jar) goes through the codec below, like a
    // file, and must decode to nothing.
    zip->s_dir_descriptor = zip->s_descriptor;
    zip->compressed_size = zip->s_descriptor ? 0u : compressed_size;
    archive->data_remaining = 0;
    zip->s_data_done = 1;
  }
  else if (zip->encryption != GARC_ZIP_ENCRYPTION_NONE
      || (zip->flags & 0x0040u)) {
    // Listed, not read: see the section comment.
    archive->data_refusal = GARC_ERR_UNSUPPORTED;
    if (zip->s_descriptor) {
      zip->s_stuck = GARC_ERR_UNSUPPORTED;
    }
  }
  else if (zip->method != GARC_ZIP_METHOD_STORED && !codec_name) {
    archive->data_refusal = GARC_ERR_UNSUPPORTED;
    if (zip->s_descriptor) {
      zip->s_stuck = GARC_ERR_UNSUPPORTED;
    }
  }
  else if (zip->s_descriptor
      && (zip->method == GARC_ZIP_METHOD_STORED
          || zip->method == GARC_ZIP_METHOD_BZIP2
          || zip->method == GARC_ZIP_METHOD_XZ
          || (zip->method == GARC_ZIP_METHOD_LZMA
              && !(zip->flags & ZIP_FLAG_LZMA_EOS))
          || zip_legacy_keys(zip->method, zip->flags, 0u, &no_legacy))) {
    // Nothing marks where these end: see the section comment.
    archive->data_refusal = GARC_ERR_UNSUPPORTED;
    zip->s_stuck = GARC_ERR_UNSUPPORTED;
  }
  else if (!zip->s_descriptor) {
    if (zip->method == GARC_ZIP_METHOD_STORED && compressed_size != size) {
      return GARC_ERR_CORRUPT;
    }
    if (zip->method == GARC_ZIP_METHOD_STORED) {
      result = garc_stream_create_slice_with_allocator(
          zip->seq, compressed_size, archive->allocator, &zip->s_slice);
      if (result != GARC_OK) {
        return result;
      }
    }
    else {
      GARC_Member_Lzma lzma_keys;
      const GARC_Member_Lzma * lzma = NULL;
      uint64_t codec_length = compressed_size;
      if (zip->method == GARC_ZIP_METHOD_LZMA) {
        uint8_t lzma_header[ZIP_LZMA_HEADER_SIZE];
        if (compressed_size < sizeof(lzma_header)) {
          return GARC_ERR_CORRUPT;
        }
        result = zs_read_exact(archive, lzma_header, sizeof(lzma_header));
        if (result != GARC_OK) {
          return result;
        }
        if (garc_zip_le16(lzma_header + 2u) != ZIP_LZMA_PROPS_SIZE
            || !zip_lzma_props_decode(lzma_header[4], &lzma_keys.lc,
                &lzma_keys.lp, &lzma_keys.pb)) {
          return GARC_ERR_CORRUPT;
        }
        lzma_keys.dict_size = garc_zip_le32(lzma_header + 5u);
        lzma_keys.uncompressed_size = size;
        lzma = &lzma_keys;
        codec_length = compressed_size - sizeof(lzma_header);
      }
      GARC_Member_Legacy legacy_keys;
      const GARC_Member_Legacy * legacy
          = zip_legacy_keys(zip->method, zip->flags, size, &legacy_keys)
          ? &legacy_keys : NULL;
      result = garc_member_codec_create(archive->allocator, zip->seq, codec_name,
          codec_length, size, lzma, legacy, &zip->codec);
      if (result != GARC_OK) {
        return result;
      }
    }
    zip->crc_active = 1;
  }
  else {
    // A descriptor member whose codec ends itself.
    if (gcomp_options_create(&zip->s_options) != GCOMP_OK) {
      return GARC_ERR_OOM;
    }
    int failed = 0;
    if (archive->limits.max_member_bytes) {
      failed |= gcomp_options_set_uint64(zip->s_options,
                    "limits.max_output_bytes", archive->limits.max_member_bytes)
          != GCOMP_OK;
    }
    if (zip->method == GARC_ZIP_METHOD_ZSTD) {
      // One frame: what follows it is the descriptor, not a second frame.
      failed |= gcomp_options_set_bool(zip->s_options, "zstd.concat", 0)
          != GCOMP_OK;
    }
    if (zip->method == GARC_ZIP_METHOD_LZMA) {
      uint8_t lzma_header[ZIP_LZMA_HEADER_SIZE];
      result = zs_read_exact(archive, lzma_header, sizeof(lzma_header));
      if (result != GARC_OK) {
        return result;
      }
      int64_t lc = 0;
      int64_t lp = 0;
      int64_t pb = 0;
      if (garc_zip_le16(lzma_header + 2u) != ZIP_LZMA_PROPS_SIZE
          || !zip_lzma_props_decode(lzma_header[4], &lc, &lp, &pb)) {
        return GARC_ERR_CORRUPT;
      }
      failed |= gcomp_options_set_bool(zip->s_options, "lzma.raw", 1) != GCOMP_OK
          || gcomp_options_set_int64(zip->s_options, "lzma.lc", lc) != GCOMP_OK
          || gcomp_options_set_int64(zip->s_options, "lzma.lp", lp) != GCOMP_OK
          || gcomp_options_set_int64(zip->s_options, "lzma.pb", pb) != GCOMP_OK
          || gcomp_options_set_uint64(zip->s_options, "lzma.dict_size",
                 garc_zip_le32(lzma_header + 5u))
              != GCOMP_OK;
    }
    if (failed) {
      return GARC_ERR_OOM;
    }
    result = garc_stream_create_decompress_with_allocator(zip->seq, codec_name,
        zip->s_options, archive->allocator, &zip->s_decoder);
    if (result != GARC_OK) {
      return result;
    }
    garc_codec_stream_stop_at_end(zip->s_decoder);
    archive->data_remaining = UINT64_MAX;
    zip->crc_active = 1;
  }

  return garc_reader_account(archive);
}

/**
 * A descriptor member's data, through its codec, and the descriptor after it.
 *
 * Only the codec knows where such a member ends, so once its stream has failed
 * the end is lost: the failure is kept in `s_stuck`, which is what the walk
 * returns from then on, rather than handing a broken decoder another read.
 */
static GARC_Result zs_read_descriptor_member(
    GARC_Archive * archive, void * buffer, size_t capacity, size_t * out_read);
static GARC_Result zs_read_sized_member(
    GARC_Archive * archive, void * buffer, size_t capacity, size_t * out_read);

GARC_Result garc_zip_stream_read(
    GARC_Archive * archive, void * buffer, size_t capacity, size_t * out_read) {
  GARC_Zip_State * zip = &archive->zip;
  *out_read = 0;
  if (zip->s_data_done || !capacity) {
    return GARC_OK;
  }
  if (zip->s_descriptor) {
    if (zip->s_stuck != GARC_OK) {
      return zip->s_stuck;
    }
    const GARC_Result result
        = zs_read_descriptor_member(archive, buffer, capacity, out_read);
    if (result != GARC_OK && !zip->s_data_done) {
      zip->s_stuck = result;
    }
    return result;
  }
  return zs_read_sized_member(archive, buffer, capacity, out_read);
}

static GARC_Result zs_read_descriptor_member(
    GARC_Archive * archive, void * buffer, size_t capacity, size_t * out_read) {
  GARC_Zip_State * zip = &archive->zip;
  size_t got = 0;
  GARC_Result result = garc_stream_read(zip->s_decoder, buffer, capacity, &got);
  if (result == GARC_ERR_LIMIT_CODEC_BYTES) {
    return GARC_ERR_LIMIT_MEMBER_BYTES;
  }
  if (result != GARC_OK) {
    return result;
  }
  if (got && archive->member.type == GARC_MEMBER_DIRECTORY) {
    return GARC_ERR_CORRUPT; // a directory whose stream decodes to data
  }
  if (got) {
    zip->running_crc
        = gcomp_crc32_update(zip->running_crc, (const uint8_t *)buffer, got);
    zip->s_produced += (uint64_t)got;
    *out_read = got;
    return GARC_OK;
  }
  // The codec stream ended. What it read past its end goes back, and what
  // is left of the member is its descriptor.
  const uint8_t * kept = NULL;
  size_t kept_length = 0;
  const uint8_t * left = NULL;
  size_t left_length = 0;
  garc_codec_stream_leftover(
      zip->s_decoder, &kept, &kept_length, &left, &left_length);
  // Staged first, because each give-back goes in front of the last.
  result = zs_give_back(archive, left, left_length);
  if (result == GARC_OK) {
    result = zs_give_back(archive, kept, kept_length);
  }
  if (result != GARC_OK) {
    return result;
  }
  zip->compressed_size = zip->position - zip->s_data_start;
  result = zs_read_descriptor(archive);
  zip->s_data_done = 1;
  if (result != GARC_OK) {
    return result;
  }
  archive->member.size = zip->s_produced;
  archive->member.stored_size = zip->s_produced;
  archive->data_remaining = 0;
  // The caps that the declared size would have answered at garc_next().
  archive->total_declared_bytes += zip->s_produced;
  if (archive->limits.max_total_bytes
      && archive->total_declared_bytes > archive->limits.max_total_bytes) {
    return GARC_ERR_LIMIT_TOTAL_BYTES;
  }
  if (gcomp_crc32_finalize(zip->running_crc) != zip->crc32) {
    return GARC_ERR_CORRUPT;
  }
  return GARC_OK;
}

/** A member whose header gave its sizes: a slice, or a codec bounded by them. */
static GARC_Result zs_read_sized_member(
    GARC_Archive * archive, void * buffer, size_t capacity, size_t * out_read) {
  GARC_Zip_State * zip = &archive->zip;
  if (!archive->data_remaining) {
    zip->s_data_done = 1;
    if (zip->crc_active) {
      zip->crc_active = 0;
      if (gcomp_crc32_finalize(zip->running_crc) != zip->crc32) {
        return GARC_ERR_CORRUPT;
      }
    }
    return GARC_OK;
  }
  size_t want = capacity;
  if ((uint64_t)want > archive->data_remaining) {
    want = (size_t)archive->data_remaining;
  }
  GARC_Stream * source
      = zip->codec ? garc_member_codec_stream(zip->codec) : zip->s_slice;
  size_t got = 0;
  GARC_Result result = garc_stream_read(source, buffer, want, &got);
  if (result != GARC_OK) {
    return result;
  }
  if (!got) {
    return GARC_ERR_CORRUPT;
  }
  zip->running_crc
      = gcomp_crc32_update(zip->running_crc, (const uint8_t *)buffer, got);
  archive->data_remaining -= (uint64_t)got;
  *out_read = got;
  return GARC_OK;
}

GARC_Result garc_zip_stream_skip(GARC_Archive * archive) {
  return zs_finish_member(archive);
}

void garc_zip_stream_release(GARC_Archive * archive) {
  GARC_Zip_State * zip = &archive->zip;
  zs_drop_member(archive);
  garc_stream_destroy(zip->seq);
  zip->seq = NULL;
  garc_buffer_free(archive->allocator, &zip->pushback);
  garc_buffer_free(archive->allocator, &zip->records);
  garc_buffer_free(archive->allocator, &zip->s_names);
}
