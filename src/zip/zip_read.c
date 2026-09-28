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

#include <ghoti.io/archive/zip.h>
#include <ghoti.io/compress/crc32.h>
#include <ghoti.io/cutil/allocator.h>
#include <stdint.h>
#include <string.h>

#include "codec/codec_internal.h"
#include "core/buffer_internal.h"
#include "reader/reader_internal.h"
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
/** Bit 11: the name and comment are UTF-8. */
#define ZIP_FLAG_UTF8 0x0800u

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
      if (result != GARC_OK) {
        return result;
      }
      zip->is_zip64 = 1;
      central_end = record_offset;
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
  int have_aes;               ///< Whether a 0x9901 field was present.
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
        // WinZip AES: the version, the vendor tag `AE`, the key strength, and
        // **the method the member would have had** - because method 99 replaced
        // it in the header. Phase H does the decryption; this is here so that the
        // refusal can say AES rather than "unsupported", and so that the real
        // method is not lost.
        if (payload >= 7u) {
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

/**
 * The `compress` method name for a zip method number, or NULL.
 *
 * **The one place a zip method number becomes a codec name**, and the reason the
 * codec layer takes a string: a second enum here would be a copy of compress's
 * list of methods, and the copy goes stale.
 *
 * Only two rows, and both are exact rather than approximate. Method 8 is RFC 1951
 * *raw* - no zlib header and no gzip wrapper - which is `compress`'s `"deflate"`
 * and not its `"zlib"`; reading one as the other fails on the first two bytes.
 * Method 93 is a zstd frame, which `compress` has, so it comes almost free.
 *
 * Method 9 is deliberately absent. "Enhanced deflate" is *not* RFC 1951 - it
 * allows a 64 KB window and a different length code - so pointing it at the
 * deflate decoder would produce plausible wrong bytes for the members that use
 * the extensions, which is worse than refusing it.
 *
 * @param method The method number from the central directory.
 * @return A method name, or NULL when this library has no codec for it.
 */
static const char * zip_codec_name(uint16_t method) {
  switch (method) {
    case GARC_ZIP_METHOD_DEFLATE:
      return "deflate";
    case GARC_ZIP_METHOD_ZSTD:
      return "zstd";
    default:
      return NULL;
  }
}

GARC_Result garc_zip_read(
    GARC_Archive * archive, void * buffer, size_t capacity, size_t * out_read) {
  GARC_Zip_State * zip = &archive->zip;

  if (!archive->data_remaining) {
    *out_read = 0;
    if (zip->crc_active) {
      // **The verdict, on the call that says the member is over.** Cleared first,
      // so a caller that keeps calling gets the answer once rather than on every
      // call, and so that a second read after a refusal does not re-refuse.
      zip->crc_active = 0;
      if (gcomp_crc32_finalize(zip->running_crc) != zip->crc32) {
        return GARC_ERR_CORRUPT;
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

  GARC_Stream * source = zip->codec
      ? garc_member_codec_stream(zip->codec) : archive->stream;
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
  garc_member_codec_destroy(archive->zip.codec);
  archive->zip.codec = NULL;
  archive->zip.crc_active = 0;
  archive->data_remaining = 0;
  return GARC_OK;
}

GARC_Result garc_zip_next(GARC_Archive * archive) {
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
  zip->external_attributes = garc_zip_le32(entry + 38u);
  uint64_t local_offset = garc_zip_le32(entry + 42u);

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

  Zip_Extra extra = {0, 0u, GARC_TIME_NONE, 0, 0, 0, 0u, 0};
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
  member->name = zip->name.length ? zip->name.bytes : NULL;
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
  const char * codec_name = zip_codec_name(zip->method);

  if (zip->encryption != GARC_ZIP_ENCRYPTION_NONE) {
    // The metadata is in the clear and the data is not. Phase H decrypts AES and
    // the ZipCrypto reader arrives before it; until then the refusal names the
    // scheme rather than the absence of a feature.
    archive->data_refusal = GARC_ERR_UNSUPPORTED;
  }
  else if (zip->method == GARC_ZIP_METHOD_STORED) {
    if (compressed_size != size) {
      // Stored means the two sizes are one number. A member that says otherwise
      // describes something the method cannot do, and both numbers are things a
      // reader seeks by.
      return GARC_ERR_CORRUPT;
    }
    result = garc_stream_seek(archive->stream, data_offset);
    if (result != GARC_OK) {
      return result;
    }
    zip->crc_active = 1;
  }
  else if (codec_name) {
    // Seek first: the decoder reads from wherever the stream is, and it reads
    // lazily, so this is the only moment the position is known to be right.
    result = garc_stream_seek(archive->stream, data_offset);
    if (result != GARC_OK) {
      return result;
    }
    result = garc_member_codec_create(archive->allocator, archive->stream,
        codec_name, compressed_size, size, &zip->codec);
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
  else {
    // A method with no codec here. The refusal names the number through
    // garc_zip_member_method(), which is what makes it a to-do list.
    archive->data_refusal = GARC_ERR_UNSUPPORTED;
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
  archive->zip.crc_active = 0;
  archive->zip.cursor = archive->zip.central_offset;
  archive->zip.entries_seen = 0;
}

void garc_zip_release(GARC_Archive * archive) {
  GARC_Zip_State * zip = &archive->zip;
  garc_member_codec_destroy(zip->codec);
  zip->codec = NULL;
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
