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
 * GNU sparse files: reading the map, checking it, and handing out the file.
 *
 * The GNU tar manual's "Sparse Formats" appendix defines four ways to write one,
 * and GNU tar 1.35 writes all four:
 *
 * - **Old GNU**, typeflag `S`: four map entries in the header at offset 386, a
 *   flag at 482 saying an extension block follows, and the real size at 483.
 *   Each extension block holds 21 more entries and the same flag at 504.
 * - **pax 0.0**: `GNU.sparse.size`, `GNU.sparse.numblocks`, then one
 *   `GNU.sparse.offset` and one `GNU.sparse.numbytes` record per region.
 * - **pax 0.1**: the same size and count, and the whole map as
 *   `GNU.sparse.map=offset,length,offset,length...`. The real name is in
 *   `GNU.sparse.name`.
 * - **pax 1.0**: `GNU.sparse.major=1`, `minor=0`, `name` and `realsize`, and
 *   the map at the front of the member's data, as decimal lines - the count,
 *   then an offset and a length per region - padded to a whole block.
 *
 * Every form ends the same way: a list of regions, a real size, and stored data
 * that is the regions back to back. GNU writes a last region of length zero at
 * the real size, which is how a file that ends in a hole says so; a file that is
 * all hole is that region alone.
 *
 * **The map is checked before a byte is handed out.** Regions in order and not
 * overlapping, each inside the real size, and adding up to exactly the stored
 * bytes. A map that claims more than is stored would make the read run into the
 * next header; one that claims less would leave stored bytes unread and shift
 * the next member. Both are GARC_ERR_CORRUPT here rather than a wrong file later.
 */

#include <ghoti.io/archive/macros.h>

#include <stdint.h>
#include <string.h>

#include "core/buffer_internal.h"
#include "tar/tar_internal.h"

#define TAR_SPARSE_OFF_MAP 386u        ///< The old GNU header's first map entry.
#define TAR_SPARSE_HEADER_ENTRIES 4u   ///< Map entries in the header itself.
#define TAR_SPARSE_OFF_EXTENDED 482u   ///< The header's "an extension follows" flag.
#define TAR_SPARSE_OFF_REALSIZE 483u   ///< The header's real size, octal.
#define TAR_SPARSE_LEN_FIELD 12u       ///< Each offset and each length, octal.
#define TAR_SPARSE_EXT_ENTRIES 21u     ///< Map entries in one extension block.
#define TAR_SPARSE_EXT_OFF_EXTENDED 504u ///< An extension block's own flag.
/** What one region costs to hold, which is what max_extra_bytes is charged. */
#define TAR_SPARSE_PAIR_BYTES 16u
/** The most digits a decimal uint64_t has. */
#define TAR_SPARSE_MAX_DIGITS 20u

/** A strict decimal: digits only, at least one, no overflow. */
static GARC_Result sparse_decimal(
    const char * text, size_t length, uint64_t * out_value) {
  if (!length || length > TAR_SPARSE_MAX_DIGITS) {
    return GARC_ERR_CORRUPT;
  }
  uint64_t value = 0;
  for (size_t i = 0; i < length; ++i) {
    if (text[i] < '0' || text[i] > '9') {
      return GARC_ERR_CORRUPT;
    }
    const uint64_t digit = (uint64_t)(text[i] - '0');
    if (value > (UINT64_MAX - digit) / 10u) {
      return GARC_ERR_CORRUPT;
    }
    value = value * 10u + digit;
  }
  *out_value = value;
  return GARC_OK;
}

/** Append one uint64_t to a pair buffer, charging the cap per pair. */
static GARC_Result sparse_append(GARC_Archive * archive, GARC_Buffer * buffer,
    uint64_t value) {
  const size_t wanted = buffer->length + sizeof(uint64_t);
  const uint64_t cap = archive->limits.max_extra_bytes;
  if (cap && (uint64_t)wanted > cap) {
    return GARC_ERR_LIMIT_EXTRA_BYTES;
  }
  if (wanted + 1u > buffer->capacity) {
    // Doubling, so a map of n regions costs O(n) copies rather than O(n^2).
    size_t grown = buffer->capacity ? buffer->capacity * 2u : 256u;
    if (grown < wanted) {
      grown = wanted;
    }
    GARC_Result result = garc_buffer_grow(archive->allocator, buffer, grown);
    if (result != GARC_OK) {
      return result;
    }
  }
  memcpy(buffer->bytes + buffer->length, &value, sizeof(value));
  buffer->length = wanted;
  return GARC_OK;
}

static uint64_t sparse_at(const GARC_Buffer * buffer, size_t index) {
  uint64_t value = 0;
  memcpy(&value, buffer->bytes + index * sizeof(uint64_t), sizeof(value));
  return value;
}

GARC_Result garc_tar_sparse_pax_pair(GARC_Archive * archive, GARC_Tar_Pax * pax,
    const char * value, size_t length, int is_numbytes) {
  uint64_t number = 0;
  GARC_Result result = sparse_decimal(value, length, &number);
  if (result != GARC_OK) {
    return result;
  }
  if (!is_numbytes == !!pax->sparse_offset_pending) {
    // Two offsets in a row, or a length with no offset in front of it. Pairing
    // them up some other way would be guessing at which region is which.
    return GARC_ERR_CORRUPT;
  }
  result = sparse_append(archive, &pax->sparse_pairs, number);
  if (result != GARC_OK) {
    return result;
  }
  if (is_numbytes) {
    pax->sparse_pair_count++;
  }
  pax->sparse_offset_pending = !is_numbytes;
  return GARC_OK;
}

/** Add a region to the member's map. */
static GARC_Result sparse_push(
    GARC_Archive * archive, uint64_t offset, uint64_t length) {
  GARC_Result result = sparse_append(archive, &archive->tar.sparse_map, offset);
  if (result == GARC_OK) {
    result = sparse_append(archive, &archive->tar.sparse_map, length);
  }
  if (result == GARC_OK) {
    archive->tar.sparse_count++;
  }
  return result;
}

/** One old-GNU map entry; *out_empty when both fields are empty, which ends it. */
static GARC_Result sparse_old_entry(GARC_Archive * archive,
    const uint8_t * entry, int * out_empty) {
  // An entry whose first byte is NUL is unused; GNU fills the rest with NULs.
  if (entry[0] == 0u) {
    *out_empty = 1;
    return GARC_OK;
  }
  *out_empty = 0;
  uint64_t offset = 0;
  uint64_t length = 0;
  GARC_Result result
      = garc_tar_parse_uint(entry, TAR_SPARSE_LEN_FIELD, &offset);
  if (result == GARC_OK) {
    result = garc_tar_parse_uint(
        entry + TAR_SPARSE_LEN_FIELD, TAR_SPARSE_LEN_FIELD, &length);
  }
  if (result != GARC_OK) {
    return result;
  }
  return sparse_push(archive, offset, length);
}

/** The old GNU form: the header's entries and the extension blocks behind it. */
static GARC_Result sparse_old_gnu(
    GARC_Archive * archive, const uint8_t * block, uint64_t * out_real) {
  GARC_Result result = garc_tar_parse_uint(block + TAR_SPARSE_OFF_REALSIZE,
      TAR_SPARSE_LEN_FIELD, out_real);
  if (result != GARC_OK) {
    return result;
  }
  int ended = 0;
  for (size_t i = 0; i < TAR_SPARSE_HEADER_ENTRIES && !ended; ++i) {
    result = sparse_old_entry(archive,
        block + TAR_SPARSE_OFF_MAP + i * 2u * TAR_SPARSE_LEN_FIELD, &ended);
    if (result != GARC_OK) {
      return result;
    }
  }
  int extended = block[TAR_SPARSE_OFF_EXTENDED] != 0u;
  uint8_t ext[GARC_TAR_BLOCK];
  while (extended) {
    // The extension blocks are not counted in the size field: they sit between
    // the header and the data, and the data offset is behind them.
    size_t got = 0;
    result = garc_tar_read(archive, ext, sizeof(ext), &got);
    if (result != GARC_OK) {
      return result;
    }
    if (got < sizeof(ext)) {
      return GARC_ERR_CORRUPT;
    }
    // Entries after the first empty one are not read, as GNU does not.
    for (size_t i = 0; i < TAR_SPARSE_EXT_ENTRIES && !ended; ++i) {
      result = sparse_old_entry(
          archive, ext + i * 2u * TAR_SPARSE_LEN_FIELD, &ended);
      if (result != GARC_OK) {
        return result;
      }
    }
    extended = ext[TAR_SPARSE_EXT_OFF_EXTENDED] != 0u;
  }
  return GARC_OK;
}

/** pax 0.1's `offset,length,offset,length...`. */
static GARC_Result sparse_pax_map(
    GARC_Archive * archive, const char * text, size_t length) {
  size_t start = 0;
  uint64_t pending = 0;
  int have_offset = 0;
  for (size_t i = 0; i <= length; ++i) {
    if (i < length && text[i] != ',') {
      continue;
    }
    uint64_t number = 0;
    GARC_Result result = sparse_decimal(text + start, i - start, &number);
    if (result != GARC_OK) {
      return result;
    }
    if (have_offset) {
      result = sparse_push(archive, pending, number);
      if (result != GARC_OK) {
        return result;
      }
    }
    else {
      pending = number;
    }
    have_offset = !have_offset;
    start = i + 1u;
  }
  // An odd count is an offset with no length.
  return have_offset ? GARC_ERR_CORRUPT : GARC_OK;
}

/**
 * pax 1.0's map, which is the front of the data: decimal lines, the count first,
 * padded to a whole block.
 */
static GARC_Result sparse_pax_one_zero(GARC_Archive * archive) {
  uint8_t block[GARC_TAR_BLOCK];
  size_t at = sizeof(block);
  uint64_t numbers_wanted = 0; // set once the count has been read
  uint64_t numbers_read = 0;
  int have_count = 0;
  uint64_t value = 0;
  size_t digits = 0;
  uint64_t pending = 0;
  for (;;) {
    if (at == sizeof(block)) {
      if (archive->data_remaining < sizeof(block)) {
        // The map claims to go on past the member's data.
        return GARC_ERR_CORRUPT;
      }
      size_t got = 0;
      GARC_Result result = garc_tar_read(archive, block, sizeof(block), &got);
      if (result != GARC_OK) {
        return result;
      }
      if (got < sizeof(block)) {
        return GARC_ERR_CORRUPT;
      }
      archive->data_remaining -= sizeof(block);
      at = 0;
    }
    const uint8_t byte = block[at++];
    if (byte >= '0' && byte <= '9') {
      if (++digits > TAR_SPARSE_MAX_DIGITS
          || value > (UINT64_MAX - (uint64_t)(byte - '0')) / 10u) {
        return GARC_ERR_CORRUPT;
      }
      value = value * 10u + (uint64_t)(byte - '0');
      continue;
    }
    if (byte != '\n' || !digits) {
      return GARC_ERR_CORRUPT;
    }
    if (!have_count) {
      // Checked against the cap before anything is held for it.
      const uint64_t cap = archive->limits.max_extra_bytes;
      if (value > UINT64_MAX / (2u * sizeof(uint64_t))
          || (cap && value * 2u * sizeof(uint64_t) > cap)) {
        return GARC_ERR_LIMIT_EXTRA_BYTES;
      }
      numbers_wanted = value * 2u;
      have_count = 1;
    }
    else if (numbers_read % 2u == 0u) {
      pending = value;
      numbers_read++;
    }
    else {
      GARC_Result result = sparse_push(archive, pending, value);
      if (result != GARC_OK) {
        return result;
      }
      numbers_read++;
    }
    value = 0;
    digits = 0;
    if (have_count && numbers_read == numbers_wanted) {
      // The rest of this block is padding, and the data starts at the next.
      return GARC_OK;
    }
  }
}

/** Read a numeric record of the `x` set; *out_have says whether it was there. */
static GARC_Result sparse_record(const GARC_Archive * archive, GARC_Pax_Key key,
    uint64_t * out_value, int * out_have) {
  const GARC_Tar_Pax * pax = &archive->tar.pax_next;
  *out_have = pax->have[key];
  if (!*out_have) {
    return GARC_OK;
  }
  return sparse_decimal(pax->records.bytes + pax->offset[key], pax->length[key],
      out_value);
}

/** Check the map against the real size and the stored bytes. */
static GARC_Result sparse_check(
    const GARC_Archive * archive, uint64_t real, uint64_t stored) {
  uint64_t end = 0;
  uint64_t total = 0;
  for (size_t i = 0; i < archive->tar.sparse_count; ++i) {
    const uint64_t offset = sparse_at(&archive->tar.sparse_map, 2u * i);
    const uint64_t length = sparse_at(&archive->tar.sparse_map, 2u * i + 1u);
    if (offset < end || offset > real || length > real - offset) {
      return GARC_ERR_CORRUPT;
    }
    end = offset + length;
    total += length; // cannot overflow: each region is inside real, in order
  }
  return total == stored ? GARC_OK : GARC_ERR_CORRUPT;
}

GARC_Result garc_tar_sparse_begin(
    GARC_Archive * archive, const uint8_t * block, int old_gnu) {
  GARC_Tar_State * tar = &archive->tar;
  tar->sparse = 0;
  tar->sparse_map.length = 0;
  tar->sparse_count = 0;
  tar->sparse_pos = 0;
  tar->sparse_index = 0;

  const GARC_Tar_Pax * pax = &tar->pax_next;
  const int pax_sparse = pax->have[GARC_PAX_SPARSE_SIZE]
      || pax->have[GARC_PAX_SPARSE_NUMBLOCKS] || pax->have[GARC_PAX_SPARSE_MAP]
      || pax->have[GARC_PAX_SPARSE_MAJOR] || pax->have[GARC_PAX_SPARSE_MINOR]
      || pax->have[GARC_PAX_SPARSE_REALSIZE] || pax->sparse_pair_count
      || pax->sparse_offset_pending;
  if (!old_gnu && !pax_sparse) {
    // GNU.sparse.name alone says nothing about the data; the name was applied.
    return GARC_OK;
  }
  if (old_gnu && pax_sparse) {
    // Two maps for one member. No writer produces it, and neither is the
    // obvious one to believe.
    return GARC_ERR_CORRUPT;
  }

  uint64_t real = 0;
  GARC_Result result = GARC_OK;
  if (old_gnu) {
    result = sparse_old_gnu(archive, block, &real);
  }
  else {
    int have_major = 0;
    int have_minor = 0;
    int have_size = 0;
    int have_realsize = 0;
    int have_count = 0;
    uint64_t major = 0;
    uint64_t minor = 0;
    uint64_t size = 0;
    uint64_t realsize = 0;
    uint64_t count = 0;
    if ((result = sparse_record(archive, GARC_PAX_SPARSE_MAJOR, &major, &have_major))
            != GARC_OK
        || (result = sparse_record(archive, GARC_PAX_SPARSE_MINOR, &minor, &have_minor))
            != GARC_OK
        || (result = sparse_record(archive, GARC_PAX_SPARSE_SIZE, &size, &have_size))
            != GARC_OK
        || (result = sparse_record(
                archive, GARC_PAX_SPARSE_REALSIZE, &realsize, &have_realsize))
            != GARC_OK
        || (result = sparse_record(
                archive, GARC_PAX_SPARSE_NUMBLOCKS, &count, &have_count))
            != GARC_OK) {
      return result;
    }
    if (pax->sparse_offset_pending) {
      return GARC_ERR_CORRUPT; // an offset whose length never came
    }
    if (have_major || have_minor || have_realsize) {
      // 1.0, the only version past 0.1 there is. Another is refused by name:
      // it would say something about the data this reader cannot know.
      if (!have_major || !have_minor || major != 1u || minor != 0u) {
        return GARC_ERR_UNSUPPORTED;
      }
      if (pax->have[GARC_PAX_SPARSE_MAP] || pax->sparse_pair_count) {
        return GARC_ERR_CORRUPT; // the map is in the data in 1.0
      }
      if (!have_realsize && !have_size) {
        return GARC_ERR_CORRUPT;
      }
      real = have_realsize ? realsize : size;
      result = sparse_pax_one_zero(archive);
    }
    else {
      if (!have_size) {
        return GARC_ERR_CORRUPT; // 0.x says the real size here or nowhere
      }
      real = size;
      if (pax->have[GARC_PAX_SPARSE_MAP]) {
        if (pax->sparse_pair_count) {
          return GARC_ERR_CORRUPT; // 0.1's map and 0.0's pairs at once
        }
        result = sparse_pax_map(archive,
            pax->records.bytes + pax->offset[GARC_PAX_SPARSE_MAP],
            pax->length[GARC_PAX_SPARSE_MAP]);
      }
      else {
        for (size_t i = 0; i < pax->sparse_pair_count && result == GARC_OK; ++i) {
          result = sparse_push(archive, sparse_at(&pax->sparse_pairs, 2u * i),
              sparse_at(&pax->sparse_pairs, 2u * i + 1u));
        }
      }
      if (result == GARC_OK && have_count && count != tar->sparse_count) {
        result = GARC_ERR_CORRUPT;
      }
    }
  }
  if (result != GARC_OK) {
    return result;
  }
  result = sparse_check(archive, real, archive->data_remaining);
  if (result != GARC_OK) {
    return result;
  }

  tar->sparse = 1;
  archive->member.type = GARC_MEMBER_FILE;
  archive->member.sparse = 1;
  archive->member.stored_size = archive->data_remaining;
  archive->member.size = real;
  return GARC_OK;
}

GARC_Result garc_tar_sparse_read(GARC_Archive * archive, void * buffer,
    size_t capacity, size_t * out_read) {
  GARC_Tar_State * tar = &archive->tar;
  const uint64_t real = archive->member.size;
  *out_read = 0;
  if (!capacity || tar->sparse_pos >= real) {
    return GARC_OK;
  }
  // Past every region already wholly handed out.
  while (tar->sparse_index < tar->sparse_count) {
    const uint64_t offset = sparse_at(&tar->sparse_map, 2u * tar->sparse_index);
    const uint64_t length
        = sparse_at(&tar->sparse_map, 2u * tar->sparse_index + 1u);
    if (tar->sparse_pos < offset + length) {
      break;
    }
    tar->sparse_index++;
  }
  uint64_t hole_end = real;
  if (tar->sparse_index < tar->sparse_count) {
    const uint64_t offset = sparse_at(&tar->sparse_map, 2u * tar->sparse_index);
    const uint64_t length
        = sparse_at(&tar->sparse_map, 2u * tar->sparse_index + 1u);
    if (tar->sparse_pos >= offset) {
      // Inside a region: its stored bytes.
      uint64_t want = offset + length - tar->sparse_pos;
      if (want > (uint64_t)capacity) {
        want = (uint64_t)capacity;
      }
      size_t got = 0;
      GARC_Result result
          = garc_tar_read(archive, (uint8_t *)buffer, (size_t)want, &got);
      if (result != GARC_OK) {
        return result;
      }
      if (!got) {
        return GARC_ERR_CORRUPT;
      }
      archive->data_remaining -= (uint64_t)got;
      tar->sparse_pos += (uint64_t)got;
      *out_read = got;
      return GARC_OK;
    }
    hole_end = offset;
  }
  // In a hole: zeros, up to the next region or the real end.
  uint64_t want = hole_end - tar->sparse_pos;
  if (want > (uint64_t)capacity) {
    want = (uint64_t)capacity;
  }
  memset(buffer, 0, (size_t)want);
  tar->sparse_pos += want;
  *out_read = (size_t)want;
  return GARC_OK;
}
