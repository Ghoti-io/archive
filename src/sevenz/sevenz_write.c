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
 * The 7z writer.
 *
 * **A 7z is written front to back with its header last**, which is the opposite
 * of what a streaming writer wants and the same shape as zip's directory: the
 * packed streams go out as members arrive, every size and CRC is remembered, and
 * the header that describes them is written at the end. The signature header at
 * the front says where that header is, which is not known until it has been
 * written, so 32 zero bytes are written first and **patched** at the end. That
 * is why this writer needs a sink that can patch and refuses one that cannot
 * (::GARC_ERR_NOT_SEEKABLE): a pipe cannot be given its start header after the
 * fact, and buffering the whole archive to get round that would hide a cost the
 * caller should choose.
 *
 * **One encoder, reset per folder.** A solid archive is one folder, so one
 * encoder for the archive; a non-solid one resets it between files. The
 * encoder's properties are fixed at creation (the dictionary is stated, not
 * defaulted) so that the property bytes the header carries are the ones the
 * encoder used.
 *
 * **The header is written plain.** 7-Zip encodes it with LZMA, which saves a few
 * hundred bytes on a large archive. Every reader accepts a plain one, and not
 * encoding it keeps the writer from needing a second encoder pass at the end.
 *
 * **What is refused.** Hard links, devices, fifos and `GARC_MEMBER_OTHER` are
 * `GARC_ERR_UNSUPPORTED`: 7z has no convention for them that a reference reads.
 * A name that is not well-formed UTF-8 is `GARC_ERR_INVALID`, because the format
 * stores UTF-16 and there is no UTF-16 for bytes that are not text.
 */

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/allocator.h>
#include <ghoti.io/archive/writer.h>
#include <ghoti.io/compress/crc32.h>
#include <ghoti.io/compress/options.h>
#include <ghoti.io/compress/registry.h>
#include <ghoti.io/compress/stream.h>
#include <ghoti.io/cutil/allocator.h>
#include <stdint.h>
#include <string.h>

#include "../codec/codec_internal.h"
#include "../core/buffer_internal.h"
#include "sevenz_internal.h"
#include "writer/writer_internal.h"

/** Bytes handed to the encoder's output buffer at a time. */
#define SZW_BUFFER 16384u

/** The dictionary every LZMA-family folder is written with: 8 MiB. */
#define SZW_DICT_SIZE (8u * 1024u * 1024u)

/** LZMA2's property byte for 8 MiB: `(2 | (b & 1)) << (b / 2 + 11)`. */
#define SZW_LZMA2_PROP 22u

/** The most a header may occupy, matching what the reader accepts. */
#define SZW_MAX_HEADER (64u * 1024u * 1024u)

/** Seconds from 1601-01-01, where FILETIME begins, to the Unix epoch. */
#define SZW_EPOCH_GAP 11644473600LL

/** What an entry is, as the header's property tables record it. */
enum {
  SZWF_DIRECTORY = 1,  ///< A directory: no stream, and no empty-file bit.
  SZWF_EMPTY_FILE = 2, ///< An empty file: no stream, with the empty-file bit.
  SZWF_HAS_MTIME = 4   ///< The entry has a modification time.
};

/** One member as the header will list it. */
typedef struct {
  uint32_t name_off; ///< Where the name starts in the names buffer.
  uint32_t name_len; ///< UTF-8 bytes in the names buffer.
  uint8_t flags;     ///< ::SZWF_DIRECTORY, ::SZWF_EMPTY_FILE and ::SZWF_HAS_MTIME.
  uint64_t mtime;    ///< FILETIME ticks; meaningful with ::SZWF_HAS_MTIME.
  uint32_t attrib;   ///< The attribute word, Unix mode in the high half.
  uint64_t size;     ///< Unpacked size in bytes.
  uint32_t crc;      ///< CRC-32 of the unpacked bytes.
  int has_stream;    ///< Whether the entry has bytes in a folder.
} SzwEntry;

/** One folder as the header will list it: a packed stream and what it holds. */
typedef struct {
  uint64_t pack_size;   ///< Bytes written to the archive for this folder.
  uint64_t unpack_size; ///< Bytes the folder decodes to.
  uint32_t nsub;        ///< How many members share the folder.
} SzwFolder;

/** Everything the 7z writer remembers until the header is written. */
struct GARC_SevenZ_Write {
  uint64_t origin; ///< Sink offset of the signature header.
  SzwEntry * entries; ///< One per member, in the order added.
  uint32_t num_entries; ///< How many entries are in use.
  uint32_t cap_entries; ///< How many @ref entries has room for.
  SzwFolder * folders; ///< One per finished folder.
  uint32_t num_folders; ///< How many folders are in use.
  uint32_t cap_folders; ///< How many @ref folders has room for.
  GARC_Buffer names; ///< Every name, as UTF-8, end to end.
  /* the folder being written */
  int folder_open; ///< Whether a folder's encoder has been started.
  uint64_t cur_pack; ///< Packed bytes written to the open folder.
  uint64_t cur_unpack; ///< Unpacked bytes given to the open folder.
  uint32_t cur_nsub; ///< Members in the open folder.
  gcomp_encoder_t * encoder; ///< The folder encoder, reset between folders.
  gcomp_options_t * encoder_options; ///< Its options, or NULL.
  uint8_t * packed; ///< Output buffer for the encoder.
  /* the member being written */
  uint32_t running_crc; ///< The unfinalized CRC-32 so far.
  uint32_t current; ///< Index in entries.
  int in_member; ///< Whether a member is open.
  /**
   * The header tables of the archive being appended to, which the new header
   * lists first; NULL for a new archive. Owned.
   */
  GARC_SevenZ_Carry * carry;
  /**
   * With @ref carry, the start header ::garc_sevenz_write_end() made, for the
   * update to write over the old one: it is before where the sink starts.
   */
  uint8_t start[GARC_SEVENZ_START_SIZE];
  int start_ready; ///< Whether @ref start is made.
};

static GARC_Result szw_grow(const GARC_Allocator * a, void * slot,
    uint32_t * count, uint32_t * cap, size_t size) {
  if (*count < *cap) {
    return GARC_OK;
  }
  void * array = NULL;
  memcpy(&array, slot, sizeof(array));
  const uint32_t wanted = *cap ? *cap * 2u : 16u;
  if (wanted < *cap) {
    return GARC_ERR_OOM;
  }
  void * grown = gcu_allocator_realloc(a, array, (size_t)wanted * size);
  if (!grown) {
    return GARC_ERR_OOM;
  }
  memcpy(slot, &grown, sizeof(grown));
  *cap = wanted;
  return GARC_OK;
}

static const char * szw_encoder_name(GARC_SevenZ_Method method) {
  switch (method) {
    case GARC_SEVENZ_LZMA2:
      return "lzma2";
    case GARC_SEVENZ_LZMA:
      return "lzma";
    case GARC_SEVENZ_BZIP2:
      return "bzip2";
    case GARC_SEVENZ_DEFLATE64:
      return "deflate64";
    default:
      return "deflate";
  }
}

GARC_Result garc_sevenz_write_begin_append(
    GARC_Writer * writer, GARC_SevenZ_Carry * carry) {
  const GARC_Allocator * a = writer->allocator;
  struct GARC_SevenZ_Write * z = (struct GARC_SevenZ_Write *)gcu_allocator_calloc(
      a, 1, sizeof(*z));
  if (!z) {
    garc_sevenz_carry_free(carry, a);
    return GARC_ERR_OOM;
  }
  writer->sevenz = z;
  z->carry = carry;
  // The archive's own frame: its start header is at 0, and the sink starts
  // where its packed streams end, so the new ones follow them.
  z->origin = 0;
  if (garc_sink_tell(writer->sink) != GARC_SEVENZ_START_SIZE + carry->data_end) {
    return GARC_ERR_INTERNAL;
  }
  return GARC_OK;
}

GARC_Result garc_sevenz_write_begin(GARC_Writer * writer) {
  const GARC_Allocator * a = writer->allocator;
  struct GARC_SevenZ_Write * z = (struct GARC_SevenZ_Write *)gcu_allocator_calloc(
      a, 1, sizeof(*z));
  if (!z) {
    return GARC_ERR_OOM;
  }
  writer->sevenz = z;
  z->origin = garc_sink_tell(writer->sink);
  /* Reserved now, patched when the header's position is known. A patch cannot
     extend the archive, so these bytes have to exist. */
  uint8_t zeros[GARC_SEVENZ_START_SIZE];
  memset(zeros, 0, sizeof(zeros));
  return garc_sink_write(writer->sink, zeros, sizeof(zeros));
}

/** Pass compressed bytes to the sink, counting them into the open folder. */
static GARC_Result szw_emit(GARC_Writer * writer, const void * bytes, size_t n) {
  struct GARC_SevenZ_Write * z = writer->sevenz;
  if (!n) {
    return GARC_OK;
  }
  GARC_Result result = garc_sink_write(writer->sink, bytes, n);
  if (result != GARC_OK) {
    return result;
  }
  z->cur_pack += n;
  return GARC_OK;
}

static GARC_Result szw_open_folder(GARC_Writer * writer) {
  struct GARC_SevenZ_Write * z = writer->sevenz;
  z->cur_pack = 0;
  z->cur_unpack = 0;
  z->cur_nsub = 0;
  if (writer->options.sevenz_method == GARC_SEVENZ_COPY) {
    z->folder_open = 1;
    return GARC_OK;
  }
  if (z->encoder) {
    GARC_Result result = garc_codec_result(gcomp_encoder_reset(z->encoder));
    if (result == GARC_OK) {
      z->folder_open = 1;
    }
    return result;
  }
  const GARC_SevenZ_Method method = writer->options.sevenz_method;
  gcomp_options_t * options = NULL;
  if (method == GARC_SEVENZ_LZMA || method == GARC_SEVENZ_LZMA2) {
    if (gcomp_options_create(&options) != GCOMP_OK) {
      return GARC_ERR_OOM;
    }
    const char * key = method == GARC_SEVENZ_LZMA ? "lzma.dict_size"
                                                   : "lzma2.dict_size";
    if ((method == GARC_SEVENZ_LZMA
            && gcomp_options_set_bool(options, "lzma.raw", 1) != GCOMP_OK)
        || gcomp_options_set_uint64(options, key, SZW_DICT_SIZE) != GCOMP_OK) {
      gcomp_options_destroy(options);
      return GARC_ERR_OOM;
    }
  }
  gcomp_status_t status = gcomp_encoder_create(gcomp_registry_default(),
      szw_encoder_name(method), options, &z->encoder);
  if (status != GCOMP_OK) {
    gcomp_options_destroy(options);
    return garc_codec_result(status);
  }
  z->encoder_options = options;
  z->packed = (uint8_t *)gcu_allocator_malloc(writer->allocator, SZW_BUFFER);
  if (!z->packed) {
    gcomp_encoder_destroy(z->encoder);
    z->encoder = NULL;
    gcomp_options_destroy(z->encoder_options);
    z->encoder_options = NULL;
    return GARC_ERR_OOM;
  }
  z->folder_open = 1;
  return GARC_OK;
}

static GARC_Result szw_close_folder(GARC_Writer * writer) {
  struct GARC_SevenZ_Write * z = writer->sevenz;
  if (!z->folder_open) {
    return GARC_OK;
  }
  if (z->encoder) {
    for (;;) {
      gcomp_buffer_t out = {z->packed, SZW_BUFFER, 0};
      const gcomp_status_t status = gcomp_encoder_finish(z->encoder, &out);
      GARC_Result result = szw_emit(writer, z->packed, out.used);
      if (result != GARC_OK) {
        return result;
      }
      if (status == GCOMP_OK) {
        break;
      }
      if (status != GCOMP_ERR_LIMIT) {
        return garc_codec_result(status);
      }
      if (!out.used) {
        return GARC_ERR_INTERNAL;
      }
    }
  }
  SzwFolder folder;
  folder.pack_size = z->cur_pack;
  folder.unpack_size = z->cur_unpack;
  folder.nsub = z->cur_nsub;
  GARC_Result result = szw_grow(writer->allocator, &z->folders, &z->num_folders,
      &z->cap_folders, sizeof(SzwFolder));
  if (result != GARC_OK) {
    return result;
  }
  z->folders[z->num_folders++] = folder;
  z->folder_open = 0;
  return GARC_OK;
}

size_t garc_sevenz_utf8_decode(const uint8_t * p, size_t left, uint32_t * cp) {
  if (!left) {
    return 0;
  }
  if (p[0] < 0x80u) {
    *cp = p[0];
    return 1u;
  }
  size_t n = 0;
  uint32_t v = 0;
  uint32_t min = 0;
  if ((p[0] & 0xE0u) == 0xC0u) {
    n = 2u; v = p[0] & 0x1Fu; min = 0x80u;
  }
  else if ((p[0] & 0xF0u) == 0xE0u) {
    n = 3u; v = p[0] & 0x0Fu; min = 0x800u;
  }
  else if ((p[0] & 0xF8u) == 0xF0u) {
    n = 4u; v = p[0] & 0x07u; min = 0x10000u;
  }
  else {
    return 0;
  }
  if (left < n) {
    return 0;
  }
  for (size_t i = 1; i < n; ++i) {
    if ((p[i] & 0xC0u) != 0x80u) {
      return 0;
    }
    v = (v << 6) | (p[i] & 0x3Fu);
  }
  if (v < min || v > 0x10FFFFu || (v >= 0xD800u && v < 0xE000u)) {
    return 0;
  }
  *cp = v;
  return n;
}

GARC_Result garc_sevenz_write_member(
    GARC_Writer * writer, const GARC_Member * member) {
  struct GARC_SevenZ_Write * z = writer->sevenz;
  if (!member->name || !member->name_length || memchr(member->name, '\0',
          member->name_length)) {
    return GARC_ERR_INVALID;
  }
  /* Every byte must be text before anything is written. */
  for (size_t at = 0; at < member->name_length;) {
    uint32_t cp = 0;
    const size_t n = garc_sevenz_utf8_decode((const uint8_t *)member->name + at,
        member->name_length - at, &cp);
    if (!n) {
      return GARC_ERR_INVALID;
    }
    at += n;
  }

  const char * data = NULL;
  uint64_t size = member->size;
  uint32_t type_bits = 0100000u;
  uint32_t flags = 0;
  switch (member->type) {
    case GARC_MEMBER_FILE:
      break;
    case GARC_MEMBER_DIRECTORY:
      if (member->size) {
        return GARC_ERR_INVALID;
      }
      type_bits = 040000u;
      flags |= SZWF_DIRECTORY;
      break;
    case GARC_MEMBER_SYMLINK:
      if (!member->link_target || !member->link_target_length
          || memchr(member->link_target, '\0', member->link_target_length)
          || member->size) {
        return GARC_ERR_INVALID;
      }
      data = member->link_target;
      size = member->link_target_length;
      type_bits = 0120000u;
      break;
    default:
      return GARC_ERR_UNSUPPORTED;
  }

  uint64_t mtime = 0;
  if (member->mtime_source != GARC_TIME_NONE || member->mtime_seconds) {
    const int64_t seconds = member->mtime_seconds;
    if (seconds < -SZW_EPOCH_GAP
        || seconds > (int64_t)(UINT64_MAX / 10000000u) - SZW_EPOCH_GAP - 1) {
      return GARC_ERR_INVALID;
    }
    mtime = ((uint64_t)(seconds + SZW_EPOCH_GAP)) * 10000000u
        + member->mtime_nanoseconds / 100u;
    flags |= SZWF_HAS_MTIME;
  }

  uint32_t attrib = (flags & SZWF_DIRECTORY) ? 0x10u : 0x20u;
  if (member->mode_valid || member->type == GARC_MEMBER_SYMLINK) {
    const uint32_t perm = member->mode_valid ? (member->mode & 07777u)
                                              : 0777u;
    attrib |= 0x8000u | ((type_bits | perm) << 16);
  }

  GARC_Result result = szw_grow(writer->allocator, &z->entries, &z->num_entries,
      &z->cap_entries, sizeof(SzwEntry));
  if (result != GARC_OK) {
    return result;
  }
  const size_t names_at = z->names.length;
  result = garc_buffer_grow(
      writer->allocator, &z->names, names_at + member->name_length);
  if (result != GARC_OK) {
    return result;
  }
  const int has_stream = size > 0 && !(flags & SZWF_DIRECTORY);
  if (has_stream) {
    if (!z->folder_open) {
      result = szw_open_folder(writer);
      if (result != GARC_OK) {
        return result;
      }
    }
  }
  memcpy(z->names.bytes + names_at, member->name, member->name_length);
  z->names.length = names_at + member->name_length;
  SzwEntry * entry = &z->entries[z->num_entries];
  memset(entry, 0, sizeof(*entry));
  entry->name_off = (uint32_t)names_at;
  entry->name_len = (uint32_t)member->name_length;
  entry->flags = (uint8_t)(flags | ((!has_stream && !(flags & SZWF_DIRECTORY))
                                        ? SZWF_EMPTY_FILE : 0));
  entry->mtime = mtime;
  entry->attrib = attrib;
  entry->size = size;
  entry->has_stream = has_stream;
  z->current = z->num_entries++;
  z->running_crc = GCOMP_CRC32_INIT;
  z->in_member = 1;
  if (has_stream) {
    ++z->cur_nsub;
  }

  writer->data_remaining = size;
  writer->data_padding = 0;
  if (data) {
    result = garc_sevenz_write_data(writer, data, (size_t)size);
    if (result != GARC_OK) {
      return result;
    }
    writer->data_remaining = 0;
  }
  return GARC_OK;
}

GARC_Result garc_sevenz_write_data(
    GARC_Writer * writer, const void * data, size_t size) {
  struct GARC_SevenZ_Write * z = writer->sevenz;
  z->running_crc
      = gcomp_crc32_update(z->running_crc, (const uint8_t *)data, size);
  z->cur_unpack += size;
  if (!z->encoder) {
    return szw_emit(writer, data, size);
  }
  gcomp_buffer_t in = {data, size, 0};
  while (in.used < size) {
    gcomp_buffer_t out = {z->packed, SZW_BUFFER, 0};
    const size_t before = in.used;
    const gcomp_status_t status = gcomp_encoder_update(z->encoder, &in, &out);
    if (status != GCOMP_OK) {
      return garc_codec_result(status);
    }
    GARC_Result result = szw_emit(writer, z->packed, out.used);
    if (result != GARC_OK) {
      return result;
    }
    if (!out.used && in.used == before) {
      return GARC_ERR_INTERNAL;
    }
  }
  return GARC_OK;
}

GARC_Result garc_sevenz_write_close_member(GARC_Writer * writer) {
  struct GARC_SevenZ_Write * z = writer->sevenz;
  if (!z->in_member) {
    return GARC_OK;
  }
  z->in_member = 0;
  SzwEntry * entry = &z->entries[z->current];
  entry->crc = gcomp_crc32_finalize(z->running_crc);
  if (writer->options.sevenz_non_solid && entry->has_stream) {
    return szw_close_folder(writer);
  }
  return GARC_OK;
}

static void put_number(GARC_Buffer * b, const GARC_Allocator * a,
    uint64_t value, GARC_Result * status);

static void put_byte(GARC_Buffer * b, const GARC_Allocator * a, uint8_t byte,
    GARC_Result * status) {
  if (*status != GARC_OK) {
    return;
  }
  *status = garc_buffer_grow(a, b, b->length + 1u);
  if (*status == GARC_OK) {
    b->bytes[b->length++] = (char)byte;
  }
}

static void put_bytes(GARC_Buffer * b, const GARC_Allocator * a,
    const void * bytes, size_t n, GARC_Result * status) {
  if (*status != GARC_OK || !n) {
    return;
  }
  *status = garc_buffer_grow(a, b, b->length + n);
  if (*status == GARC_OK) {
    memcpy(b->bytes + b->length, bytes, n);
    b->length += n;
  }
}

static void put_u32(GARC_Buffer * b, const GARC_Allocator * a, uint32_t v,
    GARC_Result * status) {
  uint8_t t[4];
  for (unsigned i = 0; i < 4u; ++i) {
    t[i] = (uint8_t)(v >> (8u * i));
  }
  put_bytes(b, a, t, 4u, status);
}

static void put_u64(GARC_Buffer * b, const GARC_Allocator * a, uint64_t v,
    GARC_Result * status) {
  uint8_t t[8];
  for (unsigned i = 0; i < 8u; ++i) {
    t[i] = (uint8_t)(v >> (8u * i));
  }
  put_bytes(b, a, t, 8u, status);
}

/** 7z's variable-length number: leading ones count the extra bytes. */
static void put_number(GARC_Buffer * b, const GARC_Allocator * a,
    uint64_t value, GARC_Result * status) {
  uint8_t first = 0;
  uint8_t mask = 0x80u;
  unsigned extra = 0;
  for (; extra < 8u; ++extra) {
    if (value < (1ull << (7u * (extra + 1u)))) {
      first = (uint8_t)(first | (uint8_t)(value >> (8u * extra)));
      break;
    }
    first = (uint8_t)(first | mask);
    mask = (uint8_t)(mask >> 1);
  }
  put_byte(b, a, first, status);
  for (unsigned i = 0; i < extra; ++i) {
    put_byte(b, a, (uint8_t)(value >> (8u * i)), status);
  }
}

static void put_bits(GARC_Buffer * b, const GARC_Allocator * a,
    const uint8_t * bits, uint64_t n, GARC_Result * status) {
  uint8_t byte = 0;
  uint8_t mask = 0x80u;
  for (uint64_t i = 0; i < n; ++i) {
    if (bits[i]) {
      byte = (uint8_t)(byte | mask);
    }
    mask = (uint8_t)(mask >> 1);
    if (!mask) {
      put_byte(b, a, byte, status);
      byte = 0;
      mask = 0x80u;
    }
  }
  if (mask != 0x80u) {
    put_byte(b, a, byte, status);
  }
}

/** The coder record for the writer's method: flag, id, properties. */
static void put_coder(GARC_Buffer * b, const GARC_Allocator * a,
    GARC_SevenZ_Method method, GARC_Result * status) {
  switch (method) {
    case GARC_SEVENZ_LZMA2: {
      const uint8_t rec[] = {0x21u, 0x21u, 0x01u, SZW_LZMA2_PROP};
      put_bytes(b, a, rec, sizeof(rec), status);
      break;
    }
    case GARC_SEVENZ_LZMA: {
      /* lc 3, lp 0, pb 2 is (2 * 5 + 0) * 9 + 3 = 0x5D, then the dictionary. */
      uint8_t rec[] = {0x23u, 0x03u, 0x01u, 0x01u, 0x05u, 0x5Du, 0, 0, 0, 0};
      for (unsigned i = 0; i < 4u; ++i) {
        rec[6u + i] = (uint8_t)(SZW_DICT_SIZE >> (8u * i));
      }
      put_bytes(b, a, rec, sizeof(rec), status);
      break;
    }
    case GARC_SEVENZ_BZIP2: {
      const uint8_t rec[] = {0x03u, 0x04u, 0x02u, 0x02u};
      put_bytes(b, a, rec, sizeof(rec), status);
      break;
    }
    case GARC_SEVENZ_DEFLATE: {
      const uint8_t rec[] = {0x03u, 0x04u, 0x01u, 0x08u};
      put_bytes(b, a, rec, sizeof(rec), status);
      break;
    }
    case GARC_SEVENZ_DEFLATE64: {
      const uint8_t rec[] = {0x03u, 0x04u, 0x01u, 0x09u};
      put_bytes(b, a, rec, sizeof(rec), status);
      break;
    }
    default: {
      const uint8_t rec[] = {0x01u, 0x00u};
      put_bytes(b, a, rec, sizeof(rec), status);
      break;
    }
  }
}

/** The UTF-8 name bytes as UTF-16LE with a terminator. */
static void put_name(GARC_Buffer * b, const GARC_Allocator * a,
    const uint8_t * name, size_t length, GARC_Result * status) {
  for (size_t at = 0; at < length;) {
    uint32_t cp = 0;
    at += garc_sevenz_utf8_decode(name + at, length - at, &cp);
    if (cp >= 0x10000u) {
      const uint32_t v = cp - 0x10000u;
      const uint16_t hi = (uint16_t)(0xD800u + (v >> 10));
      const uint16_t lo = (uint16_t)(0xDC00u + (v & 0x3FFu));
      put_byte(b, a, (uint8_t)hi, status);
      put_byte(b, a, (uint8_t)(hi >> 8), status);
      put_byte(b, a, (uint8_t)lo, status);
      put_byte(b, a, (uint8_t)(lo >> 8), status);
    }
    else {
      put_byte(b, a, (uint8_t)cp, status);
      put_byte(b, a, (uint8_t)(cp >> 8), status);
    }
  }
  put_byte(b, a, 0, status);
  put_byte(b, a, 0, status);
}

/** A carried folder's record: its coders, bind pairs and packed indices. */
static void put_carry_folder(GARC_Buffer * b, const GARC_Allocator * a,
    const GARC_SevenZ_Carry * c, const GARC_SevenZ_Carry_Folder * f,
    GARC_Result * status) {
  put_number(b, a, f->ncoders, status);
  for (uint32_t i = 0; i < f->ncoders; ++i) {
    const GARC_SevenZ_Carry_Coder * coder = &c->coders[f->coder0 + i];
    const int complex = coder->num_in != 1u || coder->num_out != 1u;
    put_byte(b, a, (uint8_t)(coder->id_len | (complex ? 0x10u : 0u)
                       | (coder->props_len ? 0x20u : 0u)), status);
    put_bytes(b, a, coder->id, coder->id_len, status);
    if (complex) {
      put_number(b, a, coder->num_in, status);
      put_number(b, a, coder->num_out, status);
    }
    if (coder->props_len) {
      put_number(b, a, coder->props_len, status);
      put_bytes(b, a, c->props + coder->props_off, coder->props_len, status);
    }
  }
  for (uint32_t i = 0; i < f->nbind; ++i) {
    put_number(b, a, c->binds[2u * (f->bind0 + i)], status);
    put_number(b, a, c->binds[2u * (f->bind0 + i) + 1u], status);
  }
  if (f->npacked > 1u) {
    for (uint32_t i = 0; i < f->npacked; ++i) {
      put_number(b, a, c->packed[f->packed0 + i], status);
    }
  }
}

/**
 * The file table's entries, carried first and then the writer's own, seen
 * one way: whether each has a stream, is an empty file or an anti-item, and
 * its time and attributes.
 */
typedef struct {
  const GARC_SevenZ_Carry * c;        ///< The carried tables, or NULL.
  const struct GARC_SevenZ_Write * z; ///< The writer, for its own entries.
  uint64_t carried;                   ///< How many entries come from @ref c.
} SzwFiles;

static int szw_file_stream(const SzwFiles * f, uint64_t i) {
  return i < f->carried
      ? !(f->c->files[i].flags & GARC_SEVENZ_CARRY_EMPTY_STREAM)
      : f->z->entries[i - f->carried].has_stream;
}

static int szw_file_empty(const SzwFiles * f, uint64_t i) {
  return i < f->carried ? (f->c->files[i].flags & GARC_SEVENZ_CARRY_EMPTY_FILE) != 0
                        : (f->z->entries[i - f->carried].flags & SZWF_EMPTY_FILE) != 0;
}

static int szw_file_anti(const SzwFiles * f, uint64_t i) {
  return i < f->carried && (f->c->files[i].flags & GARC_SEVENZ_CARRY_ANTI) != 0;
}

static int szw_file_mtime(const SzwFiles * f, uint64_t i, uint64_t * out) {
  if (i < f->carried) {
    *out = f->c->files[i].mtime;
    return (f->c->files[i].flags & GARC_SEVENZ_CARRY_HAS_MTIME) != 0;
  }
  *out = f->z->entries[i - f->carried].mtime;
  return (f->z->entries[i - f->carried].flags & SZWF_HAS_MTIME) != 0;
}

static int szw_file_attrib(const SzwFiles * f, uint64_t i, uint32_t * out) {
  if (i < f->carried) {
    *out = f->c->files[i].attrib;
    return (f->c->files[i].flags & GARC_SEVENZ_CARRY_HAS_ATTRIB) != 0;
  }
  *out = f->z->entries[i - f->carried].attrib;
  return 1;
}

static void szw_file_name(const SzwFiles * f, uint64_t i,
    const uint8_t ** name, size_t * length) {
  if (i < f->carried) {
    *name = (const uint8_t *)f->c->names + f->c->files[i].name_off;
    *length = f->c->files[i].name_len;
    return;
  }
  const SzwEntry * e = &f->z->entries[i - f->carried];
  *name = (const uint8_t *)f->z->names.bytes + e->name_off;
  *length = e->name_len;
}

/** A property of the file table: its id, then its length, then @p part. */
static void put_property(GARC_Buffer * h, const GARC_Allocator * a, uint8_t id,
    GARC_Buffer * part, GARC_Result * status) {
  put_byte(h, a, id, status);
  put_number(h, a, part->length, status);
  put_bytes(h, a, part->bytes, part->length, status);
  garc_buffer_free(a, part);
  memset(part, 0, sizeof(*part));
}

/**
 * A digest list, or a defined-vector: 1 then the values when all of @p n are
 * defined, else 0, the bits, and the defined values.
 */
static void put_defined(GARC_Buffer * b, const GARC_Allocator * a,
    const uint8_t * defined, uint64_t n, GARC_Result * status) {
  int all = 1;
  for (uint64_t i = 0; i < n; ++i) {
    all &= defined[i] != 0;
  }
  put_byte(b, a, all ? 0x01u : 0x00u, status);
  if (!all) {
    put_bits(b, a, defined, n, status);
  }
}

static GARC_Result szw_build_header(
    GARC_Writer * writer, GARC_Buffer * h) {
  struct GARC_SevenZ_Write * z = writer->sevenz;
  const GARC_SevenZ_Carry * c = z->carry;
  const GARC_Allocator * a = writer->allocator;
  const GARC_SevenZ_Method method = writer->options.sevenz_method;
  GARC_Result status = GARC_OK;
  const uint32_t carried_folders = c ? c->num_folders : 0u;
  const uint64_t folders = (uint64_t)carried_folders + z->num_folders;
  const uint64_t carried_pack = c ? c->num_pack : 0u;
  put_byte(h, a, 0x01, &status);
  if (folders) {
    put_byte(h, a, 0x04, &status);
    put_byte(h, a, 0x06, &status);
    put_number(h, a, 0, &status);
    put_number(h, a, carried_pack + z->num_folders, &status);
    put_byte(h, a, 0x09, &status);
    for (uint64_t i = 0; i < carried_pack; ++i) {
      put_number(h, a, c->pack_sizes[i], &status);
    }
    for (uint32_t i = 0; i < z->num_folders; ++i) {
      put_number(h, a, z->folders[i].pack_size, &status);
    }
    put_byte(h, a, 0x00, &status);
    put_byte(h, a, 0x07, &status);
    put_byte(h, a, 0x0B, &status);
    put_number(h, a, folders, &status);
    put_byte(h, a, 0x00, &status);
    for (uint32_t i = 0; i < carried_folders; ++i) {
      put_carry_folder(h, a, c, &c->folders[i], &status);
    }
    for (uint32_t i = 0; i < z->num_folders; ++i) {
      put_number(h, a, 1, &status);
      put_coder(h, a, method, &status);
    }
    put_byte(h, a, 0x0C, &status);
    for (uint32_t i = 0; i < carried_folders; ++i) {
      const GARC_SevenZ_Carry_Folder * f = &c->folders[i];
      for (uint32_t j = 0; j < f->nout; ++j) {
        put_number(h, a, c->unpack_sizes[f->unpack0 + j], &status);
      }
    }
    for (uint32_t i = 0; i < z->num_folders; ++i) {
      put_number(h, a, z->folders[i].unpack_size, &status);
    }
    // Folder CRC-32s, which only carried folders have: the writer's own are
    // checked member by member.
    int any_folder_crc = 0;
    for (uint32_t i = 0; i < carried_folders; ++i) {
      any_folder_crc |= c->folders[i].has_crc;
    }
    if (any_folder_crc) {
      uint8_t * def = (uint8_t *)gcu_allocator_calloc(a, (size_t)folders, 1u);
      if (!def) {
        return GARC_ERR_OOM;
      }
      for (uint32_t i = 0; i < carried_folders; ++i) {
        def[i] = (uint8_t)(c->folders[i].has_crc != 0);
      }
      put_byte(h, a, 0x0A, &status);
      put_defined(h, a, def, folders, &status);
      for (uint32_t i = 0; i < carried_folders; ++i) {
        if (c->folders[i].has_crc) {
          put_u32(h, a, c->folders[i].crc, &status);
        }
      }
      gcu_allocator_free(a, def);
    }
    put_byte(h, a, 0x00, &status);

    put_byte(h, a, 0x08, &status);
    int any_not_one = 0;
    int any_many = 0;
    for (uint32_t i = 0; i < carried_folders; ++i) {
      any_not_one |= c->folders[i].nsub != 1u;
      any_many |= c->folders[i].nsub > 1u;
    }
    for (uint32_t i = 0; i < z->num_folders; ++i) {
      any_not_one |= z->folders[i].nsub != 1u;
      any_many |= z->folders[i].nsub > 1u;
    }
    if (any_not_one) {
      put_byte(h, a, 0x0D, &status);
      for (uint32_t i = 0; i < carried_folders; ++i) {
        put_number(h, a, c->folders[i].nsub, &status);
      }
      for (uint32_t i = 0; i < z->num_folders; ++i) {
        put_number(h, a, z->folders[i].nsub, &status);
      }
    }
    if (any_many) {
      put_byte(h, a, 0x09, &status);
      uint64_t sub = 0;
      for (uint32_t i = 0; i < carried_folders; ++i) {
        const uint32_t nsub = c->folders[i].nsub;
        for (uint32_t j = 0; j + 1u < nsub; ++j) {
          put_number(h, a, c->sub_sizes[sub + j], &status);
        }
        sub += nsub;
      }
      uint32_t e = 0;
      for (uint32_t i = 0; i < z->num_folders; ++i) {
        uint32_t seen = 0;
        while (seen < z->folders[i].nsub) {
          while (!z->entries[e].has_stream) {
            ++e;
          }
          if (seen + 1u < z->folders[i].nsub) {
            put_number(h, a, z->entries[e].size, &status);
          }
          ++seen;
          ++e;
        }
      }
    }
    // The digests of every member a folder CRC does not already check: a
    // folder of one member with a CRC passes it down, as the reader takes it.
    uint64_t listed = 0;
    for (uint32_t i = 0; i < carried_folders; ++i) {
      const GARC_SevenZ_Carry_Folder * f = &c->folders[i];
      if (!(f->nsub == 1u && f->has_crc)) {
        listed += f->nsub;
      }
    }
    uint64_t own = 0;
    for (uint32_t e = 0; e < z->num_entries; ++e) {
      own += z->entries[e].has_stream ? 1u : 0u;
    }
    if (listed + own) {
      uint8_t * def = (uint8_t *)gcu_allocator_calloc(a, (size_t)(listed + own), 1u);
      if (!def) {
        return GARC_ERR_OOM;
      }
      uint64_t k = 0;
      uint64_t sub = 0;
      for (uint32_t i = 0; i < carried_folders; ++i) {
        const GARC_SevenZ_Carry_Folder * f = &c->folders[i];
        if (!(f->nsub == 1u && f->has_crc)) {
          for (uint32_t j = 0; j < f->nsub; ++j) {
            def[k++] = c->sub_has_crc[sub + j];
          }
        }
        sub += f->nsub;
      }
      for (; k < listed + own; ++k) {
        def[k] = 1u;
      }
      put_byte(h, a, 0x0A, &status);
      put_defined(h, a, def, listed + own, &status);
      gcu_allocator_free(a, def);
      sub = 0;
      for (uint32_t i = 0; i < carried_folders; ++i) {
        const GARC_SevenZ_Carry_Folder * f = &c->folders[i];
        if (!(f->nsub == 1u && f->has_crc)) {
          for (uint32_t j = 0; j < f->nsub; ++j) {
            if (c->sub_has_crc[sub + j]) {
              put_u32(h, a, c->sub_crc[sub + j], &status);
            }
          }
        }
        sub += f->nsub;
      }
      for (uint32_t e = 0; e < z->num_entries; ++e) {
        if (z->entries[e].has_stream) {
          put_u32(h, a, z->entries[e].crc, &status);
        }
      }
    }
    put_byte(h, a, 0x00, &status);
    put_byte(h, a, 0x00, &status);
  }

  SzwFiles files = {c, z, c ? c->num_files : 0u};
  const uint64_t total = files.carried + z->num_entries;
  if (total) {
    put_byte(h, a, 0x05, &status);
    put_number(h, a, total, &status);
    uint8_t * bits = (uint8_t *)gcu_allocator_calloc(a, (size_t)total, 1u);
    uint8_t * empty_bits = (uint8_t *)gcu_allocator_calloc(a, (size_t)total, 1u);
    uint8_t * anti_bits = (uint8_t *)gcu_allocator_calloc(a, (size_t)total, 1u);
    if (!bits || !empty_bits || !anti_bits) {
      gcu_allocator_free(a, bits);
      gcu_allocator_free(a, empty_bits);
      gcu_allocator_free(a, anti_bits);
      return GARC_ERR_OOM;
    }
    uint64_t nempty = 0;
    int any_file = 0;
    int any_anti = 0;
    for (uint64_t e = 0; e < total; ++e) {
      if (!szw_file_stream(&files, e)) {
        bits[e] = 1;
        empty_bits[nempty] = szw_file_empty(&files, e) ? 1u : 0u;
        anti_bits[nempty] = szw_file_anti(&files, e) ? 1u : 0u;
        any_file |= empty_bits[nempty];
        any_anti |= anti_bits[nempty];
        ++nempty;
      }
    }
    GARC_Buffer part;
    memset(&part, 0, sizeof(part));
    if (nempty) {
      put_bits(&part, a, bits, total, &status);
      put_property(h, a, 0x0E, &part, &status);
      if (any_file) {
        put_bits(&part, a, empty_bits, nempty, &status);
        put_property(h, a, 0x0F, &part, &status);
      }
      if (any_anti) {
        put_bits(&part, a, anti_bits, nempty, &status);
        put_property(h, a, 0x10, &part, &status);
      }
    }
    gcu_allocator_free(a, empty_bits);
    gcu_allocator_free(a, anti_bits);

    put_byte(&part, a, 0x00, &status);
    for (uint64_t e = 0; e < total; ++e) {
      const uint8_t * name = NULL;
      size_t length = 0;
      szw_file_name(&files, e, &name, &length);
      put_name(&part, a, name, length, &status);
    }
    put_property(h, a, 0x11, &part, &status);

    // Times and attributes, each with a defined-vector when not every entry
    // has one; `bits` is reused for it.
    int any_mtime = 0;
    for (uint64_t e = 0; e < total; ++e) {
      uint64_t unused = 0;
      bits[e] = (uint8_t)szw_file_mtime(&files, e, &unused);
      any_mtime |= bits[e];
    }
    if (any_mtime) {
      put_defined(&part, a, bits, total, &status);
      put_byte(&part, a, 0x00, &status);
      for (uint64_t e = 0; e < total; ++e) {
        uint64_t mtime = 0;
        if (szw_file_mtime(&files, e, &mtime)) {
          put_u64(&part, a, mtime, &status);
        }
      }
      put_property(h, a, 0x14, &part, &status);
    }
    int any_attrib = 0;
    for (uint64_t e = 0; e < total; ++e) {
      uint32_t unused = 0;
      bits[e] = (uint8_t)szw_file_attrib(&files, e, &unused);
      any_attrib |= bits[e];
    }
    if (any_attrib) {
      put_defined(&part, a, bits, total, &status);
      put_byte(&part, a, 0x00, &status);
      for (uint64_t e = 0; e < total; ++e) {
        uint32_t attrib = 0;
        if (szw_file_attrib(&files, e, &attrib)) {
          put_u32(&part, a, attrib, &status);
        }
      }
      put_property(h, a, 0x15, &part, &status);
    }
    gcu_allocator_free(a, bits);
    put_byte(h, a, 0x00, &status);
  }
  put_byte(h, a, 0x00, &status);
  return status;
}

GARC_Result garc_sevenz_write_end(GARC_Writer * writer) {
  struct GARC_SevenZ_Write * z = writer->sevenz;
  const GARC_Allocator * a = writer->allocator;
  GARC_Result result = szw_close_folder(writer);
  if (result != GARC_OK) {
    return result;
  }
  const uint64_t header_at = garc_sink_tell(writer->sink);
  uint8_t start[GARC_SEVENZ_START_SIZE];
  memset(start, 0, sizeof(start));
  memcpy(start, "7z\xBC\xAF\x27\x1C", 6);
  start[6] = 0;
  start[7] = 4;

  uint64_t next_size = 0;
  uint32_t next_crc = 0;
  if (z->num_entries || (z->carry && z->carry->num_files)) {
    GARC_Buffer header;
    memset(&header, 0, sizeof(header));
    result = szw_build_header(writer, &header);
    if (result == GARC_OK && header.length > SZW_MAX_HEADER) {
      result = GARC_ERR_UNSUPPORTED;
    }
    if (result == GARC_OK) {
      result = garc_sink_write(writer->sink, header.bytes, header.length);
    }
    if (result == GARC_OK) {
      next_size = header.length;
      next_crc = gcomp_crc32_finalize(gcomp_crc32_update(GCOMP_CRC32_INIT,
          (const uint8_t *)header.bytes, header.length));
    }
    garc_buffer_free(a, &header);
    if (result != GARC_OK) {
      return result;
    }
  }
  const uint64_t offset = header_at - (z->origin + GARC_SEVENZ_START_SIZE);
  for (unsigned i = 0; i < 8u; ++i) {
    start[12u + i] = (uint8_t)((next_size ? offset : 0u) >> (8u * i));
    start[20u + i] = (uint8_t)(next_size >> (8u * i));
  }
  for (unsigned i = 0; i < 4u; ++i) {
    start[28u + i] = (uint8_t)(next_crc >> (8u * i));
  }
  const uint32_t start_crc = gcomp_crc32_finalize(
      gcomp_crc32_update(GCOMP_CRC32_INIT, start + 12u, 20u));
  for (unsigned i = 0; i < 4u; ++i) {
    start[8u + i] = (uint8_t)(start_crc >> (8u * i));
  }
  if (z->carry) {
    memcpy(z->start, start, sizeof(start));
    z->start_ready = 1;
    return GARC_OK;
  }
  return garc_sink_patch(writer->sink, z->origin, start, sizeof(start));
}

GARC_Result garc_sevenz_write_start_header(
    const GARC_Writer * writer, uint8_t out[32]) {
  const struct GARC_SevenZ_Write * z = writer->sevenz;
  if (!z || !z->start_ready) {
    return GARC_ERR_INVALID;
  }
  memcpy(out, z->start, GARC_SEVENZ_START_SIZE);
  return GARC_OK;
}

void garc_sevenz_write_release(GARC_Writer * writer) {
  struct GARC_SevenZ_Write * z = writer->sevenz;
  const GARC_Allocator * a = writer->allocator;
  if (!z) {
    return;
  }
  gcomp_encoder_destroy(z->encoder);
  gcomp_options_destroy(z->encoder_options);
  gcu_allocator_free(a, z->packed);
  gcu_allocator_free(a, z->entries);
  gcu_allocator_free(a, z->folders);
  garc_buffer_free(a, &z->names);
  garc_sevenz_carry_free(z->carry, a);
  gcu_allocator_free(a, z);
  writer->sevenz = NULL;
}
