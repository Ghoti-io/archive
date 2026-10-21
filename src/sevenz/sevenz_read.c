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
 * The 7z reader.
 *
 * **What a 7z is, for this file's purposes.** A 32-byte signature header at the
 * front says where the real header is, near the end. The real header describes
 * *folders* - each a graph of coders (decompressors and filters) that turns one or
 * more packed streams into one unpacked stream - and *substreams*, the cuts of a
 * folder's output that are the files. A solid archive is one folder holding many
 * files, which is why reading file N means decoding files 0 to N-1 first and
 * throwing the bytes away. That cost is the format's, and ::garc_sevenz_next()
 * pays it lazily: nothing is decoded until a member's bytes, or a later member,
 * are asked for.
 *
 * **What is read.** Folders that are a straight chain of coders each taking one
 * stream and giving one: copy, LZMA, LZMA2, bzip2, deflate, delta and the BCJ
 * branch filters. The header itself may be encoded (7-Zip's default) and is
 * decoded with the same machinery. A coder this library has no codec for, a
 * coder with more than one input (BCJ2), and encryption are
 * ::GARC_ERR_UNSUPPORTED - on the member's *data*, not on the walk, so an
 * archive with one such folder is still an archive to list.
 *
 * **What is trusted.** Nothing in the header. Every count is bounded by the
 * bytes left to hold it before anything is allocated for it; every offset is
 * checked against the stream; every size sum is checked for wrap; a folder's
 * substream sizes must add up to the folder's unpacked size; and the header,
 * each file and (where declared) each folder is checked against its CRC-32.
 * The decoders run under `limits.max_output_bytes` equal to the size the header
 * declared for that coder, so a stream that expands past its own container's
 * statement is refused by the codec rather than by this file.
 *
 * **The format's text is UTF-16.** This library otherwise reports names as the
 * bytes the container carried and does not transcode (see the dependency
 * discussion in design.md). 7z gives no choice, so names are converted here, and
 * only here, to UTF-8: well-formed pairs become four-byte sequences and a lone
 * surrogate becomes U+FFFD, which is the one case where what is reported is not
 * what is stored.
 */

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/allocator.h>
#include <ghoti.io/archive/codec.h>
#include <ghoti.io/compress/crc32.h>
#include <ghoti.io/compress/options.h>
#include <ghoti.io/cutil/allocator.h>
#include <stdint.h>
#include <string.h>

#include "../codec/codec_internal.h"
#include "../core/buffer_internal.h"
#include "../stream/stream_internal.h"
#include "reader/reader_internal.h"
#include "sevenz_internal.h"

////////////////////////////////////////////////////////////////////////
// Constants
////////////////////////////////////////////////////////////////////////

/** The six bytes every 7z begins with. */
static const uint8_t SZ_SIGNATURE[GARC_SEVENZ_SIGNATURE_SIZE]
    = {0x37u, 0x7Au, 0xBCu, 0xAFu, 0x27u, 0x1Cu};

/**
 * The most a header, or an encoded header's unpacked bytes, may occupy.
 *
 * The header is read whole, so this is a memory bound and not a format limit.
 * 64 MiB holds the names of about a million files with room to spare; a header
 * that claims more is refused as a limit rather than allocated.
 */
#define SZ_MAX_HEADER (64u * 1024u * 1024u)

/** An encoded header may decode to another encoded header; this many, no more. */
#define SZ_MAX_HEADER_DEPTH 4u

/** Most coders in one folder. 7-Zip's own cap is 64; real archives use 1 to 4. */
#define SZ_MAX_CODERS 32u

/** Most streams one coder may name, in either direction. */
#define SZ_MAX_CODER_STREAMS 32u

/** CRC-32 of a buffer, finalized: the value 7z stores. */
static uint32_t sz_crc32(const uint8_t * data, size_t length) {
  return gcomp_crc32_finalize(gcomp_crc32_update(GCOMP_CRC32_INIT, data, length));
}

/** Property ids of the header grammar. */
enum {
  SZ_END = 0x00,
  SZ_HEADER = 0x01,
  SZ_ARCHIVE_PROPERTIES = 0x02,
  SZ_ADDITIONAL_STREAMS_INFO = 0x03,
  SZ_MAIN_STREAMS_INFO = 0x04,
  SZ_FILES_INFO = 0x05,
  SZ_PACK_INFO = 0x06,
  SZ_UNPACK_INFO = 0x07,
  SZ_SUBSTREAMS_INFO = 0x08,
  SZ_SIZE = 0x09,
  SZ_CRC = 0x0A,
  SZ_FOLDER = 0x0B,
  SZ_CODERS_UNPACK_SIZE = 0x0C,
  SZ_NUM_UNPACK_STREAM = 0x0D,
  SZ_EMPTY_STREAM = 0x0E,
  SZ_EMPTY_FILE = 0x0F,
  SZ_ANTI = 0x10,
  SZ_NAMES = 0x11,
  SZ_CTIME = 0x12,
  SZ_ATIME = 0x13,
  SZ_MTIME = 0x14,
  SZ_WIN_ATTRIBUTES = 0x15,
  SZ_ENCODED_HEADER = 0x17,
  SZ_DUMMY = 0x19
};

/** File flags. */
enum {
  SZF_EMPTY_STREAM = 1,
  SZF_EMPTY_FILE = 2,
  SZF_ANTI = 4,
  SZF_HAS_MTIME = 8,
  SZF_HAS_ATTRIB = 16
};

/** FILE_ATTRIBUTE_DIRECTORY, and 7-Zip's "the high 16 bits are st_mode". */
#define SZ_ATTR_DIRECTORY 0x10u
/** Set in the attribute word when its high 16 bits are the Unix `st_mode`. */
#define SZ_ATTR_UNIX_EXTENSION 0x8000u

/** Seconds between 1601-01-01 and 1970-01-01, the FILETIME epoch gap. */
#define SZ_EPOCH_GAP 11644473600LL

////////////////////////////////////////////////////////////////////////
// Cursor
////////////////////////////////////////////////////////////////////////

/** A read position in a buffer, which every header parser bounds itself by. */
typedef struct {
  const uint8_t * p; ///< The buffer.
  size_t len;        ///< Its length.
  size_t pos;        ///< The next byte to read.
} Cur;

static size_t cur_left(const Cur * c) {
  return c->len - c->pos;
}

static GARC_Result cur_u8(Cur * c, uint8_t * v) {
  if (c->pos >= c->len) {
    return GARC_ERR_CORRUPT;
  }
  *v = c->p[c->pos++];
  return GARC_OK;
}

static GARC_Result cur_u32(Cur * c, uint32_t * v) {
  if (cur_left(c) < 4u) {
    return GARC_ERR_CORRUPT;
  }
  const uint8_t * b = c->p + c->pos;
  *v = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16)
      | ((uint32_t)b[3] << 24);
  c->pos += 4u;
  return GARC_OK;
}

static GARC_Result cur_u64(Cur * c, uint64_t * v) {
  if (cur_left(c) < 8u) {
    return GARC_ERR_CORRUPT;
  }
  const uint8_t * b = c->p + c->pos;
  uint64_t out = 0;
  for (unsigned i = 0; i < 8u; ++i) {
    out |= (uint64_t)b[i] << (8u * i);
  }
  *v = out;
  c->pos += 8u;
  return GARC_OK;
}

/**
 * 7z's variable-length number.
 *
 * The count of leading one bits in the first byte is the count of extra bytes;
 * the first byte's remaining low bits are the *high* part of the value and the
 * extra bytes are the low part, little-endian.
 */
static GARC_Result cur_number(Cur * c, uint64_t * v) {
  uint8_t first = 0;
  GARC_Result result = cur_u8(c, &first);
  if (result != GARC_OK) {
    return result;
  }
  uint8_t mask = 0x80u;
  uint64_t value = 0;
  for (unsigned i = 0; i < 8u; ++i) {
    if (!(first & mask)) {
      const uint64_t high = (uint64_t)(first & (uint8_t)(mask - 1u));
      value += high << (8u * i);
      *v = value;
      return GARC_OK;
    }
    uint8_t byte = 0;
    result = cur_u8(c, &byte);
    if (result != GARC_OK) {
      return result;
    }
    value |= (uint64_t)byte << (8u * i);
    mask = (uint8_t)(mask >> 1);
  }
  *v = value;
  return GARC_OK;
}

static GARC_Result cur_skip(Cur * c, uint64_t n) {
  if (n > (uint64_t)cur_left(c)) {
    return GARC_ERR_CORRUPT;
  }
  c->pos += (size_t)n;
  return GARC_OK;
}

/** A count that is bounded by the bytes left: each item costs at least one. */
static GARC_Result cur_count(Cur * c, uint64_t * v, uint64_t max) {
  GARC_Result result = cur_number(c, v);
  if (result != GARC_OK) {
    return result;
  }
  if (*v > max) {
    return GARC_ERR_CORRUPT;
  }
  return GARC_OK;
}

/**
 * A count bounded by the bytes that remain *after* it was read.
 *
 * Not `cur_count(c, &n, cur_left(c))`: the argument is evaluated before the
 * number is consumed, so that bound is a few bytes too generous, and for a
 * length that is then copied from the cursor a few bytes is an over-read.
 */
static GARC_Result cur_count_left(Cur * c, uint64_t * v) {
  GARC_Result result = cur_number(c, v);
  if (result != GARC_OK) {
    return result;
  }
  if (*v > (uint64_t)cur_left(c)) {
    return GARC_ERR_CORRUPT;
  }
  return GARC_OK;
}

/** Evaluate a ::GARC_Result and return it from the caller unless it is ::GARC_OK. */
#define TRY(expr) \
  do { \
    GARC_Result try_result_ = (expr); \
    if (try_result_ != GARC_OK) { \
      return try_result_; \
    } \
  } while (0)

////////////////////////////////////////////////////////////////////////
// The parsed header
////////////////////////////////////////////////////////////////////////

/** One coder of a folder: its id, how many streams it consumes and makes, and its properties. */
typedef struct {
  uint8_t id[8];      ///< The method id bytes, most significant first.
  uint8_t id_len;     ///< How many bytes of @ref id are used.
  uint32_t num_in;    ///< Streams the coder consumes.
  uint32_t num_out;   ///< Streams the coder produces.
  uint32_t props_off; ///< Into Streams.props.
  uint32_t props_len; ///< Property bytes.
} Coder;

/** Joins one coder's output to another coder's input, within a folder. */
typedef struct {
  uint32_t in_index;  ///< The folder-wide index of the input stream.
  uint32_t out_index; ///< The folder-wide index of the output stream that feeds it.
} Bind;

/** A folder: a graph of coders that turns packed streams into one unpacked stream. */
typedef struct {
  uint32_t coder0;   ///< First coder, into Streams.coders.
  uint32_t ncoders;  ///< Coders in the folder.
  uint32_t bind0;    ///< First bind pair, into Streams.binds.
  uint32_t nbind;    ///< Bind pairs in the folder.
  uint32_t packed0;  ///< First packed in-stream index, into Streams.packed.
  uint32_t npacked;  ///< Packed streams the folder reads.
  uint32_t unpack0;  ///< First out stream's size, into Streams.unpack.
  uint32_t nout;     ///< Out streams in the folder.
  uint32_t pack0;    ///< First pack stream, into Streams.pack_*.
  uint32_t nsub;     ///< Substreams in this folder.
  uint64_t sub0;     ///< First substream, into Streams.sub_*.
  int has_crc;       ///< Whether the whole folder has a CRC-32.
  uint32_t crc;      ///< That CRC-32, when @ref has_crc.
} Folder;

/** The parsed stream tables of a header: pack streams, folders, coders, substreams. */
typedef struct {
  uint64_t pack_pos;           ///< Offset of the first pack stream after the signature header.
  uint32_t num_pack;           ///< Pack streams in the archive.
  uint64_t * pack_sizes;       ///< Each pack stream's size.
  uint64_t * pack_offsets;     ///< Each pack stream's offset from the first.
  uint32_t num_folders;        ///< Folders in the archive.
  Folder * folders;            ///< The folders.
  Coder * coders;              ///< Every folder's coders, end to end.
  uint32_t num_coders;         ///< How many of @ref coders are in use.
  uint32_t cap_coders;         ///< How many @ref coders has room for.
  Bind * binds;                ///< Every folder's bind pairs, end to end.
  uint32_t num_binds;          ///< How many of @ref binds are in use.
  uint32_t cap_binds;          ///< How many @ref binds has room for.
  uint32_t * packed;           ///< Every folder's packed in-stream indices, end to end.
  uint32_t num_packed;         ///< How many of @ref packed are in use.
  uint32_t cap_packed;         ///< How many @ref packed has room for.
  uint64_t * unpack;           ///< Every folder's out-stream sizes, end to end.
  uint32_t num_unpack;         ///< How many of @ref unpack are in use.
  uint8_t * props;             ///< Every coder's property bytes, end to end.
  size_t props_len;            ///< How many bytes of @ref props are in use.
  size_t props_cap;            ///< How many bytes @ref props has room for.
  uint64_t num_sub;            ///< Substreams in the archive, across all folders.
  uint64_t * sub_sizes;        ///< Each substream's size.
  uint8_t * sub_has_crc;       ///< Whether each substream has a CRC-32.
  uint32_t * sub_crc;          ///< Each substream's CRC-32.
} Streams;

/** One entry of the file table. */
typedef struct {
  uint32_t name_off; ///< Offset of the name in GARC_SevenZ.names, in bytes.
  uint32_t name_len; ///< Length of the name in UTF-8 bytes.
  uint8_t flags;     ///< ::SZF_ANTI, ::SZF_HAS_MTIME and the other SZF_ bits.
  uint64_t mtime;    ///< FILETIME ticks, when ::SZF_HAS_MTIME.
  uint32_t attrib;   ///< The attribute word, when ::SZF_HAS_ATTRIB.
  uint64_t sub; ///< Global substream index, when there is a stream.
} File;

/** The decoders open for one folder, from the packed stream up to the top. */
typedef struct {
  GARC_Stream * s[SZ_MAX_CODERS + 1u]; ///< The streams, packed slice first.
  size_t n;                            ///< How many of @ref s are in use.
  gcomp_options_t * o[SZ_MAX_CODERS];  ///< The options each decoder was given.
  size_t no;                           ///< How many of @ref o are in use.
  GARC_Stream * top;                   ///< The stream the unpacked bytes come from.
} Chain;

/** The 7z reader's state: the parsed header, and where the walk is. */
struct GARC_SevenZ {
  Streams main;        ///< The stream tables.
  uint64_t num_files;  ///< Entries in the file table.
  File * files;        ///< The file table.
  char * names;        ///< Every name converted to UTF-8, end to end.
  size_t names_len;    ///< Bytes in @ref names.
  uint64_t origin;     ///< Offset of the signature header in the stream.
  uint64_t stream_size; ///< The stream's size, when @ref have_size.
  int have_size;       ///< Whether the stream reported a size.
  /* the walk */
  uint64_t next_file;  ///< The next entry ::garc_sevenz_next() returns.
  int open_folder;     ///< Index of the folder being read, or -1.
  uint32_t folder_cursor; ///< The folder holding the current member's stream.
  Chain chain;         ///< The open folder's decoders.
  uint64_t folder_pos; ///< Bytes of the open folder already decoded.
  uint64_t folder_size; ///< Bytes the open folder decodes to.
  uint32_t crc;        ///< The unfinalized CRC-32 of the current member so far.
  int crc_active;      ///< Whether the current member's bytes are being checksummed.
  uint32_t expect_crc; ///< The CRC-32 the current member must finish with.
  GARC_Buffer link;    ///< The current symlink's target, which is its data.
};

static void * sz_calloc(const GARC_Allocator * a, uint64_t count, size_t size) {
  if (!count) {
    return gcu_allocator_calloc(a, 1, size ? size : 1u);
  }
  if (count > (uint64_t)SIZE_MAX / size) {
    return NULL;
  }
  return gcu_allocator_calloc(a, (size_t)count, size);
}

/**
 * Append to a growable array, doubling.
 *
 * @p slot is the address of the array pointer, passed as `void *` and moved with
 * memcpy: reading a `T **` through a `void **` is a strict-aliasing violation.
 */
static GARC_Result sz_push(const GARC_Allocator * a, void * slot,
    uint32_t * count, uint32_t * cap, size_t size, const void * item) {
  void * array = NULL;
  memcpy(&array, slot, sizeof(array));
  if (*count == *cap) {
    const uint32_t wanted = *cap ? *cap * 2u : 8u;
    if (wanted < *cap) {
      return GARC_ERR_OOM;
    }
    void * grown = gcu_allocator_realloc(a, array, (size_t)wanted * size);
    if (!grown) {
      return GARC_ERR_OOM;
    }
    array = grown;
    memcpy(slot, &array, sizeof(array));
    *cap = wanted;
  }
  memcpy((uint8_t *)array + (size_t)*count * size, item, size);
  ++*count;
  return GARC_OK;
}

static void streams_free(const GARC_Allocator * a, Streams * s) {
  gcu_allocator_free(a, s->pack_sizes);
  gcu_allocator_free(a, s->pack_offsets);
  gcu_allocator_free(a, s->folders);
  gcu_allocator_free(a, s->coders);
  gcu_allocator_free(a, s->binds);
  gcu_allocator_free(a, s->packed);
  gcu_allocator_free(a, s->unpack);
  gcu_allocator_free(a, s->props);
  gcu_allocator_free(a, s->sub_sizes);
  gcu_allocator_free(a, s->sub_has_crc);
  gcu_allocator_free(a, s->sub_crc);
  memset(s, 0, sizeof(*s));
}

/** Bit vector of @p n bits, MSB first, preceded by an all-defined byte if asked. */
static GARC_Result read_bits(Cur * c, uint64_t n, uint8_t * out) {
  if (n > (uint64_t)cur_left(c) * 8u) {
    return GARC_ERR_CORRUPT;
  }
  uint8_t byte = 0;
  uint8_t mask = 0;
  for (uint64_t i = 0; i < n; ++i) {
    if (!mask) {
      TRY(cur_u8(c, &byte));
      mask = 0x80u;
    }
    out[i] = (byte & mask) ? 1u : 0u;
    mask = (uint8_t)(mask >> 1);
  }
  return GARC_OK;
}

static GARC_Result read_defined(Cur * c, uint64_t n, uint8_t * out) {
  uint8_t all = 0;
  TRY(cur_u8(c, &all));
  if (all) {
    memset(out, 1, (size_t)n);
    return GARC_OK;
  }
  return read_bits(c, n, out);
}

/** A digest vector: which are defined, then the CRCs of those. */
static GARC_Result read_digests(
    Cur * c, uint64_t n, uint8_t * def, uint32_t * crc) {
  TRY(read_defined(c, n, def));
  for (uint64_t i = 0; i < n; ++i) {
    crc[i] = 0;
    if (def[i]) {
      TRY(cur_u32(c, &crc[i]));
    }
  }
  return GARC_OK;
}

////////////////////////////////////////////////////////////////////////
// StreamsInfo
////////////////////////////////////////////////////////////////////////

static GARC_Result parse_pack_info(
    Cur * c, const GARC_Allocator * a, Streams * s) {
  uint64_t count = 0;
  TRY(cur_number(c, &s->pack_pos));
  TRY(cur_count_left(c, &count));
  s->num_pack = (uint32_t)count;
  s->pack_sizes = (uint64_t *)sz_calloc(a, count, sizeof(uint64_t));
  s->pack_offsets = (uint64_t *)sz_calloc(a, count, sizeof(uint64_t));
  if (!s->pack_sizes || !s->pack_offsets) {
    return GARC_ERR_OOM;
  }
  int have_sizes = 0;
  for (;;) {
    uint8_t id = 0;
    TRY(cur_u8(c, &id));
    if (id == SZ_END) {
      break;
    }
    if (id == SZ_SIZE) {
      uint64_t at = 0;
      for (uint64_t i = 0; i < count; ++i) {
        TRY(cur_number(c, &s->pack_sizes[i]));
        s->pack_offsets[i] = at;
        if (s->pack_sizes[i] > UINT64_MAX - at) {
          return GARC_ERR_CORRUPT;
        }
        at += s->pack_sizes[i];
      }
      have_sizes = 1;
    }
    else if (id == SZ_CRC) {
      uint8_t * def = (uint8_t *)sz_calloc(a, count, 1u);
      uint32_t * crc = (uint32_t *)sz_calloc(a, count, sizeof(uint32_t));
      GARC_Result result = def && crc ? read_digests(c, count, def, crc)
                                       : GARC_ERR_OOM;
      gcu_allocator_free(a, def);
      gcu_allocator_free(a, crc);
      TRY(result);
    }
    else {
      return GARC_ERR_CORRUPT;
    }
  }
  if (count && !have_sizes) {
    return GARC_ERR_CORRUPT;
  }
  return GARC_OK;
}

static GARC_Result parse_folder(
    Cur * c, const GARC_Allocator * a, Streams * s, Folder * f) {
  uint64_t ncoders = 0;
  TRY(cur_count(c, &ncoders, SZ_MAX_CODERS));
  if (!ncoders) {
    return GARC_ERR_CORRUPT;
  }
  f->coder0 = s->num_coders;
  f->ncoders = (uint32_t)ncoders;
  uint64_t total_in = 0;
  uint64_t total_out = 0;
  for (uint64_t i = 0; i < ncoders; ++i) {
    Coder coder;
    memset(&coder, 0, sizeof(coder));
    uint8_t flag = 0;
    TRY(cur_u8(c, &flag));
    if (flag & 0x80u) {
      return GARC_ERR_UNSUPPORTED;
    }
    const unsigned id_len = flag & 0x0Fu;
    if (id_len > sizeof(coder.id)) {
      return GARC_ERR_UNSUPPORTED;
    }
    if (cur_left(c) < id_len) {
      return GARC_ERR_CORRUPT;
    }
    memcpy(coder.id, c->p + c->pos, id_len);
    coder.id_len = (uint8_t)id_len;
    c->pos += id_len;
    coder.num_in = 1u;
    coder.num_out = 1u;
    if (flag & 0x10u) {
      uint64_t in = 0;
      uint64_t out = 0;
      TRY(cur_count(c, &in, SZ_MAX_CODER_STREAMS));
      TRY(cur_count(c, &out, SZ_MAX_CODER_STREAMS));
      if (!in || !out) {
        return GARC_ERR_CORRUPT;
      }
      coder.num_in = (uint32_t)in;
      coder.num_out = (uint32_t)out;
    }
    if (flag & 0x20u) {
      uint64_t size = 0;
      TRY(cur_count_left(c, &size));
      if (s->props_len + size > s->props_cap) {
        size_t wanted = s->props_cap ? s->props_cap * 2u : 64u;
        while (wanted < s->props_len + size) {
          wanted *= 2u;
        }
        uint8_t * grown = (uint8_t *)gcu_allocator_realloc(a, s->props, wanted);
        if (!grown) {
          return GARC_ERR_OOM;
        }
        s->props = grown;
        s->props_cap = wanted;
      }
      if (size) {
        memcpy(s->props + s->props_len, c->p + c->pos, (size_t)size);
      }
      coder.props_off = (uint32_t)s->props_len;
      coder.props_len = (uint32_t)size;
      s->props_len += (size_t)size;
      c->pos += (size_t)size;
    }
    total_in += coder.num_in;
    total_out += coder.num_out;
    TRY(sz_push(a, &s->coders, &s->num_coders, &s->cap_coders,
        sizeof(Coder), &coder));
  }
  if (total_out < 1u || total_in > 2u * SZ_MAX_CODER_STREAMS
      || total_out > 2u * SZ_MAX_CODER_STREAMS) {
    return GARC_ERR_CORRUPT;
  }
  f->nout = (uint32_t)total_out;
  const uint64_t nbind = total_out - 1u;
  if (nbind > total_in) {
    return GARC_ERR_CORRUPT;
  }
  f->bind0 = s->num_binds;
  f->nbind = (uint32_t)nbind;
  for (uint64_t i = 0; i < nbind; ++i) {
    Bind bind;
    uint64_t in = 0;
    uint64_t out = 0;
    TRY(cur_number(c, &in));
    TRY(cur_number(c, &out));
    if (in >= total_in || out >= total_out) {
      return GARC_ERR_CORRUPT;
    }
    bind.in_index = (uint32_t)in;
    bind.out_index = (uint32_t)out;
    TRY(sz_push(a, &s->binds, &s->num_binds, &s->cap_binds,
        sizeof(Bind), &bind));
  }
  const uint64_t npacked = total_in - nbind;
  if (!npacked) {
    return GARC_ERR_CORRUPT;
  }
  f->packed0 = s->num_packed;
  f->npacked = (uint32_t)npacked;
  if (npacked == 1u) {
    uint32_t found = UINT32_MAX;
    for (uint32_t in = 0; in < total_in; ++in) {
      int bound = 0;
      for (uint32_t b = 0; b < f->nbind; ++b) {
        if (s->binds[f->bind0 + b].in_index == in) {
          bound = 1;
        }
      }
      if (!bound) {
        found = in;
        break;
      }
    }
    if (found == UINT32_MAX) {
      return GARC_ERR_CORRUPT;
    }
    TRY(sz_push(a, &s->packed, &s->num_packed, &s->cap_packed,
        sizeof(uint32_t), &found));
  }
  else {
    for (uint64_t i = 0; i < npacked; ++i) {
      uint64_t index = 0;
      TRY(cur_number(c, &index));
      if (index >= total_in) {
        return GARC_ERR_CORRUPT;
      }
      const uint32_t narrow = (uint32_t)index;
      TRY(sz_push(a, &s->packed, &s->num_packed, &s->cap_packed,
          sizeof(uint32_t), &narrow));
    }
  }
  return GARC_OK;
}

static GARC_Result parse_unpack_info(
    Cur * c, const GARC_Allocator * a, Streams * s) {
  uint8_t id = 0;
  TRY(cur_u8(c, &id));
  if (id != SZ_FOLDER) {
    return GARC_ERR_CORRUPT;
  }
  uint64_t count = 0;
  TRY(cur_count_left(c, &count));
  uint8_t external = 0;
  TRY(cur_u8(c, &external));
  if (external) {
    return GARC_ERR_UNSUPPORTED;
  }
  s->num_folders = (uint32_t)count;
  s->folders = (Folder *)sz_calloc(a, count, sizeof(Folder));
  if (!s->folders) {
    return GARC_ERR_OOM;
  }
  uint32_t pack = 0;
  uint32_t outs = 0;
  for (uint64_t i = 0; i < count; ++i) {
    Folder * f = &s->folders[i];
    TRY(parse_folder(c, a, s, f));
    f->pack0 = pack;
    f->unpack0 = outs;
    pack += f->npacked;
    outs += f->nout;
  }
  if (pack > s->num_pack) {
    return GARC_ERR_CORRUPT;
  }
  TRY(cur_u8(c, &id));
  if (id != SZ_CODERS_UNPACK_SIZE) {
    return GARC_ERR_CORRUPT;
  }
  s->num_unpack = outs;
  s->unpack = (uint64_t *)sz_calloc(a, outs, sizeof(uint64_t));
  if (!s->unpack) {
    return GARC_ERR_OOM;
  }
  for (uint32_t i = 0; i < outs; ++i) {
    TRY(cur_number(c, &s->unpack[i]));
  }
  for (;;) {
    TRY(cur_u8(c, &id));
    if (id == SZ_END) {
      break;
    }
    if (id != SZ_CRC) {
      return GARC_ERR_CORRUPT;
    }
    uint8_t * def = (uint8_t *)sz_calloc(a, count, 1u);
    uint32_t * crc = (uint32_t *)sz_calloc(a, count, sizeof(uint32_t));
    GARC_Result result = def && crc ? read_digests(c, count, def, crc)
                                     : GARC_ERR_OOM;
    if (result == GARC_OK) {
      for (uint64_t i = 0; i < count; ++i) {
        s->folders[i].has_crc = def[i];
        s->folders[i].crc = crc[i];
      }
    }
    gcu_allocator_free(a, def);
    gcu_allocator_free(a, crc);
    TRY(result);
  }
  return GARC_OK;
}

/** The index of the out stream no bind pair consumes: the folder's result. */
static int folder_main_out(const Streams * s, const Folder * f, uint32_t * out) {
  for (uint32_t o = 0; o < f->nout; ++o) {
    int bound = 0;
    for (uint32_t b = 0; b < f->nbind; ++b) {
      if (s->binds[f->bind0 + b].out_index == o) {
        bound = 1;
      }
    }
    if (!bound) {
      *out = o;
      return 1;
    }
  }
  return 0;
}

static uint64_t folder_unpack_size(const Streams * s, const Folder * f) {
  uint32_t out = 0;
  if (!folder_main_out(s, f, &out)) {
    return 0;
  }
  return s->unpack[f->unpack0 + out];
}

static GARC_Result parse_substreams_info(
    Cur * c, const GARC_Allocator * a, Streams * s) {
  /* Defaults: one substream per folder. */
  uint64_t total = 0;
  for (uint32_t i = 0; i < s->num_folders; ++i) {
    s->folders[i].nsub = 1u;
  }
  uint8_t id = 0;
  TRY(cur_u8(c, &id));
  if (id == SZ_NUM_UNPACK_STREAM) {
    for (uint32_t i = 0; i < s->num_folders; ++i) {
      uint64_t n = 0;
      TRY(cur_count(c, &n, UINT32_MAX));
      s->folders[i].nsub = (uint32_t)n;
    }
    TRY(cur_u8(c, &id));
  }
  for (uint32_t i = 0; i < s->num_folders; ++i) {
    s->folders[i].sub0 = total;
    total += s->folders[i].nsub;
    /* A substream is at least one byte of header or one folder CRC; bound the
       sum by what a header could plausibly hold so a count of 2^32 per folder
       cannot be multiplied into an allocation. */
    if (total > (uint64_t)SZ_MAX_HEADER * 8u) {
      return GARC_ERR_CORRUPT;
    }
  }
  s->num_sub = total;
  s->sub_sizes = (uint64_t *)sz_calloc(a, total, sizeof(uint64_t));
  s->sub_has_crc = (uint8_t *)sz_calloc(a, total, 1u);
  s->sub_crc = (uint32_t *)sz_calloc(a, total, sizeof(uint32_t));
  if (!s->sub_sizes || !s->sub_has_crc || !s->sub_crc) {
    return GARC_ERR_OOM;
  }
  int have_sizes = 0;
  if (id == SZ_SIZE) {
    have_sizes = 1;
    for (uint32_t i = 0; i < s->num_folders; ++i) {
      const Folder * f = &s->folders[i];
      if (!f->nsub) {
        continue;
      }
      uint64_t sum = 0;
      const uint64_t size = folder_unpack_size(s, f);
      for (uint32_t j = 0; j + 1u < f->nsub; ++j) {
        uint64_t one = 0;
        TRY(cur_number(c, &one));
        if (one > size - sum) {
          return GARC_ERR_CORRUPT;
        }
        s->sub_sizes[f->sub0 + j] = one;
        sum += one;
      }
      s->sub_sizes[f->sub0 + f->nsub - 1u] = size - sum;
    }
    TRY(cur_u8(c, &id));
  }
  if (!have_sizes) {
    for (uint32_t i = 0; i < s->num_folders; ++i) {
      const Folder * f = &s->folders[i];
      if (f->nsub == 1u) {
        s->sub_sizes[f->sub0] = folder_unpack_size(s, f);
      }
      else if (f->nsub > 1u) {
        return GARC_ERR_CORRUPT;
      }
    }
  }
  /* A folder with exactly one substream and a folder CRC passes it down. */
  uint64_t unknown = 0;
  for (uint32_t i = 0; i < s->num_folders; ++i) {
    const Folder * f = &s->folders[i];
    if (f->nsub == 1u && f->has_crc) {
      s->sub_has_crc[f->sub0] = 1u;
      s->sub_crc[f->sub0] = f->crc;
    }
    else {
      unknown += f->nsub;
    }
  }
  for (;;) {
    if (id == SZ_END) {
      break;
    }
    if (id == SZ_CRC) {
      uint8_t * def = (uint8_t *)sz_calloc(a, unknown, 1u);
      uint32_t * crc = (uint32_t *)sz_calloc(a, unknown, sizeof(uint32_t));
      GARC_Result result = def && crc ? read_digests(c, unknown, def, crc)
                                       : GARC_ERR_OOM;
      if (result == GARC_OK) {
        uint64_t k = 0;
        for (uint32_t i = 0; i < s->num_folders; ++i) {
          const Folder * f = &s->folders[i];
          if (f->nsub == 1u && f->has_crc) {
            continue;
          }
          for (uint32_t j = 0; j < f->nsub; ++j, ++k) {
            s->sub_has_crc[f->sub0 + j] = def[k];
            s->sub_crc[f->sub0 + j] = crc[k];
          }
        }
      }
      gcu_allocator_free(a, def);
      gcu_allocator_free(a, crc);
      TRY(result);
    }
    else {
      return GARC_ERR_CORRUPT;
    }
    TRY(cur_u8(c, &id));
  }
  return GARC_OK;
}

/** Parse a StreamsInfo (the id that introduced it is already read). */
static GARC_Result parse_streams_info(
    Cur * c, const GARC_Allocator * a, Streams * s) {
  int saw_pack = 0;
  int saw_unpack = 0;
  int saw_substreams = 0;
  for (;;) {
    uint8_t id = 0;
    TRY(cur_u8(c, &id));
    if (id == SZ_END) {
      break;
    }
    if (id == SZ_PACK_INFO) {
      if (saw_pack++) {
        return GARC_ERR_CORRUPT;
      }
      TRY(parse_pack_info(c, a, s));
    }
    else if (id == SZ_UNPACK_INFO) {
      if (saw_unpack++) {
        return GARC_ERR_CORRUPT;
      }
      TRY(parse_unpack_info(c, a, s));
    }
    else if (id == SZ_SUBSTREAMS_INFO) {
      /* After the folders it divides, and once. */
      if (!saw_unpack || saw_substreams) {
        return GARC_ERR_CORRUPT;
      }
      TRY(parse_substreams_info(c, a, s));
      saw_substreams = 1;
    }
    else {
      return GARC_ERR_CORRUPT;
    }
  }
  if (!saw_substreams) {
    /* One substream per folder, sized and checked as the folder is. */
    uint64_t total = s->num_folders;
    s->num_sub = total;
    s->sub_sizes = (uint64_t *)sz_calloc(a, total, sizeof(uint64_t));
    s->sub_has_crc = (uint8_t *)sz_calloc(a, total, 1u);
    s->sub_crc = (uint32_t *)sz_calloc(a, total, sizeof(uint32_t));
    if (!s->sub_sizes || !s->sub_has_crc || !s->sub_crc) {
      return GARC_ERR_OOM;
    }
    for (uint32_t i = 0; i < s->num_folders; ++i) {
      Folder * f = &s->folders[i];
      f->nsub = 1u;
      f->sub0 = i;
      s->sub_sizes[i] = folder_unpack_size(s, f);
      s->sub_has_crc[i] = (uint8_t)f->has_crc;
      s->sub_crc[i] = f->crc;
    }
  }
  return GARC_OK;
}

////////////////////////////////////////////////////////////////////////
// Folder decoding
////////////////////////////////////////////////////////////////////////

static void chain_destroy(Chain * chain) {
  /* Outermost first: a decoder reads through the stream beneath it. */
  while (chain->n) {
    garc_stream_destroy(chain->s[--chain->n]);
  }
  while (chain->no) {
    gcomp_options_destroy(chain->o[--chain->no]);
  }
  chain->top = NULL;
}

static GARC_Result wrap_lzma(const Coder * coder, const uint8_t * props,
    uint64_t out_size, gcomp_options_t * o) {
  if (coder->props_len != 5u) {
    return GARC_ERR_CORRUPT;
  }
  unsigned d = props[0];
  if (d >= 9u * 5u * 5u) {
    return GARC_ERR_CORRUPT;
  }
  const int64_t lc = (int64_t)(d % 9u);
  d /= 9u;
  const int64_t lp = (int64_t)(d % 5u);
  const int64_t pb = (int64_t)(d / 5u);
  uint64_t dict = (uint64_t)props[1] | ((uint64_t)props[2] << 8)
      | ((uint64_t)props[3] << 16) | ((uint64_t)props[4] << 24);
  if (dict < 4096u) {
    dict = 4096u;
  }
  if (gcomp_options_set_bool(o, "lzma.raw", 1) != GCOMP_OK
      || gcomp_options_set_int64(o, "lzma.lc", lc) != GCOMP_OK
      || gcomp_options_set_int64(o, "lzma.lp", lp) != GCOMP_OK
      || gcomp_options_set_int64(o, "lzma.pb", pb) != GCOMP_OK
      || gcomp_options_set_uint64(o, "lzma.dict_size", dict) != GCOMP_OK
      || gcomp_options_set_uint64(o, "lzma.uncompressed_size", out_size)
          != GCOMP_OK) {
    return GARC_ERR_OOM;
  }
  return GARC_OK;
}

/** What this library does with a coder id. */
typedef enum {
  SZM_COPY,        ///< No coder: the bytes are stored.
  SZM_LZMA,        ///< LZMA, with five property bytes.
  SZM_LZMA2,       ///< LZMA2, with one property byte.
  SZM_BZIP2,       ///< bzip2.
  SZM_DEFLATE,     ///< Raw deflate.
  SZM_DEFLATE64,   ///< Raw deflate64.
  SZM_DELTA,       ///< The delta filter.
  SZM_BCJ,         ///< A branch filter; the architecture is returned beside it.
  SZM_UNSUPPORTED  ///< Anything else: BCJ2, PPMd, encryption, an unknown id.
} Sz_Kind;

/** Map a coder id to what this library does with it. */
static Sz_Kind coder_kind(const Coder * c, const char ** arch) {
  const uint8_t * id = c->id;
  *arch = NULL;
  uint64_t v = 0;
  for (unsigned i = 0; i < c->id_len; ++i) {
    v = (v << 8) | id[i];
  }
  switch (v) {
    case 0x00u: return SZM_COPY;
    case 0x21u: return SZM_LZMA2;
    case 0x030101u: return SZM_LZMA;
    case 0x03u: return SZM_DELTA;
    case 0x040202u: return SZM_BZIP2;
    case 0x040108u: return SZM_DEFLATE;
    case 0x040109u: return SZM_DEFLATE64;
    case 0x04u: case 0x03030103u: *arch = "x86"; return SZM_BCJ;
    case 0x05u: case 0x03030205u: *arch = "powerpc"; return SZM_BCJ;
    case 0x06u: case 0x03030401u: *arch = "ia64"; return SZM_BCJ;
    case 0x07u: case 0x03030501u: *arch = "arm"; return SZM_BCJ;
    case 0x08u: case 0x03030701u: *arch = "armthumb"; return SZM_BCJ;
    case 0x09u: case 0x03030805u: *arch = "sparc"; return SZM_BCJ;
    case 0x0Au: *arch = "arm64"; return SZM_BCJ;
    case 0x0Bu: *arch = "riscv"; return SZM_BCJ;
    default: return SZM_UNSUPPORTED;
  }
}

/**
 * Build the decoder chain for one folder.
 *
 * Only a straight chain is built: every coder one stream in and one out, one
 * packed stream, each coder's output bound to the next coder's input. Anything
 * else (BCJ2's four inputs) is ::GARC_ERR_UNSUPPORTED, decided here and not at
 * parse time so that the archive stays listable.
 */
static GARC_Result chain_open(const GARC_Allocator * a, GARC_Stream * stream,
    uint64_t origin, uint64_t stream_size, int have_size, const Streams * s,
    uint32_t fi, Chain * chain) {
  const Folder * f = &s->folders[fi];
  if (f->npacked != 1u || f->nbind + 1u != f->ncoders
      || f->nout != f->ncoders) {
    return GARC_ERR_UNSUPPORTED;
  }
  for (uint32_t i = 0; i < f->ncoders; ++i) {
    const Coder * coder = &s->coders[f->coder0 + i];
    if (coder->num_in != 1u || coder->num_out != 1u) {
      return GARC_ERR_UNSUPPORTED;
    }
  }
  /* Validate every coder before opening anything, so an unsupported one
     is reported without a decoder having been built. */
  for (uint32_t i = 0; i < f->ncoders; ++i) {
    const char * arch = NULL;
    if (coder_kind(&s->coders[f->coder0 + i], &arch) == SZM_UNSUPPORTED) {
      return GARC_ERR_UNSUPPORTED;
    }
  }

  const uint32_t pack = f->pack0;
  if (pack >= s->num_pack) {
    return GARC_ERR_CORRUPT;
  }
  const uint64_t base = origin + GARC_SEVENZ_START_SIZE;
  uint64_t at = s->pack_pos;
  if (s->pack_offsets[pack] > UINT64_MAX - at) {
    return GARC_ERR_CORRUPT;
  }
  at += s->pack_offsets[pack];
  const uint64_t size = s->pack_sizes[pack];
  if (at > UINT64_MAX - base || size > UINT64_MAX - (base + at)) {
    return GARC_ERR_CORRUPT;
  }
  const uint64_t start = base + at;
  if (have_size && start + size > stream_size) {
    return GARC_ERR_CORRUPT;
  }
  GARC_Result result = garc_stream_seek(stream, start);
  if (result != GARC_OK) {
    return result;
  }
  memset(chain, 0, sizeof(*chain));
  result = garc_stream_create_slice_with_allocator(
      stream, size, a, &chain->s[0]);
  if (result != GARC_OK) {
    return result;
  }
  chain->n = 1u;
  chain->top = chain->s[0];

  /* Walk from the packed stream's consumer to the unbound output. */
  uint32_t cur = s->packed[f->packed0];
  for (uint32_t step = 0; step < f->ncoders; ++step) {
    if (cur >= f->ncoders) {
      result = GARC_ERR_CORRUPT;
      break;
    }
    const Coder * coder = &s->coders[f->coder0 + cur];
    const char * arch = NULL;
    const Sz_Kind kind = coder_kind(coder, &arch);
    const uint8_t * props = s->props ? s->props + coder->props_off : NULL;
    const uint64_t out_size = s->unpack[f->unpack0 + cur];
    if (kind != SZM_COPY) {
      gcomp_options_t * o = NULL;
      if (gcomp_options_create(&o) != GCOMP_OK) {
        result = GARC_ERR_OOM;
        break;
      }
      chain->o[chain->no++] = o;
      const char * method = NULL;
      result = GARC_OK;
      switch (kind) {
        case SZM_LZMA:
          method = "lzma";
          result = wrap_lzma(coder, props, out_size, o);
          break;
        case SZM_LZMA2:
          method = "lzma2";
          if (coder->props_len != 1u || props[0] > 40u) {
            result = GARC_ERR_CORRUPT;
          }
          break;
        case SZM_BZIP2:
          method = "bzip2";
          break;
        case SZM_DEFLATE:
          method = "deflate";
          break;
        case SZM_DEFLATE64:
          method = "deflate64";
          break;
        case SZM_DELTA:
          method = "delta";
          if (coder->props_len > 1u) {
            result = GARC_ERR_CORRUPT;
          }
          else if (gcomp_options_set_int64(o, "delta.distance",
                       coder->props_len ? (int64_t)props[0] + 1 : 1)
              != GCOMP_OK) {
            result = GARC_ERR_OOM;
          }
          break;
        case SZM_BCJ: {
          method = "bcj";
          if (gcomp_options_set_string(o, "bcj.arch", arch) != GCOMP_OK) {
            result = GARC_ERR_OOM;
          }
          else if (coder->props_len == 4u) {
            const uint64_t pc = (uint64_t)props[0] | ((uint64_t)props[1] << 8)
                | ((uint64_t)props[2] << 16) | ((uint64_t)props[3] << 24);
            if (gcomp_options_set_uint64(o, "bcj.start_offset", pc)
                != GCOMP_OK) {
              result = GARC_ERR_OOM;
            }
          }
          else if (coder->props_len != 0u) {
            result = GARC_ERR_UNSUPPORTED;
          }
          break;
        }
        default:
          result = GARC_ERR_INTERNAL;
          break;
      }
      if (result != GARC_OK) {
        break;
      }
      // The filters take no `limits.*` keys and do not need them: they write
      // exactly what they read, so the stage beneath is already capped.
      if (kind != SZM_DELTA && kind != SZM_BCJ
          && gcomp_options_set_uint64(o, "limits.max_output_bytes", out_size)
              != GCOMP_OK) {
        result = GARC_ERR_OOM;
        break;
      }
      GARC_Stream * next = NULL;
      result = garc_stream_create_decompress_with_allocator(
          chain->top, method, o, a, &next);
      if (result != GARC_OK) {
        break;
      }
      chain->s[chain->n++] = next;
      chain->top = next;
    }
    /* The coder consuming this one's output, if any. */
    uint32_t following = UINT32_MAX;
    for (uint32_t b = 0; b < f->nbind; ++b) {
      if (s->binds[f->bind0 + b].out_index == cur) {
        following = s->binds[f->bind0 + b].in_index;
      }
    }
    if (following == UINT32_MAX) {
      if (step + 1u != f->ncoders) {
        result = GARC_ERR_CORRUPT;
      }
      break;
    }
    cur = following;
    if (step + 1u == f->ncoders) {
      result = GARC_ERR_CORRUPT; /* a cycle */
    }
  }
  if (result != GARC_OK) {
    chain_destroy(chain);
  }
  return result;
}

/** Decode a folder wholly into memory: used for an encoded header. */
static GARC_Result folder_to_memory(const GARC_Allocator * a,
    GARC_Stream * stream, uint64_t origin, uint64_t stream_size, int have_size,
    const Streams * s, uint32_t fi, uint8_t ** out, size_t * out_len) {
  const Folder * f = &s->folders[fi];
  const uint64_t size = folder_unpack_size(s, f);
  if (size > SZ_MAX_HEADER) {
    return GARC_ERR_LIMIT_EXTRA_BYTES;
  }
  Chain chain;
  GARC_Result result = chain_open(
      a, stream, origin, stream_size, have_size, s, fi, &chain);
  if (result != GARC_OK) {
    return result;
  }
  uint8_t * buf = (uint8_t *)gcu_allocator_malloc(a, size ? (size_t)size : 1u);
  if (!buf) {
    chain_destroy(&chain);
    return GARC_ERR_OOM;
  }
  size_t have = 0;
  while (have < (size_t)size) {
    size_t got = 0;
    result = garc_stream_read(chain.top, buf + have, (size_t)size - have, &got);
    if (result != GARC_OK) {
      break;
    }
    if (!got) {
      result = GARC_ERR_CORRUPT;
      break;
    }
    have += got;
  }
  chain_destroy(&chain);
  if (result == GARC_OK && f->has_crc
      && sz_crc32(buf, (size_t)size) != f->crc) {
    result = GARC_ERR_CORRUPT;
  }
  if (result != GARC_OK) {
    gcu_allocator_free(a, buf);
    return result;
  }
  *out = buf;
  *out_len = (size_t)size;
  return GARC_OK;
}

////////////////////////////////////////////////////////////////////////
// FilesInfo
////////////////////////////////////////////////////////////////////////

/** Append the UTF-8 for a code point; returns bytes written (1 to 4). */
static size_t put_utf8(char * out, uint32_t cp) {
  if (cp < 0x80u) {
    out[0] = (char)cp;
    return 1u;
  }
  if (cp < 0x800u) {
    out[0] = (char)(0xC0u | (cp >> 6));
    out[1] = (char)(0x80u | (cp & 0x3Fu));
    return 2u;
  }
  if (cp < 0x10000u) {
    out[0] = (char)(0xE0u | (cp >> 12));
    out[1] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
    out[2] = (char)(0x80u | (cp & 0x3Fu));
    return 3u;
  }
  out[0] = (char)(0xF0u | (cp >> 18));
  out[1] = (char)(0x80u | ((cp >> 12) & 0x3Fu));
  out[2] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
  out[3] = (char)(0x80u | (cp & 0x3Fu));
  return 4u;
}

static GARC_Result parse_names(Cur * c, uint64_t size,
    const GARC_Allocator * a, struct GARC_SevenZ * z) {
  Cur sub = *c;
  if (size > (uint64_t)cur_left(c)) {
    return GARC_ERR_CORRUPT;
  }
  sub.len = c->pos + (size_t)size;
  uint8_t external = 0;
  TRY(cur_u8(&sub, &external));
  if (external) {
    return GARC_ERR_UNSUPPORTED;
  }
  /* Each UTF-16 unit makes at most three bytes; a pair makes four from two. */
  const size_t raw = cur_left(&sub);
  z->names = (char *)gcu_allocator_malloc(a, raw / 2u * 3u + 1u);
  if (!z->names) {
    return GARC_ERR_OOM;
  }
  size_t at = 0;
  for (uint64_t i = 0; i < z->num_files; ++i) {
    z->files[i].name_off = (uint32_t)at;
    int ended = 0;
    while (cur_left(&sub) >= 2u) {
      uint32_t unit = (uint32_t)sub.p[sub.pos] | ((uint32_t)sub.p[sub.pos + 1u] << 8);
      sub.pos += 2u;
      if (!unit) {
        ended = 1;
        break;
      }
      uint32_t cp = unit;
      if (unit >= 0xD800u && unit < 0xDC00u && cur_left(&sub) >= 2u) {
        const uint32_t low = (uint32_t)sub.p[sub.pos]
            | ((uint32_t)sub.p[sub.pos + 1u] << 8);
        if (low >= 0xDC00u && low < 0xE000u) {
          cp = 0x10000u + ((unit - 0xD800u) << 10) + (low - 0xDC00u);
          sub.pos += 2u;
        }
        else {
          cp = 0xFFFDu;
        }
      }
      else if (unit >= 0xD800u && unit < 0xE000u) {
        cp = 0xFFFDu;
      }
      at += put_utf8(z->names + at, cp);
    }
    if (!ended) {
      return GARC_ERR_CORRUPT;
    }
    z->files[i].name_len = (uint32_t)(at - z->files[i].name_off);
  }
  z->names[at] = '\0';
  z->names_len = at;
  c->pos += (size_t)size;
  return GARC_OK;
}

static GARC_Result parse_files_info(
    Cur * c, const GARC_Allocator * a, struct GARC_SevenZ * z) {
  uint64_t count = 0;
  /* A name costs at least its terminator, two bytes. */
  TRY(cur_count_left(c, &count));
  z->num_files = count;
  z->files = (File *)sz_calloc(a, count, sizeof(File));
  uint8_t * empty_stream = (uint8_t *)sz_calloc(a, count, 1u);
  if (!z->files || !empty_stream) {
    gcu_allocator_free(a, empty_stream);
    return GARC_ERR_OOM;
  }
  uint64_t num_empty = 0;
  uint32_t seen = 0;
  GARC_Result result = GARC_OK;
  uint8_t * scratch = NULL;
  for (;;) {
    uint8_t type = 0;
    result = cur_u8(c, &type);
    if (result != GARC_OK || type == SZ_END) {
      break;
    }
    uint64_t size = 0;
    result = cur_number(c, &size);
    if (result != GARC_OK) {
      break;
    }
    if (size > (uint64_t)cur_left(c)) {
      result = GARC_ERR_CORRUPT;
      break;
    }
    const size_t end = c->pos + (size_t)size;
    Cur p = *c;
    p.len = end;
    // Only the properties acted on count: 7-Zip writes kDummy padding before
    // the names and before each time block, so a repeat there is ordinary.
    if (type == SZ_EMPTY_STREAM || type == SZ_EMPTY_FILE || type == SZ_ANTI
        || type == SZ_NAMES || type == SZ_MTIME || type == SZ_WIN_ATTRIBUTES) {
      if (seen & (1u << type)) {
        result = GARC_ERR_CORRUPT; /* a property twice would count twice */
        break;
      }
      seen |= 1u << type;
    }
    switch (type) {
      case SZ_EMPTY_STREAM:
        result = read_bits(&p, count, empty_stream);
        if (result == GARC_OK) {
          for (uint64_t i = 0; i < count; ++i) {
            if (empty_stream[i]) {
              ++num_empty;
              z->files[i].flags |= SZF_EMPTY_STREAM;
            }
          }
        }
        break;
      case SZ_EMPTY_FILE:
      case SZ_ANTI: {
        scratch = (uint8_t *)sz_calloc(a, num_empty, 1u);
        if (!scratch) {
          result = GARC_ERR_OOM;
          break;
        }
        result = read_bits(&p, num_empty, scratch);
        if (result == GARC_OK) {
          uint64_t k = 0;
          for (uint64_t i = 0; i < count; ++i) {
            if (empty_stream[i]) {
              if (scratch[k++]) {
                z->files[i].flags
                    |= (type == SZ_EMPTY_FILE ? SZF_EMPTY_FILE : SZF_ANTI);
              }
            }
          }
        }
        gcu_allocator_free(a, scratch);
        scratch = NULL;
        break;
      }
      case SZ_NAMES:
        result = parse_names(&p, size, a, z);
        break;
      case SZ_MTIME:
      case SZ_WIN_ATTRIBUTES: {
        scratch = (uint8_t *)sz_calloc(a, count, 1u);
        if (!scratch) {
          result = GARC_ERR_OOM;
          break;
        }
        uint8_t external = 0;
        result = read_defined(&p, count, scratch);
        if (result == GARC_OK) {
          result = cur_u8(&p, &external);
        }
        if (result == GARC_OK && external) {
          result = GARC_ERR_UNSUPPORTED;
        }
        for (uint64_t i = 0; result == GARC_OK && i < count; ++i) {
          if (!scratch[i]) {
            continue;
          }
          if (type == SZ_MTIME) {
            result = cur_u64(&p, &z->files[i].mtime);
            z->files[i].flags |= SZF_HAS_MTIME;
          }
          else {
            result = cur_u32(&p, &z->files[i].attrib);
            z->files[i].flags |= SZF_HAS_ATTRIB;
          }
        }
        gcu_allocator_free(a, scratch);
        scratch = NULL;
        break;
      }
      default:
        /* CTime, ATime, StartPos, Comment, Dummy and anything unknown are
           skipped by their stated size. */
        break;
    }
    if (result != GARC_OK) {
      break;
    }
    c->pos = end;
  }
  gcu_allocator_free(a, scratch);
  gcu_allocator_free(a, empty_stream);
  if (result == GARC_OK && count && !z->names) {
    result = GARC_ERR_CORRUPT;
  }
  return result;
}

////////////////////////////////////////////////////////////////////////
// Header
////////////////////////////////////////////////////////////////////////

static GARC_Result parse_header(Cur * c, const GARC_Allocator * a,
    struct GARC_SevenZ * z) {
  /* Each of these appears at most once. A second would overwrite pointers the
     first allocated, which is a leak, and means nothing to the format. */
  int saw_main = 0;
  int saw_files = 0;
  for (;;) {
    uint8_t id = 0;
    TRY(cur_u8(c, &id));
    if (id == SZ_END) {
      break;
    }
    if (id == SZ_ARCHIVE_PROPERTIES) {
      for (;;) {
        uint8_t type = 0;
        TRY(cur_u8(c, &type));
        if (type == SZ_END) {
          break;
        }
        uint64_t size = 0;
        TRY(cur_number(c, &size));
        TRY(cur_skip(c, size));
      }
    }
    else if (id == SZ_ADDITIONAL_STREAMS_INFO) {
      Streams ignored;
      memset(&ignored, 0, sizeof(ignored));
      GARC_Result result = parse_streams_info(c, a, &ignored);
      streams_free(a, &ignored);
      TRY(result);
    }
    else if (id == SZ_MAIN_STREAMS_INFO) {
      if (saw_main++) {
        return GARC_ERR_CORRUPT;
      }
      TRY(parse_streams_info(c, a, &z->main));
    }
    else if (id == SZ_FILES_INFO) {
      if (saw_files++) {
        return GARC_ERR_CORRUPT;
      }
      TRY(parse_files_info(c, a, z));
    }
    else {
      return GARC_ERR_CORRUPT;
    }
  }
  return GARC_OK;
}

/** Hand each non-empty file its substream, and prove the counts agree. */
static GARC_Result assign_substreams(struct GARC_SevenZ * z) {
  uint64_t next = 0;
  for (uint64_t i = 0; i < z->num_files; ++i) {
    File * file = &z->files[i];
    if (file->flags & SZF_EMPTY_STREAM) {
      continue;
    }
    if (next >= z->main.num_sub) {
      return GARC_ERR_CORRUPT;
    }
    file->sub = next++;
  }
  if (next != z->main.num_sub) {
    return GARC_ERR_CORRUPT;
  }
  for (uint32_t i = 0; i < z->main.num_folders; ++i) {
    const Folder * f = &z->main.folders[i];
    uint64_t sum = 0;
    for (uint32_t j = 0; j < f->nsub; ++j) {
      sum += z->main.sub_sizes[f->sub0 + j];
    }
    if (f->nsub && sum != folder_unpack_size(&z->main, f)) {
      return GARC_ERR_CORRUPT;
    }
  }
  return GARC_OK;
}

int garc_sevenz_identify(const uint8_t * bytes, size_t length) {
  return length >= GARC_SEVENZ_SIGNATURE_SIZE
      && memcmp(bytes, SZ_SIGNATURE, GARC_SEVENZ_SIGNATURE_SIZE) == 0;
}

static GARC_Result read_exact(
    GARC_Stream * stream, void * buffer, size_t length) {
  size_t have = 0;
  while (have < length) {
    size_t got = 0;
    GARC_Result result
        = garc_stream_read(stream, (uint8_t *)buffer + have, length - have, &got);
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

/** Whether @p bytes start the way an executable does. */
static int sz_looks_executable(const uint8_t * bytes, size_t length) {
  if (length < 4u) {
    return 0;
  }
  static const uint8_t elf[4] = {0x7fu, 'E', 'L', 'F'};
  static const uint8_t macho[4][4] = {{0xfeu, 0xedu, 0xfau, 0xceu},
      {0xfeu, 0xedu, 0xfau, 0xcfu}, {0xceu, 0xfau, 0xedu, 0xfeu},
      {0xcfu, 0xfau, 0xedu, 0xfeu}};
  if ((bytes[0] == 'M' && bytes[1] == 'Z') || memcmp(bytes, elf, 4u) == 0) {
    return 1;
  }
  for (size_t i = 0; i < 4u; ++i) {
    if (memcmp(bytes, macho[i], 4u) == 0) {
      return 1;
    }
  }
  return 0;
}

GARC_Result garc_sevenz_locate_sfx(GARC_Archive * archive, uint64_t * out_offset) {
  if (!sz_looks_executable(archive->peek, archive->peek_length)) {
    return GARC_ERR_FORMAT;
  }
  GARC_Stream * stream = archive->stream;
  uint64_t size = 0;
  GARC_Result result = garc_stream_size(stream, &size);
  if (result != GARC_OK) {
    return GARC_ERR_FORMAT; // no size, no way to check a next header
  }
  const uint64_t start = archive->start_offset;
  const uint64_t end = size - start < GARC_SEVENZ_SFX_SCAN
      ? size : start + GARC_SEVENZ_SFX_SCAN;
  uint8_t window[65536 + GARC_SEVENZ_START_SIZE];
  uint64_t at = start;
  while (at < end) {
    size_t want = sizeof(window);
    if ((uint64_t)want > size - at) {
      want = (size_t)(size - at);
    }
    result = garc_stream_seek(stream, at);
    if (result == GARC_OK) {
      result = read_exact(stream, window, want);
    }
    if (result != GARC_OK) {
      return result;
    }
    // Every position whose signature starts before the scan's end; the start
    // header has to fit in what was read for it to be checked here.
    for (size_t i = 0; i + GARC_SEVENZ_START_SIZE <= want; ++i) {
      if (at + i >= end) {
        break;
      }
      const uint8_t * header = window + i;
      if (memcmp(header, SZ_SIGNATURE, GARC_SEVENZ_SIGNATURE_SIZE) != 0
          || header[6] != 0u || at + i == start) {
        continue;
      }
      // The same fields garc_sevenz_open() reads, read the same way.
      Cur sc = {header, GARC_SEVENZ_START_SIZE, 8u};
      uint32_t start_crc = 0;
      uint64_t next_off = 0;
      uint64_t next_size = 0;
      (void)cur_u32(&sc, &start_crc);
      (void)cur_u64(&sc, &next_off);
      (void)cur_u64(&sc, &next_size);
      if (sz_crc32(header + 12u, 20u) != start_crc) {
        continue;
      }
      const uint64_t base = at + i + GARC_SEVENZ_START_SIZE;
      if (next_off > size - base || next_size > size - base - next_off) {
        continue;
      }
      *out_offset = at + i - start;
      return GARC_OK;
    }
    if (want < sizeof(window)) {
      break;
    }
    // Overlap by a start header, so a signature across the boundary is seen.
    at += (uint64_t)(want - GARC_SEVENZ_START_SIZE + 1u);
  }
  return GARC_ERR_FORMAT;
}

GARC_Result garc_sevenz_open(GARC_Archive * archive) {
  const GARC_Allocator * a = archive->allocator;
  GARC_Stream * stream = archive->stream;
  struct GARC_SevenZ * z
      = (struct GARC_SevenZ *)gcu_allocator_calloc(a, 1, sizeof(*z));
  if (!z) {
    return GARC_ERR_OOM;
  }
  archive->sevenz = z;
  z->open_folder = -1;
  // A self-extractor's stub, if one was found, is in front of the archive.
  z->origin = archive->start_offset + archive->sevenz_sfx;
  archive->peek_length = 0;
  archive->peek_consumed = 0;
  if (!garc_stream_is_seekable(stream)) {
    return GARC_ERR_NOT_SEEKABLE;
  }
  z->have_size = garc_stream_size(stream, &z->stream_size) == GARC_OK;

  GARC_Result result = garc_stream_seek(stream, z->origin);
  if (result != GARC_OK) {
    return result;
  }
  uint8_t start[GARC_SEVENZ_START_SIZE];
  result = read_exact(stream, start, sizeof(start));
  if (result != GARC_OK) {
    return result == GARC_ERR_CORRUPT ? GARC_ERR_CORRUPT : result;
  }
  if (start[6] != 0u) {
    return GARC_ERR_UNSUPPORTED; /* major version other than 0 */
  }
  Cur sc = {start, sizeof(start), 8u};
  uint32_t start_crc = 0;
  uint64_t next_off = 0;
  uint64_t next_size = 0;
  uint32_t next_crc = 0;
  (void)cur_u32(&sc, &start_crc);
  (void)cur_u64(&sc, &next_off);
  (void)cur_u64(&sc, &next_size);
  (void)cur_u32(&sc, &next_crc);
  if (sz_crc32(start + 12u, 20u) != start_crc) {
    return GARC_ERR_CORRUPT;
  }
  if (!next_size) {
    /* An archive of nothing. */
    if (next_off || next_crc) {
      return GARC_ERR_CORRUPT;
    }
    return GARC_OK;
  }
  if (next_size > SZ_MAX_HEADER) {
    return GARC_ERR_LIMIT_EXTRA_BYTES;
  }
  const uint64_t base = z->origin + GARC_SEVENZ_START_SIZE;
  if (next_off > UINT64_MAX - base || (z->have_size
          && (base + next_off > z->stream_size
              || next_size > z->stream_size - (base + next_off)))) {
    return GARC_ERR_CORRUPT;
  }
  uint8_t * buf = (uint8_t *)gcu_allocator_malloc(a, (size_t)next_size);
  if (!buf) {
    return GARC_ERR_OOM;
  }
  size_t len = (size_t)next_size;
  result = garc_stream_seek(stream, base + next_off);
  if (result == GARC_OK) {
    result = read_exact(stream, buf, len);
  }
  if (result == GARC_OK && sz_crc32(buf, len) != next_crc) {
    result = GARC_ERR_CORRUPT;
  }

  for (unsigned depth = 0; result == GARC_OK; ++depth) {
    Cur c = {buf, len, 0};
    uint8_t id = 0;
    result = cur_u8(&c, &id);
    if (result != GARC_OK) {
      break;
    }
    if (id == SZ_HEADER) {
      result = parse_header(&c, a, z);
      if (result == GARC_OK) {
        result = assign_substreams(z);
      }
      break;
    }
    if (id != SZ_ENCODED_HEADER || depth >= SZ_MAX_HEADER_DEPTH) {
      result = GARC_ERR_CORRUPT;
      break;
    }
    Streams enc;
    memset(&enc, 0, sizeof(enc));
    result = parse_streams_info(&c, a, &enc);
    uint8_t * decoded = NULL;
    size_t decoded_len = 0;
    if (result == GARC_OK && !enc.num_folders) {
      result = GARC_ERR_CORRUPT;
    }
    if (result == GARC_OK) {
      result = folder_to_memory(a, stream, z->origin, z->stream_size,
          z->have_size, &enc, 0, &decoded, &decoded_len);
    }
    streams_free(a, &enc);
    gcu_allocator_free(a, buf);
    buf = decoded;
    len = decoded_len;
    if (result != GARC_OK) {
      buf = NULL;
    }
  }
  gcu_allocator_free(a, buf);
  return result;
}

////////////////////////////////////////////////////////////////////////
// Walking
////////////////////////////////////////////////////////////////////////

static void close_folder(struct GARC_SevenZ * z) {
  chain_destroy(&z->chain);
  z->open_folder = -1;
  z->folder_pos = 0;
}

/** Read from the open folder's decoded stream, never past its end. */
static GARC_Result folder_read(struct GARC_SevenZ * z, void * buffer,
    size_t want, size_t * out_read) {
  if ((uint64_t)want > z->folder_size - z->folder_pos) {
    want = (size_t)(z->folder_size - z->folder_pos);
  }
  *out_read = 0;
  if (!want) {
    return GARC_OK;
  }
  size_t got = 0;
  GARC_Result result = garc_stream_read(z->chain.top, buffer, want, &got);
  if (result != GARC_OK) {
    return result;
  }
  if (!got) {
    return GARC_ERR_CORRUPT;
  }
  z->folder_pos += got;
  *out_read = got;
  return GARC_OK;
}

static GARC_Result discard(struct GARC_SevenZ * z, uint64_t n) {
  uint8_t scratch[8192];
  while (n) {
    size_t got = 0;
    const size_t want = n < sizeof(scratch) ? (size_t)n : sizeof(scratch);
    GARC_Result result = folder_read(z, scratch, want, &got);
    if (result != GARC_OK) {
      return result;
    }
    if (!got) {
      return GARC_ERR_CORRUPT;
    }
    n -= got;
  }
  return GARC_OK;
}

static void fill_time(GARC_Member * m, uint64_t ticks) {
  const uint64_t seconds = ticks / 10000000u;
  m->mtime_seconds = (int64_t)seconds - SZ_EPOCH_GAP;
  m->mtime_nanoseconds = (uint32_t)((ticks % 10000000u) * 100u);
  m->mtime_source = GARC_TIME_FILETIME;
}

GARC_Result garc_sevenz_next(GARC_Archive * archive) {
  struct GARC_SevenZ * z = archive->sevenz;
  const GARC_Allocator * a = archive->allocator;
  GARC_Member * m = &archive->member;

  /* Whatever the caller left unread of the last member is consumed so the
     folder's cursor is where the next member starts. */
  if (archive->data_remaining && z->open_folder >= 0) {
    GARC_Result result = discard(z, archive->data_remaining);
    archive->data_remaining = 0;
    z->crc_active = 0;
    if (result != GARC_OK) {
      return result;
    }
  }
  z->crc_active = 0;
  archive->data_refusal = GARC_OK;

  if (z->next_file >= z->num_files) {
    close_folder(z);
    archive->at_end = 1;
    return GARC_END;
  }
  const File * file = &z->files[z->next_file];
  memset(m, 0, sizeof(*m));
  m->name = z->names + file->name_off;
  m->name_length = file->name_len;
  m->name_encoding = GARC_NAME_UTF8;
  m->header_offset = z->next_file;

  const int has_stream = !(file->flags & SZF_EMPTY_STREAM);
  uint64_t size = 0;
  if (has_stream) {
    size = z->main.sub_sizes[file->sub];
  }
  m->size = size;

  if (file->flags & SZF_HAS_MTIME) {
    fill_time(m, file->mtime);
  }
  m->type = GARC_MEMBER_FILE;
  uint32_t attrib = (file->flags & SZF_HAS_ATTRIB) ? file->attrib : 0u;
  if ((file->flags & SZF_EMPTY_STREAM) && !(file->flags & SZF_EMPTY_FILE)) {
    m->type = GARC_MEMBER_DIRECTORY;
  }
  else if (attrib & SZ_ATTR_DIRECTORY) {
    m->type = GARC_MEMBER_DIRECTORY;
  }
  if (attrib & SZ_ATTR_UNIX_EXTENSION) {
    const uint32_t mode = attrib >> 16;
    switch (mode & 0170000u) {
      case 0040000u: m->type = GARC_MEMBER_DIRECTORY; break;
      case 0120000u: m->type = GARC_MEMBER_SYMLINK; break;
      case 0010000u: m->type = GARC_MEMBER_FIFO; break;
      case 0020000u: m->type = GARC_MEMBER_CHAR_DEVICE; break;
      case 0060000u: m->type = GARC_MEMBER_BLOCK_DEVICE; break;
      case 0100000u: case 0u: break;
      default: m->type = GARC_MEMBER_OTHER; break;
    }
    if (mode) {
      m->mode = mode;
      m->mode_valid = 1;
    }
  }
  if (file->flags & SZF_ANTI) {
    m->type = GARC_MEMBER_OTHER;
  }
  if (m->type == GARC_MEMBER_DIRECTORY && has_stream) {
    /* A directory that claims bytes: not a thing the format means. */
    return GARC_ERR_CORRUPT;
  }

  GARC_Result result = GARC_OK;
  if (has_stream) {
    /* Find the folder this substream is in; they run in order. */
    while (z->folder_cursor < z->main.num_folders
        && file->sub >= z->main.folders[z->folder_cursor].sub0
                + z->main.folders[z->folder_cursor].nsub) {
      ++z->folder_cursor;
    }
    if (z->folder_cursor >= z->main.num_folders) {
      return GARC_ERR_CORRUPT;
    }
    if (z->open_folder != (int)z->folder_cursor) {
      close_folder(z);
      const Folder * f = &z->main.folders[z->folder_cursor];
      z->folder_size = folder_unpack_size(&z->main, f);
      result = chain_open(a, archive->stream, z->origin, z->stream_size,
          z->have_size, &z->main, z->folder_cursor, &z->chain);
      if (result == GARC_ERR_UNSUPPORTED) {
        /* The metadata is good; the data is not readable. */
        archive->data_refusal = GARC_ERR_UNSUPPORTED;
        result = GARC_OK;
      }
      else if (result != GARC_OK) {
        return result;
      }
      else {
        z->open_folder = (int)z->folder_cursor;
        z->folder_pos = 0;
      }
    }
  }

  if (m->type == GARC_MEMBER_SYMLINK && has_stream && size
      && archive->data_refusal == GARC_OK) {
    const size_t cap = archive->limits.max_name_bytes
        ? archive->limits.max_name_bytes : (size_t)65535u;
    if (size <= cap) {
      result = garc_buffer_grow(a, &z->link, (size_t)size);
      if (result != GARC_OK) {
        return result;
      }
      /* Read it, and keep the bytes for the caller to read again by reading
         the member: a symlink's target is its data. */
      size_t have = 0;
      while (have < (size_t)size) {
        size_t got = 0;
        result = folder_read(z, z->link.bytes + have, (size_t)size - have, &got);
        if (result != GARC_OK) {
          return result;
        }
        have += got;
      }
      z->link.length = have;
      z->link.bytes[have] = '\0';
      if (z->main.sub_has_crc[file->sub]
          && sz_crc32((const uint8_t *)z->link.bytes, have)
              != z->main.sub_crc[file->sub]) {
        return GARC_ERR_CORRUPT;
      }
      m->link_target = z->link.bytes;
      m->link_target_length = have;
      /* Consumed: there is nothing left to read for this member. */
      m->size = 0;
      size = 0;
    }
  }

  result = garc_reader_account(archive);
  if (result != GARC_OK) {
    return result;
  }
  ++z->next_file;
  archive->data_remaining = (archive->data_refusal == GARC_OK) ? size : 0u;
  if (has_stream && size && archive->data_refusal == GARC_OK) {
    z->crc = GCOMP_CRC32_INIT;
    z->crc_active = z->main.sub_has_crc[file->sub];
    z->expect_crc = z->main.sub_crc[file->sub];
  }
  else if (has_stream && !size && archive->data_refusal == GARC_OK
      && m->type != GARC_MEMBER_SYMLINK && z->main.sub_has_crc[file->sub]
      && z->main.sub_crc[file->sub] != 0u) {
    return GARC_ERR_CORRUPT; /* an empty substream with a non-empty CRC */
  }
  return GARC_OK;
}

GARC_Result garc_sevenz_read(GARC_Archive * archive, void * buffer,
    size_t capacity, size_t * out_read) {
  struct GARC_SevenZ * z = archive->sevenz;
  *out_read = 0;
  if (!archive->data_remaining) {
    if (z->crc_active) {
      z->crc_active = 0;
      if (gcomp_crc32_finalize(z->crc) != z->expect_crc) {
        return GARC_ERR_CORRUPT;
      }
    }
    return GARC_OK;
  }
  if (!capacity) {
    return GARC_OK;
  }
  size_t want = capacity;
  if ((uint64_t)want > archive->data_remaining) {
    want = (size_t)archive->data_remaining;
  }
  size_t got = 0;
  GARC_Result result = folder_read(z, buffer, want, &got);
  if (result != GARC_OK) {
    return result;
  }
  if (z->crc_active) {
    z->crc = gcomp_crc32_update(z->crc, (const uint8_t *)buffer, got);
  }
  archive->data_remaining -= got;
  *out_read = got;
  return GARC_OK;
}

GARC_Result garc_sevenz_skip(GARC_Archive * archive) {
  struct GARC_SevenZ * z = archive->sevenz;
  /* The folder cursor is moved lazily by the next call to garc_sevenz_next(),
     which discards what is left. */
  z->crc_active = 0;
  return GARC_OK;
}

void garc_sevenz_rewind(GARC_Archive * archive) {
  struct GARC_SevenZ * z = archive->sevenz;
  if (!z) {
    return;
  }
  close_folder(z);
  z->next_file = 0;
  z->folder_cursor = 0;
  z->crc_active = 0;
}

void garc_sevenz_release(GARC_Archive * archive) {
  struct GARC_SevenZ * z = archive->sevenz;
  const GARC_Allocator * a = archive->allocator;
  if (!z) {
    return;
  }
  chain_destroy(&z->chain);
  streams_free(a, &z->main);
  gcu_allocator_free(a, z->files);
  gcu_allocator_free(a, z->names);
  garc_buffer_free(a, &z->link);
  gcu_allocator_free(a, z);
  archive->sevenz = NULL;
}

void garc_sevenz_counts(
    const GARC_Archive * archive, uint64_t * out_folders, uint64_t * out_files) {
  const struct GARC_SevenZ * z = archive->sevenz;
  *out_folders = z ? z->main.num_folders : 0u;
  *out_files = z ? z->num_files : 0u;
}

////////////////////////////////////////////////////////////////////////
// Carrying a header into an append
////////////////////////////////////////////////////////////////////////

/** A copy of @p count items of @p size bytes, or NULL; a count of 0 is one byte. */
static void * sz_copy(const GARC_Allocator * a, const void * from,
    uint64_t count, size_t size) {
  void * to = sz_calloc(a, count, size);
  if (to && count && from) {
    memcpy(to, from, (size_t)count * size);
  }
  return to;
}

void garc_sevenz_carry_free(GARC_SevenZ_Carry * carry,
    const GARC_Allocator * allocator) {
  if (!carry) {
    return;
  }
  gcu_allocator_free(allocator, carry->pack_sizes);
  gcu_allocator_free(allocator, carry->folders);
  gcu_allocator_free(allocator, carry->coders);
  gcu_allocator_free(allocator, carry->binds);
  gcu_allocator_free(allocator, carry->packed);
  gcu_allocator_free(allocator, carry->props);
  gcu_allocator_free(allocator, carry->unpack_sizes);
  gcu_allocator_free(allocator, carry->sub_sizes);
  gcu_allocator_free(allocator, carry->sub_has_crc);
  gcu_allocator_free(allocator, carry->sub_crc);
  gcu_allocator_free(allocator, carry->files);
  gcu_allocator_free(allocator, carry->names);
  gcu_allocator_free(allocator, carry);
}

GARC_Result garc_sevenz_carry(const GARC_Archive * archive,
    const GARC_Allocator * allocator, GARC_SevenZ_Carry ** out) {
  if (!archive || !out || archive->format != GARC_FORMAT_SEVENZ
      || !archive->sevenz) {
    return GARC_ERR_INVALID;
  }
  const struct GARC_SevenZ * z = archive->sevenz;
  const Streams * s = &z->main;
  const GARC_Allocator * a = allocator;
  GARC_SevenZ_Carry * c
      = (GARC_SevenZ_Carry *)gcu_allocator_calloc(a, 1, sizeof(*c));
  if (!c) {
    return GARC_ERR_OOM;
  }
  c->num_pack = s->num_pack;
  c->data_end = s->pack_pos;
  if (s->num_pack) {
    c->data_end += s->pack_offsets[s->num_pack - 1u]
        + s->pack_sizes[s->num_pack - 1u];
  }
  c->pack_sizes = (uint64_t *)sz_copy(a, s->pack_sizes, s->num_pack, sizeof(uint64_t));
  c->num_folders = s->num_folders;
  c->folders = (GARC_SevenZ_Carry_Folder *)sz_calloc(
      a, s->num_folders, sizeof(GARC_SevenZ_Carry_Folder));
  c->coders = (GARC_SevenZ_Carry_Coder *)sz_calloc(
      a, s->num_coders, sizeof(GARC_SevenZ_Carry_Coder));
  c->binds = (uint32_t *)sz_calloc(a, (uint64_t)s->num_binds * 2u, sizeof(uint32_t));
  c->packed = (uint32_t *)sz_copy(a, s->packed, s->num_packed, sizeof(uint32_t));
  c->props = (uint8_t *)sz_copy(a, s->props, s->props_len, 1u);
  c->unpack_sizes = (uint64_t *)sz_copy(a, s->unpack, s->num_unpack, sizeof(uint64_t));
  c->num_sub = s->num_sub;
  c->sub_sizes = (uint64_t *)sz_copy(a, s->sub_sizes, s->num_sub, sizeof(uint64_t));
  c->sub_has_crc = (uint8_t *)sz_copy(a, s->sub_has_crc, s->num_sub, 1u);
  c->sub_crc = (uint32_t *)sz_copy(a, s->sub_crc, s->num_sub, sizeof(uint32_t));
  c->num_files = z->num_files;
  c->files = (GARC_SevenZ_Carry_File *)sz_calloc(
      a, z->num_files, sizeof(GARC_SevenZ_Carry_File));
  c->names = (char *)sz_copy(a, z->names, z->names_len, 1u);
  if (!c->pack_sizes || !c->folders || !c->coders || !c->binds || !c->packed
      || !c->props || !c->unpack_sizes || !c->sub_sizes || !c->sub_has_crc
      || !c->sub_crc || !c->files || !c->names) {
    garc_sevenz_carry_free(c, a);
    return GARC_ERR_OOM;
  }
  for (uint32_t i = 0; i < s->num_folders; ++i) {
    const Folder * f = &s->folders[i];
    GARC_SevenZ_Carry_Folder * to = &c->folders[i];
    to->coder0 = f->coder0;
    to->ncoders = f->ncoders;
    to->bind0 = f->bind0;
    to->nbind = f->nbind;
    to->packed0 = f->packed0;
    to->npacked = f->npacked;
    to->unpack0 = f->unpack0;
    to->nout = f->nout;
    to->nsub = f->nsub;
    to->has_crc = f->has_crc;
    to->crc = f->crc;
  }
  for (uint32_t i = 0; i < s->num_coders; ++i) {
    const Coder * from = &s->coders[i];
    GARC_SevenZ_Carry_Coder * to = &c->coders[i];
    memcpy(to->id, from->id, sizeof(to->id));
    to->id_len = from->id_len;
    to->num_in = from->num_in;
    to->num_out = from->num_out;
    to->props_off = from->props_off;
    to->props_len = from->props_len;
  }
  for (uint32_t i = 0; i < s->num_binds; ++i) {
    c->binds[2u * i] = s->binds[i].in_index;
    c->binds[2u * i + 1u] = s->binds[i].out_index;
  }
  for (uint64_t i = 0; i < z->num_files; ++i) {
    const File * from = &z->files[i];
    GARC_SevenZ_Carry_File * to = &c->files[i];
    to->name_off = from->name_off;
    to->name_len = from->name_len;
    to->mtime = from->mtime;
    to->attrib = from->attrib;
    to->flags = (uint8_t)(((from->flags & SZF_EMPTY_STREAM)
                              ? GARC_SEVENZ_CARRY_EMPTY_STREAM : 0u)
        | ((from->flags & SZF_EMPTY_FILE) ? GARC_SEVENZ_CARRY_EMPTY_FILE : 0u)
        | ((from->flags & SZF_ANTI) ? GARC_SEVENZ_CARRY_ANTI : 0u)
        | ((from->flags & SZF_HAS_MTIME) ? GARC_SEVENZ_CARRY_HAS_MTIME : 0u)
        | ((from->flags & SZF_HAS_ATTRIB) ? GARC_SEVENZ_CARRY_HAS_ATTRIB : 0u));
  }
  *out = c;
  return GARC_OK;
}
