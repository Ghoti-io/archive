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
#include <ghoti.io/security/aes.h>
#include <ghoti.io/security/random.h>
#include <ghoti.io/security/secret.h>
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
/** The LZMA dictionary for BCJ2's CALL and JUMP streams: 1 MiB, ample for them. */
#define SZW_SIDE_DICT_SIZE (1024u * 1024u)

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
/**
 * A folder written: its packed streams - one, or BCJ2's four in the order
 * MAIN, range coder, CALL, JUMP - and the sizes the header lists for it.
 */
typedef struct {
  uint64_t pack_size;   ///< Bytes written to the archive for this folder.
  uint64_t unpack_size; ///< Bytes the folder decodes to.
  uint32_t nsub;        ///< How many members share the folder.
  uint64_t coded_size;  ///< With encryption: the compressed bytes AES decodes to.
  uint8_t iv[16];       ///< With encryption: this folder's IV.
  GARC_SevenZ_Filter filter; ///< The filter it was written through.
  uint64_t main_raw;    ///< What the main compressor was given.
  uint64_t side_pack[3]; ///< BCJ2: the range coder's, CALL's and JUMP's packs.
  uint64_t side_coded[3]; ///< BCJ2: what each decodes to, under AES.
  uint64_t side_raw[2]; ///< BCJ2: CALL and JUMP before compression.
  uint8_t side_iv[3][16]; ///< BCJ2: the IVs of those three, under AES.
} SzwFolder;

/** CBC over one packed stream. */
typedef struct {
  uint8_t iv[16];      ///< Its IV.
  uint8_t chain[16];   ///< The last ciphertext block.
  uint8_t partial[16]; ///< Plaintext short of a block.
  size_t partial_len;  ///< How many.
  uint64_t coded;      ///< Plaintext bytes given: what AES decodes to.
} Szw_Cipher;

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
  /* encryption, when the options have a password */
  int encrypting;        ///< Whether folders, and perhaps the header, are AES.
  unsigned key_power;    ///< The cycle power the key was derived at.
  GSEC_Aes aes;          ///< The key schedule, when @ref encrypting.
  Szw_Cipher main;       ///< The open folder's first packed stream's CBC.
  uint8_t * cipher;      ///< Ciphertext on its way to the sink.
  /* filters, for the open folder */
  gcomp_encoder_t * filter; ///< A branch filter in front of the compressor.
  gcomp_options_t * filter_options; ///< Its options.
  uint8_t * filtered;    ///< Its output, on its way to the compressor.
  GARC_SevenZ_Bcj2_Enc * bcj2; ///< BCJ2, when that is the filter.
  gcomp_encoder_t * side[2]; ///< CALL's and JUMP's compressors, or NULL: copy.
  gcomp_options_t * side_options[2]; ///< Their options.
  GARC_Buffer side_out[2]; ///< CALL and JUMP, compressed, held for the end.
  uint64_t side_raw[2];  ///< CALL's and JUMP's sizes before compression.
  GARC_Buffer rc;        ///< BCJ2's range-coder stream, held for the end.
  uint64_t main_raw;     ///< Bytes given to the main compressor this folder.
  GARC_Result bcj2_status; ///< The first failure inside BCJ2's sink.
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

/** The cycle power 7-Zip writes, and what ::GARC_Writer_Options.sevenz_key_power 0 means. */
#define SZW_KEY_POWER 19u

/** Derive the key from the options' password, if there is one. */
static GARC_Result szw_key(GARC_Writer * writer) {
  struct GARC_SevenZ_Write * z = writer->sevenz;
  const GARC_Allocator * a = writer->allocator;
  if (!writer->options.password) {
    return GARC_OK;
  }
  uint8_t * utf16 = NULL;
  size_t utf16_len = 0;
  GARC_Result result = garc_sevenz_password_utf16(a, writer->options.password,
      writer->options.password_length, &utf16, &utf16_len);
  if (result != GARC_OK) {
    return result;
  }
  z->key_power = writer->options.sevenz_key_power
      ? writer->options.sevenz_key_power : SZW_KEY_POWER;
  uint8_t key[32];
  result = garc_sevenz_aes_derive(
      a, utf16, utf16_len, z->key_power, NULL, 0, key);
  gsec_wipe(utf16, utf16_len ? utf16_len : 1u);
  gcu_allocator_free(a, utf16);
  if (result == GARC_OK
      && gsec_aes_encrypt_init(&z->aes, key, sizeof(key)) != GSEC_OK) {
    result = GARC_ERR_INTERNAL;
  }
  gsec_wipe(key, sizeof(key));
  if (result != GARC_OK) {
    return result;
  }
  z->cipher = (uint8_t *)gcu_allocator_malloc(a, SZW_BUFFER);
  if (!z->cipher) {
    (void)gsec_aes_encrypt_wipe(&z->aes);
    return GARC_ERR_OOM;
  }
  z->encrypting = 1;
  return GARC_OK;
}

/** A fresh IV: 16 bytes from the kernel's generator. */
static GARC_Result szw_iv(uint8_t iv[16]) {
  return gsec_random_bytes(iv, 16u, NULL) == GSEC_OK ? GARC_OK : GARC_ERR_IO;
}

/**
 * Start a packed stream's CBC: a fresh IV, and nothing pending. Each AES coder
 * - a folder's, each of BCJ2's four, the header's - has its own.
 */
static GARC_Result szw_cipher_begin(Szw_Cipher * c) {
  GARC_Result result = szw_iv(c->iv);
  memcpy(c->chain, c->iv, sizeof(c->chain));
  c->partial_len = 0;
  c->coded = 0;
  return result;
}

/**
 * Encrypt @p n bytes of a packed stream with CBC and write the whole blocks,
 * counting them into @p pack; what is short of a block waits for more, or for
 * ::szw_cipher_finish().
 */
static GARC_Result szw_encrypt(GARC_Writer * writer, Szw_Cipher * c,
    const uint8_t * bytes, size_t n, uint64_t * pack) {
  struct GARC_SevenZ_Write * z = writer->sevenz;
  c->coded += n;
  size_t have = 0;
  while (n) {
    if (c->partial_len || n < 16u) {
      size_t take = 16u - c->partial_len;
      if (take > n) {
        take = n;
      }
      memcpy(c->partial + c->partial_len, bytes, take);
      c->partial_len += take;
      bytes += take;
      n -= take;
      if (c->partial_len < 16u) {
        break;
      }
      memcpy(z->cipher + have, c->partial, 16u);
      c->partial_len = 0;
    }
    else {
      memcpy(z->cipher + have, bytes, 16u);
      bytes += 16u;
      n -= 16u;
    }
    uint8_t * block = z->cipher + have;
    for (unsigned k = 0; k < 16u; ++k) {
      block[k] ^= c->chain[k];
    }
    if (gsec_aes_encrypt_block(&z->aes, block, block) != GSEC_OK) {
      return GARC_ERR_INTERNAL;
    }
    memcpy(c->chain, block, 16u);
    have += 16u;
    if (have == SZW_BUFFER || !n) {
      GARC_Result result = garc_sink_write(writer->sink, z->cipher, have);
      if (result != GARC_OK) {
        return result;
      }
      *pack += have;
      have = 0;
    }
  }
  if (have) {
    GARC_Result result = garc_sink_write(writer->sink, z->cipher, have);
    if (result != GARC_OK) {
      return result;
    }
    *pack += have;
  }
  return GARC_OK;
}

/** The last block of a packed stream: what is left, zero-padded, if any is. */
static GARC_Result szw_cipher_finish(
    GARC_Writer * writer, Szw_Cipher * c, uint64_t * pack) {
  if (!c->partial_len) {
    return GARC_OK;
  }
  const size_t pad = 16u - c->partial_len;
  uint8_t zeros[16];
  memset(zeros, 0, sizeof(zeros));
  const uint64_t coded = c->coded;
  GARC_Result result = szw_encrypt(writer, c, zeros, pad, pack);
  c->coded = coded; /* the padding is not the coder's */
  gsec_wipe(c->partial, sizeof(c->partial));
  return result;
}

/**
 * Write a whole packed stream held in memory - one of BCJ2's three that wait
 * for the folder's end - encrypting it when the writer does.
 */
static GARC_Result szw_write_pack(GARC_Writer * writer, const GARC_Buffer * b,
    uint64_t * pack, uint64_t * coded, uint8_t iv[16]) {
  struct GARC_SevenZ_Write * z = writer->sevenz;
  *pack = 0;
  *coded = b->length;
  if (!z->encrypting) {
    *pack = b->length;
    return b->length ? garc_sink_write(writer->sink, b->bytes, b->length)
                     : GARC_OK;
  }
  Szw_Cipher c;
  GARC_Result result = szw_cipher_begin(&c);
  if (result == GARC_OK && b->length) {
    result = szw_encrypt(writer, &c, (const uint8_t *)b->bytes, b->length, pack);
  }
  if (result == GARC_OK) {
    result = szw_cipher_finish(writer, &c, pack);
  }
  memcpy(iv, c.iv, 16u);
  gsec_wipe(&c, sizeof(c));
  return result;
}

int garc_sevenz_write_encrypts(const GARC_Writer * writer, int * header) {
  const struct GARC_SevenZ_Write * z = writer->sevenz;
  const int on = z && z->encrypting;
  *header = on && writer->options.sevenz_encrypt_header;
  return on;
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
  return szw_key(writer);
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
  GARC_Result result = szw_key(writer);
  if (result != GARC_OK) {
    return result;
  }
  /* Reserved now, patched when the header's position is known. A patch cannot
     extend the archive, so these bytes have to exist. */
  uint8_t zeros[GARC_SEVENZ_START_SIZE];
  memset(zeros, 0, sizeof(zeros));
  return garc_sink_write(writer->sink, zeros, sizeof(zeros));
}

/** Pass compressed bytes to the sink, counting them into the open folder. */
static GARC_Result szw_emit(
    GARC_Writer * writer, unsigned which, const uint8_t * bytes, size_t n) {
  struct GARC_SevenZ_Write * z = writer->sevenz;
  (void)which;
  if (!n) {
    return GARC_OK;
  }
  if (z->encrypting) {
    return szw_encrypt(writer, &z->main, bytes, n, &z->cur_pack);
  }
  GARC_Result result = garc_sink_write(writer->sink, bytes, n);
  if (result != GARC_OK) {
    return result;
  }
  z->cur_pack += n;
  return GARC_OK;
}

/** Where a stage of the folder's pipeline hands its output. */
typedef GARC_Result (*Szw_Deliver)(
    GARC_Writer * writer, unsigned which, const uint8_t * bytes, size_t n);

/** Run bytes through an encoder, handing everything it makes to @p deliver. */
static GARC_Result szw_code(GARC_Writer * writer, gcomp_encoder_t * encoder,
    uint8_t * buffer, const void * data, size_t size, Szw_Deliver deliver,
    unsigned which) {
  gcomp_buffer_t in = {data, size, 0};
  while (in.used < size) {
    gcomp_buffer_t out = {buffer, SZW_BUFFER, 0};
    const size_t before = in.used;
    const gcomp_status_t status = gcomp_encoder_update(encoder, &in, &out);
    if (status != GCOMP_OK) {
      return garc_codec_result(status);
    }
    GARC_Result result = deliver(writer, which, buffer, out.used);
    if (result != GARC_OK) {
      return result;
    }
    if (!out.used && in.used == before) {
      return GARC_ERR_INTERNAL;
    }
  }
  return GARC_OK;
}

/** Finish an encoder, handing the rest of what it makes to @p deliver. */
static GARC_Result szw_code_finish(GARC_Writer * writer,
    gcomp_encoder_t * encoder, uint8_t * buffer, Szw_Deliver deliver,
    unsigned which) {
  for (;;) {
    gcomp_buffer_t out = {buffer, SZW_BUFFER, 0};
    const gcomp_status_t status = gcomp_encoder_finish(encoder, &out);
    GARC_Result result = deliver(writer, which, buffer, out.used);
    if (result != GARC_OK) {
      return result;
    }
    if (status == GCOMP_OK) {
      return GARC_OK;
    }
    if (status != GCOMP_ERR_LIMIT) {
      return garc_codec_result(status);
    }
    if (!out.used) {
      return GARC_ERR_INTERNAL;
    }
  }
}

/** Bytes for the folder's main compressor (after any filter). */
static GARC_Result szw_main_in(
    GARC_Writer * writer, unsigned which, const uint8_t * bytes, size_t n) {
  struct GARC_SevenZ_Write * z = writer->sevenz;
  z->main_raw += n;
  if (!z->encoder) {
    return szw_emit(writer, which, bytes, n);
  }
  return szw_code(writer, z->encoder, z->packed, bytes, n, szw_emit, 0u);
}

/** Append to one of the streams held for the folder's end. */
static GARC_Result szw_hold(
    GARC_Writer * writer, GARC_Buffer * b, const uint8_t * bytes, size_t n) {
  if (!n) {
    return GARC_OK;
  }
  const size_t at = b->length;
  if (n > SIZE_MAX - at) {
    return GARC_ERR_OOM;
  }
  GARC_Result result = garc_buffer_grow(writer->allocator, b, at + n);
  if (result != GARC_OK) {
    return result;
  }
  memcpy(b->bytes + at, bytes, n);
  b->length = at + n;
  return GARC_OK;
}

/** Compressed CALL (0) or JUMP (1), held. */
static GARC_Result szw_side_out(
    GARC_Writer * writer, unsigned k, const uint8_t * bytes, size_t n) {
  return szw_hold(writer, &writer->sevenz->side_out[k], bytes, n);
}

/** CALL (0) or JUMP (1) from BCJ2, for its compressor. */
static GARC_Result szw_side_in(
    GARC_Writer * writer, unsigned k, const uint8_t * bytes, size_t n) {
  struct GARC_SevenZ_Write * z = writer->sevenz;
  z->side_raw[k] += n;
  if (!z->side[k]) {
    return szw_side_out(writer, k, bytes, n);
  }
  return szw_code(writer, z->side[k], z->filtered, bytes, n, szw_side_out, k);
}

/** BCJ2's sink: MAIN on to the compressor, the other three held. */
static GARC_Result szw_bcj2_sink(
    void * ctx, unsigned which, const uint8_t * bytes, size_t n) {
  GARC_Writer * writer = (GARC_Writer *)ctx;
  switch (which) {
    case 0u:
      return szw_main_in(writer, 0u, bytes, n);
    case 1u:
    case 2u:
      return szw_side_in(writer, which - 1u, bytes, n);
    default:
      return szw_hold(writer, &writer->sevenz->rc, bytes, n);
  }
}

/** The bcj.arch name of a simple branch filter. */
static const char * szw_filter_arch(GARC_SevenZ_Filter filter) {
  switch (filter) {
    case GARC_SEVENZ_FILTER_X86: return "x86";
    case GARC_SEVENZ_FILTER_PPC: return "powerpc";
    case GARC_SEVENZ_FILTER_IA64: return "ia64";
    case GARC_SEVENZ_FILTER_ARM: return "arm";
    case GARC_SEVENZ_FILTER_ARMT: return "armthumb";
    case GARC_SEVENZ_FILTER_SPARC: return "sparc";
    case GARC_SEVENZ_FILTER_ARM64: return "arm64";
    case GARC_SEVENZ_FILTER_RISCV: return "riscv";
    default: return NULL;
  }
}

/** A codec encoder by name; LZMA raw at @p dict when @p dict is non-zero. */
static GARC_Result szw_encoder(const char * name, const char * arch,
    GARC_SevenZ_Method method, uint64_t dict, gcomp_encoder_t ** out,
    gcomp_options_t ** out_options) {
  gcomp_options_t * options = NULL;
  if (method == GARC_SEVENZ_LZMA || method == GARC_SEVENZ_LZMA2 || arch) {
    if (gcomp_options_create(&options) != GCOMP_OK) {
      return GARC_ERR_OOM;
    }
    int failed = 0;
    if (arch) {
      failed = gcomp_options_set_string(options, "bcj.arch", arch) != GCOMP_OK;
    }
    else {
      const char * key = method == GARC_SEVENZ_LZMA ? "lzma.dict_size"
                                                     : "lzma2.dict_size";
      failed = (method == GARC_SEVENZ_LZMA
                   && gcomp_options_set_bool(options, "lzma.raw", 1) != GCOMP_OK)
          || gcomp_options_set_uint64(options, key, dict) != GCOMP_OK;
    }
    if (failed) {
      gcomp_options_destroy(options);
      return GARC_ERR_OOM;
    }
  }
  const gcomp_status_t status = gcomp_encoder_create(
      gcomp_registry_default(), name, options, out);
  if (status != GCOMP_OK) {
    gcomp_options_destroy(options);
    return garc_codec_result(status);
  }
  *out_options = options;
  return GARC_OK;
}

/** Make an encoder ready for a folder: reset the one there, or create it. */
static GARC_Result szw_ready(gcomp_encoder_t ** encoder,
    gcomp_options_t ** options, const char * name, const char * arch,
    GARC_SevenZ_Method method, uint64_t dict) {
  if (*encoder) {
    return garc_codec_result(gcomp_encoder_reset(*encoder));
  }
  return szw_encoder(name, arch, method, dict, encoder, options);
}

/** A working buffer, made once. */
static GARC_Result szw_buffer(const GARC_Allocator * a, uint8_t ** buffer) {
  if (!*buffer) {
    *buffer = (uint8_t *)gcu_allocator_malloc(a, SZW_BUFFER);
  }
  return *buffer ? GARC_OK : GARC_ERR_OOM;
}

static GARC_Result szw_open_folder(GARC_Writer * writer) {
  struct GARC_SevenZ_Write * z = writer->sevenz;
  const GARC_Allocator * a = writer->allocator;
  const GARC_SevenZ_Method method = writer->options.sevenz_method;
  const GARC_SevenZ_Filter filter = writer->options.sevenz_filter;
  z->cur_pack = 0;
  z->cur_unpack = 0;
  z->cur_nsub = 0;
  z->main_raw = 0;
  GARC_Result result = GARC_OK;
  if (z->encrypting) {
    result = szw_cipher_begin(&z->main);
  }
  if (result == GARC_OK && method != GARC_SEVENZ_COPY) {
    result = szw_ready(&z->encoder, &z->encoder_options,
        szw_encoder_name(method), NULL, method, SZW_DICT_SIZE);
    if (result == GARC_OK) {
      result = szw_buffer(a, &z->packed);
    }
  }
  if (result == GARC_OK && filter == GARC_SEVENZ_FILTER_BCJ2) {
    // CALL and JUMP are LZMA, as 7-Zip writes them, unless nothing is to be
    // compressed; the range coder's bytes are stored as they are.
    for (unsigned k = 0; k < 2u && result == GARC_OK; ++k) {
      z->side_raw[k] = 0;
      z->side_out[k].length = 0;
      if (method != GARC_SEVENZ_COPY) {
        result = szw_ready(&z->side[k], &z->side_options[k], "lzma", NULL,
            GARC_SEVENZ_LZMA, SZW_SIDE_DICT_SIZE);
      }
    }
    z->rc.length = 0;
    if (result == GARC_OK) {
      result = szw_buffer(a, &z->filtered);
    }
    if (result == GARC_OK) {
      result = garc_sevenz_bcj2_enc_create(a, szw_bcj2_sink, writer, &z->bcj2);
    }
  }
  else if (result == GARC_OK && filter != GARC_SEVENZ_FILTER_NONE) {
    result = szw_ready(&z->filter, &z->filter_options, "bcj",
        szw_filter_arch(filter), GARC_SEVENZ_COPY, 0);
    if (result == GARC_OK) {
      result = szw_buffer(a, &z->filtered);
    }
  }
  if (result == GARC_OK) {
    z->folder_open = 1;
  }
  return result;
}

static GARC_Result szw_close_folder(GARC_Writer * writer) {
  struct GARC_SevenZ_Write * z = writer->sevenz;
  if (!z->folder_open) {
    return GARC_OK;
  }
  GARC_Result result = GARC_OK;
  if (z->bcj2) {
    result = garc_sevenz_bcj2_enc_finish(z->bcj2);
    garc_sevenz_bcj2_enc_destroy(z->bcj2);
    z->bcj2 = NULL;
  }
  else if (z->filter) {
    result = szw_code_finish(writer, z->filter, z->filtered, szw_main_in, 0u);
  }
  if (result == GARC_OK && z->encoder) {
    result = szw_code_finish(writer, z->encoder, z->packed, szw_emit, 0u);
  }
  if (result == GARC_OK && z->encrypting) {
    result = szw_cipher_finish(writer, &z->main, &z->cur_pack);
  }
  SzwFolder folder;
  memset(&folder, 0, sizeof(folder));
  folder.filter = writer->options.sevenz_filter;
  if (result == GARC_OK && folder.filter == GARC_SEVENZ_FILTER_BCJ2) {
    for (unsigned k = 0; k < 2u && result == GARC_OK; ++k) {
      if (z->side[k]) {
        result = szw_code_finish(
            writer, z->side[k], z->filtered, szw_side_out, k);
      }
      folder.side_raw[k] = z->side_raw[k];
    }
    // After MAIN, in 7-Zip's order: the range coder, CALL, JUMP.
    const GARC_Buffer * held[3] = {&z->rc, &z->side_out[0], &z->side_out[1]};
    for (unsigned k = 0; k < 3u && result == GARC_OK; ++k) {
      result = szw_write_pack(writer, held[k], &folder.side_pack[k],
          &folder.side_coded[k], folder.side_iv[k]);
    }
  }
  if (result != GARC_OK) {
    return result;
  }
  folder.pack_size = z->cur_pack;
  folder.unpack_size = z->cur_unpack;
  folder.nsub = z->cur_nsub;
  folder.main_raw = z->main_raw;
  if (z->encrypting) {
    folder.coded_size = z->main.coded;
    memcpy(folder.iv, z->main.iv, sizeof(folder.iv));
  }
  result = szw_grow(writer->allocator, &z->folders, &z->num_folders,
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
    if (z->bcj2) {
      // 7-Zip converts a branch only when it lands inside its own file.
      garc_sevenz_bcj2_enc_file(z->bcj2, size);
    }
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
  if (z->bcj2) {
    return garc_sevenz_bcj2_enc_write(z->bcj2, data, size);
  }
  if (z->filter) {
    return szw_code(writer, z->filter, z->filtered, data, size, szw_main_in, 0u);
  }
  return szw_main_in(writer, 0u, (const uint8_t *)data, size);
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
/** An LZMA coder record at a dictionary size. */
static void put_lzma_coder(GARC_Buffer * b, const GARC_Allocator * a,
    uint32_t dict, GARC_Result * status) {
  /* lc 3, lp 0, pb 2 is (2 * 5 + 0) * 9 + 3 = 0x5D, then the dictionary. */
  uint8_t rec[] = {0x23u, 0x03u, 0x01u, 0x01u, 0x05u, 0x5Du, 0, 0, 0, 0};
  for (unsigned i = 0; i < 4u; ++i) {
    rec[6u + i] = (uint8_t)(dict >> (8u * i));
  }
  put_bytes(b, a, rec, sizeof(rec), status);
}

static void put_coder(GARC_Buffer * b, const GARC_Allocator * a,
    GARC_SevenZ_Method method, GARC_Result * status) {
  switch (method) {
    case GARC_SEVENZ_LZMA2: {
      const uint8_t rec[] = {0x21u, 0x21u, 0x01u, SZW_LZMA2_PROP};
      put_bytes(b, a, rec, sizeof(rec), status);
      break;
    }
    case GARC_SEVENZ_LZMA:
      put_lzma_coder(b, a, SZW_DICT_SIZE, status);
      break;
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

/**
 * An AES coder record as 7-Zip writes it: id 06 F1 07 01, eighteen property
 * bytes - the cycle power with the IV flag, a nibble saying sixteen, the IV.
 */
static void put_aes_coder(GARC_Buffer * b, const GARC_Allocator * a,
    unsigned power, const uint8_t iv[16], GARC_Result * status) {
  const uint8_t rec[] = {0x24u, 0x06u, 0xF1u, 0x07u, 0x01u, 0x12u,
      (uint8_t)(0x40u | power), 0x0Fu};
  put_bytes(b, a, rec, sizeof(rec), status);
  put_bytes(b, a, iv, 16u, status);
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

/** The coder for BCJ2's CALL and JUMP: LZMA, or copy when nothing is compressed. */
static void put_side_coder(GARC_Buffer * b, const GARC_Allocator * a,
    GARC_SevenZ_Method method, GARC_Result * status) {
  if (method == GARC_SEVENZ_COPY) {
    put_coder(b, a, method, status);
  }
  else {
    put_lzma_coder(b, a, SZW_SIDE_DICT_SIZE, status);
  }
}

/** A branch filter's coder record: BCJ2's four inputs, or a simple filter's id. */
static void put_filter_coder(GARC_Buffer * b, const GARC_Allocator * a,
    GARC_SevenZ_Filter filter, GARC_Result * status) {
  if (filter == GARC_SEVENZ_FILTER_BCJ2) {
    /* An id of four bytes, a complex coder: four in, one out. */
    const uint8_t rec[] = {0x14u, 0x03u, 0x03u, 0x01u, 0x1Bu, 0x04u, 0x01u};
    put_bytes(b, a, rec, sizeof(rec), status);
    return;
  }
  uint8_t rec[5] = {0x04u, 0x03u, 0x03u, 0, 0};
  size_t len = 5u;
  switch (filter) {
    case GARC_SEVENZ_FILTER_X86: rec[3] = 0x01u; rec[4] = 0x03u; break;
    case GARC_SEVENZ_FILTER_PPC: rec[3] = 0x02u; rec[4] = 0x05u; break;
    case GARC_SEVENZ_FILTER_IA64: rec[3] = 0x04u; rec[4] = 0x01u; break;
    case GARC_SEVENZ_FILTER_ARM: rec[3] = 0x05u; rec[4] = 0x01u; break;
    case GARC_SEVENZ_FILTER_ARMT: rec[3] = 0x07u; rec[4] = 0x01u; break;
    case GARC_SEVENZ_FILTER_SPARC: rec[3] = 0x08u; rec[4] = 0x05u; break;
    case GARC_SEVENZ_FILTER_ARM64: rec[0] = 0x01u; rec[1] = 0x0Au; len = 2u; break;
    default: rec[0] = 0x01u; rec[1] = 0x0Bu; len = 2u; break; /* RISC-V */
  }
  put_bytes(b, a, rec, len, status);
}

/**
 * The coders, bind pairs and packed in-streams of a folder this writer made.
 *
 * Plain: the compressor. A simple filter: the compressor, then the filter
 * fed by it. BCJ2, as 7-Zip writes it: JUMP's and CALL's coders, the main
 * compressor, then BCJ2 with its MAIN, CALL and JUMP bound to them and its
 * range coder's stream packed, the packed streams in the order MAIN, range
 * coder, CALL, JUMP. With AES, an AES coder goes in front of every packed
 * stream - first in the list, each with its IV - and what was packed is bound
 * to it instead.
 */
static void put_new_folder(GARC_Buffer * h, const GARC_Allocator * a,
    const struct GARC_SevenZ_Write * z, GARC_SevenZ_Method method,
    const SzwFolder * f, GARC_Result * status) {
  const int aes = z->encrypting;
  if (f->filter == GARC_SEVENZ_FILTER_BCJ2) {
    if (!aes) {
      put_number(h, a, 4, status);
      put_side_coder(h, a, method, status);
      put_side_coder(h, a, method, status);
      put_coder(h, a, method, status);
      put_filter_coder(h, a, f->filter, status);
      /* (in, out): BCJ2's JUMP, CALL and MAIN, from coders 0, 1 and 2. */
      const uint8_t binds[] = {5, 0, 4, 1, 3, 2};
      for (size_t k = 0; k < sizeof(binds); ++k) {
        put_number(h, a, binds[k], status);
      }
      const uint8_t packed[] = {2, 6, 1, 0};
      for (size_t k = 0; k < sizeof(packed); ++k) {
        put_number(h, a, packed[k], status);
      }
      return;
    }
    put_number(h, a, 8, status);
    put_aes_coder(h, a, z->key_power, f->iv, status);
    for (unsigned k = 0; k < 3u; ++k) {
      put_aes_coder(h, a, z->key_power, f->side_iv[k], status);
    }
    put_side_coder(h, a, method, status);
    put_side_coder(h, a, method, status);
    put_coder(h, a, method, status);
    put_filter_coder(h, a, f->filter, status);
    /* AES 0-3 decrypt MAIN, the range coder, CALL and JUMP; coders 4 and 5
       decode JUMP and CALL, 6 is the main compressor, 7 is BCJ2 (in 7-10). */
    const uint8_t binds[] = {4, 3, 5, 2, 6, 0, 10, 1, 7, 6, 8, 5, 9, 4};
    for (size_t k = 0; k < sizeof(binds); ++k) {
      put_number(h, a, binds[k], status);
    }
    for (uint8_t k = 0; k < 4u; ++k) {
      put_number(h, a, k, status);
    }
    return;
  }
  const int filtered = f->filter != GARC_SEVENZ_FILTER_NONE;
  put_number(h, a, 1u + (aes ? 1u : 0u) + (filtered ? 1u : 0u), status);
  if (aes) {
    // As 7-Zip lays it out: AES first, its output bound to the compressor's
    // input, the one packed stream AES's input.
    put_aes_coder(h, a, z->key_power, f->iv, status);
  }
  put_coder(h, a, method, status);
  if (filtered) {
    put_filter_coder(h, a, f->filter, status);
  }
  /* Each coder after the first takes the one before it. */
  const unsigned chain = (aes ? 1u : 0u) + (filtered ? 1u : 0u);
  for (unsigned k = 1; k <= chain; ++k) {
    put_number(h, a, k, status);
    put_number(h, a, k - 1u, status);
  }
}

/** A written folder's unpack sizes, one per coder output, in coder order. */
static void put_new_unpack(GARC_Buffer * h, const GARC_Allocator * a,
    const struct GARC_SevenZ_Write * z, const SzwFolder * f,
    GARC_Result * status) {
  if (f->filter == GARC_SEVENZ_FILTER_BCJ2) {
    if (z->encrypting) {
      put_number(h, a, f->coded_size, status);
      for (unsigned k = 0; k < 3u; ++k) {
        put_number(h, a, f->side_coded[k], status);
      }
    }
    put_number(h, a, f->side_raw[1], status); /* JUMP */
    put_number(h, a, f->side_raw[0], status); /* CALL */
    put_number(h, a, f->main_raw, status);
    put_number(h, a, f->unpack_size, status);
    return;
  }
  if (z->encrypting) {
    put_number(h, a, f->coded_size, status);
  }
  if (f->filter != GARC_SEVENZ_FILTER_NONE) {
    put_number(h, a, f->main_raw, status); /* the filter keeps the length */
  }
  put_number(h, a, f->unpack_size, status);
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
    uint64_t new_packs = 0;
    for (uint32_t i = 0; i < z->num_folders; ++i) {
      new_packs += z->folders[i].filter == GARC_SEVENZ_FILTER_BCJ2 ? 4u : 1u;
    }
    put_number(h, a, carried_pack + new_packs, &status);
    put_byte(h, a, 0x09, &status);
    for (uint64_t i = 0; i < carried_pack; ++i) {
      put_number(h, a, c->pack_sizes[i], &status);
    }
    for (uint32_t i = 0; i < z->num_folders; ++i) {
      const SzwFolder * f = &z->folders[i];
      put_number(h, a, f->pack_size, &status);
      if (f->filter == GARC_SEVENZ_FILTER_BCJ2) {
        for (unsigned k = 0; k < 3u; ++k) {
          put_number(h, a, f->side_pack[k], &status);
        }
      }
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
      put_new_folder(h, a, z, method, &z->folders[i], &status);
    }
    put_byte(h, a, 0x0C, &status);
    for (uint32_t i = 0; i < carried_folders; ++i) {
      const GARC_SevenZ_Carry_Folder * f = &c->folders[i];
      for (uint32_t j = 0; j < f->nout; ++j) {
        put_number(h, a, c->unpack_sizes[f->unpack0 + j], &status);
      }
    }
    for (uint32_t i = 0; i < z->num_folders; ++i) {
      put_new_unpack(h, a, z, &z->folders[i], &status);
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

/**
 * Encrypt a finished header and write it at @p at as a packed stream, then
 * build in @p record the encoded-header record that names it: its position,
 * its size, an AES coder with a fresh IV, the plain header's length and CRC-32.
 */
static GARC_Result szw_seal_header(GARC_Writer * writer,
    const GARC_Buffer * header, uint64_t at, GARC_Buffer * record) {
  struct GARC_SevenZ_Write * z = writer->sevenz;
  const GARC_Allocator * a = writer->allocator;
  Szw_Cipher cipher;
  uint64_t sealed = 0;
  GARC_Result result = szw_cipher_begin(&cipher);
  if (result == GARC_OK) {
    result = szw_encrypt(writer, &cipher, (const uint8_t *)header->bytes,
        header->length, &sealed);
  }
  if (result == GARC_OK) {
    result = szw_cipher_finish(writer, &cipher, &sealed);
  }
  if (result != GARC_OK) {
    gsec_wipe(&cipher, sizeof(cipher));
    return result;
  }
  const uint32_t crc = gcomp_crc32_finalize(gcomp_crc32_update(
      GCOMP_CRC32_INIT, (const uint8_t *)header->bytes, header->length));
  GARC_Result status = GARC_OK;
  put_byte(record, a, 0x17, &status);
  put_byte(record, a, 0x06, &status);
  put_number(record, a, at - (z->origin + GARC_SEVENZ_START_SIZE), &status);
  put_number(record, a, 1, &status);
  put_byte(record, a, 0x09, &status);
  put_number(record, a, sealed, &status);
  put_byte(record, a, 0x00, &status);
  put_byte(record, a, 0x07, &status);
  put_byte(record, a, 0x0B, &status);
  put_number(record, a, 1, &status);
  put_byte(record, a, 0x00, &status);
  put_number(record, a, 1, &status);
  put_aes_coder(record, a, z->key_power, cipher.iv, &status);
  gsec_wipe(&cipher, sizeof(cipher));
  put_byte(record, a, 0x0C, &status);
  put_number(record, a, header->length, &status);
  put_byte(record, a, 0x0A, &status);
  put_byte(record, a, 0x01, &status);
  put_u32(record, a, crc, &status);
  put_byte(record, a, 0x00, &status);
  put_byte(record, a, 0x00, &status);
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
  uint64_t header_offset = header_at - (z->origin + GARC_SEVENZ_START_SIZE);
  if (z->num_entries || (z->carry && z->carry->num_files)) {
    GARC_Buffer header;
    memset(&header, 0, sizeof(header));
    result = szw_build_header(writer, &header);
    if (result == GARC_OK && header.length > SZW_MAX_HEADER) {
      result = GARC_ERR_UNSUPPORTED;
    }
    uint64_t next_at = header_at;
    if (result == GARC_OK && writer->options.sevenz_encrypt_header
        && z->encrypting) {
      // The header becomes a packed stream of its own behind AES alone - as
      // 7-Zip writes an encrypted header of fewer than two items, and as its
      // reader takes any - and what the start header names is the small
      // record saying how to decode it.
      GARC_Buffer record;
      memset(&record, 0, sizeof(record));
      result = szw_seal_header(writer, &header, header_at, &record);
      if (result == GARC_OK) {
        next_at = garc_sink_tell(writer->sink);
        result = garc_sink_write(writer->sink, record.bytes, record.length);
      }
      garc_buffer_free(a, &header);
      header = record;
    }
    else if (result == GARC_OK) {
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
    header_offset = next_at - (z->origin + GARC_SEVENZ_START_SIZE);
  }
  const uint64_t offset = header_offset;
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
  if (z->encrypting) {
    (void)gsec_aes_encrypt_wipe(&z->aes);
  }
  gsec_wipe(&z->main, sizeof(z->main));
  gcu_allocator_free(a, z->cipher);
  gcomp_encoder_destroy(z->filter);
  gcomp_options_destroy(z->filter_options);
  gcu_allocator_free(a, z->filtered);
  garc_sevenz_bcj2_enc_destroy(z->bcj2);
  for (unsigned k = 0; k < 2u; ++k) {
    gcomp_encoder_destroy(z->side[k]);
    gcomp_options_destroy(z->side_options[k]);
    garc_buffer_free(a, &z->side_out[k]);
  }
  garc_buffer_free(a, &z->rc);
  gcu_allocator_free(a, z->entries);
  gcu_allocator_free(a, z->folders);
  garc_buffer_free(a, &z->names);
  garc_sevenz_carry_free(z->carry, a);
  gcu_allocator_free(a, z);
  writer->sevenz = NULL;
}
