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
 * 7-Zip's AES coder (method 06 F1 07 01), decrypted.
 *
 * **Where this came from.** 7z AES has no published specification; 7-Zip's
 * public-domain LZMA SDK is its only definition. Under a clean-room exception
 * Corey made on 2026-10-21, a describer read that source and wrote a prose
 * description with no code in it, `notes/archive/7Z-AES-DESCRIPTION.md` in the
 * workspace, checking each format fact against 7-Zip as a black box. This file
 * was written from that description and checked against 7-Zip's archives; its
 * author has not read the source.
 *
 * **The format.** The properties are a byte holding the cycle power P in its
 * low six bits and two bits that each add one to a length; a byte whose
 * nibbles are the rest of the salt and IV lengths; then the salt and the IV.
 * The key is SHA-256 over 2^P copies of salt, password (UTF-16LE) and a
 * 64-bit little-endian counter that counts the copies from zero - one hash
 * over the whole run, not a chain. P = 63 is no hash at all: the key is the
 * salt and then the password, cut or zero-padded to 32 bytes. The cipher is
 * AES-256-CBC with the IV zero-padded to 16 bytes, over plaintext zero-padded
 * to a whole block; the folder's unpack size says how much of it is real.
 *
 * **What is refused.** Properties whose lengths do not add up, and a cycle
 * power from 25 to 62, are ::GARC_ERR_UNSUPPORTED, as 7-Zip calls them
 * "Unsupported Method". Ciphertext that runs out before the unpack size, or
 * whose length is not a whole number of blocks, is ::GARC_ERR_CORRUPT, which
 * the reader turns into ::GARC_ERR_PASSWORD_OR_CORRUPT. Whole blocks beyond
 * what the unpack size needs are accepted, as 7-Zip accepts them.
 *
 * **Cost.** P is at most 24, so one key is at most 2^24 copies hashed - about
 * a second. The last key is kept with the password, and a non-solid archive's
 * folders, which share salt and P, derive it once.
 */

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/security/aes.h>
#include <ghoti.io/security/secret.h>
#include <ghoti.io/security/sha256.h>
#include <stdint.h>
#include <string.h>

#include "sevenz/sevenz_internal.h"
#include "stream/stream_internal.h"

/** The cycle power that means no key derivation. */
#define SZ_AES_RAW_POWER 63u

/** The largest cycle power that is derived; 25 to 62 are refused. */
#define SZ_AES_MAX_POWER 24u

/** Ciphertext read per refill, a whole number of blocks. */
#define SZ_AES_BUFFER 16384u

/** Copies of salt, password and counter hashed per call into SHA-256. */
#define SZ_AES_BATCH 64u

/** The properties, taken apart. */
typedef struct {
  unsigned power;    ///< P.
  uint8_t salt[16];  ///< The salt.
  size_t salt_len;   ///< Its length, 0 to 16.
  uint8_t iv[16];    ///< The IV, zero-padded.
} Sz_Aes_Props;

/** Take the properties apart, refusing what 7-Zip refuses. */
static GARC_Result aes_props(
    const uint8_t * props, size_t len, Sz_Aes_Props * out) {
  memset(out, 0, sizeof(*out));
  if (!len) {
    return GARC_OK; /* P 0, no salt, a zero IV */
  }
  const uint8_t b0 = props[0];
  out->power = b0 & 0x3Fu;
  size_t salt_len = 0;
  size_t iv_len = 0;
  if (!(b0 & 0xC0u)) {
    if (len != 1u) {
      return GARC_ERR_UNSUPPORTED;
    }
  }
  else {
    if (len < 2u) {
      return GARC_ERR_UNSUPPORTED;
    }
    salt_len = ((b0 >> 7) & 1u) + (props[1] >> 4);
    iv_len = ((b0 >> 6) & 1u) + (props[1] & 0x0Fu);
    if (len != 2u + salt_len + iv_len) {
      return GARC_ERR_UNSUPPORTED;
    }
    memcpy(out->salt, props + 2u, salt_len);
    memcpy(out->iv, props + 2u + salt_len, iv_len);
  }
  out->salt_len = salt_len;
  if (out->power > SZ_AES_MAX_POWER && out->power != SZ_AES_RAW_POWER) {
    return GARC_ERR_UNSUPPORTED;
  }
  return GARC_OK;
}

/** Derive the key for @p p into @p key, or take it from the password's cache. */
static GARC_Result aes_key(const GARC_Allocator * a, const Sz_Aes_Props * p,
    GARC_SevenZ_Password * pw, uint8_t key[32]) {
  if (pw->have_key && pw->power == p->power && pw->salt_len == p->salt_len
      && !memcmp(pw->salt, p->salt, p->salt_len)) {
    memcpy(key, pw->key, 32u);
    return GARC_OK;
  }
  if (p->power == SZ_AES_RAW_POWER) {
    memset(key, 0, 32u);
    size_t at = p->salt_len;
    memcpy(key, p->salt, at);
    size_t take = pw->utf16_len;
    if (take > 32u - at) {
      take = 32u - at;
    }
    if (take) {
      memcpy(key + at, pw->utf16, take);
    }
  }
  else {
    const uint64_t cost = (uint64_t)1u << p->power;
    if (pw->rounds_cap && (pw->rounds_spent > pw->rounds_cap
            || cost > pw->rounds_cap - pw->rounds_spent)) {
      return GARC_ERR_LIMIT_KEY_ROUNDS;
    }
    pw->rounds_spent += cost;
    const size_t unit = p->salt_len + pw->utf16_len + 8u;
    if (unit > SIZE_MAX / SZ_AES_BATCH) {
      return GARC_ERR_OOM;
    }
    uint8_t * batch = (uint8_t *)gcu_allocator_malloc(a, unit * SZ_AES_BATCH);
    if (!batch) {
      return GARC_ERR_OOM;
    }
    for (size_t i = 0; i < SZ_AES_BATCH; ++i) {
      uint8_t * u = batch + i * unit;
      memcpy(u, p->salt, p->salt_len);
      if (pw->utf16_len) {
        memcpy(u + p->salt_len, pw->utf16, pw->utf16_len);
      }
    }
    GSEC_Sha256 sha;
    GARC_Result result = GARC_OK;
    if (gsec_sha256_init(&sha) != GSEC_OK) {
      result = GARC_ERR_INTERNAL;
    }
    const uint64_t rounds = (uint64_t)1u << p->power;
    for (uint64_t done = 0; result == GARC_OK && done < rounds;) {
      uint64_t n = rounds - done;
      if (n > SZ_AES_BATCH) {
        n = SZ_AES_BATCH;
      }
      for (uint64_t i = 0; i < n; ++i) {
        uint8_t * c = batch + (size_t)i * unit + unit - 8u;
        const uint64_t counter = done + i;
        for (unsigned k = 0; k < 8u; ++k) {
          c[k] = (uint8_t)(counter >> (8u * k));
        }
      }
      if (gsec_sha256_update(&sha, batch, (size_t)n * unit) != GSEC_OK) {
        result = GARC_ERR_INTERNAL;
      }
      done += n;
    }
    if (result == GARC_OK && gsec_sha256_final(&sha, key) != GSEC_OK) {
      result = GARC_ERR_INTERNAL;
    }
    gsec_wipe(&sha, sizeof(sha));
    gsec_wipe(batch, unit * SZ_AES_BATCH);
    gcu_allocator_free(a, batch);
    if (result != GARC_OK) {
      return result;
    }
  }
  pw->have_key = 1;
  pw->power = (uint8_t)p->power;
  pw->salt_len = p->salt_len;
  memcpy(pw->salt, p->salt, p->salt_len);
  memcpy(pw->key, key, 32u);
  return GARC_OK;
}

/** An AES decrypting stream: the key schedule, CBC's state, and a buffer. */
typedef struct {
  const GARC_Allocator * allocator; ///< For this state.
  GARC_Stream * inner;    ///< The ciphertext. Borrowed.
  GSEC_Aes aes;           ///< The key schedule.
  uint8_t chain[16];      ///< The previous ciphertext block: CBC's state.
  uint8_t buffer[SZ_AES_BUFFER]; ///< Decrypted and not yet given out.
  size_t pos;             ///< The next byte of @ref buffer to give.
  size_t len;             ///< Bytes of @ref buffer decrypted.
  uint8_t partial[16];    ///< Ciphertext bytes short of a whole block.
  size_t partial_len;     ///< How many.
  uint64_t out_size;      ///< The plaintext's size.
  uint64_t out_done;      ///< Bytes given out.
  int finished;           ///< Whether the tail has been checked.
} Sz_Aes;

/** Read and decrypt the next whole blocks into the buffer. */
static GARC_Result aes_fill(Sz_Aes * d) {
  d->pos = 0;
  d->len = 0;
  memcpy(d->buffer, d->partial, d->partial_len);
  size_t have = d->partial_len;
  d->partial_len = 0;
  while (have < 16u) {
    size_t got = 0;
    GARC_Result result = garc_stream_read(
        d->inner, d->buffer + have, sizeof(d->buffer) - have, &got);
    if (result != GARC_OK) {
      return result;
    }
    if (!got) {
      break;
    }
    have += got;
  }
  const size_t whole = have & ~(size_t)15u;
  d->partial_len = have - whole;
  memcpy(d->partial, d->buffer + whole, d->partial_len);
  for (size_t at = 0; at < whole; at += 16u) {
    uint8_t * block = d->buffer + at;
    uint8_t saved[16];
    memcpy(saved, block, 16u);
    if (gsec_aes_decrypt_block(&d->aes, block, block) != GSEC_OK) {
      return GARC_ERR_INTERNAL;
    }
    for (unsigned k = 0; k < 16u; ++k) {
      block[k] ^= d->chain[k];
    }
    memcpy(d->chain, saved, 16u);
  }
  d->len = whole;
  return GARC_OK;
}

/** Past the last plaintext byte: the ciphertext must be whole blocks. */
static GARC_Result aes_finish(Sz_Aes * d) {
  size_t extra = d->partial_len;
  uint8_t sink[512];
  for (;;) {
    size_t got = 0;
    GARC_Result result = garc_stream_read(d->inner, sink, sizeof(sink), &got);
    if (result != GARC_OK) {
      return result;
    }
    if (!got) {
      break;
    }
    extra += got;
  }
  d->finished = 1;
  return (extra % 16u) ? GARC_ERR_CORRUPT : GARC_OK;
}

static GARC_Result aes_read(
    void * ctx, void * buffer, size_t size, size_t * out_read) {
  Sz_Aes * d = (Sz_Aes *)ctx;
  uint8_t * out = (uint8_t *)buffer;
  size_t n = 0;
  *out_read = 0;
  while (n < size && d->out_done < d->out_size) {
    if (d->pos == d->len) {
      GARC_Result result = aes_fill(d);
      if (result != GARC_OK) {
        return result;
      }
      if (!d->len) {
        return GARC_ERR_CORRUPT; /* the ciphertext ran out */
      }
    }
    size_t take = d->len - d->pos;
    if (take > size - n) {
      take = size - n;
    }
    if ((uint64_t)take > d->out_size - d->out_done) {
      take = (size_t)(d->out_size - d->out_done);
    }
    memcpy(out + n, d->buffer + d->pos, take);
    d->pos += take;
    n += take;
    d->out_done += take;
  }
  if (d->out_done == d->out_size && !d->finished) {
    GARC_Result result = aes_finish(d);
    if (result != GARC_OK) {
      return result;
    }
  }
  *out_read = n;
  return GARC_OK;
}

static void aes_destroy(GARC_Stream * stream) {
  Sz_Aes * d = (Sz_Aes *)stream->cb.ctx;
  (void)gsec_aes_encrypt_wipe(&d->aes);
  const GARC_Allocator * a = d->allocator;
  gsec_wipe(d, sizeof(*d));
  gcu_allocator_free(a, d);
}

GARC_Result garc_sevenz_aes_stream_create(const GARC_Allocator * allocator,
    GARC_Stream * inner, const uint8_t * props, size_t props_len,
    GARC_SevenZ_Password * password, uint64_t out_size,
    GARC_Stream ** out_stream) {
  Sz_Aes_Props p;
  GARC_Result result = aes_props(props, props_len, &p);
  if (result != GARC_OK) {
    return result;
  }
  uint8_t key[32];
  result = aes_key(allocator, &p, password, key);
  if (result != GARC_OK) {
    gsec_wipe(&p, sizeof(p));
    return result;
  }
  Sz_Aes * d = (Sz_Aes *)gcu_allocator_calloc(allocator, 1, sizeof(Sz_Aes));
  if (!d) {
    gsec_wipe(key, sizeof(key));
    gsec_wipe(&p, sizeof(p));
    return GARC_ERR_OOM;
  }
  d->allocator = allocator;
  d->inner = inner;
  d->out_size = out_size;
  memcpy(d->chain, p.iv, 16u);
  const GSEC_Result keyed = gsec_aes_encrypt_init(&d->aes, key, sizeof(key));
  gsec_wipe(key, sizeof(key));
  gsec_wipe(&p, sizeof(p));
  if (keyed != GSEC_OK) {
    gcu_allocator_free(allocator, d);
    return GARC_ERR_INTERNAL;
  }

  GARC_Stream_Callbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.ctx = d;
  callbacks.read = aes_read;
  GARC_Stream * stream = NULL;
  result = garc_stream_create_callback_with_allocator(
      &callbacks, allocator, &stream);
  if (result != GARC_OK) {
    (void)gsec_aes_encrypt_wipe(&d->aes);
    gcu_allocator_free(allocator, d);
    return result;
  }
  stream->owned_destroy = aes_destroy;
  *out_stream = stream;
  return GARC_OK;
}
