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
 * WinZip AES, read and written.
 *
 * AES wraps the compressed bytes. The compression method stays stored or
 * deflate; method 99 in the header is this framing, and the real method is
 * the last two bytes of the 0x9901 extra field. ZipCrypto is not in this
 * file.
 *
 * The key is PBKDF2-HMAC-SHA1, 1000 iterations, split into the AES key, an
 * HMAC key of the same length, and a 2-byte verifier. AES-CTR is
 * little-endian and the counter starts at 1. The HMAC is SHA-1 over the
 * ciphertext only; the member stores the first 10 bytes of the 20-byte
 * digest. `security` has no truncated HMAC, and this file does not add one:
 * it computes the digest and compares the prefix with gsec_equal().
 *
 * A wrong password and a damaged ciphertext can both fail that comparison.
 * The verifier is 16 bits, so a wrong password passes it once in 65536 and
 * then fails the HMAC. The status for that failure is therefore
 * GARC_ERR_PASSWORD_OR_CORRUPT, reported when the member is over, not on the
 * call that hands over the last plaintext.
 */

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/security/aes_ctr.h>
#include <ghoti.io/security/hmac.h>
#include <ghoti.io/security/pbkdf2.h>
#include <ghoti.io/security/random.h>
#include <ghoti.io/security/secret.h>
#include <ghoti.io/security/sha1.h>
#include <string.h>

#include "stream/stream_internal.h"
#include "zip/zip_internal.h"

/** PBKDF2 iteration count WinZip AES specifies. */
#define ZIP_AES_ITERATIONS 1000u

/** Largest AES key this format uses. */
#define ZIP_AES_MAX_KEY 32u

/**
 * Salt and key length for a strength byte.
 *
 * @param strength 1, 2 or 3.
 * @param salt_len Receives 8, 12 or 16.
 * @param key_len Receives 16, 24 or 32.
 * @return Non-zero when @p strength is one of those three.
 */
static int zip_aes_lengths(uint8_t strength, size_t * salt_len, size_t * key_len) {
  switch (strength) {
    case 1u:
      *salt_len = 8u;
      *key_len = 16u;
      return 1;
    case 2u:
      *salt_len = 12u;
      *key_len = 24u;
      return 1;
    case 3u:
      *salt_len = 16u;
      *key_len = 32u;
      return 1;
    default:
      return 0;
  }
}

size_t garc_zip_aes_framing(uint8_t strength) {
  size_t salt_len = 0;
  size_t key_len = 0;
  if (!zip_aes_lengths(strength, &salt_len, &key_len)) {
    return 0u;
  }
  return salt_len + GARC_ZIP_AES_VERIFIER_LEN + GARC_ZIP_AES_AUTH_LEN;
}

uint8_t garc_zip_aes_strength(uint32_t bits) {
  switch (bits) {
    case 128u:
      return 1u;
    case 192u:
      return 2u;
    case 256u:
      return 3u;
    default:
      return 0u;
  }
}

/**
 * Documented here as well as in zip_internal.h because doxygen does not match the
 * two declarations when a parameter's array bound is a macro.
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
    uint8_t * hmac_key, uint8_t verifier[GARC_ZIP_AES_VERIFIER_LEN]) {
  uint8_t derived[ZIP_AES_MAX_KEY * 2u + GARC_ZIP_AES_VERIFIER_LEN];
  const size_t derived_len = key_len * 2u + GARC_ZIP_AES_VERIFIER_LEN;
  const GSEC_Result result = gsec_pbkdf2(GSEC_PBKDF2_SHA1, password,
      password_len, salt, salt_len, ZIP_AES_ITERATIONS, derived, derived_len);
  if (result != GSEC_OK) {
    gsec_wipe(derived, sizeof(derived));
    return GARC_ERR_INTERNAL;
  }
  memcpy(aes_key, derived, key_len);
  memcpy(hmac_key, derived + key_len, key_len);
  memcpy(verifier, derived + key_len * 2u, GARC_ZIP_AES_VERIFIER_LEN);
  gsec_wipe(derived, sizeof(derived));
  return GARC_OK;
}

/**
 * Documented here as well as in zip_internal.h because doxygen does not match the
 * two declarations when a parameter's array bound is a macro.
 *
 * @param expected The derived verifier.
 * @param actual The verifier from the member.
 * @return Non-zero when they match.
 */
int garc_zip_aes_verifier_matches(
    const uint8_t expected[GARC_ZIP_AES_VERIFIER_LEN],
    const uint8_t actual[GARC_ZIP_AES_VERIFIER_LEN]) {
  return gsec_equal(expected, actual, GARC_ZIP_AES_VERIFIER_LEN) == GSEC_OK;
}

int garc_zip_aes_auth_matches(const uint8_t * hmac_key, size_t key_len,
    const uint8_t * ciphertext, size_t ciphertext_len, const uint8_t * tag,
    size_t tag_len) {
  uint8_t digest[GSEC_SHA1_DIGEST_LEN];
  if (tag_len != GARC_ZIP_AES_AUTH_LEN) {
    return 0;
  }
  if (gsec_hmac(GSEC_HMAC_SHA1, hmac_key, key_len, ciphertext, ciphertext_len,
          digest)
      != GSEC_OK) {
    gsec_wipe(digest, sizeof(digest));
    return 0;
  }
  const int matches = gsec_equal(digest, tag, GARC_ZIP_AES_AUTH_LEN) == GSEC_OK;
  gsec_wipe(digest, sizeof(digest));
  return matches;
}

/**
 * Decrypting stream: CTR and HMAC over a known ciphertext length.
 *
 * @p auth_ok is the reader's flag. It stays 0 until the authentication code
 * has been read and matches. The plaintext of a read is returned even when
 * the code does not match; the reader reports that on the following call.
 */
typedef struct {
  const GARC_Allocator * allocator; ///< For this object.
  GARC_Stream * inner;              ///< Ciphertext, then the authentication code.
  GSEC_Aes_Ctr ctr;                 ///< Little-endian counter, started at 1.
  GSEC_Hmac hmac;                   ///< Over the ciphertext only.
  uint64_t remaining;               ///< Ciphertext bytes not yet read.
  int * auth_ok;                    ///< Set to 1 when the code matches.
  int live;                         ///< CTR and HMAC still hold key material.
} Stream_Aes;

/**
 * Read the authentication code, compare it, and wipe the keys.
 *
 * A tag that was read and does not match leaves @c auth_ok clear and returns
 * ::GARC_OK: the plaintext of this read is still delivered, and the reader
 * reports ::GARC_ERR_PASSWORD_OR_CORRUPT on the call that finds the member
 * over. A failed read of the tag, or a failed HMAC final, is returned as that
 * error instead of being stored as a mismatch.
 *
 * @param state The stream.
 * @return ::GARC_OK, the stream's I/O error, ::GARC_ERR_CORRUPT when the tag
 *   is short, or ::GARC_ERR_INTERNAL when the HMAC final fails.
 */
static GARC_Result stream_aes_finish(Stream_Aes * state) {
  uint8_t tag[GARC_ZIP_AES_AUTH_LEN];
  uint8_t digest[GSEC_SHA1_DIGEST_LEN];
  size_t got = 0;
  const GARC_Result read
      = garc_stream_read(state->inner, tag, sizeof(tag), &got);
  GARC_Result result = GARC_OK;
  int finalized = 0;
  if (read != GARC_OK) {
    result = read;
  }
  else if (got != sizeof(tag)) {
    result = GARC_ERR_CORRUPT;
  }
  else if (gsec_hmac_final(&state->hmac, digest) != GSEC_OK) {
    gsec_wipe(&state->hmac, sizeof(state->hmac));
    finalized = 1;
    result = GARC_ERR_INTERNAL;
  }
  else {
    finalized = 1;
    if (gsec_equal(digest, tag, GARC_ZIP_AES_AUTH_LEN) == GSEC_OK) {
      *state->auth_ok = 1;
    }
  }
  if (!finalized && gsec_hmac_final(&state->hmac, digest) != GSEC_OK) {
    gsec_wipe(&state->hmac, sizeof(state->hmac));
  }
  gsec_wipe(digest, sizeof(digest));
  gsec_wipe(tag, sizeof(tag));
  gsec_aes_ctr_wipe(&state->ctr);
  state->live = 0;
  return result;
}

static GARC_Result stream_aes_read(
    void * ctx, void * buffer, size_t size, size_t * out_read) {
  Stream_Aes * state = (Stream_Aes *)ctx;
  if (!state->remaining) {
    *out_read = 0;
    return GARC_OK;
  }
  size_t want = size;
  if ((uint64_t)want > state->remaining) {
    want = (size_t)state->remaining;
  }
  size_t got = 0;
  const GARC_Result result = garc_stream_read(state->inner, buffer, want, &got);
  if (result != GARC_OK) {
    return result;
  }
  if (got) {
    if (gsec_hmac_update(&state->hmac, buffer, got) != GSEC_OK
        || gsec_aes_ctr_update(&state->ctr, buffer, buffer, got) != GSEC_OK) {
      return GARC_ERR_INTERNAL;
    }
    state->remaining -= (uint64_t)got;
  }
  if (!state->remaining && state->live) {
    // The authentication code sits immediately after the ciphertext. A tag
    // that does not match still returns the plaintext; the mismatch is
    // reported when the caller next asks and is told the member is over. A
    // failed read of the tag, or a failed HMAC final, is this read's error.
    const GARC_Result finished = stream_aes_finish(state);
    if (finished != GARC_OK) {
      return finished;
    }
  }
  *out_read = got;
  return GARC_OK;
}

static void stream_aes_destroy(GARC_Stream * stream) {
  Stream_Aes * state = (Stream_Aes *)stream->cb.ctx;
  const GARC_Allocator * allocator = state->allocator;
  if (state->live) {
    uint8_t digest[GSEC_SHA1_DIGEST_LEN];
    if (gsec_hmac_final(&state->hmac, digest) != GSEC_OK) {
      gsec_wipe(&state->hmac, sizeof(state->hmac));
    }
    gsec_wipe(digest, sizeof(digest));
    gsec_aes_ctr_wipe(&state->ctr);
    state->live = 0;
  }
  gsec_wipe(state, sizeof(*state));
  gcu_allocator_free(allocator, state);
}

/**
 * Start CTR at 1 and HMAC over the key, or wipe both on failure.
 *
 * @param ctr CTR context.
 * @param hmac HMAC context.
 * @param aes_key AES key.
 * @param hmac_key HMAC key.
 * @param key_len 16, 24 or 32.
 * @return ::GARC_OK, or ::GARC_ERR_INTERNAL.
 */
static GARC_Result zip_aes_start(GSEC_Aes_Ctr * ctr, GSEC_Hmac * hmac,
    const uint8_t * aes_key, const uint8_t * hmac_key, size_t key_len) {
  uint8_t counter[GSEC_AES_BLOCK_LEN];
  memset(counter, 0, sizeof(counter));
  // Little-endian integer 1. The first keystream block is counter value 1,
  // not 0, which is what WinZip AES specifies.
  counter[0] = 1u;
  if (gsec_aes_ctr_init(ctr, aes_key, key_len, counter, GSEC_AES_CTR_LE)
      != GSEC_OK) {
    gsec_wipe(counter, sizeof(counter));
    return GARC_ERR_INTERNAL;
  }
  if (gsec_hmac_init(hmac, GSEC_HMAC_SHA1, hmac_key, key_len) != GSEC_OK) {
    gsec_aes_ctr_wipe(ctr);
    gsec_wipe(counter, sizeof(counter));
    return GARC_ERR_INTERNAL;
  }
  gsec_wipe(counter, sizeof(counter));
  return GARC_OK;
}

GARC_Result garc_zip_aes_stream_create(const GARC_Allocator * allocator,
    GARC_Stream * inner, const uint8_t * aes_key, const uint8_t * hmac_key,
    size_t key_len, uint64_t ciphertext_len, int * auth_ok,
    GARC_Stream ** out_stream) {
  if (!inner || !aes_key || !hmac_key || !auth_ok || !out_stream || !key_len) {
    return GARC_ERR_INVALID;
  }
  if (!allocator) {
    allocator = garc_allocator_default();
  }
  Stream_Aes * state
      = (Stream_Aes *)gcu_allocator_calloc(allocator, 1, sizeof(Stream_Aes));
  if (!state) {
    return GARC_ERR_OOM;
  }
  state->allocator = allocator;
  state->inner = inner;
  state->remaining = ciphertext_len;
  state->auth_ok = auth_ok;
  if (zip_aes_start(&state->ctr, &state->hmac, aes_key, hmac_key, key_len)
      != GARC_OK) {
    gcu_allocator_free(allocator, state);
    return GARC_ERR_INTERNAL;
  }
  state->live = 1;

  GARC_Stream_Callbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.ctx = state;
  callbacks.read = stream_aes_read;

  GARC_Stream * stream = NULL;
  const GARC_Result result = garc_stream_create_callback_with_allocator(
      &callbacks, allocator, &stream);
  if (result != GARC_OK) {
    uint8_t digest[GSEC_SHA1_DIGEST_LEN];
    if (gsec_hmac_final(&state->hmac, digest) != GSEC_OK) {
      gsec_wipe(&state->hmac, sizeof(state->hmac));
    }
    gsec_wipe(digest, sizeof(digest));
    gsec_aes_ctr_wipe(&state->ctr);
    gsec_wipe(state, sizeof(*state));
    gcu_allocator_free(allocator, state);
    return result;
  }
  stream->owned_destroy = stream_aes_destroy;
  *out_stream = stream;
  return GARC_OK;
}

/**
 * Key material for one member being written.
 *
 * The typedef in zip_internal.h is the name callers use. This is the object.
 */
struct GARC_Zip_Aes {
  const GARC_Allocator * allocator; ///< For this object.
  GSEC_Aes_Ctr ctr;                 ///< Little-endian counter, started at 1.
  GSEC_Hmac hmac;                   ///< Over the ciphertext only.
  int live;                         ///< CTR and HMAC still hold key material.
};

GARC_Result garc_zip_aes_begin(const GARC_Allocator * allocator,
    const void * password, size_t password_len, uint8_t strength,
    uint8_t * prefix, size_t prefix_cap, size_t * prefix_len,
    GARC_Zip_Aes ** out) {
  size_t salt_len = 0;
  size_t key_len = 0;
  if (!prefix || !prefix_len || !out
      || !zip_aes_lengths(strength, &salt_len, &key_len)) {
    return GARC_ERR_INVALID;
  }
  if ((!password && password_len) || prefix_cap < salt_len + GARC_ZIP_AES_VERIFIER_LEN) {
    return GARC_ERR_INVALID;
  }
  if (!allocator) {
    allocator = garc_allocator_default();
  }

  const GSEC_Result drawn = gsec_random_bytes(prefix, salt_len, NULL);
  if (drawn != GSEC_OK) {
    return drawn == GSEC_ERR_IO ? GARC_ERR_IO : GARC_ERR_INTERNAL;
  }

  uint8_t aes_key[ZIP_AES_MAX_KEY];
  uint8_t hmac_key[ZIP_AES_MAX_KEY];
  uint8_t verifier[GARC_ZIP_AES_VERIFIER_LEN];
  const GARC_Result derived = garc_zip_aes_derive(password, password_len, prefix,
      salt_len, aes_key, key_len, hmac_key, verifier);
  if (derived != GARC_OK) {
    gsec_wipe(prefix, salt_len);
    gsec_wipe(aes_key, sizeof(aes_key));
    gsec_wipe(hmac_key, sizeof(hmac_key));
    return derived;
  }
  memcpy(prefix + salt_len, verifier, GARC_ZIP_AES_VERIFIER_LEN);
  *prefix_len = salt_len + GARC_ZIP_AES_VERIFIER_LEN;

  GARC_Zip_Aes * aes
      = (GARC_Zip_Aes *)gcu_allocator_calloc(allocator, 1, sizeof(GARC_Zip_Aes));
  if (!aes) {
    gsec_wipe(aes_key, sizeof(aes_key));
    gsec_wipe(hmac_key, sizeof(hmac_key));
    gsec_wipe(verifier, sizeof(verifier));
    gsec_wipe(prefix, *prefix_len);
    return GARC_ERR_OOM;
  }
  aes->allocator = allocator;
  if (zip_aes_start(&aes->ctr, &aes->hmac, aes_key, hmac_key, key_len)
      != GARC_OK) {
    gsec_wipe(aes_key, sizeof(aes_key));
    gsec_wipe(hmac_key, sizeof(hmac_key));
    gsec_wipe(verifier, sizeof(verifier));
    gsec_wipe(prefix, *prefix_len);
    gcu_allocator_free(allocator, aes);
    return GARC_ERR_INTERNAL;
  }
  aes->live = 1;
  gsec_wipe(aes_key, sizeof(aes_key));
  gsec_wipe(hmac_key, sizeof(hmac_key));
  gsec_wipe(verifier, sizeof(verifier));
  *out = aes;
  return GARC_OK;
}

GARC_Result garc_zip_aes_encrypt(
    GARC_Zip_Aes * aes, const void * in, void * out, size_t n) {
  if (!aes || !aes->live || (!in && n) || (!out && n)) {
    return GARC_ERR_INVALID;
  }
  if (!n) {
    return GARC_OK;
  }
  if (gsec_aes_ctr_update(&aes->ctr, in, out, n) != GSEC_OK
      || gsec_hmac_update(&aes->hmac, out, n) != GSEC_OK) {
    return GARC_ERR_INTERNAL;
  }
  return GARC_OK;
}

/**
 * Documented here as well as in zip_internal.h because doxygen does not match the
 * two declarations when a parameter's array bound is a macro.
 *
 * @param aes A live object.
 * @param tag Receives ::GARC_ZIP_AES_AUTH_LEN bytes.
 * @return ::GARC_OK, or ::GARC_ERR_INVALID.
 */
GARC_Result garc_zip_aes_finish(
    GARC_Zip_Aes * aes, uint8_t tag[GARC_ZIP_AES_AUTH_LEN]) {
  uint8_t digest[GSEC_SHA1_DIGEST_LEN];
  if (!aes || !aes->live || !tag) {
    return GARC_ERR_INVALID;
  }
  if (gsec_hmac_final(&aes->hmac, digest) != GSEC_OK) {
    return GARC_ERR_INTERNAL;
  }
  memcpy(tag, digest, GARC_ZIP_AES_AUTH_LEN);
  gsec_wipe(digest, sizeof(digest));
  gsec_aes_ctr_wipe(&aes->ctr);
  aes->live = 0;
  return GARC_OK;
}

void garc_zip_aes_checkpoint(
    const GARC_Zip_Aes * aes, GARC_Zip_Aes_Checkpoint * saved) {
  memcpy(&saved->ctr, &aes->ctr, sizeof(saved->ctr));
  memcpy(&saved->hmac, &aes->hmac, sizeof(saved->hmac));
}

void garc_zip_aes_restore(GARC_Zip_Aes * aes, GARC_Zip_Aes_Checkpoint * saved) {
  memcpy(&aes->ctr, &saved->ctr, sizeof(aes->ctr));
  memcpy(&aes->hmac, &saved->hmac, sizeof(aes->hmac));
  gsec_wipe(saved, sizeof(*saved));
}

void garc_zip_aes_checkpoint_wipe(GARC_Zip_Aes_Checkpoint * saved) {
  if (saved) {
    gsec_wipe(saved, sizeof(*saved));
  }
}

void garc_zip_aes_destroy(GARC_Zip_Aes * aes) {
  if (!aes) {
    return;
  }
  if (aes->live) {
    uint8_t digest[GSEC_SHA1_DIGEST_LEN];
    if (gsec_hmac_final(&aes->hmac, digest) != GSEC_OK) {
      gsec_wipe(&aes->hmac, sizeof(aes->hmac));
    }
    gsec_wipe(digest, sizeof(digest));
    gsec_aes_ctr_wipe(&aes->ctr);
    aes->live = 0;
  }
  const GARC_Allocator * allocator = aes->allocator;
  gsec_wipe(aes, sizeof(*aes));
  gcu_allocator_free(allocator, aes);
}
