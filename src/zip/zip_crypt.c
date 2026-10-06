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
 * ZipCrypto: the traditional PKWARE cipher, read and never written.
 *
 * **It is broken, and that is not a reason to refuse reading it.** Biham and
 * Kocher's 1994 attack recovers the three keys from about a dozen known
 * plaintext bytes, and a zip is full of known bytes; the archive also leaves
 * every filename, every size and every CRC in the clear whatever the password.
 * So this decrypts what exists in the world and `archive` will never produce
 * any. Writing it is refused permanently, with a status that says the cipher is
 * broken rather than that a feature is missing - no option name makes shipping a
 * cipher we know is broken honest.
 *
 * **The whole cipher is CRC-32, which is why it needs no cryptography library
 * and lands in phase D rather than behind `security`.** Three 32-bit words are
 * mixed with each plaintext byte, and two of the three steps are one table
 * lookup of the CRC-32 polynomial - `compress`'s `gcomp_crc32_update()` over a
 * single byte, exactly, because that function operates on the *unfinalized*
 * running value and the cipher's step has no inversion in it either. A private
 * copy of the table here would be a second implementation of something the
 * dependency already has, and it would be the copy that went wrong.
 *
 * Three things about the shape of this file, each of which could have gone the
 * other way:
 *
 * **The keys are derived at ::garc_zip_set_password().** The three words after
 * the password has been mixed in are all any ZipCrypto member needs. The
 * password itself is kept beside them, because a WinZip AES member has its own
 * salt and cannot be derived until that salt is read; that copy lives in the
 * zip reader, not in this file. An empty password stays distinct from no
 * password, which a missing buffer would not be.
 *
 * **Decryption is a stream, not a transform.** A member's plaintext is its
 * *compressed* bytes, so for a deflated member the layering is
 * decrypt-then-inflate and the decoder has to read through this. Making it a
 * ::GARC_Stream means the codec layer needs to know nothing about encryption: it
 * slices whatever it is given. A reader that decrypted into a buffer first would
 * have to hold a whole member.
 *
 * **The keystream depends on the plaintext**, which is what makes this a
 * self-synchronising cipher and what makes the stream stateful in a way a
 * counter mode is not: every byte decrypted updates the keys with the byte it
 * produced. There is no seeking backwards in it, which is why the stream offers
 * no seek - the same answer the slice and the decompressing stream give, for a
 * different reason.
 */

#include <ghoti.io/archive/macros.h>

#include <string.h>

#include <ghoti.io/compress/crc32.h>

#include "stream/stream_internal.h"
#include "zip/zip_internal.h"

/** The initial key words, from APPNOTE section 6.1. */
static const uint32_t ZIP_CRYPT_SEED[3] = {
  305419896u, 591751049u, 878082192u
};

/** The multiplier in the second key's update, from APPNOTE section 6.1. */
#define ZIP_CRYPT_MULTIPLIER 134775813u

/**
 * Mix one plaintext byte into the keys.
 *
 * The cipher's whole state transition. Two of its three steps are a single-byte
 * CRC-32 update, taken from `compress` rather than from a table of our own.
 *
 * @param keys The three key words, updated in place.
 * @param plain The plaintext byte just produced, or one byte of the password.
 */
static void zip_crypt_update(uint32_t keys[3], uint8_t plain) {
  keys[0] = gcomp_crc32_update(keys[0], &plain, 1u);
  keys[1] += keys[0] & 0xFFu;
  keys[1] = keys[1] * ZIP_CRYPT_MULTIPLIER + 1u;
  const uint8_t high = (uint8_t)(keys[1] >> 24);
  keys[2] = gcomp_crc32_update(keys[2], &high, 1u);
}

/**
 * The next keystream byte.
 *
 * `(temp * (temp ^ 1)) >> 8` over the low 16 bits of the third key, with bit 1
 * forced on. The multiplication is done in 32 bits and the operands are 16, so
 * it cannot overflow - which is worth saying because the published pseudocode is
 * written in terms of a 16-bit `temp` and an implementation that kept it there
 * would be wrong.
 *
 * @param keys The three key words, unchanged.
 * @return One byte of keystream.
 */
static uint8_t zip_crypt_keystream(const uint32_t keys[3]) {
  const uint32_t temp = (keys[2] | 2u) & 0xFFFFu;
  return (uint8_t)(((temp * (temp ^ 1u)) >> 8) & 0xFFu);
}

void garc_zip_crypt_derive(uint32_t keys[3], const void * password,
    size_t length) {
  memcpy(keys, ZIP_CRYPT_SEED, sizeof(ZIP_CRYPT_SEED));
  const uint8_t * bytes = (const uint8_t *)password;
  for (size_t i = 0; i < length; ++i) {
    zip_crypt_update(keys, bytes[i]);
  }
}

void garc_zip_crypt_decrypt(uint32_t keys[3], uint8_t * data, size_t length) {
  for (size_t i = 0; i < length; ++i) {
    const uint8_t plain = (uint8_t)(data[i] ^ zip_crypt_keystream(keys));
    zip_crypt_update(keys, plain);
    data[i] = plain;
  }
}

/**
 * Whether a decrypted encryption header's check byte agrees.
 *
 * Documented here as well as in zip_internal.h because doxygen does not match the
 * two declarations - the parameter's array bound is a macro - and an undocumented
 * function is what `make check-docs` fails on.
 *
 * @param header The 12 decrypted bytes.
 * @param crc32 The member's declared CRC-32.
 * @param dos_time The member's DOS time field.
 * @param have_descriptor Whether general purpose flag bit 3 is set.
 * @return Non-zero when the password is probably right.
 */
int garc_zip_crypt_header_ok(const uint8_t header[GARC_ZIP_CRYPT_HEADER_SIZE],
    uint32_t crc32, uint16_t dos_time, int have_descriptor) {
  const uint8_t check = header[GARC_ZIP_CRYPT_HEADER_SIZE - 1u];
  if (check == (uint8_t)(crc32 >> 24)) {
    return 1;
  }
  // **The second arm is not theoretical, and the corpus is what says so.** When
  // general purpose flag bit 3 is set the sizes and the CRC are in a data
  // descriptor *after* the data, so a streaming writer has no CRC to derive a
  // check byte from and uses the high byte of the DOS time field instead.
  // Info-ZIP sets bit 3 on every encrypted member it writes, so a reader that
  // only knew the CRC arm would reject the correct password for every encrypted
  // archive `zip` has ever produced - which is what `infozip-crypto.zip`
  // demonstrates, where the check byte is 0x0D and the CRC's high byte is 0x51.
  //
  // Accepting either where bit 3 is set rather than only the time is what unzip
  // does, and it costs one extra byte of false-accept probability on a member
  // whose writer chose the other convention.
  return have_descriptor && check == (uint8_t)(dos_time >> 8);
}

/**
 * The state behind a decrypting stream: the keys, and the stream it reads.
 *
 * @p inner is **borrowed**, like the slice's. The keys are a copy, taken when the
 * stream was created, because they are the member's and not the archive's: the
 * encryption header has already been mixed into them by then.
 */
typedef struct {
  const GARC_Allocator * allocator; ///< For this object.
  GARC_Stream * inner;              ///< Where the ciphertext comes from.
  uint32_t keys[3];                 ///< The cipher's state, mid-member.
} Stream_Crypt;

static GARC_Result stream_crypt_read(
    void * ctx, void * buffer, size_t size, size_t * out_read) {
  Stream_Crypt * crypt = (Stream_Crypt *)ctx;
  size_t got = 0;
  GARC_Result result = garc_stream_read(crypt->inner, buffer, size, &got);
  if (result != GARC_OK) {
    return result;
  }
  // In place: the plaintext of a ZipCrypto byte is the same length as its
  // ciphertext, so there is no staging buffer here and none needed. A short read
  // is passed through unchanged - the bound on a member's data is the slice's
  // business and the count owed is the reader's.
  garc_zip_crypt_decrypt(crypt->keys, (uint8_t *)buffer, got);
  *out_read = got;
  return GARC_OK;
}

static void stream_crypt_destroy(GARC_Stream * stream) {
  Stream_Crypt * crypt = (Stream_Crypt *)stream->cb.ctx;
  // The keys are wiped before the memory goes back. They are equivalent to the
  // password for this archive, and an allocator that reuses a block without
  // clearing it is the ordinary case rather than the exceptional one.
  memset(crypt->keys, 0, sizeof(crypt->keys));
  gcu_allocator_free(crypt->allocator, crypt);
}

GARC_Result garc_zip_crypt_stream_create(const GARC_Allocator * allocator,
    GARC_Stream * inner, const uint32_t keys[3], GARC_Stream ** out_stream) {
  if (!inner || !keys || !out_stream) {
    return GARC_ERR_INVALID;
  }
  if (!allocator) {
    allocator = garc_allocator_default();
  }

  Stream_Crypt * crypt = (Stream_Crypt *)gcu_allocator_calloc(
      allocator, 1, sizeof(Stream_Crypt));
  if (!crypt) {
    return GARC_ERR_OOM;
  }
  crypt->allocator = allocator;
  crypt->inner = inner;
  memcpy(crypt->keys, keys, sizeof(crypt->keys));

  GARC_Stream_Callbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.ctx = crypt;
  callbacks.read = stream_crypt_read;

  GARC_Stream * stream = NULL;
  GARC_Result result = garc_stream_create_callback_with_allocator(
      &callbacks, allocator, &stream);
  if (result != GARC_OK) {
    memset(crypt->keys, 0, sizeof(crypt->keys));
    gcu_allocator_free(allocator, crypt);
    return result;
  }
  stream->owned_destroy = stream_crypt_destroy;

  *out_stream = stream;
  return GARC_OK;
}
