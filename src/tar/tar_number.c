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
 * tar's numeric header fields, which are four encodings wearing one shape.
 *
 * A field is a fixed run of bytes holding an octal number, and every part of
 * that sentence has an exception. The terminator may be a NUL, a space, both,
 * or absent when the digits fill the field exactly. Leading spaces are
 * permitted and so are leading NULs in the wild. An entirely blank field means
 * zero. And GNU's extension replaces the whole scheme with base-256 when the
 * high bit of the first byte is set, because 11 octal digits cap a size at 8 GB
 * and files got bigger.
 *
 * Each of those is a plausible *wrong answer* rather than an error: a reader
 * that stops at the first space reads 0 from " 0000644", one that treats a
 * blank field as corrupt rejects v7 archives, and one that ignores the high bit
 * reads a 40-bit size as a nonsensical small octal number. So all of it is
 * parsed here, once, rather than at each field.
 */

#include <ghoti.io/archive/macros.h>

#include <stdint.h>

#include "tar/tar_internal.h"

/** The bit that says "this field is base-256, not octal". */
#define GARC_TAR_BASE256_FLAG 0x80u

/**
 * Parse base-256.
 *
 * The encoding is a two's-complement integer spread over the whole field, with
 * **bit 7 of the first byte as the base-256 flag and bit 6 as the sign bit**.
 * So the value is 7 + 8*(n-1) bits wide for an n-byte field, and 0x80 and 0xFF
 * leading bytes are just the two commonest cases of that - a positive value
 * whose top seven bits are zero, and -1 sign extension.
 *
 * This matters rather than being pedantry. Reading it as "0x80 means positive
 * and the remaining bytes are the magnitude" discards six value bits of the
 * first byte, so a field like 0x81 0x00... reads as 0 instead of 2^88. GNU tar
 * writes the general form and libarchive reads it; a reader that handles only
 * the two common leading bytes agrees with both on every archive either of them
 * happens to have written and disagrees on the format.
 *
 * A field wider than 64 bits of value is refused rather than truncated, which
 * means checking that the bits above the 64th are sign extension before any of
 * them is dropped.
 *
 * @param field The field bytes, whose first byte has the high bit set.
 * @param length The field length.
 * @param out_value Receives the value.
 * @return GARC_OK, or GARC_ERR_CORRUPT when the value does not fit in 64 bits
 *   or the sign bits contradict the value.
 */
static GARC_Result tar_parse_base256(
    const uint8_t * field, size_t length, int64_t * out_value) {
  // Bit 6 of the first byte is the sign; bit 7 is the flag that got us here.
  const int negative = (field[0] & 0x40u) != 0u;

  // Width of the two's-complement value: seven bits from the first byte and
  // eight from each of the rest.
  size_t bits = 7u + 8u * (length - 1u);

  size_t i = 0;
  if (bits > 64u) {
    // Peel the leading sign extension. Every bit above the 64th has to be a
    // copy of the sign, or the value does not fit and refusing is the only
    // honest answer - a truncation here is a wrong size, not a smaller one.
    const uint8_t expect_first = negative ? 0x7Fu : 0x00u;
    if ((field[0] & 0x7Fu) != expect_first) {
      return GARC_ERR_CORRUPT;
    }
    bits -= 7u;
    i = 1u;

    const uint8_t expect_rest = negative ? 0xFFu : 0x00u;
    while (bits > 64u) {
      if (field[i] != expect_rest) {
        return GARC_ERR_CORRUPT;
      }
      i++;
      bits -= 8u;
    }
  }

  uint64_t pattern = 0;
  if (i == 0u) {
    pattern = (uint64_t)(field[0] & 0x7Fu);
    i = 1u;
  }
  for (; i < length; ++i) {
    pattern = (pattern << 8) | (uint64_t)field[i];
  }

  // Interpret `pattern` as two's complement of width `bits`. Every conversion
  // below is performed on a value already known to be in range, because casting
  // an out-of-range unsigned value to int64_t is implementation-defined in C17.
  if (bits == 64u) {
    const uint64_t half = (uint64_t)1u << 63;
    if (negative) {
      if (pattern < half) {
        return GARC_ERR_CORRUPT; // Sign says negative, the value's top bit does not.
      }
      *out_value = (int64_t)(pattern - half) + INT64_MIN;
    } else {
      if (pattern >= half) {
        return GARC_ERR_CORRUPT;
      }
      *out_value = (int64_t)pattern;
    }
    return GARC_OK;
  }

  // Narrower than 64 bits, so the span and the value both fit in an int64_t.
  //
  // **No contradiction check here, and that is a fact about the encoding rather
  // than an omission.** This branch is reached only when nothing was peeled,
  // and then the value's own sign bit *is* bit 6 of the first byte - the same
  // bit `negative` was read from. So a leading byte that says negative over a
  // value whose top bit is clear cannot be constructed at this width: the two
  // are one bit. The checks in the peeled branch above are real because the
  // sign bits that were dropped are different bits from bit 63.
  //
  // A first draft had the same two refusals here. They were dead code - a test
  // written to fire one instead read a legitimate -2^62 - and dead code in a
  // parser is worse than absent, because it reads as a guard somebody is
  // relying on.
  // **The subtraction is spelled as a negation, not as `pattern - span`.** For
  // an 8-byte field `bits` is 63, so `span` is 2^63 - which does not fit in an
  // int64_t, and casting it there is implementation-defined. On this compiler it
  // becomes INT64_MIN, and `pattern - INT64_MIN` then overflows: UBSan reports
  // "signed integer overflow: 9223372036854775807 - -9223372036854775808". The
  // release build produced the right answer anyway, which is exactly why this
  // needed a sanitizer to find rather than a test.
  //
  // `span - pattern` is done in unsigned arithmetic and lands in
  // (0, 2^(bits-1)], so it always fits, and negating a value that fits is
  // defined. Nothing is ever converted out of range.
  const uint64_t span = (uint64_t)1u << bits;
  *out_value = negative
      ? -(int64_t)(span - pattern)
      : (int64_t)pattern;
  return GARC_OK;
}

/**
 * Parse the octal form.
 *
 * @param field The field bytes.
 * @param length The field length.
 * @param out_value Receives the value.
 * @return GARC_OK, or GARC_ERR_CORRUPT for a byte that is not an octal digit,
 *   a terminator or leading padding.
 */
static GARC_Result tar_parse_octal(
    const uint8_t * field, size_t length, uint64_t * out_value) {
  size_t i = 0;

  // Leading padding. Spaces are what the standard permits; NULs appear in the
  // wild, and a reader that refuses them rejects real archives.
  while (i < length && (field[i] == ' ' || field[i] == '\0')) {
    i++;
  }

  // An entirely blank field means zero rather than corrupt: v7 writers leave
  // fields they have no value for blank, and a device number on a regular file
  // is blank in almost every archive there is.
  if (i == length) {
    *out_value = 0;
    return GARC_OK;
  }

  uint64_t value = 0;
  int digits = 0;
  while (i < length) {
    uint8_t byte = field[i];
    if (byte == '\0' || byte == ' ') {
      break; // Terminator. The rest of the field is padding.
    }
    if (byte < '0' || byte > '7') {
      return GARC_ERR_CORRUPT;
    }
    // Three bits per digit. A 12-byte field of octal digits is 36 bits, so this
    // cannot overflow for any real field - but the check is here rather than
    // argued about, because the field length is a parameter.
    if (value > (UINT64_MAX >> 3)) {
      return GARC_ERR_CORRUPT;
    }
    value = (value << 3) | (uint64_t)(byte - '0');
    digits++;
    i++;
  }

  // No `if (!digits)` arm, and that is deliberate. The leading-padding loop above
  // consumes every space and every NUL, so if this point is reached with i <
  // length then field[i] was neither - which makes it either an octal digit or a
  // refusal, and the loop cannot have run zero times. A first draft had the arm;
  // it was dead code, found by trying to write a field that would reach it.

  // Everything after the terminator must be padding. A field with digits, a
  // NUL, and then more digits is not a number, and reading only the first part
  // is how a reader disagrees with the writer about a size.
  while (i < length) {
    if (field[i] != '\0' && field[i] != ' ') {
      return GARC_ERR_CORRUPT;
    }
    i++;
  }

  *out_value = value;
  return GARC_OK;
}

GARC_Result garc_tar_parse_uint(
    const uint8_t * field, size_t length, uint64_t * out_value) {
  if (!field || !out_value || !length) {
    return GARC_ERR_INVALID;
  }

  if ((field[0] & GARC_TAR_BASE256_FLAG) != 0u) {
    int64_t signed_value = 0;
    GARC_Result result = tar_parse_base256(field, length, &signed_value);
    if (result != GARC_OK) {
      return result;
    }
    if (signed_value < 0) {
      // A negative size, uid or device number is not a value this field can
      // legitimately carry, and clamping to zero would make a hostile archive
      // look like an empty file.
      return GARC_ERR_CORRUPT;
    }
    *out_value = (uint64_t)signed_value;
    return GARC_OK;
  }

  return tar_parse_octal(field, length, out_value);
}

GARC_Result garc_tar_parse_int(
    const uint8_t * field, size_t length, int64_t * out_value) {
  if (!field || !out_value || !length) {
    return GARC_ERR_INVALID;
  }

  if ((field[0] & GARC_TAR_BASE256_FLAG) != 0u) {
    return tar_parse_base256(field, length, out_value);
  }

  uint64_t value = 0;
  GARC_Result result = tar_parse_octal(field, length, &value);
  if (result != GARC_OK) {
    return result;
  }
  // The octal form has no sign, so the only way it fails here is by being too
  // large to represent - which a 12-byte field cannot be, and a longer one
  // could.
  if (value > (uint64_t)INT64_MAX) {
    return GARC_ERR_CORRUPT;
  }
  *out_value = (int64_t)value;
  return GARC_OK;
}

GARC_Result garc_tar_format_int(uint8_t * field, size_t length, int64_t value,
    GARC_Tar_Number_Form * out_form) {
  // Two bytes is the narrowest field that can hold one octal digit and a
  // terminator; nothing in tar is narrower, and a length of 0 or 1 would make
  // the digit loop below write outside the field.
  if (!field || !out_form || length < 2u) {
    return GARC_ERR_INVALID;
  }

  // **Octal with the widest run of digits the field allows**, zero-padded, with
  // a single NUL terminator. GNU tar writes exactly this; libarchive spends one
  // of the digits on a trailing space instead, which is equally legal and
  // expresses one octal digit less - so this spelling is the one that keeps the
  // threshold at which a pax record becomes necessary as high as the format
  // permits, and it is the spelling every reader sees most often.
  if (value >= 0) {
    const size_t digits = length - 1u;
    // Three bits per digit. A field wide enough for the shift to overflow is
    // one whose octal form holds any int64_t there is, so the comparison is
    // skipped rather than computed - `1u << 64` is undefined, not large.
    const int fits = (digits * 3u >= 63u)
        || ((uint64_t)value < ((uint64_t)1u << (digits * 3u)));
    if (fits) {
      uint64_t magnitude = (uint64_t)value;
      field[digits] = '\0';
      for (size_t i = digits; i-- > 0u;) {
        field[i] = (uint8_t)('0' + (magnitude & 7u));
        magnitude >>= 3;
      }
      *out_form = GARC_TAR_NUMBER_OCTAL;
      return GARC_OK;
    }
  }

  // Base-256: the value **sign-extended across the whole field**, with bit 7 of
  // the first byte set as the flag. Bit 6 is then the value's sign bit, which is
  // what sign extension puts there, and it is what garc_tar_parse_uint() reads
  // the sign from. Writing "0x80 then the magnitude" instead would put a
  // positive value's top bit where the sign belongs, so every value at or above
  // half the field's span would read back negative.
  const size_t bits = 7u + 8u * (length - 1u);
  if (bits < 64u) {
    // A field narrow enough to constrain an int64_t: the value has to fit the
    // two's-complement span, or bit 6 ends up carrying value rather than sign
    // and the number reads back as its own negation. An 8-byte field holds
    // 63 bits, so this refuses at 2^62.
    const int64_t limit = (int64_t)1 << (bits - 1u);
    if (value >= limit || value < -limit) {
      return GARC_ERR_UNSUPPORTED;
    }
  }

  // Conversion to an unsigned type is modulo 2^64 and so is defined for a
  // negative value; the two's-complement pattern is what that produces.
  const uint64_t pattern = (uint64_t)value;
  const uint8_t extend = (value < 0) ? 0xFFu : 0x00u;
  for (size_t i = 0; i < length; ++i) {
    // How far this byte is from the low end. The low eight bytes come from the
    // pattern and everything above them is sign extension, which is what the
    // parser peels.
    const size_t from_end = length - 1u - i;
    field[i] = (from_end < 8u)
        ? (uint8_t)((pattern >> (from_end * 8u)) & 0xFFu)
        : extend;
  }
  field[0] = (uint8_t)(field[0] | GARC_TAR_BASE256_FLAG);
  *out_form = GARC_TAR_NUMBER_BASE256;
  return GARC_OK;
}

GARC_Result garc_tar_format_uint(uint8_t * field, size_t length, uint64_t value,
    GARC_Tar_Number_Form * out_form) {
  // Above INT64_MAX there is no field this library can write: the octal form
  // would need 22 digits and base-256 is two's complement, so the value would
  // read back negative. garc_tar_parse_uint() refuses the same values from the
  // other side, which is the property worth having - a writer that can produce
  // a field its own reader rejects is a library that disagrees with itself.
  if (value > (uint64_t)INT64_MAX) {
    return GARC_ERR_UNSUPPORTED;
  }
  return garc_tar_format_int(field, length, (int64_t)value, out_form);
}
