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
 * Metadata a tar carries in front of a header rather than in it.
 *
 * A tar header is 512 fixed bytes, so anything that does not fit one - a name
 * longer than 100 bytes that will not split at a '/', a link target longer than
 * 100 bytes, a size above 8 GB in a format with no base-256 - has to arrive as
 * its own block, in front of the member it describes. GNU spells that an `L` or
 * `K` member; pax spells it an `x` or `g` member of `len key=value\n` records.
 *
 * **The carrier is not a member**, and that is the whole of why this file
 * exists. It has a name (`././@LongLink`), a size and a checksum, so a reader
 * that simply walks headers hands one to its caller as a file - which reports an
 * artefact of the format as content, and does it while the real member's name is
 * silently the truncated one in the next header.
 *
 * Reference documents are named in tar_internal.h.
 */

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/tar.h>
#include <ghoti.io/cutil/allocator.h>
#include <stdint.h>
#include <string.h>

#include "tar/tar_internal.h"

/**
 * Make sure a buffer can hold @p wanted bytes and a terminator.
 *
 * Grows and never shrinks: an archive of long names would otherwise allocate and
 * free once per member, and the buffer's lifetime is the archive's.
 *
 * @param archive The archive, for its allocator.
 * @param buffer The buffer.
 * @param wanted How many bytes have to fit.
 * @return GARC_OK, or GARC_ERR_OOM.
 */
static GARC_Result tar_buffer_reserve(
    GARC_Archive * archive, GARC_Tar_Buffer * buffer, size_t wanted) {
  if (buffer->capacity >= wanted + 1u) {
    return GARC_OK;
  }
  char * bytes = (char *)gcu_allocator_malloc(archive->allocator, wanted + 1u);
  if (!bytes) {
    return GARC_ERR_OOM;
  }
  // A fresh allocation rather than a realloc, and the old block freed only once
  // the new one exists: nothing here ever reads what the buffer held before, so
  // copying it across would be work for nobody, and a realloc that failed would
  // take the old block with it.
  //
  // What bounds a read is @ref GARC_Tar_Buffer.length, not the allocation - so a
  // shorter payload written into a buffer that still holds a longer one is
  // correct by that and by nothing else, which is why there is a test for it.
  gcu_allocator_free(archive->allocator, buffer->bytes);
  buffer->bytes = bytes;
  buffer->capacity = wanted + 1u;
  buffer->length = 0;
  return GARC_OK;
}

void garc_tar_release(GARC_Archive * archive) {
  GARC_Tar_Buffer * const buffers[4] = {
    &archive->long_name,
    &archive->long_link,
    &archive->pax_next.records,
    &archive->pax_global.records,
  };
  for (size_t i = 0; i < 4u; ++i) {
    gcu_allocator_free(archive->allocator, buffers[i]->bytes);
    buffers[i]->bytes = NULL;
    buffers[i]->capacity = 0;
    buffers[i]->length = 0;
  }
}

GARC_Result garc_tar_read_long_field(
    GARC_Archive * archive, uint64_t declared, GARC_Tar_Buffer * buffer) {
  if (!declared) {
    // A carrier that carries nothing. Not harmless: the header behind it would
    // then be read with the truncated name in its own field, so the archive
    // would be reported as if the carrier had never been there.
    return GARC_ERR_CORRUPT;
  }

  // **The cap is checked against the declared size, before the allocation.**
  // This is the one place in the tar reader where a length is declared in one
  // block and the bytes arrive in the next, so it is the one place a cap has to
  // fire on the declaration - checking after reading would mean allocating
  // whatever a hostile archive asked for in order to find out it was too much.
  //
  // One byte of slack, because the payload is the name *and* its terminator and
  // the cap is on the name. garc_reader_account() is still the authority on the
  // name itself, so a cap of N accepts a payload of N + 1 here and then refuses
  // it there if the string really is N + 1 bytes long.
  const uint64_t max_name = archive->limits.max_name_bytes;
  if (max_name && declared - 1u > max_name) {
    return GARC_ERR_LIMIT_NAME_BYTES;
  }
  if (declared > (uint64_t)SIZE_MAX - 1u) {
    // GARC_ERR_OOM rather than a limit: no cap was defeated, the machine simply
    // cannot address that much.
    //
    // **This is the second line `make coverage` reports as unexecuted, and like
    // the first it is meant to stay that way** - but for a different reason. It
    // is not defensive: it is live code on a host this suite does not run on.
    // A size field is at most 12 base-256 bytes, which garc_tar_parse_uint()
    // caps at INT64_MAX, so where `size_t` is 64 bits the comparison cannot be
    // true. Where it is 32 bits - the host this library uses `uint64_t` offsets
    // for in the first place - a declared size of 2^40 reaches it, and without
    // it the cast below would truncate and read a name into a buffer sized by
    // the low 32 bits of what was asked for.
    return GARC_ERR_OOM;
  }

  const size_t wanted = (size_t)declared;
  GARC_Result result = tar_buffer_reserve(archive, buffer, wanted);
  if (result != GARC_OK) {
    return result;
  }

  size_t got = 0;
  result = garc_tar_read(archive, (uint8_t *)buffer->bytes, wanted, &got);
  if (result != GARC_OK) {
    return result;
  }
  if (got < wanted) {
    // The carrier declared more bytes than the archive holds. GARC_ERR_CORRUPT
    // rather than a truncation reported as a short name, because a name is the
    // thing a caller makes a security decision about.
    return GARC_ERR_CORRUPT;
  }
  buffer->bytes[wanted] = '\0';

  // The payload is padded out to a whole block, exactly as a member's data is.
  const uint64_t remainder = declared % GARC_TAR_BLOCK;
  if (remainder) {
    result = garc_tar_skip(archive, GARC_TAR_BLOCK - remainder);
    if (result != GARC_OK) {
      return result;
    }
  }

  // **The string ends at the first NUL, and everything after it has to be NUL
  // too.** GNU writes `strlen + 1`, so there is exactly one; a writer that
  // omitted the terminator writes `strlen` and there is none. Either is read the
  // same way.
  //
  // What is refused is the third shape: a NUL with content behind it. That is
  // not a writer's variation, it is one payload that two readers name
  // differently - this one would report the bytes before the NUL and a reader
  // using the declared length would report all of them - and a member whose name
  // depends on which reader is asked is how a checked name and an extracted name
  // come apart.
  size_t length = 0;
  while (length < wanted && buffer->bytes[length] != '\0') {
    length++;
  }
  for (size_t i = length; i < wanted; ++i) {
    if (buffer->bytes[i] != '\0') {
      return GARC_ERR_CORRUPT;
    }
  }
  if (!length) {
    // A payload of nothing but NULs: as empty as a declared size of zero, and
    // refused for the same reason.
    return GARC_ERR_CORRUPT;
  }
  buffer->length = length;
  return GARC_OK;
}

//-----------------------------------------------------------------------------
// pax: `len key=value\n` records in an `x` or `g` member
//-----------------------------------------------------------------------------

/**
 * Make sure a buffer can hold @p wanted bytes, keeping what it already holds.
 *
 * The counterpart to tar_buffer_reserve(), which does not. A record set is
 * *appended* to - a second `x` header for one member adds to it, and a second `g`
 * overrides individual keys of it - so this one has to preserve, and the record
 * table holds offsets rather than pointers precisely so that a move here costs
 * nothing.
 *
 * @param archive The archive, for its allocator.
 * @param buffer The buffer.
 * @param wanted How many bytes have to fit.
 * @return GARC_OK, or GARC_ERR_OOM with the old contents intact.
 */
static GARC_Result tar_buffer_grow(
    GARC_Archive * archive, GARC_Tar_Buffer * buffer, size_t wanted) {
  if (buffer->capacity >= wanted + 1u) {
    return GARC_OK;
  }
  // realloc rather than malloc-and-copy: it returns NULL without freeing the old
  // block, so a failure here leaves the set that was already parsed readable.
  char * bytes = (char *)gcu_allocator_realloc(
      archive->allocator, buffer->bytes, wanted + 1u);
  if (!bytes) {
    return GARC_ERR_OOM;
  }
  buffer->bytes = bytes;
  buffer->capacity = wanted + 1u;
  return GARC_OK;
}

void garc_tar_pax_reset(GARC_Tar_Pax * pax) {
  pax->records.length = 0;
  for (size_t i = 0; i < (size_t)GARC_PAX_KEY_COUNT; ++i) {
    pax->have[i] = 0;
    pax->offset[i] = 0;
    pax->length[i] = 0;
  }
}

/**
 * The keys this reader acts on, spelled once.
 *
 * The lengths come from strlen() rather than being written beside the literals.
 * A number next to the string it measures is one fact written twice, and the two
 * drift the first time somebody corrects a spelling - at which point the key
 * silently stops matching and the record it named is silently ignored, which is
 * what this reader does with keys it does not know.
 */
static const struct {
  const char * name;
  GARC_Pax_Key key;
} tar_pax_keys[] = {
  {"path", GARC_PAX_PATH},
  {"linkpath", GARC_PAX_LINKPATH},
  {"uname", GARC_PAX_UNAME},
  {"gname", GARC_PAX_GNAME},
  {"size", GARC_PAX_SIZE},
  {"mtime", GARC_PAX_MTIME},
  {"uid", GARC_PAX_UID},
  {"gid", GARC_PAX_GID},
  {"hdrcharset", GARC_PAX_HDRCHARSET},
};

/** GNU's sparse records, which change what a member's data *is*. */
static const char tar_pax_sparse_prefix[] = "GNU.sparse.";

/**
 * Parse the records in `pax->records[from .. to)` into the table.
 *
 * A record is `len SP key = value LF`, where `len` is the decimal length of the
 * whole record *including itself* - the one self-referential field in any of
 * these formats, and the reason a record can be found without scanning for a
 * delimiter that a value might contain.
 *
 * Later wins, within a block and across blocks, which is pax's own rule: an `x`
 * header overrides a `g` one and a second `g` overrides the first, key by key. It
 * is the opposite of what this reader does with two GNU `L` members, and the
 * difference is that pax *defines* the override and GNU defines no order between
 * two carriers of the same kind.
 *
 * @param pax The set to add to.
 * @param from Where the new bytes start.
 * @param to Where they end.
 * @return GARC_OK, GARC_ERR_UNSUPPORTED for a sparse member, or
 *   GARC_ERR_CORRUPT.
 */
static GARC_Result tar_pax_parse(
    GARC_Tar_Pax * pax, size_t from, size_t to) {
  const char * bytes = pax->records.bytes;
  size_t pos = from;

  while (pos < to) {
    // The length. Decimal, at least one digit, then exactly one space.
    size_t cursor = pos;
    uint64_t length = 0;
    while (cursor < to && bytes[cursor] >= '0' && bytes[cursor] <= '9') {
      if (length > (UINT64_MAX - 9u) / 10u) {
        return GARC_ERR_CORRUPT;
      }
      length = length * 10u + (uint64_t)(bytes[cursor] - '0');
      cursor++;
    }
    if (cursor == pos || cursor >= to || bytes[cursor] != ' ') {
      // No digits, or nothing after them, or no space. A reader that scanned
      // forward for the next newline instead would keep going through a block of
      // arbitrary bytes and report whatever happened to contain a '='.
      return GARC_ERR_CORRUPT;
    }

    // The length has to name a record that is inside this block and long enough
    // to hold what it must: the digits, the space, a key of at least one byte,
    // the '=', and the newline.
    const uint64_t smallest = (uint64_t)(cursor - pos) + 4u;
    if (length < smallest || length > (uint64_t)(to - pos)) {
      return GARC_ERR_CORRUPT;
    }
    const size_t end = pos + (size_t)length;
    if (bytes[end - 1u] != '\n') {
      return GARC_ERR_CORRUPT;
    }

    const size_t key = cursor + 1u;
    size_t equals = key;
    while (equals < end - 1u && bytes[equals] != '=') {
      equals++;
    }
    if (equals >= end - 1u || equals == key) {
      // No '=' inside the record, or an empty key. Either would leave this
      // reader guessing at where a value began.
      return GARC_ERR_CORRUPT;
    }

    const size_t key_length = equals - key;
    if (key_length >= sizeof(tar_pax_sparse_prefix) - 1u
        && memcmp(bytes + key, tar_pax_sparse_prefix,
               sizeof(tar_pax_sparse_prefix) - 1u)
            == 0) {
      // **Sparse is refused rather than ignored.** These records say the member's
      // data is a map of holes and extents, so a reader that skipped them would
      // hand a caller the map as the file's contents and report a size that is
      // neither the stored length nor the real one. GARC_ERR_UNSUPPORTED names a
      // feature that is not read yet; silence would name nothing.
      return GARC_ERR_UNSUPPORTED;
    }

    for (size_t i = 0; i < sizeof(tar_pax_keys) / sizeof(tar_pax_keys[0]); ++i) {
      if (key_length == strlen(tar_pax_keys[i].name)
          && memcmp(bytes + key, tar_pax_keys[i].name, key_length) == 0) {
        const GARC_Pax_Key which = tar_pax_keys[i].key;
        pax->have[which] = 1;
        pax->offset[which] = equals + 1u;
        pax->length[which] = (end - 1u) - (equals + 1u);
        break;
      }
    }

    pos = end;
  }
  return GARC_OK;
}

GARC_Result garc_tar_read_pax_records(
    GARC_Archive * archive, uint64_t declared, int global) {
  GARC_Tar_Pax * pax = global ? &archive->pax_global : &archive->pax_next;

  if (!declared) {
    // An `x` or `g` member with no records. Unlike an empty GNU carrier this says
    // nothing false - there is simply nothing to apply - so it is read and
    // ignored rather than refused.
    return GARC_OK;
  }

  // **The first cap in this library with a construct to bound.** No tar field
  // read before pax was an "extra field", so max_extra_bytes was a status with no
  // path to it. What it bounds is the record bytes this reader is *holding* for
  // the current member: the global set, which persists, plus whatever `x` headers
  // have added. That is the quantity a chain of either can grow, and bounding
  // only one header at a time would leave a hundred of them unbounded.
  //
  // Checked against the declaration, before the allocation, for the reason
  // garc_tar_read_long_field() gives.
  const uint64_t held = (uint64_t)archive->pax_global.records.length
      + (uint64_t)archive->pax_next.records.length;
  const uint64_t cap = archive->limits.max_extra_bytes;
  if (cap && (declared > cap || held > cap - declared)) {
    return GARC_ERR_LIMIT_EXTRA_BYTES;
  }
  if (declared > (uint64_t)SIZE_MAX - 1u - (uint64_t)pax->records.length) {
    // The third of the lines `make coverage` reports as unexecuted, and the same
    // kind as the one in garc_tar_read_long_field(): live code on a host where
    // `size_t` is narrower than `uint64_t`, unreachable on one where it is not.
    return GARC_ERR_OOM;
  }

  const size_t from = pax->records.length;
  const size_t wanted = from + (size_t)declared;
  GARC_Result result = tar_buffer_grow(archive, &pax->records, wanted);
  if (result != GARC_OK) {
    return result;
  }

  size_t got = 0;
  result = garc_tar_read(
      archive, (uint8_t *)pax->records.bytes + from, (size_t)declared, &got);
  if (result != GARC_OK) {
    return result;
  }
  if (got < (size_t)declared) {
    return GARC_ERR_CORRUPT;
  }
  pax->records.length = wanted;
  pax->records.bytes[wanted] = '\0';

  const uint64_t remainder = declared % GARC_TAR_BLOCK;
  if (remainder) {
    result = garc_tar_skip(archive, GARC_TAR_BLOCK - remainder);
    if (result != GARC_OK) {
      return result;
    }
  }

  return tar_pax_parse(pax, from, wanted);
}

/**
 * The value in force for one key, `x` overriding `g`.
 *
 * @param archive The archive.
 * @param which The key.
 * @param out_bytes Receives the value's bytes.
 * @param out_length Receives its length.
 * @return Non-zero when the key has a value to apply. A key present with an empty
 *   value is *deleted*, and returns zero here without falling through to the
 *   global set - which is the whole point of being able to write one.
 */
static int tar_pax_value(const GARC_Archive * archive, GARC_Pax_Key which,
    const char ** out_bytes, size_t * out_length) {
  const GARC_Tar_Pax * const sets[2] = {&archive->pax_next, &archive->pax_global};
  for (size_t i = 0; i < 2u; ++i) {
    if (!sets[i]->have[which]) {
      continue;
    }
    if (!sets[i]->length[which]) {
      return 0;
    }
    *out_bytes = sets[i]->records.bytes + sets[i]->offset[which];
    *out_length = sets[i]->length[which];
    return 1;
  }
  return 0;
}

/** Whether any record at all is in force, which is what makes a member pax. */
static int tar_pax_any(const GARC_Archive * archive) {
  for (size_t i = 0; i < (size_t)GARC_PAX_KEY_COUNT; ++i) {
    if (archive->pax_next.have[i] || archive->pax_global.have[i]) {
      return 1;
    }
  }
  return 0;
}

/** A decimal unsigned integer, over bytes that are not NUL-terminated. */
static GARC_Result tar_pax_u64(
    const char * bytes, size_t length, uint64_t * out_value) {
  if (!length) {
    return GARC_ERR_CORRUPT;
  }
  uint64_t value = 0;
  for (size_t i = 0; i < length; ++i) {
    if (bytes[i] < '0' || bytes[i] > '9') {
      return GARC_ERR_CORRUPT;
    }
    if (value > (UINT64_MAX - 9u) / 10u) {
      return GARC_ERR_CORRUPT;
    }
    value = value * 10u + (uint64_t)(bytes[i] - '0');
  }
  *out_value = value;
  return GARC_OK;
}

/** A decimal signed integer, for `uid=` and `gid=`. */
static GARC_Result tar_pax_i64(
    const char * bytes, size_t length, int64_t * out_value) {
  int negative = 0;
  if (length && (bytes[0] == '-' || bytes[0] == '+')) {
    negative = (bytes[0] == '-');
    bytes++;
    length--;
  }
  uint64_t magnitude = 0;
  GARC_Result result = tar_pax_u64(bytes, length, &magnitude);
  if (result != GARC_OK) {
    return result;
  }
  if (negative) {
    if (magnitude > (uint64_t)INT64_MAX + 1u) {
      return GARC_ERR_CORRUPT;
    }
    // Spelled as a subtraction from the span rather than as -(int64_t)magnitude,
    // because the most negative value's magnitude does not fit an int64_t and
    // converting it is out of range - which UBSan sees and a release build does
    // not. The same shape the base-256 parser had.
    *out_value = (int64_t)(magnitude - 1u) * -1 - 1;
    return GARC_OK;
  }
  if (magnitude > (uint64_t)INT64_MAX) {
    return GARC_ERR_CORRUPT;
  }
  *out_value = (int64_t)magnitude;
  return GARC_OK;
}

/**
 * A pax time: `[-]seconds[.fraction]`.
 *
 * **Floor, not truncation toward zero.** The nanoseconds a member reports are
 * unsigned, so the only reading under which seconds + nanoseconds/1e9 equals the
 * value is one where a negative time rounds *down*: `-1.5` is -2 seconds and
 * 500000000 nanoseconds. Truncating would give -1 and 500000000, which is -0.5 -
 * a time half a second after the epoch where the archive said half a second
 * before it.
 *
 * Digits past the ninth are dropped rather than rounded, because rounding up
 * could carry into the second and this library reports what the container said.
 */
static GARC_Result tar_pax_time(const char * bytes, size_t length,
    int64_t * out_seconds, uint32_t * out_nanoseconds) {
  int negative = 0;
  if (length && (bytes[0] == '-' || bytes[0] == '+')) {
    negative = (bytes[0] == '-');
    bytes++;
    length--;
  }

  size_t whole = 0;
  while (whole < length && bytes[whole] != '.') {
    whole++;
  }

  uint64_t seconds = 0;
  GARC_Result result = tar_pax_u64(bytes, whole, &seconds);
  if (result != GARC_OK) {
    return result;
  }

  uint32_t nanoseconds = 0;
  if (whole < length) {
    // A '.' with no digits behind it is not a number, and neither is one with a
    // non-digit: both are refused rather than read as a whole second, because a
    // time this reader guessed at is a time a caller cannot check.
    const size_t fraction = whole + 1u;
    if (fraction >= length) {
      return GARC_ERR_CORRUPT;
    }
    uint32_t scale = 100000000u;
    for (size_t i = fraction; i < length; ++i) {
      if (bytes[i] < '0' || bytes[i] > '9') {
        return GARC_ERR_CORRUPT;
      }
      if (scale) {
        nanoseconds += (uint32_t)(bytes[i] - '0') * scale;
        scale /= 10u;
      }
    }
  }

  if (negative) {
    if (seconds > (uint64_t)INT64_MAX) {
      return GARC_ERR_CORRUPT;
    }
    int64_t signed_seconds = -(int64_t)seconds;
    if (nanoseconds) {
      // No guard on the subtraction, and `make coverage` is what settled that: a
      // check for INT64_MIN here never executed, because the range check above
      // leaves `signed_seconds` in [-INT64_MAX, 0] and INT64_MIN is one below
      // that. The borrow therefore lands at INT64_MIN at worst, which is
      // representable. A dead guard would read as though it were load-bearing.
      signed_seconds -= 1;
      nanoseconds = 1000000000u - nanoseconds;
    }
    *out_seconds = signed_seconds;
  } else {
    if (seconds > (uint64_t)INT64_MAX) {
      return GARC_ERR_CORRUPT;
    }
    *out_seconds = (int64_t)seconds;
  }
  *out_nanoseconds = nanoseconds;
  return GARC_OK;
}

/**
 * What the records' character set declaration means for a name that came from one.
 *
 * Absent means UTF-8: POSIX says extended header records are encoded that way,
 * so a `path=` record with no `hdrcharset=` beside it *is* a declaration. What
 * `BINARY` says is the opposite - these are bytes and nobody is claiming
 * anything - and anything else is a charset this library cannot vouch for, which
 * is the same answer for a different reason.
 */
static GARC_Name_Encoding tar_pax_encoding(const GARC_Archive * archive) {
  static const char utf8[] = "ISO-IR 10646 2000 UTF-8";
  const char * bytes = NULL;
  size_t length = 0;
  if (!tar_pax_value(archive, GARC_PAX_HDRCHARSET, &bytes, &length)) {
    return GARC_NAME_UTF8;
  }
  if (length == sizeof(utf8) - 1u && memcmp(bytes, utf8, length) == 0) {
    return GARC_NAME_UTF8;
  }
  return GARC_NAME_UNDECLARED;
}

GARC_Result garc_tar_apply_pax(GARC_Archive * archive) {
  if (!tar_pax_any(archive)) {
    return GARC_OK;
  }

  GARC_Member * member = &archive->member;
  const char * bytes = NULL;
  size_t length = 0;

  if (tar_pax_value(archive, GARC_PAX_PATH, &bytes, &length)) {
    member->name = bytes;
    member->name_length = length;
    // The one place a name carries a declaration rather than none. It applies
    // only to a name that came from a *record*: the header's own field is bytes
    // with no statement about them, whatever the records say about themselves.
    member->name_encoding = tar_pax_encoding(archive);
  }
  if (tar_pax_value(archive, GARC_PAX_LINKPATH, &bytes, &length)) {
    member->link_target = bytes;
    member->link_target_length = length;
  }
  if (tar_pax_value(archive, GARC_PAX_UNAME, &bytes, &length)) {
    member->uname = bytes;
    member->uname_length = length;
  }
  if (tar_pax_value(archive, GARC_PAX_GNAME, &bytes, &length)) {
    member->gname = bytes;
    member->gname_length = length;
  }

  if (tar_pax_value(archive, GARC_PAX_SIZE, &bytes, &length)) {
    uint64_t size = 0;
    GARC_Result result = tar_pax_u64(bytes, length, &size);
    if (result != GARC_OK) {
      return result;
    }
    // Only where the member has data at all, which is the rule the header reader
    // applies to its own size field - see garc_tar_type_carries_data(). A
    // `size=` record on a directory would otherwise send the cursor into the next
    // header by a route the header field is already guarded against.
    member->size = garc_tar_type_carries_data(member->type) ? size : 0u;
  }

  if (tar_pax_value(archive, GARC_PAX_MTIME, &bytes, &length)) {
    int64_t seconds = 0;
    uint32_t nanoseconds = 0;
    GARC_Result result = tar_pax_time(bytes, length, &seconds, &nanoseconds);
    if (result != GARC_OK) {
      return result;
    }
    member->mtime_seconds = seconds;
    member->mtime_nanoseconds = nanoseconds;
    // Which field answered, not just what it said. A tar written by GNU tar
    // carries the time twice and the two can disagree, so a caller comparing two
    // archives needs to know which it is looking at.
    member->mtime_source = GARC_TIME_PAX_DECIMAL;
  }

  if (tar_pax_value(archive, GARC_PAX_UID, &bytes, &length)) {
    GARC_Result result = tar_pax_i64(bytes, length, &member->uid);
    if (result != GARC_OK) {
      return result;
    }
    member->ids_valid = 1;
  }
  if (tar_pax_value(archive, GARC_PAX_GID, &bytes, &length)) {
    GARC_Result result = tar_pax_i64(bytes, length, &member->gid);
    if (result != GARC_OK) {
      return result;
    }
    member->ids_valid = 1;
  }

  // A member any record was in force for was not read as a ustar member, even
  // when the record changed no field it reports - an inherited `hdrcharset` is
  // still a statement about how this member's name is to be read.
  archive->tar_variant = GARC_TAR_PAX;
  return GARC_OK;
}
