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
  gcu_allocator_free(archive->allocator, archive->long_name.bytes);
  gcu_allocator_free(archive->allocator, archive->long_link.bytes);
  archive->long_name.bytes = NULL;
  archive->long_link.bytes = NULL;
  archive->long_name.capacity = 0;
  archive->long_link.capacity = 0;
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
