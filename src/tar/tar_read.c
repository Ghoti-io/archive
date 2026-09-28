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
 * Reading tar: v7, ustar, and GNU's long-name members.
 *
 * pax's extended records are a separate commit of the same phase; where this
 * file would have to change for them, it says so.
 *
 * Reference documents are named in tar_internal.h.
 */

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/tar.h>
#include <stdint.h>
#include <string.h>

#include "tar/tar_internal.h"

/** The magic and version a POSIX.1-1988 ustar header carries. */
static const uint8_t tar_magic_ustar[8] = {'u', 's', 't', 'a', 'r', 0, '0', '0'};

/** What GNU writes instead: "ustar  " and a NUL, magic and version run
 *  together. */
static const uint8_t tar_magic_gnu[8] = {'u', 's', 't', 'a', 'r', ' ', ' ', 0};

/**
 * The checksum of a header block, computed both ways.
 *
 * The field itself is read as spaces, which is the rule that makes the
 * checksum self-consistent. Historically some writers summed the bytes as
 * signed chars and some as unsigned, and the two differ exactly when a header
 * contains a byte above 0x7F - a non-ASCII name, or a base-256 numeric field.
 * Accepting only one rejects real archives, so both are computed and the caller
 * is told which matched.
 */
static void tar_checksum(
    const uint8_t * block, uint32_t * out_unsigned, int32_t * out_signed) {
  uint32_t sum_unsigned = 0;
  int32_t sum_signed = 0;
  for (size_t i = 0; i < GARC_TAR_BLOCK; ++i) {
    const int in_field = (i >= GARC_TAR_OFF_CHKSUM
        && i < GARC_TAR_OFF_CHKSUM + GARC_TAR_LEN_CHKSUM);
    const uint8_t byte = in_field ? (uint8_t)' ' : block[i];
    sum_unsigned += (uint32_t)byte;
    // The signed reading, spelled without relying on a plain char's signedness,
    // which is a platform choice: ARM's is unsigned and x86's is signed, so
    // `(signed char)byte` is the portable spelling of what those writers did.
    sum_signed += (int32_t)(int8_t)byte;
  }
  *out_unsigned = sum_unsigned;
  *out_signed = sum_signed;
}

/** Whether a block is entirely zero, which is the end-of-archive marker. */
static int tar_block_is_zero(const uint8_t * block) {
  for (size_t i = 0; i < GARC_TAR_BLOCK; ++i) {
    if (block[i] != 0u) {
      return 0;
    }
  }
  return 1;
}

int garc_tar_identify(const uint8_t * block, size_t length) {
  if (!block || length < GARC_TAR_BLOCK) {
    // Nothing shorter than one block can be identified, and a file of 100 bytes
    // is not a tar however much it looks like the beginning of one.
    return 0;
  }
  return garc_tar_block_is_header(block) || tar_block_is_zero(block);
}

int garc_tar_block_is_header(const uint8_t * block) {
  if (!block) {
    return 0;
  }

  uint64_t declared = 0;
  if (garc_tar_parse_uint(block + GARC_TAR_OFF_CHKSUM, GARC_TAR_LEN_CHKSUM,
          &declared) != GARC_OK) {
    return 0;
  }

  uint32_t sum_unsigned = 0;
  int32_t sum_signed = 0;
  tar_checksum(block, &sum_unsigned, &sum_signed);

  return (declared == (uint64_t)sum_unsigned)
      || (sum_signed >= 0 && declared == (uint64_t)sum_signed);
}

/**
 * Copy a fixed-width, NUL-padded header string into caller storage.
 *
 * tar's strings are NUL-terminated only when they are shorter than the field,
 * so a field that is exactly full has no terminator - which is why this takes
 * the field width and returns the length rather than using strlen. The
 * destination is NUL-terminated for convenience and the length is what the
 * member reports.
 *
 * @param destination Storage of at least @p width + 1 bytes.
 * @param field The field bytes.
 * @param width The field width.
 * @return The length of the string, which is the field width when it is full.
 */
static size_t tar_copy_field(
    char * destination, const uint8_t * field, size_t width) {
  size_t length = 0;
  while (length < width && field[length] != '\0') {
    length++;
  }
  memcpy(destination, field, length);
  destination[length] = '\0';
  return length;
}

/**
 * Map a tar typeflag onto a member type.
 *
 * The v7 and ustar sets overlap and disagree about one value: in v7 the field
 * is a "linkflag" whose NUL means a regular file, and ustar spells that '0'.
 * Both are accepted for both variants, because writers were never that careful
 * and the alternative is reporting a regular file as an unknown type.
 *
 * '7' is a contiguous file, which no filesystem in use has; every reader treats
 * it as a regular file and so does this one. An unrecognised flag becomes
 * GARC_MEMBER_OTHER rather than a file: extracting an unknown type as a regular
 * file is how a reader invents data.
 */
static GARC_Member_Type tar_type_from_flag(uint8_t flag) {
  switch (flag) {
    case '\0':
    case '0':
    case '7':
      return GARC_MEMBER_FILE;
    case '1':
      return GARC_MEMBER_HARDLINK;
    case '2':
      return GARC_MEMBER_SYMLINK;
    case '3':
      return GARC_MEMBER_CHAR_DEVICE;
    case '4':
      return GARC_MEMBER_BLOCK_DEVICE;
    case '5':
      return GARC_MEMBER_DIRECTORY;
    case '6':
      return GARC_MEMBER_FIFO;
    default:
      return GARC_MEMBER_OTHER;
  }
}

int garc_tar_type_carries_data(GARC_Member_Type type) {
  return type == GARC_MEMBER_FILE || type == GARC_MEMBER_OTHER;
}

/** Which variant a header block's magic and version declare. */
static GARC_Tar_Variant tar_variant_from_magic(const uint8_t * block) {
  const uint8_t * magic = block + GARC_TAR_OFF_MAGIC;
  if (memcmp(magic, tar_magic_ustar, sizeof(tar_magic_ustar)) == 0) {
    return GARC_TAR_USTAR;
  }
  if (memcmp(magic, tar_magic_gnu, sizeof(tar_magic_gnu)) == 0) {
    return GARC_TAR_GNU;
  }
  // No magic at all, or one nobody recognises. The checksum has already said
  // this is a header, so it is a v7 one - the variant with no magic field.
  return GARC_TAR_V7;
}

/**
 * Fill in the member from one header block.
 *
 * @param archive The archive, whose storage the member's strings point into.
 * @param block The 512-byte header.
 * @return GARC_OK, or GARC_ERR_CORRUPT for a field that is not a number.
 */
static GARC_Result tar_read_header(GARC_Archive * archive,
    const uint8_t * block) {
  GARC_Member * member = &archive->member;
  memset(member, 0, sizeof(*member));

  const GARC_Tar_Variant variant = tar_variant_from_magic(block);
  archive->tar.variant = variant;

  // The name. ustar splits a long name across a 155-byte prefix and the
  // 100-byte name, joined with a '/'; v7 has no prefix field at all, and its
  // bytes there are whatever the writer left - so the prefix is read only when
  // the magic says it exists. A reader that always reads it turns v7 padding
  // into a directory component.
  size_t name_length = 0;
  if (variant != GARC_TAR_V7) {
    char prefix[GARC_TAR_LEN_PREFIX + 1u];
    size_t prefix_length = tar_copy_field(
        prefix, block + GARC_TAR_OFF_PREFIX, GARC_TAR_LEN_PREFIX);
    if (prefix_length) {
      memcpy(archive->tar.name_storage, prefix, prefix_length);
      archive->tar.name_storage[prefix_length] = '/';
      name_length = prefix_length + 1u;
    }
  }
  name_length += tar_copy_field(archive->tar.name_storage + name_length,
      block + GARC_TAR_OFF_NAME, GARC_TAR_LEN_NAME);

  member->name = archive->tar.name_storage;
  member->name_length = name_length;
  // tar has never carried a statement about its names' encoding. pax's
  // `hdrcharset=` record is the only thing that does, and it arrives with pax.
  member->name_encoding = GARC_NAME_UNDECLARED;

  const uint8_t typeflag = block[GARC_TAR_OFF_TYPEFLAG];
  member->type = tar_type_from_flag(typeflag);

  size_t link_length = tar_copy_field(archive->tar.link_storage,
      block + GARC_TAR_OFF_LINKNAME, GARC_TAR_LEN_LINKNAME);
  if (link_length) {
    member->link_target = archive->tar.link_storage;
    member->link_target_length = link_length;
  }

  uint64_t size = 0;
  GARC_Result result = garc_tar_parse_uint(
      block + GARC_TAR_OFF_SIZE, GARC_TAR_LEN_SIZE, &size);
  if (result != GARC_OK) {
    return result;
  }
  // A directory, a symlink, a fifo or a device has no data, and the size field
  // is not always zero in one - some writers leave a stale value there. Reading
  // it as a data length walks the cursor into the next header, which is a
  // plausible wrong answer rather than an error: the reader then reports the
  // next header's bytes as this member's contents.
  member->size = garc_tar_type_carries_data(member->type) ? size : 0u;

  uint64_t mode = 0;
  result = garc_tar_parse_uint(
      block + GARC_TAR_OFF_MODE, GARC_TAR_LEN_MODE, &mode);
  if (result != GARC_OK) {
    return result;
  }
  member->mode = (uint32_t)(mode & 0xFFFFFFFFu);
  member->mode_valid = 1;

  result = garc_tar_parse_int(
      block + GARC_TAR_OFF_UID, GARC_TAR_LEN_UID, &member->uid);
  if (result != GARC_OK) {
    return result;
  }
  result = garc_tar_parse_int(
      block + GARC_TAR_OFF_GID, GARC_TAR_LEN_GID, &member->gid);
  if (result != GARC_OK) {
    return result;
  }
  member->ids_valid = 1;

  result = garc_tar_parse_int(
      block + GARC_TAR_OFF_MTIME, GARC_TAR_LEN_MTIME, &member->mtime_seconds);
  if (result != GARC_OK) {
    return result;
  }
  member->mtime_nanoseconds = 0;
  member->mtime_source = GARC_TIME_TAR_OCTAL;

  if (variant != GARC_TAR_V7) {
    member->uname_length = tar_copy_field(
        archive->tar.uname_storage, block + GARC_TAR_OFF_UNAME, GARC_TAR_LEN_UNAME);
    if (member->uname_length) {
      member->uname = archive->tar.uname_storage;
    }
    member->gname_length = tar_copy_field(
        archive->tar.gname_storage, block + GARC_TAR_OFF_GNAME, GARC_TAR_LEN_GNAME);
    if (member->gname_length) {
      member->gname = archive->tar.gname_storage;
    }
  }

  // The device numbers are meaningful for a device member and are blank in
  // every other header there is, so they are read only where they mean
  // something. Reporting 0/0 as a valid device for a regular file would be a
  // number a caller could act on.
  if (member->type == GARC_MEMBER_CHAR_DEVICE
      || member->type == GARC_MEMBER_BLOCK_DEVICE) {
    uint64_t major = 0;
    uint64_t minor = 0;
    result = garc_tar_parse_uint(
        block + GARC_TAR_OFF_DEVMAJOR, GARC_TAR_LEN_DEVMAJOR, &major);
    if (result != GARC_OK) {
      return result;
    }
    result = garc_tar_parse_uint(
        block + GARC_TAR_OFF_DEVMINOR, GARC_TAR_LEN_DEVMINOR, &minor);
    if (result != GARC_OK) {
      return result;
    }
    member->device_major = (uint32_t)(major & 0xFFFFFFFFu);
    member->device_minor = (uint32_t)(minor & 0xFFFFFFFFu);
    member->device_valid = 1;
  }

  return GARC_OK;
}

uint64_t garc_tar_offset(const GARC_Archive * archive) {
  const uint64_t served = garc_stream_tell(archive->stream);
  const uint64_t pending
      = (uint64_t)(archive->peek_length - archive->peek_consumed);
  // The window was filled by reading `peek_length` bytes from the stream, so
  // what it has served is never less than what is still unread of it.
  return served - pending;
}

GARC_Result garc_tar_read(GARC_Archive * archive, uint8_t * destination,
    size_t count, size_t * out_got) {
  size_t total = 0;

  // Whatever identification looked at comes first. Without this the first
  // header would be read twice on a seekable stream and skipped on a pipe.
  if (archive->peek_consumed < archive->peek_length) {
    size_t available = archive->peek_length - archive->peek_consumed;
    size_t take = available < count ? available : count;
    memcpy(destination, archive->peek + archive->peek_consumed, take);
    archive->peek_consumed += take;
    total = take;
  }

  // A callback stream may serve fewer bytes than asked for without being at its
  // end - a pipe does it constantly - so a single read is not an answer.
  // Accumulating here is what keeps "the stream ended" (zero bytes) apart from
  // "the stream ended partway through" (one to count - 1), which are the two
  // answers a caller has to tell apart.
  while (total < count) {
    size_t got = 0;
    GARC_Result result = garc_stream_read(
        archive->stream, destination + total, count - total, &got);
    if (result != GARC_OK) {
      return result;
    }
    if (!got) {
      break;
    }
    total += got;
  }
  *out_got = total;
  return GARC_OK;
}

GARC_Result garc_tar_skip(GARC_Archive * archive, uint64_t count) {
  // **No peek window to drain here, and that is a fact rather than an
  // assumption.** Every skip in this reader is reached after a whole 512-byte
  // block has been read, and the window is one block - so reading a block always
  // empties it. A drain was written here first and `make coverage` showed it
  // never executed; dead handling in a reader is worse than absent, because it
  // reads as a guard somebody relies on.
  //
  // If a format ever wants to skip before reading a block, this is the function
  // that has to learn about the window, and the two call sites in garc_tar_next()
  // and garc_tar_read_long_field() are what establish the rule today.
  return count ? garc_stream_skip(archive->stream, count) : GARC_OK;
}

/**
 * Read one whole block, or report how much was there.
 *
 * @param archive The archive.
 * @param block Destination of GARC_TAR_BLOCK bytes.
 * @param out_got Receives how many bytes were available, 0 to GARC_TAR_BLOCK.
 * @return GARC_OK, or a stream failure.
 */
static GARC_Result tar_read_block(
    GARC_Archive * archive, uint8_t * block, size_t * out_got) {
  return garc_tar_read(archive, block, GARC_TAR_BLOCK, out_got);
}

GARC_Result garc_tar_next(GARC_Archive * archive) {
  uint8_t block[GARC_TAR_BLOCK];

  // Step over whatever is left of the previous member, data and padding
  // together. A caller is never required to read bytes it does not want in
  // order to reach the next header.
  if (archive->data_remaining || archive->data_padding) {
    GARC_Result skipped = garc_tar_skip(
        archive, archive->data_remaining + archive->data_padding);
    archive->data_remaining = 0;
    archive->data_padding = 0;
    if (skipped != GARC_OK) {
      return skipped;
    }
  }

  // A member's metadata arrives in front of it, so nothing carried over from the
  // previous call may still be claimed. Cleared here rather than where it is
  // applied, because the case that matters is the call that *failed* partway
  // through a carrier: without this, its name would be applied to whatever
  // header a caller reached next.
  archive->tar.have_long_name = 0;
  archive->tar.have_long_link = 0;
  // An `x` header's records are the next member's and nobody else's. The global
  // set is deliberately not reset: POSIX keeps those in force until a later
  // record replaces them.
  garc_tar_pax_reset(&archive->tar.pax_next);

  // Where the member's first block is, which is a carrier's when there is one. A
  // caller re-reading a member from this offset has to get the same member, and
  // starting at the header behind a carrier would lose the long name.
  uint64_t group_offset = 0;
  int in_group = 0;
  // Whether a block has been read that *describes a member*, which is a different
  // question. Every metadata block joins the group, because the group is a run of
  // blocks and re-reading has to start at the front of it; only some of them leave
  // a member owed. A `g` header describes every member after it, and "none" is a
  // number of members - `tar --concatenate` leaves globals at the end of what it
  // joined - so a `g` with nothing behind it is a clean archive where an `x` with
  // nothing behind it is damage.
  int member_owed = 0;

  // A loop rather than recursion on the zero-block case. A stream of nothing but
  // zero blocks is a 40-byte gzip file that expands to any size you like, so
  // recursing once per block is a stack overflow reachable from input.
  for (;;) {
    const uint64_t header_offset = garc_tar_offset(archive);

    size_t got = 0;
    GARC_Result result = tar_read_block(archive, block, &got);
    if (result != GARC_OK) {
      return result;
    }

    if (member_owed && (got < GARC_TAR_BLOCK || tar_block_is_zero(block))) {
      // Metadata with nothing behind it. What it said describes a member that is
      // not in the archive, and treating the end of the stream as a clean end here
      // would report a complete archive whose last member's name was silently
      // dropped.
      return GARC_ERR_CORRUPT;
    }

    if (got < GARC_TAR_BLOCK) {
      // Whether this is a complete archive or a truncated one turns on whether
      // the end marker was seen, and the two have to be distinguishable:
      // `tar cf - x | head -c 4096` produces the second, and reporting it as a
      // clean end would hand a caller half an archive with no indication.
      //
      // A *partial* block after the marker is the normal shape of a truncated
      // tail, because writers pad the end of an archive to a record boundary
      // and some strip that padding. Before the marker it is damage.
      if (archive->tar.saw_end_marker) {
        archive->at_end = 1;
        return GARC_END;
      }
      return GARC_ERR_CORRUPT;
    }

    if (tar_block_is_zero(block)) {
      // The marker is two zero blocks. One is what most writers' output ends
      // with once the padding is stripped, and a reader that insists on the
      // second rejects those - so the first is recorded and the end is decided
      // by what follows it. Two in a row, then the end of the stream, is the
      // clean case and arrives at the branch above.
      archive->tar.saw_end_marker = 1;
      continue;
    }

    if (!garc_tar_block_is_header(block)) {
      return GARC_ERR_CORRUPT;
    }

    uint32_t sum_unsigned = 0;
    int32_t sum_signed = 0;
    tar_checksum(block, &sum_unsigned, &sum_signed);
    uint64_t declared = 0;
    (void)garc_tar_parse_uint(
        block + GARC_TAR_OFF_CHKSUM, GARC_TAR_LEN_CHKSUM, &declared);
    // Which reading matched. The unsigned one is checked first because it is
    // what every writer in use produces; the signed one only matters for
    // archives old enough to have a non-ASCII byte in a header.
    archive->tar.checksum_was_signed
        = (declared != (uint64_t)sum_unsigned) ? 1 : 0;

    // GNU's 'L' and 'K' carry the next member's name and link target. They are
    // not members: handing one to a caller as a file called "././@LongLink"
    // reports an artefact of the format as content, and does it while the real
    // member's name is silently the truncated copy in the header behind it. So
    // the payload is read here and the loop goes round for the header it
    // describes. Checked before the header is parsed, because a carrier's own
    // name, mode and times describe nothing.
    const uint8_t typeflag = block[GARC_TAR_OFF_TYPEFLAG];
    if (typeflag == 'L' || typeflag == 'K') {
      uint64_t declared = 0;
      result = garc_tar_parse_uint(
          block + GARC_TAR_OFF_SIZE, GARC_TAR_LEN_SIZE, &declared);
      if (result != GARC_OK) {
        return result;
      }

      const int is_name = (typeflag == 'L');
      int * have = is_name ? &archive->tar.have_long_name : &archive->tar.have_long_link;
      if (*have) {
        // **Two carriers of the same kind for one member, refused.** Not a
        // stylistic objection: each one allocates its declared size, so a chain
        // of them is a few hundred bytes of archive asking for as much memory as
        // the cap allows, once per link in the chain. libarchive added the same
        // refusal for the same reason. No writer emits one, and last-one-wins
        // would make a member's name depend on how far a reader got.
        return GARC_ERR_CORRUPT;
      }

      result = garc_tar_read_long_field(archive, declared,
          is_name ? &archive->tar.long_name : &archive->tar.long_link);
      if (result != GARC_OK) {
        return result;
      }
      *have = 1;
      member_owed = 1;
      if (!in_group) {
        group_offset = header_offset;
        in_group = 1;
      }
      continue;
    }

    // pax carries the same things, and more, as `len key=value\n` records: an `x`
    // member's apply to the member behind it and a `g` member's until a later
    // record replaces them. Read here for the same reason as GNU's carriers, and
    // with the same consequence - neither is a member.
    if (typeflag == 'x' || typeflag == 'g') {
      uint64_t declared = 0;
      result = garc_tar_parse_uint(
          block + GARC_TAR_OFF_SIZE, GARC_TAR_LEN_SIZE, &declared);
      if (result != GARC_OK) {
        return result;
      }
      const int global = (typeflag == 'g');
      result = garc_tar_read_pax_records(archive, declared, global);
      if (result != GARC_OK) {
        return result;
      }
      // A `g` joins the group and owes no member. It joins because header_offset
      // promises an offset the member can be re-read from, and for the member
      // immediately behind a global that is true only if the global is inside the
      // run - re-reading from the `x` alone loses the `hdrcharset` and gives a
      // member whose name carries a different declaration. For a member further on
      // the promise cannot be kept at all: nothing in a pax archive lets one
      // member's offset carry a global a thousand blocks behind it, and that is a
      // property of the format rather than of this field.
      if (!global) {
        member_owed = 1;
      }
      if (!in_group) {
        group_offset = header_offset;
        in_group = 1;
      }
      continue;
    }

    // GNU's old sparse typeflag, which pax spells with `GNU.sparse.*` records.
    // Refused for the same reason those are: the member's data is a map of holes
    // and extents, and this typeflag would otherwise fall through to
    // GARC_MEMBER_OTHER and be reported as a file whose contents are the map.
    if (typeflag == 'S') {
      return GARC_ERR_UNSUPPORTED;
    }

    result = tar_read_header(archive, block);
    if (result != GARC_OK) {
      return result;
    }

    // A name or a target that arrived in front of the header replaces the
    // header's own field, which holds a truncated copy of it. The variant becomes
    // GNU whatever the magic said, because the carrier is GNU's construct and a
    // member read through one was not read as a ustar member.
    if (archive->tar.have_long_name) {
      archive->member.name = archive->tar.long_name.bytes;
      archive->member.name_length = archive->tar.long_name.length;
      archive->tar.variant = GARC_TAR_GNU;
    }
    if (archive->tar.have_long_link) {
      archive->member.link_target = archive->tar.long_link.bytes;
      archive->member.link_target_length = archive->tar.long_link.length;
      archive->tar.variant = GARC_TAR_GNU;
    }

    // pax last, so that a record beats a GNU carrier where an archive somehow has
    // both. No writer produces one: `--format=gnu` writes carriers and
    // `--format=pax` writes records. The order is defined rather than refused
    // because pax *has* an override rule and this is an instance of it, which is
    // the opposite of two GNU carriers of the same kind - there the format defines
    // no order, which is why those are refused.
    result = garc_tar_apply_pax(archive);
    if (result != GARC_OK) {
      return result;
    }

    archive->member.header_offset = in_group ? group_offset : header_offset;
    archive->member.data_offset = garc_tar_offset(archive);

    archive->data_remaining = archive->member.size;
    // Data is padded to a whole block. The modulo is on the declared size, so a
    // member declaring a size it does not have is caught by the read rather
    // than here.
    const uint64_t remainder = archive->member.size % GARC_TAR_BLOCK;
    archive->data_padding = remainder ? (GARC_TAR_BLOCK - remainder) : 0u;

    // A header after the end marker means the marker was data, not an end. GNU
    // tar warns and continues, and so does this: the marker ends the archive
    // only if nothing follows it.
    archive->tar.saw_end_marker = 0;

    return garc_reader_account(archive);
  }
}
