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
 * Writing zip: a local header per member, a directory at the end, and the two
 * ways of saying a size you did not know in time.
 *
 * **The structure is written forwards and read backwards**, which is the whole
 * shape of this file. The reader starts at the end record and trusts the central
 * directory; the writer therefore has to produce a directory that is worth
 * trusting, and every offset in it is a position this file recorded as it went
 * past. Nothing here re-reads what it wrote.
 *
 * Three problems the format sets a writer, and what each costs:
 *
 * **A local header carries a CRC-32 and a compressed size that are not known
 * until the data has been written.** There are exactly two lawful answers: leave
 * zeros and put the real values in a *data descriptor* after the data, with
 * general purpose flag bit 3 set to say so; or go back and fill the header in.
 * Both are here, and which one is used is ::GARC_Zip_Sizes - a property of the
 * archive rather than a route its bytes take, because a consumer reading a zip as
 * a stream needs the first form and some old tools refuse it. The sink's
 * ::garc_sink_patch is what makes the second possible, and
 * ::garc_sink_is_seekable() is the question ::GARC_ZIP_SIZES_AUTO asks.
 *
 * **The central directory cannot be written until every offset is known**, so it
 * is accumulated in memory and emitted at ::garc_writer_finish(). That is the
 * format and not a choice: the end record points at the directory, and the
 * directory points back at every local header. tar's writer holds nothing at all
 * between members; this one holds about 46 bytes plus a name each, and a caller
 * writing a million members should know that.
 *
 * **zip64 is per field and per record, not per archive.** A value that does not
 * fit its 32-bit slot is written as `0xFFFFFFFF` there and for real in a 0x0001
 * extra field, and the extra carries *only* the marked fields, in the order the
 * specification lists them. That makes the local header and the central entry
 * disagree about how many fields are in the extra, which is not an inconsistency:
 * in the local header the compressed size is unknown when the header is written,
 * so it is marked whenever zip64 is in play at all; in the central entry it is
 * known, so it is marked only if it really does not fit. `zip -fz` produces
 * exactly that asymmetry - 16 bytes of payload in the local header and 8 in the
 * directory - and `infozip-zip64.zip` in the corpus is the evidence.
 *
 * **What this writes, exhaustively, because "the minimum" is only a claim if it
 * is enumerated.** Per member: a local header, the data, a descriptor when the
 * discipline asks for one, and a central directory entry. Two extra fields, and
 * no others:
 *
 * - **0x0001, zip64**, when a field needs it, as above.
 * - **0x5455, the extended timestamp**, carrying the mtime as an epoch second,
 *   and *only when the DOS field cannot carry it exactly*. The DOS field has
 *   two-second resolution and starts in 1980, so without this a zip writer
 *   silently rounds half of all times and cannot express one before 1980 at all.
 *   Writing it conditionally is what keeps "the minimum" true: an archive whose
 *   every mtime is an even second in range has no extra fields in it.
 *
 * No Ux, no Unix uid/gid (0x7875), no NTFS timestamp. A caller that needs an
 * owner in a zip cannot have one - the format has no field for it outside a
 * vendor extra - and that is said in writer.h rather than worked around here.
 */

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/allocator.h>
#include <ghoti.io/archive/name.h>
#include <ghoti.io/archive/writer.h>
#include <ghoti.io/compress/compress.h>
#include <ghoti.io/compress/crc32.h>
#include <ghoti.io/compress/registry.h>
#include <ghoti.io/compress/stream.h>
#include <ghoti.io/cutil/allocator.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>

#include "codec/codec_internal.h"
#include "core/buffer_internal.h"
#include "writer/writer_internal.h"
#include "zip/zip_internal.h"

/** The value a 32-bit field holds when its real value is in a zip64 extra. */
#define ZIP_MARKER32 0xFFFFFFFFu

/** The value a 16-bit field holds for the same reason. */
#define ZIP_MARKER16 0xFFFFu

/** General purpose flag bit 3: the sizes are in a data descriptor. */
#define ZIP_FLAG_DATA_DESCRIPTOR 0x0008u

/** General purpose flag bit 11: the name is UTF-8. */
#define ZIP_FLAG_UTF8 0x0800u

/** `version made by`: Unix in the high byte, 3.0 in the low. Info-ZIP's. */
#define ZIP_VERSION_MADE_BY 0x031Eu

/** `version needed`: 2.0, which is what a deflated or a stored member needs. */
#define ZIP_VERSION_NEEDED 20u

/** `version needed` for a record with a zip64 field in it. */
#define ZIP_VERSION_NEEDED_ZIP64 45u

/** The DOS `directory` attribute bit, in the low half of external attributes. */
#define ZIP_DOS_DIRECTORY 0x10u

/** A data descriptor with 32-bit sizes: signature, CRC, and two sizes. */
#define ZIP_DESCRIPTOR_SIZE_32 16u

/** The same descriptor with 64-bit sizes, which a zip64 member needs. */
#define ZIP_DESCRIPTOR_SIZE_64 24u

/** The largest archive comment the end record's length field can describe. */
#define ZIP_MAX_COMMENT 65535u

/**
 * Bytes handed to the deflate encoder's output buffer at a time.
 *
 * The same 10240 the codec layer uses, and the same reason: big enough that the
 * encoder always makes progress in it, small enough to be one allocation per
 * archive rather than a function of the member's size.
 */
#define ZIP_DEFLATE_BUFFER 10240u

/**
 * `compress`'s name for zip's method 8.
 *
 * Raw RFC 1951, which is what a zip member holds - not `"zlib"`, whose two-byte
 * header no zip reader expects. The reader's zip_codec_name() spells the same
 * string for the same reason, and the two are deliberately not shared: they are
 * the same word for opposite directions, and a reader that gained a method the
 * writer must not produce is the case that would break a shared table.
 */
#define ZIP_DEFLATE_METHOD "deflate"

static const uint8_t ZIP_SIG_LOCAL[4] = {'P', 'K', 3, 4};
static const uint8_t ZIP_SIG_CENTRAL[4] = {'P', 'K', 1, 2};
static const uint8_t ZIP_SIG_DESCRIPTOR[4] = {'P', 'K', 7, 8};
static const uint8_t ZIP_SIG_ZIP64_EOCD[4] = {'P', 'K', 6, 6};
static const uint8_t ZIP_SIG_ZIP64_LOCATOR[4] = {'P', 'K', 6, 7};
static const uint8_t ZIP_SIG_EOCD[4] = {'P', 'K', 5, 6};

/**
 * Whether a member's name should be flagged UTF-8.
 *
 * **Bit 11 is a claim about the bytes, so it is made only when the claim is
 * true.** Two conditions, and the second was a defect the oracle gate found on its
 * first run:
 *
 * - The name has a byte above 0x7F. An all-ASCII name means the same thing with
 *   the flag and without it, and every writer in the corpus leaves it clear there.
 * - **And the name is well-formed UTF-8.** The first version of this asked only
 *   the first question, so a name carrying raw bytes got the flag - and an archive
 *   that *claims* UTF-8 about bytes that are not is refused outright by Python's
 *   `zipfile` and has the member skipped by libarchive. That is not a hypothetical
 *   shape: it is `mal-utf8-lie.zip` in the corpus, built on purpose to be hostile,
 *   and this writer was producing it by accident from an ordinary name.
 *
 * With the flag clear such a name is cp437 by specification, which is a lawful
 * reading every reference accepts, and is what Info-ZIP writes.
 *
 * The validator is ::garc_name_check()'s, not a second one: one UTF-8 decision in
 * this library rather than two that can disagree. What this still does *not* do is
 * refuse anything - a name with findings is the caller's to decide about, which is
 * the rule tar's writer follows too.
 *
 * @param name The name.
 * @param length Its length.
 * @return Non-zero when bit 11 should be set.
 */
static int zip_name_needs_utf8_flag(const char * name, size_t length) {
  int high = 0;
  for (size_t i = 0; i < length; ++i) {
    if ((unsigned char)name[i] >= 0x80u) {
      high = 1;
      break;
    }
  }
  if (!high) {
    return 0;
  }
  return (garc_name_check(name, length) & GARC_NAME_NOT_UTF8) ? 0 : 1;
}

/**
 * Append bytes to the central directory being accumulated.
 *
 * @param writer The writer.
 * @param bytes What to append.
 * @param length How many.
 * @return GARC_OK or GARC_ERR_OOM.
 */
static GARC_Result zip_central_append(
    GARC_Writer * writer, const void * bytes, size_t length) {
  GARC_Zip_Write_State * zip = &writer->zip;
  GARC_Result result = garc_buffer_grow(writer->allocator, &zip->central,
      zip->central.length + length);
  if (result != GARC_OK) {
    return result;
  }
  memcpy(zip->central.bytes + zip->central.length, bytes, length);
  zip->central.length += length;
  return GARC_OK;
}

uint64_t garc_zip_deflate_bound(uint64_t size) {
  size_t bound = 0;
  if (size > (uint64_t)(size_t)-1
      || gcomp_encode_bound(gcomp_registry_default(), ZIP_DEFLATE_METHOD, NULL,
             (size_t)size, &bound)
          != GCOMP_OK) {
    // **Saturating rather than refusing**, because the caller is asking a question
    // whose safe answer is already known: a size with no bound to be had is a
    // member whose compressed size cannot be promised to fit a 32-bit field, so it
    // gets zip64 fields. Three ways to arrive here and one answer for all of them -
    // a size larger than a size_t on a 32-bit host, a bound larger than a size_t,
    // and a deflate that is somehow not registered.
    return UINT64_MAX;
  }
  return (uint64_t)bound;
}

/**
 * Whether this member's records need zip64 fields, and mark them if so.
 *
 * Decided **before the data is written**, because the local header is written
 * first and its layout depends on the answer. The compressed size is therefore not
 * available to decide on - so what stands in for it is not the declared size but
 * the largest the compressed size *can* be, which for a stored member is the
 * declared size and for a deflated one is ::garc_zip_deflate_bound of it.
 *
 * **That is the whole of the answer, and it is an answer rather than a deferral.**
 * The alternative - decide on the declared size, and refuse when the compressed
 * size turns out to cross 4 GiB after all - needs a refusal arm reachable only by
 * a member of very nearly 4 GiB that deflate expands, which is a line nothing
 * could put in a position to fail. Deciding on the bound has no such arm: a
 * member whose bound fits a 32-bit field cannot produce a compressed size that
 * does not.
 *
 * The cost is that a member within the bound's slack of the threshold gets zip64
 * fields it would probably have done without. compress's deflate bound reserves
 * about a quarter of a percent, so that is the top ten megabytes of the 4 GiB
 * range - and being wrong in that direction costs an archive a few readers from
 * 1993, where being wrong in the other costs it a size field it cannot write.
 *
 * @param writer The writer.
 * @param size The member's declared size.
 * @param method The method this member will be written with.
 * @return Non-zero when zip64 fields are needed.
 */
static int zip_needs_zip64(
    const GARC_Writer * writer, uint64_t size, uint16_t method) {
  const uint64_t largest = method == GARC_ZIP_METHOD_DEFLATE
      ? garc_zip_deflate_bound(size) : size;
  return writer->options.zip_force_zip64
      || largest >= (uint64_t)ZIP_MARKER32
      || garc_sink_tell(writer->sink) >= (uint64_t)ZIP_MARKER32;
}

/**
 * Have an encoder ready for this member, in its initial state.
 *
 * One encoder for the archive, reset between members: see
 * @ref GARC_Zip_Write_State.encoder. Created on the first member that needs one,
 * so that an archive of stored members allocates nothing for a codec it never
 * uses.
 *
 * @param writer The writer.
 * @return ::GARC_OK, ::GARC_ERR_OOM, or what the encoder refused with.
 */
static GARC_Result zip_deflate_begin(GARC_Writer * writer) {
  GARC_Zip_Write_State * zip = &writer->zip;
  if (zip->encoder) {
    return garc_codec_result(gcomp_encoder_reset(zip->encoder));
  }

  // The encoder before the buffer, which is the order with one unreachable line in
  // it rather than three: deflate is always registered and always has an encoder,
  // so the refusal below cannot be reached from a test, while the buffer's can be -
  // and putting the allocation second means the refusal needs no cleanup.
  const gcomp_status_t status = gcomp_encoder_create(
      gcomp_registry_default(), ZIP_DEFLATE_METHOD, NULL, &zip->encoder);
  if (status != GCOMP_OK) {
    return garc_codec_result(status);
  }
  zip->packed
      = (uint8_t *)gcu_allocator_malloc(writer->allocator, ZIP_DEFLATE_BUFFER);
  if (!zip->packed) {
    gcomp_encoder_destroy(zip->encoder);
    zip->encoder = NULL;
    return GARC_ERR_OOM;
  }
  return GARC_OK;
}

/**
 * Pass whatever the encoder has produced to the sink, and count it.
 *
 * @param writer The writer.
 * @param used How many bytes are in @ref GARC_Zip_Write_State.packed.
 * @return ::GARC_OK or what the sink refused with.
 */
static GARC_Result zip_deflate_emit(GARC_Writer * writer, size_t used) {
  GARC_Zip_Write_State * zip = &writer->zip;
  if (!used) {
    return GARC_OK;
  }
  const GARC_Result result = garc_sink_write(writer->sink, zip->packed, used);
  if (result != GARC_OK) {
    return result;
  }
  zip->compressed += (uint64_t)used;
  return GARC_OK;
}

/**
 * Close this member's deflate stream, writing its final block.
 *
 * @param writer The writer.
 * @return ::GARC_OK, or what the encoder or the sink refused with.
 */
static GARC_Result zip_deflate_end(GARC_Writer * writer) {
  GARC_Zip_Write_State * zip = &writer->zip;
  for (;;) {
    gcomp_buffer_t out = {zip->packed, ZIP_DEFLATE_BUFFER, 0};
    const gcomp_status_t status = gcomp_encoder_finish(zip->encoder, &out);
    const GARC_Result result = zip_deflate_emit(writer, out.used);
    if (result != GARC_OK) {
      return result;
    }
    if (status == GCOMP_OK) {
      return GARC_OK;
    }
    if (status != GCOMP_ERR_LIMIT) {
      return garc_codec_result(status);
    }
    // GCOMP_ERR_LIMIT is "there is more"; go round with a drained buffer. The
    // same loop codec_sink_finish() runs, and the same reason it is a loop: a
    // member's last block can be larger than the buffer. A round that produced
    // nothing cannot be made progress on by draining, so it is this library's
    // invariant failing rather than a caller's mistake - and it is the one thing
    // standing between that failure and a loop with no end.
    if (!out.used) {
      return GARC_ERR_INTERNAL;
    }
  }
}

GARC_Result garc_zip_write_member(
    GARC_Writer * writer, const GARC_Member * member) {
  GARC_Zip_Write_State * zip = &writer->zip;

  if (!member->name || !member->name_length) {
    // The same refusal the tar writer makes, for the same reason: no writer
    // produces an empty name and no filesystem holds one.
    return GARC_ERR_INVALID;
  }
  if (memchr(member->name, '\0', member->name_length)) {
    return GARC_ERR_INVALID;
  }
  if (member->name_length > 0xFFFFu) {
    // The name length field is 16 bits, and there is no carrier record in zip to
    // put a longer one in. A refusal rather than a truncation.
    return GARC_ERR_UNSUPPORTED;
  }

  const char * data = NULL;
  uint64_t size = member->size;
  switch (member->type) {
    case GARC_MEMBER_FILE:
      break;
    case GARC_MEMBER_DIRECTORY:
      if (member->size) {
        // A directory carries no data, so a declared size is a promise the caller
        // would not be allowed to keep.
        return GARC_ERR_INVALID;
      }
      break;
    case GARC_MEMBER_SYMLINK:
      // **The one place this writer writes bytes the caller did not.** A zip
      // symlink has no link field: its target *is* its data. So the caller sets
      // link_target as it would for a tar and writes nothing, and the target is
      // written here - which is what lets an archive be copied from tar to zip
      // without the caller knowing which it is writing.
      if (!member->link_target || !member->link_target_length) {
        return GARC_ERR_INVALID;
      }
      if (memchr(member->link_target, '\0', member->link_target_length)) {
        return GARC_ERR_INVALID;
      }
      if (member->size) {
        return GARC_ERR_INVALID;
      }
      data = member->link_target;
      size = (uint64_t)member->link_target_length;
      break;
    default:
      // A fifo, a device, a hard link, or GARC_MEMBER_OTHER. zip's external
      // attributes could carry the mode bits, but there is no convention for what
      // such a member's data is and no reference here writes one - so it is
      // refused by name rather than invented.
      return GARC_ERR_UNSUPPORTED;
  }

  zip->local_offset = garc_sink_tell(writer->sink);
  zip->declared = size;
  zip->compressed = 0;
  zip->running_crc = GCOMP_CRC32_INIT;
  // **The method, decided here because the local header carries it** and the
  // header goes out before the first byte of data. Two kinds of member are stored
  // whatever the options say - one with no data at all, and a symlink - and
  // writer.h argues both. A directory reaches the first without ever having had
  // the option.
  zip->method
      = writer->options.zip_method == GARC_ZIP_METHOD_DEFLATE && size
          && member->type != GARC_MEMBER_SYMLINK
      ? GARC_ZIP_METHOD_DEFLATE : GARC_ZIP_METHOD_STORED;
  zip->used_zip64 = zip_needs_zip64(writer, size, zip->method);
  zip->zip64_offset = 0;
  if (zip->method == GARC_ZIP_METHOD_DEFLATE) {
    // Before the header, so that a member refused for want of an encoder is
    // refused with nothing written - the same rule the name checks above follow.
    const GARC_Result ready = zip_deflate_begin(writer);
    if (ready != GARC_OK) {
      return ready;
    }
  }

  zip->flags = 0;
  if (zip_name_needs_utf8_flag(member->name, member->name_length)) {
    zip->flags |= ZIP_FLAG_UTF8;
  }
  // Which discipline this member uses. AUTO asks the sink; the other two were
  // settled at garc_writer_create(), which is where LOCAL over a sink that cannot
  // patch is refused - so by here the answer cannot fail.
  const int descriptor = writer->options.zip_sizes == GARC_ZIP_SIZES_DESCRIPTOR
      || (writer->options.zip_sizes == GARC_ZIP_SIZES_AUTO
          && !garc_sink_is_seekable(writer->sink));
  if (descriptor) {
    zip->flags |= ZIP_FLAG_DATA_DESCRIPTOR;
  }

  const int exact
      = garc_zip_epoch_to_dos(member->mtime_source == GARC_TIME_NONE
              ? (int64_t)0 : member->mtime_seconds,
          &zip->dos_date, &zip->dos_time);
  // The extended timestamp, and only when it would help. Three conditions, and the
  // third was a defect a test found:
  //
  // - The caller supplied a time. GARC_TIME_NONE gets neither field filled in
  //   usefully: zip has no way to say "no time", the DOS pair is mandatory, and
  //   inventing an extra field to carry a time nobody supplied is worse than the
  //   clamp.
  // - The DOS pair cannot carry it exactly. When it can, the extra field would be
  //   nine bytes saying what the header already says.
  // - **And the extra field can carry it**, which is a narrower range than the DOS
  //   pair's at the top end: 0x5455 holds a signed 32-bit epoch second, so it stops
  //   in 2038 where the DOS date runs to 2107. A time past that was being truncated
  //   into the field - 2108 came back as 1971 - which is worse than the clamp it
  //   was there to avoid. Above INT32_MAX the DOS pair is the *better* of the two,
  //   and below INT32_MIN neither can hold it and the clamp stands.
  const int fits_ut = member->mtime_seconds >= (int64_t)INT32_MIN
      && member->mtime_seconds <= (int64_t)INT32_MAX;
  const int want_ut
      = member->mtime_source != GARC_TIME_NONE && !exact && fits_ut;

  // **The type bits come from the type and the permissions from the mode**, which
  // is the one place this writer composes a field rather than copying one. It has
  // to: a zip has no typeflag, so what makes a member a symlink is `S_IFLNK` in
  // the high half of these attributes - and a caller copying a member out of a
  // *tar* has permissions in GARC_Member.mode and nothing else, because tar's
  // mode field carries no type. Taking `mode` whole would turn every symlink
  // copied from a tar into a regular file with unusual permissions, which is what
  // the first run of this writer did.
  //
  // A caller copying out of a zip has the type bits in `mode` as well, and
  // composing from `member->type` reproduces them exactly - the reader derived the
  // type from those bits in the first place - so there is no need to ask which
  // kind of caller this is.
  uint32_t unix_mode = member->mode_valid ? (member->mode & 07777u) : 0u;
  switch (member->type) {
    case GARC_MEMBER_DIRECTORY:
      unix_mode |= 0040000u;
      break;
    case GARC_MEMBER_SYMLINK:
      unix_mode |= 0120000u;
      break;
    default:
      unix_mode |= 0100000u;
      break;
  }
  zip->external_attributes = unix_mode << 16;
  if (member->type == GARC_MEMBER_DIRECTORY) {
    // The DOS attribute bit, which is how a zip written for Windows says
    // "directory" - and what this library's own reader falls back to when
    // `version made by` does not say Unix. Set from the *type*, which is not
    // normalising the name: a caller's trailing slash is still theirs.
    zip->external_attributes |= ZIP_DOS_DIRECTORY;
  }

  // The extra field, built once and written into both records with the lengths
  // each of them needs.
  uint8_t extra[32];
  size_t local_extra = 0;
  if (zip->used_zip64) {
    garc_zip_put16(extra + local_extra, 0x0001u);
    garc_zip_put16(extra + local_extra + 2u, 16u);
    garc_zip_put64(extra + local_extra + 4u, size);
    garc_zip_put64(extra + local_extra + 12u, 0u); // Patched or descriptor-borne.
    local_extra = 20u;
  }
  if (want_ut) {
    // 0x5455: one flags byte saying which times follow, then the times. Only
    // mtime, which is bit 0 - this library has no atime or ctime to write, and a
    // field claiming times it does not carry is what makes Info-ZIP's UT nine
    // bytes in one record and five in the other.
    garc_zip_put16(extra + local_extra, 0x5455u);
    garc_zip_put16(extra + local_extra + 2u, 5u);
    extra[local_extra + 4u] = 0x01u;
    // Cast through int32_t, because the field is signed and a negative time has to
    // arrive as one: the reader reads it back with the same signedness.
    garc_zip_put32(extra + local_extra + 5u,
        (uint32_t)(int32_t)member->mtime_seconds);
    local_extra += 9u;
  }
  // **The central entry's extra is a different length from the local one**, and it
  // is built here rather than at close so that the rule lives in one place. Its
  // zip64 payload carries only the uncompressed size: the compressed size and the
  // local offset are known by the time the directory is written and go in their
  // own fields for real. Info-ZIP's `-fz` output has exactly this asymmetry, 16
  // bytes of payload in the local header against 8 in the directory.
  uint8_t central[32];
  size_t central_extra = 0;
  if (zip->used_zip64) {
    garc_zip_put16(central + central_extra, 0x0001u);
    garc_zip_put16(central + central_extra + 2u, 8u);
    garc_zip_put64(central + central_extra + 4u, size);
    central_extra = 12u;
  }
  if (want_ut) {
    // The same five payload bytes in both records, unlike Info-ZIP's nine-then-five
    // - it carries an atime in the local copy and this library has none to carry.
    memcpy(central + central_extra, extra + local_extra - 9u, 9u);
    central_extra += 9u;
  }

  uint8_t header[GARC_ZIP_LOCAL_HEADER_SIZE];
  memcpy(header, ZIP_SIG_LOCAL, 4);
  garc_zip_put16(header + 4u,
      zip->used_zip64 ? ZIP_VERSION_NEEDED_ZIP64 : ZIP_VERSION_NEEDED);
  garc_zip_put16(header + 6u, zip->flags);
  garc_zip_put16(header + 8u, zip->method);
  garc_zip_put16(header + 10u, zip->dos_time);
  garc_zip_put16(header + 12u, zip->dos_date);
  // Zero here in every discipline: with a descriptor these stay zero, and with
  // the patching form they are filled in when the data is done. Writing the CRC
  // now is impossible either way - it is of bytes the caller has not handed over.
  garc_zip_put32(header + 14u, 0u);
  garc_zip_put32(header + 18u, zip->used_zip64 ? ZIP_MARKER32 : 0u);
  garc_zip_put32(header + 22u, zip->used_zip64 ? ZIP_MARKER32 : 0u);
  garc_zip_put16(header + 26u, (uint16_t)member->name_length);
  garc_zip_put16(header + 28u, (uint16_t)local_extra);

  GARC_Result result = garc_sink_write(writer->sink, header, sizeof(header));
  if (result != GARC_OK) {
    return result;
  }
  zip->crc_offset = zip->local_offset + 14u;
  result = garc_sink_write(writer->sink, member->name, member->name_length);
  if (result != GARC_OK) {
    return result;
  }
  if (local_extra) {
    zip->zip64_offset = zip->used_zip64
        ? garc_sink_tell(writer->sink) + 4u : 0u;
    result = garc_sink_write(writer->sink, extra, local_extra);
    if (result != GARC_OK) {
      return result;
    }
  }

  // The name and the central extra are kept until finish, when the directory is
  // written. Two buffers rather than one concatenation, because the entry's two
  // length fields describe them separately and a single buffer would have to be
  // split again to fill them in.
  result = garc_buffer_grow(writer->allocator, &zip->name, member->name_length);
  if (result != GARC_OK) {
    return result;
  }
  memcpy(zip->name.bytes, member->name, member->name_length);
  zip->name.length = member->name_length;
  result = garc_buffer_grow(writer->allocator, &zip->extra, central_extra);
  if (result != GARC_OK) {
    return result;
  }
  memcpy(zip->extra.bytes, central, central_extra);
  zip->extra.length = central_extra;

  writer->data_remaining = size;
  writer->data_padding = 0; // zip pads nothing. Ever.

  if (data) {
    // A symlink's target, written here so the caller writes nothing. Through the
    // same function a caller's own writes go through, so the CRC and the
    // compressed total are accounted for identically.
    result = garc_zip_write_data(writer, data, (size_t)size);
    if (result != GARC_OK) {
      return result;
    }
    // **And the caller owes nothing.** That decrement lives in
    // garc_writer_write(), which this did not go through, so without this line the
    // member stays short for ever and the *next* garc_writer_add() is refused.
    // The failure is one member late, which is what made it worth a line of its
    // own rather than a subtraction inside the write.
    writer->data_remaining = 0;
  }
  return GARC_OK;
}

GARC_Result garc_zip_write_data(
    GARC_Writer * writer, const void * data, size_t size) {
  GARC_Zip_Write_State * zip = &writer->zip;
  // **The CRC is of the uncompressed bytes whatever the method**, because it is
  // what an extractor checks after inflating. Computed into a local and assigned
  // only once the bytes are away, so that a failed write leaves the member exactly
  // as it was - the all-or-nothing the sink promises, kept one level up.
  const uint32_t crc
      = gcomp_crc32_update(zip->running_crc, (const uint8_t *)data, size);

  if (zip->method == GARC_ZIP_METHOD_STORED) {
    const GARC_Result result = garc_sink_write(writer->sink, data, size);
    if (result != GARC_OK) {
      return result;
    }
    // Counted separately from data_remaining, which counts what the *caller* still
    // owes. For a stored member the two totals agree; a compressed one is why they
    // are two fields.
    zip->compressed += (uint64_t)size;
    zip->running_crc = crc;
    return GARC_OK;
  }

  // Deflate. The loop drains the encoder rather than assuming one pass empties it,
  // because the output of a block can exceed the buffer on data that does not
  // compress - which is the case the buffer is sized for rather than against.
  gcomp_buffer_t in = {data, size, 0};
  while (in.used < size) {
    gcomp_buffer_t out = {zip->packed, ZIP_DEFLATE_BUFFER, 0};
    const size_t before = in.used;
    const gcomp_status_t status
        = gcomp_encoder_update(zip->encoder, &in, &out);
    if (status != GCOMP_OK) {
      return garc_codec_result(status);
    }
    const GARC_Result result = zip_deflate_emit(writer, out.used);
    if (result != GARC_OK) {
      return result;
    }
    if (!out.used && in.used == before) {
      // Neither consumed nor produced, with input still in hand: codec_sink_write()
      // guards the same round for the same reason, and calls it the same thing.
      return GARC_ERR_INTERNAL;
    }
  }
  // Only here. Unlike the stored path this cannot be retried - the encoder has the
  // bytes - so the assignment is not a promise about a retry, it is the same
  // statement made in the same place.
  zip->running_crc = crc;
  return GARC_OK;
}

/**
 * Write the data descriptor that follows a member whose header said nothing.
 *
 * Its size fields are 8 bytes each when the member's records are zip64 and 4
 * otherwise, which is the one place the descriptor's own layout is decided - and
 * it has to match what a reader will assume from the local header's version and
 * extra field, because the descriptor has no length of its own.
 *
 * @param writer The writer.
 * @param crc The finalized CRC-32.
 * @return GARC_OK or GARC_ERR_IO.
 */
static GARC_Result zip_write_descriptor(GARC_Writer * writer, uint32_t crc) {
  const GARC_Zip_Write_State * zip = &writer->zip;
  uint8_t descriptor[ZIP_DESCRIPTOR_SIZE_64];
  // The signature is optional in the specification and universal in practice;
  // every reference in the corpus writes it, and a reader scanning for the end of
  // a streamed member needs it.
  memcpy(descriptor, ZIP_SIG_DESCRIPTOR, 4);
  garc_zip_put32(descriptor + 4u, crc);
  size_t length = ZIP_DESCRIPTOR_SIZE_32;
  if (zip->used_zip64) {
    garc_zip_put64(descriptor + 8u, zip->compressed);
    garc_zip_put64(descriptor + 16u, zip->declared);
    length = ZIP_DESCRIPTOR_SIZE_64;
  }
  else {
    garc_zip_put32(descriptor + 8u, (uint32_t)zip->compressed);
    garc_zip_put32(descriptor + 12u, (uint32_t)zip->declared);
  }
  return garc_sink_write(writer->sink, descriptor, length);
}

/**
 * Fill in the local header this member wrote with zeros in it.
 *
 * Three patches rather than one: the CRC and the two 32-bit size fields are
 * contiguous, and the zip64 payload is elsewhere. Written as one call for the
 * contiguous run and one for the payload, because a patch per field would be
 * three round trips through a caller's `fseek` for no gain.
 *
 * @param writer The writer.
 * @param crc The finalized CRC-32.
 * @return GARC_OK, or GARC_ERR_IO from the sink.
 */
static GARC_Result zip_patch_header(GARC_Writer * writer, uint32_t crc) {
  const GARC_Zip_Write_State * zip = &writer->zip;
  uint8_t fields[12];
  garc_zip_put32(fields, crc);
  garc_zip_put32(fields + 4u,
      zip->used_zip64 ? ZIP_MARKER32 : (uint32_t)zip->compressed);
  garc_zip_put32(fields + 8u,
      zip->used_zip64 ? ZIP_MARKER32 : (uint32_t)zip->declared);
  GARC_Result result
      = garc_sink_patch(writer->sink, zip->crc_offset, fields, sizeof(fields));
  if (result != GARC_OK || !zip->used_zip64) {
    return result;
  }
  // The real values, in the order the specification lists them: uncompressed
  // size, then compressed size.
  uint8_t payload[16];
  garc_zip_put64(payload, zip->declared);
  garc_zip_put64(payload + 8u, zip->compressed);
  return garc_sink_patch(
      writer->sink, zip->zip64_offset, payload, sizeof(payload));
}

GARC_Result garc_zip_write_close_member(GARC_Writer * writer) {
  GARC_Zip_Write_State * zip = &writer->zip;

  // **The deflate stream ends before anything is written about its length**, which
  // is the whole reason this is a hook and not a subtraction: the final block is
  // part of the compressed size, and the descriptor or the patched header that
  // carries that size comes after it.
  if (zip->method == GARC_ZIP_METHOD_DEFLATE) {
    const GARC_Result ended = zip_deflate_end(writer);
    if (ended != GARC_OK) {
      return ended;
    }
  }
  const uint32_t crc = gcomp_crc32_finalize(zip->running_crc);

  GARC_Result result = (zip->flags & ZIP_FLAG_DATA_DESCRIPTOR)
      ? zip_write_descriptor(writer, crc)
      : zip_patch_header(writer, crc);
  if (result != GARC_OK) {
    return result;
  }

  // The central entry, which is what a reader will believe. Its sizes are the
  // real ones in every discipline: a descriptor is for the *local* header's
  // benefit, and the directory has never had an excuse.
  const size_t extra_length = zip->extra.length;
  uint8_t entry[GARC_ZIP_CENTRAL_ENTRY_SIZE];
  memcpy(entry, ZIP_SIG_CENTRAL, 4);
  garc_zip_put16(entry + 4u, ZIP_VERSION_MADE_BY);
  garc_zip_put16(entry + 6u,
      zip->used_zip64 ? ZIP_VERSION_NEEDED_ZIP64 : ZIP_VERSION_NEEDED);
  garc_zip_put16(entry + 8u, zip->flags);
  garc_zip_put16(entry + 10u, zip->method);
  garc_zip_put16(entry + 12u, zip->dos_time);
  garc_zip_put16(entry + 14u, zip->dos_date);
  garc_zip_put32(entry + 16u, crc);
  garc_zip_put32(entry + 20u, (uint32_t)zip->compressed);
  garc_zip_put32(entry + 24u,
      zip->used_zip64 ? ZIP_MARKER32 : (uint32_t)zip->declared);
  garc_zip_put16(entry + 28u, (uint16_t)zip->name.length);
  garc_zip_put16(entry + 30u, (uint16_t)extra_length);
  garc_zip_put16(entry + 32u, 0u); // No member comment.
  garc_zip_put16(entry + 34u, 0u); // Disk 0, which is the only disk there is.
  garc_zip_put16(entry + 36u, 0u); // Internal attributes: no writer sets these.
  garc_zip_put32(entry + 38u, zip->external_attributes);
  garc_zip_put32(entry + 42u, (uint32_t)zip->local_offset);

  result = zip_central_append(writer, entry, sizeof(entry));
  if (result != GARC_OK) {
    return result;
  }
  result = zip_central_append(writer, zip->name.bytes, zip->name.length);
  if (result != GARC_OK) {
    return result;
  }
  if (extra_length) {
    result = zip_central_append(writer, zip->extra.bytes, extra_length);
    if (result != GARC_OK) {
      return result;
    }
  }
  zip->entries++;
  return GARC_OK;
}

GARC_Result garc_zip_write_end(GARC_Writer * writer) {
  GARC_Zip_Write_State * zip = &writer->zip;
  const uint64_t central_offset = garc_sink_tell(writer->sink);

  GARC_Result result
      = garc_sink_write(writer->sink, zip->central.bytes, zip->central.length);
  if (result != GARC_OK) {
    return result;
  }
  const uint64_t central_size = zip->central.length;

  // **The zip64 end record, when any of the end record's own fields will not
  // fit** - and also when the caller forced zip64, so that a forced archive is
  // one throughout rather than one with zip64 members and a 1993 end record.
  const int need_zip64_end = writer->options.zip_force_zip64
      || zip->entries > (uint64_t)ZIP_MARKER16
      || central_size >= (uint64_t)ZIP_MARKER32
      || central_offset >= (uint64_t)ZIP_MARKER32;
  if (need_zip64_end) {
    uint8_t record[GARC_ZIP_ZIP64_EOCD_SIZE];
    memcpy(record, ZIP_SIG_ZIP64_EOCD, 4);
    // The size field counts the record *after* itself, which is 56 - 12: four
    // bytes of signature and eight of the field are not in it.
    garc_zip_put64(record + 4u, GARC_ZIP_ZIP64_EOCD_SIZE - 12u);
    garc_zip_put16(record + 12u, ZIP_VERSION_MADE_BY);
    garc_zip_put16(record + 14u, ZIP_VERSION_NEEDED_ZIP64);
    garc_zip_put32(record + 16u, 0u); // This disk.
    garc_zip_put32(record + 20u, 0u); // The disk the directory starts on.
    garc_zip_put64(record + 24u, zip->entries);
    garc_zip_put64(record + 32u, zip->entries);
    garc_zip_put64(record + 40u, central_size);
    garc_zip_put64(record + 48u, central_offset);
    result = garc_sink_write(writer->sink, record, sizeof(record));
    if (result != GARC_OK) {
      return result;
    }

    uint8_t locator[GARC_ZIP_ZIP64_LOCATOR_SIZE];
    memcpy(locator, ZIP_SIG_ZIP64_LOCATOR, 4);
    garc_zip_put32(locator + 4u, 0u); // The disk the zip64 record is on.
    garc_zip_put64(locator + 8u, central_offset + central_size);
    garc_zip_put32(locator + 16u, 1u); // The number of disks.
    result = garc_sink_write(writer->sink, locator, sizeof(locator));
    if (result != GARC_OK) {
      return result;
    }
  }

  uint8_t eocd[GARC_ZIP_EOCD_SIZE];
  memcpy(eocd, ZIP_SIG_EOCD, 4);
  garc_zip_put16(eocd + 4u, 0u); // This disk.
  garc_zip_put16(eocd + 6u, 0u); // The disk the directory starts on.
  // Marked only where the value does not fit, which is the same rule the members'
  // fields follow. `zip -fz` marks the central offset on an archive whose offset
  // fits, and this does not: the forced flag is about the *members'* fields and
  // the zip64 end record above, and a marker over a value that fits is a lie a
  // reader has to work around.
  const uint16_t entries16 = zip->entries > (uint64_t)ZIP_MARKER16
      ? ZIP_MARKER16 : (uint16_t)zip->entries;
  garc_zip_put16(eocd + 8u, entries16);
  garc_zip_put16(eocd + 10u, entries16);
  garc_zip_put32(eocd + 12u, central_size >= (uint64_t)ZIP_MARKER32
      ? ZIP_MARKER32 : (uint32_t)central_size);
  garc_zip_put32(eocd + 16u, central_offset >= (uint64_t)ZIP_MARKER32
      ? ZIP_MARKER32 : (uint32_t)central_offset);
  garc_zip_put16(eocd + 20u, 0u); // No archive comment.
  return garc_sink_write(writer->sink, eocd, sizeof(eocd));
}

void garc_zip_write_release(GARC_Writer * writer) {
  // The encoder before the buffer it writes into, which is the order
  // garc_member_codec_destroy() gives the reason for: a teardown that reads the
  // buffer would read a freed one the other way round.
  gcomp_encoder_destroy(writer->zip.encoder);
  gcu_allocator_free(writer->allocator, writer->zip.packed);
  garc_buffer_free(writer->allocator, &writer->zip.central);
  garc_buffer_free(writer->allocator, &writer->zip.name);
  garc_buffer_free(writer->allocator, &writer->zip.extra);
}

const char * garc_zip_sizes_string(GARC_Zip_Sizes sizes) {
  switch (sizes) {
    case GARC_ZIP_SIZES_AUTO:
      return "auto";
    case GARC_ZIP_SIZES_DESCRIPTOR:
      return "data descriptor";
    case GARC_ZIP_SIZES_LOCAL:
      return "local header";
    case GARC_ZIP_SIZES_COUNT:
    default:
      return "unknown";
  }
}
