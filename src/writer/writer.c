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
 * The format-independent half of building an archive: the member cursor, the
 * data accounting, and the end of the archive.
 *
 * Everything that knows what a tar header looks like is in `src/tar/tar_write.c`,
 * for the reason the reader is split the same way: the next format has the same
 * cursor and none of the header.
 */

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/allocator.h>
#include <ghoti.io/archive/writer.h>
#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/cutil/file.h>
#include <stdint.h>
#include <string.h>

#include "ar/ar_internal.h"
#include "reader/reader_internal.h"
#include "cpio/cpio_internal.h"
#include "sevenz/sevenz_internal.h"
#include "shar/shar_internal.h"
#include "tar/tar_internal.h"
#include "writer/writer_internal.h"
#include "zip/zip_internal.h"

void garc_writer_options_default(GARC_Writer_Options * options) {
  if (!options) {
    return;
  }
  options->tar_variant = GARC_TAR_PAX;
  // Ask the sink. The only value that never refuses, and the one that produces
  // the better archive wherever it can: local headers with real sizes in them
  // where the sink can be patched, descriptors where it cannot.
  options->zip_sizes = GARC_ZIP_SIZES_AUTO;
  // Off, because a zip64 field on a member that does not need one is refused by
  // some old readers. GARC_Writer_Options says why the knob exists at all.
  options->zip_force_zip64 = 0;
  // LZMA2 solid, which is 7-Zip's default and the zero of both fields.
  options->sevenz_method = GARC_SEVENZ_LZMA2;
  options->sevenz_non_solid = 0;
  options->cpio_variant = GARC_CPIO_NEWC;
  options->shar_uuencode = 0;
  // Stored, which is also this field's zero. GARC_Writer_Options argues it.
  options->zip_method = GARC_ZIP_METHOD_STORED;
  // No password. A zero-filled struct agrees: the pointer and the length are
  // both zero, and that is unencrypted. Bits of 0 mean AES-256 only once a
  // password is set.
  options->zip_password = NULL;
  options->zip_password_length = 0;
  options->zip_aes_bits = 0;
  // No record padding. bsdtar's answer rather than GNU tar's: 10240 bytes was a
  // tape record, every reader accepts either, and this library's archives are
  // built in memory and handed to a caller far more often than they are written
  // to tape.
  options->blocking_factor = 0;
}

/**
 * Finish whatever the current member still owes, so that the sink is positioned
 * at a block boundary.
 *
 * Called by garc_writer_add() before the next header and by garc_writer_finish()
 * before the end marker - the two places a member can close - so the "did the
 * caller deliver what it declared" check has one home rather than two that can
 * disagree.
 *
 * @param writer The writer.
 * @return GARC_OK, GARC_ERR_INVALID when the member is short, or GARC_ERR_IO.
 */
/**
 * Record @p result as the writer's failure unless it provably changed nothing.
 *
 * A sink write is all or nothing, so a position that did not move means no byte
 * of this call reached the sink. That is enough for tar, ar and cpio, whose
 * writers keep nothing between calls but the sink's position. zip, 7z and shar
 * keep a CRC, an encoder, a directory or a half-written line, and a failure
 * there may have moved them, so it fails the writer whatever the position says
 * - except a refusal from an add, which those formats make before they change
 * anything.
 *
 * @param writer The writer.
 * @param result The failure.
 * @param before The sink's position when the call began.
 * @param refusal_is_clean Whether ::GARC_ERR_INVALID and ::GARC_ERR_UNSUPPORTED
 *   are refusals made before anything changed, which is true of an add.
 * @return @p result.
 */
static GARC_Result writer_fail(GARC_Writer * writer, GARC_Result result,
    uint64_t before, int refusal_is_clean) {
  int clean = garc_sink_tell(writer->sink) == before;
  if (clean) {
    const int stateless = writer->format == GARC_FORMAT_TAR
        || writer->format == GARC_FORMAT_AR || writer->format == GARC_FORMAT_CPIO;
    const int refusal = refusal_is_clean
        && (result == GARC_ERR_INVALID || result == GARC_ERR_UNSUPPORTED);
    clean = stateless || refusal;
  }
  if (!clean) {
    writer->failed = result;
  }
  return result;
}

static GARC_Result writer_close_member(GARC_Writer * writer) {
  if (!writer->have_member) {
    return GARC_OK;
  }
  if (writer->data_remaining) {
    // The header already says how many bytes there are, and it has been written.
    // Padding to fit would make the archive claim data it does not have; letting
    // it through would put the next header where a reader is not looking for one.
    return GARC_ERR_INVALID;
  }
  const uint64_t before = garc_sink_tell(writer->sink);
  // Each format's own closing work, through a hook rather than inline: tar pads
  // and zip writes a descriptor or patches a header and appends a directory
  // entry, and neither rule belongs in the file that has no format in it.
  GARC_Result result;
  if (writer->format == GARC_FORMAT_AR) {
    result = garc_ar_write_close_member(writer);
  }
  else if (writer->format == GARC_FORMAT_CPIO) {
    result = garc_cpio_write_close_member(writer);
  }
  else if (writer->format == GARC_FORMAT_SHAR) {
    result = garc_shar_write_close_member(writer);
  }
  else if (writer->format == GARC_FORMAT_SEVENZ) {
    result = garc_sevenz_write_close_member(writer);
  }
  else if (writer->format == GARC_FORMAT_ZIP) {
    result = garc_zip_write_close_member(writer);
  }
  else {
    result = garc_tar_write_close_member(writer);
  }
  if (result != GARC_OK) {
    return writer_fail(writer, result, before, 0);
  }
  writer->data_padding = 0;
  writer->have_member = 0;
  return GARC_OK;
}

GARC_Result garc_writer_create(GARC_Sink * sink, GARC_Format format,
    const GARC_Writer_Options * options, GARC_Writer ** out_writer) {
  return garc_writer_create_with_allocator(
      sink, format, options, NULL, out_writer);
}

GARC_Result garc_writer_create_with_allocator(GARC_Sink * sink,
    GARC_Format format, const GARC_Writer_Options * options,
    const GARC_Allocator * allocator, GARC_Writer ** out_writer) {
  if (!out_writer || !sink) {
    return GARC_ERR_INVALID;
  }

  GARC_Writer_Options resolved;
  garc_writer_options_default(&resolved);
  if (options) {
    resolved = *options;
  }

  if (format == GARC_FORMAT_TAR) {
    switch (resolved.tar_variant) {
      case GARC_TAR_PAX:
      case GARC_TAR_USTAR:
        break;
      case GARC_TAR_NONE:
        // What a zero-filled options struct holds. Refused rather than treated as
        // the default, so that a caller who meant to choose and forgot is told;
        // NULL is how a caller says they do not mind.
        return GARC_ERR_INVALID;
      default:
        // v7 and GNU. Both are read, neither is written; writer.h says why.
        return GARC_ERR_UNSUPPORTED;
    }
  }
  else if (format == GARC_FORMAT_ZIP) {
    switch (resolved.zip_sizes) {
      case GARC_ZIP_SIZES_AUTO:
      case GARC_ZIP_SIZES_DESCRIPTOR:
        break;
      case GARC_ZIP_SIZES_LOCAL:
        if (!garc_sink_is_seekable(sink)) {
          // **Refused here rather than at the first member**, and by name rather
          // than as "unsupported": the caller asked for a form of archive this
          // sink cannot produce, which is a fact known before a byte is written.
          // Failing later would leave a truncated archive behind a refusal.
          return GARC_ERR_NOT_SEEKABLE;
        }
        break;
      default:
        return GARC_ERR_INVALID;
    }
    switch (resolved.zip_method) {
      case GARC_ZIP_METHOD_STORED:
      case GARC_ZIP_METHOD_DEFLATE:
      case GARC_ZIP_METHOD_DEFLATE64:
      case GARC_ZIP_METHOD_BZIP2:
      case GARC_ZIP_METHOD_ZSTD:
      case GARC_ZIP_METHOD_XZ:
      case GARC_ZIP_METHOD_LZMA:
        break;
      default:
        // Every other value, the readable ones included. Refused here rather than
        // at the first member, for the same reason the sizes are: the answer is
        // known before a byte is written, and a refusal afterwards would leave a
        // truncated archive behind it.
        return GARC_ERR_UNSUPPORTED;
    }
    if (!resolved.zip_password && resolved.zip_password_length) {
      return GARC_ERR_INVALID;
    }
    switch (resolved.zip_aes_bits) {
      case 0u:
      case 128u:
      case 192u:
      case 256u:
        break;
      default:
        return GARC_ERR_INVALID;
    }
    // zip has no variants and tar_variant is meaningless here, so it is not
    // checked: a caller copying an archive from tar to zip should not have to
    // clear a field that describes the format they are no longer writing.
  }
  else if (format == GARC_FORMAT_SEVENZ) {
    // The signature header at the front is written last, so the sink has to be
    // able to go back for it. See sevenz_write.c.
    if (!garc_sink_is_seekable(sink)) {
      return GARC_ERR_NOT_SEEKABLE;
    }
    switch (resolved.sevenz_method) {
      case GARC_SEVENZ_LZMA2:
      case GARC_SEVENZ_LZMA:
      case GARC_SEVENZ_BZIP2:
      case GARC_SEVENZ_DEFLATE:
      case GARC_SEVENZ_DEFLATE64:
      case GARC_SEVENZ_COPY:
        break;
      default:
        return GARC_ERR_INVALID;
    }
  }
  else if (format == GARC_FORMAT_AR || format == GARC_FORMAT_SHAR) {
    // Streamed: nothing here needs the sink to go back.
  }
  else if (format == GARC_FORMAT_CPIO) {
    switch (resolved.cpio_variant) {
      case GARC_CPIO_NEWC:
      case GARC_CPIO_ODC:
        break;
      default:
        return GARC_ERR_INVALID;
    }
  }
  else {
    // GARC_FORMAT_UNKNOWN included: a caller who has not said what to write has
    // not said it, and there is no format to guess at from a sink.
    return format == GARC_FORMAT_UNKNOWN ? GARC_ERR_INVALID
                                         : GARC_ERR_UNSUPPORTED;
  }

  if (!allocator) {
    allocator = garc_allocator_default();
  }
  GARC_Writer * writer
      = (GARC_Writer *)gcu_allocator_calloc(allocator, 1, sizeof(GARC_Writer));
  if (!writer) {
    return GARC_ERR_OOM;
  }
  writer->sink = sink;
  writer->allocator = allocator;
  writer->format = format;
  writer->options = resolved;

  if (format == GARC_FORMAT_ZIP && resolved.zip_password) {
    const uint32_t bits
        = resolved.zip_aes_bits ? resolved.zip_aes_bits : 256u;
    const GARC_Result adopted = garc_zip_write_adopt_password(
        writer, resolved.zip_password, resolved.zip_password_length, bits);
    if (adopted != GARC_OK) {
      garc_writer_destroy(writer);
      return adopted;
    }
    // The caller's pointer is not the copy. Drop it so a later use of the
    // options struct cannot read a buffer the caller has freed.
    writer->options.zip_password = NULL;
    writer->options.zip_password_length = 0;
  }

  if (format == GARC_FORMAT_SEVENZ) {
    const GARC_Result begun = garc_sevenz_write_begin(writer);
    if (begun != GARC_OK) {
      garc_writer_destroy(writer);
      return begun;
    }
  }

  *out_writer = writer;
  return GARC_OK;
}

GARC_Result garc_writer_add(GARC_Writer * writer, const GARC_Member * member) {
  if (!writer || !member) {
    return GARC_ERR_INVALID;
  }
  if (writer->failed) {
    return writer->failed;
  }
  if (writer->finished) {
    return GARC_ERR_INVALID;
  }

  GARC_Result result = writer_close_member(writer);
  if (result != GARC_OK) {
    return result;
  }

  const uint64_t before = garc_sink_tell(writer->sink);
  if (member->sparse_regions && writer->format != GARC_FORMAT_TAR) {
    // Only tar has a way to say where the holes are.
    return GARC_ERR_UNSUPPORTED;
  }
  if (writer->format == GARC_FORMAT_AR) {
    result = garc_ar_write_member(writer, member);
  }
  else if (writer->format == GARC_FORMAT_CPIO) {
    result = garc_cpio_write_member(writer, member);
  }
  else if (writer->format == GARC_FORMAT_SHAR) {
    result = garc_shar_write_member(writer, member);
  }
  else if (writer->format == GARC_FORMAT_SEVENZ) {
    result = garc_sevenz_write_member(writer, member);
  }
  else if (writer->format == GARC_FORMAT_ZIP) {
    result = garc_zip_write_member(writer, member);
  }
  else {
    result = garc_tar_write_member(writer, member);
  }
  if (result != GARC_OK) {
    // have_member stays clear: a header that was not written describes nothing,
    // and leaving a member open would make the next add() pad for data that has
    // no header in front of it. Part of a header in the sink is another matter:
    // see writer_fail().
    return writer_fail(writer, result, before, 1);
  }

  writer->member_count++;
  writer->have_member = 1;
  return GARC_OK;
}

GARC_Result garc_writer_write(
    GARC_Writer * writer, const void * data, size_t size) {
  if (!writer || (!data && size)) {
    return GARC_ERR_INVALID;
  }
  if (writer->failed) {
    return writer->failed;
  }
  if (!writer->have_member || writer->finished) {
    return GARC_ERR_INVALID;
  }
  if ((uint64_t)size > writer->data_remaining) {
    // Refused here rather than at the end: the header is already written and
    // says how long the member is, so these bytes have nowhere to go. Writing
    // them and reporting afterwards would leave the archive unrecoverable.
    return GARC_ERR_INVALID;
  }
  if (!size) {
    return GARC_OK;
  }

  const uint64_t before = garc_sink_tell(writer->sink);
  GARC_Result result;
  if (writer->format == GARC_FORMAT_SHAR) {
    result = garc_shar_write_data(writer, data, size);
  }
  else if (writer->format == GARC_FORMAT_SEVENZ) {
    result = garc_sevenz_write_data(writer, data, size);
  }
  else if (writer->format == GARC_FORMAT_ZIP) {
    result = garc_zip_write_data(writer, data, size);
  }
  else if (writer->format == GARC_FORMAT_TAR) {
    result = garc_tar_write_data(writer, data, size);
  }
  else {
    result = garc_sink_write(writer->sink, data, size);
  }
  if (result != GARC_OK) {
    // Part of the chunk may be out, or inside an encoder, and then the member
    // cannot be completed honestly.
    return writer_fail(writer, result, before, 0);
  }
  writer->data_remaining -= (uint64_t)size;
  return GARC_OK;
}

GARC_Result garc_writer_finish(GARC_Writer * writer) {
  if (!writer) {
    return GARC_ERR_INVALID;
  }
  if (writer->failed) {
    return writer->failed;
  }
  if (writer->finished) {
    return GARC_ERR_INVALID;
  }

  GARC_Result result = writer_close_member(writer);
  if (result != GARC_OK) {
    return result;
  }

  const uint64_t before = garc_sink_tell(writer->sink);
  if (writer->format == GARC_FORMAT_AR) {
    result = garc_ar_write_end(writer);
  }
  else if (writer->format == GARC_FORMAT_CPIO) {
    result = garc_cpio_write_end(writer);
  }
  else if (writer->format == GARC_FORMAT_SHAR) {
    result = garc_shar_write_end(writer);
  }
  else if (writer->format == GARC_FORMAT_SEVENZ) {
    result = garc_sevenz_write_end(writer);
  }
  else if (writer->format == GARC_FORMAT_ZIP) {
    result = garc_zip_write_end(writer);
  }
  else {
    result = garc_tar_write_end(writer);
  }
  if (result != GARC_OK) {
    return writer_fail(writer, result, before, 0);
  }
  writer->finished = 1;
  return GARC_OK;
}

/** Every flag ::garc_writer_copy_member() accepts. */
#define GARC_COPY_KNOWN (GARC_COPY_RAW)

/** How much of a member is moved per read. */
#define GARC_COPY_CHUNK 16384u

/**
 * A symlink's target from its data, for a source that keeps the target there.
 *
 * zip and cpio store a symlink's target as the member's data, and a zip
 * reader lends it as the link target only when it is stored in the clear. In
 * every other case the target is read here, so that every writer is handed a
 * link with a target and no data, which is what each of them takes.
 */
static GARC_Result copy_read_target(GARC_Archive * archive,
    const GARC_Allocator * allocator, char ** out, size_t * out_length) {
  const uint64_t size = archive->member.size;
  const uint64_t cap = archive->limits.max_name_bytes;
  if (cap && size > cap) {
    return GARC_ERR_LIMIT_NAME_BYTES;
  }
  if (size > (uint64_t)SIZE_MAX - 1u) {
    return GARC_ERR_OOM;
  }
  char * target = (char *)gcu_allocator_malloc(allocator, (size_t)size + 1u);
  if (!target) {
    return GARC_ERR_OOM;
  }
  size_t have = 0;
  for (;;) {
    size_t got = 0;
    GARC_Result result = garc_read_member(
        archive, target + have, (size_t)size - have + (have == size), &got);
    if (result != GARC_OK) {
      gcu_allocator_free(allocator, target);
      return result;
    }
    if (!got) {
      break;
    }
    have += got;
    if (have > (size_t)size) {
      gcu_allocator_free(allocator, target);
      return GARC_ERR_CORRUPT;
    }
  }
  *out = target;
  *out_length = have;
  return GARC_OK;
}

/**
 * Copy a member whose size its container does not state.
 *
 * A writer puts the size in the header, ahead of the data, so the data is read
 * to its end into a temporary file first - the reader's own caps bound how much
 * that can be - and then written with the size it turned out to have.
 */
static GARC_Result copy_spooled(GARC_Writer * writer, GARC_Archive * archive,
    GARC_Member * member, uint8_t * chunk) {
  GCU_File_Temp temp;
  if (gcu_file_temp_create(&temp, NULL, "garc-copy", writer->allocator)
      != GCU_FILE_OK) {
    return GARC_ERR_IO;
  }
  GCU_File_Handle file = gcu_file_temp_handle(&temp);
  uint64_t total = 0;
  GARC_Result result = GARC_OK;
  for (;;) {
    size_t got = 0;
    result = garc_read_member(archive, chunk, GARC_COPY_CHUNK, &got);
    if (result != GARC_OK || !got) {
      break;
    }
    if (gcu_file_write_bytes(&file, chunk, got) != GCU_FILE_OK) {
      result = GARC_ERR_IO;
      break;
    }
    total += (uint64_t)got;
  }
  if (result == GARC_OK
      && gcu_file_seek(&file, 0, GCU_FILE_SEEK_SET) != GCU_FILE_OK) {
    result = GARC_ERR_IO;
  }
  if (result == GARC_OK) {
    member->size = total;
    member->size_unknown = 0;
    result = garc_writer_add(writer, member);
  }
  while (result == GARC_OK && total) {
    const size_t want
        = total < GARC_COPY_CHUNK ? (size_t)total : (size_t)GARC_COPY_CHUNK;
    size_t got = 0;
    if (gcu_file_read_bytes(&file, chunk, want, &got) != GCU_FILE_OK
        || got != want) {
      // The spool is ours, so a short read is the disk failing: the member's
      // header is out and the writer cannot finish it.
      result = GARC_ERR_IO;
      writer->failed = result;
      break;
    }
    result = garc_writer_write(writer, chunk, got);
    total -= (uint64_t)got;
  }
  gcu_file_temp_abort(&temp);
  return result;
}

GARC_Result garc_writer_copy_member(GARC_Writer * writer,
    GARC_Archive * archive, const GARC_Member * as, uint32_t flags) {
  if (!writer || !archive || (flags & ~GARC_COPY_KNOWN)) {
    return GARC_ERR_INVALID;
  }
  if (writer->failed) {
    return writer->failed;
  }
  if (writer->finished || !archive->have_member || archive->member_touched) {
    return GARC_ERR_INVALID;
  }
  const GARC_Member * source = &archive->member;
  if (as && (as->type != source->type || as->size != source->size)) {
    return GARC_ERR_INVALID;
  }

  if (flags & GARC_COPY_RAW) {
    if (writer->format != GARC_FORMAT_ZIP || archive->format != GARC_FORMAT_ZIP) {
      return GARC_ERR_UNSUPPORTED;
    }
    GARC_Result result = writer_close_member(writer);
    if (result != GARC_OK) {
      return result;
    }
    const uint64_t before = garc_sink_tell(writer->sink);
    result = garc_zip_write_raw(writer, archive, as ? as->name : NULL,
        as ? as->name_length : 0u);
    // A raw copy reads the source by offset, which moves the stream a stored
    // member is read from - so once it has read anything the member is spent.
    // Its refusals (a name, strong encryption, a field too long, memory) come
    // before the first read and leave the member as it was.
    if (result == GARC_OK || garc_sink_tell(writer->sink) != before
        || (result != GARC_ERR_INVALID && result != GARC_ERR_UNSUPPORTED
            && result != GARC_ERR_OOM)) {
      archive->member_touched = 1;
    }
    if (result != GARC_OK) {
      return writer_fail(writer, result, before, 1);
    }
    writer->member_count++;
    return GARC_OK;
  }

  GARC_Member member = as ? *as : *source;
  char * target = NULL;
  uint8_t * chunk = NULL;
  GARC_Result result = GARC_OK;
  if (member.type == GARC_MEMBER_SYMLINK) {
    // A link is written as a target and no data, by every writer.
    if (!member.link_target) {
      size_t length = 0;
      result = copy_read_target(archive, writer->allocator, &target, &length);
      if (result != GARC_OK) {
        return result;
      }
      member.link_target = target;
      member.link_target_length = length;
    }
    member.size = 0;
    result = garc_writer_add(writer, &member);
    gcu_allocator_free(writer->allocator, target);
    return result;
  }
  if (member.type != GARC_MEMBER_FILE) {
    // Directories, hard links, devices and fifos carry no data to move.
    member.size = 0;
    return garc_writer_add(writer, &member);
  }

  chunk = (uint8_t *)gcu_allocator_malloc(writer->allocator, GARC_COPY_CHUNK);
  if (!chunk) {
    return GARC_ERR_OOM;
  }
  if (source->size_unknown) {
    result = copy_spooled(writer, archive, &member, chunk);
    gcu_allocator_free(writer->allocator, chunk);
    return result;
  }
  // The first bytes before the header. A member that cannot be read at all -
  // encrypted with no password, a method with no codec - is refused here, with
  // nothing written, so the caller can skip it and go on.
  size_t got = 0;
  result = garc_read_member(archive, chunk, GARC_COPY_CHUNK, &got);
  if (result == GARC_OK) {
    result = garc_writer_add(writer, &member);
  }
  while (result == GARC_OK && got) {
    result = garc_writer_write(writer, chunk, got);
    if (result != GARC_OK) {
      break;
    }
    result = garc_read_member(archive, chunk, GARC_COPY_CHUNK, &got);
    if (result != GARC_OK && writer->have_member) {
      // The header is out and part of the data with it. The member cannot be
      // finished honestly, so the writer fails with the reader's status.
      writer->failed = result;
    }
  }
  gcu_allocator_free(writer->allocator, chunk);
  return result;
}

uint64_t garc_writer_member_count(const GARC_Writer * writer) {
  return writer ? writer->member_count : 0u;
}

uint64_t garc_writer_data_remaining(const GARC_Writer * writer) {
  return writer ? writer->data_remaining : 0u;
}

void garc_writer_dump(const GARC_Writer * writer, FILE * out) {
  if (!out) {
    return;
  }
  if (!writer) {
    fprintf(out, "GARC_Writer: (null)\n");
    return;
  }
  if (writer->format == GARC_FORMAT_ZIP) {
    fprintf(out, "GARC_Writer: format=zip sizes=%s method=%s%s\n",
        garc_zip_sizes_string(writer->options.zip_sizes),
        garc_zip_method_string(writer->options.zip_method),
        writer->options.zip_force_zip64 ? " zip64=forced" : "");
    fprintf(out, "  directory: %llu entries, %llu bytes\n",
        (unsigned long long)writer->zip.entries,
        (unsigned long long)writer->zip.central.length);
  }
  else if (writer->format == GARC_FORMAT_SEVENZ) {
    fprintf(out, "GARC_Writer: format=7z method=%d%s\n",
        (int)writer->options.sevenz_method,
        writer->options.sevenz_non_solid ? " non-solid" : "");
  }
  else {
    fprintf(out, "GARC_Writer: format=%s variant=%s blocking=%u\n",
        garc_format_string(writer->format),
        garc_tar_variant_string(writer->options.tar_variant),
        (unsigned)writer->options.blocking_factor);
  }
  fprintf(out, "  members=%llu offset=%llu finished=%d\n",
      (unsigned long long)writer->member_count,
      (unsigned long long)garc_sink_tell(writer->sink), writer->finished);
  if (writer->have_member) {
    fprintf(out, "  member open: %llu data bytes owed, %llu padding\n",
        (unsigned long long)writer->data_remaining,
        (unsigned long long)writer->data_padding);
  }
}

void garc_writer_destroy(GARC_Writer * writer) {
  if (!writer) {
    return;
  }
  const GARC_Allocator * allocator = writer->allocator;
  garc_buffer_free(allocator, &writer->records);
  garc_buffer_free(allocator, &writer->sparse_plan);
  // Unconditionally, not behind a format test: the zip state's buffers are NULL
  // for a tar writer and garc_buffer_free() of a NULL buffer is a no-op, so a
  // condition here would be a second place the format lives for no gain.
  garc_zip_write_release(writer);
  garc_sevenz_write_release(writer);
  garc_shar_write_release(writer);
  gcu_allocator_free(allocator, writer);
}
