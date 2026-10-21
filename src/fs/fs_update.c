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
 * Changing an archive file: a rewrite through a temporary file, or an append to
 * an uncompressed tar where it ends. The policy is in fs.h.
 */

#include <ghoti.io/archive/fs.h>

#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/cutil/file.h>

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "fs/fs_internal.h"
#include "reader/reader_internal.h"
#include "sevenz/sevenz_internal.h"
#include "writer/writer_internal.h"

/** Every flag ::garc_fs_update_begin() accepts. */
#define GARC_FS_UPDATE_FLAGS_KNOWN                                             \
  (GARC_FS_IN_PLACE | GARC_FS_NO_SYNC | GARC_FS_NAME_HINT)

/** A tar block. */
#define FS_TAR_BLOCK 512u

/**
 * The most an in-place append keeps of what follows the members, to put back.
 *
 * That is the end marker and the padding to a record, ten kilobytes at tar's
 * own blocking factor of twenty. An archive with more than this after its
 * members has something there this library did not write, and is refused in
 * place rather than held in memory to restore.
 */
#define FS_TAIL_LIMIT ((size_t)1u << 20)

/** What an update holds: the original, the writer, and how to undo an append. */
struct GARC_Fs_Update {
  const GARC_Allocator * allocator; ///< Where this came from.
  GARC_Archive * archive;           ///< The original, for a rewrite.
  GARC_Sink * sink;                 ///< Where the writer writes.
  GARC_Writer * writer;             ///< The writer.
  bool committed;                   ///< Whether commit succeeded.
  bool in_place;                    ///< An append to the original itself.
  bool sync;                        ///< Whether an in-place commit syncs.
  GCU_File_Handle file;             ///< The original, open for update, in place.
  uint64_t end;                     ///< Where its end marker was, in place.
  uint64_t length;                  ///< Its length before the append, in place.
  uint8_t * tail;                   ///< Its bytes from @ref end to @ref length.
  /**
   * The same bytes, for a zip, in a temporary file: a zip's tail is its whole
   * central directory, which can be far larger than a tar's end marker.
   */
  GCU_File_Temp tail_file;
  bool tail_in_file;                ///< Whether @ref tail_file holds the tail.
  /** Where the archive's own offsets count from: a zip's or a 7z's stub, or 0. */
  uint64_t origin;
  /**
   * A 7z's start header before the append, which the writer rewrites: put
   * back with the tail when the append is abandoned.
   */
  uint8_t start[GARC_SEVENZ_START_SIZE];
  bool start_saved;                 ///< Whether @ref start holds it.
  bool touched;                     ///< Whether the append has written a byte.
};

////////////////////////////////////////////////////////////////////////
// The sink an in-place append writes through
////////////////////////////////////////////////////////////////////////

static GARC_Result update_write(void * ctx, const void * buffer, size_t size) {
  GARC_Fs_Update * update = (GARC_Fs_Update *)ctx;
  update->touched = true;
  return gcu_file_write_bytes(&update->file, buffer, size) == GCU_FILE_OK
      ? GARC_OK
      : GARC_ERR_IO;
}

static GARC_Result update_patch(
    void * ctx, uint64_t offset, const void * buffer, size_t size) {
  GARC_Fs_Update * update = (GARC_Fs_Update *)ctx;
  int64_t here = 0;
  // The writer's offsets are the archive's; the file's are past any stub.
  offset += update->origin;
  if (offset > (uint64_t)INT64_MAX
      || gcu_file_tell(&update->file, &here) != GCU_FILE_OK
      || gcu_file_seek(&update->file, (int64_t)offset, GCU_FILE_SEEK_SET)
          != GCU_FILE_OK
      || gcu_file_write_bytes(&update->file, buffer, size) != GCU_FILE_OK
      || gcu_file_seek(&update->file, here, GCU_FILE_SEEK_SET) != GCU_FILE_OK) {
    return GARC_ERR_IO;
  }
  return GARC_OK;
}

/**
 * Walk an uncompressed tar to where its members end.
 *
 * The end is after the last member's stored data, rounded up to a block, which
 * is where the end marker starts. Taken from the members rather than from where
 * the reader stopped, because the reader may have read one zero block or two,
 * and an archive with no members ends where it starts.
 */
static GARC_Result update_find_end(const char * path,
    const GARC_Limits * limits, const GARC_Allocator * allocator,
    uint64_t * out_end) {
  GARC_Stream * stream = NULL;
  GARC_Result result = garc_fs_stream_open_with_allocator(path, allocator, &stream);
  if (result != GARC_OK) {
    return result;
  }
  GARC_Archive * archive = NULL;
  result = garc_open_with_allocator(stream, limits, allocator, &archive);
  if (result == GARC_OK && garc_format(archive) != GARC_FORMAT_TAR) {
    result = GARC_ERR_UNSUPPORTED;
  }
  uint64_t end = 0;
  const GARC_Member * member = NULL;
  while (result == GARC_OK && (result = garc_next(archive, &member)) == GARC_OK) {
    const uint64_t stored = member->stored_size;
    const uint64_t blocks = stored / FS_TAR_BLOCK + (stored % FS_TAR_BLOCK != 0u);
    end = member->data_offset + blocks * FS_TAR_BLOCK;
  }
  // A pax global header applies to every member after it - the appended ones
  // too - so a `g` setting an mtime or a charset would change what the new
  // members say. A rewrite has no such problem; this refuses and says so.
  const int has_global
      = result == GARC_END && archive->tar.pax_global.records.length != 0;
  garc_close(archive);
  garc_stream_destroy(stream);
  if (has_global) {
    return GARC_ERR_UNSUPPORTED;
  }
  if (result != GARC_END) {
    // GARC_ERR_FORMAT here is a compressed tar or not a tar: only an
    // uncompressed one can be appended to where it lies.
    return result == GARC_ERR_FORMAT ? GARC_ERR_UNSUPPORTED : result;
  }
  *out_end = end;
  return GARC_OK;
}

/**
 * A zip's directory, for an append where it lies: where it starts (which is
 * where new members go), where the archive's offsets count from, and its
 * entries, which the writer keeps.
 */
static GARC_Result update_find_zip(const char * path, const GARC_Limits * limits,
    const GARC_Allocator * allocator, uint64_t * out_end, uint64_t * out_origin,
    uint8_t ** out_directory, size_t * out_length, uint64_t * out_count) {
  GARC_Stream * stream = NULL;
  GARC_Result result = garc_fs_stream_open_with_allocator(path, allocator, &stream);
  if (result != GARC_OK) {
    return result;
  }
  GARC_Archive * archive = NULL;
  result = garc_open_with_allocator(stream, limits, allocator, &archive);
  if (result == GARC_OK && (garc_format(archive) != GARC_FORMAT_ZIP
          || archive->zip.multi_disk)) {
    // A split zip's new members would go in its last volume, with every disk
    // field to account for; that is a rewrite's job.
    result = GARC_ERR_UNSUPPORTED;
  }
  uint8_t * directory = NULL;
  size_t length = 0;
  if (result == GARC_OK) {
    if (archive->zip.central_size > (uint64_t)SIZE_MAX) {
      result = GARC_ERR_UNSUPPORTED;
    }
    else {
      length = (size_t)archive->zip.central_size;
      directory = (uint8_t *)gcu_allocator_malloc(allocator, length ? length : 1u);
      result = directory ? garc_stream_seek(stream, archive->zip.central_offset)
                         : GARC_ERR_OOM;
    }
  }
  if (result == GARC_OK && length) {
    result = garc_stream_read_exact(stream, directory, length);
  }
  if (result == GARC_OK) {
    *out_end = archive->zip.central_offset;
    *out_origin = archive->zip.origin;
    *out_count = archive->zip.declared_members;
    *out_directory = directory;
    *out_length = length;
    directory = NULL;
  }
  gcu_allocator_free(allocator, directory);
  garc_close(archive);
  garc_stream_destroy(stream);
  return result;
}

/** The format of the archive at @p path, opened only to ask. */
static GARC_Result update_format(const char * path, const GARC_Limits * limits,
    const GARC_Allocator * allocator, GARC_Format * out_format) {
  GARC_Stream * stream = NULL;
  GARC_Result result = garc_fs_stream_open_with_allocator(path, allocator, &stream);
  if (result != GARC_OK) {
    return result;
  }
  GARC_Archive * archive = NULL;
  result = garc_open_with_allocator(stream, limits, allocator, &archive);
  if (result == GARC_OK) {
    *out_format = garc_format(archive);
  }
  garc_close(archive);
  garc_stream_destroy(stream);
  // Not an archive this reads, uncompressed: nothing to append to in place.
  return result == GARC_ERR_FORMAT ? GARC_ERR_UNSUPPORTED : result;
}

/** Copy the file's bytes from @p from to its end into a temporary. */
static GARC_Result update_save_tail(GARC_Fs_Update * update, uint64_t from) {
  GARC_Result result = garc_fs_from_file(gcu_file_temp_create(
      &update->tail_file, NULL, "garc-tail", update->allocator));
  if (result != GARC_OK) {
    return result;
  }
  update->tail_in_file = true;
  GCU_File_Handle saved = gcu_file_temp_handle(&update->tail_file);
  if (from > (uint64_t)INT64_MAX
      || gcu_file_seek(&update->file, (int64_t)from, GCU_FILE_SEEK_SET)
          != GCU_FILE_OK) {
    return GARC_ERR_IO;
  }
  uint8_t chunk[16384];
  uint64_t left = update->length - from;
  while (left) {
    const size_t want = left < sizeof(chunk) ? (size_t)left : sizeof(chunk);
    size_t got = 0;
    if (gcu_file_read_bytes(&update->file, chunk, want, &got) != GCU_FILE_OK
        || got != want
        || gcu_file_write_bytes(&saved, chunk, got) != GCU_FILE_OK) {
      return GARC_ERR_IO;
    }
    left -= (uint64_t)got;
  }
  return garc_fs_from_file(gcu_file_flush(&saved));
}

/** Write the saved tail back at @p to, and cut the file to its old length. */
static void update_restore_tail(GARC_Fs_Update * update, uint64_t to) {
  GCU_File_Handle saved = gcu_file_temp_handle(&update->tail_file);
  if (gcu_file_seek(&saved, 0, GCU_FILE_SEEK_SET) != GCU_FILE_OK
      || to > (uint64_t)INT64_MAX
      || gcu_file_seek(&update->file, (int64_t)to, GCU_FILE_SEEK_SET)
          != GCU_FILE_OK) {
    return;
  }
  uint8_t chunk[16384];
  uint64_t left = update->length - to;
  while (left) {
    const size_t want = left < sizeof(chunk) ? (size_t)left : sizeof(chunk);
    size_t got = 0;
    if (gcu_file_read_bytes(&saved, chunk, want, &got) != GCU_FILE_OK
        || got != want
        || gcu_file_write_bytes(&update->file, chunk, got) != GCU_FILE_OK) {
      return;
    }
    left -= (uint64_t)got;
  }
  (void)gcu_file_truncate(&update->file, update->length);
}

/**
 * Append to a zip where it lies: the new members go where its directory was,
 * and the writer, which has the old directory's entries, writes them and the
 * new ones' after the new members, then the end records.
 */
static GARC_Result update_begin_zip(GARC_Fs_Update * update, const char * path,
    const GARC_Limits * limits, const GARC_Writer_Options * options) {
  if (options && options->zip_volume_size) {
    return GARC_ERR_INVALID; // a split set is not appended to where it lies
  }
  uint8_t * directory = NULL;
  size_t length = 0;
  uint64_t count = 0;
  GARC_Result result = update_find_zip(path, limits, update->allocator,
      &update->end, &update->origin, &directory, &length, &count);
  if (result != GARC_OK) {
    return result;
  }
  result = garc_fs_from_file(gcu_file_open(&update->file, path,
      GCU_FILE_OPEN_UPDATE, GCU_FILE_PERMS_PRESERVE, update->allocator));
  int64_t file_length = 0;
  if (result == GARC_OK
      && (gcu_file_seek(&update->file, 0, GCU_FILE_SEEK_END) != GCU_FILE_OK
          || gcu_file_tell(&update->file, &file_length) != GCU_FILE_OK
          || (uint64_t)file_length < update->end)) {
    result = GARC_ERR_IO;
  }
  if (result == GARC_OK) {
    update->length = (uint64_t)file_length;
    result = update_save_tail(update, update->end);
  }
  if (result == GARC_OK
      && gcu_file_seek(&update->file, (int64_t)update->end, GCU_FILE_SEEK_SET)
          != GCU_FILE_OK) {
    result = GARC_ERR_IO;
  }
  if (result == GARC_OK) {
    GARC_Sink_Callbacks callbacks;
    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.write = update_write;
    callbacks.patch = update_patch;
    callbacks.ctx = update;
    // In the archive's own frame, so the new members' offsets agree with the
    // old ones' when there is a stub in front.
    callbacks.start = update->end - update->origin;
    result = garc_sink_create_callback_with_allocator(
        &callbacks, update->allocator, &update->sink);
  }
  if (result == GARC_OK) {
    result = garc_writer_create_with_allocator(update->sink, GARC_FORMAT_ZIP,
        options, update->allocator, &update->writer);
  }
  if (result == GARC_OK) {
    result = garc_zip_write_adopt_directory(update->writer, directory, length, count);
  }
  gcu_allocator_free(update->allocator, directory);
  return result;
}

/**
 * Append to a 7z where it lies: the new folders go where its packed streams
 * end - over its header, which the tail keeps - and the writer, which has the
 * old header's tables, writes them and the new ones in a new header, then the
 * start header that points at it.
 */
static GARC_Result update_begin_sevenz(GARC_Fs_Update * update, const char * path,
    const GARC_Limits * limits, const GARC_Writer_Options * options) {
  GARC_Stream * stream = NULL;
  GARC_Result result = garc_fs_stream_open_with_allocator(
      path, update->allocator, &stream);
  if (result != GARC_OK) {
    return result;
  }
  GARC_Archive * archive = NULL;
  GARC_SevenZ_Carry * carry = NULL;
  result = garc_open_with_allocator(stream, limits, update->allocator, &archive);
  if (result == GARC_OK) {
    update->origin = garc_base_offset(archive);
    result = garc_sevenz_carry(archive, update->allocator, &carry);
  }
  // Closed before the file is opened to be written, which Windows wants.
  garc_close(archive);
  garc_stream_destroy(stream);
  if (result != GARC_OK) {
    return result;
  }
  const uint64_t data = GARC_SEVENZ_START_SIZE + carry->data_end;
  update->end = update->origin + data;
  result = garc_fs_from_file(gcu_file_open(&update->file, path,
      GCU_FILE_OPEN_UPDATE, GCU_FILE_PERMS_PRESERVE, update->allocator));
  int64_t file_length = 0;
  size_t got = 0;
  if (result == GARC_OK
      && (update->end > (uint64_t)INT64_MAX
          || gcu_file_seek(&update->file, 0, GCU_FILE_SEEK_END) != GCU_FILE_OK
          || gcu_file_tell(&update->file, &file_length) != GCU_FILE_OK
          || (uint64_t)file_length < update->end
          || gcu_file_seek(&update->file, (int64_t)update->origin, GCU_FILE_SEEK_SET)
              != GCU_FILE_OK
          || gcu_file_read_bytes(&update->file, update->start, sizeof(update->start),
                 &got) != GCU_FILE_OK
          || got != sizeof(update->start))) {
    result = GARC_ERR_IO;
  }
  if (result == GARC_OK) {
    update->start_saved = true;
    update->length = (uint64_t)file_length;
    result = update_save_tail(update, update->end);
  }
  if (result == GARC_OK
      && gcu_file_seek(&update->file, (int64_t)update->end, GCU_FILE_SEEK_SET)
          != GCU_FILE_OK) {
    result = GARC_ERR_IO;
  }
  if (result == GARC_OK) {
    GARC_Sink_Callbacks callbacks;
    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.write = update_write;
    callbacks.patch = update_patch;
    callbacks.ctx = update;
    // In the archive's own frame, past any stub, as the start header counts.
    callbacks.start = data;
    result = garc_sink_create_callback_with_allocator(
        &callbacks, update->allocator, &update->sink);
  }
  if (result != GARC_OK) {
    garc_sevenz_carry_free(carry, update->allocator);
    return result;
  }
  return garc_writer_create_sevenz_append(
      update->sink, options, update->allocator, carry, &update->writer);
}

static GARC_Result update_begin_in_place(GARC_Fs_Update * update,
    const char * path, const GARC_Limits * limits,
    const GARC_Writer_Options * options) {
  GARC_Format format = GARC_FORMAT_TAR;
  GARC_Result result = update_format(path, limits, update->allocator, &format);
  if (result != GARC_OK) {
    return result;
  }
  if (format == GARC_FORMAT_ZIP) {
    return update_begin_zip(update, path, limits, options);
  }
  if (format == GARC_FORMAT_SEVENZ) {
    return update_begin_sevenz(update, path, limits, options);
  }
  result = update_find_end(path, limits, update->allocator, &update->end);
  if (result != GARC_OK) {
    return result;
  }
  result = garc_fs_from_file(gcu_file_open(&update->file, path,
      GCU_FILE_OPEN_UPDATE, GCU_FILE_PERMS_PRESERVE, update->allocator));
  if (result != GARC_OK) {
    return result;
  }
  // What follows the members - the end marker and its padding - kept, so that
  // an abandoned append can put the file back exactly as it was.
  int64_t length = 0;
  if (update->end > (uint64_t)INT64_MAX
      || gcu_file_seek(&update->file, 0, GCU_FILE_SEEK_END) != GCU_FILE_OK
      || gcu_file_tell(&update->file, &length) != GCU_FILE_OK
      || (uint64_t)length < update->end) {
    return GARC_ERR_IO;
  }
  update->length = (uint64_t)length;
  const uint64_t tail = update->length - update->end;
  if (tail > (uint64_t)FS_TAIL_LIMIT) {
    return GARC_ERR_UNSUPPORTED;
  }
  update->tail = (uint8_t *)gcu_allocator_malloc(
      update->allocator, tail ? (size_t)tail : 1u);
  if (!update->tail) {
    return GARC_ERR_OOM;
  }
  size_t got = 0;
  if (gcu_file_seek(&update->file, (int64_t)update->end, GCU_FILE_SEEK_SET)
          != GCU_FILE_OK
      || gcu_file_read_bytes(&update->file, update->tail, (size_t)tail, &got)
          != GCU_FILE_OK
      || got != (size_t)tail
      || gcu_file_seek(&update->file, (int64_t)update->end, GCU_FILE_SEEK_SET)
          != GCU_FILE_OK) {
    return GARC_ERR_IO;
  }
  GARC_Sink_Callbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.write = update_write;
  callbacks.patch = update_patch;
  callbacks.ctx = update;
  callbacks.start = update->end;
  result = garc_sink_create_callback_with_allocator(
      &callbacks, update->allocator, &update->sink);
  if (result != GARC_OK) {
    return result;
  }
  return garc_writer_create_with_allocator(update->sink, GARC_FORMAT_TAR,
      options, update->allocator, &update->writer);
}

static GARC_Result update_begin_rewrite(GARC_Fs_Update * update,
    const char * path, const GARC_Limits * limits,
    const GARC_Writer_Options * options, uint32_t flags) {
  const char * method = NULL;
  GARC_Result result = garc_fs_open_detecting(path, limits, NULL,
      flags & GARC_FS_NAME_HINT, update->allocator, &update->archive, &method);
  if (result != GARC_OK) {
    return result;
  }
  const GARC_Format format = garc_format(update->archive);
  result = garc_fs_sink_create_with_allocator(path, method, NULL,
      flags & GARC_FS_NO_SYNC, update->allocator, &update->sink);
  if (result != GARC_OK) {
    return result;
  }
  return garc_writer_create_with_allocator(
      update->sink, format, options, update->allocator, &update->writer);
}

GARC_Result garc_fs_update_begin_with_allocator(const char * path,
    const GARC_Limits * limits, const GARC_Writer_Options * options,
    uint32_t flags, const GARC_Allocator * allocator,
    GARC_Fs_Update ** out_update) {
  if (!path || !out_update || (flags & ~GARC_FS_UPDATE_FLAGS_KNOWN)) {
    return GARC_ERR_INVALID;
  }
  if (!allocator) {
    allocator = garc_allocator_default();
  }
  GARC_Fs_Update * update = (GARC_Fs_Update *)gcu_allocator_calloc(
      allocator, 1, sizeof(GARC_Fs_Update));
  if (!update) {
    return GARC_ERR_OOM;
  }
  update->allocator = allocator;
  update->in_place = (flags & GARC_FS_IN_PLACE) != 0;
  update->sync = (flags & GARC_FS_NO_SYNC) == 0;
  GARC_Result result = update->in_place
      ? update_begin_in_place(update, path, limits, options)
      : update_begin_rewrite(update, path, limits, options, flags);
  if (result != GARC_OK) {
    // Nothing has been written to the original yet, so there is nothing to put
    // back: the destroy only releases.
    garc_fs_update_destroy(update);
    return result;
  }
  *out_update = update;
  return GARC_OK;
}

GARC_Result garc_fs_update_begin(const char * path, const GARC_Limits * limits,
    const GARC_Writer_Options * options, uint32_t flags,
    GARC_Fs_Update ** out_update) {
  return garc_fs_update_begin_with_allocator(
      path, limits, options, flags, NULL, out_update);
}

GARC_Archive * garc_fs_update_archive(GARC_Fs_Update * update) {
  return update ? update->archive : NULL;
}

GARC_Writer * garc_fs_update_writer(GARC_Fs_Update * update) {
  return update ? update->writer : NULL;
}

GARC_Result garc_fs_update_keep(GARC_Fs_Update * update) {
  if (!update || !update->archive || update->committed) {
    return GARC_ERR_INVALID;
  }
  const uint32_t flags = garc_format(update->archive) == GARC_FORMAT_ZIP
      ? GARC_COPY_RAW : 0u;
  // A 7z member is decoded and written again, and this writer does not
  // encrypt: keeping an encrypted one would write it back in the clear, and
  // keeping anything from behind an encrypted header would publish its name.
  if (garc_format(update->archive) == GARC_FORMAT_SEVENZ
      && garc_sevenz_member_encrypted(update->archive)) {
    return GARC_ERR_UNSUPPORTED;
  }
  return garc_writer_copy_member(update->writer, update->archive, NULL, flags);
}

GARC_Result garc_fs_update_keep_rest(GARC_Fs_Update * update) {
  if (!update || !update->archive || update->committed) {
    return GARC_ERR_INVALID;
  }
  const GARC_Member * member = NULL;
  GARC_Result result;
  while ((result = garc_next(update->archive, &member)) == GARC_OK) {
    result = garc_fs_update_keep(update);
    if (result != GARC_OK) {
      return result;
    }
  }
  return result == GARC_END ? GARC_OK : result;
}

GARC_Result garc_fs_update_commit(GARC_Fs_Update * update) {
  if (!update || update->committed) {
    return GARC_ERR_INVALID;
  }
  GARC_Result result = garc_writer_finish(update->writer);
  if (result != GARC_OK) {
    return result;
  }
  if (update->in_place && update->start_saved) {
    // A 7z's start header, which now points at the new header: written last,
    // as the writer patches it last in a new archive. Abandoned before here,
    // the tail and the old start header both go back (garc_fs_update_destroy).
    uint8_t start[GARC_SEVENZ_START_SIZE];
    int64_t here = 0;
    result = garc_sevenz_write_start_header(update->writer, start);
    if (result == GARC_OK
        && (gcu_file_tell(&update->file, &here) != GCU_FILE_OK
            || update->origin > (uint64_t)INT64_MAX
            || gcu_file_seek(&update->file, (int64_t)update->origin,
                   GCU_FILE_SEEK_SET) != GCU_FILE_OK
            || gcu_file_write_bytes(&update->file, start, sizeof(start))
                != GCU_FILE_OK
            || gcu_file_seek(&update->file, here, GCU_FILE_SEEK_SET)
                != GCU_FILE_OK)) {
      result = GARC_ERR_IO;
    }
    if (result != GARC_OK) {
      return result;
    }
  }
  if (update->in_place) {
    // The archive now ends where the writer stopped; what the old one had past
    // that - a zip's longer directory or comment, padding - would read as more.
    int64_t here = 0;
    result = garc_fs_from_file(gcu_file_tell(&update->file, &here));
    if (result == GARC_OK) {
      result = garc_fs_from_file(gcu_file_truncate(&update->file, (uint64_t)here));
    }
    if (result == GARC_OK) {
      result = garc_fs_from_file(update->sync ? gcu_file_sync(&update->file)
                                              : gcu_file_flush(&update->file));
    }
    if (result == GARC_OK) {
      result = garc_fs_from_file(gcu_file_close(&update->file));
    }
    if (result == GARC_OK) {
      update->committed = true;
    }
    return result;
  }
  // The original is closed before the rename, which Windows will not do over
  // a file that is still open.
  garc_close(update->archive);
  update->archive = NULL;
  result = garc_sink_finish(update->sink);
  if (result == GARC_OK) {
    update->committed = true;
  }
  return result;
}

void garc_fs_update_destroy(GARC_Fs_Update * update) {
  if (!update) {
    return;
  }
  garc_writer_destroy(update->writer);
  garc_close(update->archive);
  if (update->in_place && !update->committed && update->file.stream
      && update->tail_in_file && update->touched) {
    update_restore_tail(update, update->end);
    if (update->start_saved && update->origin <= (uint64_t)INT64_MAX
        && gcu_file_seek(&update->file, (int64_t)update->origin, GCU_FILE_SEEK_SET)
            == GCU_FILE_OK) {
      (void)gcu_file_write_bytes(&update->file, update->start, sizeof(update->start));
    }
  }
  if (update->in_place && !update->committed && update->file.stream
      && update->tail && update->sink
      && garc_sink_tell(update->sink) != update->end) {
    // Abandoned after writing: the bytes that followed the members go back,
    // and the file is cut to its old length, so it is the file it was. Writing
    // only an end marker is not enough - a header after a marker means the
    // marker was data, to this reader and to GNU tar's --ignore-zeros alike.
    if (gcu_file_seek(&update->file, (int64_t)update->end, GCU_FILE_SEEK_SET)
        == GCU_FILE_OK) {
      (void)gcu_file_write_bytes(&update->file, update->tail,
          (size_t)(update->length - update->end));
      (void)gcu_file_truncate(&update->file, update->length);
    }
  }
  (void)gcu_file_close(&update->file);
  // For a rewrite this removes the temporary unless it was renamed into place.
  garc_sink_destroy(update->sink);
  gcu_allocator_free(update->allocator, update->tail);
  if (update->tail_in_file) {
    gcu_file_temp_abort(&update->tail_file);
  }
  gcu_allocator_free(update->allocator, update);
}
