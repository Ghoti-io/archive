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
 * Files as streams and sinks, and opening an archive by path. The policy is in
 * fs.h. Everything here goes through cutil's file handle, which is what makes
 * paths UTF-8 and offsets 64-bit on Windows as well.
 */

#include <ghoti.io/archive/fs.h>

#include <ghoti.io/compress/compress.h>
#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/cutil/file.h>
#include <ghoti.io/cutil/path.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "fs/fs_internal.h"
#include "reader/reader_internal.h"
#include "sink/sink_internal.h"
#include "stream/stream_internal.h"

/** Every flag ::garc_fs_sink_create() accepts. */
#define GARC_FS_SINK_FLAGS_KNOWN (GARC_FS_NO_SYNC)

/** Every flag ::garc_fs_open() accepts. */
#define GARC_FS_OPEN_FLAGS_KNOWN (GARC_FS_NAME_HINT)

/**
 * How many bytes `gcomp_detect()` is shown.
 *
 * It wants six for xz and steps over zstd skippable frames, whose size is
 * declared. A file that opens with more skippable frame than this is not
 * detected, which is the honest outcome for a tar nobody would write that way.
 */
#define GARC_FS_SNIFF_BYTES 64u

////////////////////////////////////////////////////////////////////////
// The file stream
////////////////////////////////////////////////////////////////////////

/** What a file stream owns. */
typedef struct FsFileStream {
  GCU_File_Handle file;             ///< The open file.
  uint64_t size;                    ///< Its length when it was opened.
  const GARC_Allocator * allocator; ///< Where this struct came from.
} FsFileStream;

static GARC_Result fs_stream_read(
    void * ctx, void * buffer, size_t size, size_t * out_read) {
  FsFileStream * state = (FsFileStream *)ctx;
  return garc_fs_from_file(
      gcu_file_read_bytes(&state->file, buffer, size, out_read));
}

static GARC_Result fs_stream_seek(void * ctx, uint64_t offset) {
  FsFileStream * state = (FsFileStream *)ctx;
  if (offset > (uint64_t)INT64_MAX) {
    return GARC_ERR_IO;
  }
  GCU_File_Result result
      = gcu_file_seek(&state->file, (int64_t)offset, GCU_FILE_SEEK_SET);
  return result == GCU_FILE_OK ? GARC_OK : GARC_ERR_IO;
}

static GARC_Result fs_stream_size(void * ctx, uint64_t * out_size) {
  *out_size = ((FsFileStream *)ctx)->size;
  return GARC_OK;
}

static void fs_stream_destroy(GARC_Stream * stream) {
  FsFileStream * state = (FsFileStream *)stream->cb.ctx;
  // A read-only close has nothing buffered to lose, so its status says nothing.
  (void)gcu_file_close(&state->file);
  gcu_allocator_free(state->allocator, state);
}

GARC_Result garc_fs_stream_open_with_allocator(const char * path,
    const GARC_Allocator * allocator, GARC_Stream ** out_stream) {
  if (!path || !out_stream) {
    return GARC_ERR_INVALID;
  }
  if (!allocator) {
    allocator = garc_allocator_default();
  }
  // fopen() of a directory succeeds on glibc and the first read fails, which
  // would arrive as an I/O error on a call that was simply given the wrong path.
  if (gcu_file_is_directory(path)) {
    return GARC_ERR_INVALID;
  }

  FsFileStream * state = (FsFileStream *)gcu_allocator_calloc(
      allocator, 1, sizeof(FsFileStream));
  if (!state) {
    return GARC_ERR_OOM;
  }
  state->allocator = allocator;
  GARC_Result result = garc_fs_from_file(gcu_file_open(&state->file, path,
      GCU_FILE_OPEN_READ, GCU_FILE_PERMS_DEFAULT, allocator));
  if (result != GARC_OK) {
    gcu_allocator_free(allocator, state);
    return result;
  }

  // The size is the handle's, not a stat of the path: the path could name a
  // different file by now, and the handle cannot.
  int64_t end = 0;
  if (gcu_file_seek(&state->file, 0, GCU_FILE_SEEK_END) != GCU_FILE_OK
      || gcu_file_tell(&state->file, &end) != GCU_FILE_OK || end < 0
      || gcu_file_seek(&state->file, 0, GCU_FILE_SEEK_SET) != GCU_FILE_OK) {
    (void)gcu_file_close(&state->file);
    gcu_allocator_free(allocator, state);
    return GARC_ERR_IO;
  }
  state->size = (uint64_t)end;

  GARC_Stream_Callbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.ctx = state;
  callbacks.read = fs_stream_read;
  callbacks.seek = fs_stream_seek;
  callbacks.size = fs_stream_size;

  GARC_Stream * stream = NULL;
  result = garc_stream_create_callback_with_allocator(
      &callbacks, allocator, &stream);
  if (result != GARC_OK) {
    (void)gcu_file_close(&state->file);
    gcu_allocator_free(allocator, state);
    return result;
  }
  stream->owned_destroy = fs_stream_destroy;
  *out_stream = stream;
  return GARC_OK;
}

GARC_Result garc_fs_stream_open(const char * path, GARC_Stream ** out_stream) {
  return garc_fs_stream_open_with_allocator(path, NULL, out_stream);
}

////////////////////////////////////////////////////////////////////////
// The file sink
////////////////////////////////////////////////////////////////////////

/** What a file sink owns. */
typedef struct FsFileSink {
  GCU_File_Temp temp;               ///< The temporary file, until committed.
  char * dest;                      ///< Where it goes on finish. Owned.
  GCU_File_Sync sync;               ///< How hard the commit tries.
  bool done;                        ///< Committed, or failed to; spent either way.
  const GARC_Allocator * allocator; ///< Where this struct and @ref dest came from.
} FsFileSink;

static GARC_Result fs_sink_write(void * ctx, const void * buffer, size_t size) {
  FsFileSink * state = (FsFileSink *)ctx;
  if (state->done) {
    return GARC_ERR_INVALID;
  }
  GCU_File_Handle file = gcu_file_temp_handle(&state->temp);
  return gcu_file_write_bytes(&file, buffer, size) == GCU_FILE_OK
      ? GARC_OK
      : GARC_ERR_IO;
}

static GARC_Result fs_sink_patch(
    void * ctx, uint64_t offset, const void * buffer, size_t size) {
  FsFileSink * state = (FsFileSink *)ctx;
  if (state->done) {
    return GARC_ERR_INVALID;
  }
  if (offset > (uint64_t)INT64_MAX) {
    return GARC_ERR_IO;
  }
  // The sink checks the range is inside what was written, so the position to
  // come back to is always the end.
  GCU_File_Handle file = gcu_file_temp_handle(&state->temp);
  if (gcu_file_seek(&file, (int64_t)offset, GCU_FILE_SEEK_SET) != GCU_FILE_OK
      || gcu_file_write_bytes(&file, buffer, size) != GCU_FILE_OK
      || gcu_file_seek(&file, 0, GCU_FILE_SEEK_END) != GCU_FILE_OK) {
    return GARC_ERR_IO;
  }
  return GARC_OK;
}

static GARC_Result fs_sink_finish(GARC_Sink * sink) {
  FsFileSink * state = (FsFileSink *)sink->cb.ctx;
  if (state->done) {
    return GARC_ERR_INVALID;
  }
  state->done = true;
  // On failure the temporary is removed and the destination is as it was.
  GCU_File_Result result = gcu_file_temp_commit(
      &state->temp, state->dest, state->sync, GCU_FILE_PERMS_PRESERVE);
  if (result == GCU_FILE_OK) {
    return GARC_OK;
  }
  return result == GCU_FILE_ERR_ACCESS ? GARC_ERR_ACCESS : GARC_ERR_IO;
}

static void fs_sink_destroy(GARC_Sink * sink) {
  FsFileSink * state = (FsFileSink *)sink->cb.ctx;
  // Accepts a temporary already committed, so this is unconditional.
  gcu_file_temp_abort(&state->temp);
  gcu_allocator_free(state->allocator, state->dest);
  gcu_allocator_free(state->allocator, state);
}

/** Copy a NUL-terminated string through @p allocator, or NULL. */
static char * fs_file_dup(const GARC_Allocator * allocator, const char * text) {
  size_t length = strlen(text);
  char * copy = (char *)gcu_allocator_malloc(allocator, length + 1u);
  if (copy) {
    memcpy(copy, text, length + 1u);
  }
  return copy;
}

/** The uncompressed file sink, which can patch. */
static GARC_Result fs_plain_sink_create(const char * path, uint32_t flags,
    const GARC_Allocator * allocator, GARC_Sink ** out_sink) {
  // The temporary goes beside the destination, because a rename is atomic only
  // within one filesystem.
  size_t need = 0;
  if (gcu_path_dirname(GCU_PATH_NATIVE, path, NULL, 0, &need) != GCU_PATH_OK) {
    return GARC_ERR_INVALID;
  }
  char * dir = (char *)gcu_allocator_malloc(allocator, need + 1u);
  if (!dir) {
    return GARC_ERR_OOM;
  }
  if (gcu_path_dirname(GCU_PATH_NATIVE, path, dir, need + 1u, NULL)
      != GCU_PATH_OK) {
    gcu_allocator_free(allocator, dir);
    return GARC_ERR_INVALID;
  }
  if (!gcu_file_is_directory(dir)) {
    gcu_allocator_free(allocator, dir);
    return GARC_ERR_NOT_FOUND;
  }
  if (gcu_file_is_directory(path)) {
    gcu_allocator_free(allocator, dir);
    return GARC_ERR_INVALID;
  }

  FsFileSink * state = (FsFileSink *)gcu_allocator_calloc(
      allocator, 1, sizeof(FsFileSink));
  if (!state) {
    gcu_allocator_free(allocator, dir);
    return GARC_ERR_OOM;
  }
  state->allocator = allocator;
  state->sync
      = (flags & GARC_FS_NO_SYNC) ? GCU_FILE_SYNC_NONE : GCU_FILE_SYNC_FULL;
  state->dest = fs_file_dup(allocator, path);
  if (!state->dest) {
    gcu_allocator_free(allocator, dir);
    gcu_allocator_free(allocator, state);
    return GARC_ERR_OOM;
  }
  GARC_Result result = garc_fs_from_file(
      gcu_file_temp_create(&state->temp, dir, ".garc-", allocator));
  gcu_allocator_free(allocator, dir);
  if (result != GARC_OK) {
    gcu_allocator_free(allocator, state->dest);
    gcu_allocator_free(allocator, state);
    return result;
  }

  GARC_Sink_Callbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.ctx = state;
  callbacks.write = fs_sink_write;
  callbacks.patch = fs_sink_patch;

  GARC_Sink * sink = NULL;
  result = garc_sink_create_callback_with_allocator(
      &callbacks, allocator, &sink);
  if (result != GARC_OK) {
    gcu_file_temp_abort(&state->temp);
    gcu_allocator_free(allocator, state->dest);
    gcu_allocator_free(allocator, state);
    return result;
  }
  sink->owned_finish = fs_sink_finish;
  sink->owned_destroy = fs_sink_destroy;
  *out_sink = sink;
  return GARC_OK;
}

/**
 * A compressing sink over a file sink, owning both.
 *
 * The codec sink borrows what it writes to, like every wrapper here, so this is
 * the one place that holds the pair and ends them in order: the codec's trailer
 * first, then the rename.
 */
typedef struct FsChainSink {
  GARC_Sink * codec;                ///< The compressing sink. Owned.
  GARC_Sink * file;                 ///< The file sink under it. Owned.
  const GARC_Allocator * allocator; ///< Where this struct came from.
} FsChainSink;

static GARC_Result fs_chain_write(void * ctx, const void * buffer, size_t size) {
  return garc_sink_write(((FsChainSink *)ctx)->codec, buffer, size);
}

static GARC_Result fs_chain_finish(GARC_Sink * sink) {
  FsChainSink * state = (FsChainSink *)sink->cb.ctx;
  GARC_Result result = garc_sink_finish(state->codec);
  if (result != GARC_OK) {
    // The file is not renamed into place: half a codec stream is not an
    // archive, and the destination should keep whatever it held.
    return result;
  }
  return garc_sink_finish(state->file);
}

static void fs_chain_destroy(GARC_Sink * sink) {
  FsChainSink * state = (FsChainSink *)sink->cb.ctx;
  garc_sink_destroy(state->codec);
  garc_sink_destroy(state->file);
  gcu_allocator_free(state->allocator, state);
}

GARC_Result garc_fs_sink_create_with_allocator(const char * path,
    const char * method, gcomp_options_t * options, uint32_t flags,
    const GARC_Allocator * allocator, GARC_Sink ** out_sink) {
  if (!path || !*path || !out_sink || (flags & ~GARC_FS_SINK_FLAGS_KNOWN)) {
    return GARC_ERR_INVALID;
  }
  if (!allocator) {
    allocator = garc_allocator_default();
  }

  GARC_Sink * file = NULL;
  GARC_Result result = fs_plain_sink_create(path, flags, allocator, &file);
  if (result != GARC_OK || !method) {
    if (result == GARC_OK) {
      *out_sink = file;
    }
    return result;
  }

  FsChainSink * state = (FsChainSink *)gcu_allocator_calloc(
      allocator, 1, sizeof(FsChainSink));
  if (!state) {
    garc_sink_destroy(file);
    return GARC_ERR_OOM;
  }
  state->allocator = allocator;
  state->file = file;
  result = garc_sink_create_compress_with_allocator(
      file, method, options, allocator, &state->codec);
  if (result != GARC_OK) {
    garc_sink_destroy(file);
    gcu_allocator_free(allocator, state);
    return result;
  }

  // No patch: what reaches the file is a codec's output, and a byte of the
  // archive has no fixed place in it to go back to.
  GARC_Sink_Callbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.ctx = state;
  callbacks.write = fs_chain_write;

  GARC_Sink * sink = NULL;
  result = garc_sink_create_callback_with_allocator(
      &callbacks, allocator, &sink);
  if (result != GARC_OK) {
    garc_sink_destroy(state->codec);
    garc_sink_destroy(file);
    gcu_allocator_free(allocator, state);
    return result;
  }
  sink->owned_finish = fs_chain_finish;
  sink->owned_destroy = fs_chain_destroy;
  *out_sink = sink;
  return GARC_OK;
}

GARC_Result garc_fs_sink_create(const char * path, const char * method,
    gcomp_options_t * options, uint32_t flags, GARC_Sink ** out_sink) {
  return garc_fs_sink_create_with_allocator(
      path, method, options, flags, NULL, out_sink);
}

////////////////////////////////////////////////////////////////////////
// Opening by path
////////////////////////////////////////////////////////////////////////

/** Whether @p text ends in @p suffix, ignoring ASCII case. */
static bool fs_ends_with(const char * text, const char * suffix) {
  size_t length = strlen(text);
  size_t want = strlen(suffix);
  if (want > length) {
    return false;
  }
  const char * tail = text + (length - want);
  for (size_t i = 0; i < want; ++i) {
    char c = tail[i];
    if (c >= 'A' && c <= 'Z') {
      c = (char)(c - 'A' + 'a');
    }
    if (c != suffix[i]) {
      return false;
    }
  }
  return true;
}

/**
 * The codec that wrote the start of @p stream, or NULL.
 *
 * Leaves the stream at offset 0 when it returns a name.
 */
static const char * fs_sniff(
    GARC_Stream * stream, const char * path, uint32_t flags) {
  if (garc_stream_seek(stream, 0) != GARC_OK) {
    return NULL;
  }
  uint8_t head[GARC_FS_SNIFF_BYTES];
  size_t got = 0;
  if (garc_stream_read(stream, head, sizeof(head), &got) != GARC_OK) {
    return NULL;
  }
  if (garc_stream_seek(stream, 0) != GARC_OK) {
    return NULL;
  }

  const char * name = NULL;
  if (gcomp_detect(head, got, &name, NULL) == GCOMP_OK && name) {
    // zlib is reported when two bytes merely could be its header. Acting on
    // that would decode the start of an unknown file as zlib and report the
    // decoder's complaint instead of "not an archive".
    static const char * const trusted[]
        = {"gzip", "bzip2", "xz", "zstd", "lz4"};
    for (size_t i = 0; i < sizeof(trusted) / sizeof(trusted[0]); ++i) {
      if (strcmp(name, trusted[i]) == 0) {
        return trusted[i];
      }
    }
  }

  if (flags & GARC_FS_NAME_HINT) {
    if (fs_ends_with(path, ".br") || fs_ends_with(path, ".tbr")) {
      return "brotli";
    }
    if (fs_ends_with(path, ".lzma") || fs_ends_with(path, ".tlzma")) {
      return "lzma";
    }
  }
  return NULL;
}

////////////////////////////////////////////////////////////////////////
// Split archives
////////////////////////////////////////////////////////////////////////

/** At most this many parts, which is what zip's 16-bit disk field allows. */
#define FS_MAX_VOLUMES 65535u

static void fs_free_paths(
    const GARC_Allocator * allocator, char ** paths, size_t count) {
  for (size_t i = 0; i < count; ++i) {
    gcu_allocator_free(allocator, paths[i]);
  }
  gcu_allocator_free(allocator, paths);
}

/** @p stem followed by @p suffix, in a new string. */
static char * fs_with_suffix(
    const GARC_Allocator * allocator, const char * stem, size_t stem_length,
    const char * suffix) {
  const size_t suffix_length = strlen(suffix);
  char * out = (char *)gcu_allocator_malloc(
      allocator, stem_length + suffix_length + 1u);
  if (out) {
    memcpy(out, stem, stem_length);
    memcpy(out + stem_length, suffix, suffix_length + 1u);
  }
  return out;
}

/**
 * The files of the split archive @p path belongs to, in order, or none.
 *
 * Two layouts, both named by convention rather than by anything inside them:
 *
 * - `name.001`, `name.002`, ... - what 7-Zip's `-v` and `split -d -a 3` write,
 *   whatever the archive is. Given the first part, every consecutive part that
 *   exists is taken.
 * - `name.z01`, `name.z02`, ..., then `name.zip` - a split zip, as Info-ZIP's
 *   `zip -s` and WinZip write it. Given the `.zip` (which holds the end record)
 *   or the `.z01`, when `name.z01` exists.
 *
 * Sets `*out_count` to 0 when @p path is not part of either.
 */
static GARC_Result fs_volume_paths(const GARC_Allocator * allocator,
    const char * path, char *** out_paths, size_t * out_count) {
  *out_paths = NULL;
  *out_count = 0;
  const size_t length = strlen(path);
  const bool numbered = fs_ends_with(path, ".001");
  const bool zip = fs_ends_with(path, ".zip") || fs_ends_with(path, ".z01");
  if (!numbered && !zip) {
    return GARC_OK;
  }
  const size_t stem = length - 4u;
  // The extension's case, so that NAME.ZIP looks for NAME.Z01.
  const char z = path[stem + 1u];
  char suffix[16];
  if (zip) {
    snprintf(suffix, sizeof(suffix), ".%c01", z);
    char * first = fs_with_suffix(allocator, path, stem, suffix);
    if (!first) {
      return GARC_ERR_OOM;
    }
    const bool split = gcu_file_exists(first);
    gcu_allocator_free(allocator, first);
    if (!split) {
      return GARC_OK;
    }
  }
  char ** paths = NULL;
  size_t count = 0;
  size_t capacity = 0;
  for (unsigned n = 1; n <= FS_MAX_VOLUMES; ++n) {
    if (numbered) {
      snprintf(suffix, sizeof(suffix), n < 1000u ? ".%03u" : ".%u", n);
    }
    else {
      snprintf(suffix, sizeof(suffix), n < 100u ? ".%c%02u" : ".%c%u", z, n);
    }
    char * part = fs_with_suffix(allocator, path, stem, suffix);
    if (!part) {
      fs_free_paths(allocator, paths, count);
      return GARC_ERR_OOM;
    }
    if (!gcu_file_exists(part)) {
      gcu_allocator_free(allocator, part);
      break;
    }
    if (count == capacity) {
      const size_t grown = capacity ? capacity * 2u : 8u;
      char ** bigger = (char **)gcu_allocator_realloc(
          allocator, paths, grown * sizeof(*paths));
      if (!bigger) {
        gcu_allocator_free(allocator, part);
        fs_free_paths(allocator, paths, count);
        return GARC_ERR_OOM;
      }
      paths = bigger;
      capacity = grown;
    }
    paths[count++] = part;
  }
  if (zip) {
    // The .zip is the last disk, with the end record.
    char * last = fs_with_suffix(allocator, path, stem, z == 'Z' ? ".ZIP" : ".zip");
    if (!last) {
      fs_free_paths(allocator, paths, count);
      return GARC_ERR_OOM;
    }
    if (count == capacity) {
      char ** bigger = (char **)gcu_allocator_realloc(
          allocator, paths, (capacity + 1u) * sizeof(*paths));
      if (!bigger) {
        gcu_allocator_free(allocator, last);
        fs_free_paths(allocator, paths, count);
        return GARC_ERR_OOM;
      }
      paths = bigger;
    }
    paths[count++] = last;
  }
  *out_paths = paths;
  *out_count = count;
  return GARC_OK;
}

/**
 * The stream an archive at @p path is read from: the file, or for a split
 * archive every part in order, through a concatenation that owns them.
 */
static GARC_Result fs_open_source(const char * path,
    const GARC_Allocator * allocator, GARC_Stream ** out_stream) {
  char ** paths = NULL;
  size_t count = 0;
  GARC_Result result = fs_volume_paths(allocator, path, &paths, &count);
  if (result != GARC_OK) {
    return result;
  }
  if (count < 2u) {
    fs_free_paths(allocator, paths, count);
    return garc_fs_stream_open_with_allocator(path, allocator, out_stream);
  }
  GARC_Stream ** parts = (GARC_Stream **)gcu_allocator_calloc(
      allocator, count, sizeof(*parts));
  if (!parts) {
    fs_free_paths(allocator, paths, count);
    return GARC_ERR_OOM;
  }
  size_t opened = 0;
  for (; opened < count && result == GARC_OK; ++opened) {
    result = garc_fs_stream_open_with_allocator(
        paths[opened], allocator, &parts[opened]);
  }
  GARC_Stream * whole = NULL;
  if (result == GARC_OK) {
    result = garc_stream_create_concat_with_allocator(
        parts, count, allocator, &whole);
  }
  if (result == GARC_OK) {
    garc_stream_concat_own_parts(whole);
    *out_stream = whole;
  }
  else {
    for (size_t i = 0; i < count; ++i) {
      garc_stream_destroy(parts[i]);
    }
  }
  gcu_allocator_free(allocator, parts);
  fs_free_paths(allocator, paths, count);
  return result;
}

GARC_Result garc_fs_open_detecting(const char * path,
    const GARC_Limits * limits, gcomp_options_t * options, uint32_t flags,
    const GARC_Allocator * allocator, GARC_Archive ** out_archive,
    const char ** out_method) {
  *out_method = NULL;

  GARC_Stream * file = NULL;
  GARC_Result result = fs_open_source(path, allocator, &file);
  if (result != GARC_OK) {
    return result;
  }

  // The containers first. A tar whose first member happens to be named "BZh9"
  // is a tar, and only the container's own check can say so.
  GARC_Archive * archive = NULL;
  result = garc_open_with_allocator(file, limits, allocator, &archive);
  if (result == GARC_OK) {
    archive->owned_stream = file;
    *out_archive = archive;
    return GARC_OK;
  }
  if (result != GARC_ERR_FORMAT) {
    garc_stream_destroy(file);
    return result;
  }

  const char * method = fs_sniff(file, path, flags);
  if (!method) {
    garc_stream_destroy(file);
    return GARC_ERR_FORMAT;
  }

  GARC_Stream * decoded = NULL;
  result = garc_stream_create_decompress_with_allocator(
      file, method, options, allocator, &decoded);
  if (result != GARC_OK) {
    garc_stream_destroy(file);
    return result;
  }
  result = garc_open_with_allocator(decoded, limits, allocator, &archive);
  if (result != GARC_OK) {
    garc_stream_destroy(decoded);
    garc_stream_destroy(file);
    return result;
  }
  archive->owned_stream = decoded;
  archive->owned_inner = file;
  *out_archive = archive;
  *out_method = method;
  return GARC_OK;
}

GARC_Result garc_fs_open_with_allocator(const char * path,
    const GARC_Limits * limits, gcomp_options_t * options, uint32_t flags,
    const GARC_Allocator * allocator, GARC_Archive ** out_archive) {
  if (!path || !out_archive || (flags & ~GARC_FS_OPEN_FLAGS_KNOWN)) {
    return GARC_ERR_INVALID;
  }
  if (!allocator) {
    allocator = garc_allocator_default();
  }
  const char * method = NULL;
  return garc_fs_open_detecting(
      path, limits, options, flags, allocator, out_archive, &method);
}

GARC_Result garc_fs_open(const char * path, const GARC_Limits * limits,
    gcomp_options_t * options, uint32_t flags, GARC_Archive ** out_archive) {
  return garc_fs_open_with_allocator(
      path, limits, options, flags, NULL, out_archive);
}
