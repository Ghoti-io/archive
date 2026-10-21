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
 * The library half of `make check-volumes`: open an archive by its path, the
 * way garc_fs_open() finds a split set's other parts, and print what is in it.
 *
 * Usage:
 *   volume_probe <path>                 read, as below
 *   volume_probe -                      read standard input, a stream that
 *                                        cannot seek: a split set's volumes
 *                                        piped in order
 *   volume_probe write <name.zip> <dir>  pack @p dir as a zip split into
 *                                        64 KiB volumes, through
 *                                        garc_fs_sink_create_volumes()
 *   volume_probe copy <name.zip> <from>  copy every member of the zip at
 *                                        @p from, split or not, into the
 *                                        same volumes with ::GARC_COPY_RAW
 *
 * One row per file member - `name`, `size`, `crc32` in hex - tab-separated, in
 * the archive's order. check_volumes.py compares them with the source files
 * the references split, so the reading is held to the bytes and not to
 * another reader. A member whose data does not read to its end is an error.
 */

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <ghoti.io/archive/archive.h>
#include <ghoti.io/archive/fs.h>
#include <ghoti.io/compress/crc32.h>

/**
 * Pack @p from into a split zip at @p path, deflated, 64 KiB volumes: a
 * directory through garc_fs_pack(), or a zip copied raw member by member.
 */
static int write_split(const char * path, const char * from, int copy) {
  GARC_Sink * sink = NULL;
  GARC_Result result = garc_fs_sink_create_volumes(path, GARC_FS_NO_SYNC, &sink);
  GARC_Writer * writer = NULL;
  if (result == GARC_OK) {
    GARC_Writer_Options options;
    garc_writer_options_default(&options);
    options.zip_method = GARC_ZIP_METHOD_DEFLATE;
    options.zip_volume_size = 65536u;
    result = garc_writer_create(sink, GARC_FORMAT_ZIP, &options, &writer);
  }
  if (result == GARC_OK && !copy) {
    result = garc_fs_pack(writer, from, 0);
  }
  if (result == GARC_OK && copy) {
    GARC_Archive * source = NULL;
    result = garc_fs_open(from, NULL, NULL, 0, &source);
    const GARC_Member * member = NULL;
    while (result == GARC_OK && (result = garc_next(source, &member)) == GARC_OK) {
      result = garc_writer_copy_member(writer, source, NULL, GARC_COPY_RAW);
    }
    if (result == GARC_END) {
      result = GARC_OK;
    }
    garc_close(source);
  }
  if (result == GARC_OK) {
    result = garc_writer_finish(writer);
  }
  if (result == GARC_OK) {
    result = garc_sink_finish(sink);
  }
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
  if (result != GARC_OK) {
    fprintf(stderr, "%s: write: %s\n", path, garc_result_string(result));
    return 1;
  }
  return 0;
}

/** Standard input as a stream that reads and does nothing else. */
static GARC_Result stdin_read(void * ctx, void * buffer, size_t size,
    size_t * out_read) {
  (void)ctx;
  *out_read = fread(buffer, 1, size, stdin);
  return ferror(stdin) ? GARC_ERR_IO : GARC_OK;
}

int main(int argc, char ** argv) {
  if (argc == 4 && strcmp(argv[1], "write") == 0) {
    return write_split(argv[2], argv[3], 0);
  }
  if (argc == 4 && strcmp(argv[1], "copy") == 0) {
    return write_split(argv[2], argv[3], 1);
  }
  if (argc != 2) {
    fprintf(stderr,
        "usage: %s <path>\n       %s write <name.zip> <dir>\n"
        "       %s copy <name.zip> <from.zip>\n",
        argv[0], argv[0], argv[0]);
    return 2;
  }
  GARC_Archive * archive = NULL;
  GARC_Stream * piped = NULL;
  GARC_Result result = GARC_OK;
  if (strcmp(argv[1], "-") == 0) {
    GARC_Stream_Callbacks callbacks;
    memset(&callbacks, 0, sizeof(callbacks));
    callbacks.read = stdin_read;
    result = garc_stream_create_callback(&callbacks, &piped);
    if (result == GARC_OK) {
      result = garc_open(piped, NULL, &archive);
    }
  }
  else {
    result = garc_fs_open(argv[1], NULL, NULL, 0, &archive);
  }
  if (result != GARC_OK) {
    fprintf(stderr, "%s: open: %s\n", argv[1], garc_result_string(result));
    garc_stream_destroy(piped);
    return 1;
  }
  const GARC_Member * member = NULL;
  while ((result = garc_next(archive, &member)) == GARC_OK) {
    if (member->type != GARC_MEMBER_FILE) {
      continue;
    }
    uint32_t crc = GCOMP_CRC32_INIT;
    uint64_t size = 0;
    unsigned char buffer[65536];
    size_t got = 0;
    while ((result = garc_read_member(archive, buffer, sizeof(buffer), &got))
            == GARC_OK
        && got) {
      crc = gcomp_crc32_update(crc, buffer, got);
      size += got;
    }
    if (result != GARC_OK) {
      fprintf(stderr, "%s: %.*s: %s\n", argv[1], (int)member->name_length,
          member->name, garc_result_string(result));
      garc_close(archive);
      garc_stream_destroy(piped);
      return 1;
    }
    printf("%.*s\t%" PRIu64 "\t%08x\n", (int)member->name_length, member->name,
        size, (unsigned)gcomp_crc32_finalize(crc));
  }
  garc_close(archive);
  garc_stream_destroy(piped);
  if (result != GARC_END) {
    fprintf(stderr, "%s: next: %s\n", argv[1], garc_result_string(result));
    return 1;
  }
  return 0;
}
