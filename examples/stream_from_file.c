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
 * Read a file through this library without this library opening it.
 *
 * This is the whole of what a caller has to write to use the archive reader on
 * a file on disk, and it is the reason there is no `garc_stream_create_file()`:
 * the `fopen` is here, in the caller, where the caller's own permissions,
 * sandbox and error handling apply. The library sees three function pointers.
 *
 * Usage: `stream_from_file <path>`
 */

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include <ghoti.io/archive/archive.h>

static GARC_Result file_read(
    void * ctx, void * buffer, size_t size, size_t * out_read) {
  FILE * file = (FILE *)ctx;
  size_t got = fread(buffer, 1, size, file);
  if (got < size && ferror(file)) {
    return GARC_ERR_IO;
  }
  // A short read at the end of the file is not a failure; the stream reports it
  // as the end, and read_exact is what turns it into a truncated-archive error
  // where a fixed-size structure was expected.
  *out_read = got;
  return GARC_OK;
}

static GARC_Result file_seek(void * ctx, uint64_t offset) {
  FILE * file = (FILE *)ctx;
  if (offset > (uint64_t)LONG_MAX) {
    return GARC_ERR_IO;
  }
  return fseek(file, (long)offset, SEEK_SET) == 0 ? GARC_OK : GARC_ERR_IO;
}

static GARC_Result file_size(void * ctx, uint64_t * out_size) {
  FILE * file = (FILE *)ctx;
  long here = ftell(file);
  if (here < 0 || fseek(file, 0, SEEK_END) != 0) {
    return GARC_ERR_IO;
  }
  long end = ftell(file);
  if (end < 0 || fseek(file, here, SEEK_SET) != 0) {
    return GARC_ERR_IO;
  }
  *out_size = (uint64_t)end;
  return GARC_OK;
}

/**
 * Read an archive from a file, through callbacks the caller owns.
 *
 * @param argc Argument count.
 * @param argv `argv[1]` is the archive to read.
 * @return 0 on success, 1 on any failure, 2 on a usage error.
 */
int main(int argc, char ** argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s <path>\n", argv[0]);
    return 2;
  }

  FILE * file = fopen(argv[1], "rb");
  if (!file) {
    fprintf(stderr, "cannot open %s\n", argv[1]);
    return 1;
  }

  GARC_Stream_Callbacks callbacks = {
    .read = file_read,
    .seek = file_seek,
    .size = file_size,
    .ctx = file,
  };

  GARC_Stream * stream = NULL;
  GARC_Result result = garc_stream_create_callback(&callbacks, &stream);
  if (result != GARC_OK) {
    fprintf(stderr, "garc_stream_create_callback: %s\n",
        garc_result_string(result));
    fclose(file);
    return 1;
  }

  printf("archive library %s\n", garc_version_string());
  printf("seekable: %s\n", garc_stream_is_seekable(stream) ? "yes" : "no");

  uint64_t size = 0;
  result = garc_stream_size(stream, &size);
  if (result == GARC_OK) {
    printf("size: %" PRIu64 " bytes\n", size);
  } else {
    // Which is what a pipe would say, and is not "zero bytes".
    printf("size: unknown (%s)\n", garc_result_string(result));
  }

  unsigned char head[16];
  size_t got = 0;
  result = garc_stream_read(stream, head, sizeof(head), &got);
  if (result != GARC_OK) {
    fprintf(stderr, "garc_stream_read: %s\n", garc_result_string(result));
    garc_stream_destroy(stream);
    fclose(file);
    return 1;
  }

  printf("first %zu bytes:", got);
  for (size_t i = 0; i < got; ++i) {
    printf(" %02x", head[i]);
  }
  printf("\n");
  printf("offset now: %" PRIu64 "\n", garc_stream_tell(stream));

  garc_stream_destroy(stream);
  fclose(file);
  return 0;
}
