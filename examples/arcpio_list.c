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
 * List an ar or a cpio from standard input, which cannot seek.
 *
 * Both formats are read straight through, so neither needs the stream to go
 * back, and this program supplies only `read`. That is the point of it: a
 * `tar` has always been readable from a pipe, and so are these, which means
 * `cat archive.cpio | arcpio_list` works and an `ar` on a socket is an archive
 * like any other. The container is identified from the first bytes, so the same
 * program lists either.
 *
 * What it prints is what the reader reports and not what it would be safe to
 * extract: a name is shown as the archive carries it. The binary cpio header
 * is refused by name, and a shell archive is never read at all.
 *
 * Usage: arcpio_list < archive
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

#include <ghoti.io/archive/archive.h>

static GARC_Result read_cb(
    void * ctx, void * buffer, size_t size, size_t * out_read) {
  FILE * file = (FILE *)ctx;
  const size_t got = fread(buffer, 1, size, file);
  if (got < size && ferror(file)) {
    return GARC_ERR_IO;
  }
  *out_read = got;
  return GARC_OK;
}

/**
 * List the ar or cpio on standard input: the format, then one line per member.
 *
 * @return 0 on success, 1 on a failure.
 */
int main(void) {
  GARC_Stream_Callbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));
#ifdef _WIN32
  // Windows opens standard input in text mode, which turns CR LF into LF and
  // stops at the first 0x1A: an archive read through it arrives altered and
  // short. Found by running this program under wine.
  _setmode(_fileno(stdin), _O_BINARY);
#endif
  callbacks.ctx = stdin;
  callbacks.read = read_cb;
  GARC_Stream * stream = NULL;
  GARC_Result result = garc_stream_create_callback(&callbacks, &stream);
  GARC_Archive * archive = NULL;
  if (result == GARC_OK) {
    result = garc_open(stream, NULL, &archive);
  }
  if (result != GARC_OK) {
    fprintf(stderr, "arcpio_list: %s\n", garc_result_string(result));
    garc_stream_destroy(stream);
    return 1;
  }
  printf("format: %s\n", garc_format_string(garc_format(archive)));

  const GARC_Member * member = NULL;
  while ((result = garc_next(archive, &member)) == GARC_OK) {
    printf("%-9s %04o %10" PRIu64 "  %.*s", garc_member_type_string(member->type),
        member->mode & 07777u, member->size, (int)member->name_length,
        member->name);
    if (member->link_target) {
      printf(" -> %.*s", (int)member->link_target_length, member->link_target);
    }
    putchar('\n');
    // Nothing is read: the next call steps over the data, and over cpio's and
    // ar's padding, without the caller having to.
  }
  garc_close(archive);
  garc_stream_destroy(stream);
  if (result != GARC_END) {
    fprintf(stderr, "arcpio_list: %s\n", garc_result_string(result));
    return 1;
  }
  return 0;
}
