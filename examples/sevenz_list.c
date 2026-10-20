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
 * List a 7z, and read each file to prove its checksum.
 *
 * A 7z cannot be read from a pipe: its header is at the end, so the stream has
 * to seek, and one that cannot is reported as ::GARC_ERR_NOT_SEEKABLE rather
 * than as a bad archive. ::garc_fs_open() opens the file seekably.
 *
 * **Listing is cheap and reading is not, in a solid archive.** The files of a
 * solid archive are cut from one decompressed stream, so the listing needs no
 * decoding at all, but reaching a file means decoding every file before it.
 * This program reads each member to its end, which is the cost of checking
 * every CRC-32 and the reason the status of the *last* read is printed: the
 * checksum verdict arrives on the call that returns zero bytes.
 *
 * A member whose coder this library cannot decode (BCJ2, PPMd, encryption) is
 * still listed; its read is ::GARC_ERR_UNSUPPORTED.
 *
 * Usage: sevenz_list <path.7z>
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ghoti.io/archive/archive.h>
#include <ghoti.io/archive/fs.h>

/**
 * List a 7z, reading each file to its end and printing the status of the last
 * read, which is where the CRC-32 verdict arrives.
 *
 * @param argc Argument count.
 * @param argv `sevenz_list <path.7z>`.
 * @return 0 on success, 1 on a failure, 2 on a usage error.
 */
int main(int argc, char ** argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s <path.7z>\n", argv[0]);
    return 2;
  }
  // fs.h opens the file seekably, with 64-bit offsets on every platform. The
  // reader itself never opens a file; this is the opt-in layer that does.
  GARC_Archive * archive = NULL;
  GARC_Result result = garc_fs_open(argv[1], NULL, NULL, 0, &archive);
  if (result != GARC_OK) {
    fprintf(stderr, "%s: %s\n", argv[1], garc_result_string(result));
    return 1;
  }

  const GARC_Member * member = NULL;
  int problems = 0;
  while ((result = garc_next(archive, &member)) == GARC_OK) {
    uint8_t buffer[8192];
    size_t got = 0;
    uint64_t total = 0;
    GARC_Result read;
    while ((read = garc_read_member(archive, buffer, sizeof(buffer), &got))
            == GARC_OK
        && got) {
      total += got;
    }
    printf("%-9s %10" PRIu64 "  %.*s", garc_member_type_string(member->type),
        member->size, (int)member->name_length, member->name);
    if (member->link_target) {
      printf(" -> %.*s", (int)member->link_target_length, member->link_target);
    }
    if (read != GARC_OK) {
      printf("   [%s]", garc_result_string(read));
      ++problems;
    }
    else if (total != member->size && !member->link_target) {
      printf("   [read %" PRIu64 "]", total);
      ++problems;
    }
    putchar('\n');
  }
  garc_close(archive);
  if (result != GARC_END) {
    fprintf(stderr, "%s: %s\n", argv[1], garc_result_string(result));
    return 1;
  }
  return problems ? 1 : 0;
}
