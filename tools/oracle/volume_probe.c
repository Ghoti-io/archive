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
 *   volume_probe <path>
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

int main(int argc, char ** argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s <path>\n", argv[0]);
    return 2;
  }
  GARC_Archive * archive = NULL;
  GARC_Result result = garc_fs_open(argv[1], NULL, NULL, 0, &archive);
  if (result != GARC_OK) {
    fprintf(stderr, "%s: open: %s\n", argv[1], garc_result_string(result));
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
      return 1;
    }
    printf("%.*s\t%" PRIu64 "\t%08x\n", (int)member->name_length, member->name,
        size, (unsigned)gcomp_crc32_finalize(crc));
  }
  garc_close(archive);
  if (result != GARC_END) {
    fprintf(stderr, "%s: next: %s\n", argv[1], garc_result_string(result));
    return 1;
  }
  return 0;
}
