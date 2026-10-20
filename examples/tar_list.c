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
 * List an archive's members, and total the bytes of the ones that are files.
 *
 * `tar -tvf` without the parts that need a filesystem. Three things it shows
 * that a shorter example would not:
 *
 * **One call opens a file, compressed or not.** ::garc_fs_open() is in fs.h,
 * which is opt-in: the reader itself never opens a file. It tries the
 * containers, then asks `compress` what wrote the first bytes, so the same
 * program lists a `.tar`, a `.tar.gz`, a `.tar.xz`, a `.zip` or a `.7z`.
 * `--name-hint` lets the file name decide for brotli and `.lzma`, which have no
 * magic number.
 *
 * **A member name is printed escaped.** A name is attacker-controlled bytes, so
 * a listing tool that writes them straight to a terminal can be made to say
 * whatever the archive wants. This is what the escaping in `garc_member_dump()`
 * is for, and an example that skipped it would be teaching the wrong lesson.
 *
 * **Limits are on by default.** NULL limits are bounded on every field, and
 * NULL codec options cap a decompressed stream at 512 MiB, so a hostile archive
 * cannot make this program ask for a petabyte.
 *
 * Usage: `tar_list [--name-hint] <path>`
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ghoti.io/archive/archive.h>
#include <ghoti.io/archive/fs.h>

/** Print bytes with everything but printable ASCII escaped. */
static void print_escaped(const char * bytes, size_t length) {
  for (size_t i = 0; i < length; ++i) {
    const unsigned char byte = (unsigned char)bytes[i];
    if (byte == '\\') {
      fputs("\\\\", stdout);
    } else if (byte >= 0x20u && byte < 0x7Fu) {
      putchar((int)byte);
    } else {
      printf("\\x%02X", (unsigned)byte);
    }
  }
}

/**
 * List one archive's members.
 *
 * @param argc Argument count.
 * @param argv `tar_list [--name-hint] <path>`.
 * @return 0 on success, 1 on any failure, 2 on a usage error.
 */
int main(int argc, char ** argv) {
  uint32_t flags = 0;
  int at = 1;
  if (argc == 3 && strcmp(argv[1], "--name-hint") == 0) {
    flags = GARC_FS_NAME_HINT;
    at = 2;
  }
  if (argc != at + 1) {
    fprintf(stderr, "usage: %s [--name-hint] <path>\n", argv[0]);
    return 2;
  }
  const char * path = argv[at];

  GARC_Archive * archive = NULL;
  GARC_Result result = garc_fs_open(path, NULL, NULL, flags, &archive);
  if (result != GARC_OK) {
    fprintf(stderr, "%s: %s\n", path, garc_result_string(result));
    return 1;
  }

  printf("%s: %s\n", path, garc_format_string(garc_format(archive)));

  uint64_t file_bytes = 0;
  const GARC_Member * member = NULL;
  while ((result = garc_next(archive, &member)) == GARC_OK) {
    printf("%-9s %8" PRIu64 " %11" PRId64 " 0%04o ",
        garc_member_type_string(member->type), member->size,
        member->mtime_seconds, (unsigned)member->mode);
    print_escaped(member->name, member->name_length);
    if (member->link_target) {
      fputs(" -> ", stdout);
      print_escaped(member->link_target, member->link_target_length);
    }
    putchar('\n');

    if (member->type == GARC_MEMBER_FILE) {
      // Reading the data is not needed to list it - garc_next() steps over
      // whatever is left - so this is here to show that the bytes are reachable,
      // and that what they add up to is the declared size.
      char buffer[8192];
      size_t got = 0;
      while ((result = garc_read_member(archive, buffer, sizeof(buffer), &got))
              == GARC_OK
          && got) {
        file_bytes += (uint64_t)got;
      }
      if (result != GARC_OK) {
        fprintf(stderr, "  reading that member: %s\n",
            garc_result_string(result));
        break;
      }
    }
  }

  // GARC_END is the end of a well-formed archive and is not a failure, which is
  // why this asks the predicate rather than comparing against GARC_OK.
  if (garc_result_is_error(result)) {
    fprintf(stderr, "%s: %s after %" PRIu64 " members\n", path,
        garc_result_string(result), garc_member_count(archive));
    garc_close(archive);
    return 1;
  }

  printf("%" PRIu64 " members, %" PRIu64 " declared bytes, %" PRIu64 " read\n",
      garc_member_count(archive), garc_total_declared_bytes(archive),
      file_bytes);

  // Closes the file and any decompressing stream with it.
  garc_close(archive);
  return 0;
}
