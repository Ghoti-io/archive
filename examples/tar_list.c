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
 * `tar -tvf` without the parts that need a filesystem. Two things it shows that
 * a shorter example would not:
 *
 * **The library never opens the file.** The `fopen` is here; the library gets
 * three function pointers. That is not ceremony - it is the property that makes
 * a zip-slip impossible in anything this library does.
 *
 * **A member name is printed escaped.** A name is attacker-controlled bytes, so
 * a listing tool that writes them straight to a terminal can be made to say
 * whatever the archive wants. This is what the escaping in `garc_member_dump()`
 * is for, and an example that skipped it would be teaching the wrong lesson.
 *
 * Usage: tar_list <path.tar>
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
 * @param argv `argv[1]` is the archive to read.
 * @return 0 on success, 1 on any failure, 2 on a usage error.
 */
int main(int argc, char ** argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s <path.tar>\n", argv[0]);
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
    fprintf(stderr, "stream: %s\n", garc_result_string(result));
    fclose(file);
    return 1;
  }

  // NULL limits means garc_limits_default(), which is bounded on every field -
  // so this program cannot be made to ask for a petabyte by a hostile archive.
  GARC_Archive * archive = NULL;
  result = garc_open(stream, NULL, &archive);
  if (result != GARC_OK) {
    fprintf(stderr, "%s: %s\n", argv[1], garc_result_string(result));
    garc_stream_destroy(stream);
    fclose(file);
    return 1;
  }

  printf("%s: %s\n", argv[1], garc_format_string(garc_format(archive)));

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
    fprintf(stderr, "%s: %s after %" PRIu64 " members\n", argv[1],
        garc_result_string(result), garc_member_count(archive));
    garc_close(archive);
    garc_stream_destroy(stream);
    fclose(file);
    return 1;
  }

  printf("%" PRIu64 " members, %" PRIu64 " declared bytes, %" PRIu64 " read\n",
      garc_member_count(archive), garc_total_declared_bytes(archive),
      file_bytes);

  garc_close(archive);
  garc_stream_destroy(stream);
  fclose(file);
  return 0;
}
