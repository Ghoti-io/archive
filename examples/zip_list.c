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
 * List a zip's members, with the things only a zip has.
 *
 * `unzip -Z` without the parts that need a filesystem, and deliberately not a
 * second copy of `tar_list.c`: what this shows is the handful of questions a zip
 * can be asked and a tar cannot.
 *
 * **A seek is required, and this program says so.** The `size` and `seek`
 * callbacks are not optional here the way they are for a tar: the answer to
 * "what is in this archive" is at the far end of the file. A stream that cannot
 * seek gets ::GARC_ERR_NOT_SEEKABLE from ::garc_open(), which this prints as
 * itself rather than as "not an archive".
 *
 * **A member this library cannot decompress is still a member.** Its name, size,
 * time and method are all readable; only ::garc_read_member() refuses, and it
 * refuses by naming the method. A listing tool has no reason to stop there, so
 * this one does not - which is the difference between a refusal that is a to-do
 * list and one that is a dead end.
 *
 * **The base offset is worth printing.** A self-extracting archive has bytes in
 * front of it that its own offsets do not count, and this is where a caller
 * finds out how many - the library worked it out rather than reading it.
 *
 * Usage: zip_list <path.zip>
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
 * List one zip's members.
 *
 * @param argc Argument count.
 * @param argv `argv[1]` is the archive to read.
 * @return 0 on success, 1 on any failure, 2 on a usage error.
 */
int main(int argc, char ** argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s <path.zip>\n", argv[0]);
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

  GARC_Archive * archive = NULL;
  result = garc_open(stream, NULL, &archive);
  if (result != GARC_OK) {
    fprintf(stderr, "%s: %s\n", argv[1], garc_result_string(result));
    garc_stream_destroy(stream);
    fclose(file);
    return 1;
  }

  if (garc_format(archive) != GARC_FORMAT_ZIP) {
    // Not a failure of the library: this program is about the zip accessors, and
    // asking them about a tar would answer zero for every one of them.
    fprintf(stderr, "%s is a %s, not a zip\n", argv[1],
        garc_format_string(garc_format(archive)));
    garc_close(archive);
    garc_stream_destroy(stream);
    fclose(file);
    return 1;
  }

  printf("%s: %" PRIu64 " members declared%s", argv[1],
      garc_zip_declared_members(archive),
      garc_zip_has_zip64_end_record(archive) ? ", zip64" : "");
  const uint64_t base = garc_zip_base_offset(archive);
  if (base) {
    printf(", %" PRIu64 " bytes in front of the archive", base);
  }
  putchar('\n');

  size_t comment_length = 0;
  const char * comment = garc_zip_archive_comment(archive, &comment_length);
  if (comment) {
    fputs("comment: ", stdout);
    print_escaped(comment, comment_length);
    putchar('\n');
  }

  uint64_t unreadable = 0;
  const GARC_Member * member = NULL;
  while ((result = garc_next(archive, &member)) == GARC_OK) {
    const uint16_t method = garc_zip_member_method(archive);
    printf("%-9s %10" PRIu64 " %10" PRIu64 " %-12s crc %08" PRIx32 " ",
        garc_member_type_string(member->type), member->size,
        garc_zip_member_compressed_size(archive),
        garc_zip_method_string(method), garc_zip_member_crc32(archive));
    print_escaped(member->name, member->name_length);
    if (member->link_target) {
      fputs(" -> ", stdout);
      print_escaped(member->link_target, member->link_target_length);
    }
    if (garc_zip_member_encryption(archive) != GARC_ZIP_ENCRYPTION_NONE) {
      printf(" [%s]",
          garc_zip_encryption_string(garc_zip_member_encryption(archive)));
    }
    putchar('\n');

    if (member->type != GARC_MEMBER_FILE) {
      continue;
    }
    char buffer[8192];
    size_t got = 0;
    uint64_t read = 0;
    GARC_Result data;
    while ((data = garc_read_member(archive, buffer, sizeof(buffer), &got))
            == GARC_OK
        && got) {
      read += (uint64_t)got;
    }
    if (data == GARC_ERR_UNSUPPORTED) {
      // The member is fine and this library cannot decompress it. Counted and
      // carried on with, because the walk is unaffected: the next member's
      // position came from the central directory and not from this one's data.
      ++unreadable;
      continue;
    }
    if (data != GARC_OK) {
      fprintf(stderr, "  reading that member: %s\n", garc_result_string(data));
      break;
    }
    if (read != member->size) {
      // The size is what the archive declared; this is the check that it was
      // telling the truth.
      fprintf(stderr, "  declared %" PRIu64 " bytes and held %" PRIu64 "\n",
          member->size, read);
    }
  }

  if (garc_result_is_error(result)) {
    fprintf(stderr, "%s: %s after %" PRIu64 " members\n", argv[1],
        garc_result_string(result), garc_member_count(archive));
    garc_close(archive);
    garc_stream_destroy(stream);
    fclose(file);
    return 1;
  }

  printf("%" PRIu64 " members, %" PRIu64 " declared bytes",
      garc_member_count(archive), garc_total_declared_bytes(archive));
  if (unreadable) {
    printf(", %" PRIu64 " with a method this build cannot decompress",
        unreadable);
  }
  putchar('\n');

  garc_close(archive);
  garc_stream_destroy(stream);
  fclose(file);
  return 0;
}
