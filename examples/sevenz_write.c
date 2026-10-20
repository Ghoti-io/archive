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
 * Write a 7z to a file, and show what the format asks of its sink.
 *
 * A 7z puts its header at the *end* and the pointer to that header at the
 * *front*: the 32-byte signature header says where the real header is, and
 * that is not known until every file has been written. So the sink must be
 * able to `patch` - overwrite bytes already written - and the library refuses
 * a sink that cannot with ::GARC_ERR_NOT_SEEKABLE rather than producing an
 * archive that points nowhere. The file sink from fs.h can, and it renames the
 * finished file into place, so a failed run leaves nothing at the path.
 *
 * **Solid is the default.** All the files go through one compressor, so each
 * sees the ones before it, which is why a solid archive is smaller and why
 * reading its last file means decoding all the others. `--non-solid` gives
 * each file a compressor of its own.
 *
 * **LZMA2 is the default method**, as it is 7-Zip's; `--lzma`, `--bzip2`,
 * `--deflate`, `--deflate64` and `--copy` name the others. A symlink's target is written as
 * its data, as zip does, and the library does that for you.
 *
 * Usage: sevenz_write <path.7z> [--non-solid]
 *            [--lzma | --bzip2 | --deflate | --deflate64 | --copy]
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ghoti.io/archive/archive.h>
#include <ghoti.io/archive/fs.h>

typedef struct {
  const char * name;
  GARC_Member_Type type;
  const char * data;
  const char * link;
  uint32_t mode;
  int64_t mtime;
} Entry;

static const Entry ENTRIES[] = {
  {"notes", GARC_MEMBER_DIRECTORY, NULL, NULL, 0755, 1000000000},
  {"notes/hello.txt", GARC_MEMBER_FILE, "hello, archive\n", NULL, 0644,
      1000000000},
  {"notes/run.sh", GARC_MEMBER_FILE, "#!/bin/sh\necho hello\n", NULL, 0755,
      1000000000},
  {"notes/link", GARC_MEMBER_SYMLINK, NULL, "hello.txt", 0777, 1000000000},
  {"notes/empty", GARC_MEMBER_FILE, "", NULL, 0644, 1000000000},
  {"notes/caf\xC3\xA9 \xF0\x9F\x98\x80.txt", GARC_MEMBER_FILE,
      "names are UTF-8 here and UTF-16 in the archive\n", NULL, 0644,
      1000000000},
};

/**
 * Write a small 7z of fixed members.
 *
 * @param argc Argument count.
 * @param argv `sevenz_write <path.7z>` and the options in the file comment.
 * @return 0 on success, 1 on a failure, 2 on a usage error.
 */
int main(int argc, char ** argv) {
  if (argc < 2) {
    fprintf(stderr,
        "usage: %s <path.7z> [--non-solid] "
        "[--lzma | --bzip2 | --deflate | --deflate64 | --copy]\n",
        argv[0]);
    return 2;
  }
  GARC_SevenZ_Method method = GARC_SEVENZ_LZMA2;
  int non_solid = 0;
  for (int i = 2; i < argc; ++i) {
    if (strcmp(argv[i], "--non-solid") == 0) {
      non_solid = 1;
    }
    else if (strcmp(argv[i], "--lzma") == 0) {
      method = GARC_SEVENZ_LZMA;
    }
    else if (strcmp(argv[i], "--bzip2") == 0) {
      method = GARC_SEVENZ_BZIP2;
    }
    else if (strcmp(argv[i], "--deflate") == 0) {
      method = GARC_SEVENZ_DEFLATE;
    }
    else if (strcmp(argv[i], "--deflate64") == 0) {
      method = GARC_SEVENZ_DEFLATE64;
    }
    else if (strcmp(argv[i], "--copy") == 0) {
      method = GARC_SEVENZ_COPY;
    }
    else {
      fprintf(stderr, "%s: unknown option %s\n", argv[0], argv[i]);
      return 2;
    }
  }

  GARC_Sink * sink = NULL;
  GARC_Result result = garc_fs_sink_create(argv[1], NULL, NULL, 0, &sink);
  if (result != GARC_OK) {
    fprintf(stderr, "%s: %s\n", argv[1], garc_result_string(result));
    return 1;
  }

  GARC_Writer_Options options;
  garc_writer_options_default(&options);
  options.sevenz_method = method;
  options.sevenz_non_solid = non_solid;
  GARC_Writer * writer = NULL;
  result = garc_writer_create(sink, GARC_FORMAT_SEVENZ, &options, &writer);
  if (result != GARC_OK) {
    fprintf(stderr, "writer: %s\n", garc_result_string(result));
    garc_sink_destroy(sink);
    return 1;
  }

  for (size_t i = 0; result == GARC_OK
       && i < sizeof(ENTRIES) / sizeof(*ENTRIES); ++i) {
    const Entry * entry = &ENTRIES[i];
    GARC_Member member;
    memset(&member, 0, sizeof(member));
    member.name = entry->name;
    member.name_length = strlen(entry->name);
    member.type = entry->type;
    member.size = entry->data ? strlen(entry->data) : 0u;
    member.mode = entry->mode;
    member.mode_valid = 1;
    member.mtime_seconds = entry->mtime;
    member.mtime_source = GARC_TIME_FILETIME;
    if (entry->link) {
      member.link_target = entry->link;
      member.link_target_length = strlen(entry->link);
    }
    result = garc_writer_add(writer, &member);
    if (result == GARC_OK && member.size) {
      result = garc_writer_write(writer, entry->data, (size_t)member.size);
    }
    if (result != GARC_OK) {
      fprintf(stderr, "%s: %s\n", entry->name, garc_result_string(result));
    }
  }
  if (result == GARC_OK) {
    // Not called by destroy: finishing writes the header and patches the start
    // of the file, it can fail, and a destructor cannot say so.
    result = garc_writer_finish(writer);
    if (result != GARC_OK) {
      fprintf(stderr, "finish: %s\n", garc_result_string(result));
    }
  }
  if (result == GARC_OK) {
    // The rename into place. A sink destroyed unfinished removes its
    // temporary file instead.
    result = garc_sink_finish(sink);
    if (result != GARC_OK) {
      fprintf(stderr, "%s: %s\n", argv[1], garc_result_string(result));
    }
  }
  const uint64_t written = garc_sink_tell(sink);
  const uint64_t members = garc_writer_member_count(writer);
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
  if (result != GARC_OK) {
    return 1;
  }
  printf("%s: %" PRIu64 " members, %" PRIu64 " bytes, %s\n", argv[1], members,
      written, non_solid ? "one folder per file" : "solid");
  return 0;
}
