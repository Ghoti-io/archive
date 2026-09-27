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
 * Build a small tar and write it to a file, then to standard output.
 *
 * Three things it shows that a shorter example would not:
 *
 * **The library never opens the file.** The `fopen` is here; the library gets one
 * function pointer. Writing is the direction where that matters most - a library
 * that created files would be a library that could be made to create them
 * somewhere else.
 *
 * **Both sinks, from the same code.** The members are written once through a
 * `GARC_Writer`, which is pointed at a growable buffer in one call and at a
 * `FILE *` in the other. That is the whole of what the sink abstraction buys, and
 * an example that used only the memory one would not show it.
 *
 * **A declared size is a promise.** `member.size` is set before the bytes are
 * written and the writer refuses a different number of them, because the header
 * carrying that size has already gone out. Getting it wrong is a caller bug and
 * the example checks for it like any other.
 *
 * Usage: tar_write [path.tar]
 *        With no path, the archive goes to standard output.
 */

#include <stdio.h>
#include <string.h>

#include <ghoti.io/archive/archive.h>

/** Write through a FILE *, which is the whole of a sink for a file on disk. */
static GARC_Result file_write(void * ctx, const void * buffer, size_t size) {
  FILE * out = (FILE *)ctx;
  // All of them or none: fwrite reports how many items it took, and a short
  // write is a failure rather than an end of anything.
  return fwrite(buffer, 1, size, out) == size ? GARC_OK : GARC_ERR_IO;
}

/** One member of the archive this builds. */
typedef struct {
  const char * name;
  const char * data;
  GARC_Member_Type type;
} Entry;

static const Entry entries[] = {
  {"notes/", NULL, GARC_MEMBER_DIRECTORY},
  {"notes/hello.txt", "Hello, tar.\n", GARC_MEMBER_FILE},
  {"notes/empty.txt", "", GARC_MEMBER_FILE},
  {"notes/link", "hello.txt", GARC_MEMBER_SYMLINK},
};

/**
 * Put every entry into @p writer.
 *
 * @param writer The writer.
 * @return GARC_OK, or the first failure.
 */
static GARC_Result build(GARC_Writer * writer) {
  for (size_t i = 0; i < sizeof(entries) / sizeof(entries[0]); ++i) {
    const Entry * entry = &entries[i];

    GARC_Member member;
    memset(&member, 0, sizeof(member));
    member.name = entry->name;
    member.name_length = strlen(entry->name);
    member.type = entry->type;
    member.mode = entry->type == GARC_MEMBER_DIRECTORY ? 0755u : 0644u;
    member.mode_valid = 1;
    member.uid = 0;
    member.gid = 0;
    member.ids_valid = 1;
    // A fixed time rather than the clock, so that two runs of this program
    // produce the same bytes. An archive that changes every time it is built is
    // one nobody can check.
    member.mtime_seconds = 1700000000;
    member.mtime_source = GARC_TIME_TAR_OCTAL;

    if (entry->type == GARC_MEMBER_SYMLINK) {
      member.link_target = entry->data;
      member.link_target_length = strlen(entry->data);
    } else if (entry->type == GARC_MEMBER_FILE) {
      member.size = strlen(entry->data);
    }

    GARC_Result result = garc_writer_add(writer, &member);
    if (result != GARC_OK) {
      fprintf(stderr, "tar_write: %s: %s\n", entry->name,
          garc_result_string(result));
      return result;
    }
    if (member.size) {
      result = garc_writer_write(writer, entry->data, (size_t)member.size);
      if (result != GARC_OK) {
        fprintf(stderr, "tar_write: %s: %s\n", entry->name,
            garc_result_string(result));
        return result;
      }
    }
  }
  return garc_writer_finish(writer);
}

/**
 * Run @p build against one sink.
 *
 * @param sink The sink.
 * @return 0 on success.
 */
static int write_to(GARC_Sink * sink) {
  GARC_Writer * writer = NULL;
  GARC_Result result
      = garc_writer_create(sink, GARC_FORMAT_TAR, NULL, &writer);
  if (result != GARC_OK) {
    fprintf(stderr, "tar_write: %s\n", garc_result_string(result));
    return 1;
  }
  result = build(writer);
  garc_writer_destroy(writer);
  return result == GARC_OK ? 0 : 1;
}

int main(int argc, char ** argv) {
  // First into memory, so the size can be reported before anything is committed
  // to disk. A caller streaming to a socket would skip this half.
  GARC_Sink * memory = NULL;
  if (garc_sink_create_memory(&memory) != GARC_OK) {
    fprintf(stderr, "tar_write: out of memory\n");
    return 1;
  }
  if (write_to(memory) != 0) {
    garc_sink_destroy(memory);
    return 1;
  }
  const void * bytes = NULL;
  size_t length = 0;
  if (garc_sink_data(memory, &bytes, &length) != GARC_OK) {
    garc_sink_destroy(memory);
    return 1;
  }
  fprintf(stderr, "tar_write: %zu bytes, %zu members\n", length,
      sizeof(entries) / sizeof(entries[0]));

  FILE * out = stdout;
  if (argc > 1) {
    out = fopen(argv[1], "wb");
    if (!out) {
      perror(argv[1]);
      garc_sink_destroy(memory);
      return 1;
    }
  }

  // And again through a callback, which is the same writer over a different
  // sink. The bytes are identical, which is what the fuzz harness asserts too.
  GARC_Sink_Callbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.ctx = out;
  callbacks.write = file_write;

  GARC_Sink * sink = NULL;
  int status = 1;
  if (garc_sink_create_callback(&callbacks, &sink) == GARC_OK) {
    status = write_to(sink);
    garc_sink_destroy(sink);
  }

  if (out != stdout) {
    if (fclose(out) != 0) {
      perror(argv[1]);
      status = 1;
    }
  } else if (fflush(out) != 0) {
    perror("stdout");
    status = 1;
  }
  garc_sink_destroy(memory);
  return status;
}
