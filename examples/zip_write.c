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
 * Write a zip to a file, and show what the sink's `patch` buys.
 *
 * Deliberately **not** `tar_write.c` with a different format constant. What this
 * shows is the one thing zip writing has that tar writing does not: a member's
 * CRC-32 and compressed size are not known when its local header is written, so
 * the archive either carries a *data descriptor* after each member or the header
 * is filled in afterwards. Which one happens depends on whether the sink can go
 * back, and a `FILE *` can - so this program supplies a `patch` callback and
 * reports which form it produced.
 *
 * **`patch` is nine lines and it is the whole difference.** Without it the same
 * program writes a valid archive that is 16 bytes per member longer and has flag
 * bit 3 set on every member. Run with `--stream` to see that, which is what a
 * caller writing to a socket gets whether they ask for it or not.
 *
 * **A symlink's target is written for you.** In zip a symlink has no link field:
 * its target *is* its data. So this sets ::GARC_Member.link_target and writes no
 * bytes, exactly as a tar caller would, and the writer puts the target in the
 * member. That is what lets a program copy an archive from tar to zip without
 * knowing which it is writing.
 *
 * Usage: zip_write <path.zip> [--stream]
 */

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ghoti.io/archive/archive.h>

static GARC_Result file_write(void * ctx, const void * buffer, size_t size) {
  FILE * file = (FILE *)ctx;
  return fwrite(buffer, 1, size, file) == size ? GARC_OK : GARC_ERR_IO;
}

/**
 * Overwrite bytes already written, and leave the position where it was.
 *
 * **Restoring the position is this callback's contract**, which is why the sink
 * takes a `patch` rather than a `seek`: three lines here, once, instead of a
 * pairing rule the library would have to trust every caller to keep.
 *
 * @param ctx The `FILE *`.
 * @param offset Where to write, from the first byte written.
 * @param buffer The replacement bytes.
 * @param size How many.
 * @return ::GARC_OK, or ::GARC_ERR_IO.
 */
static GARC_Result file_patch(
    void * ctx, uint64_t offset, const void * buffer, size_t size) {
  FILE * file = (FILE *)ctx;
  const long here = ftell(file);
  if (here < 0 || offset > (uint64_t)LONG_MAX) {
    return GARC_ERR_IO;
  }
  if (fseek(file, (long)offset, SEEK_SET) != 0) {
    return GARC_ERR_IO;
  }
  if (fwrite(buffer, 1, size, file) != size) {
    return GARC_ERR_IO;
  }
  return fseek(file, here, SEEK_SET) == 0 ? GARC_OK : GARC_ERR_IO;
}

/** One member to write: what a caller's own loop would be filling in. */
typedef struct {
  const char * name;
  GARC_Member_Type type;
  const char * data;  /**< NULL for anything that carries none. */
  const char * link;  /**< A symlink's target. */
  uint32_t mode;      /**< Permission bits; the type bits come from `type`. */
  int64_t mtime;      /**< Seconds since the epoch. */
} Entry;

static const Entry ENTRIES[] = {
  {"notes/", GARC_MEMBER_DIRECTORY, NULL, NULL, 0755, 1000000000},
  {"notes/hello.txt", GARC_MEMBER_FILE, "hello, archive\n", NULL, 0644,
      1000000000},
  // An odd second, which the MS-DOS date field cannot hold: it has two-second
  // resolution. The writer notices and adds an extended timestamp field, so this
  // member's time survives where it would otherwise be rounded down - and it is
  // the only member in this archive with an extra field on it.
  {"notes/odd-second.txt", GARC_MEMBER_FILE, "written at an odd second\n", NULL,
      0644, 1000000001},
  {"notes/run.sh", GARC_MEMBER_FILE, "#!/bin/sh\necho hello\n", NULL, 0755,
      1000000000},
  {"notes/link", GARC_MEMBER_SYMLINK, NULL, "hello.txt", 0777, 1000000000},
};

/**
 * Write a small archive.
 *
 * @param argc Argument count.
 * @param argv `argv[1]` is the archive to write; `--stream` forces the
 *   data-descriptor form.
 * @return 0 on success, 1 on any failure, 2 on a usage error.
 */
int main(int argc, char ** argv) {
  int stream = 0;
  if (argc == 3 && strcmp(argv[2], "--stream") == 0) {
    stream = 1;
  }
  else if (argc != 2) {
    fprintf(stderr, "usage: %s <path.zip> [--stream]\n", argv[0]);
    return 2;
  }

  FILE * file = fopen(argv[1], "wb");
  if (!file) {
    fprintf(stderr, "cannot write %s\n", argv[1]);
    return 1;
  }

  GARC_Sink_Callbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.write = file_write;
  callbacks.ctx = file;
  if (!stream) {
    // Offered, not required. Leaving it NULL is how a caller writing to a pipe
    // says so, and the archive is still valid - see the report at the end.
    callbacks.patch = file_patch;
  }

  GARC_Sink * sink = NULL;
  GARC_Result result = garc_sink_create_callback(&callbacks, &sink);
  if (result != GARC_OK) {
    fprintf(stderr, "sink: %s\n", garc_result_string(result));
    fclose(file);
    return 1;
  }

  GARC_Writer * writer = NULL;
  // NULL options: GARC_ZIP_SIZES_AUTO, which asks the sink. Asking for
  // GARC_ZIP_SIZES_LOCAL with no `patch` would be GARC_ERR_NOT_SEEKABLE here,
  // which is the refusal a caller wants when the form matters to them.
  result = garc_writer_create(sink, GARC_FORMAT_ZIP, NULL, &writer);
  if (result != GARC_OK) {
    fprintf(stderr, "writer: %s\n", garc_result_string(result));
    garc_sink_destroy(sink);
    fclose(file);
    return 1;
  }

  for (size_t i = 0; i < sizeof(ENTRIES) / sizeof(*ENTRIES); ++i) {
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
    // Saying where the time came from is what lets the writer decide whether an
    // extended timestamp is needed. GARC_TIME_NONE would mean "no time at all",
    // which zip cannot express - the DOS field is mandatory - so such a member
    // gets the earliest time the field can hold and no extra field.
    member.mtime_source = GARC_TIME_ZIP_DOS;
    if (entry->link) {
      member.link_target = entry->link;
      member.link_target_length = strlen(entry->link);
    }

    result = garc_writer_add(writer, &member);
    if (result != GARC_OK) {
      fprintf(stderr, "%s: %s\n", entry->name, garc_result_string(result));
      break;
    }
    if (entry->data) {
      result = garc_writer_write(writer, entry->data, strlen(entry->data));
      if (result != GARC_OK) {
        fprintf(stderr, "%s: %s\n", entry->name, garc_result_string(result));
        break;
      }
    }
  }

  if (result == GARC_OK) {
    // **Not called by destroy, and that is deliberate**: finishing writes the
    // central directory and the end record, it can fail, and a destructor cannot
    // report it. An abandoned archive stays truncated on purpose.
    result = garc_writer_finish(writer);
    if (result != GARC_OK) {
      fprintf(stderr, "finish: %s\n", garc_result_string(result));
    }
  }

  const uint64_t written = garc_sink_tell(sink);
  const uint64_t members = garc_writer_member_count(writer);
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
  if (fclose(file) != 0) {
    fprintf(stderr, "%s: could not be closed\n", argv[1]);
    return 1;
  }
  if (result != GARC_OK) {
    return 1;
  }

  printf("%s: %" PRIu64 " members, %" PRIu64 " bytes, sizes in the %s\n",
      argv[1], members, written,
      stream ? "data descriptors (the sink could not go back)"
             : "local headers (the sink could be patched)");
  return 0;
}
