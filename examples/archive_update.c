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
 * Delete members from an archive file and add new ones, in place or by
 * rewriting it.
 *
 * The rewrite is ::garc_fs_update_begin()'s default and works for tar,
 * compressed tar, zip, 7z, ar and cpio: every member not named with `-d` is
 * kept with ::garc_fs_update_keep() - for zip that is the stored bytes, so
 * nothing is recompressed and an encrypted member needs no password - the `-a`
 * members are added, and the new file is renamed over the old one only when
 * all of it worked. Until then, and if anything fails, the original is as it
 * was.
 *
 * `--in-place` appends to an uncompressed tar where it ends instead, which is
 * what `tar -r` does: fast for a large archive, not atomic, and refused for
 * every other format. With it `-d` is refused, because deleting is a rewrite.
 *
 * Usage: `archive_update ARCHIVE [--in-place] [-d NAME]... [-a NAME=TEXT]...`
 */

#include <stdio.h>
#include <string.h>

#include <ghoti.io/archive/archive.h>
#include <ghoti.io/archive/fs.h>

/** Add one member whose bytes are @p text. */
static GARC_Result add_text(GARC_Writer * writer, const char * name,
    size_t name_length, const char * text) {
  GARC_Member member;
  memset(&member, 0, sizeof(member));
  member.name = name;
  member.name_length = name_length;
  member.type = GARC_MEMBER_FILE;
  member.size = strlen(text);
  member.mode = 0644;
  member.mode_valid = 1;
  GARC_Result result = garc_writer_add(writer, &member);
  if (result == GARC_OK && member.size) {
    result = garc_writer_write(writer, text, (size_t)member.size);
  }
  return result;
}

/** Whether @p name is one of the `-d` arguments. */
static int is_deleted(int argc, char ** argv, const GARC_Member * member) {
  for (int i = 2; i + 1 < argc; ++i) {
    if (strcmp(argv[i], "-d") == 0
        && strlen(argv[i + 1]) == member->name_length
        && memcmp(argv[i + 1], member->name, member->name_length) == 0) {
      return 1;
    }
  }
  return 0;
}

/**
 * Change an archive file as the arguments say.
 *
 * @param argc Argument count.
 * @param argv See the file comment.
 * @return 0 on success, 1 on a failure, 2 on a usage error.
 */
int main(int argc, char ** argv) {
  if (argc < 2) {
    fprintf(stderr,
        "usage: %s ARCHIVE [--in-place] [-d NAME]... [-a NAME=TEXT]...\n",
        argv[0]);
    return 2;
  }
  uint32_t flags = 0;
  int deletes = 0;
  for (int i = 2; i < argc; ++i) {
    if (strcmp(argv[i], "--in-place") == 0) {
      flags |= GARC_FS_IN_PLACE;
    }
    else if ((strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "-a") == 0)
        && i + 1 < argc) {
      deletes += argv[i][1] == 'd';
      if (argv[i][1] == 'a' && !strchr(argv[i + 1], '=')) {
        fprintf(stderr, "%s: -a wants NAME=TEXT\n", argv[0]);
        return 2;
      }
      ++i;
    }
    else {
      fprintf(stderr, "%s: unknown argument %s\n", argv[0], argv[i]);
      return 2;
    }
  }
  if ((flags & GARC_FS_IN_PLACE) && deletes) {
    fprintf(stderr, "%s: deleting is a rewrite; drop --in-place\n", argv[0]);
    return 2;
  }

  GARC_Fs_Update * update = NULL;
  GARC_Result result
      = garc_fs_update_begin(argv[1], NULL, NULL, flags, &update);
  if (result != GARC_OK) {
    fprintf(stderr, "%s: %s\n", argv[1], garc_result_string(result));
    return 1;
  }

  GARC_Archive * archive = garc_fs_update_archive(update);
  unsigned kept = 0;
  unsigned dropped = 0;
  if (archive) {
    const GARC_Member * member = NULL;
    while ((result = garc_next(archive, &member)) == GARC_OK) {
      if (is_deleted(argc, argv, member)) {
        ++dropped;
        continue;
      }
      result = garc_fs_update_keep(update);
      if (result != GARC_OK) {
        fprintf(stderr, "%.*s: %s\n", (int)member->name_length, member->name,
            garc_result_string(result));
        break;
      }
      ++kept;
    }
    if (result == GARC_END) {
      result = GARC_OK;
    }
  }

  unsigned added = 0;
  for (int i = 2; result == GARC_OK && i + 1 < argc; ++i) {
    if (strcmp(argv[i], "-a") == 0) {
      const char * equals = strchr(argv[i + 1], '=');
      result = add_text(garc_fs_update_writer(update), argv[i + 1],
          (size_t)(equals - argv[i + 1]), equals + 1);
      if (result != GARC_OK) {
        fprintf(stderr, "%s: %s\n", argv[i + 1], garc_result_string(result));
      }
      ++added;
      ++i;
    }
  }

  if (result == GARC_OK) {
    result = garc_fs_update_commit(update);
    if (result != GARC_OK) {
      fprintf(stderr, "%s: %s\n", argv[1], garc_result_string(result));
    }
  }
  // Without a commit this removes the temporary file, or puts an in-place
  // archive back as it was.
  garc_fs_update_destroy(update);
  if (result != GARC_OK) {
    return 1;
  }
  if (flags & GARC_FS_IN_PLACE) {
    printf("%s: %u added in place\n", argv[1], added);
  }
  else {
    printf("%s: %u kept, %u deleted, %u added\n", argv[1], kept, dropped, added);
  }
  return 0;
}
