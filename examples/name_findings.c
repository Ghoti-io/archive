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
 * Refuse a hostile archive before reading any of it, and say why.
 *
 * The shape a caller wants when it is deciding whether to *accept* an archive at
 * all: walk the members, classify every name and every link target, print what is
 * wrong, and exit non-zero if anything is. It reads no member data, so an archive
 * can be judged for the cost of its headers.
 *
 * Three things this shows that a shorter example would not:
 *
 * **A link target is checked as well as a name.** They are equally dangerous and
 * ::garc_name_check() takes bytes, so it is the same call twice.
 *
 * **Refusing is the caller's policy, not the library's.** This program refuses on
 * ::GARC_NAME_ESCAPES and merely reports ::GARC_NAME_PORTABILITY, because it is
 * pretending to extract on a POSIX host. A program writing to a Windows
 * filesystem would add the Windows findings to the first set. The library
 * publishes the two masks and neither decides for you.
 *
 * **Passing is not permission.** Said in the output, because it is the thing a
 * reader of this example is most likely to get wrong: a name with no findings
 * still escapes any root you like if an earlier member made one of its
 * directories a symlink. That is the resolved-path check, and it belongs in the
 * extraction layer.
 *
 * Usage: name_findings <path.tar>
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
 * This program's policy: which findings are a reason to refuse an archive.
 *
 * ::GARC_NAME_ESCAPES is the library's set for "names somewhere a root does not
 * contain". Added to it here: an empty name and one with a NUL in it, which are in
 * neither published mask because they are not path questions - they are names that
 * cannot be used at all, whatever the extraction policy is.
 *
 * Not added: the Windows findings, because this program is pretending to extract
 * on a POSIX host. One writing to a Windows filesystem would add
 * ::GARC_NAME_WINDOWS_TRAVERSAL, ::GARC_NAME_WINDOWS_RESERVED and
 * ::GARC_NAME_TRAILING_DOT_OR_SPACE, and that is the decision the library leaves
 * to a caller rather than making for it.
 */
#define REFUSING_FINDINGS                                                      \
  (GARC_NAME_ESCAPES | GARC_NAME_EMPTY | GARC_NAME_NUL_BYTE)

/**
 * Print one string's findings, and hand back the mask so the caller can decide.
 *
 * Returning the findings rather than a verdict is the same separation the library
 * makes: this function says what is there, and main() applies the policy.
 *
 * @param what "name" or "target", for the message.
 * @param bytes The string.
 * @param length Its length.
 * @return The findings, so nothing has to classify the same bytes twice.
 */
static uint32_t report(const char * what, const char * bytes, size_t length) {
  const uint32_t findings = garc_name_check(bytes, length);
  if (!findings) {
    return 0;
  }
  printf("  %s ", what);
  print_escaped(bytes, length);
  putchar('\n');
  for (uint32_t bit = 1u; bit <= GARC_NAME_FINDING_ALL; bit <<= 1) {
    if (findings & bit) {
      printf("    %s %s\n", (bit & REFUSING_FINDINGS) ? "REFUSE" : "note  ",
          garc_name_finding_string((GARC_Name_Finding)bit));
    }
  }
  return findings;
}

/**
 * Report what ::garc_name_check() finds about every member name in an archive.
 *
 * @param argc Argument count.
 * @param argv `argv[1]` is the archive to read.
 * @return 0 when nothing in the archive would be refused, 1 when something
 *   would, and 2 on a usage error.
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

  // No seek and no size: judging an archive needs neither, so this works on a
  // pipe - which is the point at which you most want to refuse it.
  GARC_Stream_Callbacks callbacks = {.read = file_read, .ctx = file};
  GARC_Stream * stream = NULL;
  if (garc_stream_create_callback(&callbacks, &stream) != GARC_OK) {
    fclose(file);
    return 1;
  }

  GARC_Archive * archive = NULL;
  GARC_Result result = garc_open(stream, NULL, &archive);
  if (result != GARC_OK) {
    fprintf(stderr, "%s: %s\n", argv[1], garc_result_string(result));
    garc_stream_destroy(stream);
    fclose(file);
    return 1;
  }

  uint64_t members = 0;
  uint64_t flagged = 0;
  int refuse = 0;
  const GARC_Member * member = NULL;
  while ((result = garc_next(archive, &member)) == GARC_OK) {
    members++;
    uint32_t findings = report("name  ", member->name, member->name_length);
    if (member->link_target) {
      findings |= report(
          "target", member->link_target, member->link_target_length);
    }
    if (findings) {
      flagged++;
    }
    if (findings & REFUSING_FINDINGS) {
      refuse = 1;
    }
  }

  if (garc_result_is_error(result)) {
    fprintf(stderr, "%s: %s after %" PRIu64 " members\n", argv[1],
        garc_result_string(result), members);
    garc_close(archive);
    garc_stream_destroy(stream);
    fclose(file);
    return 1;
  }

  printf("%s: %" PRIu64 " members, %" PRIu64 " with findings\n", argv[1],
      members, flagged);
  if (refuse) {
    printf("REFUSED: something in this archive names a place outside a root\n");
  } else {
    printf("no refusing findings - which is **not** permission to extract:\n"
           "a name with none of these still escapes if an earlier member made\n"
           "one of its directories a symlink. Resolve as you create.\n");
  }

  garc_close(archive);
  garc_stream_destroy(stream);
  fclose(file);
  return refuse ? 1 : 0;
}
