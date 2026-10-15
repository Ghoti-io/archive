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
 * The library half of `make check-arcpio-writer`: write ar, cpio and shar, and
 * read the first two back.
 *
 * As for the other writers, **the bytes have to leave the process** - whether
 * libarchive, 7-Zip and `sh` accept them is a question only they can answer - and
 * **what went in is stated separately from what came out**: `write` prints the
 * intent before any reference has seen a byte.
 *
 * Usage:
 *   arcpio_writer_probe write <directory>   write the archives, print intent
 *   arcpio_writer_probe read <path>         print this library's reading
 *
 * Rows: archive name type size mtime mode link crc, byte strings escaped as in
 * `zip_writer_probe.c`.
 */

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ghoti.io/archive/archive.h>
#include <ghoti.io/compress/crc32.h>

typedef struct {
  const char * name;
  size_t name_length;
  GARC_Member_Type type;
  const char * data;
  size_t data_length;
  const char * link;
  uint32_t mode;
  int64_t mtime;
} Entry;

#define LIT(s) (s), (sizeof(s) - 1u)

static const Entry AR_ENTRIES[] = {
  {LIT("a.txt"), GARC_MEMBER_FILE, LIT("first\n"), NULL, 0644, 1000000000},
  {LIT("fifteen-chars-x"), GARC_MEMBER_FILE, LIT("15\n"), NULL, 0644, 1000000000},
  {LIT("sixteen-chars-xy"), GARC_MEMBER_FILE, LIT("16\n"), NULL, 0644, 1000000000},
  {LIT("long-name-beyond-sixteen-bytes.txt"), GARC_MEMBER_FILE, LIT("long\n"),
      NULL, 0644, 1000000000},
  {LIT("name with spaces.txt"), GARC_MEMBER_FILE, LIT("spaces\n"), NULL, 0644,
      1000000000},
  {LIT("odd"), GARC_MEMBER_FILE, LIT("odd"), NULL, 0644, 1000000000},
  {LIT("even"), GARC_MEMBER_FILE, LIT("even"), NULL, 0755, 1000000000},
  {LIT("empty"), GARC_MEMBER_FILE, LIT(""), NULL, 0644, 1000000000},
  {LIT("big.bin"), GARC_MEMBER_FILE, NULL, 0u, NULL, 0600, 1000000000},
  {LIT("odd-second"), GARC_MEMBER_FILE, LIT("x\n"), NULL, 0644, 1000000001},
};

static const Entry TREE_ENTRIES[] = {
  {LIT("hello.txt"), GARC_MEMBER_FILE, LIT("hello, archive\n"), NULL, 0644,
      1000000000},
  {LIT("dir"), GARC_MEMBER_DIRECTORY, NULL, 0u, NULL, 0755, 1000000000},
  {LIT("dir/nested.txt"), GARC_MEMBER_FILE, LIT("nested\n"), NULL, 0644,
      1000000000},
  {LIT("dir/link"), GARC_MEMBER_SYMLINK, NULL, 0u, "../hello.txt", 0777,
      1000000000},
  {LIT("empty.txt"), GARC_MEMBER_FILE, LIT(""), NULL, 0644, 1000000000},
  /* Every length mod 4, and each ends in a newline because the text shar
   * cannot carry data that does not. */
  {LIT("s2"), GARC_MEMBER_FILE, LIT("2\n"), NULL, 0644, 1000000000},
  {LIT("s3"), GARC_MEMBER_FILE, LIT("33\n"), NULL, 0644, 1000000000},
  {LIT("s4"), GARC_MEMBER_FILE, LIT("444\n"), NULL, 0644, 1000000000},
  {LIT("s5"), GARC_MEMBER_FILE, LIT("5555\n"), NULL, 0644, 1000000000},
  {LIT("exec.sh"), GARC_MEMBER_FILE, LIT("#!/bin/sh\nexit 0\n"), NULL, 0755,
      1000000000},
  {LIT("it's quoted.txt"), GARC_MEMBER_FILE, LIT("quotes\n"), NULL, 0644,
      1000000000},
  {LIT("big.bin"), GARC_MEMBER_FILE, NULL, 0u, NULL, 0644, 1000000000},
};

/* cpio can also carry a fifo; shar and ar cannot. */
static const Entry CPIO_EXTRA = {LIT("fifo"), GARC_MEMBER_FIFO, NULL, 0u, NULL,
    0644, 1000000000};

static const Entry UU_ENTRIES[] = {
  {LIT("binary.bin"), GARC_MEMBER_FILE, NULL, 0u, NULL, 0644, 1000000000},
  {LIT("text.txt"), GARC_MEMBER_FILE, LIT("text\n"), NULL, 0644, 1000000000},
  {LIT("no-newline"), GARC_MEMBER_FILE, LIT("tail"), NULL, 0644, 1000000000},
};

static char BIG[5000];
static char BINARY[300];

static void fill(void) {
  for (size_t i = 0; i < sizeof(BIG); ++i) {
    BIG[i] = (char)('a' + (i / 9) % 26);
    if (i % 61 == 60) {
      BIG[i] = '\n';
    }
  }
  BIG[sizeof(BIG) - 1u] = '\n';
  for (size_t i = 0; i < sizeof(BINARY); ++i) {
    BINARY[i] = (char)(i * 7u);
  }
}

static void print_escaped(const char * bytes, size_t length) {
  for (size_t i = 0; i < length; ++i) {
    const unsigned char byte = (unsigned char)bytes[i];
    if (byte == '\\') {
      fputs("\\\\", stdout);
    }
    else if (byte >= 0x20u && byte < 0x7Fu) {
      putchar((int)byte);
    }
    else {
      printf("\\x%02X", (unsigned)byte);
    }
  }
}

static const char * type_name(GARC_Member_Type type) {
  switch (type) {
    case GARC_MEMBER_FILE:
      return "file";
    case GARC_MEMBER_DIRECTORY:
      return "directory";
    case GARC_MEMBER_SYMLINK:
      return "symlink";
    case GARC_MEMBER_FIFO:
      return "fifo";
    default:
      return "other";
  }
}

static void print_row(const char * archive, const char * name,
    size_t name_length, const char * type, uint64_t size, int64_t mtime,
    uint32_t mode, const char * link, size_t link_length, uint32_t crc) {
  printf("%s\t", archive);
  print_escaped(name, name_length);
  printf("\t%s\t%" PRIu64 "\t%" PRId64 "\t%04o\t", type, size, mtime, mode);
  print_escaped(link ? link : "", link_length);
  printf("\t%08" PRIx32 "\n", crc);
}

static GARC_Result file_write(void * ctx, const void * buffer, size_t size) {
  return fwrite(buffer, 1, size, (FILE *)ctx) == size ? GARC_OK : GARC_ERR_IO;
}

static GARC_Result read_cb(
    void * ctx, void * buffer, size_t size, size_t * out_read) {
  FILE * file = (FILE *)ctx;
  const size_t got = fread(buffer, 1, size, file);
  if (got < size && ferror(file)) {
    return GARC_ERR_IO;
  }
  *out_read = got;
  return GARC_OK;
}

static int write_one(const char * directory, const char * name,
    GARC_Format format, GARC_Cpio_Variant variant, int uu,
    const Entry * entries, size_t count, int with_fifo) {
  char path[1024];
  snprintf(path, sizeof(path), "%s/%s", directory, name);
  FILE * file = fopen(path, "wb");
  if (!file) {
    fprintf(stderr, "cannot write %s\n", path);
    return 1;
  }
  /* No patch callback: none of these formats may need one. */
  GARC_Sink_Callbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.write = file_write;
  callbacks.ctx = file;
  GARC_Sink * sink = NULL;
  GARC_Result result = garc_sink_create_callback(&callbacks, &sink);
  GARC_Writer * writer = NULL;
  if (result == GARC_OK) {
    GARC_Writer_Options options;
    garc_writer_options_default(&options);
    options.cpio_variant = variant;
    options.shar_uuencode = uu;
    result = garc_writer_create(sink, format, &options, &writer);
  }
  if (result != GARC_OK) {
    fprintf(stderr, "%s: %s\n", name, garc_result_string(result));
    garc_sink_destroy(sink);
    fclose(file);
    return 1;
  }
  for (size_t i = 0; result == GARC_OK && i <= count; ++i) {
    const Entry * entry = i < count ? &entries[i] : (with_fifo ? &CPIO_EXTRA : NULL);
    if (!entry) {
      break;
    }
    const char * data = entry->data;
    size_t data_length = entry->data_length;
    if (strcmp(entry->name, "big.bin") == 0) {
      data = BIG;
      data_length = sizeof(BIG);
    }
    else if (strcmp(entry->name, "binary.bin") == 0) {
      data = BINARY;
      data_length = sizeof(BINARY);
    }
    GARC_Member member;
    memset(&member, 0, sizeof(member));
    member.name = entry->name;
    member.name_length = entry->name_length;
    member.type = entry->type;
    member.size = entry->type == GARC_MEMBER_FILE ? data_length : 0u;
    member.mode = entry->mode;
    member.mode_valid = 1;
    member.mtime_seconds = entry->mtime;
    member.mtime_source = GARC_TIME_UNIX;
    if (entry->link) {
      member.link_target = entry->link;
      member.link_target_length = strlen(entry->link);
    }
    result = garc_writer_add(writer, &member);
    if (result == GARC_OK && member.size) {
      result = garc_writer_write(writer, data, data_length);
    }
    if (result != GARC_OK) {
      fprintf(stderr, "%s: %s: %s\n", name, entry->name,
          garc_result_string(result));
      break;
    }
    const char * content = data;
    uint64_t size = member.size;
    if (entry->type == GARC_MEMBER_SYMLINK) {
      content = entry->link;
      size = (uint64_t)strlen(entry->link);
    }
    const uint32_t crc = gcomp_crc32_finalize(gcomp_crc32_update(
        GCOMP_CRC32_INIT, (const uint8_t *)(content ? content : ""),
        (size_t)size));
    print_row(name, entry->name, entry->name_length, type_name(entry->type),
        size, entry->mtime, entry->mode, entry->link,
        entry->link ? strlen(entry->link) : 0u, crc);
  }
  if (result == GARC_OK) {
    result = garc_writer_finish(writer);
  }
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
  fclose(file);
  if (result != GARC_OK) {
    fprintf(stderr, "%s: %s\n", name, garc_result_string(result));
    return 1;
  }
  return 0;
}

static int do_read(const char * path) {
  FILE * file = fopen(path, "rb");
  if (!file) {
    fprintf(stderr, "cannot read %s\n", path);
    return 1;
  }
  /* A pipe's shape: no seek, no size. */
  GARC_Stream_Callbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.ctx = file;
  callbacks.read = read_cb;
  GARC_Stream * stream = NULL;
  GARC_Archive * archive = NULL;
  GARC_Result result = garc_stream_create_callback(&callbacks, &stream);
  if (result == GARC_OK) {
    result = garc_open(stream, NULL, &archive);
  }
  if (result != GARC_OK) {
    fprintf(stderr, "%s: open: %s\n", path, garc_result_string(result));
    garc_stream_destroy(stream);
    fclose(file);
    return 1;
  }
  const GARC_Member * member = NULL;
  while ((result = garc_next(archive, &member)) == GARC_OK) {
    uint32_t crc = GCOMP_CRC32_INIT;
    uint64_t total = 0;
    uint8_t buffer[4096];
    size_t got = 0;
    GARC_Result read = GARC_OK;
    while ((read = garc_read_member(archive, buffer, sizeof(buffer), &got))
            == GARC_OK
        && got) {
      crc = gcomp_crc32_update(crc, buffer, got);
      total += got;
    }
    if (read != GARC_OK) {
      fprintf(stderr, "%s: read: %s\n", path, garc_result_string(read));
      result = read;
      break;
    }
    if (member->type == GARC_MEMBER_SYMLINK) {
      total = member->link_target_length;
      crc = gcomp_crc32_update(GCOMP_CRC32_INIT,
          (const uint8_t *)member->link_target, member->link_target_length);
    }
    print_row(path, member->name, member->name_length,
        type_name(member->type), total, member->mtime_seconds,
        member->mode & 07777u, member->link_target,
        member->link_target_length, gcomp_crc32_finalize(crc));
  }
  garc_close(archive);
  garc_stream_destroy(stream);
  fclose(file);
  if (result != GARC_END) {
    fprintf(stderr, "%s: walk: %s\n", path, garc_result_string(result));
    return 1;
  }
  return 0;
}

#define COUNT(a) (sizeof(a) / sizeof(*(a)))

int main(int argc, char ** argv) {
  fill();
  if (argc == 3 && strcmp(argv[1], "write") == 0) {
    const char * d = argv[2];
    return write_one(d, "files.a", GARC_FORMAT_AR, GARC_CPIO_NEWC, 0, AR_ENTRIES,
               COUNT(AR_ENTRIES), 0)
        || write_one(d, "newc.cpio", GARC_FORMAT_CPIO, GARC_CPIO_NEWC, 0,
               TREE_ENTRIES, COUNT(TREE_ENTRIES), 1)
        || write_one(d, "odc.cpio", GARC_FORMAT_CPIO, GARC_CPIO_ODC, 0,
               TREE_ENTRIES, COUNT(TREE_ENTRIES), 1)
        || write_one(d, "text.shar", GARC_FORMAT_SHAR, GARC_CPIO_NEWC, 0,
               TREE_ENTRIES, COUNT(TREE_ENTRIES), 0)
        || write_one(d, "uu.shar", GARC_FORMAT_SHAR, GARC_CPIO_NEWC, 1,
               UU_ENTRIES, COUNT(UU_ENTRIES), 0);
  }
  if (argc == 3 && strcmp(argv[1], "read") == 0) {
    return do_read(argv[2]);
  }
  fprintf(stderr, "usage: %s write <directory> | read <path>\n", argv[0]);
  return 2;
}
