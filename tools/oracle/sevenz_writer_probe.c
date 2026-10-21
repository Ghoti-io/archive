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
 * The library half of `make check-sevenz-writer`: write 7z archives, and read
 * them back.
 *
 * **The bytes have to leave the process**, because whether 7-Zip and libarchive
 * accept them is a question only those programs can answer. **What went in is
 * stated separately from what came out**: `write` prints the *intent* before any
 * reference has seen an archive, and every reading is compared against it, never
 * against another reading.
 *
 * The same members are written six ways - LZMA2 solid (the default), LZMA2
 * non-solid, LZMA, bzip2, deflate and copy - so the references are asked about
 * every coder this writer produces and every archive differs from the others in
 * nothing but its encoding.
 *
 * Usage:
 *   sevenz_writer_probe write <directory>   write the archives, print intent
 *   sevenz_writer_probe read <path.7z>      print this library's reading
 *   sevenz_writer_probe append <path.7z>    add one member where the archive
 *                                           lies (::GARC_FS_IN_PLACE), print
 *                                           its row
 *
 * Each prints tab-separated rows:
 *
 *   archive name type size mtime mode link crc
 *
 * Byte-string columns are escaped as in `zip_writer_probe.c`.
 */

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ghoti.io/archive/archive.h>
#include <ghoti.io/archive/fs.h>
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

static const Entry ENTRIES[] = {
  {LIT("hello.txt"), GARC_MEMBER_FILE, LIT("hello, archive\n"), NULL, 0644,
      1000000000},
  {LIT("notes"), GARC_MEMBER_DIRECTORY, NULL, 0u, NULL, 0755, 1000000000},
  {LIT("notes/link"), GARC_MEMBER_SYMLINK, NULL, 0u, "hello.txt", 0777,
      1000000000},
  /* Zero length: an empty file, which 7z stores as an empty stream with the
   * empty-file bit, distinguishing it from a directory. */
  {LIT("empty"), GARC_MEMBER_FILE, LIT(""), NULL, 0644, 1000000000},
  {LIT("emptydir"), GARC_MEMBER_DIRECTORY, NULL, 0u, NULL, 0755, 1000000000},
  /* Compressible and longer than any buffer, so the data path loops. */
  {LIT("big.bin"), GARC_MEMBER_FILE, NULL, 0u, NULL, 0644, 1000000000},
  /* A BMP name and a non-BMP one, the latter a surrogate pair in UTF-16. */
  {LIT("na\xC3\xAFve.txt"), GARC_MEMBER_FILE, LIT("a non-ASCII name\n"), NULL,
      0644, 1000000000},
  {LIT("smile-\xF0\x9F\x98\x80.txt"), GARC_MEMBER_FILE, LIT("a surrogate pair\n"),
      NULL, 0644, 1000000000},
  /* Bytes that do not compress, so the packed size exceeds the unpacked. */
  {LIT("noise.bin"), GARC_MEMBER_FILE, NULL, 0u, NULL, 0644, 1000000000},
  /* The last 1,000 of its 41,000 bytes repeat the first 1,000: a match 40,000
   * back, beyond deflate's 32 KiB window and within deflate64's. */
  {LIT("far.bin"), GARC_MEMBER_FILE, NULL, 0u, NULL, 0644, 1000000000},
  {LIT("exec"), GARC_MEMBER_FILE, LIT("#!/bin/sh\nexit 0\n"), NULL, 0755,
      1000000000},
  {LIT("private"), GARC_MEMBER_FILE, LIT("secret\n"), NULL, 0600, 1000000000},
  {LIT("odd-second.txt"), GARC_MEMBER_FILE, LIT("odd\n"), NULL, 0644,
      1000000001},
};

#define ENTRY_COUNT (sizeof(ENTRIES) / sizeof(*ENTRIES))

static char BIG[20000];
static char NOISE[3000];
static char FAR_BIN[41000];

static void fill(void) {
  for (size_t i = 0; i < sizeof(BIG); ++i) {
    BIG[i] = (char)('a' + (i / 7) % 26);
  }
  uint32_t state = 12345u;
  for (size_t i = 0; i < sizeof(NOISE); ++i) {
    state = state * 1103515245u + 12345u;
    NOISE[i] = (char)(state >> 16);
  }
  state = 0x2468ACE1u;
  for (size_t i = 0; i < 1000u; ++i) {
    state = state * 1103515245u + 12345u;
    FAR_BIN[i] = (char)(state >> 16);
  }
  for (size_t i = 1000u; i < 40000u; ++i) {
    state = state * 1103515245u + 12345u;
    FAR_BIN[i] = (char)('a' + ((state >> 16) % 7u));
  }
  memcpy(FAR_BIN + 40000u, FAR_BIN, 1000u);
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

static GARC_Result file_patch(
    void * ctx, uint64_t offset, const void * buffer, size_t size) {
  FILE * file = (FILE *)ctx;
  const long here = ftell(file);
  if (here < 0 || offset > (uint64_t)LONG_MAX
      || fseek(file, (long)offset, SEEK_SET) != 0) {
    return GARC_ERR_IO;
  }
  if (fwrite(buffer, 1, size, file) != size) {
    return GARC_ERR_IO;
  }
  return fseek(file, here, SEEK_SET) == 0 ? GARC_OK : GARC_ERR_IO;
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

static GARC_Result seek_cb(void * ctx, uint64_t offset) {
  if (offset > (uint64_t)LONG_MAX) {
    return GARC_ERR_IO;
  }
  return fseek((FILE *)ctx, (long)offset, SEEK_SET) == 0 ? GARC_OK
                                                           : GARC_ERR_IO;
}

static GARC_Result size_cb(void * ctx, uint64_t * out_size) {
  FILE * file = (FILE *)ctx;
  const long here = ftell(file);
  if (here < 0 || fseek(file, 0, SEEK_END) != 0) {
    return GARC_ERR_IO;
  }
  const long end = ftell(file);
  if (end < 0 || fseek(file, here, SEEK_SET) != 0) {
    return GARC_ERR_IO;
  }
  *out_size = (uint64_t)end;
  return GARC_OK;
}

/**
 * The password of the encrypted archives, which check_sevenz_writer.py gives
 * 7-Zip: an accent, and U+1F600, whose surrogate pair is where a UTF-16
 * keying that disagreed with 7-Zip's would show.
 */
#define PROBE_PASSWORD "probe-p\xC3\xA4ss-\xF0\x9F\x98\x80"

static int write_one(const char * directory, const char * name,
    GARC_SevenZ_Method method, int non_solid, int encrypt, int header) {
  char path[1024];
  snprintf(path, sizeof(path), "%s/%s", directory, name);
  FILE * file = fopen(path, "wb");
  if (!file) {
    fprintf(stderr, "cannot write %s\n", path);
    return 1;
  }
  GARC_Sink_Callbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.write = file_write;
  callbacks.patch = file_patch;
  callbacks.ctx = file;
  GARC_Sink * sink = NULL;
  GARC_Result result = garc_sink_create_callback(&callbacks, &sink);
  if (result != GARC_OK) {
    fprintf(stderr, "%s: sink: %s\n", name, garc_result_string(result));
    fclose(file);
    return 1;
  }
  GARC_Writer_Options options;
  garc_writer_options_default(&options);
  options.sevenz_method = method;
  options.sevenz_non_solid = non_solid;
  if (encrypt) {
    /* 7-Zip's own cost, so the archive is what 7-Zip itself would write. */
    options.password = PROBE_PASSWORD;
    options.password_length = sizeof(PROBE_PASSWORD) - 1u;
    options.sevenz_encrypt_header = header;
  }
  GARC_Writer * writer = NULL;
  result = garc_writer_create(sink, GARC_FORMAT_SEVENZ, &options, &writer);
  if (result != GARC_OK) {
    fprintf(stderr, "%s: writer: %s\n", name, garc_result_string(result));
    garc_sink_destroy(sink);
    fclose(file);
    return 1;
  }
  for (size_t i = 0; i < ENTRY_COUNT; ++i) {
    const Entry * entry = &ENTRIES[i];
    const char * data = entry->data;
    size_t data_length = entry->data_length;
    if (strcmp(entry->name, "big.bin") == 0) {
      data = BIG;
      data_length = sizeof(BIG);
    }
    else if (strcmp(entry->name, "far.bin") == 0) {
      data = FAR_BIN;
      data_length = sizeof(FAR_BIN);
    }
    else if (strcmp(entry->name, "noise.bin") == 0) {
      data = NOISE;
      data_length = sizeof(NOISE);
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
    member.mtime_source = GARC_TIME_FILETIME;
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
  GARC_Stream_Callbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.ctx = file;
  callbacks.read = read_cb;
  callbacks.seek = seek_cb;
  callbacks.size = size_cb;
  GARC_Stream * stream = NULL;
  GARC_Archive * archive = NULL;
  GARC_Result result = garc_stream_create_callback(&callbacks, &stream);
  if (result == GARC_OK) {
    result = garc_open(stream, NULL, &archive);
  }
  if (result == GARC_OK) {
    /* Harmless on an archive with nothing encrypted; needed on the others,
       and on an encrypted header it is what decodes the member list. */
    result = garc_set_password(
        archive, PROBE_PASSWORD, sizeof(PROBE_PASSWORD) - 1u);
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
    const char * link = member->link_target;
    size_t link_length = member->link_target_length;
    if (member->type == GARC_MEMBER_SYMLINK) {
      total = link_length;
      crc = gcomp_crc32_update(GCOMP_CRC32_INIT, (const uint8_t *)link,
          link_length);
    }
    print_row(path, member->name, member->name_length,
        type_name(member->type), total, member->mtime_seconds,
        member->mode & 07777u, link, link_length, gcomp_crc32_finalize(crc));
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

/**
 * Append one member to the 7z at @p path where it lies (::GARC_FS_IN_PLACE),
 * and print its row as `write` prints the intent.
 */
static int do_append(const char * path) {
  static const char NAME[] = "appended/by-the-probe.txt";
  static const char DATA[] = "appended in place by sevenz_writer_probe\n";
  GARC_Fs_Update * update = NULL;
  GARC_Result result = garc_fs_update_begin(path, NULL, NULL,
      GARC_FS_IN_PLACE | GARC_FS_NO_SYNC, &update);
  if (result == GARC_OK) {
    GARC_Member member;
    memset(&member, 0, sizeof(member));
    member.name = NAME;
    member.name_length = sizeof(NAME) - 1u;
    member.type = GARC_MEMBER_FILE;
    member.size = sizeof(DATA) - 1u;
    member.mode = 0640;
    member.mode_valid = 1;
    member.mtime_seconds = 1234567890;
    member.mtime_source = GARC_TIME_FILETIME;
    GARC_Writer * writer = garc_fs_update_writer(update);
    result = garc_writer_add(writer, &member);
    if (result == GARC_OK) {
      result = garc_writer_write(writer, DATA, sizeof(DATA) - 1u);
    }
  }
  if (result == GARC_OK) {
    result = garc_fs_update_commit(update);
  }
  garc_fs_update_destroy(update);
  if (result != GARC_OK) {
    fprintf(stderr, "%s: append: %s\n", path, garc_result_string(result));
    return 1;
  }
  const uint32_t crc = gcomp_crc32_finalize(gcomp_crc32_update(
      GCOMP_CRC32_INIT, (const uint8_t *)DATA, sizeof(DATA) - 1u));
  print_row(path, NAME, sizeof(NAME) - 1u, "file", sizeof(DATA) - 1u,
      1234567890, 0640, NULL, 0u, crc);
  return 0;
}

static const struct {
  const char * name;
  GARC_SevenZ_Method method;
  int non_solid;
  int encrypt;
  int header;
} ARCHIVES[] = {
  {"lzma2.7z", GARC_SEVENZ_LZMA2, 0, 0, 0},
  {"lzma2-nonsolid.7z", GARC_SEVENZ_LZMA2, 1, 0, 0},
  {"lzma.7z", GARC_SEVENZ_LZMA, 0, 0, 0},
  {"bzip2.7z", GARC_SEVENZ_BZIP2, 0, 0, 0},
  {"deflate.7z", GARC_SEVENZ_DEFLATE, 0, 0, 0},
  {"deflate64.7z", GARC_SEVENZ_DEFLATE64, 0, 0, 0},
  {"copy.7z", GARC_SEVENZ_COPY, 0, 0, 0},
  {"aes.7z", GARC_SEVENZ_LZMA2, 0, 1, 0},
  {"aes-header.7z", GARC_SEVENZ_LZMA2, 0, 1, 1},
  {"aes-copy-nonsolid.7z", GARC_SEVENZ_COPY, 1, 1, 0},
};

int main(int argc, char ** argv) {
  fill();
  if (argc == 3 && strcmp(argv[1], "write") == 0) {
    for (size_t i = 0; i < sizeof(ARCHIVES) / sizeof(*ARCHIVES); ++i) {
      if (write_one(argv[2], ARCHIVES[i].name, ARCHIVES[i].method,
              ARCHIVES[i].non_solid, ARCHIVES[i].encrypt,
              ARCHIVES[i].header)) {
        return 1;
      }
    }
    return 0;
  }
  if (argc == 3 && strcmp(argv[1], "read") == 0) {
    return do_read(argv[2]);
  }
  if (argc == 3 && strcmp(argv[1], "append") == 0) {
    return do_append(argv[2]);
  }
  fprintf(stderr,
      "usage: %s write <directory> | read <path.7z> | append <path.7z>\n",
      argv[0]);
  return 2;
}
