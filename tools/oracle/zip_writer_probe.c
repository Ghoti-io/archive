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
 * The library half of `make check-zip-writer`: write zips, and read them back.
 *
 * The same three reasons `writer_probe.c` exists, and one more that is zip's:
 *
 * **The bytes have to leave the process**, because whether unzip, bsdtar, 7-Zip
 * and Python accept them is a question only those programs can answer.
 *
 * **What went in is stated separately from what came out.** The table below is
 * the *intent*, printed in `write` mode before any reference has seen an archive.
 * Every later reading is compared against it, never against another reading - a
 * gate that compared our reading to theirs would pass whenever both were wrong
 * the same way.
 *
 * **`read` mode prints this library's reading in the same shape**, so the gate can
 * point it at what a reference re-wrote.
 *
 * **And the same members are written three ways.** A zip member's CRC and
 * compressed size go either in a data descriptor or in the local header, and this
 * writer produces both plus a forced-zip64 variant - so the gate asks the
 * references about three encodings of one archive and requires the same answer.
 * That is the phase's own requirement, and it cannot be checked on this machine
 * alone: the reader here deliberately ignores the local header's sizes, so it
 * reads all three identically whether they are right or not.
 *
 * Usage:
 *   zip_writer_probe write <directory>   write the archives, print intent rows
 *   zip_writer_probe read <path.zip>     print this library's reading of one
 *   zip_writer_probe describe            what each archive is for, one per line
 *
 * The first two print tab-separated rows in one shape:
 *
 *   archive index name type size mtime mode linkname method crc
 *
 * **The `crc` column is the CRC-32 of the data the probe *means* to write**, not
 * the one the writer computed - so a reference's reported CRC is compared against
 * the intent like every other column. What that checks is the plumbing: whether
 * the right checksum reached the right member's records. Whether the value itself
 * describes the bytes is a different question, and Python's `testzip()` answers it
 * by recomputing every one of them.
 *
 * The byte-string columns are escaped the way `make_zip_corpus.py`'s `escape()`
 * escapes them. That is one rule written twice in two languages, and what stops it
 * drifting is that the table below contains a backslash, a byte above 0x7F and a
 * byte that is not well-formed UTF-8 - so every branch of both spellings runs on
 * every invocation of this gate.
 */

#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ghoti.io/archive/archive.h>
#include <ghoti.io/compress/crc32.h>

/** A member to write, and therefore also a row of expectations. */
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

/**
 * The members every archive holds.
 *
 * One table for every archive, so that the three encodings differ in nothing but
 * their encoding - which is what makes "all three read the same" a statement about
 * the writer rather than about three different inputs.
 */
static const Entry ENTRIES[] = {
  {LIT("hello.txt"), GARC_MEMBER_FILE, LIT("hello, archive\n"), NULL, 0644,
      1000000000},
  {LIT("notes/"), GARC_MEMBER_DIRECTORY, NULL, 0u, NULL, 0755, 1000000000},
  {LIT("notes/link"), GARC_MEMBER_SYMLINK, NULL, 0u, "hello.txt", 0777,
      1000000000},
  /* Zero length, where a reader that seeks by size lands on the next header
   * whether its arithmetic is right or not. */
  {LIT("empty"), GARC_MEMBER_FILE, LIT(""), NULL, 0644, 1000000000},
  /* Longer than one buffer of most readers, so the data path loops. */
  {LIT("big.bin"), GARC_MEMBER_FILE, NULL, 0u, NULL, 0644, 1000000000},
  /* A name that is not ASCII, which is what makes the UTF-8 flag mean
   * something, and a name with a backslash in it, which libarchive treats as a
   * separator for a zip member and the other references do not. */
  {LIT("na\xC3\xAFve.txt"), GARC_MEMBER_FILE, LIT("a non-ASCII name\n"), NULL,
      0644, 1000000000},
  {LIT("back\\slash.txt"), GARC_MEMBER_FILE, LIT("a backslash\n"), NULL, 0644,
      1000000000},
  /* Not well-formed UTF-8, which is the name the writer must not flag as UTF-8
   * even though it has a high byte in it. */
  {LIT("bad\x80utf.txt"), GARC_MEMBER_FILE, LIT("raw bytes\n"), NULL, 0644,
      1000000000},
  /* An odd second, which the MS-DOS field cannot hold, so this is the member the
   * writer adds an extended timestamp to. */
  {LIT("odd-second.txt"), GARC_MEMBER_FILE, LIT("odd\n"), NULL, 0644,
      1000000001},
  /* Bytes deflate cannot shrink, so this is the member whose *compressed* size
   * is larger than its uncompressed one in the deflated archives - which is a
   * shape a reader's arithmetic can get wrong and the stored archives cannot
   * produce. */
  {LIT("noise.bin"), GARC_MEMBER_FILE, NULL, 0u, NULL, 0644, 1000000000},
  /* Modes the high half of external_file_attributes has to carry intact. */
  {LIT("setuid"), GARC_MEMBER_FILE, LIT("root\n"), NULL, 04755, 1000000000},
  {LIT("noperms"), GARC_MEMBER_FILE, LIT("none\n"), NULL, 0000, 1000000000},
};

#define ENTRY_COUNT (sizeof(ENTRIES) / sizeof(*ENTRIES))

/** `big.bin`'s contents, built rather than spelled. */
static char BIG[3000];

/**
 * `noise.bin`'s contents: bytes deflate cannot shrink.
 *
 * A linear congruential generator, so the same bytes come out on every host and
 * the intent rows are reproducible. Not cryptographic and it does not need to be -
 * it needs no runs and no skewed byte frequency, which is what defeats both halves
 * of deflate.
 */
static char NOISE[3000];

/**
 * **Nine encodings of one member list**, which is what the gate compares against
 * each other and against the references.
 *
 * The encodings differ in nothing but their encoding, which is what makes "all
 * seven read the same" a statement about the writer rather than about seven
 * different inputs. `pipe.zip` is the streaming form reached the way a caller
 * reaches it by accident - a sink with no `patch`, which is what a socket is -
 * and it must come out identical to asking for descriptors outright. `aes.zip`
 * is the same stored members with a password, written as WinZip AES.
 */
static const struct {
  const char * name;
  GARC_Zip_Sizes sizes;
  int patchable;
  int force_zip64;
  GARC_Zip_Method method;
  int aes;
  const char * purpose;
} ARCHIVES[] = {
  {"local.zip", GARC_ZIP_SIZES_LOCAL, 1, 0, GARC_ZIP_METHOD_STORED, 0,
      "sizes and CRC filled into each local header, which needs a patchable sink"},
  {"descriptor.zip", GARC_ZIP_SIZES_DESCRIPTOR, 1, 0, GARC_ZIP_METHOD_STORED, 0,
      "sizes and CRC in a data descriptor after each member, flag bit 3 set"},
  {"pipe.zip", GARC_ZIP_SIZES_AUTO, 0, 0, GARC_ZIP_METHOD_STORED, 0,
      "the same descriptors, reached by a sink that cannot patch rather than by "
      "asking"},
  {"zip64.zip", GARC_ZIP_SIZES_LOCAL, 1, 1, GARC_ZIP_METHOD_STORED, 0,
      "zip64 fields on every member plus a zip64 end record and locator"},
  // **Deflate, both ways the sizes can be written**, because those are the two
  // places a compressed size goes and it is a different number from the
  // uncompressed one in both. A stored archive cannot tell them apart: its two
  // sizes are the same number, so a writer that put the wrong one in the local
  // header would pass every stored archive here.
  {"deflate.zip", GARC_ZIP_SIZES_LOCAL, 1, 0, GARC_ZIP_METHOD_DEFLATE, 0,
      "deflated members with the compressed size patched into each local header"},
  {"deflate-descriptor.zip", GARC_ZIP_SIZES_DESCRIPTOR, 1, 0,
      GARC_ZIP_METHOD_DEFLATE, 0,
      "deflated members with the compressed size in a data descriptor"},
  {"aes.zip", GARC_ZIP_SIZES_LOCAL, 1, 0, GARC_ZIP_METHOD_STORED, 1,
      "the stored members, encrypted with WinZip AES and the corpus password"},
  // **One zstd archive and one LZMA archive.** unzip is not asked about either.
  // 7-Zip is. Python is asked about the LZMA archive only when it accepts the
  // bytes, and it is not asked about zstd. The same exception aes.zip already
  // has, with that one difference.
  {"zstd.zip", GARC_ZIP_SIZES_LOCAL, 1, 0, GARC_ZIP_METHOD_ZSTD, 0,
      "zstd members, method 93, a bare frame"},
  {"lzma.zip", GARC_ZIP_SIZES_LOCAL, 1, 0, GARC_ZIP_METHOD_LZMA, 0,
      "LZMA members, method 14, version 0x0119, an end marker, bit 1 set"},
};

/** The password `aes.zip` is written and read with. The corpus uses the same one. */
static const char AES_PASSWORD[] = "ghoti-password";

#define ARCHIVE_COUNT (sizeof(ARCHIVES) / sizeof(*ARCHIVES))

/** Print bytes the way make_zip_corpus.py's escape() prints them. */
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

/** The vocabulary the gate's other columns use for a type. */
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

/** Print one row. The columns are the file comment's. */
static void print_row(const char * archive, size_t index, const char * name,
    size_t name_length, const char * type, uint64_t size, int64_t mtime,
    uint32_t mode, const char * link, size_t link_length, uint16_t method,
    uint32_t crc) {
  printf("%s\t%zu\t", archive, index);
  print_escaped(name, name_length);
  printf("\t%s\t%" PRIu64 "\t%" PRId64 "\t%04o\t", type, size, mtime, mode);
  print_escaped(link ? link : "", link_length);
  printf("\t%u\t%08" PRIx32 "\n", (unsigned)method, crc);
}

static GARC_Result file_write(void * ctx, const void * buffer, size_t size) {
  FILE * file = (FILE *)ctx;
  return fwrite(buffer, 1, size, file) == size ? GARC_OK : GARC_ERR_IO;
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
  FILE * file = (FILE *)ctx;
  if (offset > (uint64_t)LONG_MAX) {
    return GARC_ERR_IO;
  }
  return fseek(file, (long)offset, SEEK_SET) == 0 ? GARC_OK : GARC_ERR_IO;
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
 * Write one archive, and print the intent rows for it.
 *
 * @param directory Where to put it.
 * @param name The archive's file name.
 * @param sizes Which size discipline to use.
 * @param patchable Whether to offer the sink a `patch` callback.
 * @param force_zip64 Whether to force zip64 fields.
 * @param method Which method to write the members with.
 * @param aes Whether to encrypt with WinZip AES. A directory stays in the clear.
 * @return 0 on success.
 */
static int write_one(const char * directory, const char * name,
    GARC_Zip_Sizes sizes, int patchable, int force_zip64,
    GARC_Zip_Method method, int aes) {
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
  callbacks.ctx = file;
  if (patchable) {
    callbacks.patch = file_patch;
  }

  GARC_Sink * sink = NULL;
  GARC_Result result = garc_sink_create_callback(&callbacks, &sink);
  if (result != GARC_OK) {
    fprintf(stderr, "%s: sink: %s\n", name, garc_result_string(result));
    fclose(file);
    return 1;
  }

  GARC_Writer_Options options;
  garc_writer_options_default(&options);
  options.zip_sizes = sizes;
  options.zip_force_zip64 = force_zip64;
  options.zip_method = method;
  if (aes) {
    options.zip_password = AES_PASSWORD;
    options.zip_password_length = sizeof(AES_PASSWORD) - 1u;
  }
  GARC_Writer * writer = NULL;
  result = garc_writer_create(sink, GARC_FORMAT_ZIP, &options, &writer);
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
    member.mtime_source = GARC_TIME_ZIP_DOS;
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

    // The intent row. A symlink's size is its target's length, because the
    // target IS the data - which is the one place this writer puts bytes in a
    // member the caller did not hand it.
    const char * content = data;
    uint64_t size = member.size;
    if (entry->type == GARC_MEMBER_SYMLINK) {
      content = entry->link;
      size = (uint64_t)strlen(entry->link);
    }
    const uint32_t crc = gcomp_crc32_finalize(gcomp_crc32_update(
        GCOMP_CRC32_INIT, (const uint8_t *)(content ? content : ""),
        (size_t)size));
    // **The method the writer is expected to have used**, which is the archive's
    // except where the writer's own rules override it: a member with no data is
    // stored, and so is a symlink. Spelled here rather than read back out of the
    // archive, because that is what makes this an intent row - a probe that asked
    // the archive would agree with it whatever the writer did.
    //
    // AES writes method 99 and a CRC of 0 for everything except a directory.
    // The real method stays in 0x9901, and AE-2 does not store the data CRC.
    const int encrypt = aes && entry->type != GARC_MEMBER_DIRECTORY;
    const uint16_t expect = encrypt ? (uint16_t)GARC_ZIP_METHOD_AES
        : entry->type == GARC_MEMBER_FILE && size
            ? (uint16_t)method : (uint16_t)GARC_ZIP_METHOD_STORED;
    print_row(name, i, entry->name, entry->name_length, type_name(entry->type),
        size, entry->mtime, entry->mode, entry->link,
        entry->link ? strlen(entry->link) : 0u, expect,
        encrypt ? 0u : crc);
  }

  if (result == GARC_OK) {
    result = garc_writer_finish(writer);
    if (result != GARC_OK) {
      fprintf(stderr, "%s: finish: %s\n", name, garc_result_string(result));
    }
  }
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
  if (fclose(file) != 0) {
    fprintf(stderr, "%s: close failed\n", name);
    return 1;
  }
  return result == GARC_OK ? 0 : 1;
}

/** Print this library's reading of one archive, in the same shape. */
static int read_one(const char * path) {
  FILE * file = fopen(path, "rb");
  if (!file) {
    fprintf(stderr, "cannot read %s\n", path);
    return 1;
  }
  GARC_Stream_Callbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.read = read_cb;
  callbacks.seek = seek_cb;
  callbacks.size = size_cb;
  callbacks.ctx = file;

  GARC_Stream * stream = NULL;
  GARC_Result result = garc_stream_create_callback(&callbacks, &stream);
  if (result != GARC_OK) {
    fprintf(stderr, "%s: stream: %s\n", path, garc_result_string(result));
    fclose(file);
    return 1;
  }
  GARC_Archive * archive = NULL;
  result = garc_open(stream, NULL, &archive);
  if (result != GARC_OK) {
    fprintf(stderr, "%s: %s\n", path, garc_result_string(result));
    garc_stream_destroy(stream);
    fclose(file);
    return 1;
  }

  // The base name, so a row says which archive it came from however the gate
  // spelled the path.
  const char * slash = strrchr(path, '/');
  const char * name = slash ? slash + 1 : path;
  if (strcmp(name, "aes.zip") == 0) {
    result = garc_zip_set_password(
        archive, AES_PASSWORD, sizeof(AES_PASSWORD) - 1u);
    if (result != GARC_OK) {
      fprintf(stderr, "%s: password: %s\n", name, garc_result_string(result));
      garc_close(archive);
      garc_stream_destroy(stream);
      fclose(file);
      return 1;
    }
  }

  size_t index = 0;
  const GARC_Member * member = NULL;
  while ((result = garc_next(archive, &member)) == GARC_OK) {
    // Read the data through, so the CRC verdict arrives: a member that reads to
    // its end and reports GARC_OK is one whose bytes match the declared CRC.
    char buffer[4096];
    char held[512];
    size_t held_len = 0;
    size_t got = 0;
    uint64_t total = 0;
    GARC_Result data = GARC_OK;
    if (member->type == GARC_MEMBER_FILE
        || member->type == GARC_MEMBER_SYMLINK) {
      while ((data = garc_read_member(archive, buffer, sizeof(buffer), &got))
              == GARC_OK
          && got) {
        // An encrypted symlink has no link_target: the eager read is only for
        // a stored, unencrypted member. The decrypted bytes are the target,
        // and the intent row names that target, so they are what this row
        // prints. Every target in this corpus fits in held.
        if (member->type == GARC_MEMBER_SYMLINK) {
          if (held_len + got > sizeof(held)) {
            fprintf(stderr, "%s: member %zu: link target does not fit\n",
                name, index);
            garc_close(archive);
            garc_stream_destroy(stream);
            fclose(file);
            return 1;
          }
          memcpy(held + held_len, buffer, got);
          held_len += got;
        }
        total += (uint64_t)got;
      }
    }
    if (data != GARC_OK) {
      fprintf(stderr, "%s: member %zu: %s\n", name, index,
          garc_result_string(data));
      garc_close(archive);
      garc_stream_destroy(stream);
      fclose(file);
      return 1;
    }
    if (member->type == GARC_MEMBER_FILE && total != member->size) {
      fprintf(stderr, "%s: member %zu held %" PRIu64 " of %" PRIu64 "\n", name,
          index, total, member->size);
      garc_close(archive);
      garc_stream_destroy(stream);
      fclose(file);
      return 1;
    }
    const char * link = member->link_target;
    size_t link_length = member->link_target_length;
    if (member->type == GARC_MEMBER_SYMLINK && !link) {
      link = held;
      link_length = held_len;
    }
    print_row(name, index, member->name, member->name_length,
        type_name(member->type), member->size, member->mtime_seconds,
        member->mode & 07777u, link, link_length,
        garc_zip_member_method(archive), garc_zip_member_crc32(archive));
    ++index;
  }

  const int failed = garc_result_is_error(result);
  if (failed) {
    fprintf(stderr, "%s: %s after %zu members\n", name,
        garc_result_string(result), index);
  }
  garc_close(archive);
  garc_stream_destroy(stream);
  fclose(file);
  return failed ? 1 : 0;
}

/**
 * Write the archives or read one back.
 *
 * @param argc Argument count.
 * @param argv `write <directory>` or `read <path.zip>`.
 * @return 0 on success, 1 on failure, 2 on a usage error.
 */
int main(int argc, char ** argv) {
  // Not a constant expression, so it is filled in here rather than spelled in the
  // table. The pattern repeats, so deflate would shrink it - which matters when
  // this member is compressed rather than stored.
  uint32_t state = 0x13579BDFu;
  for (size_t i = 0; i < sizeof(NOISE); ++i) {
    state = state * 1103515245u + 12345u;
    NOISE[i] = (char)(unsigned char)(state >> 16);
  }
  for (size_t i = 0; i < sizeof(BIG); ++i) {
    BIG[i] = (char)('a' + (i % 26u));
  }

  if (argc == 2 && strcmp(argv[1], "describe") == 0) {
    for (size_t i = 0; i < ARCHIVE_COUNT; ++i) {
      printf("%s\t%s\n", ARCHIVES[i].name, ARCHIVES[i].purpose);
    }
    return 0;
  }
  if (argc == 3 && strcmp(argv[1], "read") == 0) {
    return read_one(argv[2]);
  }
  if (argc != 3 || strcmp(argv[1], "write") != 0) {
    fprintf(stderr,
        "usage: %s write <directory> | read <path.zip> | describe\n", argv[0]);
    return 2;
  }

  for (size_t i = 0; i < ARCHIVE_COUNT; ++i) {
    if (write_one(argv[2], ARCHIVES[i].name, ARCHIVES[i].sizes,
            ARCHIVES[i].patchable, ARCHIVES[i].force_zip64,
            ARCHIVES[i].method, ARCHIVES[i].aes)) {
      return 1;
    }
  }
  return 0;
}
