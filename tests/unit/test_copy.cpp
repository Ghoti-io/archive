/**
 * @file
 *
 * Copying members from a reader into a writer.
 *
 * The whole corpus is the input: every fixture of every format, copied into tar
 * and into zip member by member, must come back as the members that went in -
 * or each refusal must leave the writer usable, so that a caller copying an
 * archive with one unreadable member loses that member and not the rest. Raw
 * zip copies are judged harder: the method, the flags, the CRC and the stored
 * size must be the source's, and the member must read exactly as it did,
 * including the ones this library cannot decode.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <algorithm>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <ghoti.io/archive/archive.h>
#include <ghoti.io/cutil/dir.h>

#include "tar_manifest.h"
#include "test_helpers.h"

using garctest::read_fixture;

namespace {

const char kCorpusPassword[] = "ghoti-password";

/** What one member read as. */
struct Read {
  std::string name;
  GARC_Member_Type type = GARC_MEMBER_FILE;
  std::string link;
  std::string data;
  GARC_Result result = GARC_OK; ///< How reading its data ended.
  uint16_t zip_method = 0;
  uint16_t zip_flags = 0;
  uint32_t zip_crc = 0;
  uint64_t zip_compressed = 0;
};

struct Opened {
  std::vector<uint8_t> bytes;
  GARC_Stream * stream = nullptr;
  GARC_Archive * archive = nullptr;
  ~Opened() {
    garc_close(archive);
    garc_stream_destroy(stream);
  }
  GARC_Result open(std::vector<uint8_t> data) {
    bytes = std::move(data);
    if (garc_stream_create_memory(bytes.data(), bytes.size(), &stream) != GARC_OK) {
      return GARC_ERR_OOM;
    }
    GARC_Result result = garc_open(stream, nullptr, &archive);
    if (result == GARC_OK && garc_format(archive) == GARC_FORMAT_ZIP) {
      result = garc_zip_set_password(
          archive, kCorpusPassword, std::strlen(kCorpusPassword));
    }
    return result;
  }
};

Read describe(GARC_Archive * archive, const GARC_Member * member) {
  Read read;
  read.name.assign(member->name, member->name_length);
  read.type = member->type;
  if (member->link_target) {
    read.link.assign(member->link_target, member->link_target_length);
  }
  if (garc_format(archive) == GARC_FORMAT_ZIP) {
    read.zip_method = garc_zip_member_method(archive);
    read.zip_flags = garc_zip_member_flags(archive);
    read.zip_crc = garc_zip_member_crc32(archive);
    read.zip_compressed = garc_zip_member_compressed_size(archive);
  }
  return read;
}

void read_data(GARC_Archive * archive, Read * read) {
  char buffer[4096];
  for (;;) {
    size_t got = 0;
    read->result = garc_read_member(archive, buffer, sizeof(buffer), &got);
    if (read->result != GARC_OK || !got) {
      return;
    }
    read->data.append(buffer, got);
  }
}

/** Every member of an archive, read through. */
std::vector<Read> read_all(const std::vector<uint8_t> & bytes, GARC_Result * opened) {
  std::vector<Read> out;
  Opened source;
  *opened = source.open(bytes);
  if (*opened != GARC_OK) {
    return out;
  }
  const GARC_Member * member = nullptr;
  while (garc_next(source.archive, &member) == GARC_OK) {
    Read read = describe(source.archive, member);
    read_data(source.archive, &read);
    if (read.type == GARC_MEMBER_SYMLINK && read.link.empty()) {
      // Where a zip keeps a target it could not lend.
      read.link = read.data;
    }
    if (read.type == GARC_MEMBER_SYMLINK) {
      read.data.clear();
    }
    out.push_back(read);
  }
  return out;
}

std::vector<std::string> fixtures(const std::string & directory,
    const char * suffix) {
  // Through cutil rather than opendir(): readdir() on a 32-bit target built
  // without large-file support fails on a filesystem with 64-bit inode
  // numbers, and listed nothing on i686 under qemu.
  std::vector<std::string> names;
  const std::string path = std::string(GARC_TEST_DATA) + "/" + directory;
  GCU_Dir handle;
  std::memset(&handle, 0, sizeof(handle));
  if (gcu_dir_open(&handle, path.c_str(), nullptr) != GCU_FILE_OK) {
    return names;
  }
  for (;;) {
    const char * entry = nullptr;
    bool done = false;
    if (gcu_dir_read(&handle, &entry, nullptr, &done) != GCU_FILE_OK || done) {
      break;
    }
    const std::string name = entry;
    if (name.size() > std::strlen(suffix)
        && name.compare(name.size() - std::strlen(suffix), std::strlen(suffix),
               suffix)
            == 0) {
      names.push_back(path + "/" + name);
    }
  }
  gcu_dir_close(&handle);
  std::sort(names.begin(), names.end());
  return names;
}

std::vector<std::string> every_fixture() {
  std::vector<std::string> all;
  for (const auto & [directory, suffix] :
      std::vector<std::pair<const char *, const char *>>{{"tar", ".tar"},
          {"zip", ".zip"}, {"sevenz", ".7z"}, {"arcpio", ".cpio"},
          {"arcpio", ".a"}}) {
    for (const std::string & path : fixtures(directory, suffix)) {
      all.push_back(path);
    }
  }
  return all;
}

/** Copy every member of @p bytes into @p format; who was refused, and the output. */
struct Copied {
  std::vector<uint8_t> bytes;
  std::vector<size_t> copied;   ///< Indexes into the source's members.
  std::vector<GARC_Result> refused;
  GARC_Result finished = GARC_OK;
};

Copied copy_all(const std::vector<uint8_t> & bytes, GARC_Format format,
    uint32_t flags) {
  Copied out;
  Opened source;
  if (source.open(bytes) != GARC_OK) {
    out.finished = GARC_ERR_FORMAT;
    return out;
  }
  GARC_Sink * sink = nullptr;
  EXPECT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  GARC_Writer * writer = nullptr;
  EXPECT_EQ(garc_writer_create(sink, format, nullptr, &writer), GARC_OK);
  const GARC_Member * member = nullptr;
  size_t index = 0;
  while (garc_next(source.archive, &member) == GARC_OK) {
    const uint64_t before = garc_sink_tell(sink);
    const GARC_Result result
        = garc_writer_copy_member(writer, source.archive, nullptr, flags);
    if (result == GARC_OK) {
      out.copied.push_back(index);
    }
    else {
      out.refused.push_back(result);
      // A refusal of one member is not the end of the copy.
      EXPECT_EQ(garc_sink_tell(sink), before)
          << "a refused copy wrote " << garc_result_string(result);
    }
    ++index;
  }
  out.finished = garc_writer_finish(writer);
  const void * data = nullptr;
  size_t length = 0;
  garc_sink_data(sink, &data, &length);
  out.bytes.assign(static_cast<const uint8_t *>(data),
      static_cast<const uint8_t *>(data) + length);
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
  return out;
}

std::string name_for(GARC_Format format, const Read & read) {
  // zip writes a directory's name with a trailing slash.
  if (format == GARC_FORMAT_ZIP && read.type == GARC_MEMBER_DIRECTORY
      && (read.name.empty() || read.name.back() != '/')) {
    return read.name + "/";
  }
  return read.name;
}

} // namespace

TEST(CopyMember, EveryFixtureCopiesIntoTarAndZipOrRefusesCleanly) {
  const std::vector<std::string> paths = every_fixture();
  ASSERT_GT(paths.size(), 40u);
  size_t members = 0;
  size_t refusals = 0;
  for (const std::string & path : paths) {
    for (GARC_Format format : {GARC_FORMAT_TAR, GARC_FORMAT_ZIP}) {
      SCOPED_TRACE(path + " -> " + garc_format_string(format));
      const std::vector<uint8_t> bytes = read_fixture(path);
      GARC_Result opened = GARC_OK;
      const std::vector<Read> before = read_all(bytes, &opened);
      if (opened != GARC_OK) {
        continue; // a fixture that is refused at open is not a copy question
      }
      const Copied copied = copy_all(bytes, format, 0);
      ASSERT_EQ(copied.finished, GARC_OK);
      refusals += copied.refused.size();
      const std::vector<Read> after = read_all(copied.bytes, &opened);
      ASSERT_EQ(opened, GARC_OK);
      ASSERT_EQ(after.size(), copied.copied.size());
      for (size_t k = 0; k < after.size(); ++k) {
        const Read & was = before[copied.copied[k]];
        const Read & now = after[k];
        EXPECT_EQ(now.name, name_for(format, was)) << was.name;
        EXPECT_EQ(now.type, was.type) << was.name;
        EXPECT_EQ(now.link, was.link) << was.name;
        EXPECT_EQ(now.data, was.data) << was.name;
        EXPECT_EQ(now.result, GARC_OK) << was.name;
        ++members;
      }
    }
  }
  EXPECT_GT(members, 300u);
  // The corpus has members no writer can take (devices into zip) and members
  // this library cannot read (PPMd, BCJ2): refusals the copy must survive.
  EXPECT_GT(refusals, 0u);
}

TEST(CopyMember, ARawZipCopyKeepsTheStoredBytesOfEveryMember) {
  const std::vector<std::string> paths = fixtures("zip", ".zip");
  ASSERT_GT(paths.size(), 20u);
  size_t members = 0;
  size_t unreadable = 0;
  for (const std::string & path : paths) {
    SCOPED_TRACE(path);
    const std::vector<uint8_t> bytes = read_fixture(path);
    GARC_Result opened = GARC_OK;
    const std::vector<Read> before = read_all(bytes, &opened);
    if (opened != GARC_OK) {
      continue;
    }
    const Copied copied = copy_all(bytes, GARC_FORMAT_ZIP, GARC_COPY_RAW);
    ASSERT_EQ(copied.finished, GARC_OK);
    // Raw copies do not refuse for want of a codec or a password.
    EXPECT_TRUE(copied.refused.empty());
    const std::vector<Read> after = read_all(copied.bytes, &opened);
    ASSERT_EQ(opened, GARC_OK);
    ASSERT_EQ(after.size(), before.size());
    for (size_t k = 0; k < after.size(); ++k) {
      const Read & was = before[k];
      const Read & now = after[k];
      SCOPED_TRACE(was.name);
      EXPECT_EQ(now.name, was.name);
      EXPECT_EQ(now.type, was.type);
      EXPECT_EQ(now.zip_method, was.zip_method);
      // Only the descriptor's job could change, and it does not.
      EXPECT_EQ(now.zip_flags, was.zip_flags);
      EXPECT_EQ(now.zip_crc, was.zip_crc);
      EXPECT_EQ(now.zip_compressed, was.zip_compressed);
      // Read exactly as it was: the same bytes, or the same refusal.
      EXPECT_EQ(now.result, was.result) << garc_result_string(now.result);
      EXPECT_EQ(now.data, was.data);
      EXPECT_EQ(now.link, was.link);
      if (was.result != GARC_OK) {
        ++unreadable;
      }
      ++members;
    }
  }
  // Every member of the zip corpus, 81 of them when this was written.
  EXPECT_GE(members, 81u);
  // sevenzip-ppmd.zip is the case this exists for: a method with no codec here,
  // carried across unchanged.
  EXPECT_GT(unreadable, 0u);
}

TEST(CopyMember, ARawCopyCanRenameButNotTurnADirectoryIntoAFile) {
  // A zip with a file and a directory, made by this library.
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  GARC_Writer * writer = nullptr;
  ASSERT_EQ(garc_writer_create(sink, GARC_FORMAT_ZIP, nullptr, &writer), GARC_OK);
  GARC_Member member;
  std::memset(&member, 0, sizeof(member));
  member.name = "dir";
  member.name_length = 3;
  member.type = GARC_MEMBER_DIRECTORY;
  ASSERT_EQ(garc_writer_add(writer, &member), GARC_OK);
  member.name = "file.txt";
  member.name_length = 8;
  member.type = GARC_MEMBER_FILE;
  member.size = 5;
  ASSERT_EQ(garc_writer_add(writer, &member), GARC_OK);
  ASSERT_EQ(garc_writer_write(writer, "hello", 5), GARC_OK);
  ASSERT_EQ(garc_writer_finish(writer), GARC_OK);
  const void * data = nullptr;
  size_t length = 0;
  ASSERT_EQ(garc_sink_data(sink, &data, &length), GARC_OK);
  const std::vector<uint8_t> bytes(static_cast<const uint8_t *>(data),
      static_cast<const uint8_t *>(data) + length);
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);

  Opened source;
  ASSERT_EQ(source.open(bytes), GARC_OK);
  ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  ASSERT_EQ(garc_writer_create(sink, GARC_FORMAT_ZIP, nullptr, &writer), GARC_OK);
  const GARC_Member * read = nullptr;
  ASSERT_EQ(garc_next(source.archive, &read), GARC_OK); // dir/
  GARC_Member as = *read;
  as.name = "renamed";
  as.name_length = 7;
  EXPECT_EQ(garc_writer_copy_member(writer, source.archive, &as, GARC_COPY_RAW),
      GARC_ERR_INVALID);
  // The refusal read nothing, so the member is still there to copy.
  as.name = "renamed/";
  as.name_length = 8;
  EXPECT_EQ(garc_writer_copy_member(writer, source.archive, &as, GARC_COPY_RAW),
      GARC_OK);
  ASSERT_EQ(garc_next(source.archive, &read), GARC_OK); // file.txt
  as = *read;
  as.name = "moved.txt";
  as.name_length = 9;
  ASSERT_EQ(garc_writer_copy_member(writer, source.archive, &as, GARC_COPY_RAW),
      GARC_OK);
  ASSERT_EQ(garc_writer_finish(writer), GARC_OK);
  ASSERT_EQ(garc_sink_data(sink, &data, &length), GARC_OK);
  GARC_Result opened = GARC_OK;
  const std::vector<Read> after = read_all(std::vector<uint8_t>(
      static_cast<const uint8_t *>(data), static_cast<const uint8_t *>(data) + length),
      &opened);
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
  ASSERT_EQ(opened, GARC_OK);
  ASSERT_EQ(after.size(), 2u);
  EXPECT_EQ(after[0].name, "renamed/");
  EXPECT_EQ(after[0].type, GARC_MEMBER_DIRECTORY);
  EXPECT_EQ(after[1].name, "moved.txt");
  EXPECT_EQ(after[1].data, "hello");
}

TEST(CopyMember, TheRefusalsSayWhatIsWrong) {
  const std::vector<uint8_t> tar
      = read_fixture(std::string(GARC_TEST_DATA) + "/tar/ustar-basic.tar");
  Opened source;
  ASSERT_EQ(source.open(tar), GARC_OK);
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  GARC_Writer * writer = nullptr;
  ASSERT_EQ(garc_writer_create(sink, GARC_FORMAT_ZIP, nullptr, &writer), GARC_OK);
  // No current member yet.
  EXPECT_EQ(garc_writer_copy_member(writer, source.archive, nullptr, 0),
      GARC_ERR_INVALID);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(source.archive, &member), GARC_OK);
  while (member->type != GARC_MEMBER_FILE || !member->size) {
    ASSERT_EQ(garc_next(source.archive, &member), GARC_OK);
  }
  EXPECT_EQ(garc_writer_copy_member(writer, source.archive, nullptr, 4u),
      GARC_ERR_INVALID);
  EXPECT_EQ(garc_writer_copy_member(writer, source.archive, nullptr, GARC_COPY_RAW),
      GARC_ERR_UNSUPPORTED);
  GARC_Member as = *member;
  as.size += 1;
  EXPECT_EQ(garc_writer_copy_member(writer, source.archive, &as, 0),
      GARC_ERR_INVALID);
  as = *member;
  as.type = GARC_MEMBER_DIRECTORY;
  EXPECT_EQ(garc_writer_copy_member(writer, source.archive, &as, 0),
      GARC_ERR_INVALID);
  // Read from, then asked to copy: refused rather than copied short.
  char byte = 0;
  size_t got = 0;
  ASSERT_EQ(garc_read_member(source.archive, &byte, 1, &got), GARC_OK);
  EXPECT_EQ(garc_writer_copy_member(writer, source.archive, nullptr, 0),
      GARC_ERR_INVALID);
  EXPECT_EQ(garc_writer_member_count(writer), 0u);
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
}

TEST(CopyMember, AnEncryptedMemberWithNoPasswordIsRefusedBeforeAnythingIsWritten) {
  const std::vector<uint8_t> bytes
      = read_fixture(std::string(GARC_TEST_DATA) + "/zip/infozip-crypto.zip");
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream), GARC_OK);
  GARC_Archive * archive = nullptr;
  ASSERT_EQ(garc_open(stream, nullptr, &archive), GARC_OK);
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  GARC_Writer * writer = nullptr;
  ASSERT_EQ(garc_writer_create(sink, GARC_FORMAT_TAR, nullptr, &writer), GARC_OK);
  const GARC_Member * member = nullptr;
  int refused = 0;
  while (garc_next(archive, &member) == GARC_OK) {
    if (garc_zip_member_encryption(archive) == GARC_ZIP_ENCRYPTION_NONE) {
      continue;
    }
    EXPECT_EQ(garc_writer_copy_member(writer, archive, nullptr, 0),
        GARC_ERR_PASSWORD_REQUIRED);
    EXPECT_EQ(garc_sink_tell(sink), 0u);
    ++refused;
  }
  EXPECT_GT(refused, 0);
  // And the writer is still usable after every one of them.
  EXPECT_EQ(garc_writer_finish(writer), GARC_OK);
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
  garc_close(archive);
  garc_stream_destroy(stream);
}

TEST(CopyMember, ARawCopyThatLandsPastFourGibibytesGetsAZip64Offset) {
  // The source's own entry had no zip64 field. The copy lands at 5 GiB, so its
  // central entry needs one, with the offset, and the marker in the 32-bit
  // field - rebuilt, since the source's extra field had none to keep.
  const std::vector<uint8_t> bytes
      = read_fixture(std::string(GARC_TEST_DATA) + "/zip/infozip-deflate.zip");
  Opened source;
  ASSERT_EQ(source.open(bytes), GARC_OK);
  struct Tail {
    uint64_t start = (uint64_t)5 << 30;
    std::string bytes;
  } tail;
  GARC_Sink_Callbacks callbacks{};
  callbacks.write = [](void * ctx, const void * buffer, size_t size) {
    static_cast<Tail *>(ctx)->bytes.append(static_cast<const char *>(buffer), size);
    return GARC_OK;
  };
  callbacks.ctx = &tail;
  callbacks.start = tail.start;
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_callback(&callbacks, &sink), GARC_OK);
  GARC_Writer * writer = nullptr;
  ASSERT_EQ(garc_writer_create(sink, GARC_FORMAT_ZIP, nullptr, &writer), GARC_OK);
  const GARC_Member * member = nullptr;
  size_t copied = 0;
  while (garc_next(source.archive, &member) == GARC_OK) {
    ASSERT_EQ(garc_writer_copy_member(writer, source.archive, nullptr, GARC_COPY_RAW),
        GARC_OK);
    ++copied;
  }
  ASSERT_EQ(garc_writer_finish(writer), GARC_OK);
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
  ASSERT_GT(copied, 0u);
  // Every central entry: the marker in the offset field, and a zip64 field
  // whose payload is the 8-byte offset alone, equal to where the member is.
  size_t at = 0;
  size_t entries = 0;
  const std::string & b = tail.bytes;
  auto le16 = [&](size_t i) { return (uint32_t)(uint8_t)b[i] | ((uint32_t)(uint8_t)b[i + 1] << 8); };
  auto le32 = [&](size_t i) { return le16(i) | (le16(i + 2) << 16); };
  while ((at = b.find(std::string("PK\x01\x02", 4), at)) != std::string::npos) {
    EXPECT_EQ(le32(at + 42), 0xFFFFFFFFu);
    const size_t name = le16(at + 28);
    const size_t extra = at + 46 + name;
    ASSERT_EQ(le16(extra), 0x0001u);
    ASSERT_EQ(le16(extra + 2), 8u);
    uint64_t offset = 0;
    for (int i = 7; i >= 0; --i) {
      offset = (offset << 8) | (uint8_t)b[extra + 4 + i];
    }
    ASSERT_GE(offset, tail.start);
    EXPECT_EQ(b.compare(offset - tail.start, 4, std::string("PK\x03\x04", 4)), 0);
    ++entries;
    at += 4;
  }
  EXPECT_EQ(entries, copied);
}

/** Copy every member of a zip read off a pipe into a tar, into @p out. */
GARC_Result copy_piped_zip_to_tar(const std::vector<uint8_t> & zip,
    std::vector<uint8_t> * out, uint64_t * failed_at_offset) {
  garctest::BufferSource source(zip.data(), zip.size(), false, false);
  GARC_Stream * stream = nullptr;
  EXPECT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK);
  GARC_Archive * archive = nullptr;
  EXPECT_EQ(garc_open(stream, nullptr, &archive), GARC_OK);
  GARC_Sink * sink = nullptr;
  EXPECT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  GARC_Writer * writer = nullptr;
  EXPECT_EQ(garc_writer_create(sink, GARC_FORMAT_TAR, nullptr, &writer), GARC_OK);
  const GARC_Member * member = nullptr;
  GARC_Result result = GARC_OK;
  GARC_Result walked;
  while ((walked = garc_next(archive, &member)) == GARC_OK) {
    const uint64_t before = garc_sink_tell(sink);
    result = garc_writer_copy_member(writer, archive, nullptr, 0);
    if (result != GARC_OK) {
      *failed_at_offset = before;
      EXPECT_EQ(garc_sink_tell(sink), before) << "a refused copy wrote";
      break;
    }
  }
  if (result == GARC_OK) {
    EXPECT_EQ(walked, GARC_END);
    result = garc_writer_finish(writer);
  }
  const void * data = nullptr;
  size_t length = 0;
  garc_sink_data(sink, &data, &length);
  out->assign(static_cast<const uint8_t *>(data),
      static_cast<const uint8_t *>(data) + length);
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
  garc_close(archive);
  garc_stream_destroy(stream);
  return result;
}

TEST(CopyMember, AMemberOfUnknownSizeIsSpooledAndCopiedWhole) {
  // Off a pipe, a descriptor member's size is not known until its data has been
  // read, and a tar header needs it first. The copy reads the member to its end
  // into a temporary file, and writes it with the size it turned out to have.
  const std::vector<uint8_t> zip
      = read_fixture(std::string(GARC_TEST_DATA) + "/zip/bsdtar-descriptors.zip");
  ASSERT_FALSE(zip.empty());
  std::vector<uint8_t> tar;
  uint64_t failed_at = 0;
  ASSERT_EQ(copy_piped_zip_to_tar(zip, &tar, &failed_at), GARC_OK);

  GARC_Result opened = GARC_ERR_INTERNAL;
  const std::vector<Read> want = read_all(zip, &opened);
  ASSERT_EQ(opened, GARC_OK);
  const std::vector<Read> got = read_all(tar, &opened);
  ASSERT_EQ(opened, GARC_OK);
  ASSERT_EQ(got.size(), want.size());
  size_t with_data = 0;
  for (size_t i = 0; i < got.size(); ++i) {
    SCOPED_TRACE(want[i].name);
    EXPECT_EQ(got[i].name, want[i].name);
    EXPECT_EQ(got[i].data, want[i].data);
    EXPECT_EQ(got[i].result, GARC_OK);
    with_data += want[i].data.empty() ? 0u : 1u;
  }
  EXPECT_GE(with_data, 2u) << "the fixture no longer has descriptor members with data";
}

TEST(CopyMember, AnUnknownSizeMemberThatFailsItsCheckWritesNothing) {
  // Spooling first means the verdict on the data - CRC-32, or the decoder's -
  // arrives before the header is written, so a bad member is refused cleanly
  // where a known-size one would already be half written.
  std::vector<uint8_t> zip
      = read_fixture(std::string(GARC_TEST_DATA) + "/zip/bsdtar-descriptors.zip");
  ASSERT_FALSE(zip.empty());
  // The first member's descriptor CRC-32, one bit off.
  const std::string haystack(zip.begin(), zip.end());
  const size_t descriptor = haystack.find(std::string("PK\x07\x08", 4));
  ASSERT_NE(descriptor, std::string::npos);
  zip[descriptor + 4] ^= 0x01u;
  std::vector<uint8_t> tar;
  uint64_t failed_at = 0;
  EXPECT_EQ(copy_piped_zip_to_tar(zip, &tar, &failed_at), GARC_ERR_CORRUPT);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
