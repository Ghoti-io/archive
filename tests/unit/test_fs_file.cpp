/**
 * @file
 *
 * Files as streams and sinks, and opening an archive by path.
 *
 * Every compressed open has a control that shows the core reader refuses the
 * same file, so a pass is the sniff working and not the file having been
 * written uncompressed. The sink's promise is about the destination, so the
 * sink tests look at the directory, not only at the bytes.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstring>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <sys/stat.h>
#ifndef _WIN32
#include <unistd.h>
#endif

#include <gtest/gtest.h>

#include <ghoti.io/archive/fs.h>
#include <ghoti.io/compress/compress.h>
#include <ghoti.io/cutil/dir.h>
#include <ghoti.io/cutil/file.h>

#include "failing_allocator.h"

using garctest::FailingAllocator;

namespace {

using Entry = std::pair<std::string, std::string>;

std::vector<Entry> sample() {
  std::string big;
  for (int i = 0; i < 5000; ++i) {
    big += "line " + std::to_string(i) + "\n";
  }
  return {{"a.txt", "alpha"}, {"dir/b.bin", big}, {"empty", ""}};
}

GARC_Member file_member(const Entry & entry) {
  GARC_Member member;
  std::memset(&member, 0, sizeof(member));
  member.name = entry.first.data();
  member.name_length = entry.first.size();
  member.name_encoding = GARC_NAME_UTF8;
  member.type = GARC_MEMBER_FILE;
  member.size = entry.second.size();
  member.mode = 0644;
  member.mode_valid = 1;
  return member;
}

/** Write @p entries as @p format into @p sink, finishing writer and sink. */
GARC_Result write_archive(GARC_Sink * sink, GARC_Format format,
    const std::vector<Entry> & entries) {
  GARC_Writer * writer = nullptr;
  GARC_Result result = garc_writer_create(sink, format, nullptr, &writer);
  if (result != GARC_OK) {
    return result;
  }
  for (const Entry & entry : entries) {
    const GARC_Member member = file_member(entry);
    result = garc_writer_add(writer, &member);
    if (result == GARC_OK && !entry.second.empty()) {
      result = garc_writer_write(writer, entry.second.data(), entry.second.size());
    }
    if (result != GARC_OK) {
      garc_writer_destroy(writer);
      return result;
    }
  }
  result = garc_writer_finish(writer);
  garc_writer_destroy(writer);
  if (result != GARC_OK) {
    return result;
  }
  return garc_sink_finish(sink);
}

/** Every member's name and bytes, in order. */
std::vector<Entry> read_all(GARC_Archive * archive) {
  std::vector<Entry> found;
  const GARC_Member * member = nullptr;
  while (garc_next(archive, &member) == GARC_OK) {
    Entry entry(std::string(member->name, member->name_length), "");
    char buffer[4096];
    size_t got = 0;
    while (garc_read_member(archive, buffer, sizeof(buffer), &got) == GARC_OK
        && got) {
      entry.second.append(buffer, got);
    }
    found.push_back(entry);
  }
  return found;
}

std::string read_file(const std::string & path) {
  void * data = nullptr;
  size_t length = 0;
  if (gcu_file_read(path.c_str(), GCU_FILE_UNLIMITED, nullptr, &data, &length)
      != GCU_FILE_OK) {
    return {};
  }
  std::string text(static_cast<char *>(data), length);
  gcu_file_free(nullptr, data);
  return text;
}

void write_file(const std::string & path, const std::string & bytes) {
  ASSERT_EQ(GCU_FILE_OK,
      gcu_file_write_atomic(path.c_str(), bytes.data(), bytes.size(),
          GCU_FILE_SYNC_NONE, GCU_FILE_PERMS_DEFAULT, nullptr));
}

/** Compress @p bytes whole with a `compress` method, through archive's sink. */
std::string compressed(const std::string & bytes, const char * method) {
  GARC_Sink * memory = nullptr;
  GARC_Sink * codec = nullptr;
  EXPECT_EQ(GARC_OK, garc_sink_create_memory(&memory));
  EXPECT_EQ(GARC_OK, garc_sink_create_compress(memory, method, nullptr, &codec));
  EXPECT_EQ(GARC_OK, garc_sink_write(codec, bytes.data(), bytes.size()));
  EXPECT_EQ(GARC_OK, garc_sink_finish(codec));
  const void * data = nullptr;
  size_t length = 0;
  EXPECT_EQ(GARC_OK, garc_sink_data(memory, &data, &length));
  std::string out(static_cast<const char *>(data), length);
  garc_sink_destroy(codec);
  garc_sink_destroy(memory);
  return out;
}

/** A tar of @p entries, in memory. */
std::string tar_bytes(const std::vector<Entry> & entries) {
  GARC_Sink * memory = nullptr;
  EXPECT_EQ(GARC_OK, garc_sink_create_memory(&memory));
  EXPECT_EQ(GARC_OK, write_archive(memory, GARC_FORMAT_TAR, entries));
  const void * data = nullptr;
  size_t length = 0;
  EXPECT_EQ(GARC_OK, garc_sink_data(memory, &data, &length));
  std::string out(static_cast<const char *>(data), length);
  garc_sink_destroy(memory);
  return out;
}

class FsFile : public testing::Test {
protected:
  std::string dir;

  void SetUp() override {
    char * made = nullptr;
    ASSERT_EQ(GCU_FILE_OK,
        gcu_dir_temp_create(nullptr, "garc-fs-file", nullptr, &made));
    dir = made;
    gcu_dir_free_path(nullptr, made);
  }

  void TearDown() override {
    for (const std::string & name : names()) {
      gcu_file_remove(at(name).c_str());
    }
    gcu_dir_remove(dir.c_str());
  }

  std::string at(const std::string & name) const { return dir + "/" + name; }

  std::set<std::string> names() const {
    std::set<std::string> found;
    GCU_Dir handle;
    std::memset(&handle, 0, sizeof(handle));
    if (gcu_dir_open(&handle, dir.c_str(), nullptr) != GCU_FILE_OK) {
      return found;
    }
    for (;;) {
      const char * name = nullptr;
      bool done = false;
      if (gcu_dir_read(&handle, &name, nullptr, &done) != GCU_FILE_OK || done) {
        break;
      }
      found.insert(name);
    }
    gcu_dir_close(&handle);
    return found;
  }

  /** The core reader's answer for a file, with no detection. */
  GARC_Result core_open(const std::string & path) {
    GARC_Stream * stream = nullptr;
    GARC_Result result = garc_fs_stream_open(path.c_str(), &stream);
    if (result != GARC_OK) {
      return result;
    }
    GARC_Archive * archive = nullptr;
    result = garc_open(stream, nullptr, &archive);
    garc_close(archive);
    garc_stream_destroy(stream);
    return result;
  }
};

} // namespace

////////////////////////////////////////////////////////////////////////
// The stream
////////////////////////////////////////////////////////////////////////

TEST_F(FsFile, StreamReadsTheFileSeeksAndKnowsItsSize) {
  write_file(at("f"), "0123456789");
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(GARC_OK, garc_fs_stream_open(at("f").c_str(), &stream));
  EXPECT_TRUE(garc_stream_is_seekable(stream));
  uint64_t size = 0;
  ASSERT_EQ(GARC_OK, garc_stream_size(stream, &size));
  EXPECT_EQ(10u, size);
  char buffer[4];
  ASSERT_EQ(GARC_OK, garc_stream_seek(stream, 6));
  ASSERT_EQ(GARC_OK, garc_stream_read_exact(stream, buffer, 4));
  EXPECT_EQ("6789", std::string(buffer, 4));
  size_t got = 99;
  ASSERT_EQ(GARC_OK, garc_stream_read(stream, buffer, 4, &got));
  EXPECT_EQ(0u, got);
  garc_stream_destroy(stream);
}

TEST_F(FsFile, StreamNamesAMissingFileAndADirectoryApart) {
  GARC_Stream * stream = nullptr;
  EXPECT_EQ(GARC_ERR_NOT_FOUND,
      garc_fs_stream_open(at("absent").c_str(), &stream));
  EXPECT_EQ(GARC_ERR_INVALID, garc_fs_stream_open(dir.c_str(), &stream));
  EXPECT_EQ(GARC_ERR_INVALID, garc_fs_stream_open(nullptr, &stream));
  EXPECT_EQ(GARC_ERR_INVALID, garc_fs_stream_open(at("x").c_str(), nullptr));
  EXPECT_EQ(nullptr, stream);
}

#ifndef _WIN32
TEST_F(FsFile, StreamOfAnUnreadableFileIsAccessDenied) {
  if (geteuid() == 0) {
    GTEST_SKIP() << "root reads a mode-0 file";
  }
  write_file(at("locked"), "secret");
  ASSERT_EQ(0, chmod(at("locked").c_str(), 0));
  GARC_Stream * stream = nullptr;
  EXPECT_EQ(GARC_ERR_ACCESS, garc_fs_stream_open(at("locked").c_str(), &stream));
  chmod(at("locked").c_str(), 0600);
}
#endif

////////////////////////////////////////////////////////////////////////
// The sink
////////////////////////////////////////////////////////////////////////

TEST_F(FsFile, SinkWritesEveryFormatAndTheFileReadsBack) {
  // zip and 7z patch, so this is the patch callback; 7z refuses a sink that
  // cannot.
  const std::vector<std::pair<GARC_Format, const char *>> formats = {
      {GARC_FORMAT_TAR, "t.tar"}, {GARC_FORMAT_ZIP, "t.zip"},
      {GARC_FORMAT_SEVENZ, "t.7z"}, {GARC_FORMAT_AR, "t.a"},
      {GARC_FORMAT_CPIO, "t.cpio"}};
  for (const auto & [format, name] : formats) {
    SCOPED_TRACE(name);
    GARC_Sink * sink = nullptr;
    ASSERT_EQ(GARC_OK, garc_fs_sink_create(at(name).c_str(), nullptr, nullptr,
                           GARC_FS_NO_SYNC, &sink));
    EXPECT_TRUE(garc_sink_is_seekable(sink));
    std::vector<Entry> entries = sample();
    if (format == GARC_FORMAT_AR) {
      entries[1].first = "b.bin"; // ar has no directories
    }
    ASSERT_EQ(GARC_OK, write_archive(sink, format, entries));
    garc_sink_destroy(sink);

    GARC_Archive * archive = nullptr;
    ASSERT_EQ(GARC_OK, garc_fs_open(at(name).c_str(), nullptr, nullptr, 0,
                           &archive));
    EXPECT_EQ(format, garc_format(archive));
    EXPECT_EQ(entries, read_all(archive));
    garc_close(archive);
  }
}

TEST_F(FsFile, SinkZipPatchesItsHeadersInsteadOfWritingDescriptors) {
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(GARC_OK, garc_fs_sink_create(at("p.zip").c_str(), nullptr, nullptr,
                         GARC_FS_NO_SYNC, &sink));
  ASSERT_EQ(GARC_OK, write_archive(sink, GARC_FORMAT_ZIP, sample()));
  garc_sink_destroy(sink);
  std::string bytes = read_file(at("p.zip"));
  ASSERT_GT(bytes.size(), 30u);
  ASSERT_EQ(0, std::memcmp(bytes.data(), "PK\x03\x04", 4));
  // General purpose bit 3 is the data descriptor. Clear means the CRC and sizes
  // went back into the local header, which only a patch can do.
  EXPECT_EQ(0, static_cast<unsigned char>(bytes[6]) & 0x08);
  // The control: the same writer through the compressing file sink cannot
  // patch, and says so with the bit.
  ASSERT_EQ(GARC_OK, garc_fs_sink_create(at("p.zip.gz").c_str(), "gzip",
                         nullptr, GARC_FS_NO_SYNC, &sink));
  EXPECT_FALSE(garc_sink_is_seekable(sink));
  ASSERT_EQ(GARC_OK, write_archive(sink, GARC_FORMAT_ZIP, sample()));
  garc_sink_destroy(sink);
  GARC_Stream * file = nullptr;
  GARC_Stream * plain = nullptr;
  ASSERT_EQ(GARC_OK, garc_fs_stream_open(at("p.zip.gz").c_str(), &file));
  ASSERT_EQ(GARC_OK,
      garc_stream_create_decompress(file, "gzip", nullptr, &plain));
  unsigned char head[8];
  ASSERT_EQ(GARC_OK, garc_stream_read_exact(plain, head, sizeof(head)));
  EXPECT_EQ(0x08, head[6] & 0x08);
  garc_stream_destroy(plain);
  garc_stream_destroy(file);
}

TEST_F(FsFile, SinkThatIsNotFinishedLeavesTheDestinationAndNoTemporary) {
  write_file(at("keep.tar"), "the old contents");
  const std::set<std::string> before = names();
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(GARC_OK, garc_fs_sink_create(at("keep.tar").c_str(), nullptr,
                         nullptr, GARC_FS_NO_SYNC, &sink));
  ASSERT_EQ(GARC_OK, garc_sink_write(sink, "partial", 7));
  // The temporary is real while the sink is live; that is where the bytes are.
  EXPECT_EQ(before.size() + 1, names().size());
  garc_sink_destroy(sink);
  EXPECT_EQ(before, names());
  EXPECT_EQ("the old contents", read_file(at("keep.tar")));
}

TEST_F(FsFile, SinkFinishReplacesTheFileAndKeepsItsPermissions) {
  write_file(at("r.tar"), "old");
#ifndef _WIN32
  ASSERT_EQ(0, chmod(at("r.tar").c_str(), 0640));
#endif
  const std::set<std::string> before = names();
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(GARC_OK,
      garc_fs_sink_create(at("r.tar").c_str(), nullptr, nullptr, 0, &sink));
  ASSERT_EQ(GARC_OK, write_archive(sink, GARC_FORMAT_TAR, sample()));
  EXPECT_EQ(before, names());
  EXPECT_EQ(tar_bytes(sample()), read_file(at("r.tar")));
#ifndef _WIN32
  struct stat info;
  ASSERT_EQ(0, stat(at("r.tar").c_str(), &info));
  EXPECT_EQ(0640u, info.st_mode & 0777u);
#endif
  // Spent: a second finish and a later write are refused, and destroying it
  // does not remove the file it put in place.
  EXPECT_EQ(GARC_ERR_INVALID, garc_sink_finish(sink));
  EXPECT_NE(GARC_OK, garc_sink_write(sink, "x", 1));
  garc_sink_destroy(sink);
  EXPECT_EQ(tar_bytes(sample()), read_file(at("r.tar")));
}

TEST_F(FsFile, SinkRefusesWhatItCannotCreateAndLeavesNothingBehind) {
  GARC_Sink * sink = nullptr;
  EXPECT_EQ(GARC_ERR_NOT_FOUND,
      garc_fs_sink_create(at("no/such/dir/x.tar").c_str(), nullptr, nullptr,
          0, &sink));
  EXPECT_EQ(GARC_ERR_INVALID,
      garc_fs_sink_create(dir.c_str(), nullptr, nullptr, 0, &sink));
  EXPECT_EQ(GARC_ERR_INVALID,
      garc_fs_sink_create(at("x").c_str(), nullptr, nullptr,
          GARC_FS_NAME_HINT, &sink));
  EXPECT_EQ(GARC_ERR_INVALID,
      garc_fs_sink_create("", nullptr, nullptr, 0, &sink));
  EXPECT_EQ(GARC_ERR_UNSUPPORTED,
      garc_fs_sink_create(at("x").c_str(), "no-such-codec", nullptr, 0, &sink));
  EXPECT_EQ(nullptr, sink);
  EXPECT_TRUE(names().empty());
}

TEST_F(FsFile, CompressingSinkThatFailsItsFinishDoesNotRename) {
  // 7z through a codec is refused at create, before a byte is written, and the
  // sink can still be destroyed without leaving a file.
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(GARC_OK, garc_fs_sink_create(at("s.7z.gz").c_str(), "gzip",
                         nullptr, GARC_FS_NO_SYNC, &sink));
  GARC_Writer * writer = nullptr;
  EXPECT_EQ(GARC_ERR_NOT_SEEKABLE,
      garc_writer_create(sink, GARC_FORMAT_SEVENZ, nullptr, &writer));
  garc_sink_destroy(sink);
  EXPECT_TRUE(names().empty());
}

////////////////////////////////////////////////////////////////////////
// Opening by path
////////////////////////////////////////////////////////////////////////

TEST_F(FsFile, OpenDetectsEveryCodecWithAMagicNumber) {
  for (const char * method : {"gzip", "bzip2", "xz", "zstd", "lz4"}) {
    SCOPED_TRACE(method);
    // A name that says nothing, so only the bytes can have decided.
    const std::string path = at(std::string("plain-") + method);
    GARC_Sink * sink = nullptr;
    ASSERT_EQ(GARC_OK, garc_fs_sink_create(path.c_str(), method, nullptr,
                           GARC_FS_NO_SYNC, &sink));
    ASSERT_EQ(GARC_OK, write_archive(sink, GARC_FORMAT_TAR, sample()));
    garc_sink_destroy(sink);

    // The control: the core reader, which detects nothing, refuses the file.
    EXPECT_EQ(GARC_ERR_FORMAT, core_open(path));

    GARC_Archive * archive = nullptr;
    ASSERT_EQ(GARC_OK, garc_fs_open(path.c_str(), nullptr, nullptr, 0, &archive));
    EXPECT_EQ(GARC_FORMAT_TAR, garc_format(archive));
    EXPECT_EQ(sample(), read_all(archive));
    // A codec stream cannot seek, and finding is the call that needs to.
    garc_close(archive);
  }
}

TEST_F(FsFile, OpenUsesTheNameOnlyWhenAskedAndOnlyForCodecsWithNoMagic) {
  const std::string tar = tar_bytes(sample());
  for (const auto & [method, name] :
      std::vector<std::pair<const char *, const char *>>{
          {"brotli", "b.tar.br"}, {"brotli", "B.TBR"}, {"lzma", "l.tar.lzma"},
          {"lzma", "l.tlzma"}}) {
    SCOPED_TRACE(name);
    write_file(at(name), compressed(tar, method));
    GARC_Archive * archive = nullptr;
    EXPECT_EQ(GARC_ERR_FORMAT,
        garc_fs_open(at(name).c_str(), nullptr, nullptr, 0, &archive));
    ASSERT_EQ(GARC_OK, garc_fs_open(at(name).c_str(), nullptr, nullptr,
                           GARC_FS_NAME_HINT, &archive));
    EXPECT_EQ(sample(), read_all(archive));
    garc_close(archive);
  }
  // The same brotli bytes under a name that says nothing are not guessed at.
  write_file(at("b.tar"), compressed(tar, "brotli"));
  GARC_Archive * archive = nullptr;
  EXPECT_EQ(GARC_ERR_FORMAT, garc_fs_open(at("b.tar").c_str(), nullptr, nullptr,
                                 GARC_FS_NAME_HINT, &archive));
  // lzip's .tlz is not taken for .lzma.
  write_file(at("l.tlz"), compressed(tar, "lzma"));
  EXPECT_EQ(GARC_ERR_FORMAT, garc_fs_open(at("l.tlz").c_str(), nullptr, nullptr,
                                 GARC_FS_NAME_HINT, &archive));
  EXPECT_EQ(nullptr, archive);
}

TEST_F(FsFile, OpenDoesNotTrustAZlibGuess) {
  const std::string bytes = compressed(tar_bytes(sample()), "zlib");
  const char * name = nullptr;
  // The control: compress does call these bytes zlib.
  ASSERT_EQ(GCOMP_OK, gcomp_detect(bytes.data(), bytes.size(), &name, nullptr));
  ASSERT_STREQ("zlib", name);
  write_file(at("z.tar.zlib"), bytes);
  GARC_Archive * archive = nullptr;
  EXPECT_EQ(GARC_ERR_FORMAT, garc_fs_open(at("z.tar.zlib").c_str(), nullptr,
                                 nullptr, GARC_FS_NAME_HINT, &archive));
}

TEST_F(FsFile, OpenTriesTheContainersBeforeTheCodecs) {
  // A tar whose first bytes are its first member's name, chosen to be bzip2's
  // magic. Sniffing first would decode it as bzip2 and fail.
  const std::vector<Entry> entries = {{"BZh91AY&SY", "not bzip2"}};
  const std::string tar = tar_bytes(entries);
  const char * name = nullptr;
  ASSERT_EQ(GCOMP_OK, gcomp_detect(tar.data(), tar.size(), &name, nullptr));
  ASSERT_STREQ("bzip2", name);
  write_file(at("looks-like.bz2"), tar);
  GARC_Archive * archive = nullptr;
  ASSERT_EQ(GARC_OK, garc_fs_open(at("looks-like.bz2").c_str(), nullptr,
                         nullptr, 0, &archive));
  EXPECT_EQ(entries, read_all(archive));
  garc_close(archive);
}

TEST_F(FsFile, OpenOfACompressedFileThatIsNotAnArchiveIsFormat) {
  write_file(at("notes.txt.gz"), compressed("just some text\n", "gzip"));
  write_file(at("random"), std::string(700, '\x5a'));
  GARC_Archive * archive = nullptr;
  EXPECT_EQ(GARC_ERR_FORMAT,
      garc_fs_open(at("notes.txt.gz").c_str(), nullptr, nullptr, 0, &archive));
  EXPECT_EQ(GARC_ERR_FORMAT,
      garc_fs_open(at("random").c_str(), nullptr, nullptr, 0, &archive));
  EXPECT_EQ(GARC_ERR_NOT_FOUND,
      garc_fs_open(at("absent").c_str(), nullptr, nullptr, 0, &archive));
  EXPECT_EQ(GARC_ERR_INVALID,
      garc_fs_open(at("random").c_str(), nullptr, nullptr, GARC_FS_NO_SYNC,
          &archive));
  EXPECT_EQ(nullptr, archive);
}

TEST_F(FsFile, OpenPassesLimitsAndCodecOptionsThrough) {
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(GARC_OK, garc_fs_sink_create(at("cap.tar.gz").c_str(), "gzip",
                         nullptr, GARC_FS_NO_SYNC, &sink));
  ASSERT_EQ(GARC_OK, write_archive(sink, GARC_FORMAT_TAR, sample()));
  garc_sink_destroy(sink);

  GARC_Limits limits;
  garc_limits_default(&limits);
  limits.max_members = 1;
  GARC_Archive * archive = nullptr;
  ASSERT_EQ(GARC_OK,
      garc_fs_open(at("cap.tar.gz").c_str(), &limits, nullptr, 0, &archive));
  const GARC_Member * member = nullptr;
  EXPECT_EQ(GARC_OK, garc_next(archive, &member));
  EXPECT_EQ(GARC_ERR_LIMIT_MEMBERS, garc_next(archive, &member));
  garc_close(archive);

  gcomp_options_t * options = nullptr;
  ASSERT_EQ(GCOMP_OK, gcomp_options_create(&options));
  ASSERT_EQ(GCOMP_OK, gcomp_options_set_uint64(options, "limits.max_output_bytes", 1024));
  ASSERT_EQ(GARC_OK,
      garc_fs_open(at("cap.tar.gz").c_str(), nullptr, options, 0, &archive));
  GARC_Result last = GARC_OK;
  while ((last = garc_next(archive, &member)) == GARC_OK) {
    char buffer[4096];
    size_t got = 0;
    while ((last = garc_read_member(archive, buffer, sizeof(buffer), &got))
            == GARC_OK
        && got) {
    }
    if (last != GARC_OK) {
      break;
    }
  }
  EXPECT_EQ(GARC_ERR_LIMIT_CODEC_BYTES, last);
  garc_close(archive);
  gcomp_options_destroy(options);
}

TEST_F(FsFile, FsFlagsDoNotLeakBetweenCalls) {
  // One bit space, and each call accepts only its own bits.
  write_file(at("t.tar"), tar_bytes(sample()));
  GARC_Archive * archive = nullptr;
  ASSERT_EQ(GARC_OK,
      garc_fs_open(at("t.tar").c_str(), nullptr, nullptr, 0, &archive));
  EXPECT_EQ(GARC_ERR_INVALID,
      garc_fs_extract(archive, dir.c_str(), GARC_FS_NAME_HINT));
  EXPECT_EQ(GARC_ERR_INVALID,
      garc_fs_extract(archive, dir.c_str(), GARC_FS_NO_SYNC));
  garc_close(archive);
}

TEST_F(FsFile, ExtractAndPackNameAMissingRoot) {
  // They said GARC_ERR_IO before the filesystem layer had a status for it.
  write_file(at("t.tar"), tar_bytes(sample()));
  GARC_Archive * archive = nullptr;
  ASSERT_EQ(GARC_OK,
      garc_fs_open(at("t.tar").c_str(), nullptr, nullptr, 0, &archive));
  EXPECT_EQ(GARC_ERR_NOT_FOUND,
      garc_fs_extract(archive, at("absent").c_str(), 0));
  garc_close(archive);

  GARC_Sink * sink = nullptr;
  GARC_Writer * writer = nullptr;
  ASSERT_EQ(GARC_OK, garc_sink_create_memory(&sink));
  ASSERT_EQ(GARC_OK, garc_writer_create(sink, GARC_FORMAT_TAR, nullptr, &writer));
  EXPECT_EQ(GARC_ERR_NOT_FOUND, garc_fs_pack(writer, at("absent").c_str(), 0));
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
}

////////////////////////////////////////////////////////////////////////
// Allocation failure
////////////////////////////////////////////////////////////////////////

TEST_F(FsFile, EveryAllocationFailureIsReportedAndFreesWhatItTook) {
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(GARC_OK, garc_fs_sink_create(at("in.tar.xz").c_str(), "xz", nullptr,
                         GARC_FS_NO_SYNC, &sink));
  ASSERT_EQ(GARC_OK, write_archive(sink, GARC_FORMAT_TAR, sample()));
  garc_sink_destroy(sink);
  const std::set<std::string> before = names();

  bool reached_ok_open = false;
  bool reached_ok_sink = false;
  for (size_t budget = 0; budget < 64u; ++budget) {
    SCOPED_TRACE(budget);
    {
      FailingAllocator allocator(budget);
      GARC_Archive * archive = nullptr;
      GARC_Result result = garc_fs_open_with_allocator(at("in.tar.xz").c_str(),
          nullptr, nullptr, 0, allocator.get(), &archive);
      EXPECT_TRUE(result == GARC_OK || result == GARC_ERR_OOM)
          << garc_result_string(result);
      allocator.stop_failing();
      if (result == GARC_OK) {
        reached_ok_open = true;
        EXPECT_EQ(sample(), read_all(archive));
      }
      garc_close(archive);
      EXPECT_EQ(0u, allocator.live());
    }
    {
      FailingAllocator allocator(budget);
      GARC_Result result = garc_fs_sink_create_with_allocator(
          at("out.tar.gz").c_str(), "gzip", nullptr, GARC_FS_NO_SYNC,
          allocator.get(), &sink);
      EXPECT_TRUE(result == GARC_OK || result == GARC_ERR_OOM)
          << garc_result_string(result);
      if (result == GARC_OK) {
        reached_ok_sink = true;
        garc_sink_destroy(sink);
      }
      EXPECT_EQ(0u, allocator.live());
      EXPECT_EQ(before, names());
    }
  }
  // The sweep must walk past the last allocation, or it measured only failures.
  EXPECT_TRUE(reached_ok_open);
  EXPECT_TRUE(reached_ok_sink);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
