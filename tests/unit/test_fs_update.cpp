/**
 * @file
 *
 * Changing an archive file: delete, replace, rename and append by rewriting it,
 * and append to an uncompressed tar where it lies.
 *
 * The promise is about the file on disk, so the tests look at the file: the
 * original's bytes are unchanged until a commit, an abandoned update leaves
 * them exactly as they were, and nothing is left in the directory but the
 * archive.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstring>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <ghoti.io/archive/fs.h>
#include <ghoti.io/cutil/dir.h>
#include <ghoti.io/cutil/file.h>

namespace {

using Entry = std::pair<std::string, std::string>;

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
  member.mtime_seconds = 1000000000;
  member.mtime_source = GARC_TIME_TAR_OCTAL;
  return member;
}

GARC_Result add(GARC_Writer * writer, const Entry & entry) {
  const GARC_Member member = file_member(entry);
  GARC_Result result = garc_writer_add(writer, &member);
  if (result == GARC_OK && !entry.second.empty()) {
    result = garc_writer_write(writer, entry.second.data(), entry.second.size());
  }
  return result;
}

std::vector<Entry> read_all(const std::string & path) {
  std::vector<Entry> found;
  GARC_Archive * archive = nullptr;
  EXPECT_EQ(garc_fs_open(path.c_str(), nullptr, nullptr, GARC_FS_NAME_HINT,
                &archive),
      GARC_OK);
  if (!archive) {
    return found;
  }
  if (garc_format(archive) == GARC_FORMAT_ZIP) {
    garc_zip_set_password(archive, "ghoti-password", 14);
  }
  const GARC_Member * member = nullptr;
  GARC_Result result;
  while ((result = garc_next(archive, &member)) == GARC_OK) {
    Entry entry(std::string(member->name, member->name_length), "");
    char buffer[4096];
    size_t got = 0;
    while (garc_read_member(archive, buffer, sizeof(buffer), &got) == GARC_OK
        && got) {
      entry.second.append(buffer, got);
    }
    found.push_back(entry);
  }
  EXPECT_EQ(result, GARC_END);
  garc_close(archive);
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

const std::vector<Entry> kThree = {
    {"a.txt", "alpha\n"}, {"b.txt", "bravo\n"}, {"c.txt", "charlie\n"}};

class FsUpdate : public testing::Test {
protected:
  std::string dir;

  void SetUp() override {
    char * made = nullptr;
    ASSERT_EQ(GCU_FILE_OK,
        gcu_dir_temp_create(nullptr, "garc-fs-update", nullptr, &made));
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

  /** An archive of @p entries at @p name, written by this library. */
  void make(const std::string & name, GARC_Format format,
      const std::vector<Entry> & entries, const char * method = nullptr) {
    GARC_Sink * sink = nullptr;
    ASSERT_EQ(garc_fs_sink_create(at(name).c_str(), method, nullptr,
                  GARC_FS_NO_SYNC, &sink),
        GARC_OK);
    GARC_Writer * writer = nullptr;
    ASSERT_EQ(garc_writer_create(sink, format, nullptr, &writer), GARC_OK);
    for (const Entry & entry : entries) {
      ASSERT_EQ(add(writer, entry), GARC_OK);
    }
    ASSERT_EQ(garc_writer_finish(writer), GARC_OK);
    ASSERT_EQ(garc_sink_finish(sink), GARC_OK);
    garc_writer_destroy(writer);
    garc_sink_destroy(sink);
  }
};

} // namespace

TEST_F(FsUpdate, DeleteReplaceAndAddByRewritingEveryFormat) {
  const std::vector<std::pair<GARC_Format, const char *>> formats = {
      {GARC_FORMAT_TAR, nullptr}, {GARC_FORMAT_TAR, "gzip"},
      {GARC_FORMAT_TAR, "zstd"}, {GARC_FORMAT_ZIP, nullptr},
      {GARC_FORMAT_SEVENZ, nullptr}, {GARC_FORMAT_AR, nullptr},
      {GARC_FORMAT_CPIO, nullptr}};
  for (const auto & [format, method] : formats) {
    const std::string name = std::string("x-") + garc_format_string(format)
        + (method ? std::string(".") + method : "");
    SCOPED_TRACE(name);
    make(name, format, kThree, method);
    const std::string before = read_file(at(name));

    GARC_Fs_Update * update = nullptr;
    ASSERT_EQ(garc_fs_update_begin(at(name).c_str(), nullptr, nullptr,
                  GARC_FS_NO_SYNC, &update),
        GARC_OK);
    GARC_Archive * archive = garc_fs_update_archive(update);
    ASSERT_NE(archive, nullptr);
    const GARC_Member * member = nullptr;
    while (garc_next(archive, &member) == GARC_OK) {
      const std::string member_name(member->name, member->name_length);
      if (member_name == "b.txt") {
        continue; // deleted, and replaced below
      }
      ASSERT_EQ(garc_fs_update_keep(update), GARC_OK);
    }
    ASSERT_EQ(add(garc_fs_update_writer(update), {"b.txt", "BRAVO, again\n"}),
        GARC_OK);
    ASSERT_EQ(add(garc_fs_update_writer(update), {"d.txt", "delta\n"}), GARC_OK);
    // Until the commit the file is what it was.
    EXPECT_EQ(read_file(at(name)), before);
    ASSERT_EQ(garc_fs_update_commit(update), GARC_OK);
    garc_fs_update_destroy(update);

    EXPECT_EQ(read_all(at(name)),
        (std::vector<Entry>{{"a.txt", "alpha\n"}, {"c.txt", "charlie\n"},
            {"b.txt", "BRAVO, again\n"}, {"d.txt", "delta\n"}}));
    if (method) {
      // Written back through the codec it was read through.
      const std::string after = read_file(at(name));
      EXPECT_EQ(after.substr(0, 2), before.substr(0, 2));
    }
    // And nothing left behind beside it.
    EXPECT_EQ(names().count(name), 1u);
  }
  EXPECT_EQ(names().size(), formats.size());
}

TEST_F(FsUpdate, AnAbandonedRewriteLeavesTheFileAndNoTemporary) {
  make("keep.zip", GARC_FORMAT_ZIP, kThree);
  const std::string before = read_file(at("keep.zip"));
  const std::set<std::string> listing = names();
  GARC_Fs_Update * update = nullptr;
  ASSERT_EQ(garc_fs_update_begin(at("keep.zip").c_str(), nullptr, nullptr,
                GARC_FS_NO_SYNC, &update),
      GARC_OK);
  ASSERT_EQ(garc_fs_update_keep_rest(update), GARC_OK);
  ASSERT_EQ(add(garc_fs_update_writer(update), {"new.txt", "never\n"}), GARC_OK);
  garc_fs_update_destroy(update);
  EXPECT_EQ(read_file(at("keep.zip")), before);
  EXPECT_EQ(names(), listing);
}

TEST_F(FsUpdate, KeepingAZipMemberCopiesItAsStoredWithoutItsPassword) {
  // An AES member, kept by an update that never has the password: the bytes
  // are moved, not decrypted, and still decrypt with it afterwards.
  GARC_Writer_Options options;
  garc_writer_options_default(&options);
  options.zip_password = "ghoti-password";
  options.zip_password_length = 14;
  options.zip_method = GARC_ZIP_METHOD_DEFLATE;
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_fs_sink_create(at("secret.zip").c_str(), nullptr, nullptr,
                GARC_FS_NO_SYNC, &sink),
      GARC_OK);
  GARC_Writer * writer = nullptr;
  ASSERT_EQ(garc_writer_create(sink, GARC_FORMAT_ZIP, &options, &writer), GARC_OK);
  ASSERT_EQ(add(writer, {"secret.txt", std::string(3000, 's') + "\n"}), GARC_OK);
  ASSERT_EQ(garc_writer_finish(writer), GARC_OK);
  ASSERT_EQ(garc_sink_finish(sink), GARC_OK);
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);

  GARC_Fs_Update * update = nullptr;
  ASSERT_EQ(garc_fs_update_begin(at("secret.zip").c_str(), nullptr, nullptr,
                GARC_FS_NO_SYNC, &update),
      GARC_OK);
  ASSERT_EQ(garc_fs_update_keep_rest(update), GARC_OK);
  ASSERT_EQ(add(garc_fs_update_writer(update), {"plain.txt", "open\n"}), GARC_OK);
  ASSERT_EQ(garc_fs_update_commit(update), GARC_OK);
  garc_fs_update_destroy(update);

  EXPECT_EQ(read_all(at("secret.zip")),
      (std::vector<Entry>{{"secret.txt", std::string(3000, 's') + "\n"},
          {"plain.txt", "open\n"}}));
}

TEST_F(FsUpdate, RenameIsACopyWithANewName) {
  make("r.tar", GARC_FORMAT_TAR, kThree);
  GARC_Fs_Update * update = nullptr;
  ASSERT_EQ(garc_fs_update_begin(at("r.tar").c_str(), nullptr, nullptr,
                GARC_FS_NO_SYNC, &update),
      GARC_OK);
  GARC_Archive * archive = garc_fs_update_archive(update);
  const GARC_Member * member = nullptr;
  while (garc_next(archive, &member) == GARC_OK) {
    GARC_Member as = *member;
    const std::string renamed = "renamed-" + std::string(member->name, member->name_length);
    as.name = renamed.data();
    as.name_length = renamed.size();
    ASSERT_EQ(garc_writer_copy_member(garc_fs_update_writer(update), archive, &as, 0),
        GARC_OK);
  }
  ASSERT_EQ(garc_fs_update_commit(update), GARC_OK);
  garc_fs_update_destroy(update);
  const std::vector<Entry> after = read_all(at("r.tar"));
  ASSERT_EQ(after.size(), 3u);
  EXPECT_EQ(after[1], (Entry{"renamed-b.txt", "bravo\n"}));
}

TEST_F(FsUpdate, AppendingInPlaceLeavesTheOriginalBytesAndAddsAfterThem) {
  make("log.tar", GARC_FORMAT_TAR, kThree);
  const std::string before = read_file(at("log.tar"));
  GARC_Fs_Update * update = nullptr;
  ASSERT_EQ(garc_fs_update_begin(at("log.tar").c_str(), nullptr, nullptr,
                GARC_FS_IN_PLACE | GARC_FS_NO_SYNC, &update),
      GARC_OK);
  EXPECT_EQ(garc_fs_update_archive(update), nullptr);
  EXPECT_EQ(garc_fs_update_keep(update), GARC_ERR_INVALID);
  ASSERT_EQ(add(garc_fs_update_writer(update), {"d.txt", "delta\n"}), GARC_OK);
  ASSERT_EQ(garc_fs_update_commit(update), GARC_OK);
  garc_fs_update_destroy(update);

  const std::string after = read_file(at("log.tar"));
  // Three members of one block of data each: the members end at 3 * 1024.
  const size_t end = 3u * 1024u;
  ASSERT_GE(after.size(), end);
  EXPECT_EQ(after.substr(0, end), before.substr(0, end));
  EXPECT_EQ(read_all(at("log.tar")),
      (std::vector<Entry>{{"a.txt", "alpha\n"}, {"b.txt", "bravo\n"},
          {"c.txt", "charlie\n"}, {"d.txt", "delta\n"}}));
  EXPECT_EQ(names(), (std::set<std::string>{"log.tar"}));
}

TEST_F(FsUpdate, AnAbandonedInPlaceAppendPutsTheFileBackAsItWas) {
  make("log.tar", GARC_FORMAT_TAR, kThree);
  const std::string before = read_file(at("log.tar"));
  GARC_Fs_Update * update = nullptr;
  ASSERT_EQ(garc_fs_update_begin(at("log.tar").c_str(), nullptr, nullptr,
                GARC_FS_IN_PLACE | GARC_FS_NO_SYNC, &update),
      GARC_OK);
  ASSERT_EQ(add(garc_fs_update_writer(update),
                {"half.txt", std::string(5000, 'h')}),
      GARC_OK);
  garc_fs_update_destroy(update);
  // Byte for byte the file it was: the tail put back and the length restored.
  EXPECT_EQ(read_file(at("log.tar")), before);
  EXPECT_EQ(read_all(at("log.tar")), kThree);
}

TEST_F(FsUpdate, AppendingInPlaceToAnEmptyTarStartsAtTheBeginning) {
  make("empty.tar", GARC_FORMAT_TAR, {});
  GARC_Fs_Update * update = nullptr;
  ASSERT_EQ(garc_fs_update_begin(at("empty.tar").c_str(), nullptr, nullptr,
                GARC_FS_IN_PLACE | GARC_FS_NO_SYNC, &update),
      GARC_OK);
  ASSERT_EQ(add(garc_fs_update_writer(update), {"first.txt", "one\n"}), GARC_OK);
  ASSERT_EQ(garc_fs_update_commit(update), GARC_OK);
  garc_fs_update_destroy(update);
  EXPECT_EQ(read_all(at("empty.tar")), (std::vector<Entry>{{"first.txt", "one\n"}}));
}

TEST_F(FsUpdate, AppendingInPlaceToAZipWritesAfterItsMembersAndANewDirectory) {
  // The new members go where the old directory began; the directory written
  // after them is the old one's entries and the new ones', with new end
  // records. Every member before the directory is the same bytes.
  make("log.zip", GARC_FORMAT_ZIP, kThree);
  const std::string before = read_file(at("log.zip"));
  const size_t directory = before.find(std::string("PK\x01\x02", 4));
  ASSERT_NE(directory, std::string::npos);
  GARC_Fs_Update * update = nullptr;
  ASSERT_EQ(garc_fs_update_begin(at("log.zip").c_str(), nullptr, nullptr,
                GARC_FS_IN_PLACE | GARC_FS_NO_SYNC, &update),
      GARC_OK);
  EXPECT_EQ(garc_fs_update_archive(update), nullptr);
  ASSERT_EQ(add(garc_fs_update_writer(update), {"d.txt", "delta\n"}), GARC_OK);
  ASSERT_EQ(add(garc_fs_update_writer(update), {"e.txt", std::string(9000, 'e')}),
      GARC_OK);
  ASSERT_EQ(garc_fs_update_commit(update), GARC_OK);
  garc_fs_update_destroy(update);
  const std::string after = read_file(at("log.zip"));
  EXPECT_EQ(after.substr(0, directory), before.substr(0, directory));
  EXPECT_EQ(read_all(at("log.zip")),
      (std::vector<Entry>{{"a.txt", "alpha\n"}, {"b.txt", "bravo\n"},
          {"c.txt", "charlie\n"}, {"d.txt", "delta\n"},
          {"e.txt", std::string(9000, 'e')}}));
  EXPECT_EQ(names(), (std::set<std::string>{"log.zip"}));

  // And a second append, onto the first one's directory.
  ASSERT_EQ(garc_fs_update_begin(at("log.zip").c_str(), nullptr, nullptr,
                GARC_FS_IN_PLACE | GARC_FS_NO_SYNC, &update),
      GARC_OK);
  ASSERT_EQ(add(garc_fs_update_writer(update), {"f.txt", "foxtrot\n"}), GARC_OK);
  ASSERT_EQ(garc_fs_update_commit(update), GARC_OK);
  garc_fs_update_destroy(update);
  EXPECT_EQ(read_all(at("log.zip")).size(), 6u);
}

TEST_F(FsUpdate, AnAbandonedInPlaceZipAppendPutsTheFileBackAsItWas) {
  make("log.zip", GARC_FORMAT_ZIP, kThree);
  const std::string before = read_file(at("log.zip"));
  GARC_Fs_Update * update = nullptr;
  ASSERT_EQ(garc_fs_update_begin(at("log.zip").c_str(), nullptr, nullptr,
                GARC_FS_IN_PLACE | GARC_FS_NO_SYNC, &update),
      GARC_OK);
  ASSERT_EQ(add(garc_fs_update_writer(update), {"half.txt", std::string(50000, 'h')}),
      GARC_OK);
  garc_fs_update_destroy(update);
  EXPECT_EQ(read_file(at("log.zip")), before);
  EXPECT_EQ(read_all(at("log.zip")), kThree);
  EXPECT_EQ(names(), (std::set<std::string>{"log.zip"}));
}

TEST_F(FsUpdate, AppendingInPlaceToAZipBehindAStubKeepsItsOffsets) {
  // A self-extractor's stub in front: the archive's offsets count from where
  // the stub ends, and the new members' must too.
  make("plain.zip", GARC_FORMAT_ZIP, kThree);
  const std::string stub(3000, 'S');
  {
    GARC_Sink * sink = nullptr;
    ASSERT_EQ(garc_fs_sink_create(at("sfx.exe").c_str(), nullptr, nullptr,
                  GARC_FS_NO_SYNC, &sink), GARC_OK);
    const std::string body = stub + read_file(at("plain.zip"));
    ASSERT_EQ(garc_sink_write(sink, body.data(), body.size()), GARC_OK);
    ASSERT_EQ(garc_sink_finish(sink), GARC_OK);
    garc_sink_destroy(sink);
  }
  // Built as the stub plus a zip whose offsets were written from 0, so the
  // reader discovers the stub's length.
  GARC_Fs_Update * update = nullptr;
  ASSERT_EQ(garc_fs_update_begin(at("sfx.exe").c_str(), nullptr, nullptr,
                GARC_FS_IN_PLACE | GARC_FS_NO_SYNC, &update),
      GARC_OK);
  ASSERT_EQ(add(garc_fs_update_writer(update), {"d.txt", "delta\n"}), GARC_OK);
  ASSERT_EQ(garc_fs_update_commit(update), GARC_OK);
  garc_fs_update_destroy(update);
  EXPECT_EQ(read_file(at("sfx.exe")).substr(0, stub.size()), stub);
  EXPECT_EQ(read_all(at("sfx.exe")).size(), 4u);
}

TEST_F(FsUpdate, InPlaceIsRefusedWhereItCannotBeHonest) {
  make("x.zip", GARC_FORMAT_ZIP, kThree);
  make("x.tar.gz", GARC_FORMAT_TAR, kThree, "gzip");
  // A pax global header, which would apply to the appended members too.
  {
    GARC_Sink * sink = nullptr;
    ASSERT_EQ(garc_fs_sink_create(at("g.tar").c_str(), nullptr, nullptr,
                  GARC_FS_NO_SYNC, &sink),
        GARC_OK);
    const std::string records = "18 mtime=12345678\n";
    std::string block(512, '\0');
    std::memcpy(&block[0], "./GlobalHead", 12);
    std::memcpy(&block[100], "0000644", 7);
    std::memcpy(&block[108], "0000000", 7);
    std::memcpy(&block[116], "0000000", 7);
    std::memcpy(&block[124], "00000000022", 11);
    std::memcpy(&block[136], "00000000000", 11);
    block[156] = 'g';
    std::memcpy(&block[257], "ustar", 6);
    std::memcpy(&block[263], "00", 2);
    std::memset(&block[148], ' ', 8);
    unsigned sum = 0;
    for (unsigned char byte : block) {
      sum += byte;
    }
    char text[8];
    std::snprintf(text, sizeof(text), "%06o", sum);
    std::memcpy(&block[148], text, 7);
    std::string data = records;
    data.resize(512, '\0');
    ASSERT_EQ(garc_sink_write(sink, block.data(), block.size()), GARC_OK);
    ASSERT_EQ(garc_sink_write(sink, data.data(), data.size()), GARC_OK);
    GARC_Writer * writer = nullptr;
    GARC_Sink_Callbacks pass{};
    (void)pass;
    ASSERT_EQ(garc_writer_create(sink, GARC_FORMAT_TAR, nullptr, &writer), GARC_OK);
    ASSERT_EQ(add(writer, {"m.txt", "m\n"}), GARC_OK);
    ASSERT_EQ(garc_writer_finish(writer), GARC_OK);
    ASSERT_EQ(garc_sink_finish(sink), GARC_OK);
    garc_writer_destroy(writer);
    garc_sink_destroy(sink);
  }
  for (const char * name : {"x.tar.gz", "g.tar"}) {
    SCOPED_TRACE(name);
    const std::string before = read_file(at(name));
    GARC_Fs_Update * update = nullptr;
    EXPECT_EQ(garc_fs_update_begin(at(name).c_str(), nullptr, nullptr,
                  GARC_FS_IN_PLACE, &update),
        GARC_ERR_UNSUPPORTED);
    EXPECT_EQ(update, nullptr);
    EXPECT_EQ(read_file(at(name)), before);
  }
  GARC_Fs_Update * update = nullptr;
  EXPECT_EQ(garc_fs_update_begin(at("x.zip").c_str(), nullptr, nullptr, 1u << 9,
                &update),
      GARC_ERR_INVALID);
  // A zip asked to be split, appended to where it lies.
  GARC_Writer_Options split;
  garc_writer_options_default(&split);
  split.zip_volume_size = 65536;
  const std::string zip_before = read_file(at("x.zip"));
  EXPECT_EQ(garc_fs_update_begin(at("x.zip").c_str(), nullptr, &split,
                GARC_FS_IN_PLACE, &update),
      GARC_ERR_INVALID);
  EXPECT_EQ(read_file(at("x.zip")), zip_before);
  EXPECT_EQ(garc_fs_update_begin(at("absent.tar").c_str(), nullptr, nullptr, 0,
                &update),
      GARC_ERR_NOT_FOUND);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
