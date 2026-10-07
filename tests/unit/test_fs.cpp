/**
 * @file
 *
 * Extracting into a directory and packing one back.
 *
 * The hostile fixtures are the gate. A name the classifier calls an escape is
 * not written, a link is not created unless the call asked for links, and a
 * refusal leaves what was already written without deleting the root.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstring>
#include <set>
#include <string>
#include <vector>

#include <sys/stat.h>

#include <gtest/gtest.h>

#include <ghoti.io/archive/fs.h>
#include <ghoti.io/cutil/dir.h>
#include <ghoti.io/cutil/file.h>
#include <ghoti.io/cutil/path.h>

#include "tar_builder.h"
#include "tar_manifest.h"

using garctest::TarArchive;
using garctest::file_header;
using garctest::pax_header;
using garctest::pax_record;
using garctest::read_fixture;

namespace {

std::string tar_fixture(const std::string & name) {
  return std::string(GARC_TEST_DATA) + "/tar/" + name;
}

std::string zip_fixture(const std::string & name) {
  return std::string(GARC_TEST_DATA) + "/zip/" + name;
}

std::string join_path(const std::string & dir, const std::string & name) {
  return dir + "/" + name;
}

std::set<std::string> list_dir(const std::string & path) {
  std::set<std::string> names;
  GCU_Dir dir;
  std::memset(&dir, 0, sizeof(dir));
  if (gcu_dir_open(&dir, path.c_str(), nullptr) != GCU_FILE_OK) {
    return names;
  }
  for (;;) {
    const char * name = nullptr;
    bool done = false;
    if (gcu_dir_read(&dir, &name, nullptr, &done) != GCU_FILE_OK || done) {
      break;
    }
    names.insert(name);
  }
  gcu_dir_close(&dir);
  return names;
}

void remove_tree(const std::string & path) {
  GCU_File_Info info;
  if (gcu_file_stat_link(path.c_str(), &info) != GCU_FILE_OK) {
    return;
  }
  if (info.type == GCU_FILE_TYPE_DIRECTORY) {
    GCU_Dir dir;
    std::memset(&dir, 0, sizeof(dir));
    if (gcu_dir_open(&dir, path.c_str(), nullptr) == GCU_FILE_OK) {
      for (;;) {
        const char * name = nullptr;
        bool done = false;
        if (gcu_dir_read(&dir, &name, nullptr, &done) != GCU_FILE_OK || done) {
          break;
        }
        remove_tree(join_path(path, name));
      }
      gcu_dir_close(&dir);
    }
    gcu_dir_remove(path.c_str());
    return;
  }
  gcu_file_remove(path.c_str());
}

/** True when any symlink exists under path. Does not follow links. */
bool tree_has_symlink(const std::string & path) {
  GCU_File_Info info;
  if (gcu_file_stat_link(path.c_str(), &info) != GCU_FILE_OK) {
    return false;
  }
  if (info.type == GCU_FILE_TYPE_SYMLINK) {
    return true;
  }
  if (info.type != GCU_FILE_TYPE_DIRECTORY) {
    return false;
  }
  GCU_Dir dir;
  std::memset(&dir, 0, sizeof(dir));
  if (gcu_dir_open(&dir, path.c_str(), nullptr) != GCU_FILE_OK) {
    return false;
  }
  bool found = false;
  for (;;) {
    const char * name = nullptr;
    bool done = false;
    if (gcu_dir_read(&dir, &name, nullptr, &done) != GCU_FILE_OK || done) {
      break;
    }
    if (tree_has_symlink(join_path(path, name))) {
      found = true;
      break;
    }
  }
  gcu_dir_close(&dir);
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
          GCU_FILE_SYNC_NONE, GCU_FILE_PERMS_PRIVATE, nullptr));
}

struct Opened {
  std::vector<uint8_t> bytes;
  GARC_Stream * stream = nullptr;
  GARC_Archive * archive = nullptr;

  explicit Opened(std::vector<uint8_t> data) : bytes(std::move(data)) {}

  ~Opened() {
    garc_close(archive);
    garc_stream_destroy(stream);
  }

  Opened(const Opened &) = delete;
  Opened & operator=(const Opened &) = delete;

  void open() {
    ASSERT_FALSE(bytes.empty());
    ASSERT_EQ(GARC_OK,
        garc_stream_create_memory(bytes.data(), bytes.size(), &stream));
    ASSERT_EQ(GARC_OK, garc_open(stream, nullptr, &archive));
  }
};

class ExtractRoot : public testing::Test {
protected:
  std::string root;
  std::string parent;
  std::set<std::string> parent_before;

  void SetUp() override {
    char * made = nullptr;
    ASSERT_EQ(GCU_FILE_OK,
        gcu_dir_temp_create(nullptr, "garc-fs", nullptr, &made));
    root = made;
    gcu_dir_free_path(nullptr, made);

    char parent_buf[4096];
    size_t length = 0;
    ASSERT_EQ(GCU_PATH_OK,
        gcu_path_dirname(GCU_PATH_NATIVE, root.c_str(), parent_buf,
            sizeof(parent_buf), &length));
    parent = parent_buf;
    parent_before = list_dir(parent);
  }

  void TearDown() override {
    if (!root.empty()) {
      remove_tree(root);
    }
    gcu_file_remove("/tmp/ghoti-escaped");
    gcu_file_remove("/tmp/ghoti-escaped-fs");
  }

  void expect_parent_unchanged() {
    EXPECT_EQ(parent_before, list_dir(parent));
  }
};

TarArchive ordinary_tree() {
  return TarArchive()
      .header(file_header("sub", 0, 02755, '5'))
      .header(file_header("sub/note.txt", 5, 04755))
      .data("hello")
      .marker();
}

} // namespace

TEST_F(ExtractRoot, OrdinaryTreeKeepsBytesAndClearsSpecialModeBits) {
  Opened opened(ordinary_tree().bytes());
  opened.open();
  ASSERT_EQ(GARC_OK, garc_fs_extract(opened.archive, root.c_str(), 0));

  EXPECT_EQ("hello", read_file(join_path(root, "sub/note.txt")));
  GCU_File_Identity file_id;
  GCU_File_Identity dir_id;
  ASSERT_EQ(GCU_FILE_OK,
      gcu_file_identity(join_path(root, "sub/note.txt").c_str(), &file_id));
  ASSERT_EQ(GCU_FILE_OK,
      gcu_file_identity(join_path(root, "sub").c_str(), &dir_id));
  EXPECT_EQ(0u, file_id.mode & 07000u);
  EXPECT_EQ(0755u, file_id.mode & 0777u);
  EXPECT_EQ(0u, dir_id.mode & 07000u);
  EXPECT_EQ(0755u, dir_id.mode & 0777u);
  expect_parent_unchanged();
}

TEST_F(ExtractRoot, MalPathsTarWritesNothing) {
  Opened opened(read_fixture(tar_fixture("mal-paths.tar")));
  opened.open();
  EXPECT_EQ(GARC_ERR_REFUSED, garc_fs_extract(opened.archive, root.c_str(), 0));
  EXPECT_TRUE(list_dir(root).empty());
  EXPECT_FALSE(tree_has_symlink(root));
  expect_parent_unchanged();
  EXPECT_FALSE(gcu_file_exists("/tmp/ghoti-escaped"));
}

TEST_F(ExtractRoot, MalPathsZipWritesNothing) {
  Opened opened(read_fixture(zip_fixture("mal-paths.zip")));
  opened.open();
  EXPECT_EQ(GARC_ERR_REFUSED, garc_fs_extract(opened.archive, root.c_str(), 0));
  EXPECT_TRUE(list_dir(root).empty());
  EXPECT_FALSE(tree_has_symlink(root));
  expect_parent_unchanged();
}

TEST_F(ExtractRoot, MalLinksWithoutTheFlagCreatesNoSymlink) {
  Opened opened(read_fixture(tar_fixture("mal-links.tar")));
  opened.open();
  EXPECT_EQ(GARC_ERR_REFUSED, garc_fs_extract(opened.archive, root.c_str(), 0));
  EXPECT_FALSE(tree_has_symlink(root));
  EXPECT_TRUE(list_dir(root).empty());
  expect_parent_unchanged();
  EXPECT_FALSE(gcu_file_exists("/tmp/ghoti-escaped"));
}

TEST_F(ExtractRoot, LinkFlagStillRefusesATargetThatLeavesTheRoot) {
  Opened opened(read_fixture(tar_fixture("mal-links.tar")));
  opened.open();
  EXPECT_EQ(GARC_ERR_REFUSED,
      garc_fs_extract(opened.archive, root.c_str(), GARC_FS_ALLOW_LINKS));
  EXPECT_FALSE(tree_has_symlink(root));
  EXPECT_FALSE(gcu_file_exists("/tmp/ghoti-escaped"));
  expect_parent_unchanged();
}

TEST_F(ExtractRoot, ContainedSymlinkIsCreatedWhenLinksAreAllowed) {
  // file_header does not set the link field. The target is `inside`, which
  // stays in the root.
  garctest::TarHeader symlink;
  symlink.field(0, 100, "link");
  symlink.octal(100, 8, 0777);
  symlink.octal(108, 8, 0);
  symlink.octal(116, 8, 0);
  symlink.octal(124, 12, 0);
  symlink.octal(136, 12, 0);
  symlink.bytes[156] = '2';
  symlink.field(157, 100, "inside");
  symlink.ustar();
  symlink.checksum();
  TarArchive built = TarArchive()
                         .header(file_header("inside", 4, 0644))
                         .data("body")
                         .header(symlink)
                         .marker();
  Opened opened(built.bytes());
  opened.open();
  ASSERT_EQ(GARC_OK,
      garc_fs_extract(opened.archive, root.c_str(), GARC_FS_ALLOW_LINKS));
  GCU_File_Info info;
  ASSERT_EQ(GCU_FILE_OK,
      gcu_file_stat_link(join_path(root, "link").c_str(), &info));
  EXPECT_EQ(GCU_FILE_TYPE_SYMLINK, info.type);
  char * text = nullptr;
  size_t length = 0;
  ASSERT_EQ(GCU_FILE_OK,
      gcu_file_read_link(join_path(root, "link").c_str(), nullptr, &text,
          &length));
  EXPECT_EQ(std::string("inside"), std::string(text, length));
  gcu_file_free(nullptr, text);
  EXPECT_EQ("body", read_file(join_path(root, "link")));
  expect_parent_unchanged();
}

TEST_F(ExtractRoot, SymlinkWhoseTargetLeavesIsNotCreated) {
  garctest::TarHeader symlink;
  symlink.field(0, 100, "bad");
  symlink.octal(100, 8, 0777);
  symlink.octal(108, 8, 0);
  symlink.octal(116, 8, 0);
  symlink.octal(124, 12, 0);
  symlink.octal(136, 12, 0);
  symlink.bytes[156] = '2';
  symlink.field(157, 100, "/tmp/ghoti-escaped-fs");
  symlink.ustar();
  symlink.checksum();
  Opened opened(TarArchive().header(symlink).marker().bytes());
  opened.open();
  EXPECT_EQ(GARC_ERR_REFUSED,
      garc_fs_extract(opened.archive, root.c_str(), GARC_FS_ALLOW_LINKS));
  EXPECT_FALSE(gcu_file_exists(join_path(root, "bad").c_str()));
  EXPECT_FALSE(tree_has_symlink(root));
  EXPECT_FALSE(gcu_file_exists("/tmp/ghoti-escaped-fs"));
}

TEST_F(ExtractRoot, NulInANameIsNotCreated) {
  std::string value("foo");
  value.push_back('\0');
  value += "bar";
  std::string record = pax_record("path", value);
  Opened opened(TarArchive()
          .header(pax_header('x', record.size()))
          .data(record)
          .header(file_header("plain", 3, 0644))
          .data("abc")
          .marker()
          .bytes());
  opened.open();
  const GARC_Member * member = nullptr;
  ASSERT_EQ(GARC_OK, garc_next(opened.archive, &member));
  ASSERT_NE(nullptr, static_cast<const void *>(
      std::memchr(member->name, '\0', member->name_length)));
  // The reader is now past that member. Rebuild and extract from the start.
  Opened again(TarArchive()
          .header(pax_header('x', record.size()))
          .data(record)
          .header(file_header("plain", 3, 0644))
          .data("abc")
          .marker()
          .bytes());
  again.open();
  EXPECT_EQ(GARC_ERR_REFUSED, garc_fs_extract(again.archive, root.c_str(), 0));
  EXPECT_FALSE(gcu_file_exists(join_path(root, "foo").c_str()));
  EXPECT_FALSE(gcu_file_exists(join_path(root, "plain").c_str()));
  EXPECT_TRUE(list_dir(root).empty());
}

static void advance_past_member(GARC_Archive * archive, const char * name) {
  const size_t length = std::strlen(name);
  for (;;) {
    const GARC_Member * member = nullptr;
    ASSERT_EQ(GARC_OK, garc_next(archive, &member));
    if (member->name_length == length
        && std::memcmp(member->name, name, length) == 0) {
      return;
    }
  }
}

TEST_F(ExtractRoot, ReservedNameNeedsThePortabilityFlag) {
  // CON sits after the escapes in mal-paths.tar. A full extract stops on the
  // first of those, so the cursor is moved to the member before CON and the
  // extract starts there. The fixture continues past CON into another escape,
  // which is why the portability run still returns a refusal after CON exists.
  Opened blocked(read_fixture(tar_fixture("mal-paths.tar")));
  blocked.open();
  advance_past_member(blocked.archive, "..");
  if (HasFatalFailure()) {
    return;
  }
  EXPECT_EQ(GARC_ERR_REFUSED, garc_fs_extract(blocked.archive, root.c_str(), 0));
  EXPECT_FALSE(gcu_file_exists(join_path(root, "CON").c_str()));

  Opened allowed(read_fixture(tar_fixture("mal-paths.tar")));
  allowed.open();
  advance_past_member(allowed.archive, "..");
  if (HasFatalFailure()) {
    return;
  }
  EXPECT_EQ(GARC_ERR_REFUSED,
      garc_fs_extract(
          allowed.archive, root.c_str(), GARC_FS_ALLOW_PORTABLE_NAMES));
  EXPECT_TRUE(gcu_file_exists(join_path(root, "CON").c_str()));
  expect_parent_unchanged();
}

TEST_F(ExtractRoot, SecondMemberOnTheSameCanonicalPathIsNotWritten) {
  TarArchive archive = TarArchive()
                           .header(file_header("x", 4, 0644))
                           .data("keep")
                           .header(file_header("sub/../x", 4, 0644))
                           .data("nope")
                           .marker();
  Opened opened(archive.bytes());
  opened.open();
  EXPECT_EQ(GARC_ERR_REFUSED,
      garc_fs_extract(
          opened.archive, root.c_str(), GARC_FS_ALLOW_PORTABLE_NAMES));
  EXPECT_EQ("keep", read_file(join_path(root, "x")));
}

TEST_F(ExtractRoot, RefusalStopsAndLeavesTheEarlierFile) {
  TarArchive archive = TarArchive()
                           .header(file_header("good", 3, 0644))
                           .data("one")
                           .header(file_header("../evil", 3, 0644))
                           .data("two")
                           .header(file_header("later", 3, 0644))
                           .data("six")
                           .marker();
  Opened opened(archive.bytes());
  opened.open();
  EXPECT_EQ(GARC_ERR_REFUSED, garc_fs_extract(opened.archive, root.c_str(), 0));
  EXPECT_EQ("one", read_file(join_path(root, "good")));
  EXPECT_FALSE(gcu_file_exists(join_path(root, "later").c_str()));
  EXPECT_FALSE(gcu_file_exists(join_path(root, "evil").c_str()));
  expect_parent_unchanged();
}

TEST_F(ExtractRoot, AnExistingFileIsLeftUnchanged) {
  write_file(join_path(root, "keep.txt"), "original");
  Opened opened(TarArchive()
          .header(file_header("keep.txt", 3, 0644))
          .data("new")
          .marker()
          .bytes());
  opened.open();
  EXPECT_EQ(GARC_ERR_REFUSED, garc_fs_extract(opened.archive, root.c_str(), 0));
  EXPECT_EQ("original", read_file(join_path(root, "keep.txt")));
}

TEST_F(ExtractRoot, ParentComponentStaysInsideOnlyWithTheFlag) {
  TarArchive archive = TarArchive()
                           .header(file_header("sub/../inside.txt", 3, 0644))
                           .data("yes")
                           .marker();
  Opened blocked(archive.bytes());
  blocked.open();
  EXPECT_EQ(GARC_ERR_REFUSED, garc_fs_extract(blocked.archive, root.c_str(), 0));
  EXPECT_FALSE(gcu_file_exists(join_path(root, "inside.txt").c_str()));

  Opened allowed(archive.bytes());
  allowed.open();
  ASSERT_EQ(GARC_OK,
      garc_fs_extract(
          allowed.archive, root.c_str(), GARC_FS_ALLOW_PORTABLE_NAMES));
  EXPECT_EQ("yes", read_file(join_path(root, "inside.txt")));
  expect_parent_unchanged();
}

TEST_F(ExtractRoot, AParentComponentThatLeavesIsStillRefused) {
  Opened opened(TarArchive()
          .header(file_header("sub/../../outside.txt", 3, 0644))
          .data("no")
          .marker()
          .bytes());
  opened.open();
  EXPECT_EQ(GARC_ERR_REFUSED,
      garc_fs_extract(
          opened.archive, root.c_str(), GARC_FS_ALLOW_PORTABLE_NAMES));
  EXPECT_FALSE(gcu_file_exists(join_path(root, "outside.txt").c_str()));
  EXPECT_FALSE(gcu_file_exists(join_path(parent, "outside.txt").c_str()));
  expect_parent_unchanged();
}

TEST_F(ExtractRoot, PackAndExtractRoundTripMatchesBytesAndMasksModes) {
  ASSERT_EQ(GCU_FILE_OK, gcu_dir_create(join_path(root, "sub").c_str()));
  write_file(join_path(root, "sub/note.txt"), "hello");
  ASSERT_EQ(GCU_FILE_OK,
      gcu_file_set_mode(join_path(root, "sub/note.txt").c_str(), 06755));
  ASSERT_EQ(GCU_FILE_OK,
      gcu_file_set_mode(join_path(root, "sub").c_str(), 02755));

  GARC_Sink * sink = nullptr;
  ASSERT_EQ(GARC_OK, garc_sink_create_memory(&sink));
  GARC_Writer * writer = nullptr;
  ASSERT_EQ(GARC_OK,
      garc_writer_create(sink, GARC_FORMAT_TAR, nullptr, &writer));
  ASSERT_EQ(GARC_OK, garc_fs_pack(writer, root.c_str(), 0));
  ASSERT_EQ(GARC_OK, garc_writer_finish(writer));
  const void * packed = nullptr;
  size_t packed_size = 0;
  ASSERT_EQ(GARC_OK, garc_sink_data(sink, &packed, &packed_size));

  char * other = nullptr;
  ASSERT_EQ(GCU_FILE_OK,
      gcu_dir_temp_create(nullptr, "garc-fs-out", nullptr, &other));
  std::string out = other;
  gcu_dir_free_path(nullptr, other);

  Opened opened(std::vector<uint8_t>(
      static_cast<const uint8_t *>(packed),
      static_cast<const uint8_t *>(packed) + packed_size));
  opened.open();
  ASSERT_EQ(GARC_OK, garc_fs_extract(opened.archive, out.c_str(), 0));
  EXPECT_EQ("hello", read_file(join_path(out, "sub/note.txt")));
  GCU_File_Identity file_id;
  GCU_File_Identity dir_id;
  ASSERT_EQ(GCU_FILE_OK,
      gcu_file_identity(join_path(out, "sub/note.txt").c_str(), &file_id));
  ASSERT_EQ(GCU_FILE_OK,
      gcu_file_identity(join_path(out, "sub").c_str(), &dir_id));
  EXPECT_EQ(0u, file_id.mode & 07000u);
  EXPECT_EQ(0755u, file_id.mode);
  EXPECT_EQ(0u, dir_id.mode & 07000u);
  EXPECT_EQ(0755u, dir_id.mode);

  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
  remove_tree(out);
}

TEST_F(ExtractRoot, PackStoresASymlinkAndNotTheOutsideBytes) {
  write_file(join_path(parent, "secret-outside"), "SECRET-BYTES");
  ASSERT_EQ(GCU_FILE_OK,
      gcu_file_symlink(join_path(parent, "secret-outside").c_str(),
          join_path(root, "link").c_str()));

  GARC_Sink * sink = nullptr;
  ASSERT_EQ(GARC_OK, garc_sink_create_memory(&sink));
  GARC_Writer * writer = nullptr;
  ASSERT_EQ(GARC_OK,
      garc_writer_create(sink, GARC_FORMAT_TAR, nullptr, &writer));
  ASSERT_EQ(GARC_OK, garc_fs_pack(writer, root.c_str(), 0));
  ASSERT_EQ(GARC_OK, garc_writer_finish(writer));
  const void * packed = nullptr;
  size_t packed_size = 0;
  ASSERT_EQ(GARC_OK, garc_sink_data(sink, &packed, &packed_size));
  std::string archive(static_cast<const char *>(packed), packed_size);
  EXPECT_EQ(std::string::npos, archive.find("SECRET-BYTES"));

  Opened opened(std::vector<uint8_t>(
      static_cast<const uint8_t *>(packed),
      static_cast<const uint8_t *>(packed) + packed_size));
  opened.open();
  const GARC_Member * member = nullptr;
  ASSERT_EQ(GARC_OK, garc_next(opened.archive, &member));
  EXPECT_EQ(GARC_MEMBER_SYMLINK, member->type);
  EXPECT_EQ(std::string(join_path(parent, "secret-outside")),
      std::string(member->link_target, member->link_target_length));
  EXPECT_EQ(0u, member->size);

  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
  gcu_file_remove(join_path(parent, "secret-outside").c_str());
}

TEST_F(ExtractRoot, PackRefusesAHardLinkWhoseOtherNameIsOutside) {
  write_file(join_path(parent, "outside-file"), "out");
  ASSERT_EQ(GCU_FILE_OK,
      gcu_file_hardlink(join_path(parent, "outside-file").c_str(),
          join_path(root, "inside").c_str()));
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(GARC_OK, garc_sink_create_memory(&sink));
  GARC_Writer * writer = nullptr;
  ASSERT_EQ(GARC_OK,
      garc_writer_create(sink, GARC_FORMAT_TAR, nullptr, &writer));
  EXPECT_EQ(GARC_ERR_REFUSED, garc_fs_pack(writer, root.c_str(), 0));
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
  gcu_file_remove(join_path(parent, "outside-file").c_str());
}

TEST_F(ExtractRoot, HardLinkInsideTheTreeIsAHardLinkMember) {
  write_file(join_path(root, "hard"), "same");
  ASSERT_EQ(GCU_FILE_OK,
      gcu_file_hardlink(join_path(root, "hard").c_str(),
          join_path(root, "sibling").c_str()));
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(GARC_OK, garc_sink_create_memory(&sink));
  GARC_Writer * writer = nullptr;
  ASSERT_EQ(GARC_OK,
      garc_writer_create(sink, GARC_FORMAT_TAR, nullptr, &writer));
  ASSERT_EQ(GARC_OK, garc_fs_pack(writer, root.c_str(), 0));
  ASSERT_EQ(GARC_OK, garc_writer_finish(writer));
  const void * packed = nullptr;
  size_t packed_size = 0;
  ASSERT_EQ(GARC_OK, garc_sink_data(sink, &packed, &packed_size));

  char * other = nullptr;
  ASSERT_EQ(GCU_FILE_OK,
      gcu_dir_temp_create(nullptr, "garc-fs-hl", nullptr, &other));
  std::string out = other;
  gcu_dir_free_path(nullptr, other);
  Opened opened(std::vector<uint8_t>(
      static_cast<const uint8_t *>(packed),
      static_cast<const uint8_t *>(packed) + packed_size));
  opened.open();
  std::string file_name;
  std::string link_name;
  for (;;) {
    const GARC_Member * member = nullptr;
    GARC_Result step = garc_next(opened.archive, &member);
    if (step == GARC_END) {
      break;
    }
    ASSERT_EQ(GARC_OK, step);
    std::string name(member->name, member->name_length);
    if (member->type == GARC_MEMBER_HARDLINK) {
      link_name = std::string(member->link_target, member->link_target_length);
    }
    else if (member->type == GARC_MEMBER_FILE) {
      file_name = name;
    }
  }
  EXPECT_FALSE(file_name.empty());
  EXPECT_EQ(file_name, link_name);

  garc_close(opened.archive);
  opened.archive = nullptr;
  garc_stream_destroy(opened.stream);
  opened.stream = nullptr;
  opened.open();
  ASSERT_EQ(GARC_OK,
      garc_fs_extract(opened.archive, out.c_str(), GARC_FS_ALLOW_LINKS));
  EXPECT_EQ("same", read_file(join_path(out, "hard")));
  EXPECT_EQ("same", read_file(join_path(out, "sibling")));
  GCU_File_Identity left;
  GCU_File_Identity right;
  ASSERT_EQ(GCU_FILE_OK, gcu_file_identity(join_path(out, "hard").c_str(), &left));
  ASSERT_EQ(GCU_FILE_OK,
      gcu_file_identity(join_path(out, "sibling").c_str(), &right));
  EXPECT_EQ(left.inode, right.inode);

  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
  remove_tree(out);
}

TEST_F(ExtractRoot, AnExistingDirectoryIsNotEntered) {
  ASSERT_EQ(GCU_FILE_OK, gcu_dir_create(join_path(root, "sub").c_str()));
  Opened opened(TarArchive()
                    .header(file_header("sub/note.txt", 4, 0644))
                    .data("nope")
                    .marker()
                    .bytes());
  opened.open();
  EXPECT_EQ(GARC_ERR_REFUSED, garc_fs_extract(opened.archive, root.c_str(), 0));
  EXPECT_FALSE(gcu_file_exists(join_path(root, "sub/note.txt").c_str()));
}

TEST_F(ExtractRoot, APreexistingSymlinkIsNotFollowed) {
  ASSERT_EQ(GCU_FILE_OK, gcu_dir_create(join_path(root, "real").c_str()));
  ASSERT_EQ(GCU_FILE_OK,
      gcu_file_symlink("real", join_path(root, "sneak").c_str()));
  Opened opened(TarArchive()
                    .header(file_header("sneak/note.txt", 4, 0644))
                    .data("nope")
                    .marker()
                    .bytes());
  opened.open();
  EXPECT_EQ(GARC_ERR_REFUSED, garc_fs_extract(opened.archive, root.c_str(), 0));
  EXPECT_FALSE(gcu_file_exists(join_path(root, "real/note.txt").c_str()));
}

TEST_F(ExtractRoot, ALinkIntoAPreexistingDirectoryDoesNotReceiveChildren) {
  ASSERT_EQ(GCU_FILE_OK, gcu_dir_create(join_path(root, "planted").c_str()));
  garctest::TarHeader symlink;
  symlink.field(0, 100, "via");
  symlink.octal(100, 8, 0777);
  symlink.octal(108, 8, 0);
  symlink.octal(116, 8, 0);
  symlink.octal(124, 12, 0);
  symlink.octal(136, 12, 0);
  symlink.bytes[156] = '2';
  symlink.field(157, 100, "planted");
  symlink.ustar();
  symlink.checksum();
  Opened opened(TarArchive()
                    .header(symlink)
                    .header(file_header("via/note.txt", 4, 0644))
                    .data("nope")
                    .marker()
                    .bytes());
  opened.open();
  EXPECT_EQ(GARC_ERR_REFUSED,
      garc_fs_extract(opened.archive, root.c_str(), GARC_FS_ALLOW_LINKS));
  EXPECT_FALSE(gcu_file_exists(join_path(root, "planted/note.txt").c_str()));
}

TEST_F(ExtractRoot, HardLinkWithoutTheFlagIsRefused) {
  garctest::TarHeader link;
  link.field(0, 100, "alias");
  link.octal(100, 8, 0644);
  link.octal(108, 8, 0);
  link.octal(116, 8, 0);
  link.octal(124, 12, 0);
  link.octal(136, 12, 0);
  link.bytes[156] = '1';
  link.field(157, 100, "orig");
  link.ustar();
  link.checksum();
  Opened opened(TarArchive()
                    .header(file_header("orig", 4, 0644))
                    .data("body")
                    .header(link)
                    .marker()
                    .bytes());
  opened.open();
  EXPECT_EQ(GARC_ERR_REFUSED, garc_fs_extract(opened.archive, root.c_str(), 0));
  EXPECT_EQ("body", read_file(join_path(root, "orig")));
  EXPECT_FALSE(gcu_file_exists(join_path(root, "alias").c_str()));
}

TEST_F(ExtractRoot, HardLinkToAPreexistingFileIsRefused) {
  write_file(join_path(root, "orig"), "planted");
  garctest::TarHeader link;
  link.field(0, 100, "alias");
  link.octal(100, 8, 0644);
  link.octal(108, 8, 0);
  link.octal(116, 8, 0);
  link.octal(124, 12, 0);
  link.octal(136, 12, 0);
  link.bytes[156] = '1';
  link.field(157, 100, "orig");
  link.ustar();
  link.checksum();
  Opened opened(TarArchive().header(link).marker().bytes());
  opened.open();
  EXPECT_EQ(GARC_ERR_REFUSED,
      garc_fs_extract(opened.archive, root.c_str(), GARC_FS_ALLOW_LINKS));
  EXPECT_EQ("planted", read_file(join_path(root, "orig")));
  EXPECT_FALSE(gcu_file_exists(join_path(root, "alias").c_str()));
}

TEST_F(ExtractRoot, FifoMemberIsNotCreated) {
  Opened opened(
      TarArchive().header(file_header("pipe", 0, 0644, '6')).marker().bytes());
  opened.open();
  EXPECT_EQ(GARC_ERR_REFUSED, garc_fs_extract(opened.archive, root.c_str(), 0));
  EXPECT_FALSE(gcu_file_exists(join_path(root, "pipe").c_str()));
}

TEST_F(ExtractRoot, DotSlashTargetIsStored) {
  garctest::TarHeader symlink;
  symlink.field(0, 100, "link");
  symlink.octal(100, 8, 0777);
  symlink.octal(108, 8, 0);
  symlink.octal(116, 8, 0);
  symlink.octal(124, 12, 0);
  symlink.octal(136, 12, 0);
  symlink.bytes[156] = '2';
  symlink.field(157, 100, "./inside");
  symlink.ustar();
  symlink.checksum();
  Opened opened(TarArchive()
                    .header(file_header("inside", 4, 0644))
                    .data("body")
                    .header(symlink)
                    .marker()
                    .bytes());
  opened.open();
  ASSERT_EQ(GARC_OK,
      garc_fs_extract(opened.archive, root.c_str(), GARC_FS_ALLOW_LINKS));
  char * text = nullptr;
  size_t length = 0;
  ASSERT_EQ(GCU_FILE_OK,
      gcu_file_read_link(join_path(root, "link").c_str(), nullptr, &text,
          &length));
  EXPECT_EQ(std::string("./inside"), std::string(text, length));
  gcu_file_free(nullptr, text);
}

TEST_F(ExtractRoot, PackRefusesAFifo) {
  ASSERT_EQ(0, mkfifo(join_path(root, "pipe").c_str(), 0644));
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(GARC_OK, garc_sink_create_memory(&sink));
  GARC_Writer * writer = nullptr;
  ASSERT_EQ(GARC_OK, garc_writer_create(sink, GARC_FORMAT_TAR, nullptr, &writer));
  EXPECT_EQ(GARC_ERR_REFUSED, garc_fs_pack(writer, root.c_str(), 0));
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
}

TEST(FsApi, UnknownFlagBitsAreInvalid) {
  EXPECT_EQ(GARC_ERR_INVALID, garc_fs_extract(nullptr, "x", 0));
  EXPECT_EQ(GARC_ERR_INVALID, garc_fs_pack(nullptr, "x", 0));
  EXPECT_EQ(GARC_ERR_INVALID, garc_fs_extract(nullptr, "x", 1u << 7));
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
