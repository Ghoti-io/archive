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
#ifndef _WIN32
#include <unistd.h>
#endif

#include <gtest/gtest.h>

#include <ghoti.io/archive/fs.h>
#include <ghoti.io/cutil/dir.h>
#include <ghoti.io/cutil/file.h>
#include <ghoti.io/cutil/path.h>

#include "sevenz_builder.h"
#include "tar_builder.h"
#include "tar_manifest.h"
#include "test_helpers.h"

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
  EXPECT_EQ(0u, dir_id.mode & 07000u);
#ifndef _WIN32
  // Windows has no Unix mode to apply; fs.h says so.
  EXPECT_EQ(0755u, file_id.mode & 0777u);
  EXPECT_EQ(0755u, dir_id.mode & 0777u);
#endif
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

/** A zip of one stored member, so its data is in the archive verbatim. */
std::vector<uint8_t> stored_zip(const std::string & name, const std::string & data) {
  std::vector<uint8_t> bytes;
  GARC_Sink * sink = nullptr;
  if (garc_sink_create_memory(&sink) != GARC_OK) {
    return bytes;
  }
  GARC_Writer_Options options;
  garc_writer_options_default(&options);
  options.zip_method = GARC_ZIP_METHOD_STORED;
  GARC_Writer * writer = nullptr;
  if (garc_writer_create(sink, GARC_FORMAT_ZIP, &options, &writer) == GARC_OK) {
    GARC_Member member;
    std::memset(&member, 0, sizeof(member));
    member.name = name.data();
    member.name_length = name.size();
    member.type = GARC_MEMBER_FILE;
    member.size = data.size();
    member.mode = 0644;
    member.mode_valid = 1;
    const void * raw = nullptr;
    size_t size = 0;
    if (garc_writer_add(writer, &member) == GARC_OK
        && garc_writer_write(writer, data.data(), data.size()) == GARC_OK
        && garc_writer_finish(writer) == GARC_OK
        && garc_sink_data(sink, &raw, &size) == GARC_OK && raw) {
      bytes.assign(static_cast<const uint8_t *>(raw),
          static_cast<const uint8_t *>(raw) + size);
    }
    garc_writer_destroy(writer);
  }
  garc_sink_destroy(sink);
  return bytes;
}

TEST_F(ExtractRoot, AZipMemberWhoseCrcDoesNotMatchIsNotExtractedAsGood) {
  // Extraction used to read exactly the member's size and stop, so it never made
  // the call that returns no bytes - which is where a zip member's CRC-32 is
  // compared. A member with one byte changed was written out and reported as
  // GARC_OK.
  const std::string data = "the bytes a CRC-32 covers\n";
  std::vector<uint8_t> good = stored_zip("checked.txt", data);
  ASSERT_FALSE(good.empty());
  {
    // The control: the same archive unchanged extracts.
    Opened opened(good);
    opened.open();
    EXPECT_EQ(GARC_OK, garc_fs_extract(opened.archive, root.c_str(), 0));
    EXPECT_EQ(read_file(join_path(root, "checked.txt")), data);
    gcu_file_remove(join_path(root, "checked.txt").c_str());
  }
  const std::string haystack(good.begin(), good.end());
  const size_t at = haystack.find(data);
  ASSERT_NE(at, std::string::npos);
  ASSERT_EQ(haystack.find(data, at + 1), std::string::npos);
  good[at] ^= 0x01u;
  Opened opened(good);
  opened.open();
  EXPECT_EQ(GARC_ERR_CORRUPT, garc_fs_extract(opened.archive, root.c_str(), 0));
}

TEST_F(ExtractRoot, AZipReadOffAPipeExtractsTheSameFiles) {
  // bsdtar writes a descriptor after every member, so off a pipe each file's
  // size is unknown until its data has been read; extraction reads until the
  // reader says the member is over, not until a size it was never told.
  const std::vector<uint8_t> bytes
      = read_fixture(zip_fixture("bsdtar-descriptors.zip"));
  ASSERT_FALSE(bytes.empty());
  garctest::BufferSource source(bytes.data(), bytes.size(), false, false);
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(GARC_OK, garc_stream_create_callback(source.callbacks(), &stream));
  GARC_Archive * archive = nullptr;
  ASSERT_EQ(GARC_OK, garc_open(stream, nullptr, &archive));
  EXPECT_EQ(GARC_OK, garc_fs_extract(archive, root.c_str(), 0));
  garc_close(archive);
  garc_stream_destroy(stream);

  // The reference is the same archive extracted from memory.
  char * made = nullptr;
  ASSERT_EQ(GCU_FILE_OK, gcu_dir_temp_create(nullptr, "garc-fs-ref", nullptr, &made));
  const std::string reference = made;
  gcu_dir_free_path(nullptr, made);
  Opened opened(bytes);
  opened.open();
  EXPECT_EQ(GARC_OK, garc_fs_extract(opened.archive, reference.c_str(), 0));
  const std::set<std::string> names = list_dir(reference);
  EXPECT_FALSE(names.empty());
  EXPECT_EQ(list_dir(root), names);
  size_t files = 0;
  for (const std::string & name : names) {
    struct stat info;
    if (stat(join_path(reference, name).c_str(), &info) == 0 && S_ISREG(info.st_mode)) {
      EXPECT_EQ(read_file(join_path(root, name)), read_file(join_path(reference, name)))
          << name;
      ++files;
    }
  }
  EXPECT_GE(files, 1u);
  remove_tree(reference);
}

/** Bytes the filesystem allocated to @p path, or -1 where it cannot say. */
long long allocated_bytes(const std::string & path) {
#ifdef _WIN32
  (void)path;
  return -1;
#else
  struct stat info;
  if (stat(path.c_str(), &info) != 0) {
    return -1;
  }
  return static_cast<long long>(info.st_blocks) * 512;
#endif
}

TEST_F(ExtractRoot, ASparseMemberIsExtractedWithItsHolesLeftAsHoles) {
  // The bytes are the member's real content, holes as zeros, and a filesystem
  // that keeps holes is left one: all-hole.bin is 256 KiB of nothing and
  // should cost no blocks. The control is a file made with a hole by hand, so
  // a filesystem that keeps none (or Windows, where st_blocks does not exist)
  // is told apart from an extraction that wrote the zeros.
  const std::string probe = join_path(root, "probe-hole");
  GCU_File_Handle handle;
  std::memset(&handle, 0, sizeof(handle));
  ASSERT_EQ(GCU_FILE_OK, gcu_file_open(&handle, probe.c_str(), GCU_FILE_OPEN_WRITE,
      GCU_FILE_PERMS_PRIVATE, nullptr));
  ASSERT_EQ(GCU_FILE_OK, gcu_file_truncate(&handle, 1u << 20));
  ASSERT_EQ(GCU_FILE_OK, gcu_file_close(&handle));
  const long long probe_blocks = allocated_bytes(probe);
  const bool holes_kept = probe_blocks >= 0 && probe_blocks < (1 << 19);
  gcu_file_remove(probe.c_str());

  size_t checked = 0;
  for (const char * fixture : {"gnu-sparse.tar", "pax-sparse-0.0.tar",
           "pax-sparse-0.1.tar", "pax-sparse-1.0.tar"}) {
    SCOPED_TRACE(fixture);
    const std::vector<uint8_t> bytes = read_fixture(tar_fixture(fixture));
    ASSERT_FALSE(bytes.empty());
    char * made = nullptr;
    ASSERT_EQ(GCU_FILE_OK, gcu_dir_temp_create(nullptr, "garc-sparse", nullptr, &made));
    const std::string out = made;
    gcu_dir_free_path(nullptr, made);
    {
      Opened opened(bytes);
      opened.open();
      EXPECT_EQ(GARC_OK, garc_fs_extract(opened.archive, out.c_str(), 0));
    }
    // What the reader says each member is, which test_tar_sparse holds to the
    // references; the extracted file must be those bytes.
    Opened opened(bytes);
    opened.open();
    const GARC_Member * member = nullptr;
    while (garc_next(opened.archive, &member) == GARC_OK) {
      const std::string name(member->name, member->name_length);
      SCOPED_TRACE(name);
      ASSERT_TRUE(member->sparse);
      std::string want;
      char buffer[8192];
      size_t got = 0;
      while (garc_read_member(opened.archive, buffer, sizeof(buffer), &got) == GARC_OK
          && got) {
        want.append(buffer, got);
      }
      const std::string path = join_path(out, name);
      EXPECT_EQ(read_file(path), want);
      if (holes_kept) {
        const long long used = allocated_bytes(path);
        // Never more than the stored regions plus a block at each end of each.
        EXPECT_LE(used, static_cast<long long>(member->stored_size)
                + 2 * 4096 * 16)
            << "the holes were written as zeros";
        if (name == "all-hole.bin") {
          EXPECT_LT(used, 4096 * 2);
        }
      }
      ++checked;
    }
    remove_tree(out);
  }
  EXPECT_EQ(checked, 16u);
}

/** Pack @p dir with @p format and the default options; the archive's bytes. */
std::vector<uint8_t> pack_tree(const std::string & dir, GARC_Format format) {
  std::vector<uint8_t> bytes;
  GARC_Sink * sink = nullptr;
  EXPECT_EQ(GARC_OK, garc_sink_create_memory(&sink));
  GARC_Writer * writer = nullptr;
  EXPECT_EQ(GARC_OK, garc_writer_create(sink, format, nullptr, &writer));
  EXPECT_EQ(GARC_OK, garc_fs_pack(writer, dir.c_str(), 0));
  EXPECT_EQ(GARC_OK, garc_writer_finish(writer));
  const void * data = nullptr;
  size_t size = 0;
  if (garc_sink_data(sink, &data, &size) == GARC_OK && data) {
    bytes.assign(static_cast<const uint8_t *>(data),
        static_cast<const uint8_t *>(data) + size);
  }
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
  return bytes;
}

TEST_F(ExtractRoot, AFileWithHolesIsPackedSparseWhereTheFormatCanSayIt) {
  // 4 MiB with data at the start and the end and a hole between. Into tar it
  // goes as pax sparse 1.0 - the archive holds the data, not the hole - and
  // into zip, which has no way to say it, as its real content. Both extract to
  // the same bytes.
  const std::string path = join_path(root, "disk.img");
  GCU_File_Handle handle;
  std::memset(&handle, 0, sizeof(handle));
  ASSERT_EQ(GCU_FILE_OK, gcu_file_open(&handle, path.c_str(), GCU_FILE_OPEN_WRITE,
      GCU_FILE_PERMS_PRIVATE, nullptr));
  const std::string head(8192, 'h');
  const std::string tail(4096, 't');
  ASSERT_EQ(GCU_FILE_OK, gcu_file_write_bytes(&handle, head.data(), head.size()));
  ASSERT_EQ(GCU_FILE_OK, gcu_file_seek(&handle, (4 << 20) - 4096, GCU_FILE_SEEK_SET));
  ASSERT_EQ(GCU_FILE_OK, gcu_file_write_bytes(&handle, tail.data(), tail.size()));
  ASSERT_EQ(GCU_FILE_OK, gcu_file_close(&handle));
  std::string want = head;
  want.append((4u << 20) - 4096u - head.size(), '\0');
  want += tail;
  ASSERT_EQ(read_file(path), want);
  const bool holes = allocated_bytes(path) >= 0 && allocated_bytes(path) < (1 << 20);

  for (GARC_Format format : {GARC_FORMAT_TAR, GARC_FORMAT_ZIP}) {
    SCOPED_TRACE(format == GARC_FORMAT_TAR ? "tar" : "zip");
    const std::vector<uint8_t> bytes = pack_tree(root, format);
    ASSERT_FALSE(bytes.empty());
    Opened opened(bytes);
    opened.open();
    const GARC_Member * member = nullptr;
    ASSERT_EQ(GARC_OK, garc_next(opened.archive, &member));
    EXPECT_EQ(std::string(member->name, member->name_length), "disk.img");
    EXPECT_EQ(member->size, want.size());
    if (format == GARC_FORMAT_TAR && holes) {
      EXPECT_TRUE(member->sparse);
      EXPECT_LT(bytes.size(), 64u * 1024u) << "the hole was stored";
    }
    if (format == GARC_FORMAT_ZIP) {
      EXPECT_FALSE(member->sparse);
    }
    char * made = nullptr;
    ASSERT_EQ(GCU_FILE_OK, gcu_dir_temp_create(nullptr, "garc-holes", nullptr, &made));
    const std::string out = made;
    gcu_dir_free_path(nullptr, made);
    Opened again(bytes);
    again.open();
    EXPECT_EQ(GARC_OK, garc_fs_extract(again.archive, out.c_str(), 0));
    EXPECT_TRUE(read_file(join_path(out, "disk.img")) == want);
    remove_tree(out);
  }
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
#ifdef _WIN32
  // cutil does not create a symlink on Windows, so the member is refused there
  // with the flag set, and nothing is made in its place.
  EXPECT_EQ(GARC_ERR_REFUSED,
      garc_fs_extract(opened.archive, root.c_str(), GARC_FS_ALLOW_LINKS));
  EXPECT_FALSE(gcu_file_exists(join_path(root, "link").c_str()));
  return;
#endif
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

namespace {

/** A ustar symlink header: @p name pointing at @p target. */
garctest::TarHeader symlink_header(const std::string & name, const std::string & target) {
  garctest::TarHeader symlink;
  symlink.field(0, 100, name);
  symlink.octal(100, 8, 0777);
  symlink.octal(108, 8, 0);
  symlink.octal(116, 8, 0);
  symlink.octal(124, 12, 0);
  symlink.octal(136, 12, 0);
  symlink.bytes[156] = '2';
  symlink.field(157, 100, target);
  symlink.ustar();
  symlink.checksum();
  return symlink;
}

} // namespace

TEST_F(ExtractRoot, ALinkMayComeBeforeItsTarget) {
#ifdef _WIN32
  GTEST_SKIP() << "cutil does not create a symlink on Windows";
#endif
  // The target does not exist when the link is made, so what is left of it
  // is judged by its spelling - and stays inside.
  Opened opened(TarArchive()
                    .header(symlink_header("early", "later/file.txt"))
                    .header(file_header("later/", 0, 0755, '5'))
                    .header(file_header("later/file.txt", 4, 0644))
                    .data("body")
                    .marker()
                    .bytes());
  opened.open();
  ASSERT_EQ(GARC_OK,
      garc_fs_extract(opened.archive, root.c_str(), GARC_FS_ALLOW_LINKS));
  EXPECT_EQ("body", read_file(join_path(root, "early")));
}

TEST_F(ExtractRoot, ALinkThatClimbsButStaysInsideIsCreated) {
#ifdef _WIN32
  GTEST_SKIP() << "cutil does not create a symlink on Windows";
#endif
  // `usr/lib/libx.so -> ../../lib/libx.so`, as packages ship them: the target
  // climbs out of the link's directory and not out of the root.
  Opened opened(TarArchive()
                    .header(file_header("lib/", 0, 0755, '5'))
                    .header(file_header("lib/libx.so", 4, 0644))
                    .data("code")
                    .header(file_header("usr/", 0, 0755, '5'))
                    .header(file_header("usr/lib/", 0, 0755, '5'))
                    .header(symlink_header("usr/lib/libx.so", "../../lib/libx.so"))
                    .marker()
                    .bytes());
  opened.open();
  ASSERT_EQ(GARC_OK,
      garc_fs_extract(opened.archive, root.c_str(), GARC_FS_ALLOW_LINKS));
  EXPECT_EQ("code", read_file(join_path(root, "usr/lib/libx.so")));
}

TEST_F(ExtractRoot, ALinkThatClimbsOutOfTheRootIsRefused) {
  // One `..` more than the link is deep: through directories that exist, so
  // the resolved half refuses, and after one that does not, which climbs
  // from a name a later member could still make a link.
  for (const char * target : {"../../outside", "missing/../../../x"}) {
    SCOPED_TRACE(target);
    Opened opened(TarArchive()
                      .header(file_header("d/", 0, 0755, '5'))
                      .header(symlink_header("d/l", target))
                      .marker()
                      .bytes());
    opened.open();
    EXPECT_EQ(GARC_ERR_REFUSED,
        garc_fs_extract(opened.archive, root.c_str(), GARC_FS_ALLOW_LINKS));
    EXPECT_FALSE(tree_has_symlink(root));
    remove_tree(join_path(root, "d"));
  }
  expect_parent_unchanged();
}

TEST_F(ExtractRoot, ALinkCannotClimbThroughANameThatDoesNotExistYet) {
  // `l -> d/../x` with no `d` reads as `x`, inside. But a later member can
  // make `d` a link to the root itself, inside too, and then `l` is
  // `root/../x`: outside, made of two links each judged inside on its own. A
  // `..` after a component that is not there yet is unknowable when the link
  // is made, so it is refused.
  Opened opened(TarArchive()
                    .header(symlink_header("l", "d/../x"))
                    .header(symlink_header("d", "."))
                    .marker()
                    .bytes());
  opened.open();
  EXPECT_EQ(GARC_ERR_REFUSED,
      garc_fs_extract(opened.archive, root.c_str(), GARC_FS_ALLOW_LINKS));
  EXPECT_FALSE(gcu_file_exists(join_path(root, "l").c_str()));
  EXPECT_FALSE(tree_has_symlink(root));
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
#ifdef _WIN32
  // On Windows the flag does not allow it: "CON" there is the console, and
  // opening it would write the member to the screen and report success.
  EXPECT_FALSE(gcu_file_exists(join_path(root, "CON").c_str()));
#else
  EXPECT_TRUE(gcu_file_exists(join_path(root, "CON").c_str()));
#endif
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

TEST_F(ExtractRoot, GnuTarsDotLayoutExtracts) {
  // `tar -C dir -cf x.tar .` names the root "./" and everything under it
  // "./name". The commonest tar there is, and its first member is the root.
  Opened opened(TarArchive()
          .header(file_header("./", 0, 0755, '5'))
          .header(file_header("./a.txt", 3, 0644))
          .data("one")
          .header(file_header("./d/", 0, 0755, '5'))
          .header(file_header("./d/b.txt", 3, 0644))
          .data("two")
          .marker()
          .bytes());
  opened.open();
  EXPECT_EQ(GARC_OK, garc_fs_extract(opened.archive, root.c_str(), 0));
  EXPECT_EQ("one", read_file(join_path(root, "a.txt")));
  EXPECT_EQ("two", read_file(join_path(root, "d/b.txt")));
  expect_parent_unchanged();
}

TEST_F(ExtractRoot, ADirectoryMemberAfterItsChildrenIsGivenItsMode) {
  // A zip lists files before (or without) their directories as often as not,
  // so the directory a child made has its own member later.
  Opened opened(TarArchive()
          .header(file_header("late/child.txt", 3, 0644))
          .data("kid")
          .header(file_header("late/", 0, 0700, '5'))
          .marker()
          .bytes());
  opened.open();
  EXPECT_EQ(GARC_OK, garc_fs_extract(opened.archive, root.c_str(), 0));
  EXPECT_EQ("kid", read_file(join_path(root, "late/child.txt")));
#ifndef _WIN32
  GCU_File_Identity identity;
  ASSERT_EQ(GCU_FILE_OK,
      gcu_file_identity(join_path(root, "late").c_str(), &identity));
  EXPECT_EQ(0700u, identity.mode & 0777u);
#endif
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
#ifdef _WIN32
  GTEST_SKIP() << "the setup sets Unix modes, which Windows has none of";
#endif
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

//-----------------------------------------------------------------------------
// 7z goes through the same layer
//-----------------------------------------------------------------------------

TEST_F(ExtractRoot, ASevenZipArchiveExtractsWithItsBytesAndMasksItsModes) {
  Opened opened(read_fixture(std::string(GARC_TEST_DATA) + "/sevenz/basic.7z"));
  opened.open();
  ASSERT_EQ(GARC_OK, garc_fs_extract(opened.archive, root.c_str(), 0));
  EXPECT_EQ("hello, archive\n", read_file(join_path(root, "hello.txt")));
  EXPECT_EQ("nested\n", read_file(join_path(root, "sub/deep/nested.txt")));
  EXPECT_EQ(std::string(11600, '\0').size(),
      read_file(join_path(root, "compressible.txt")).size());
  EXPECT_TRUE(list_dir(join_path(root, "emptydir")).empty());
  GCU_File_Identity id;
  ASSERT_EQ(GCU_FILE_OK,
      gcu_file_identity(join_path(root, "program.bin").c_str(), &id));
#ifndef _WIN32
  EXPECT_EQ(0755u, id.mode & 0777u);
#endif
  expect_parent_unchanged();
}

TEST_F(ExtractRoot, ASevenZipArchiveWithEscapingNamesWritesNothing) {
  garctest::SzBuilder builder;
  builder.add("ok.txt", "fine");
  builder.add("../escaped", "x");
  builder.add("/tmp/ghoti-escaped-fs", "x");
  const std::string built = builder.build();
  Opened opened(std::vector<uint8_t>(built.begin(), built.end()));
  opened.open();
  EXPECT_EQ(GARC_ERR_REFUSED, garc_fs_extract(opened.archive, root.c_str(), 0));
  EXPECT_FALSE(gcu_file_exists("/tmp/ghoti-escaped-fs"));
  expect_parent_unchanged();
}

TEST_F(ExtractRoot, PackedAsSevenZipAndExtractedAgainMatches) {
  ASSERT_EQ(GCU_FILE_OK, gcu_dir_create(join_path(root, "sub").c_str()));
  write_file(join_path(root, "sub/note.txt"), "hello");
  write_file(join_path(root, "top.txt"), std::string(50000, 'z'));

  GARC_Sink * sink = nullptr;
  ASSERT_EQ(GARC_OK, garc_sink_create_memory(&sink));
  GARC_Writer * writer = nullptr;
  ASSERT_EQ(GARC_OK,
      garc_writer_create(sink, GARC_FORMAT_SEVENZ, nullptr, &writer));
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
  EXPECT_EQ(std::string(50000, 'z'), read_file(join_path(out, "top.txt")));

  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
  remove_tree(out);
}

TEST_F(ExtractRoot, PackStoresASymlinkAndNotTheOutsideBytes) {
#ifdef _WIN32
  GTEST_SKIP() << "the setup makes a symlink, which cutil does not create on Windows";
#endif
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
#ifdef _WIN32
  GTEST_SKIP() << "the setup makes a symlink, which cutil does not create on Windows";
#endif
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

TEST_F(ExtractRoot, APreexistingSymlinkOutOfTheRootIsNotFollowed) {
#ifdef _WIN32
  GTEST_SKIP() << "the setup makes a symlink, which cutil does not create on Windows";
#endif
  // The link was there before the extract, and it leads out: the parent's
  // canonical path is outside the root, which is refused before the link's
  // own provenance is asked about.
  char * made = nullptr;
  ASSERT_EQ(GCU_FILE_OK, gcu_dir_temp_create(nullptr, "garc-out", nullptr, &made));
  const std::string outside = made;
  gcu_dir_free_path(nullptr, made);
  ASSERT_EQ(GCU_FILE_OK,
      gcu_file_symlink(outside.c_str(), join_path(root, "out").c_str()));
  Opened opened(TarArchive()
                    .header(file_header("out/note.txt", 4, 0644))
                    .data("nope")
                    .marker()
                    .bytes());
  opened.open();
  EXPECT_EQ(GARC_ERR_REFUSED, garc_fs_extract(opened.archive, root.c_str(), 0));
  EXPECT_TRUE(list_dir(outside).empty());
  remove_tree(outside);
}

TEST_F(ExtractRoot, AFileIsNotAParentDirectory) {
  // A member under a name an earlier member wrote as a file: the walk finds a
  // file where a directory has to be, and refuses rather than replacing it.
  Opened opened(TarArchive()
                    .header(file_header("plain", 3, 0644))
                    .data("one")
                    .header(file_header("plain/child.txt", 3, 0644))
                    .data("two")
                    .marker()
                    .bytes());
  opened.open();
  EXPECT_EQ(GARC_ERR_REFUSED, garc_fs_extract(opened.archive, root.c_str(), 0));
  EXPECT_EQ("one", read_file(join_path(root, "plain")));
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
#ifdef _WIN32
  GTEST_SKIP() << "extracting a symlink is refused on Windows, which ContainedSymlinkIsCreatedWhenLinksAreAllowed asserts";
#endif
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
#ifdef _WIN32
  GTEST_SKIP() << "Windows has no fifo in the filesystem to pack";
#else
  ASSERT_EQ(0, mkfifo(join_path(root, "pipe").c_str(), 0644));
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(GARC_OK, garc_sink_create_memory(&sink));
  GARC_Writer * writer = nullptr;
  ASSERT_EQ(GARC_OK, garc_writer_create(sink, GARC_FORMAT_TAR, nullptr, &writer));
  EXPECT_EQ(GARC_ERR_REFUSED, garc_fs_pack(writer, root.c_str(), 0));
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
#endif
}

namespace {

/** Pack @p dir into a tar in memory; the status. */
GARC_Result pack_status(const std::string & dir) {
  GARC_Sink * sink = nullptr;
  EXPECT_EQ(GARC_OK, garc_sink_create_memory(&sink));
  GARC_Writer * writer = nullptr;
  EXPECT_EQ(GARC_OK, garc_writer_create(sink, GARC_FORMAT_TAR, nullptr, &writer));
  const GARC_Result result = garc_fs_pack(writer, dir.c_str(), 0);
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
  return result;
}

} // namespace

TEST_F(ExtractRoot, PackStopsAtSixtyFourDirectoriesDeep) {
  // Each level holds a directory handle open while the next is read, so the
  // depth is capped, and a tree past it is refused rather than half packed.
  std::string at = root;
  for (int level = 0; level < 64; ++level) {
    at = join_path(at, "d");
    ASSERT_EQ(GCU_FILE_OK, gcu_dir_create(at.c_str()));
  }
  EXPECT_EQ(GARC_OK, pack_status(root));
  at = join_path(at, "d");
  ASSERT_EQ(GCU_FILE_OK, gcu_dir_create(at.c_str()));
  EXPECT_EQ(GARC_ERR_REFUSED, pack_status(root));
}

TEST_F(ExtractRoot, PackReportsADirectoryItCannotRead) {
#ifdef _WIN32
  GTEST_SKIP() << "a Unix mode does not take read access away on Windows";
#else
  if (geteuid() == 0) {
    GTEST_SKIP() << "root reads a directory whatever its mode";
  }
  const std::string closed = join_path(root, "closed");
  ASSERT_EQ(GCU_FILE_OK, gcu_dir_create(closed.c_str()));
  write_file(join_path(closed, "inside.txt"), "x");
  ASSERT_EQ(0, chmod(closed.c_str(), 0));
  EXPECT_EQ(GARC_ERR_ACCESS, pack_status(root));
  ASSERT_EQ(0, chmod(closed.c_str(), 0755));
#endif
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
