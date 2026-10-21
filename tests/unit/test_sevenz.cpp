/**
 * @file
 *
 * Reading 7z, against what the source tree says the fixtures contain.
 *
 * The fixtures are written by 7-Zip 25.01 in the pinned container, and the
 * expectation is not another program's reading of them: `manifest.tsv` is
 * computed from the files that were archived. A passing row is the library
 * agreeing with what went in.
 *
 * Archives that no tool writes - a file count the header cannot hold, substream
 * sizes that do not add up, a CRC that is wrong - are built byte by byte with
 * `sevenz_builder.h`, each from a control that is read without complaint.
 *
 * **A missing corpus fails these tests rather than skipping them.**
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "failing_allocator.h"
#include "sevenz/sevenz_internal.h"
#include "sevenz_builder.h"
#include "sevenz_coders.h"
#include "tar_manifest.h"
#include "test_helpers.h"
#include "portable.h"

using garctest::BufferSource;
using garctest::SzBuilder;
using garctest::read_fixture;

namespace {

std::string data_path(const std::string & name) {
  return std::string(GARC_TEST_DATA) + "/sevenz/" + name;
}

/** An open archive over bytes, with the stream kept alive beside it. */
class Opened {
public:
  Opened(const std::vector<uint8_t> & bytes, const GARC_Limits * limits = nullptr,
      bool can_seek = true)
      : bytes_(bytes), source_(bytes_.data(), bytes_.size(), can_seek, true) {
    if (garc_stream_create_callback(source_.callbacks(), &stream_) != GARC_OK) {
      stream_ = nullptr;
      return;
    }
    open_result_ = garc_open(stream_, limits, &archive_);
  }

  explicit Opened(const std::string & bytes, const GARC_Limits * limits = nullptr,
      bool can_seek = true)
      : Opened(std::vector<uint8_t>(bytes.begin(), bytes.end()), limits,
            can_seek) {}

  ~Opened() {
    garc_close(archive_);
    garc_stream_destroy(stream_);
  }

  Opened(const Opened &) = delete;
  Opened & operator=(const Opened &) = delete;

  GARC_Result open_result() const { return open_result_; }
  GARC_Archive * archive() const { return archive_; }

private:
  std::vector<uint8_t> bytes_;
  BufferSource source_;
  GARC_Stream * stream_ = nullptr;
  GARC_Archive * archive_ = nullptr;
  GARC_Result open_result_ = GARC_ERR_INTERNAL;
};

std::vector<uint8_t> fixture(const std::string & name) {
  std::vector<uint8_t> bytes = read_fixture(data_path(name));
  EXPECT_FALSE(bytes.empty()) << "missing corpus file " << name;
  return bytes;
}

/** The password of the hand-built AES archives. */
const std::string kBuiltPassword = "built-\xF0\x9F\x98\x80";

/** x86-ish bytes: plenty of E8, E9 and 0F 8x, with small displacements. */
std::string x86ish(uint32_t seed, size_t size) {
  std::string out;
  uint32_t x = seed;
  auto next = [&x]() {
    x = x * 1103515245u + 12345u;
    return x >> 16;
  };
  while (out.size() < size) {
    const uint32_t r = next() % 100u;
    if (r < 6u) {
      out.push_back(static_cast<char>(r < 3u ? 0xE8 : 0xE9));
      const uint32_t rel = next() % 0x3000u;
      for (unsigned k = 0; k < 4u; ++k) {
        out.push_back(static_cast<char>((rel >> (8u * k)) & 0xFFu));
      }
    }
    else if (r < 8u) {
      out.push_back(0x0F);
      out.push_back(static_cast<char>(0x80 + next() % 16u));
    }
    else {
      out.push_back(static_cast<char>(next() & 0xFFu));
    }
  }
  out.resize(size);
  return out;
}

/** An AES-then-copy folder over @p plain, cycle power 0, a salt and a short IV. */
std::string built_aes(const std::string & plain, const std::string & password) {
  using namespace garctest;
  const std::string salt("\x11\x22", 2);
  const std::string iv("\x01\x02\x03", 3);
  std::string iv16 = iv;
  iv16.resize(16, '\0');
  const std::string sealed
      = sz_aes_encrypt(sz_aes_key(password, 0, salt), iv16, plain);
  SzFolder f;
  f.coders.push_back({sz_aes_id(), 1, sz_aes_props(0, salt, iv)});
  f.coders.push_back({std::string(1, '\0'), 1, ""});
  f.binds = {{1, 0}};
  f.packed = {0};
  f.unpack = {plain.size(), plain.size()};
  return sz_folder_archive({sealed}, f, "secret.txt", plain);
}

/**
 * BCJ2 with an AES coder in front of each of its four streams, which is the
 * shape 7-Zip writes for `-mf=BCJ2` with a password; the header encrypted too
 * when @p header is set.
 */
std::string built_aes_bcj2(const std::string & plain, bool header) {
  using namespace garctest;
  const Bcj2Streams b = bcj2_encode(plain, bcj2_seven_zip_rule);
  const std::string key = sz_aes_key(kBuiltPassword, 0, "");
  SzFolder f;
  std::vector<std::string> packs;
  const std::string * streams[4] = {&b.main, &b.call, &b.jump, &b.rc};
  for (unsigned i = 0; i < 4u; ++i) {
    const std::string iv(4, static_cast<char>('a' + i));
    std::string iv16 = iv;
    iv16.resize(16, '\0');
    packs.push_back(sz_aes_encrypt(key, iv16, *streams[i]));
    f.coders.push_back({sz_aes_id(), 1, sz_aes_props(0, "", iv)});
    f.unpack.push_back(streams[i]->size());
  }
  f.coders.push_back({sz_bcj2_id(), 4, ""});
  f.binds = {{4, 0}, {5, 1}, {6, 2}, {7, 3}};
  f.packed = {0, 1, 2, 3};
  f.unpack.push_back(plain.size());
  return header ? sz_folder_archive(packs, f, "prog.bin", plain, key,
                      std::string("\x5A", 1))
                : sz_folder_archive(packs, f, "prog.bin", plain);
}

/** A fixture by name, or one of the hand-built archives the sweeps run over. */
std::vector<uint8_t> sweep_input(const std::string & name) {
  std::string built;
  if (name == "built:aes") {
    built = built_aes(std::string(3000, 'q') + "tail", kBuiltPassword);
  }
  else if (name == "built:aes-header") {
    built = built_aes_bcj2(x86ish(5, 4000), true);
  }
  else if (name == "built:aes-bcj2") {
    built = built_aes_bcj2(x86ish(6, 6000), false);
  }
  else {
    return read_fixture(data_path(name));
  }
  return std::vector<uint8_t>(built.begin(), built.end());
}

/** Read a member to its end, keeping the status of the call that ends it. */
std::string read_member(GARC_Archive * archive, GARC_Result * status) {
  std::string out;
  char buffer[777];
  size_t got = 0;
  for (;;) {
    *status = garc_read_member(archive, buffer, sizeof(buffer), &got);
    if (*status != GARC_OK || !got) {
      break;
    }
    out.append(buffer, got);
  }
  return out;
}

struct Seen {
  GARC_Member_Type type = GARC_MEMBER_FILE;
  uint64_t size = 0;
  uint32_t mode = 0;
  int64_t mtime = 0;
  std::string data;
  std::string link;
  GARC_Result status = GARC_OK;
};

/** Walk and read everything. Returns the status that ended the walk. */
GARC_Result walk(GARC_Archive * archive, std::map<std::string, Seen> * out,
    std::vector<std::string> * order = nullptr) {
  const GARC_Member * member = nullptr;
  GARC_Result result = GARC_OK;
  while ((result = garc_next(archive, &member)) == GARC_OK) {
    const std::string name(member->name, member->name_length);
    Seen seen;
    seen.type = member->type;
    seen.size = member->size;
    seen.mode = member->mode;
    seen.mtime = member->mtime_seconds;
    if (member->link_target) {
      seen.link.assign(member->link_target, member->link_target_length);
    }
    seen.data = read_member(archive, &seen.status);
    (*out)[name] = seen;
    if (order) {
      order->push_back(name);
    }
  }
  return result;
}

struct Row {
  std::string name, type;
  uint64_t size = 0;
  uint32_t crc = 0;
  uint32_t mode = 0;
  int64_t mtime = 0;
};

std::vector<Row> manifest() {
  const std::vector<uint8_t> bytes = fixture("manifest.tsv");
  std::istringstream in(std::string(bytes.begin(), bytes.end()));
  std::vector<Row> rows;
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty() || line[0] == '#') {
      continue;
    }
    std::vector<std::string> f;
    std::stringstream ls(line);
    std::string cell;
    while (std::getline(ls, cell, '\t')) {
      f.push_back(cell);
    }
    Row row;
    row.name = f[0];
    row.type = f[1];
    row.size = std::stoull(f[2]);
    row.crc = static_cast<uint32_t>(std::stoul(f[3], nullptr, 16));
    row.mode = static_cast<uint32_t>(std::stoul(f[4], nullptr, 8));
    row.mtime = std::stoll(f[5]);
    rows.push_back(row);
  }
  return rows;
}

const char * const kReadable[] = {"basic.7z", "copy.7z", "lzma.7z", "bzip2.7z",
    "deflate.7z", "deflate64.7z", "nonsolid.7z", "plainhdr.7z", "delta.7z", "bcj.7z",
    "arm64.7z", "bcj2.7z", "bcj2-copy.7z", "bcj2-mf.7z"};

/** The password of every AES fixture, as UTF-8: make_sevenz_corpus.py's PASSWORD. */
const std::string kPassword = "ghoti-p\xC3\xA4ss-\xF0\x9F\x98\x80";

/** The AES fixtures that hold the whole tree. */
const char * const kEncrypted[] = {"aes.7z", "aes-header.7z", "aes-nonsolid.7z",
    "aes-copy.7z", "aes-bcj2.7z"};

} // namespace

TEST(SevenZ, EveryReadableArchiveHoldsExactlyWhatWasArchived) {
  const std::vector<Row> rows = manifest();
  ASSERT_EQ(rows.size(), 12u) << "manifest.tsv is not the corpus";
  for (const char * name : kReadable) {
    SCOPED_TRACE(name);
    Opened opened(fixture(name));
    ASSERT_EQ(opened.open_result(), GARC_OK);
    EXPECT_EQ(garc_format(opened.archive()), GARC_FORMAT_SEVENZ);
    std::map<std::string, Seen> seen;
    ASSERT_EQ(walk(opened.archive(), &seen), GARC_END);
    ASSERT_EQ(seen.size(), rows.size());
    for (const Row & row : rows) {
      SCOPED_TRACE(row.name);
      ASSERT_EQ(seen.count(row.name), 1u);
      const Seen & got = seen[row.name];
      EXPECT_EQ(got.type, row.type == "directory" ? GARC_MEMBER_DIRECTORY
                                                   : GARC_MEMBER_FILE);
      EXPECT_EQ(got.size, row.size);
      EXPECT_EQ(got.data.size(), row.size);
      EXPECT_EQ(got.status, GARC_OK);
      EXPECT_EQ(got.mode & 07777u, row.mode);
      EXPECT_EQ(got.mtime, row.mtime);
      if (row.type == "file") {
        EXPECT_EQ(garctest::sz_crc(got.data), row.crc);
      }
    }
  }
}

TEST(SevenZ, EveryBranchFilterTheReaderMapsDecodesARealArchive) {
  // program.bin alone, through each filter 7-Zip 25.01 offers beyond x86 and
  // ARM64. A wrong mapping from id to architecture decodes to wrong bytes, and
  // the CRC says so.
  const uint32_t program_crc = [] {
    for (const Row & row : manifest()) {
      if (row.name == "program.bin") {
        return row.crc;
      }
    }
    return 0u;
  }();
  ASSERT_NE(program_crc, 0u);
  for (const char * name : {"ppc.7z", "ia64.7z", "arm.7z", "armt.7z",
           "sparc.7z", "riscv.7z"}) {
    SCOPED_TRACE(name);
    Opened opened(fixture(name));
    ASSERT_EQ(opened.open_result(), GARC_OK);
    std::map<std::string, Seen> seen;
    ASSERT_EQ(walk(opened.archive(), &seen), GARC_END);
    ASSERT_EQ(seen.size(), 1u);
    EXPECT_EQ(seen["program.bin"].status, GARC_OK);
    EXPECT_EQ(garctest::sz_crc(seen["program.bin"].data), program_crc);
  }
}

TEST(SevenZ, TheDumpNamesTheFoldersAndEntries) {
  Opened opened(fixture("nonsolid.7z"));
  ASSERT_EQ(opened.open_result(), GARC_OK);
  garctest::MemStream out_capture;
  FILE * out = out_capture.file();
  ASSERT_NE(out, nullptr);
  garc_archive_dump(opened.archive(), out);
  out_capture.close();
  const std::string dump = out_capture.text();
  EXPECT_NE(dump.find("format=7z"), std::string::npos);
  EXPECT_NE(dump.find("7z: "), std::string::npos);
  EXPECT_NE(dump.find("folders"), std::string::npos);
}

TEST(SevenZ, TheFormatHasAName) {
  EXPECT_STREQ(garc_format_string(GARC_FORMAT_SEVENZ), "7z");
  EXPECT_STREQ(garc_time_source_string(GARC_TIME_FILETIME), "7z-filetime");
}

TEST(SevenZ, ASymlinkIsASymlinkWithItsTarget) {
  Opened opened(fixture("symlink.7z"));
  ASSERT_EQ(opened.open_result(), GARC_OK);
  std::map<std::string, Seen> seen;
  ASSERT_EQ(walk(opened.archive(), &seen), GARC_END);
  ASSERT_EQ(seen.size(), 2u);
  EXPECT_EQ(seen["hello.txt"].type, GARC_MEMBER_FILE);
  EXPECT_EQ(seen["link-to-hello"].type, GARC_MEMBER_SYMLINK);
  EXPECT_EQ(seen["link-to-hello"].link, "hello.txt");
  EXPECT_EQ(seen["link-to-hello"].mode & 0170000u, 0120000u);
}

TEST(SevenZ, ASolidArchiveSkipsToALaterMemberWithoutReadingTheEarlierOnes) {
  Opened opened(fixture("basic.7z"));
  ASSERT_EQ(opened.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  std::string wanted;
  while (garc_next(opened.archive(), &member) == GARC_OK) {
    const std::string name(member->name, member->name_length);
    if (name == "sub/deep/nested.txt") {
      GARC_Result status = GARC_OK;
      wanted = read_member(opened.archive(), &status);
      EXPECT_EQ(status, GARC_OK);
      break;
    }
    ASSERT_EQ(garc_skip_member(opened.archive()), GARC_OK);
  }
  EXPECT_EQ(wanted, "nested\n");
}

TEST(SevenZ, FindRewindsAndFindsAgain) {
  Opened opened(fixture("nonsolid.7z"));
  ASSERT_EQ(opened.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  for (int pass = 0; pass < 2; ++pass) {
    ASSERT_EQ(garc_find(opened.archive(), "sub/one", 7, &member), GARC_OK);
    GARC_Result status = GARC_OK;
    EXPECT_EQ(read_member(opened.archive(), &status), "x");
    EXPECT_EQ(status, GARC_OK);
  }
  EXPECT_EQ(garc_find(opened.archive(), "nope", 4, &member), GARC_END);
}

TEST(SevenZ, ANonSeekableStreamIsNamedAsSuch) {
  Opened opened(fixture("basic.7z"), nullptr, false);
  EXPECT_EQ(opened.open_result(), GARC_ERR_NOT_SEEKABLE);
}

/** @p archive behind @p stub, the way a self-extractor is laid out. */
std::vector<uint8_t> behind(const std::string & stub, const std::vector<uint8_t> & archive) {
  std::vector<uint8_t> out(stub.begin(), stub.end());
  out.insert(out.end(), archive.begin(), archive.end());
  return out;
}

/** A stub of @p length bytes that starts like @p magic and holds no signature. */
std::string stub_of(const std::string & magic, size_t length) {
  std::string stub = magic;
  for (size_t i = stub.size(); i < length; ++i) {
    stub.push_back(static_cast<char>((i * 131u + 7u) % 251u));
  }
  return stub;
}

TEST(SevenZ, AnArchiveBehindAnExecutableStubIsFoundAndReadTheSame) {
  // 7-Zip's self-extractors are an executable with the archive appended: a PE
  // on Windows, an ELF on Linux (the pinned image's 7zCon.sfx), Mach-O on a Mac.
  const std::vector<uint8_t> plain = fixture("nonsolid.7z");
  std::map<std::string, Seen> want;
  {
    Opened opened(plain);
    ASSERT_EQ(opened.open_result(), GARC_OK);
    ASSERT_EQ(walk(opened.archive(), &want), GARC_END);
    EXPECT_EQ(garc_base_offset(opened.archive()), 0u);
  }
  ASSERT_FALSE(want.empty());
  const std::string magics[] = {std::string("MZ"), std::string("\x7f" "ELF", 4),
      std::string("\xcf\xfa\xed\xfe", 4)};
  for (const std::string & magic : magics) {
    for (size_t length : {4u, 70000u, 518752u}) {
      SCOPED_TRACE(length);
      const std::vector<uint8_t> bytes = behind(stub_of(magic, length), plain);
      Opened opened(bytes);
      ASSERT_EQ(opened.open_result(), GARC_OK);
      EXPECT_EQ(garc_format(opened.archive()), GARC_FORMAT_SEVENZ);
      EXPECT_EQ(garc_base_offset(opened.archive()), length);
      std::map<std::string, Seen> got;
      EXPECT_EQ(walk(opened.archive(), &got), GARC_END);
      ASSERT_EQ(got.size(), want.size());
      for (const auto & [name, seen] : want) {
        EXPECT_EQ(got[name].data, seen.data) << name;
        EXPECT_EQ(got[name].status, seen.status) << name;
      }
      // And a find, which rewinds, rewinds to the archive and not the stub.
      const GARC_Member * member = nullptr;
      EXPECT_EQ(garc_find(opened.archive(), "sub/one", 7, &member), GARC_OK);
    }
  }
}

TEST(SevenZ, ASignatureWhoseStartHeaderDoesNotCheckIsPassedOver) {
  // A stub can contain the six signature bytes - the self-extractor's own
  // code looks for them - and only a start header whose CRC matches and whose
  // next header lies in the file is the archive.
  const std::vector<uint8_t> plain = fixture("nonsolid.7z");
  std::string stub = stub_of("MZ", 4096);
  std::string decoy(plain.begin(), plain.begin() + 32);
  decoy[9] = static_cast<char>(decoy[9] ^ 0x01); // the start header's CRC
  stub += decoy;
  stub += stub_of("x", 1000);
  const std::vector<uint8_t> bytes = behind(stub, plain);
  Opened opened(bytes);
  ASSERT_EQ(opened.open_result(), GARC_OK);
  EXPECT_EQ(garc_base_offset(opened.archive()), stub.size());
}

TEST(SevenZ, OnlyAnExecutableIsScannedAndOnlyItsFirstEightMiB) {
  const std::vector<uint8_t> plain = fixture("basic.7z");
  {
    // Not an executable: a text file that happens to have a 7z in it is not one.
    Opened opened(behind(stub_of("hello", 5000), plain));
    EXPECT_EQ(opened.open_result(), GARC_ERR_FORMAT);
  }
  {
    // Past the bound.
    Opened opened(behind(stub_of("MZ", (8u << 20) + 16u), plain));
    EXPECT_EQ(opened.open_result(), GARC_ERR_FORMAT);
  }
  {
    // Just inside it.
    Opened opened(behind(stub_of("MZ", (8u << 20) - 64u), plain));
    EXPECT_EQ(opened.open_result(), GARC_OK);
  }
  {
    // A stream that cannot seek is not scanned: the header is at the end anyway.
    Opened opened(behind(stub_of("MZ", 100), plain), nullptr, false);
    EXPECT_EQ(opened.open_result(), GARC_ERR_FORMAT);
  }
}

TEST(SevenZ, NamesAreUtf8) {
  Opened opened(fixture("basic.7z"));
  ASSERT_EQ(opened.open_result(), GARC_OK);
  std::map<std::string, Seen> seen;
  ASSERT_EQ(walk(opened.archive(), &seen), GARC_END);
  EXPECT_EQ(seen.count("unicode/\xC3\xA9\xC3\xA8\xF0\x9F\x98\x80.txt"), 1u);
}

namespace {

/**
 * Walk a 7z seekably, reading every member through, with the read after
 * @p fail_after failing (none when SIZE_MAX) and at most @p cap bytes a read.
 * Returns the first failure anywhere, or GARC_OK; what was read in @p seen.
 */
GARC_Result sweep_walk(const std::vector<uint8_t> & bytes, size_t cap,
    size_t fail_after, size_t * reads, std::string * seen,
    const std::string * password = nullptr) {
  BufferSource source(bytes.data(), bytes.size(), true, true);
  source.cap_reads(cap);
  if (fail_after != SIZE_MAX) {
    source.fail_reads_after(fail_after, 1u);
  }
  GARC_Stream * stream = nullptr;
  if (garc_stream_create_callback(source.callbacks(), &stream) != GARC_OK) {
    return GARC_ERR_OOM;
  }
  GARC_Archive * archive = nullptr;
  GARC_Result result = garc_open(stream, nullptr, &archive);
  if (result == GARC_OK && password) {
    result = garc_set_password(archive, password->data(), password->size());
  }
  const GARC_Member * member = nullptr;
  while (result == GARC_OK && (result = garc_next(archive, &member)) == GARC_OK) {
    seen->append(member->name, member->name_length);
    seen->push_back('\0');
    char buffer[4096];
    size_t got = 0;
    while ((result = garc_read_member(archive, buffer, sizeof(buffer), &got))
            == GARC_OK
        && got) {
      seen->append(buffer, got);
    }
    seen->push_back('\0');
  }
  garc_close(archive);
  garc_stream_destroy(stream);
  *reads = source.reads();
  return result == GARC_END ? GARC_OK : result;
}

} // namespace

TEST(SevenZ, EveryReadFailureOfAWalkIsReportedAsTheFailure) {
  // The signature, the start header, the header, an encoded header's packed
  // stream, every folder's packed streams through every coder: each read a
  // clean walk makes, failed in turn, ends the walk with the stream's own
  // status - never with a verdict on bytes that were not read, and never with
  // a walk that went on as if they had been.
  //
  // The encrypted ones are walked with the password, and among them is an
  // encrypted header (decoded inside garc_set_password()) and BCJ2 behind four
  // AES coders, whose four packed streams are read interleaved through
  // positioned slices of one archive stream.
  size_t points = 0;
  for (const char * name : {"basic.7z", "copy.7z", "nonsolid.7z", "plainhdr.7z",
           "bzip2.7z", "deflate.7z", "delta.7z", "bcj.7z", "symlink.7z",
           "bcj2.7z", "bcj2-copy.7z", "built:aes", "built:aes-header",
           "built:aes-bcj2"}) {
    const std::vector<uint8_t> bytes = sweep_input(name);
    ASSERT_FALSE(bytes.empty()) << name;
    const bool encrypted = std::string(name).rfind("built:aes", 0) == 0;
    const std::string * password = encrypted ? &kBuiltPassword : nullptr;
    for (const size_t cap : {size_t(0), size_t(512)}) {
      SCOPED_TRACE(std::string(name) + " in reads of " + std::to_string(cap));
      size_t reads = 0;
      std::string want;
      ASSERT_EQ(GARC_OK,
          sweep_walk(bytes, cap, SIZE_MAX, &reads, &want, password));
      for (size_t k = 0; k < reads; ++k) {
        size_t unused = 0;
        std::string got;
        EXPECT_EQ(GARC_ERR_IO,
            sweep_walk(bytes, cap, k, &unused, &got, password))
            << "failing read " << k << " of " << reads;
        ++points;
      }
    }
  }
  // 530 before BCJ2 and AES were added.
  EXPECT_GT(points, 600u) << points;
}

TEST(SevenZ, EveryTruncationOfAnArchiveIsRefusedAtOpen) {
  const std::vector<uint8_t> whole = fixture("plainhdr.7z");
  for (size_t length : {size_t(0), size_t(1), size_t(6), size_t(31), size_t(32),
           size_t(33), whole.size() / 2, whole.size() - 1}) {
    SCOPED_TRACE(length);
    Opened opened(std::vector<uint8_t>(whole.begin(), whole.begin() + length));
    EXPECT_NE(opened.open_result(), GARC_OK);
  }
}

TEST(SevenZ, AFlippedByteNeverCrashesAndIsUsuallyRefused) {
  // The whole of a small archive, one byte at a time. Each outcome is a status
  // from the library's vocabulary; under ASan a read or write out of bounds is
  // the failure this is looking for. The start header and the header are
  // covered by CRCs, so almost every flip is refused at open.
  const std::vector<uint8_t> whole = fixture("symlink.7z");
  size_t refused = 0;
  for (size_t i = 0; i < whole.size(); ++i) {
    std::vector<uint8_t> mutated = whole;
    mutated[i] ^= 0x55;
    Opened opened(mutated);
    if (opened.open_result() != GARC_OK) {
      ++refused;
      continue;
    }
    std::map<std::string, Seen> seen;
    walk(opened.archive(), &seen);
  }
  EXPECT_GT(refused, whole.size() * 3 / 4);
}

//-----------------------------------------------------------------------------
// Limits
//-----------------------------------------------------------------------------

TEST(SevenZ, EachLimitFiresWithItsOwnStatus) {
  GARC_Limits limits;
  garc_limits_default(&limits);
  limits.max_members = 3;
  {
    Opened opened(fixture("basic.7z"), &limits);
    ASSERT_EQ(opened.open_result(), GARC_OK);
    std::map<std::string, Seen> seen;
    EXPECT_EQ(walk(opened.archive(), &seen), GARC_ERR_LIMIT_MEMBERS);
  }
  garc_limits_default(&limits);
  limits.max_member_bytes = 100;
  {
    Opened opened(fixture("basic.7z"), &limits);
    ASSERT_EQ(opened.open_result(), GARC_OK);
    std::map<std::string, Seen> seen;
    EXPECT_EQ(walk(opened.archive(), &seen), GARC_ERR_LIMIT_MEMBER_BYTES);
  }
  garc_limits_default(&limits);
  limits.max_total_bytes = 1000;
  {
    Opened opened(fixture("basic.7z"), &limits);
    ASSERT_EQ(opened.open_result(), GARC_OK);
    std::map<std::string, Seen> seen;
    EXPECT_EQ(walk(opened.archive(), &seen), GARC_ERR_LIMIT_TOTAL_BYTES);
  }
  garc_limits_default(&limits);
  limits.max_name_bytes = 4;
  {
    Opened opened(fixture("basic.7z"), &limits);
    ASSERT_EQ(opened.open_result(), GARC_OK);
    std::map<std::string, Seen> seen;
    EXPECT_EQ(walk(opened.archive(), &seen), GARC_ERR_LIMIT_NAME_BYTES);
  }
}

//-----------------------------------------------------------------------------
// Hand-built archives: the control, then one thing broken at a time
//-----------------------------------------------------------------------------

namespace {

SzBuilder control() {
  SzBuilder builder;
  builder.add("a.txt", "alpha");
  builder.add("b.txt", "bravo bravo");
  builder.add_directory("dir");
  builder.add("empty", "");
  return builder;
}

}  // namespace

TEST(SevenZBuilt, TheControlIsReadWithoutComplaint) {
  for (bool solid : {true, false}) {
    Opened opened(control().solid(solid).build());
    ASSERT_EQ(opened.open_result(), GARC_OK);
    std::map<std::string, Seen> seen;
    std::vector<std::string> order;
    ASSERT_EQ(walk(opened.archive(), &seen, &order), GARC_END);
    ASSERT_EQ(order, (std::vector<std::string>{"a.txt", "b.txt", "dir", "empty"}));
    EXPECT_EQ(seen["a.txt"].data, "alpha");
    EXPECT_EQ(seen["b.txt"].data, "bravo bravo");
    EXPECT_EQ(seen["dir"].type, GARC_MEMBER_DIRECTORY);
    EXPECT_EQ(seen["empty"].type, GARC_MEMBER_FILE);
    EXPECT_EQ(seen["empty"].size, 0u);
  }
}

TEST(SevenZBuilt, AnArchiveOfNothingHasNoMembers) {
  std::string out = SzBuilder::assemble("", "");
  Opened opened(out);
  ASSERT_EQ(opened.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  EXPECT_EQ(garc_next(opened.archive(), &member), GARC_END);
}

TEST(SevenZBuilt, ATimeAndAnAttributeWordAreReported) {
  SzBuilder builder = control();
  builder.add("t", "x");
  builder.last().has_mtime = true;
  // 2001-09-09T01:46:40Z, as 100 ns ticks since 1601, plus 5 ticks.
  builder.last().mtime = (1000000000ull + 11644473600ull) * 10000000ull + 5ull;
  builder.last().has_attr = true;
  builder.last().attr = 0x8000u | (0100755u << 16);
  Opened opened(builder.build());
  ASSERT_EQ(opened.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  bool found = false;
  while (garc_next(opened.archive(), &member) == GARC_OK) {
    if (std::string(member->name, member->name_length) == "t") {
      found = true;
      EXPECT_EQ(member->mtime_seconds, 1000000000);
      EXPECT_EQ(member->mtime_nanoseconds, 500u);
      EXPECT_EQ(member->mtime_source, GARC_TIME_FILETIME);
      EXPECT_EQ(member->mode, 0100755u);
      EXPECT_TRUE(member->mode_valid);
    }
  }
  EXPECT_TRUE(found);
}

TEST(SevenZBuilt, AWindowsDirectoryAttributeMakesADirectoryOfAFileWithNoData) {
  SzBuilder builder;
  builder.add("x", "");
  builder.last().has_attr = true;
  builder.last().attr = 0x10u;
  Opened opened(builder.build());
  ASSERT_EQ(opened.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive(), &member), GARC_OK);
  EXPECT_EQ(member->type, GARC_MEMBER_DIRECTORY);
}

TEST(SevenZBuilt, SurrogatesBecomeFourByteUtf8AndALoneOneBecomesAReplacement) {
  SzBuilder builder;
  builder.add(std::u16string{u'a', 0xD83D, 0xDE00}, "1");
  builder.add(std::u16string{u'b', 0xD83D, u'c'}, "2");
  builder.add(std::u16string{u'd', 0xDE00}, "3");
  Opened opened(builder.build());
  ASSERT_EQ(opened.open_result(), GARC_OK);
  std::map<std::string, Seen> seen;
  ASSERT_EQ(walk(opened.archive(), &seen), GARC_END);
  EXPECT_EQ(seen.count("a\xF0\x9F\x98\x80"), 1u);
  EXPECT_EQ(seen.count("b\xEF\xBF\xBD" "c"), 1u);
  EXPECT_EQ(seen.count("d\xEF\xBF\xBD"), 1u);
}

TEST(SevenZBuilt, AnAntiItemIsOtherAndNotData) {
  SzBuilder builder;
  builder.add("gone", "");
  builder.last().empty_file = false;
  builder.last().anti = true;
  Opened opened(builder.build());
  ASSERT_EQ(opened.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive(), &member), GARC_OK);
  EXPECT_EQ(member->type, GARC_MEMBER_OTHER);
}

TEST(SevenZBuilt, AWrongStoredCrcIsReportedWhenTheMemberEnds) {
  SzBuilder builder = control();
  builder.add("bad", "damaged");
  builder.last().crc_error = 1u;
  Opened opened(builder.build());
  ASSERT_EQ(opened.open_result(), GARC_OK);
  std::map<std::string, Seen> seen;
  ASSERT_EQ(walk(opened.archive(), &seen), GARC_END);
  EXPECT_EQ(seen["bad"].data, "damaged");
  EXPECT_EQ(seen["bad"].status, GARC_ERR_CORRUPT);
  EXPECT_EQ(seen["a.txt"].status, GARC_OK);
}

TEST(SevenZBuilt, ADamagedStartHeaderIsRefused) {
  std::string good = control().build();
  for (size_t i : {size_t(8), size_t(12), size_t(19), size_t(27), size_t(31)}) {
    SCOPED_TRACE(i);
    std::string bad = good;
    bad[i] = static_cast<char>(bad[i] ^ 1);
    Opened opened(bad);
    EXPECT_EQ(opened.open_result(), GARC_ERR_CORRUPT);
  }
}

TEST(SevenZBuilt, ADamagedHeaderIsRefusedByItsCrc) {
  std::string good = control().build();
  std::string bad = good;
  bad[bad.size() - 3] = static_cast<char>(bad[bad.size() - 3] ^ 1);
  Opened opened(bad);
  EXPECT_EQ(opened.open_result(), GARC_ERR_CORRUPT);
}

TEST(SevenZBuilt, ANewerMajorVersionIsUnsupported) {
  std::string bad = control().build();
  bad[6] = 1;
  Opened opened(bad);
  EXPECT_EQ(opened.open_result(), GARC_ERR_UNSUPPORTED);
}

TEST(SevenZBuilt, AHeaderPointingPastTheEndOfTheFileIsCorrupt) {
  SzBuilder builder = control();
  const std::string packed = builder.packed();
  const std::string header = builder.header();
  std::string out = SzBuilder::assemble(packed, header);
  // Claim an offset 1000 bytes further on, with the start CRC recomputed.
  std::string start;
  garctest::sz_u64(start, packed.size() + 1000u);
  garctest::sz_u64(start, header.size());
  garctest::sz_u32(start, garctest::sz_crc(header));
  std::string forged = out.substr(0, 8);
  garctest::sz_u32(forged, garctest::sz_crc(start));
  forged += start + out.substr(32);
  Opened opened(forged);
  EXPECT_EQ(opened.open_result(), GARC_ERR_CORRUPT);
}

TEST(SevenZBuilt, ASubstreamLargerThanItsFolderIsCorrupt) {
  SzBuilder builder = control();
  std::string header = builder.header();
  // Two substreams: the header says 0D 02 09 <size of a.txt>. Make it 100,
  // which is more than the 16-byte folder holds; the last is what is left.
  const size_t at = header.find(std::string("\x0D\x02\x09", 3));
  ASSERT_NE(at, std::string::npos);
  header[at + 3] = 100;
  Opened opened(SzBuilder::assemble(builder.packed(), header));
  EXPECT_EQ(opened.open_result(), GARC_ERR_CORRUPT);
}

TEST(SevenZBuilt, AFileCountTheHeaderCannotHoldIsRefusedBeforeAnythingIsAllocated) {
  std::string header;
  header.push_back(0x01);
  header.push_back(0x05);
  garctest::sz_number(header, 0x00FFFFFFFFFFFFFFull);
  header.push_back(0x00);
  header.push_back(0x00);
  Opened opened(SzBuilder::assemble("", header));
  EXPECT_EQ(opened.open_result(), GARC_ERR_CORRUPT);
}

TEST(SevenZBuilt, ANonEmptyFileCountThatDisagreesWithTheStreamsIsCorrupt) {
  // Two substreams, one file with a stream.
  SzBuilder two;
  two.add("a", "x");
  two.add("b", "y");
  std::string header = two.header();
  // Drop b's stream from the file list by marking it empty: set the
  // EmptyStream bit for file 1. The header has no 0x0E property yet, so splice.
  const size_t names = header.find('\x11');
  ASSERT_NE(names, std::string::npos);
  std::string bits;
  bits.push_back(0x0E);
  bits.push_back(0x01);
  bits.push_back(0x40);
  header.insert(names, bits);
  Opened opened(SzBuilder::assemble(two.packed(), header));
  EXPECT_EQ(opened.open_result(), GARC_ERR_CORRUPT);
}

TEST(SevenZBuilt, AnUnknownCoderIsUnsupportedOnTheDataOnly) {
  SzBuilder builder = control();
  std::string header = builder.header();
  // The coder is "01 01 00": one coder, flag 0x01, id 00 (copy). Make it id 0x7F.
  const size_t at = header.find(std::string("\x01\x01\x00\x0C", 4));
  ASSERT_NE(at, std::string::npos);
  header[at + 2] = 0x7F;
  Opened opened(SzBuilder::assemble(builder.packed(), header));
  ASSERT_EQ(opened.open_result(), GARC_OK);
  std::map<std::string, Seen> seen;
  ASSERT_EQ(walk(opened.archive(), &seen), GARC_END);
  EXPECT_EQ(seen["a.txt"].status, GARC_ERR_UNSUPPORTED);
  EXPECT_EQ(seen["dir"].status, GARC_OK);
  EXPECT_EQ(seen["empty"].status, GARC_OK);
}

TEST(SevenZBuilt, AHeaderSectionTwiceIsCorruptNotALeak) {
  // A second FilesInfo or MainStreamsInfo would overwrite what the first
  // allocated. The fuzzer found the leak; the format has no meaning for it.
  SzBuilder builder = control();
  std::string header = builder.header();
  ASSERT_EQ(header.back(), '\x00');
  const size_t files = header.find('\x05', 1);
  ASSERT_NE(files, std::string::npos);
  std::string twice = header.substr(0, header.size() - 1)
      + header.substr(files, header.size() - files - 1) + std::string(1, '\x00');
  Opened opened(SzBuilder::assemble(builder.packed(), twice));
  EXPECT_EQ(opened.open_result(), GARC_ERR_CORRUPT);
}

TEST(SevenZBuilt, AnOverlongPropertyLengthIsCorruptNotAnOverRead) {
  // A coder whose property size claims more than the header holds. The bound
  // used to be taken before the size's own bytes were consumed.
  SzBuilder builder = control();
  std::string header = builder.header();
  const size_t at = header.find(std::string("\x01\x01\x00\x0C", 4));
  ASSERT_NE(at, std::string::npos);
  // flag 0x21: id size 1 and has-properties; id 00; property size 0x7F.
  std::string bad = header.substr(0, at + 1) + std::string("\x21\x00\x7F", 3)
      + header.substr(at + 3);
  Opened opened(SzBuilder::assemble(builder.packed(), bad));
  EXPECT_EQ(opened.open_result(), GARC_ERR_CORRUPT);
}

//-----------------------------------------------------------------------------
// Corruption and allocation failure, swept
//-----------------------------------------------------------------------------

namespace {

/** Recompute the two header CRCs of an archive whose header was edited. */
std::vector<uint8_t> refix(std::vector<uint8_t> bytes) {
  auto le64 = [&](size_t at) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) {
      v = (v << 8) | bytes[at + i];
    }
    return v;
  };
  const uint64_t offset = le64(12);
  const uint64_t length = le64(20);
  if (32 + offset + length <= bytes.size()) {
    const uint32_t crc = garctest::sz_crc(std::string(
        bytes.begin() + 32 + offset, bytes.begin() + 32 + offset + length));
    for (int i = 0; i < 4; ++i) {
      bytes[28 + i] = static_cast<uint8_t>(crc >> (8 * i));
    }
  }
  const uint32_t start = garctest::sz_crc(
      std::string(bytes.begin() + 12, bytes.begin() + 32));
  for (int i = 0; i < 4; ++i) {
    bytes[8 + i] = static_cast<uint8_t>(start >> (8 * i));
  }
  return bytes;
}

bool documented(GARC_Result result) {
  return result == GARC_OK || result == GARC_END || result == GARC_ERR_CORRUPT
      || result == GARC_ERR_UNSUPPORTED || result == GARC_ERR_OOM
      || result == GARC_ERR_LIMIT_EXTRA_BYTES || result == GARC_ERR_IO
      || result == GARC_ERR_LIMIT_CODEC_BYTES
      || result == GARC_ERR_LIMIT_NAME_BYTES
      || result == GARC_ERR_LIMIT_MEMBERS
      || result == GARC_ERR_LIMIT_MEMBER_BYTES
      || result == GARC_ERR_LIMIT_TOTAL_BYTES;
}

/** Walk and read all of an archive; returns the first status that is not OK. */
GARC_Result walk_all(const std::vector<uint8_t> & bytes) {
  Opened opened(bytes);
  if (opened.open_result() != GARC_OK) {
    return opened.open_result();
  }
  std::map<std::string, Seen> seen;
  const GARC_Result result = walk(opened.archive(), &seen);
  for (const auto & one : seen) {
    if (!documented(one.second.status)) {
      return GARC_ERR_INTERNAL;
    }
  }
  return result;
}

void sweep_header(const std::vector<uint8_t> & whole) {
  uint64_t offset = 0;
  uint64_t length = 0;
  for (int i = 7; i >= 0; --i) {
    offset = (offset << 8) | whole[12 + i];
    length = (length << 8) | whole[20 + i];
  }
  ASSERT_LE(32 + offset + length, whole.size());
  size_t reached = 0;
  for (uint64_t at = 0; at < length; ++at) {
    for (uint8_t value : {uint8_t(0x00), uint8_t(0x01), uint8_t(0x7F),
             uint8_t(0xFF)}) {
      std::vector<uint8_t> mutated = whole;
      uint8_t & byte = mutated[32 + offset + at];
      if (byte == value) {
        continue;
      }
      byte = value;
      const GARC_Result result = walk_all(refix(mutated));
      EXPECT_TRUE(documented(result)) << "byte " << at << " -> "
          << int(value) << ": " << garc_result_string(result);
      reached += result != GARC_END;
    }
  }
  // Almost every edit to a header changes its meaning, and a sweep that
  // refused none of them would not be reaching the parser.
  EXPECT_GT(reached * 4, size_t(length));
}

}  // namespace

TEST(SevenZSweep, EveryByteOfAPlainHeaderEditedIsAnswered) {
  sweep_header(fixture("plainhdr.7z"));
  sweep_header(fixture("symlink.7z"));
  sweep_header(fixture("nonsolid.7z"));
}

TEST(SevenZSweep, EveryByteOfABuiltHeaderEditedIsAnswered) {
  SzBuilder builder = control();
  builder.add("t", "x");
  builder.last().has_mtime = true;
  builder.last().mtime = 130000000000000000ull;
  builder.last().has_attr = true;
  builder.last().attr = 0x8000u | (0100644u << 16);
  const std::string built = builder.build();
  sweep_header(std::vector<uint8_t>(built.begin(), built.end()));
}

TEST(SevenZSweep, EveryAllocationFailureInOpenAndWalkIsAnswered) {
  for (const char * name : {"basic.7z", "plainhdr.7z", "symlink.7z",
           "nonsolid.7z", "bcj.7z", "delta.7z", "copy.7z", "bcj2-copy.7z",
           "built:aes", "built:aes-header", "built:aes-bcj2"}) {
    SCOPED_TRACE(name);
    const std::vector<uint8_t> bytes = sweep_input(name);
    const bool encrypted = std::string(name).rfind("built:aes", 0) == 0;
    bool finished = false;
    for (size_t budget = 0; budget < 4000u && !finished; ++budget) {
      garctest::FailingAllocator allocator(budget);
      GARC_Stream * stream = nullptr;
      ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
          GARC_OK);
      GARC_Archive * archive = nullptr;
      GARC_Result result = garc_open_with_allocator(
          stream, nullptr, allocator.get(), &archive);
      if (result == GARC_OK && encrypted) {
        result = garc_set_password(
            archive, kBuiltPassword.data(), kBuiltPassword.size());
      }
      if (result == GARC_OK) {
        const GARC_Member * member = nullptr;
        while ((result = garc_next(archive, &member)) == GARC_OK) {
          char buffer[4096];
          size_t got = 0;
          GARC_Result read;
          while ((read = garc_read_member(archive, buffer, sizeof(buffer),
                      &got)) == GARC_OK
              && got) {
          }
          if (read != GARC_OK) {
            result = read;
            break;
          }
        }
      }
      EXPECT_TRUE(result == GARC_END || result == GARC_ERR_OOM)
          << garc_result_string(result);
      finished = result == GARC_END;
      garc_close(archive);
      garc_stream_destroy(stream);
      allocator.stop_failing();
      EXPECT_EQ(allocator.live(), 0u) << "budget " << budget;
    }
    EXPECT_TRUE(finished) << "never reached a clean walk";
  }
}

TEST(SevenZBuilt, UnixTypeBitsInTheAttributeWordSelectTheMemberType) {
  const struct {
    uint32_t mode;
    GARC_Member_Type type;
  } cases[] = {
    {0010644u, GARC_MEMBER_FIFO}, {0020644u, GARC_MEMBER_CHAR_DEVICE},
    {0060644u, GARC_MEMBER_BLOCK_DEVICE}, {0140644u, GARC_MEMBER_OTHER},
    {0100644u, GARC_MEMBER_FILE}, {0000644u, GARC_MEMBER_FILE},
  };
  for (const auto & one : cases) {
    SCOPED_TRACE(one.mode);
    SzBuilder builder;
    builder.add("x", "");
    builder.last().has_attr = true;
    builder.last().attr = 0x8000u | (one.mode << 16);
    Opened opened(builder.build());
    ASSERT_EQ(opened.open_result(), GARC_OK);
    const GARC_Member * member = nullptr;
    ASSERT_EQ(garc_next(opened.archive(), &member), GARC_OK);
    EXPECT_EQ(member->type, one.type);
  }
}

TEST(SevenZBuilt, ArchivePropertiesAreSkippedByTheirStatedSize) {
  SzBuilder builder = control();
  std::string header = builder.header();
  // 01 (Header) then 02 (ArchiveProperties): type 0x42, size 3, three bytes, end.
  header.insert(1, std::string("\x02\x42\x03xyz\x00", 7));
  Opened opened(SzBuilder::assemble(builder.packed(), header));
  ASSERT_EQ(opened.open_result(), GARC_OK);
  std::map<std::string, Seen> seen;
  EXPECT_EQ(walk(opened.archive(), &seen), GARC_END);
  EXPECT_EQ(seen["a.txt"].data, "alpha");
}

TEST(SevenZBuilt, AnAdditionalStreamsInfoIsParsedAndIgnored) {
  SzBuilder builder = control();
  std::string header = builder.header();
  // An empty StreamsInfo (just its End) after the Header id.
  header.insert(1, std::string("\x03\x00", 2));
  Opened opened(SzBuilder::assemble(builder.packed(), header));
  ASSERT_EQ(opened.open_result(), GARC_OK);
  std::map<std::string, Seen> seen;
  EXPECT_EQ(walk(opened.archive(), &seen), GARC_END);
}

TEST(SevenZBuilt, ADirectoryThatClaimsBytesIsCorrupt) {
  SzBuilder builder;
  builder.add("d", "data");
  builder.last().has_attr = true;
  builder.last().attr = 0x10u;
  Opened opened(builder.build());
  ASSERT_EQ(opened.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  EXPECT_EQ(garc_next(opened.archive(), &member), GARC_ERR_CORRUPT);
}

TEST(SevenZBuilt, ASymlinkLongerThanTheNameCapKeepsItsBytesAsData) {
  SzBuilder builder;
  builder.add("l", std::string(40, 't'));
  builder.last().has_attr = true;
  builder.last().attr = 0x8000u | (0120777u << 16);
  GARC_Limits limits;
  garc_limits_default(&limits);
  limits.max_name_bytes = 16;
  Opened opened(builder.build(), &limits);
  ASSERT_EQ(opened.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive(), &member), GARC_OK);
  EXPECT_EQ(member->type, GARC_MEMBER_SYMLINK);
  EXPECT_EQ(member->link_target, nullptr);
  GARC_Result status = GARC_OK;
  EXPECT_EQ(read_member(opened.archive(), &status), std::string(40, 't'));
  EXPECT_EQ(status, GARC_OK);
}

//-----------------------------------------------------------------------------
// BCJ2
//-----------------------------------------------------------------------------

namespace {

/** Decode four BCJ2 streams through the reader's own coder, @p chunk at a time. */
GARC_Result bcj2_decode(const garctest::Bcj2Streams & in, uint64_t out_size,
    std::string * out, size_t chunk = 4096) {
  const std::string * parts[4] = {&in.main, &in.call, &in.jump, &in.rc};
  GARC_Stream * streams[4] = {nullptr, nullptr, nullptr, nullptr};
  for (unsigned i = 0; i < 4u; ++i) {
    if (garc_stream_create_memory(parts[i]->data(), parts[i]->size(),
            &streams[i])
        != GARC_OK) {
      return GARC_ERR_OOM;
    }
  }
  GARC_Stream * bcj2 = nullptr;
  GARC_Result result = garc_sevenz_bcj2_stream_create(
      garc_allocator_default(), streams, out_size, &bcj2);
  std::vector<char> buffer(chunk);
  while (result == GARC_OK) {
    size_t got = 0;
    result = garc_stream_read(bcj2, buffer.data(), buffer.size(), &got);
    if (result != GARC_OK || !got) {
      break;
    }
    out->append(buffer.data(), got);
  }
  garc_stream_destroy(bcj2);
  for (GARC_Stream * stream : streams) {
    garc_stream_destroy(stream);
  }
  return result;
}

bool convert_all(size_t, int32_t) { return true; }
bool convert_none(size_t, int32_t) { return false; }
bool convert_odd(size_t at, int32_t) { return (at & 1u) != 0; }

} // namespace

TEST(SevenZBcj2, TheCoderUndoesEveryChoiceOfWhichBranchesToConvert) {
  // The only freedom a BCJ2 encoder has is which candidates to convert; the
  // decoder must undo any choice. All, none, alternate, and 7-Zip's rule.
  for (uint32_t seed : {1u, 2u, 3u}) {
    const std::string plain = x86ish(seed, 20000);
    for (auto rule : {convert_all, convert_none, convert_odd,
             garctest::bcj2_seven_zip_rule}) {
      const garctest::Bcj2Streams s = garctest::bcj2_encode(plain, rule);
      for (size_t chunk : {size_t(1), size_t(7), size_t(65536)}) {
        std::string out;
        EXPECT_EQ(bcj2_decode(s, plain.size(), &out, chunk), GARC_OK);
        EXPECT_EQ(out, plain) << "seed " << seed << " chunk " << chunk;
      }
    }
  }
}

TEST(SevenZBcj2, WithNoCandidatesTheRangeCoderIsFiveZeroBytes) {
  const std::string plain = "no branches in here at all";
  const garctest::Bcj2Streams s = garctest::bcj2_encode(plain, convert_all);
  EXPECT_EQ(s.rc, std::string(5, '\0'));
  EXPECT_TRUE(s.call.empty());
  EXPECT_TRUE(s.jump.empty());
  std::string out;
  EXPECT_EQ(bcj2_decode(s, plain.size(), &out), GARC_OK);
  EXPECT_EQ(out, plain);
}

TEST(SevenZBcj2, ATrailingCandidateStillHasItsBitDecoded) {
  // An E8 as the last byte, and one with three bytes after it: neither can be
  // converted, both have a 0 bit, and a decoder that skipped it would leave
  // range-coder state behind and fail the end checks.
  for (const std::string & plain : {std::string("abc\xE8", 4),
           std::string("abc\xE8\x01\x02\x03", 7), std::string("\xE9", 1)}) {
    const garctest::Bcj2Streams s = garctest::bcj2_encode(plain, convert_all);
    std::string out;
    EXPECT_EQ(bcj2_decode(s, plain.size(), &out), GARC_OK);
    EXPECT_EQ(out, plain);
  }
}

TEST(SevenZBcj2, AConvertedDisplacementEndingInZeroFMakesTheNext8xACandidate) {
  // 7-Zip's limit keeps a converted displacement's top byte away from 0F, so
  // its own archives never have this; the decoder must still treat a 0F that
  // a conversion wrote as the first half of a 0F 8x.
  std::string plain("\x90\xE8", 2);
  plain += std::string("\x00\x00\x00\x0F", 4); // displacement 0x0F000000
  plain += std::string("\x85\x10\x00\x00\x00", 5); // 8x, then its displacement
  plain += std::string(32, '\x90');
  const garctest::Bcj2Streams s = garctest::bcj2_encode(plain, convert_all);
  ASSERT_EQ(s.call.size(), 4u);
  ASSERT_EQ(s.jump.size(), 4u) << "the 85 after a written 0F was not converted";
  std::string out;
  EXPECT_EQ(bcj2_decode(s, plain.size(), &out), GARC_OK);
  EXPECT_EQ(out, plain);
}

TEST(SevenZBcj2, AnythingLeftOverOrMissingIsCorrupt) {
  const std::string plain = x86ish(9, 3000);
  const garctest::Bcj2Streams good
      = garctest::bcj2_encode(plain, garctest::bcj2_seven_zip_rule);
  ASSERT_FALSE(good.call.empty());
  ASSERT_FALSE(good.jump.empty());
  {
    std::string out;
    ASSERT_EQ(bcj2_decode(good, plain.size(), &out), GARC_OK);
  }
  struct Case {
    const char * what;
    garctest::Bcj2Streams s;
    uint64_t size;
  };
  std::vector<Case> cases;
  auto with = [&](const char * what, auto edit, uint64_t size) {
    garctest::Bcj2Streams s = good;
    edit(s);
    cases.push_back({what, s, size});
  };
  with("first range byte not zero",
      [](garctest::Bcj2Streams & s) { s.rc[0] = 1; }, plain.size());
  with("code all ones",
      [](garctest::Bcj2Streams & s) { s.rc.replace(0, 5, "\x00\xFF\xFF\xFF\xFF", 5); },
      plain.size());
  with("a range byte too many",
      [](garctest::Bcj2Streams & s) { s.rc.push_back(0); }, plain.size());
  with("a range byte too few",
      [](garctest::Bcj2Streams & s) { s.rc.pop_back(); }, plain.size());
  with("the last range byte changed",
      [](garctest::Bcj2Streams & s) { s.rc.back() ^= 0x01; }, plain.size());
  with("a call short",
      [](garctest::Bcj2Streams & s) { s.call.resize(s.call.size() - 4); },
      plain.size());
  with("a call too many",
      [](garctest::Bcj2Streams & s) { s.call += std::string(4, '\0'); },
      plain.size());
  with("a jump too many",
      [](garctest::Bcj2Streams & s) { s.jump += std::string(4, '\0'); },
      plain.size());
  with("main too long",
      [](garctest::Bcj2Streams & s) { s.main.push_back('x'); }, plain.size());
  with("declared size short", [](garctest::Bcj2Streams &) {}, plain.size() - 1);
  with("declared size long", [](garctest::Bcj2Streams &) {}, plain.size() + 1);
  with("no range coder at all",
      [](garctest::Bcj2Streams & s) { s.rc.clear(); }, plain.size());
  for (const Case & c : cases) {
    std::string out;
    EXPECT_EQ(bcj2_decode(c.s, c.size, &out), GARC_ERR_CORRUPT) << c.what;
  }
}

TEST(SevenZBcj2, The7ZipRuleReproducesTheFourStreams7ZipWrote) {
  // bcj2-copy.7z puts BCJ2's four streams behind Copy coders, so they sit raw
  // in the pack area: MAIN, then the range coder, then CALL, then JUMP. The
  // folder decodes to the files in order. Encoding that with 7-Zip's rule must
  // give 7-Zip's bytes, which checks this file's encoder - and so the reading
  // of the description that the decoder shares with it - against 7-Zip. It
  // is also how the rule's per-file target limit, which the description left
  // open, was found: without it the streams part 222 bytes into program.bin.
  const std::vector<uint8_t> bytes = fixture("bcj2-copy.7z");
  Opened opened(bytes);
  ASSERT_EQ(opened.open_result(), GARC_OK);
  std::string folder;
  std::vector<std::pair<size_t, size_t>> files;
  const GARC_Member * member = nullptr;
  while (garc_next(opened.archive(), &member) == GARC_OK) {
    GARC_Result status = GARC_OK;
    const size_t start = folder.size();
    folder += read_member(opened.archive(), &status);
    ASSERT_EQ(status, GARC_OK);
    if (folder.size() > start) {
      files.push_back({start, folder.size() - start});
    }
  }
  const garctest::Bcj2Streams s
      = garctest::bcj2_encode(folder, garctest::bcj2_seven_zip_files(files));
  EXPECT_FALSE(s.call.empty());
  const std::string packed = s.main + s.rc + s.call + s.jump;
  ASSERT_GE(bytes.size(), 32u + packed.size());
  EXPECT_TRUE(std::equal(packed.begin(), packed.end(),
      reinterpret_cast<const char *>(bytes.data()) + 32))
      << "the encoder does not reproduce 7-Zip's BCJ2 streams";
}

//-----------------------------------------------------------------------------
// AES
//-----------------------------------------------------------------------------

namespace {

/** Walk with @p password set first (none when NULL). */
GARC_Result walk_with(const std::vector<uint8_t> & bytes,
    const std::string * password, std::map<std::string, Seen> * seen) {
  Opened opened(bytes);
  if (opened.open_result() != GARC_OK) {
    return opened.open_result();
  }
  if (password) {
    const GARC_Result set = garc_set_password(
        opened.archive(), password->data(), password->size());
    if (set != GARC_OK) {
      return set;
    }
  }
  return walk(opened.archive(), seen);
}

/** Check a walk against the manifest, every file's data with @p want_status. */
void expect_manifest(const std::map<std::string, Seen> & seen,
    GARC_Result want_status) {
  const std::vector<Row> rows = manifest();
  ASSERT_EQ(seen.size(), rows.size());
  for (const Row & row : rows) {
    SCOPED_TRACE(row.name);
    ASSERT_EQ(seen.count(row.name), 1u);
    const Seen & got = seen.at(row.name);
    EXPECT_EQ(got.size, row.size);
    if (row.type != "file") {
      continue;
    }
    if (!row.size) {
      EXPECT_EQ(got.status, GARC_OK);
      continue;
    }
    EXPECT_EQ(got.status, want_status);
    if (want_status == GARC_OK) {
      EXPECT_EQ(garctest::sz_crc(got.data), row.crc);
    }
  }
}

} // namespace

TEST(SevenZAes, EveryEncryptedArchiveHoldsWhatWasArchived) {
  for (const char * name : kEncrypted) {
    SCOPED_TRACE(name);
    std::map<std::string, Seen> seen;
    ASSERT_EQ(walk_with(fixture(name), &kPassword, &seen), GARC_END);
    expect_manifest(seen, GARC_OK);
  }
}

TEST(SevenZAes, WithoutAPasswordTheNamesAreReadAndTheDataIsNot) {
  for (const char * name : {"aes.7z", "aes-nonsolid.7z", "aes-bcj2.7z"}) {
    SCOPED_TRACE(name);
    std::map<std::string, Seen> seen;
    ASSERT_EQ(walk_with(fixture(name), nullptr, &seen), GARC_END);
    expect_manifest(seen, GARC_ERR_PASSWORD_REQUIRED);
  }
}

TEST(SevenZAes, AWrongPasswordIsPasswordOrCorruptAndTheWalkGoesOn) {
  // No check value exists: LZMA2 fails on the garbage, the copy coder's bytes
  // fail their CRC-32, and BCJ2's end checks fail. All three are one status.
  const std::string wrong = "not the password";
  for (const char * name : {"aes.7z", "aes-nonsolid.7z", "aes-copy.7z",
           "aes-bcj2.7z"}) {
    SCOPED_TRACE(name);
    std::map<std::string, Seen> seen;
    ASSERT_EQ(walk_with(fixture(name), &wrong, &seen), GARC_END);
    expect_manifest(seen, GARC_ERR_PASSWORD_OR_CORRUPT);
  }
}

TEST(SevenZAes, AnEncryptedHeaderWaitsForThePassword) {
  for (const char * name : {"aes-header.7z", "aes-header-one.7z"}) {
    SCOPED_TRACE(name);
    Opened opened(fixture(name));
    ASSERT_EQ(opened.open_result(), GARC_OK);
    const GARC_Member * member = nullptr;
    EXPECT_EQ(garc_next(opened.archive(), &member), GARC_ERR_PASSWORD_REQUIRED);
    EXPECT_EQ(garc_member_count(opened.archive()), 0u);
    const std::string wrong = "wrong";
    EXPECT_EQ(garc_set_password(opened.archive(), wrong.data(), wrong.size()),
        GARC_ERR_PASSWORD_OR_CORRUPT);
    EXPECT_EQ(garc_next(opened.archive(), &member), GARC_ERR_PASSWORD_REQUIRED);
    ASSERT_EQ(garc_set_password(
                  opened.archive(), kPassword.data(), kPassword.size()),
        GARC_OK);
    std::map<std::string, Seen> seen;
    ASSERT_EQ(walk(opened.archive(), &seen), GARC_END);
    if (std::string(name) == "aes-header.7z") {
      expect_manifest(seen, GARC_OK);
    }
    else {
      ASSERT_EQ(seen.size(), 1u);
      EXPECT_EQ(seen["hello.txt"].data, "hello, archive\n");
      EXPECT_EQ(seen["hello.txt"].status, GARC_OK);
    }
  }
}

TEST(SevenZAes, APasswordSetPartWayThroughASolidFolderReadsTheRest) {
  // The folder is not opened for the members before the password, so the one
  // after it starts the folder at a later member and has to skip to it.
  Opened opened(fixture("aes.7z"));
  ASSERT_EQ(opened.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  size_t refused = 0;
  while (refused < 2u && garc_next(opened.archive(), &member) == GARC_OK) {
    GARC_Result status = GARC_OK;
    read_member(opened.archive(), &status);
    if (member->size) {
      EXPECT_EQ(status, GARC_ERR_PASSWORD_REQUIRED);
      ++refused;
    }
  }
  ASSERT_EQ(refused, 2u);
  ASSERT_EQ(garc_set_password(
                opened.archive(), kPassword.data(), kPassword.size()),
      GARC_OK);
  std::map<std::string, Seen> rest;
  ASSERT_EQ(walk(opened.archive(), &rest), GARC_END);
  const std::vector<Row> rows = manifest();
  size_t checked = 0;
  for (const Row & row : rows) {
    if (rest.count(row.name) && row.type == "file" && row.size) {
      EXPECT_EQ(rest[row.name].status, GARC_OK) << row.name;
      EXPECT_EQ(garctest::sz_crc(rest[row.name].data), row.crc) << row.name;
      ++checked;
    }
  }
  EXPECT_GT(checked, 2u);
}

TEST(SevenZAes, APasswordThatIsNotUtf8IsInvalid) {
  Opened opened(fixture("aes.7z"));
  ASSERT_EQ(opened.open_result(), GARC_OK);
  for (const std::string & bad : {std::string("\xFF", 1), std::string("\xC3", 1),
           std::string("\xED\xA0\x80", 3), std::string("\xC0\x80", 2)}) {
    EXPECT_EQ(garc_set_password(opened.archive(), bad.data(), bad.size()),
        GARC_ERR_INVALID);
  }
  EXPECT_EQ(garc_set_password(opened.archive(), nullptr, 1), GARC_ERR_INVALID);
  EXPECT_EQ(garc_set_password(nullptr, "x", 1), GARC_ERR_INVALID);
}

TEST(SevenZAes, APasswordOnAFormatWithoutEncryptionIsInvalid) {
  Opened opened(fixture("copy.7z"));
  ASSERT_EQ(opened.open_result(), GARC_OK);
  EXPECT_EQ(garc_set_password(opened.archive(), "x", 1), GARC_OK)
      << "a 7z without encryption still takes one";
  const std::string tar(1024, '\0');
  Opened empty_tar(tar);
  if (empty_tar.open_result() == GARC_OK) {
    EXPECT_EQ(garc_set_password(empty_tar.archive(), "x", 1), GARC_ERR_INVALID);
  }
}

namespace {

/** One file behind an AES coder alone, with the properties given. */
std::string aes_alone(const std::string & props, const std::string & sealed,
    const std::string & plain) {
  garctest::SzFolder f;
  f.coders.push_back({garctest::sz_aes_id(), 1, props});
  f.packed = {0};
  f.unpack = {plain.size()};
  return garctest::sz_folder_archive({sealed}, f, "f", plain);
}

/** The one file's status and data, with kBuiltPassword. */
GARC_Result read_one(const std::string & archive, std::string * data) {
  std::map<std::string, Seen> seen;
  const std::vector<uint8_t> bytes(archive.begin(), archive.end());
  const GARC_Result walked = walk_with(bytes, &kBuiltPassword, &seen);
  if (walked != GARC_END) {
    return walked;
  }
  if (seen.size() != 1u) {
    return GARC_ERR_INTERNAL;
  }
  *data = seen.begin()->second.data;
  return seen.begin()->second.status;
}

} // namespace

TEST(SevenZAes, EveryPropertyLayout7ZipAcceptsDecrypts) {
  using namespace garctest;
  const std::string plain = "seven-zip's aes, by its properties\n";
  struct Case {
    const char * what;
    unsigned power;
    std::string salt, iv;
    bool given;        // props as written, rather than built from the three
    std::string props;
  };
  const std::vector<Case> cases = {
      {"no properties at all: power 0, no salt, a zero IV", 0, "", "", true,
          std::string()},
      {"one byte: power only", 0, "", "", true, std::string(1, '\x00')},
      {"power 0 with salt and IV", 0, "\x01\x02", "\x0A\x0B\x0C", false, ""},
      {"a sixteen-byte salt and IV", 0, std::string(16, 's'),
          std::string(16, 'i'), false, ""},
      {"power 63, no hash: salt then password", 63, "salt", "iv", false, ""},
      {"power 63 with a salt that leaves room for little of the password", 63,
          std::string(16, 'S'), std::string(16, 'v'), false, ""},
      {"a clear flag with a non-zero nibble still counts", 0, "\x77\x88",
          "\x99", true, std::string("\x40\x20\x77\x88\x99", 5)},
  };
  for (const Case & c : cases) {
    SCOPED_TRACE(c.what);
    const std::string props
        = c.given ? c.props : sz_aes_props(c.power, c.salt, c.iv);
    std::string iv16 = c.iv;
    iv16.resize(16, '\0');
    const std::string sealed
        = sz_aes_encrypt(sz_aes_key(kBuiltPassword, c.power, c.salt), iv16, plain);
    std::string data;
    EXPECT_EQ(read_one(aes_alone(props, sealed, plain), &data), GARC_OK);
    EXPECT_EQ(data, plain);
  }
}

TEST(SevenZAes, PropertiesAndPowers7ZipRefusesAreUnsupported) {
  using namespace garctest;
  const std::string plain = "x";
  const std::string sealed = std::string(16, '\0');
  for (const std::string & props : {std::string("\x19", 1), std::string("\x3E", 1),
           sz_aes_props(25, "", std::string(16, 'i')),
           sz_aes_props(62, "", std::string(16, 'i')),
           std::string("\x05\x00", 2), std::string("\x40\x0F\x01\x02", 4),
           sz_aes_props(0, "ab", "cd") + "x"}) {
    std::string data;
    EXPECT_EQ(read_one(aes_alone(props, sealed, plain), &data),
        GARC_ERR_UNSUPPORTED);
  }
}

TEST(SevenZAes, TheCiphertextMustCoverTheDataInWholeBlocks) {
  using namespace garctest;
  const std::string plain(38, 'p');
  const std::string iv(16, 'v');
  const std::string props = sz_aes_props(0, "", iv);
  const std::string sealed
      = sz_aes_encrypt(sz_aes_key(kBuiltPassword, 0, ""), iv, plain);
  ASSERT_EQ(sealed.size(), 48u);
  std::string data;
  EXPECT_EQ(read_one(aes_alone(props, sealed, plain), &data), GARC_OK);
  EXPECT_EQ(data, plain);
  // A whole block more is accepted, as 7-Zip accepts it.
  EXPECT_EQ(read_one(aes_alone(props, sealed + std::string(16, 'z'), plain), &data),
      GARC_OK);
  EXPECT_EQ(data, plain);
  // A block short, part of a block short, or part of a block over are not.
  for (size_t size : {size_t(32), size_t(40), size_t(47), size_t(49), size_t(56)}) {
    std::string cut = (sealed + std::string(16, 'z')).substr(0, size);
    EXPECT_EQ(read_one(aes_alone(props, cut, plain), &data),
        GARC_ERR_PASSWORD_OR_CORRUPT)
        << size;
  }
}

TEST(SevenZAes, AnEmptyPasswordIsAPassword) {
  using namespace garctest;
  const std::string plain = "empty password";
  const std::string iv(16, '1');
  const std::string sealed = sz_aes_encrypt(sz_aes_key("", 0, ""), iv, plain);
  const std::string archive = aes_alone(sz_aes_props(0, "", iv), sealed, plain);
  const std::vector<uint8_t> bytes(archive.begin(), archive.end());
  const std::string empty;
  std::map<std::string, Seen> seen;
  ASSERT_EQ(walk_with(bytes, &empty, &seen), GARC_END);
  EXPECT_EQ(seen["f"].status, GARC_OK);
  EXPECT_EQ(seen["f"].data, plain);
  seen.clear();
  ASSERT_EQ(walk_with(bytes, nullptr, &seen), GARC_END);
  EXPECT_EQ(seen["f"].status, GARC_ERR_PASSWORD_REQUIRED);
}

TEST(SevenZAes, KeyDerivationStopsAtItsCapAndCountsOnlyNewKeys) {
  // Power 10 is 1024 rounds. A cap of 1023 refuses the first key; 1024 allows
  // it; and reading the member twice (a rewind) does not derive it twice.
  using namespace garctest;
  const std::string plain = "capped";
  const std::string iv(16, 'c');
  const std::string sealed
      = sz_aes_encrypt(sz_aes_key(kBuiltPassword, 10, "s"), iv, plain);
  const std::string archive = aes_alone(sz_aes_props(10, "s", iv), sealed, plain);
  for (uint64_t cap : {uint64_t(1023), uint64_t(1024), uint64_t(0)}) {
    SCOPED_TRACE(cap);
    GARC_Limits limits;
    garc_limits_default(&limits);
    limits.max_key_rounds = cap;
    Opened opened(archive, &limits);
    ASSERT_EQ(opened.open_result(), GARC_OK);
    ASSERT_EQ(garc_set_password(opened.archive(), kBuiltPassword.data(),
                  kBuiltPassword.size()),
        GARC_OK);
    for (int pass = 0; pass < 2; ++pass) {
      const GARC_Member * member = nullptr;
      if (pass) {
        ASSERT_EQ(garc_find(opened.archive(), "f", 1, &member), GARC_OK);
      }
      else {
        const GARC_Result next = garc_next(opened.archive(), &member);
        if (cap == 1023u) {
          EXPECT_EQ(next, GARC_ERR_LIMIT_KEY_ROUNDS);
          break;
        }
        ASSERT_EQ(next, GARC_OK);
      }
      GARC_Result status = GARC_OK;
      EXPECT_EQ(read_member(opened.archive(), &status), plain);
      EXPECT_EQ(status, GARC_OK);
    }
  }
}

TEST(SevenZAes, BuiltArchivesWithTheHeaderAndBcj2EncryptedRead) {
  for (bool header : {false, true}) {
    SCOPED_TRACE(header ? "header encrypted" : "header plain");
    const std::string plain = x86ish(header ? 21u : 22u, 9000);
    const std::string archive = built_aes_bcj2(plain, header);
    std::string data;
    EXPECT_EQ(read_one(archive, &data), GARC_OK);
    EXPECT_TRUE(data == plain) << data.size() << " bytes of " << plain.size();
  }
}

TEST(SevenZAes, AnAppendToAnArchiveWhoseHeaderIsEncryptedIsRefused) {
  // The append writes a plain header, which would publish the names the
  // archive encrypted. Without a password the tables are not even known.
  Opened opened(fixture("aes-header.7z"));
  ASSERT_EQ(opened.open_result(), GARC_OK);
  GARC_SevenZ_Carry * carry = nullptr;
  EXPECT_EQ(garc_sevenz_carry(opened.archive(), garc_allocator_default(), &carry),
      GARC_ERR_UNSUPPORTED);
  ASSERT_EQ(garc_set_password(opened.archive(), kPassword.data(), kPassword.size()),
      GARC_OK);
  EXPECT_EQ(garc_sevenz_carry(opened.archive(), garc_allocator_default(), &carry),
      GARC_ERR_UNSUPPORTED);
  EXPECT_EQ(carry, nullptr);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
