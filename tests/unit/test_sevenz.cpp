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

#include "sevenz_builder.h"
#include "tar_manifest.h"
#include "test_helpers.h"

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
    "deflate.7z", "nonsolid.7z", "plainhdr.7z", "delta.7z", "bcj.7z",
    "arm64.7z"};

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

TEST(SevenZ, BcjTwoIsRefusedOnTheDataAndNotOnTheWalk) {
  Opened opened(fixture("bcj2.7z"));
  ASSERT_EQ(opened.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  size_t unreadable = 0;
  size_t listed = 0;
  GARC_Result result;
  while ((result = garc_next(opened.archive(), &member)) == GARC_OK) {
    ++listed;
    GARC_Result status = GARC_OK;
    read_member(opened.archive(), &status);
    if (member->size) {
      EXPECT_EQ(status, GARC_ERR_UNSUPPORTED) << member->name;
      ++unreadable;
    }
    else {
      EXPECT_EQ(status, GARC_OK) << member->name;
    }
  }
  EXPECT_EQ(result, GARC_END);
  EXPECT_EQ(listed, 12u);
  EXPECT_GT(unreadable, 0u);
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

TEST(SevenZ, NamesAreUtf8) {
  Opened opened(fixture("basic.7z"));
  ASSERT_EQ(opened.open_result(), GARC_OK);
  std::map<std::string, Seen> seen;
  ASSERT_EQ(walk(opened.archive(), &seen), GARC_END);
  EXPECT_EQ(seen.count("unicode/\xC3\xA9\xC3\xA8\xF0\x9F\x98\x80.txt"), 1u);
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

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
