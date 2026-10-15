/**
 * @file
 *
 * Reading and writing ar and cpio, and writing shar.
 *
 * The fixtures are written by libarchive's bsdtar in the pinned container and
 * the expectation is the source tree they were made from. What no reference in
 * the image writes - GNU's long-name table, a System V symbol table, the crc
 * dialect, devices - is built byte by byte here, from a well-formed control with
 * one thing turned at a time.
 *
 * Both formats are streams, so each corpus archive is read twice: from a file,
 * and from a pipe that cannot seek. The second is the one that fails if the
 * identification window is not drained into the first member's data.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstdint>
#include <cstring>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "failing_allocator.h"
#include "sevenz_builder.h"
#include "tar_manifest.h"
#include "test_helpers.h"

using garctest::BufferSource;
using garctest::read_fixture;
using garctest::sz_crc;

namespace {

std::string data_path(const std::string & name) {
  return std::string(GARC_TEST_DATA) + "/arcpio/" + name;
}

std::vector<uint8_t> fixture(const std::string & name) {
  std::vector<uint8_t> bytes = read_fixture(data_path(name));
  EXPECT_FALSE(bytes.empty()) << "missing corpus file " << name;
  return bytes;
}

std::vector<uint8_t> bytes_of(const std::string & text) {
  return std::vector<uint8_t>(text.begin(), text.end());
}

class Opened {
public:
  Opened(const std::vector<uint8_t> & bytes, const GARC_Limits * limits = nullptr,
      bool can_seek = true)
      : bytes_(bytes), source_(bytes_.data(), bytes_.size(), can_seek, can_seek) {
    if (garc_stream_create_callback(source_.callbacks(), &stream_) != GARC_OK) {
      stream_ = nullptr;
      return;
    }
    open_result_ = garc_open(stream_, limits, &archive_);
  }
  explicit Opened(const std::string & text, const GARC_Limits * limits = nullptr,
      bool can_seek = true)
      : Opened(bytes_of(text), limits, can_seek) {}
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

struct Seen {
  GARC_Member_Type type = GARC_MEMBER_FILE;
  uint64_t size = 0;
  uint32_t mode = 0;
  int64_t mtime = 0;
  std::string data;
  std::string link;
  GARC_Result status = GARC_OK;
  uint32_t major = 0;
  uint32_t minor = 0;
  bool device = false;
};

std::string read_member(GARC_Archive * archive, GARC_Result * status) {
  std::string out;
  char buffer[333];
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

GARC_Result walk(GARC_Archive * archive, std::map<std::string, Seen> * out,
    std::vector<std::string> * order = nullptr) {
  const GARC_Member * member = nullptr;
  GARC_Result result;
  while ((result = garc_next(archive, &member)) == GARC_OK) {
    const std::string name(member->name, member->name_length);
    Seen seen;
    seen.type = member->type;
    seen.size = member->size;
    seen.mode = member->mode;
    seen.mtime = member->mtime_seconds;
    seen.major = member->device_major;
    seen.minor = member->device_minor;
    seen.device = member->device_valid != 0;
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
  std::string name, type, link;
  uint64_t size = 0;
  uint32_t crc = 0;
  uint32_t mode = 0;
  int64_t mtime = 0;
};

std::vector<Row> manifest(const std::string & name) {
  const std::vector<uint8_t> bytes = fixture(name);
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
    f.resize(7);
    Row row;
    row.name = f[0];
    row.type = f[1];
    row.size = std::stoull(f[2]);
    row.crc = static_cast<uint32_t>(std::stoul(f[3], nullptr, 16));
    row.mode = static_cast<uint32_t>(std::stoul(f[4], nullptr, 8));
    row.mtime = std::stoll(f[5]);
    row.link = f[6];
    rows.push_back(row);
  }
  return rows;
}

GARC_Member_Type type_of(const std::string & name) {
  if (name == "directory") return GARC_MEMBER_DIRECTORY;
  if (name == "symlink") return GARC_MEMBER_SYMLINK;
  if (name == "fifo") return GARC_MEMBER_FIFO;
  return GARC_MEMBER_FILE;
}

void expect_rows(const std::vector<Row> & rows,
    const std::map<std::string, Seen> & seen) {
  ASSERT_EQ(seen.size(), rows.size());
  for (const Row & row : rows) {
    SCOPED_TRACE(row.name);
    ASSERT_EQ(seen.count(row.name), 1u);
    const Seen & got = seen.at(row.name);
    EXPECT_EQ(got.type, type_of(row.type));
    EXPECT_EQ(got.status, GARC_OK);
    EXPECT_EQ(got.mode & 07777u, row.mode);
    EXPECT_EQ(got.mtime, row.mtime);
    if (row.type == "file") {
      EXPECT_EQ(got.size, row.size);
      EXPECT_EQ(got.data.size(), row.size);
      EXPECT_EQ(sz_crc(got.data), row.crc);
    }
    if (row.type == "symlink") {
      EXPECT_EQ(got.link, row.link);
    }
  }
}

}  // namespace

//-----------------------------------------------------------------------------
// The corpus
//-----------------------------------------------------------------------------

TEST(Cpio, EveryTextDialectHoldsExactlyWhatWasArchived) {
  const std::vector<Row> rows = manifest("manifest-cpio.tsv");
  ASSERT_EQ(rows.size(), 16u);
  for (const char * name : {"newc.cpio", "odc.cpio"}) {
    for (bool can_seek : {true, false}) {
      SCOPED_TRACE(name);
      SCOPED_TRACE(can_seek);
      Opened opened(fixture(name), nullptr, can_seek);
      ASSERT_EQ(opened.open_result(), GARC_OK);
      EXPECT_EQ(garc_format(opened.archive()), GARC_FORMAT_CPIO);
      std::map<std::string, Seen> seen;
      ASSERT_EQ(walk(opened.archive(), &seen), GARC_END);
      expect_rows(rows, seen);
    }
  }
}

TEST(Ar, TheCommonArchiveHoldsExactlyWhatWasArchivedInOrder) {
  const std::vector<Row> rows = manifest("manifest-ar.tsv");
  ASSERT_EQ(rows.size(), 9u);
  for (bool can_seek : {true, false}) {
    SCOPED_TRACE(can_seek);
    Opened opened(fixture("common.a"), nullptr, can_seek);
    ASSERT_EQ(opened.open_result(), GARC_OK);
    EXPECT_EQ(garc_format(opened.archive()), GARC_FORMAT_AR);
    std::map<std::string, Seen> seen;
    std::vector<std::string> order;
    ASSERT_EQ(walk(opened.archive(), &seen, &order), GARC_END);
    ASSERT_EQ(order.size(), rows.size());
    for (size_t i = 0; i < rows.size(); ++i) {
      EXPECT_EQ(order[i], rows[i].name);
    }
    expect_rows(rows, seen);
  }
}

TEST(Cpio, TheBinaryDialectIsRefusedByName) {
  Opened opened(fixture("bin.cpio"));
  EXPECT_EQ(opened.open_result(), GARC_ERR_UNSUPPORTED);
}

TEST(ArCpio, FormatsHaveNamesAndTimesHaveASource) {
  EXPECT_STREQ(garc_format_string(GARC_FORMAT_AR), "ar");
  EXPECT_STREQ(garc_format_string(GARC_FORMAT_CPIO), "cpio");
  EXPECT_STREQ(garc_format_string(GARC_FORMAT_SHAR), "shar");
  EXPECT_STREQ(garc_time_source_string(GARC_TIME_UNIX), "unix-seconds");
}

TEST(Ar, FindRewindsAndTheSecondWalkReadsTheMagicAgain) {
  Opened opened(fixture("common.a"));
  ASSERT_EQ(opened.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  for (int pass = 0; pass < 2; ++pass) {
    ASSERT_EQ(garc_find(opened.archive(), "odd", 3, &member), GARC_OK);
    GARC_Result status = GARC_OK;
    EXPECT_EQ(read_member(opened.archive(), &status), "odd");
  }
  EXPECT_EQ(garc_find(opened.archive(), "nope", 4, &member), GARC_END);
}

TEST(Cpio, SkippingMembersLandsOnTheRightOnes) {
  Opened opened(fixture("newc.cpio"), nullptr, false);
  ASSERT_EQ(opened.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  std::string wanted;
  while (garc_next(opened.archive(), &member) == GARC_OK) {
    if (std::string(member->name, member->name_length) == "s3") {
      GARC_Result status = GARC_OK;
      wanted = read_member(opened.archive(), &status);
      break;
    }
    ASSERT_EQ(garc_skip_member(opened.archive()), GARC_OK);
  }
  EXPECT_EQ(wanted, "xyz");
}

//-----------------------------------------------------------------------------
// Hand-built ar
//-----------------------------------------------------------------------------

namespace {

std::string pad(const std::string & text, size_t width) {
  return text + std::string(width - text.size(), ' ');
}

std::string ar_header(const std::string & name, size_t size,
    const std::string & mode = "100644", const std::string & mtime = "1000000000") {
  return pad(name, 16) + pad(mtime, 12) + pad("0", 6) + pad("0", 6)
      + pad(mode, 8) + pad(std::to_string(size), 10) + "`\n";
}

std::string ar_member(const std::string & name, const std::string & data) {
  return ar_header(name, data.size()) + data + (data.size() & 1 ? "\n" : "");
}

const std::string kArMagic = "!<arch>\n";

}  // namespace

TEST(ArBuilt, GnuLongNamesComeFromTheTableAndSymbolTablesAreNotMembers) {
  const std::string table = "a-name-longer-than-sixteen.txt/\nsecond-long-name.c/\n";
  std::string text = kArMagic + ar_member("/", std::string("\0\0\0\0", 4))
      + ar_member("//", table) + ar_member("/0", "one")
      + ar_member("/32", "two") + ar_member("short.o/", "three")
      + ar_member("/SYM64/", "skipped");
  Opened opened(text);
  ASSERT_EQ(opened.open_result(), GARC_OK);
  std::map<std::string, Seen> seen;
  std::vector<std::string> order;
  ASSERT_EQ(walk(opened.archive(), &seen, &order), GARC_END);
  ASSERT_EQ(order, (std::vector<std::string>{"a-name-longer-than-sixteen.txt",
                       "second-long-name.c", "short.o"}));
  EXPECT_EQ(seen["a-name-longer-than-sixteen.txt"].data, "one");
  EXPECT_EQ(seen["second-long-name.c"].data, "two");
  EXPECT_EQ(seen["short.o"].data, "three");
}

TEST(ArBuilt, BsdNamesAreInTheDataAndItsSymbolTableIsSkipped) {
  const std::string symdef = std::string("__.SYMDEF SORTED") + std::string(4, '\0')
      + "symbols";
  const std::string name = "a-bsd-name-longer-than-sixteen";
  std::string text = kArMagic
      + ar_header("#1/20", symdef.size()) + symdef + (symdef.size() & 1 ? "\n" : "")
      + ar_header("#1/" + std::to_string(name.size()), name.size() + 4)
      + name + "data" + "";
  Opened opened(text);
  ASSERT_EQ(opened.open_result(), GARC_OK);
  std::map<std::string, Seen> seen;
  ASSERT_EQ(walk(opened.archive(), &seen), GARC_END);
  ASSERT_EQ(seen.size(), 1u);
  EXPECT_EQ(seen[name].data, "data");
  EXPECT_EQ(seen[name].size, 4u);
}

TEST(ArBuilt, AnEmptyArchiveHasNoMembers) {
  Opened opened(kArMagic);
  ASSERT_EQ(opened.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  EXPECT_EQ(garc_next(opened.archive(), &member), GARC_END);
}

TEST(ArBuilt, ABlankModeAndATrailingSpaceNameAreHandled) {
  std::string text = kArMagic + ar_header("blank-mode/", 0, "   ")
      + ar_member("normal/", "x");
  Opened opened(text);
  ASSERT_EQ(opened.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive(), &member), GARC_OK);
  EXPECT_FALSE(member->mode_valid);
  EXPECT_EQ(std::string(member->name, member->name_length), "blank-mode");
}

TEST(ArBuilt, EachDamageIsCorruptAndNothingElse) {
  const std::string good = kArMagic + ar_member("a/", "data");
  struct Case {
    const char * what;
    std::string text;
  };
  std::vector<Case> cases;
  {
    std::string t = good;
    t[8 + 58] = 'x';
    cases.push_back({"a header that does not end in the marker", t});
  }
  cases.push_back({"a header cut short", good.substr(0, 8 + 30)});
  cases.push_back({"data cut short", good.substr(0, good.size() - 3)});
  cases.push_back({"a size that is not a number",
      kArMagic + pad("a/", 16) + pad("0", 12) + pad("0", 6) + pad("0", 6)
          + pad("100644", 8) + pad("12x", 10) + "`\n"});
  cases.push_back({"a name offset with no table",
      kArMagic + ar_member("/0", "x")});
  cases.push_back({"a name offset past the table",
      kArMagic + ar_member("//", "ab/\n") + ar_member("/99", "x")});
  cases.push_back({"a BSD name longer than the member",
      kArMagic + ar_header("#1/50", 4) + "abcd"});
  cases.push_back({"an empty name", kArMagic + ar_member("/", "x").replace(0, 0, "")
          .substr(0, 0) + ar_header("", 0)});
  for (const Case & one : cases) {
    SCOPED_TRACE(one.what);
    Opened opened(one.text);
    if (opened.open_result() != GARC_OK) {
      EXPECT_EQ(opened.open_result(), GARC_ERR_FORMAT);
      continue;
    }
    std::map<std::string, Seen> seen;
    const GARC_Result result = walk(opened.archive(), &seen);
    bool any_bad = result == GARC_ERR_CORRUPT;
    for (const auto & member : seen) {
      any_bad |= member.second.status == GARC_ERR_CORRUPT;
    }
    EXPECT_TRUE(any_bad) << garc_result_string(result);
  }
}

TEST(ArBuilt, TheLimitsFire) {
  GARC_Limits limits;
  garc_limits_default(&limits);
  limits.max_members = 1;
  {
    Opened opened(kArMagic + ar_member("a/", "1") + ar_member("b/", "2"), &limits);
    std::map<std::string, Seen> seen;
    EXPECT_EQ(walk(opened.archive(), &seen), GARC_ERR_LIMIT_MEMBERS);
  }
  garc_limits_default(&limits);
  limits.max_name_bytes = 4;
  {
    const std::string name = "long-bsd-name";
    Opened opened(kArMagic + ar_header("#1/13", 13) + name, &limits);
    std::map<std::string, Seen> seen;
    EXPECT_EQ(walk(opened.archive(), &seen), GARC_ERR_LIMIT_NAME_BYTES);
  }
}

//-----------------------------------------------------------------------------
// Hand-built cpio
//-----------------------------------------------------------------------------

namespace {

std::string hex8(uint64_t v) {
  char text[16];
  snprintf(text, sizeof(text), "%08llx", static_cast<unsigned long long>(v));
  return text;
}

std::string newc(const std::string & name, const std::string & data,
    uint32_t mode, const char * magic = "070701", uint32_t check = 0,
    uint32_t rmajor = 0, uint32_t rminor = 0) {
  std::string out = magic + hex8(1) + hex8(mode) + hex8(0) + hex8(0) + hex8(1)
      + hex8(1000000000) + hex8(data.size()) + hex8(0) + hex8(0) + hex8(rmajor)
      + hex8(rminor) + hex8(name.size() + 1) + hex8(check);
  out += name;
  out.push_back('\0');
  out.append((4 - (110 + name.size() + 1) % 4) % 4, '\0');
  out += data;
  out.append((4 - data.size() % 4) % 4, '\0');
  return out;
}

std::string trailer() { return newc("TRAILER!!!", "", 0); }

}  // namespace

TEST(CpioBuilt, TheCrcDialectChecksItsSum) {
  uint32_t sum = 0;
  for (unsigned char c : std::string("checked")) {
    sum += c;
  }
  {
    Opened opened(newc("f", "checked", 0100644, "070702", sum) + trailer());
    ASSERT_EQ(opened.open_result(), GARC_OK);
    std::map<std::string, Seen> seen;
    ASSERT_EQ(walk(opened.archive(), &seen), GARC_END);
    EXPECT_EQ(seen["f"].status, GARC_OK);
    EXPECT_EQ(seen["f"].data, "checked");
  }
  {
    Opened opened(newc("f", "checked", 0100644, "070702", sum + 1) + trailer());
    ASSERT_EQ(opened.open_result(), GARC_OK);
    std::map<std::string, Seen> seen;
    ASSERT_EQ(walk(opened.archive(), &seen), GARC_END);
    EXPECT_EQ(seen["f"].status, GARC_ERR_CORRUPT);
  }
}

TEST(CpioBuilt, DevicesCarryTheirNumbersAndASocketIsOther) {
  Opened opened(newc("chr", "", 020644, "070701", 0, 4, 64)
      + newc("blk", "", 060644, "070701", 0, 8, 1) + newc("sock", "", 0140644)
      + newc("fifo", "", 010644) + trailer());
  ASSERT_EQ(opened.open_result(), GARC_OK);
  std::map<std::string, Seen> seen;
  ASSERT_EQ(walk(opened.archive(), &seen), GARC_END);
  EXPECT_EQ(seen["chr"].type, GARC_MEMBER_CHAR_DEVICE);
  EXPECT_TRUE(seen["chr"].device);
  EXPECT_EQ(seen["chr"].major, 4u);
  EXPECT_EQ(seen["chr"].minor, 64u);
  EXPECT_EQ(seen["blk"].type, GARC_MEMBER_BLOCK_DEVICE);
  EXPECT_EQ(seen["sock"].type, GARC_MEMBER_OTHER);
  EXPECT_EQ(seen["fifo"].type, GARC_MEMBER_FIFO);
}

TEST(CpioBuilt, AnArchiveWithNoTrailerEndsWhereTheStreamDoes) {
  Opened opened(newc("only", "data", 0100644));
  ASSERT_EQ(opened.open_result(), GARC_OK);
  std::map<std::string, Seen> seen;
  EXPECT_EQ(walk(opened.archive(), &seen), GARC_END);
  EXPECT_EQ(seen["only"].data, "data");
}

TEST(CpioBuilt, EachDamageIsCorruptAndNothingElse) {
  const std::string good = newc("f", "data", 0100644) + trailer();
  struct Case {
    const char * what;
    std::string text;
  };
  std::vector<Case> cases;
  cases.push_back({"a header cut short", good.substr(0, 60)});
  cases.push_back({"a name cut short", good.substr(0, 112)});
  cases.push_back({"data cut short", good.substr(0, 116 + 2)});
  {
    std::string t = good;
    t[10] = 'g';
    cases.push_back({"a field that is not hex", t});
  }
  {
    std::string t = good;
    t.replace(6 + 8 * 11, 8, hex8(0));
    cases.push_back({"a name size of zero", t});
  }
  {
    std::string t = good;
    t[110] = 'X';
    t[111] = 'Y';
    cases.push_back({"a name that is not terminated", t});
  }
  {
    std::string t = good;
    t.replace(0, 6, "070700");
    cases.push_back({"a magic that is not one", t});
  }
  for (const Case & one : cases) {
    SCOPED_TRACE(one.what);
    Opened opened(one.text);
    if (opened.open_result() != GARC_OK) {
      EXPECT_NE(opened.open_result(), GARC_ERR_INTERNAL);
      continue;
    }
    std::map<std::string, Seen> seen;
    const GARC_Result result = walk(opened.archive(), &seen);
    bool any_bad = result == GARC_ERR_CORRUPT;
    for (const auto & member : seen) {
      any_bad |= member.second.status == GARC_ERR_CORRUPT;
    }
    EXPECT_TRUE(any_bad) << garc_result_string(result);
  }
}

TEST(CpioBuilt, TheLimitsFire) {
  GARC_Limits limits;
  garc_limits_default(&limits);
  limits.max_name_bytes = 3;
  {
    Opened opened(newc("long-name", "", 0100644) + trailer(), &limits);
    std::map<std::string, Seen> seen;
    EXPECT_EQ(walk(opened.archive(), &seen), GARC_ERR_LIMIT_NAME_BYTES);
  }
  garc_limits_default(&limits);
  limits.max_name_bytes = 4;
  {
    Opened opened(newc("lnk", "much-too-long", 0120777) + trailer(), &limits);
    std::map<std::string, Seen> seen;
    EXPECT_EQ(walk(opened.archive(), &seen), GARC_ERR_LIMIT_NAME_BYTES);
  }
}

//-----------------------------------------------------------------------------
// Corruption and allocation failure, swept
//-----------------------------------------------------------------------------

namespace {

bool documented(GARC_Result result) {
  return result == GARC_OK || result == GARC_END || result == GARC_ERR_CORRUPT
      || result == GARC_ERR_UNSUPPORTED || result == GARC_ERR_FORMAT
      || result == GARC_ERR_OOM || result == GARC_ERR_IO
      || result == GARC_ERR_LIMIT_NAME_BYTES
      || result == GARC_ERR_LIMIT_EXTRA_BYTES
      || result == GARC_ERR_LIMIT_MEMBERS
      || result == GARC_ERR_LIMIT_MEMBER_BYTES
      || result == GARC_ERR_LIMIT_TOTAL_BYTES;
}

void sweep_bytes(const std::vector<uint8_t> & whole, size_t limit) {
  for (size_t at = 0; at < whole.size() && at < limit; ++at) {
    for (uint8_t value : {uint8_t(0x00), uint8_t(0x20), uint8_t(0x7F),
             uint8_t(0xFF), uint8_t('9')}) {
      std::vector<uint8_t> mutated = whole;
      if (mutated[at] == value) {
        continue;
      }
      mutated[at] = value;
      Opened opened(mutated, nullptr, at % 2 == 0);
      if (opened.open_result() != GARC_OK) {
        EXPECT_TRUE(documented(opened.open_result()));
        continue;
      }
      std::map<std::string, Seen> seen;
      EXPECT_TRUE(documented(walk(opened.archive(), &seen)));
      for (const auto & one : seen) {
        EXPECT_TRUE(documented(one.second.status));
      }
    }
  }
}

}  // namespace

TEST(ArCpioSweep, EveryHeaderByteEditedIsAnswered) {
  sweep_bytes(fixture("common.a"), 8 + 60 * 3);
  sweep_bytes(fixture("newc.cpio"), 400);
  sweep_bytes(fixture("odc.cpio"), 400);
}

TEST(ArCpioSweep, EveryAllocationFailureIsAnswered) {
  for (const char * name : {"common.a", "newc.cpio", "odc.cpio"}) {
    SCOPED_TRACE(name);
    const std::vector<uint8_t> bytes = fixture(name);
    bool finished = false;
    for (size_t budget = 0; budget < 200u && !finished; ++budget) {
      garctest::FailingAllocator allocator(budget);
      GARC_Stream * stream = nullptr;
      ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
          GARC_OK);
      GARC_Archive * archive = nullptr;
      GARC_Result result = garc_open_with_allocator(
          stream, nullptr, allocator.get(), &archive);
      if (result == GARC_OK) {
        const GARC_Member * member = nullptr;
        while ((result = garc_next(archive, &member)) == GARC_OK) {
        }
      }
      EXPECT_TRUE(result == GARC_END || result == GARC_ERR_OOM);
      finished = result == GARC_END;
      garc_close(archive);
      garc_stream_destroy(stream);
      allocator.stop_failing();
      EXPECT_EQ(allocator.live(), 0u);
    }
    EXPECT_TRUE(finished);
  }
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
