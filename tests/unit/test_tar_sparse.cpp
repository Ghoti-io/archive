/**
 * @file
 *
 * GNU sparse files, in the four forms GNU tar writes.
 *
 * The fixtures are GNU tar 1.35's (tools/oracle/make_corpus.py), and what they
 * should read as is two other readers' answer: sparse.tsv has the sha256 of
 * every member's real content as Python's tarfile and as bsdtar read it. The
 * hand-built archives below are the one file - five bytes, a hole, three bytes,
 * a hole - in each form, and then every way a map can be wrong.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <ghoti.io/archive/archive.h>
#include <ghoti.io/security/sha256.h>

#include "tar_builder.h"
#include "tar_manifest.h"

using garctest::TarArchive;
using garctest::TarHeader;
using garctest::file_header;
using garctest::pax_header;
using garctest::pax_record;
using garctest::read_fixture;

namespace {

struct Opened {
  std::vector<uint8_t> bytes;
  GARC_Stream * stream = nullptr;
  GARC_Archive * archive = nullptr;

  ~Opened() {
    garc_close(archive);
    garc_stream_destroy(stream);
  }

  GARC_Result open(std::vector<uint8_t> data, const GARC_Limits * limits = nullptr) {
    bytes = std::move(data);
    if (garc_stream_create_memory(bytes.data(), bytes.size(), &stream) != GARC_OK) {
      return GARC_ERR_OOM;
    }
    return garc_open(stream, limits, &archive);
  }
};

/** Read the rest of the current member, seven bytes at a time. */
GARC_Result read_all(GARC_Archive * archive, std::string * out) {
  out->clear();
  char buffer[7]; // across every hole and region boundary below
  for (;;) {
    size_t got = 0;
    GARC_Result result = garc_read_member(archive, buffer, sizeof(buffer), &got);
    if (result != GARC_OK) {
      return result;
    }
    if (!got) {
      return GARC_OK;
    }
    out->append(buffer, got);
  }
}

std::string sha256_hex(const std::string & bytes) {
  unsigned char digest[GSEC_SHA256_DIGEST_LEN];
  if (gsec_sha256(bytes.data(), bytes.size(), digest) != GSEC_OK) {
    return {};
  }
  static const char hex[] = "0123456789abcdef";
  std::string out;
  for (unsigned char byte : digest) {
    out.push_back(hex[byte >> 4]);
    out.push_back(hex[byte & 0x0fu]);
  }
  return out;
}

std::string fixture_path(const std::string & name) {
  return std::string(GARC_TEST_DATA) + "/tar/" + name;
}

/** The one file every hand-built archive holds: "abcde", 5 zeros, "XYZ", 3 zeros. */
const std::string kStored = "abcdeXYZ";
const std::string kReal = std::string("abcde") + std::string(5, '\0') + "XYZ"
    + std::string(3, '\0');

/** A pax `x` header, then a '0' member whose data is @p stored. */
std::vector<uint8_t> pax_sparse(const std::string & records,
    const std::string & stored, char global_or_x = 'x') {
  TarArchive archive;
  archive.header(pax_header(global_or_x, records.size()))
      .data(records)
      .header(file_header("GNUSparseFile.0/f", stored.size()))
      .data(stored)
      .marker();
  return archive.bytes();
}

/** The 1.0 map, as decimal lines padded to a block, ahead of @p stored. */
std::string one_zero_data(const std::vector<std::pair<uint64_t, uint64_t>> & map,
    const std::string & stored) {
  std::string text = std::to_string(map.size()) + "\n";
  for (const auto & region : map) {
    text += std::to_string(region.first) + "\n" + std::to_string(region.second) + "\n";
  }
  text.resize((text.size() + 511) / 512 * 512, '\0');
  return text + stored;
}

/** An old GNU 'S' header with up to four entries, and the blocks after it. */
std::vector<uint8_t> old_sparse(
    const std::vector<std::pair<uint64_t, uint64_t>> & map, uint64_t real,
    const std::string & stored) {
  TarHeader header = file_header("f", stored.size(), 0644u, 'S');
  header.gnu();
  const size_t in_header = map.size() < 4 ? map.size() : 4;
  for (size_t i = 0; i < in_header; ++i) {
    header.octal(386 + i * 24, 12, map[i].first);
    header.octal(386 + i * 24 + 12, 12, map[i].second);
  }
  header.bytes[482] = map.size() > 4 ? 1 : 0;
  header.octal(483, 12, real);
  header.checksum();
  TarArchive archive;
  archive.header(header);
  for (size_t at = 4; at < map.size(); at += 21) {
    TarHeader ext;
    for (size_t i = 0; i < 21 && at + i < map.size(); ++i) {
      ext.octal(i * 24, 12, map[at + i].first);
      ext.octal(i * 24 + 12, 12, map[at + i].second);
    }
    ext.bytes[504] = at + 21 < map.size() ? 1 : 0;
    archive.header(ext);
  }
  archive.data(stored).marker();
  return archive.bytes();
}

const std::vector<std::pair<uint64_t, uint64_t>> kMap = {{0, 5}, {10, 3}, {16, 0}};

/** Open, step to the first member, and say how that went. */
GARC_Result first(Opened & opened, std::vector<uint8_t> bytes,
    const GARC_Limits * limits = nullptr) {
  GARC_Result result = opened.open(std::move(bytes), limits);
  if (result != GARC_OK) {
    return result;
  }
  const GARC_Member * member = nullptr;
  return garc_next(opened.archive, &member);
}

} // namespace

//-----------------------------------------------------------------------------
// GNU tar's archives, against tarfile and bsdtar
//-----------------------------------------------------------------------------

TEST(TarSparse, EveryFixtureMemberReadsAsBothReferencesRead) {
  std::ifstream table(fixture_path("sparse.tsv"));
  ASSERT_TRUE(table.good());
  std::string line;
  int rows = 0;
  while (std::getline(table, line)) {
    if (line.empty() || line[0] == '#') {
      continue;
    }
    std::istringstream fields(line);
    std::string archive_name, index_text, name, real_text, by_tarfile, by_bsdtar;
    std::getline(fields, archive_name, '\t');
    std::getline(fields, index_text, '\t');
    std::getline(fields, name, '\t');
    std::getline(fields, real_text, '\t');
    std::getline(fields, by_tarfile, '\t');
    std::getline(fields, by_bsdtar, '\t');
    SCOPED_TRACE(archive_name + " " + name);
    // The two references agree, or this row is not a statement of anything.
    ASSERT_EQ(by_tarfile, by_bsdtar);

    Opened opened;
    ASSERT_EQ(opened.open(read_fixture(fixture_path(archive_name))), GARC_OK);
    const GARC_Member * member = nullptr;
    for (int i = 0; i <= std::stoi(index_text); ++i) {
      ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
    }
    EXPECT_EQ(std::string(member->name, member->name_length), name);
    EXPECT_EQ(member->type, GARC_MEMBER_FILE);
    EXPECT_TRUE(member->sparse);
    EXPECT_EQ(member->size, std::stoull(real_text));
    EXPECT_LT(member->stored_size, member->size);
    std::string content;
    ASSERT_EQ(read_all(opened.archive, &content), GARC_OK);
    EXPECT_EQ(content.size(), member->size);
    EXPECT_EQ(sha256_hex(content), by_tarfile);
    ++rows;
  }
  // Four layouts in each of four forms. Fewer would mean the table, not the
  // reader, had changed.
  EXPECT_EQ(rows, 16);
}

TEST(TarSparse, AFixtureWalkedWithoutReadingStepsOverEveryMember) {
  for (const char * name : {"gnu-sparse.tar", "pax-sparse-0.0.tar",
           "pax-sparse-0.1.tar", "pax-sparse-1.0.tar"}) {
    SCOPED_TRACE(name);
    Opened opened;
    ASSERT_EQ(opened.open(read_fixture(fixture_path(name))), GARC_OK);
    const GARC_Member * member = nullptr;
    int count = 0;
    GARC_Result result;
    while ((result = garc_next(opened.archive, &member)) == GARC_OK) {
      ++count;
      if (count == 2) {
        // Part of one member, then on: the rest of its regions are skipped.
        char buffer[100];
        size_t got = 0;
        ASSERT_EQ(garc_read_member(opened.archive, buffer, sizeof(buffer), &got),
            GARC_OK);
        EXPECT_GT(got, 0u);
      }
    }
    EXPECT_EQ(result, GARC_END);
    EXPECT_EQ(count, 4);
  }
}

TEST(TarSparse, FindReachesASparseMemberAndReadsIt) {
  Opened opened;
  ASSERT_EQ(opened.open(read_fixture(fixture_path("pax-sparse-1.0.tar"))), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_find(opened.archive, "lead-hole.bin", 13, &member), GARC_OK);
  EXPECT_TRUE(member->sparse);
  std::string content;
  ASSERT_EQ(read_all(opened.archive, &content), GARC_OK);
  EXPECT_EQ(content.size(), 204800u);
  // The first 196608 bytes are hole.
  EXPECT_EQ(content.find_first_not_of('\0'), 196608u);
}

//-----------------------------------------------------------------------------
// One small file, four forms
//-----------------------------------------------------------------------------

TEST(TarSparse, TheSameFileReadsTheSameInEveryForm) {
  struct Form {
    const char * what;
    std::vector<uint8_t> bytes;
  };
  const std::vector<Form> forms = {
      {"old GNU", old_sparse(kMap, 16, kStored)},
      {"pax 0.0",
          pax_sparse(pax_record("GNU.sparse.size", "16")
                  + pax_record("GNU.sparse.numblocks", "3")
                  + pax_record("GNU.sparse.offset", "0")
                  + pax_record("GNU.sparse.numbytes", "5")
                  + pax_record("GNU.sparse.offset", "10")
                  + pax_record("GNU.sparse.numbytes", "3")
                  + pax_record("GNU.sparse.offset", "16")
                  + pax_record("GNU.sparse.numbytes", "0"),
              kStored)},
      {"pax 0.1",
          pax_sparse(pax_record("GNU.sparse.size", "16")
                  + pax_record("GNU.sparse.numblocks", "3")
                  + pax_record("GNU.sparse.name", "real-name")
                  + pax_record("GNU.sparse.map", "0,5,10,3,16,0"),
              kStored)},
      {"pax 1.0",
          pax_sparse(pax_record("GNU.sparse.major", "1")
                  + pax_record("GNU.sparse.minor", "0")
                  + pax_record("GNU.sparse.name", "real-name")
                  + pax_record("GNU.sparse.realsize", "16"),
              one_zero_data(kMap, kStored))},
  };
  for (const Form & form : forms) {
    SCOPED_TRACE(form.what);
    Opened opened;
    ASSERT_EQ(opened.open(form.bytes), GARC_OK);
    const GARC_Member * member = nullptr;
    ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
    EXPECT_TRUE(member->sparse);
    EXPECT_EQ(member->size, 16u);
    EXPECT_EQ(member->stored_size, kStored.size());
    std::string content;
    ASSERT_EQ(read_all(opened.archive, &content), GARC_OK);
    EXPECT_EQ(content, kReal);
    const GARC_Member * next = nullptr;
    EXPECT_EQ(garc_next(opened.archive, &next), GARC_END);
  }
}

TEST(TarSparse, TheRealNameReplacesThePlaceholder) {
  // The header names "GNUSparseFile.0/f", the placeholder a reader that knows
  // nothing of sparse files extracts somewhere harmless.
  Opened opened;
  ASSERT_EQ(opened.open(pax_sparse(pax_record("GNU.sparse.size", "16")
                                  + pax_record("GNU.sparse.name", "real-name")
                                  + pax_record("GNU.sparse.map", "0,5,10,3"),
                kStored)),
      GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_EQ(std::string(member->name, member->name_length), "real-name");
}

TEST(TarSparse, AnOrdinaryMemberIsNotSparseAndStoresItsSize) {
  TarArchive archive;
  archive.header(file_header("plain", 5)).data("hello").marker();
  Opened opened;
  ASSERT_EQ(opened.open(archive.bytes()), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_FALSE(member->sparse);
  EXPECT_EQ(member->stored_size, 5u);
}

//-----------------------------------------------------------------------------
// Maps that are wrong
//-----------------------------------------------------------------------------

TEST(TarSparse, EveryWrongMapIsRefusedAndSaysHow) {
  struct Case {
    const char * what;
    std::vector<uint8_t> bytes;
    GARC_Result expected;
  };
  auto zero_one = [](const std::string & map, const std::string & stored,
                      const std::string & size = "16") {
    return pax_sparse(pax_record("GNU.sparse.size", size)
            + pax_record("GNU.sparse.map", map),
        stored);
  };
  auto one_zero = [](const std::string & data, const std::string & major = "1") {
    return pax_sparse(pax_record("GNU.sparse.major", major)
            + pax_record("GNU.sparse.minor", "0")
            + pax_record("GNU.sparse.realsize", "16"),
        data);
  };
  std::vector<Case> cases = {
      {"regions out of order", zero_one("10,3,0,5", kStored), GARC_ERR_CORRUPT},
      {"regions that overlap", zero_one("0,5,3,3", kStored), GARC_ERR_CORRUPT},
      {"a region past the real size", zero_one("0,5,14,3", kStored),
          GARC_ERR_CORRUPT},
      {"a region whose length overflows", zero_one("1,18446744073709551615", "x"),
          GARC_ERR_CORRUPT},
      {"a map claiming more than is stored", zero_one("0,5,10,4", kStored),
          GARC_ERR_CORRUPT},
      {"a map claiming less than is stored", zero_one("0,5,10,2", kStored),
          GARC_ERR_CORRUPT},
      {"an offset with no length", zero_one("0,5,10", kStored), GARC_ERR_CORRUPT},
      {"a number that is not one", zero_one("0,5,1x,3", kStored), GARC_ERR_CORRUPT},
      {"an empty number", zero_one("0,5,,3", kStored), GARC_ERR_CORRUPT},
      {"no real size", pax_sparse(pax_record("GNU.sparse.map", "0,5,10,3"), kStored),
          GARC_ERR_CORRUPT},
      {"a count that disagrees",
          pax_sparse(pax_record("GNU.sparse.size", "16")
                  + pax_record("GNU.sparse.numblocks", "3")
                  + pax_record("GNU.sparse.map", "0,5,10,3"),
              kStored),
          GARC_ERR_CORRUPT},
      {"a length with no offset in front of it",
          pax_sparse(pax_record("GNU.sparse.size", "16")
                  + pax_record("GNU.sparse.numbytes", "5"),
              kStored),
          GARC_ERR_CORRUPT},
      {"two offsets in a row",
          pax_sparse(pax_record("GNU.sparse.size", "16")
                  + pax_record("GNU.sparse.offset", "0")
                  + pax_record("GNU.sparse.offset", "10"),
              kStored),
          GARC_ERR_CORRUPT},
      {"an offset whose length never came",
          pax_sparse(pax_record("GNU.sparse.size", "16")
                  + pax_record("GNU.sparse.offset", "0"),
              kStored),
          GARC_ERR_CORRUPT},
      {"0.0's pairs and 0.1's map at once",
          pax_sparse(pax_record("GNU.sparse.size", "16")
                  + pax_record("GNU.sparse.offset", "0")
                  + pax_record("GNU.sparse.numbytes", "5")
                  + pax_record("GNU.sparse.map", "10,3"),
              kStored),
          GARC_ERR_CORRUPT},
      {"a 1.0 map that runs past the data", one_zero("2\n0\n5\n"),
          GARC_ERR_CORRUPT},
      {"a 1.0 map with a letter in it",
          one_zero(std::string("2\n0\n5\n1y\n3\n") + std::string(500, '\0') + kStored),
          GARC_ERR_CORRUPT},
      {"a 1.0 map with no newline after a number",
          one_zero(std::string("2\n0 5\n") + std::string(506, '\0') + kStored),
          GARC_ERR_CORRUPT},
      {"a version after 1.0", one_zero(one_zero_data(kMap, kStored), "2"),
          GARC_ERR_UNSUPPORTED},
      {"a sparse record this reader does not know",
          pax_sparse(pax_record("GNU.sparse.size", "16")
                  + pax_record("GNU.sparse.map", "0,5,10,3")
                  + pax_record("GNU.sparse.future", "1"),
              kStored),
          GARC_ERR_UNSUPPORTED},
      {"a sparse map in a global header",
          pax_sparse(pax_record("GNU.sparse.size", "16")
                  + pax_record("GNU.sparse.map", "0,5,10,3"),
              kStored, 'g'),
          GARC_ERR_UNSUPPORTED},
      {"an old header whose map is short of the data",
          old_sparse({{0, 5}}, 16, kStored), GARC_ERR_CORRUPT},
  };
  {
    // An 'S' header that says an extension block follows, and none does.
    std::vector<uint8_t> bytes = old_sparse(kMap, 16, kStored);
    bytes[482] = 1;
    TarHeader again;
    again.bytes.assign(bytes.begin(), bytes.begin() + 512);
    std::memset(again.bytes.data() + 148, ' ', 8);
    again.checksum();
    std::copy(again.bytes.begin(), again.bytes.end(), bytes.begin());
    bytes.resize(512);
    cases.push_back({"an extension block the archive does not have", bytes,
        GARC_ERR_CORRUPT});
  }
  {
    // Both maps for one member.
    TarArchive archive;
    const std::string records = pax_record("GNU.sparse.size", "16")
        + pax_record("GNU.sparse.map", "0,5,10,3");
    archive.header(pax_header('x', records.size())).data(records);
    const std::vector<uint8_t> old = old_sparse(kMap, 16, kStored);
    archive.raw(old);
    cases.push_back({"an old header and pax records at once", archive.bytes(),
        GARC_ERR_CORRUPT});
  }
  for (const Case & one : cases) {
    SCOPED_TRACE(one.what);
    Opened opened;
    EXPECT_EQ(first(opened, one.bytes), one.expected)
        << garc_result_string(first(opened, one.bytes));
  }
}

//-----------------------------------------------------------------------------
// The caps
//-----------------------------------------------------------------------------

/** The bytes of a file of @p size whose runs hold @p fill, and zeros elsewhere. */
std::string sparse_content(uint64_t size,
    const std::vector<GARC_Sparse_Region> & runs, std::string * stored) {
  std::string content(size, '\0');
  stored->clear();
  for (size_t i = 0; i < runs.size(); ++i) {
    for (uint64_t j = 0; j < runs[i].length; ++j) {
      const char byte = static_cast<char>('a' + (i + j) % 26);
      content[runs[i].offset + j] = byte;
      stored->push_back(byte);
    }
  }
  return content;
}

/** A pax tar holding one sparse member, written by this library. */
GARC_Result write_sparse(const std::string & name, uint64_t size,
    const std::vector<GARC_Sparse_Region> & runs, const std::string & stored,
    GARC_Tar_Variant variant, std::string * out) {
  GARC_Sink * sink = nullptr;
  if (garc_sink_create_memory(&sink) != GARC_OK) {
    return GARC_ERR_OOM;
  }
  GARC_Writer_Options options;
  garc_writer_options_default(&options);
  options.tar_variant = variant;
  GARC_Writer * writer = nullptr;
  GARC_Result result = garc_writer_create(sink, GARC_FORMAT_TAR, &options, &writer);
  if (result == GARC_OK) {
    GARC_Member member;
    std::memset(&member, 0, sizeof(member));
    member.name = name.data();
    member.name_length = name.size();
    member.type = GARC_MEMBER_FILE;
    member.size = size;
    member.mode = 0644;
    member.mode_valid = 1;
    static const GARC_Sparse_Region none{0, 0};
    member.sparse_regions = runs.empty() ? &none : runs.data();
    member.sparse_region_count = runs.size();
    result = garc_writer_add(writer, &member);
    if (result == GARC_OK) {
      EXPECT_EQ(garc_writer_data_remaining(writer), stored.size());
      result = garc_writer_write(writer, stored.data(), stored.size());
    }
    if (result == GARC_OK) {
      result = garc_writer_finish(writer);
    }
    const void * data = nullptr;
    size_t length = 0;
    if (result == GARC_OK && garc_sink_data(sink, &data, &length) == GARC_OK) {
      out->assign(static_cast<const char *>(data), length);
    }
    garc_writer_destroy(writer);
  }
  garc_sink_destroy(sink);
  return result;
}

TEST(TarSparse, AWrittenSparseMemberReadsBackAsItsRealContent) {
  // Written as pax sparse 1.0 and read by this library's 1.0 reader, which the
  // fixtures hold to GNU tar's own output. check-writer hands the same shapes
  // to GNU tar, bsdtar and tarfile.
  struct Shape {
    const char * name;
    uint64_t size;
    std::vector<GARC_Sparse_Region> runs;
  };
  const Shape shapes[] = {
      {"dir/many.bin", 300000, {{0, 10}, {4096, 4096}, {100000, 1}, {299990, 10}}},
      {"tail-hole.bin", 1 << 20, {{0, 512}}},
      {"lead-hole.bin", 204800, {{200000, 4800}}},
      {"all-hole.bin", 262144, {}},
      // Closer than a block apart: the writer merges them (GNU tar reads each
      // run as whole blocks), and the merged run's gap is zeros it adds.
      {"close.bin", 10000, {{0, 10}, {100, 10}, {700, 3}, {5000, 3}}},
  };
  for (const Shape & shape : shapes) {
    SCOPED_TRACE(shape.name);
    std::string stored;
    const std::string content = sparse_content(shape.size, shape.runs, &stored);
    std::string tar;
    ASSERT_EQ(GARC_OK, write_sparse(shape.name, shape.size, shape.runs, stored,
                           GARC_TAR_PAX, &tar));
    // The holes are not in the archive: what is, past the caller's bytes, is
    // at most a block of padding per run (see tar_write_sparse_member()).
    const size_t slack = (shape.runs.size() + 1) * 512;
    EXPECT_LT(tar.size(), stored.size() + slack + 8 * 512);
    GARC_Stream * stream = nullptr;
    ASSERT_EQ(GARC_OK, garc_stream_create_memory(tar.data(), tar.size(), &stream));
    GARC_Archive * archive = nullptr;
    ASSERT_EQ(GARC_OK, garc_open(stream, nullptr, &archive));
    const GARC_Member * member = nullptr;
    ASSERT_EQ(GARC_OK, garc_next(archive, &member));
    EXPECT_EQ(std::string(member->name, member->name_length), shape.name);
    EXPECT_TRUE(member->sparse);
    EXPECT_EQ(member->size, shape.size);
    EXPECT_GE(member->stored_size, stored.size());
    EXPECT_LE(member->stored_size, stored.size() + slack);
    std::string got;
    EXPECT_EQ(GARC_OK, read_all(archive, &got));
    EXPECT_TRUE(got == content) << "content differs";
    EXPECT_EQ(GARC_END, garc_next(archive, &member));
    garc_close(archive);
    garc_stream_destroy(stream);
  }
}

TEST(TarSparse, AWrongRunListIsRefusedBeforeAnythingIsWritten) {
  std::string out;
  const std::string bytes(10, 'x');
  // Out of order, overlapping, past the end, and past the end by overflow.
  EXPECT_EQ(GARC_ERR_INVALID,
      write_sparse("f", 100, {{50, 5}, {10, 5}}, bytes, GARC_TAR_PAX, &out));
  EXPECT_EQ(GARC_ERR_INVALID,
      write_sparse("f", 100, {{10, 6}, {15, 4}}, bytes, GARC_TAR_PAX, &out));
  EXPECT_EQ(GARC_ERR_INVALID,
      write_sparse("f", 100, {{95, 10}}, bytes, GARC_TAR_PAX, &out));
  EXPECT_EQ(GARC_ERR_INVALID,
      write_sparse("f", 100, {{UINT64_MAX - 2, 10}}, bytes, GARC_TAR_PAX, &out));
  // ustar has no way to say it, and neither has any format but tar.
  EXPECT_EQ(GARC_ERR_UNSUPPORTED,
      write_sparse("f", 100, {{0, 10}}, bytes, GARC_TAR_USTAR, &out));
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(GARC_OK, garc_sink_create_memory(&sink));
  GARC_Writer * writer = nullptr;
  ASSERT_EQ(GARC_OK, garc_writer_create(sink, GARC_FORMAT_ZIP, nullptr, &writer));
  GARC_Member member;
  std::memset(&member, 0, sizeof(member));
  member.name = "f";
  member.name_length = 1;
  member.type = GARC_MEMBER_FILE;
  member.size = 100;
  const GARC_Sparse_Region run{0, 10};
  member.sparse_regions = &run;
  member.sparse_region_count = 1;
  const uint64_t before = garc_sink_tell(sink);
  EXPECT_EQ(GARC_ERR_UNSUPPORTED, garc_writer_add(writer, &member));
  EXPECT_EQ(before, garc_sink_tell(sink));
  // And the writer goes on: a refusal before a byte is written is clean.
  member.sparse_regions = nullptr;
  member.sparse_region_count = 0;
  member.size = 0;
  EXPECT_EQ(GARC_OK, garc_writer_add(writer, &member));
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
}

TEST(TarSparse, AMemberCopiedFromAReaderIsWrittenWhole) {
  // A reader never sets sparse_regions, so handing its member to a writer
  // writes the real content, as before - copy_member included.
  const std::vector<uint8_t> fixture = read_fixture(
      std::string(GARC_TEST_DATA) + "/tar/pax-sparse-1.0.tar");
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(GARC_OK, garc_stream_create_memory(fixture.data(), fixture.size(), &stream));
  GARC_Archive * archive = nullptr;
  ASSERT_EQ(GARC_OK, garc_open(stream, nullptr, &archive));
  const GARC_Member * member = nullptr;
  ASSERT_EQ(GARC_OK, garc_next(archive, &member));
  EXPECT_TRUE(member->sparse);
  EXPECT_EQ(member->sparse_regions, nullptr);
  garc_close(archive);
  garc_stream_destroy(stream);
}

TEST(TarSparse, TheRealSizeIsWhatTheMemberCapIsAgainst) {
  // A sparse member is a decompression bomb by construction: eight stored
  // bytes and an exabyte of hole. The cap is on what a reader would hand out.
  GARC_Limits limits;
  garc_limits_default(&limits);
  limits.max_member_bytes = 1000;
  Opened small;
  EXPECT_EQ(first(small, pax_sparse(pax_record("GNU.sparse.size", "16")
                                  + pax_record("GNU.sparse.map", "0,5,10,3"),
                              kStored),
                &limits),
      GARC_OK);
  Opened huge;
  EXPECT_EQ(first(huge, pax_sparse(pax_record("GNU.sparse.size", "1000000000000000000")
                                 + pax_record("GNU.sparse.map", "0,5,10,3"),
                             kStored),
                &limits),
      GARC_ERR_LIMIT_MEMBER_BYTES);
}

TEST(TarSparse, TheMapIsHeldWithinTheExtraBytesCap) {
  GARC_Limits limits;
  garc_limits_default(&limits);
  limits.max_extra_bytes = 4096;
  // 300 regions are 4800 bytes to hold, past the cap in every form.
  std::string map;
  std::vector<std::pair<uint64_t, uint64_t>> regions;
  std::string records00 = pax_record("GNU.sparse.size", "600");
  for (int i = 0; i < 300; ++i) {
    map += (i ? "," : "") + std::to_string(i * 2) + ",1";
    regions.push_back({static_cast<uint64_t>(i * 2), 1});
    records00 += pax_record("GNU.sparse.offset", std::to_string(i * 2))
        + pax_record("GNU.sparse.numbytes", "1");
  }
  const std::string stored(300, 's');
  {
    Opened opened;
    EXPECT_EQ(first(opened, pax_sparse(records00, stored), &limits),
        GARC_ERR_LIMIT_EXTRA_BYTES);
  }
  {
    Opened opened;
    EXPECT_EQ(first(opened, pax_sparse(pax_record("GNU.sparse.size", "600")
                                     + pax_record("GNU.sparse.map", map),
                                 stored),
                  &limits),
        GARC_ERR_LIMIT_EXTRA_BYTES);
  }
  {
    Opened opened;
    EXPECT_EQ(first(opened, pax_sparse(pax_record("GNU.sparse.major", "1")
                                     + pax_record("GNU.sparse.minor", "0")
                                     + pax_record("GNU.sparse.realsize", "600"),
                                 one_zero_data(regions, stored)),
                  &limits),
        GARC_ERR_LIMIT_EXTRA_BYTES);
  }
  {
    Opened opened;
    EXPECT_EQ(first(opened, old_sparse(regions, 600, stored), &limits),
        GARC_ERR_LIMIT_EXTRA_BYTES);
  }
  // The control: the same archives with the default cap read.
  {
    Opened opened;
    EXPECT_EQ(first(opened, old_sparse(regions, 600, stored)), GARC_OK);
    std::string content;
    ASSERT_EQ(read_all(opened.archive, &content), GARC_OK);
    EXPECT_EQ(content.size(), 600u);
    EXPECT_EQ(content.substr(0, 4), std::string("s\0s\0", 4));
  }
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
