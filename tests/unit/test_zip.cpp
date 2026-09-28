/**
 * @file
 *
 * Reading zip, against what four references say the fixtures contain.
 *
 * The fixtures are written by Info-ZIP 3.0, libarchive 3.7.4, 7-Zip 25.01 and
 * Python 3.13.5's `zipfile` in the pinned container, and the expectations come
 * from two of those reading them back plus all four saying whether they would
 * open the archive at all. A passing row here is independent implementations
 * agreeing rather than this library agreeing with itself.
 *
 * **Where the references disagree with each other, this file says which one is
 * being believed and why.** Two fixtures are refused by references that read the
 * other one, and this library reads both - see
 * `ReadsTheArchivesSomeReferencesRefuse`, which asserts against the recorded
 * verdicts rather than around them.
 *
 * **A missing corpus fails these tests rather than skipping them.** The fixtures
 * are committed, so their absence is a broken checkout; a skip would make a clone
 * with no `tests/data/` look exactly like a clone that passes.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstring>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "test_helpers.h"
#include "zip_manifest.h"

using garctest::BufferSource;
using garctest::ZipManifestRow;
using garctest::ZipNameRow;
using garctest::ZipOpeningRow;
using garctest::read_fixture;
using garctest::zip_manifest_load;
using garctest::zip_names_load;
using garctest::zip_openings_load;

namespace {

std::string data_path(const std::string & name) {
  return std::string(GARC_TEST_DATA) + "/zip/" + name;
}

/** Python's zipfile's reading of every member of every fixture it can open. */
const std::map<std::string, std::vector<ZipManifestRow>> & manifest() {
  static const std::map<std::string, std::vector<ZipManifestRow>> rows
      = zip_manifest_load(data_path("manifest.tsv"));
  return rows;
}

/** bsdtar's type, mode and link target for every member. */
const std::map<std::string, std::vector<ZipNameRow>> & names() {
  static const std::map<std::string, std::vector<ZipNameRow>> rows
      = zip_names_load(data_path("names.tsv"));
  return rows;
}

/** What each of four references does when handed each archive. */
const std::vector<ZipOpeningRow> & openings() {
  static const std::vector<ZipOpeningRow> rows
      = zip_openings_load(data_path("openings.tsv"));
  return rows;
}

/**
 * The name Python read for a member, or an empty result when it read none.
 *
 * Python's `zipfile` reports the name as the archive holds it, which is what makes
 * it the reference for bytes. It is used below to tell a member whose name
 * libarchive *translated* from one it merely read.
 */
std::pair<bool, std::string> python_name(
    const std::string & archive, size_t index) {
  const auto found = manifest().find(archive);
  if (found == manifest().end() || index >= found->second.size()) {
    return {false, std::string()};
  }
  return {true, found->second[index].name};
}

std::string member_name(const GARC_Member * member) {
  return std::string(member->name, member->name_length);
}

std::string member_link(const GARC_Member * member) {
  return member->link_target
      ? std::string(member->link_target, member->link_target_length)
      : std::string();
}

/** This library's type name, in the vocabulary names.tsv uses. */
std::string type_name(GARC_Member_Type type) {
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

/** An open archive over a fixture, with the stream kept alive beside it. */
class Fixture {
public:
  explicit Fixture(const std::string & name, const GARC_Limits * limits = nullptr,
      bool can_seek = true, bool knows_size = true)
      : bytes_(read_fixture(data_path(name))),
        source_(bytes_.data(), bytes_.size(), can_seek, knows_size) {
    if (garc_stream_create_callback(source_.callbacks(), &stream_) != GARC_OK) {
      stream_ = nullptr;
      return;
    }
    open_result_ = garc_open(stream_, limits, &archive_);
  }

  ~Fixture() {
    garc_close(archive_);
    garc_stream_destroy(stream_);
  }

  Fixture(const Fixture &) = delete;
  Fixture & operator=(const Fixture &) = delete;

  GARC_Result open_result() const { return open_result_; }
  GARC_Archive * archive() const { return archive_; }
  size_t size() const { return bytes_.size(); }
  const std::vector<uint8_t> & bytes() const { return bytes_; }

private:
  std::vector<uint8_t> bytes_;
  BufferSource source_;
  GARC_Stream * stream_ = nullptr;
  GARC_Archive * archive_ = nullptr;
  GARC_Result open_result_ = GARC_ERR_INTERNAL;
};

/** Read a member's whole data, which for a stored member is its contents. */
std::string read_all(GARC_Archive * archive) {
  std::string out;
  char buffer[512];
  size_t got = 0;
  while (garc_read_member(archive, buffer, sizeof(buffer), &got) == GARC_OK
      && got) {
    out.append(buffer, got);
  }
  return out;
}

//-----------------------------------------------------------------------------
// The corpus, member by member
//-----------------------------------------------------------------------------

TEST(ZipCorpus, TheManifestIsNotEmpty) {
  // The denominator. Every test below iterates the manifest, so an unreadable or
  // truncated manifest would make all of them pass while asking nothing - which
  // is the shape a corpus-driven suite fails in silently.
  ASSERT_FALSE(manifest().empty()) << "no manifest at " << data_path("manifest.tsv");
  size_t rows = 0;
  for (const auto & entry : manifest()) {
    rows += entry.second.size();
  }
  EXPECT_EQ(rows, 75u) << "the manifest has moved; check-zip-corpus says whether "
                          "the references or the generator changed";
  // 25 of the 29 fixtures appear. Python refuses three - the EOCD decoy pair, and
  // mal-utf8-lie.zip, whose names claim UTF-8 and are not - and python-empty.zip
  // has no members to describe, so it contributes no rows and therefore no key.
  // Spelled out because "25" on its own would be a number nobody could check.
  EXPECT_EQ(manifest().size(), 25u);
}

TEST(ZipCorpus, EveryMemberAgreesWithPythonsZipfile) {
  size_t compared = 0;
  for (const auto & entry : manifest()) {
    const std::string & name = entry.first;
    const std::vector<ZipManifestRow> & rows = entry.second;
    Fixture fixture(name);
    ASSERT_EQ(fixture.open_result(), GARC_OK) << name;
    ASSERT_EQ(garc_format(fixture.archive()), GARC_FORMAT_ZIP) << name;

    const GARC_Member * member = nullptr;
    size_t index = 0;
    GARC_Result result;
    while ((result = garc_next(fixture.archive(), &member)) == GARC_OK) {
      ASSERT_LT(index, rows.size()) << name << ": more members than the manifest";
      const ZipManifestRow & row = rows[index];
      const std::string where = name + " member " + std::to_string(index);

      EXPECT_EQ(member_name(member), row.name) << where;
      EXPECT_EQ(member->size, row.size) << where;
      EXPECT_EQ(garc_zip_member_compressed_size(fixture.archive()),
          row.compressed_size) << where;
      EXPECT_EQ(garc_zip_member_method(fixture.archive()), row.method) << where;
      EXPECT_EQ(garc_zip_member_crc32(fixture.archive()), row.crc) << where;
      EXPECT_EQ(garc_zip_member_flags(fixture.archive()), row.flags) << where;
      EXPECT_EQ(member->name_encoding,
          row.utf8 ? GARC_NAME_UTF8 : GARC_NAME_UNDECLARED) << where;
      EXPECT_EQ(garc_zip_member_version_made_by(fixture.archive()) >> 8,
          row.create_system) << where;
      EXPECT_EQ(member->header_offset, row.header_offset) << where;
      EXPECT_EQ(garc_zip_member_extra_length(fixture.archive()),
          row.extra_length()) << where;

      // The mode is valid exactly when the writer put something in the high half
      // of external_file_attributes. Python's zipfile writes a bare permission
      // mask with no S_IFMT bits, which is a real thing writers do and must not
      // read as "no mode".
      if (row.mode) {
        EXPECT_TRUE(member->mode_valid) << where;
        EXPECT_EQ(member->mode, row.mode) << where;
      }
      else {
        EXPECT_FALSE(member->mode_valid) << where;
      }

      // **Every fixture's mtime is the same even second**, so the DOS field and
      // the extended fields agree exactly and one expectation covers all three
      // sources. That is a property of the corpus (see MTIME in the generator),
      // and it is what makes this comparison possible without re-implementing
      // three conversions here.
      EXPECT_EQ(member->mtime_seconds, row.dos_epoch()) << where
          << " (source " << garc_time_source_string(member->mtime_source) << ")";

      ++index;
      ++compared;
    }
    EXPECT_EQ(result, GARC_END) << name;
    EXPECT_EQ(index, rows.size()) << name << ": fewer members than the manifest";
  }
  EXPECT_EQ(compared, 75u);
}

TEST(ZipCorpus, EveryTypeAndLinkAgreesWithLibarchive) {
  size_t compared = 0;
  size_t symlinks = 0;
  size_t directories = 0;
  size_t named = 0;
  size_t renamed = 0;
  for (const auto & entry : names()) {
    const std::string & name = entry.first;
    const std::vector<ZipNameRow> & rows = entry.second;
    Fixture fixture(name);
    ASSERT_EQ(fixture.open_result(), GARC_OK) << name;

    const GARC_Member * member = nullptr;
    size_t index = 0;
    while (garc_next(fixture.archive(), &member) == GARC_OK) {
      ASSERT_LT(index, rows.size()) << name;
      const ZipNameRow & row = rows[index];
      const std::string where = name + " member " + std::to_string(index);
      // **libarchive's name column is a name it decided, not one it read.** For a
      // zip member it translates backslashes to slashes and reports a decomposed
      // name in composed form, so for five members of the malicious fixtures its
      // name is not the archive's bytes. Python's is, so where the two references
      // disagree the reader is held to Python's and the disagreement is counted -
      // which is not the same as excusing it: a translation this test did not know
      // about would move the count.
      const std::pair<bool, std::string> theirs = python_name(name, index);
      if (!theirs.first || theirs.second == row.name) {
        EXPECT_EQ(member_name(member), row.name) << where;
        ++named;
      }
      else {
        EXPECT_EQ(member_name(member), theirs.second)
            << where << ": the two references disagree about this name and we "
               "match neither";
        ++renamed;
      }
      EXPECT_EQ(type_name(member->type), row.type) << where;
      // A symlink's target is the member's *data* in zip, so agreeing with
      // libarchive here means having read the data during the walk.
      EXPECT_EQ(member_link(member), row.link) << where;
      if (row.type == "symlink") {
        ++symlinks;
      }
      if (row.type == "directory") {
        ++directories;
      }
      ++index;
      ++compared;
    }
    EXPECT_EQ(index, rows.size()) << name;
  }
  EXPECT_EQ(compared, 79u);
  // The corpus has to contain the types this comparison is about, or it would
  // pass by having nothing to disagree over.
  EXPECT_GE(symlinks, 1u);
  EXPECT_GE(directories, 2u);
  EXPECT_EQ(named, 74u);
  // And the conditional above has to be seen to take both arms, or a bug in it
  // would make the name comparison silently vacuous. Five: one decomposed name,
  // two backslash traversals, a drive letter and a UNC path.
  EXPECT_EQ(renamed, 5u)
      << "the two references no longer disagree about the five names they did, or "
         "the condition that finds the disagreement has stopped working";
}

TEST(ZipCorpus, EverySourceOfTimeIsRepresented) {
  // Three fields can carry an mtime and this library prefers the most precise.
  // If the corpus had only one of them, the preference would be untested and the
  // comparison above would pass on a reader that ignored the other two.
  std::set<GARC_Time_Source> seen;
  for (const auto & entry : manifest()) {
    Fixture fixture(entry.first);
    ASSERT_EQ(fixture.open_result(), GARC_OK) << entry.first;
    const GARC_Member * member = nullptr;
    while (garc_next(fixture.archive(), &member) == GARC_OK) {
      seen.insert(member->mtime_source);
    }
  }
  EXPECT_EQ(seen.count(GARC_TIME_ZIP_DOS), 1u) << "no member with only a DOS time";
  EXPECT_EQ(seen.count(GARC_TIME_ZIP_UNIX), 1u) << "no 0x5455 extended timestamp";
  EXPECT_EQ(seen.count(GARC_TIME_ZIP_NTFS), 1u) << "no 0x000a NTFS timestamp";
}

TEST(ZipCorpus, ReadsTheArchivesSomeReferencesRefuse) {
  // **The disagreement, asserted rather than assumed.** openings.tsv records what
  // four references do with each fixture; this checks that the recorded refusals
  // are still there - so the claim "we read what they refuse" cannot quietly
  // become "nobody refuses anything" - and that this library opens all 23.
  std::map<std::string, size_t> refusals;
  std::set<std::string> archives;
  for (const ZipOpeningRow & row : openings()) {
    archives.insert(row.archive);
    if (row.refused()) {
      refusals[row.archive]++;
    }
  }
  ASSERT_EQ(archives.size(), 29u) << "openings.tsv does not cover the corpus";

  // The two the corpus exists to record. Spelled out rather than counted, because
  // a count would still pass if the refusals moved to different archives.
  EXPECT_GE(refusals["python-comments.zip"], 1u)
      << "no reference refuses the EOCD decoy any more";
  EXPECT_GE(refusals["python-eocd-decoy.zip"], 2u)
      << "the 22-byte decoy is no longer refused by two references";
  EXPECT_GE(refusals["python-prologue.zip"], 2u)
      << "the self-extracting stub is no longer refused by two references";

  for (const std::string & name : archives) {
    Fixture fixture(name);
    EXPECT_EQ(fixture.open_result(), GARC_OK) << name << " should open here";
    EXPECT_EQ(garc_format(fixture.archive()), GARC_FORMAT_ZIP) << name;
  }
}

//-----------------------------------------------------------------------------
// The structure: what the end record and the central directory settle
//-----------------------------------------------------------------------------

TEST(Zip, TheBaseOffsetIsZeroForAnOrdinaryArchive) {
  Fixture fixture("infozip-stored.zip");
  ASSERT_EQ(fixture.open_result(), GARC_OK);
  EXPECT_EQ(garc_zip_base_offset(fixture.archive()), 0u);
  EXPECT_EQ(garc_zip_declared_members(fixture.archive()), 4u);
}

TEST(Zip, TheBaseOffsetIsTheStubInFrontOfTheArchive) {
  // python-prologue.zip is python-names.zip behind a 40-byte shell stub, so every
  // offset in its central directory is short by exactly that. 7-Zip refuses this
  // archive outright and unzip warns about it; libarchive and this library read
  // it, which is what the base offset is for.
  Fixture fixture("python-prologue.zip");
  ASSERT_EQ(fixture.open_result(), GARC_OK);
  EXPECT_EQ(garc_zip_base_offset(fixture.archive()), 40u);

  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(fixture.archive(), &member), GARC_OK);
  EXPECT_EQ(member_name(member), "na\xc3\xafve.txt");
  // The header offset is absolute: the stub is in front of it.
  EXPECT_GE(member->header_offset, 40u);
  EXPECT_EQ(read_all(fixture.archive()), "a non-ASCII name\n");
}

TEST(Zip, AnEmptyArchiveIsTwentyTwoBytesAndNoMembers) {
  Fixture fixture("python-empty.zip");
  ASSERT_EQ(fixture.open_result(), GARC_OK);
  EXPECT_EQ(fixture.size(), 22u);
  EXPECT_EQ(garc_zip_declared_members(fixture.archive()), 0u);
  const GARC_Member * member = nullptr;
  EXPECT_EQ(garc_next(fixture.archive(), &member), GARC_END);
  // unzip calls this a warning and exits 1. Zero members is not an error here,
  // for the same reason an empty tar is not: the archive says what it holds.
}

TEST(Zip, AnArchiveCommentIsReportedAsBytes) {
  Fixture fixture("python-comments.zip");
  ASSERT_EQ(fixture.open_result(), GARC_OK);
  size_t length = 0;
  const char * comment = garc_zip_archive_comment(fixture.archive(), &length);
  ASSERT_NE(comment, nullptr);
  const std::string text(comment, length);
  // The comment contains an end-of-central-directory signature, which is the
  // whole point of the fixture: Python's zipfile cannot open this archive.
  EXPECT_NE(text.find(std::string("PK\x05\x06", 4)), std::string::npos);
}

TEST(Zip, TheLongestPossibleCommentIsRead) {
  // 65,535 bytes, which is the largest the length field can describe and
  // therefore the bound the backwards scan is written against.
  Fixture fixture("python-maxcomment.zip");
  ASSERT_EQ(fixture.open_result(), GARC_OK);
  size_t length = 0;
  ASSERT_NE(garc_zip_archive_comment(fixture.archive(), &length), nullptr);
  EXPECT_EQ(length, 65535u);
}

TEST(Zip, TheDecoyPairIsBothRead) {
  // One byte count apart: 10 bytes behind the decoy in one and 22 in the other.
  // unzip reads the first and refuses the second; this library reads both,
  // because the scan validates the record it finds rather than trusting the last
  // signature in the tail.
  for (const char * name : {"python-comments.zip", "python-eocd-decoy.zip"}) {
    Fixture fixture(name);
    ASSERT_EQ(fixture.open_result(), GARC_OK) << name;
    EXPECT_EQ(garc_zip_declared_members(fixture.archive()), 2u) << name;
    const GARC_Member * member = nullptr;
    ASSERT_EQ(garc_next(fixture.archive(), &member), GARC_OK) << name;
    EXPECT_EQ(member_name(member), "hello.txt") << name;
  }
}

TEST(Zip, ASignatureInsideMemberDataIsNotTheEndRecord) {
  // The control: a member whose *contents* are a plausible central directory
  // header and end record. Every reference reads this archive, so a reader this
  // fixture breaks is broken by its own scan.
  Fixture fixture("python-data-decoy.zip");
  ASSERT_EQ(fixture.open_result(), GARC_OK);
  EXPECT_EQ(garc_zip_declared_members(fixture.archive()), 3u);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(fixture.archive(), &member), GARC_OK);
  EXPECT_EQ(member_name(member), "innocent.txt");
  ASSERT_EQ(garc_next(fixture.archive(), &member), GARC_OK);
  EXPECT_EQ(member_name(member), "decoy-inside.bin");
  const std::string data = read_all(fixture.archive());
  EXPECT_EQ(data.compare(0, 4, "PK\x01\x02", 4), 0);
  ASSERT_EQ(garc_next(fixture.archive(), &member), GARC_OK);
  EXPECT_EQ(member_name(member), "after.txt");
}

TEST(Zip, ZipSixtyFourFieldsArePresentOnlyForTheFieldsThatOverflowed) {
  // **`zip -fz` produces the discriminating layout.** Its central directory says
  // the uncompressed size is 0xFFFFFFFF and gives the compressed size as an
  // ordinary 15, so the 0x0001 extra field carries **one** 8-byte value rather
  // than two. A reader that consumed the zip64 values positionally - or that
  // assumed a 16-byte field - would read this member's size out of the wrong
  // eight bytes, and no archive where both fields overflowed would show it.
  Fixture forced("infozip-zip64.zip");
  ASSERT_EQ(forced.open_result(), GARC_OK);
  EXPECT_TRUE(garc_zip_has_zip64_end_record(forced.archive()));
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(forced.archive(), &member), GARC_OK);
  EXPECT_TRUE(garc_zip_member_used_zip64(forced.archive()));
  EXPECT_EQ(garc_zip_member_extra_length(forced.archive()), 12u)
      << "one 8-byte value and its 4-byte header";
  EXPECT_EQ(member->size, 15u);
  EXPECT_EQ(garc_zip_member_compressed_size(forced.archive()), 15u);
  EXPECT_EQ(read_all(forced.archive()), "hello, archive\n");
}

TEST(Zip, AZipSixtyFourLocalHeaderIsIgnoredWhenTheDirectoryDoesNotNeedOne) {
  // Python's `force_zip64` writes the zip64 extra field into the **local header
  // only**: that header says both sizes are 0xFFFFFFFF, and the central directory
  // gives them as 28 with no extra field at all. So this archive is the one that
  // punishes a reader for believing the local header - it would report a member
  // of 4,294,967,295 bytes - and the one that shows the archive-level and
  // member-level zip64 questions are separate, since there is no zip64 end record
  // here either.
  Fixture fixture("python-zip64.zip");
  ASSERT_EQ(fixture.open_result(), GARC_OK);
  EXPECT_FALSE(garc_zip_has_zip64_end_record(fixture.archive()));
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(fixture.archive(), &member), GARC_OK);
  EXPECT_FALSE(garc_zip_member_used_zip64(fixture.archive()))
      << "the central directory needed no zip64 value, so none was taken";
  EXPECT_EQ(member->size, 28u);
  EXPECT_EQ(read_all(fixture.archive()), "zip64 by force, not by size\n");

  // And the local header really does say 0xFFFFFFFF, which is what makes the
  // assertion above about this library rather than about the archive.
  const std::vector<uint8_t> & bytes = fixture.bytes();
  ASSERT_GE(bytes.size(), 30u);
  for (size_t at = 18; at < 26; ++at) {
    EXPECT_EQ(bytes[at], 0xFFu) << "local header size field byte " << at;
  }
}

TEST(Zip, TheSizesComeFromTheCentralDirectoryAndNotTheLocalHeader) {
  // **The rule the format is read by.** libarchive writes a data descriptor for
  // every member with data, so this archive's local headers all say a size of
  // zero and its central directory says the truth. A reader that believed the
  // local header would report every member as empty and would still "work".
  Fixture fixture("bsdtar-descriptors.zip");
  ASSERT_EQ(fixture.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(fixture.archive(), &member), GARC_OK);
  EXPECT_EQ(member_name(member), "hello.txt");
  EXPECT_EQ(member->size, 15u);
  EXPECT_NE(garc_zip_member_flags(fixture.archive()) & 0x0008u, 0u)
      << "the fixture is supposed to use data descriptors";

  // And the bytes in the local header really are zero, which is what makes the
  // assertion above about this library rather than about the archive.
  const std::vector<uint8_t> & bytes = fixture.bytes();
  ASSERT_GE(bytes.size(), 30u);
  for (size_t at = 18; at < 26; ++at) {
    EXPECT_EQ(bytes[at], 0u) << "local header size field byte " << at;
  }
}

//-----------------------------------------------------------------------------
// Methods and encryption: what is refused, and how the refusal names itself
//-----------------------------------------------------------------------------

TEST(Zip, StoredAndDeflatedMembersReadTheSameBytes) {
  // **Four writers' deflate against one reader, with a free oracle.** Every
  // member of python-methods.zip is the same 1,160 bytes under a different
  // method, so the stored member is what the deflated one has to equal - no
  // expectation written here, just two members of the corpus that must agree.
  // A decoder that dropped a block or ended early fails this without anyone
  // having to say what the content was.
  Fixture fixture("python-methods.zip");
  ASSERT_EQ(fixture.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  std::string stored;
  std::string deflated;
  size_t refused = 0;
  while (garc_next(fixture.archive(), &member) == GARC_OK) {
    const uint16_t method = garc_zip_member_method(fixture.archive());
    const std::string name = member_name(member);
    if (method == GARC_ZIP_METHOD_STORED) {
      stored = read_all(fixture.archive());
    }
    else if (method == GARC_ZIP_METHOD_DEFLATE) {
      deflated = read_all(fixture.archive());
    }
    else {
      char buffer[64];
      size_t got = 0;
      EXPECT_EQ(garc_read_member(fixture.archive(), buffer, sizeof(buffer), &got),
          GARC_ERR_UNSUPPORTED) << name;
      ++refused;
    }
  }
  EXPECT_EQ(deflated.size(), 1160u);
  EXPECT_EQ(deflated, stored);
  EXPECT_EQ(refused, 2u) << "bzip2 and lzma have no codec here";
}

TEST(ZipCorpus, EveryDeflatedMemberInTheCorpusReadsAndItsCrcVerifies) {
  // **Every deflated member of every fixture, from four writers.** The CRC is
  // declared in the archive by the writer, so a member that reads cleanly to the
  // end is one where this reader and that writer agree about all of its bytes -
  // which is a stronger statement than any expectation written here could be, and
  // the only one that scales to the whole corpus.
  size_t deflated = 0;
  size_t stored = 0;
  size_t unsupported = 0;
  for (const auto & entry : manifest()) {
    Fixture fixture(entry.first);
    ASSERT_EQ(fixture.open_result(), GARC_OK) << entry.first;
    const GARC_Member * member = nullptr;
    while (garc_next(fixture.archive(), &member) == GARC_OK) {
      const std::string where = entry.first + " " + member_name(member);
      char buffer[512];
      size_t got = 0;
      uint64_t total = 0;
      GARC_Result result;
      while ((result = garc_read_member(fixture.archive(), buffer,
                  sizeof(buffer), &got))
              == GARC_OK
          && got) {
        total += got;
      }
      if (result == GARC_ERR_UNSUPPORTED) {
        ++unsupported;
        continue;
      }
      // GARC_OK here is both "the bytes were all there" and "the CRC the writer
      // declared is the CRC of what came out".
      EXPECT_EQ(result, GARC_OK) << where << ": " << garc_result_string(result);
      EXPECT_EQ(total, member->size) << where;
      if (garc_zip_member_method(fixture.archive()) == GARC_ZIP_METHOD_DEFLATE) {
        ++deflated;
      }
      else {
        ++stored;
      }
    }
  }
  // The denominator, so a corpus that stopped containing deflated members would
  // fail here rather than passing with nothing to decompress.
  EXPECT_GE(deflated, 4u);
  EXPECT_GE(stored, 20u);
  EXPECT_GE(unsupported, 5u) << "bzip2, lzma, ppmd, deflate64, AES, ZipCrypto";
}

TEST(Zip, EveryCodecGatedMethodRefusesWithItsNumber) {
  // One fixture per method, each written by 7-Zip or Python, so the refusal is
  // measured against an archive that really contains the method rather than
  // against a hand-set field.
  const struct {
    const char * fixture;
    uint16_t method;
    const char * name;
  } cases[] = {
    // Method 9 is the one worth naming: "enhanced deflate" is *not* RFC 1951 - a
    // 64 KB window and a different length code - so pointing it at the deflate
    // decoder would produce plausible wrong bytes for the members that use the
    // extensions and correct ones for the members that do not.
    {"sevenzip-deflate64.zip", GARC_ZIP_METHOD_DEFLATE64,
        "enhanced deflate (deflate64)"},
    {"sevenzip-methods.zip", GARC_ZIP_METHOD_BZIP2, "bzip2"},
    {"sevenzip-lzma.zip", GARC_ZIP_METHOD_LZMA, "lzma"},
    {"sevenzip-ppmd.zip", GARC_ZIP_METHOD_PPMD, "ppmd"},
  };
  for (const auto & one : cases) {
    Fixture fixture(one.fixture);
    ASSERT_EQ(fixture.open_result(), GARC_OK) << one.fixture;
    const GARC_Member * member = nullptr;
    ASSERT_EQ(garc_next(fixture.archive(), &member), GARC_OK) << one.fixture;
    EXPECT_EQ(garc_zip_member_method(fixture.archive()), one.method)
        << one.fixture;
    EXPECT_STREQ(garc_zip_method_string(one.method), one.name);
    char buffer[16];
    size_t got = 0;
    EXPECT_EQ(garc_read_member(fixture.archive(), buffer, sizeof(buffer), &got),
        GARC_ERR_UNSUPPORTED) << one.fixture;
    // The metadata is still right, which is what makes the refusal a to-do list:
    // an archive with one bzip2 member is still an archive to walk.
    EXPECT_EQ(member->size, 1160u) << one.fixture;
  }
}

TEST(Zip, AMemberWithAnUnreadableMethodCanStillBeSkipped) {
  // The walk does not stop at a member it cannot decompress. Python's methods
  // fixture has stored, deflate, bzip2 and lzma in that order, and all four
  // members have to be reported.
  Fixture fixture("python-methods.zip");
  ASSERT_EQ(fixture.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  std::vector<uint16_t> methods;
  while (garc_next(fixture.archive(), &member) == GARC_OK) {
    methods.push_back(garc_zip_member_method(fixture.archive()));
  }
  EXPECT_EQ(methods,
      std::vector<uint16_t>({GARC_ZIP_METHOD_STORED, GARC_ZIP_METHOD_DEFLATE,
          GARC_ZIP_METHOD_BZIP2, GARC_ZIP_METHOD_LZMA}));
}

TEST(Zip, ZipCryptoIsNamedRatherThanCalledUnsupported) {
  Fixture fixture("infozip-crypto.zip");
  ASSERT_EQ(fixture.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(fixture.archive(), &member), GARC_OK);
  EXPECT_EQ(garc_zip_member_encryption(fixture.archive()),
      GARC_ZIP_ENCRYPTION_ZIPCRYPTO);
  EXPECT_STREQ(garc_zip_encryption_string(GARC_ZIP_ENCRYPTION_ZIPCRYPTO),
      "ZipCrypto (broken)");
  // The metadata is in the clear, which is true of zip at every password
  // strength and worth a test rather than a sentence: the name and the size are
  // readable without the password.
  EXPECT_EQ(member_name(member), "hello.txt");
  EXPECT_EQ(member->size, 15u);
  // 12 bytes of encryption header in front of the data, which is why the
  // compressed size exceeds the uncompressed one for a stored member.
  EXPECT_EQ(garc_zip_member_compressed_size(fixture.archive()), 27u);
  char buffer[16];
  size_t got = 0;
  EXPECT_EQ(garc_read_member(fixture.archive(), buffer, sizeof(buffer), &got),
      GARC_ERR_UNSUPPORTED);
}

TEST(Zip, WinZipAesIsNamedAndItsRealMethodIsNotLost) {
  Fixture fixture("sevenzip-aes.zip");
  ASSERT_EQ(fixture.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(fixture.archive(), &member), GARC_OK);
  EXPECT_EQ(garc_zip_member_method(fixture.archive()), GARC_ZIP_METHOD_AES);
  EXPECT_EQ(garc_zip_member_encryption(fixture.archive()),
      GARC_ZIP_ENCRYPTION_AES);
  EXPECT_STREQ(garc_zip_method_string(GARC_ZIP_METHOD_AES), "WinZip AES");
  // unzip 6.00 refuses this member too, with "need PK compat. v5.1", so the
  // refusal is the format's age rather than this library being conservative.
  char buffer[16];
  size_t got = 0;
  EXPECT_EQ(garc_read_member(fixture.archive(), buffer, sizeof(buffer), &got),
      GARC_ERR_UNSUPPORTED);
}

//-----------------------------------------------------------------------------
// Unix metadata, which is only meaningful when the host byte says so
//-----------------------------------------------------------------------------

TEST(Zip, ModesAndSymlinksComeFromTheUnixHalfOfTheAttributes) {
  Fixture fixture("infozip-unix.zip");
  ASSERT_EQ(fixture.open_result(), GARC_OK);
  std::map<std::string, const GARC_Member *> found;
  std::map<std::string, uint32_t> modes;
  std::map<std::string, GARC_Member_Type> types;
  std::map<std::string, std::string> links;
  const GARC_Member * member = nullptr;
  while (garc_next(fixture.archive(), &member) == GARC_OK) {
    const std::string name = member_name(member);
    modes[name] = member->mode_valid ? member->mode : 0u;
    types[name] = member->type;
    links[name] = member_link(member);
  }
  EXPECT_EQ(types["emptydir/"], GARC_MEMBER_DIRECTORY);
  EXPECT_EQ(types["link-to-hello"], GARC_MEMBER_SYMLINK);
  EXPECT_EQ(links["link-to-hello"], "hello.txt");
  EXPECT_EQ(modes["modes/executable"] & 07777u, 0755u);
  // The setuid bit is reported rather than masked. Masking it on the way in would
  // make "extraction must not honour one by default" untestable later.
  EXPECT_EQ(modes["modes/setuid"] & 07777u, 04755u);
}

TEST(Zip, UidAndGidComeFromTheUnixExtraFieldWhenThereIsOne) {
  // Info-ZIP writes 0x7875 by default, and `-X` turns it off - so the pair of
  // fixtures is what separates "this reader parses the field" from "this reader
  // reports whatever it has".
  Fixture with("infozip-extras.zip");
  ASSERT_EQ(with.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(with.archive(), &member), GARC_OK);
  EXPECT_TRUE(member->ids_valid);
  // Zero because the corpus is generated by root inside the pinned container,
  // which is a fact about the fixture and not about this machine - comparing
  // against getuid() here would pass on the generator's host and fail on every
  // other one.
  EXPECT_EQ(member->uid, 0);
  EXPECT_EQ(member->gid, 0);

  Fixture without("infozip-stored.zip");
  ASSERT_EQ(without.open_result(), GARC_OK);
  ASSERT_EQ(garc_next(without.archive(), &member), GARC_OK);
  EXPECT_FALSE(member->ids_valid)
      << "`zip -X` writes no uid/gid field, so there is nothing to report";
}

TEST(Zip, TheExtendedTimestampIsShorterInTheCentralDirectory) {
  // Info-ZIP's 0x5455 field is nine bytes in the local header and five in the
  // central directory. This library reads the central directory's copy, and the
  // fixture's extra ids in the manifest are the central directory's - so a reader
  // that parsed the local layout here would get the wrong length and the wrong
  // time.
  Fixture fixture("infozip-extras.zip");
  ASSERT_EQ(fixture.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(fixture.archive(), &member), GARC_OK);
  EXPECT_EQ(member->mtime_source, GARC_TIME_ZIP_UNIX);
  EXPECT_EQ(garc_zip_member_extra_length(fixture.archive()), 24u)
      << "5 bytes of UT plus 11 of Ux, each with a 4-byte header";
}

TEST(Zip, SevenZipsNtfsTimestampWinsOverTheDosField) {
  Fixture fixture("sevenzip-basic.zip");
  ASSERT_EQ(fixture.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(fixture.archive(), &member), GARC_OK);
  EXPECT_EQ(member->mtime_source, GARC_TIME_ZIP_NTFS);
  // The same second as every other fixture, because the tree's mtime is fixed -
  // which is what lets one expectation cover three sources.
  EXPECT_EQ(member->mtime_seconds, 1000000000);
}

//-----------------------------------------------------------------------------
// Duplicate names, seeking, finding
//-----------------------------------------------------------------------------

TEST(Zip, TwoMembersMayShareAName) {
  // Every reference accepts this and reports both. Reporting both is what this
  // library does too: silently picking one would be deciding which of two
  // answers a caller wanted, and the two have different contents.
  Fixture fixture("python-dups.zip");
  ASSERT_EQ(fixture.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  std::vector<std::string> contents;
  while (garc_next(fixture.archive(), &member) == GARC_OK) {
    EXPECT_EQ(member_name(member), "same.txt");
    contents.push_back(read_all(fixture.archive()));
  }
  EXPECT_EQ(contents,
      std::vector<std::string>({"first\n", "second, and different\n"}));
}

TEST(Zip, FindReturnsTheFirstMemberWithTheName) {
  // garc_find() is the generic scan, which for zip means walking the central
  // directory from the start. With two members sharing a name, the first is the
  // answer - the same rule the tar reader follows.
  Fixture fixture("python-dups.zip");
  ASSERT_EQ(fixture.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_find(fixture.archive(), "same.txt", 8u, &member), GARC_OK);
  EXPECT_EQ(read_all(fixture.archive()), "first\n");
  EXPECT_EQ(garc_member_count(fixture.archive()), 1u);

  // And a name that is not there ends the walk rather than failing.
  EXPECT_EQ(garc_find(fixture.archive(), "absent", 6u, &member), GARC_END);
}

TEST(Zip, FindWorksTwiceBecauseTheWalkIsReset) {
  // The rewind has to put the central directory cursor back. Asking twice is the
  // only thing that can tell a reset cursor from one that happened to be at the
  // start already, which is what the tar reader's rewind comment says a second
  // format would inherit.
  Fixture fixture("infozip-stored.zip");
  ASSERT_EQ(fixture.open_result(), GARC_OK);
  const GARC_Member * first = nullptr;
  ASSERT_EQ(garc_find(fixture.archive(), "sizes/one", 9u, &first), GARC_OK);
  const uint64_t offset = first->header_offset;
  const GARC_Member * second = nullptr;
  ASSERT_EQ(garc_find(fixture.archive(), "sizes/one", 9u, &second), GARC_OK);
  EXPECT_EQ(second->header_offset, offset);
  EXPECT_EQ(garc_member_count(fixture.archive()), 3u);
}

TEST(Zip, AZipOnAPipeIsRefusedByNameRatherThanAsAnUnknownFormat) {
  // **The status matters more than the refusal.** A caller handed
  // GARC_ERR_FORMAT for a file every other tool opens would go looking for the
  // wrong problem; NOT_SEEKABLE says what to change.
  Fixture fixture("infozip-stored.zip", nullptr, /*can_seek=*/false,
      /*knows_size=*/false);
  EXPECT_EQ(fixture.open_result(), GARC_ERR_NOT_SEEKABLE);
}

TEST(Zip, AZipBehindAStubIsNotFoundOnAPipe) {
  // The stub's first bytes are not a zip's, so identification cannot claim it
  // from the front, and the backwards scan needs a seek. This is the one zip that
  // reads as "not an archive" rather than as one that needs seeking - which is
  // honest: nothing about the front of the file says zip.
  Fixture fixture("python-prologue.zip", nullptr, false, false);
  EXPECT_EQ(fixture.open_result(), GARC_ERR_FORMAT);
}

//-----------------------------------------------------------------------------
// Limits
//-----------------------------------------------------------------------------

TEST(Zip, TheExtraFieldCapFiresWithItsOwnStatus) {
  // **The first use of GARC_ERR_LIMIT_EXTRA_BYTES.** tar has no extra fields, so
  // until zip arrived this code was a limit with nothing to enforce.
  GARC_Limits limits;
  garc_limits_default(&limits);
  limits.max_extra_bytes = 8u;
  Fixture fixture("infozip-extras.zip", &limits);
  ASSERT_EQ(fixture.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  EXPECT_EQ(garc_next(fixture.archive(), &member), GARC_ERR_LIMIT_EXTRA_BYTES);

  // The bound, not just the status: 24 bytes is what that member has, and a cap
  // of exactly 24 must pass.
  GARC_Limits exact;
  garc_limits_default(&exact);
  exact.max_extra_bytes = 24u;
  Fixture ok("infozip-extras.zip", &exact);
  ASSERT_EQ(ok.open_result(), GARC_OK);
  EXPECT_EQ(garc_next(ok.archive(), &member), GARC_OK);
}

TEST(Zip, TheNameCapFiresBeforeTheNameIsAllocated) {
  GARC_Limits limits;
  garc_limits_default(&limits);
  limits.max_name_bytes = 4u;
  Fixture fixture("infozip-stored.zip", &limits);
  ASSERT_EQ(fixture.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  EXPECT_EQ(garc_next(fixture.archive(), &member), GARC_ERR_LIMIT_NAME_BYTES);
}

TEST(Zip, TheMemberCapCountsMembers) {
  GARC_Limits limits;
  garc_limits_default(&limits);
  limits.max_members = 2u;
  Fixture fixture("infozip-stored.zip", &limits);
  ASSERT_EQ(fixture.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  EXPECT_EQ(garc_next(fixture.archive(), &member), GARC_OK);
  EXPECT_EQ(garc_next(fixture.archive(), &member), GARC_OK);
  EXPECT_EQ(garc_next(fixture.archive(), &member), GARC_ERR_LIMIT_MEMBERS);
  EXPECT_EQ(garc_member_count(fixture.archive()), 2u);
}

//-----------------------------------------------------------------------------
// The dump, and the accessors on something that is not a zip
//-----------------------------------------------------------------------------

TEST(Zip, TheAccessorsAnswerZeroForAnArchiveThatIsNotAZip) {
  EXPECT_EQ(garc_zip_member_method(nullptr), 0u);
  EXPECT_EQ(garc_zip_member_flags(nullptr), 0u);
  EXPECT_EQ(garc_zip_member_compressed_size(nullptr), 0u);
  EXPECT_EQ(garc_zip_member_crc32(nullptr), 0u);
  EXPECT_EQ(garc_zip_member_version_made_by(nullptr), 0u);
  EXPECT_EQ(garc_zip_member_external_attributes(nullptr), 0u);
  EXPECT_EQ(garc_zip_member_encryption(nullptr), GARC_ZIP_ENCRYPTION_NONE);
  EXPECT_EQ(garc_zip_member_extra_length(nullptr), 0u);
  EXPECT_EQ(garc_zip_member_used_zip64(nullptr), 0);
  EXPECT_EQ(garc_zip_has_zip64_end_record(nullptr), 0);
  EXPECT_EQ(garc_zip_base_offset(nullptr), 0u);
  EXPECT_EQ(garc_zip_declared_members(nullptr), 0u);
  size_t length = 42u;
  EXPECT_EQ(garc_zip_archive_comment(nullptr, &length), nullptr);
  EXPECT_EQ(length, 0u);
  EXPECT_EQ(garc_zip_archive_comment(nullptr, nullptr), nullptr);

  // A tar is not a zip, and asking it a zip question is not an error - it is
  // zero, the same rule garc_tar_member_variant() follows for a zip.
  const std::vector<uint8_t> tar
      = read_fixture(std::string(GARC_TEST_DATA) + "/tar/ustar-basic.tar");
  ASSERT_FALSE(tar.empty());
  BufferSource source(tar.data(), tar.size(), true, true);
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK);
  GARC_Archive * archive = nullptr;
  ASSERT_EQ(garc_open(stream, nullptr, &archive), GARC_OK);
  EXPECT_EQ(garc_format(archive), GARC_FORMAT_TAR);
  EXPECT_EQ(garc_zip_declared_members(archive), 0u);
  EXPECT_EQ(garc_zip_member_method(archive), 0u);
  garc_close(archive);
  garc_stream_destroy(stream);
}

TEST(Zip, TheMethodAndEncryptionNamesCoverEveryValue) {
  // Names for a message, so the interesting case is a number with no name: it is
  // "unknown" rather than a NULL or an empty string, because the caller is
  // building a diagnostic and a NULL there is a crash in the reporting path.
  EXPECT_STREQ(garc_zip_method_string(GARC_ZIP_METHOD_STORED), "stored");
  EXPECT_STREQ(garc_zip_method_string(GARC_ZIP_METHOD_SHRUNK), "shrunk");
  EXPECT_STREQ(garc_zip_method_string(GARC_ZIP_METHOD_REDUCED_1),
      "reduced, factor 1");
  EXPECT_STREQ(garc_zip_method_string(GARC_ZIP_METHOD_REDUCED_2),
      "reduced, factor 2");
  EXPECT_STREQ(garc_zip_method_string(GARC_ZIP_METHOD_REDUCED_3),
      "reduced, factor 3");
  EXPECT_STREQ(garc_zip_method_string(GARC_ZIP_METHOD_REDUCED_4),
      "reduced, factor 4");
  EXPECT_STREQ(garc_zip_method_string(GARC_ZIP_METHOD_IMPLODED), "imploded");
  EXPECT_STREQ(garc_zip_method_string(GARC_ZIP_METHOD_ZSTD), "zstd");
  EXPECT_STREQ(garc_zip_method_string(GARC_ZIP_METHOD_XZ), "xz");
  EXPECT_STREQ(garc_zip_method_string(7), "unknown");
  EXPECT_STREQ(garc_zip_method_string(65535), "unknown");
  EXPECT_STREQ(garc_zip_encryption_string(GARC_ZIP_ENCRYPTION_NONE), "none");
  EXPECT_STREQ(garc_zip_encryption_string(GARC_ZIP_ENCRYPTION_AES), "WinZip AES");
  EXPECT_STREQ(garc_zip_encryption_string(GARC_ZIP_ENCRYPTION_COUNT), "unknown");
  EXPECT_STREQ(garc_format_string(GARC_FORMAT_ZIP), "zip");
}

TEST(Zip, TheDumpNamesTheFormatAndTheMember) {
  Fixture fixture("sevenzip-basic.zip");
  ASSERT_EQ(fixture.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(fixture.archive(), &member), GARC_OK);

  char * buffer = nullptr;
  size_t length = 0;
  FILE * out = open_memstream(&buffer, &length);
  ASSERT_NE(out, nullptr);
  garc_archive_dump(fixture.archive(), out);
  fclose(out);
  const std::string text(buffer, length);
  free(buffer);

  EXPECT_NE(text.find("format=zip"), std::string::npos) << text;
  EXPECT_NE(text.find("declared members"), std::string::npos) << text;
  // 7-Zip put compressible.txt first and deflated it, so the member line names
  // method 8. Asserted as the string the dump prints rather than as a number,
  // because the point of the dump is that a person can read it.
  EXPECT_NE(text.find("method 8 (deflate)"), std::string::npos) << text;
}

} // namespace

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
