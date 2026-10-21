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

#include <ghoti.io/compress/crc32.h>
#include <ghoti.io/security/sha256.h>

#include "test_helpers.h"
#include "zip_builder.h"
#include "zip_manifest.h"
#include "portable.h"

using garctest::BufferSource;
using garctest::ZipDecryptedRow;
using garctest::ZipManifestRow;
using garctest::ZipNameRow;
using garctest::ZipOpeningRow;
using garctest::read_fixture;
using garctest::split_zip;
using garctest::zip_decrypted_load;
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

/** The plaintext of every encrypted member, from three programs that decrypt. */
const std::vector<ZipDecryptedRow> & decrypted() {
  static const std::vector<ZipDecryptedRow> rows
      = zip_decrypted_load(data_path("decrypted.tsv"));
  return rows;
}

/**
 * The password every encrypted fixture was written with.
 *
 * `PASSWORD` in `tools/oracle/make_zip_corpus.py`. Spelled here rather than read
 * from the corpus because it is an input to the fixtures and not a reading of
 * them - a `.tsv` carrying it would invite a test to take whatever it found.
 */
const char kCorpusPassword[] = "ghoti-password";

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

/**
 * Read a member and keep the status of the call that ends it.
 *
 * read_all() drops that status. AES reports the HMAC on the zero-byte call,
 * so a test that only kept the bytes would pass a member whose tag did not
 * match.
 */
std::string read_checked(GARC_Archive * archive, GARC_Result * status) {
  std::string out;
  char buffer[512];
  size_t got = 0;
  GARC_Result result;
  while ((result = garc_read_member(archive, buffer, sizeof(buffer), &got))
          == GARC_OK
      && got) {
    out.append(buffer, got);
  }
  *status = result;
  return out;
}

/** Two stored AES members, so a password set once can be used for the second. */
std::vector<uint8_t> two_aes_members() {
  std::vector<uint8_t> bytes;
  GARC_Sink * sink = nullptr;
  if (garc_sink_create_memory(&sink) != GARC_OK) {
    return bytes;
  }
  GARC_Writer_Options options;
  garc_writer_options_default(&options);
  options.password = kCorpusPassword;
  options.password_length = std::strlen(kCorpusPassword);
  GARC_Writer * writer = nullptr;
  if (garc_writer_create(sink, GARC_FORMAT_ZIP, &options, &writer) != GARC_OK) {
    garc_sink_destroy(sink);
    return bytes;
  }
  const char * names[] = {"one.txt", "two.txt"};
  const char * bodies[] = {"one\n", "two\n"};
  for (int i = 0; i < 2; ++i) {
    GARC_Member member;
    std::memset(&member, 0, sizeof(member));
    member.name = names[i];
    member.name_length = std::strlen(names[i]);
    member.type = GARC_MEMBER_FILE;
    member.size = std::strlen(bodies[i]);
    member.mode = 0644;
    member.mode_valid = 1;
    member.mtime_seconds = 1000000000;
    member.mtime_source = GARC_TIME_ZIP_DOS;
    if (garc_writer_add(writer, &member) != GARC_OK
        || garc_writer_write(writer, bodies[i], member.size) != GARC_OK) {
      garc_writer_destroy(writer);
      garc_sink_destroy(sink);
      return {};
    }
  }
  if (garc_writer_finish(writer) != GARC_OK) {
    garc_writer_destroy(writer);
    garc_sink_destroy(sink);
    return {};
  }
  const void * raw = nullptr;
  size_t size = 0;
  if (garc_sink_data(sink, &raw, &size) == GARC_OK && raw && size) {
    const uint8_t * data = static_cast<const uint8_t *>(raw);
    bytes.assign(data, data + size);
  }
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
  return bytes;
}

/** `sha256:<hex>/<length>`, the shape of a decrypted.tsv digest column. */
std::string sha256_column(const std::string & bytes) {
  unsigned char digest[GSEC_SHA256_DIGEST_LEN];
  if (gsec_sha256(bytes.data(), bytes.size(), digest) != GSEC_OK) {
    return {};
  }
  static const char hex[] = "0123456789abcdef";
  std::string out = "sha256:";
  for (size_t i = 0; i < sizeof(digest); ++i) {
    out.push_back(hex[digest[i] >> 4]);
    out.push_back(hex[digest[i] & 0x0fu]);
  }
  out.push_back('/');
  out += std::to_string(bytes.size());
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
  std::string bzip2;
  std::string lzma;
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
    else if (method == GARC_ZIP_METHOD_BZIP2) {
      bzip2 = read_all(fixture.archive());
    }
    else if (method == GARC_ZIP_METHOD_LZMA) {
      lzma = read_all(fixture.archive());
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
  EXPECT_EQ(bzip2, stored);
  EXPECT_EQ(lzma, stored);
  EXPECT_EQ(refused, 0u);
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
  size_t encrypted = 0;
  for (const auto & entry : manifest()) {
    Fixture fixture(entry.first);
    ASSERT_EQ(fixture.open_result(), GARC_OK) << entry.first;
    // **The password is set for every fixture, not only the encrypted ones.** It
    // costs nothing on an archive with no encrypted member, and it puts the
    // ZipCrypto-around-deflate member into this sweep rather than beside it: the
    // strongest statement about the decrypt-then-inflate layering is that its
    // bytes pass the CRC the writer declared, and that is the statement this test
    // already makes about everything else.
    ASSERT_EQ(garc_set_password(fixture.archive(), kCorpusPassword,
                  std::strlen(kCorpusPassword)),
        GARC_OK) << entry.first;
    const GARC_Member * member = nullptr;
    while (garc_next(fixture.archive(), &member) == GARC_OK) {
      if (garc_zip_member_encryption(fixture.archive())
          != GARC_ZIP_ENCRYPTION_NONE) {
        ++encrypted;
      }
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
      const uint16_t method = garc_zip_member_method(fixture.archive());
      if (method == GARC_ZIP_METHOD_DEFLATE
          || method == GARC_ZIP_METHOD_DEFLATE64) {
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
  // And the encrypted members are in it rather than skipped past, which is what
  // makes this test cover the cipher as well as the codec.
  EXPECT_GE(encrypted, 4u);
  EXPECT_GE(unsupported, 1u) << "ppmd";
}

TEST(Zip, Deflate64MembersReadAndMatchTheirStoredBytes) {
  // Method 9 is "enhanced deflate", which is *not* RFC 1951 - a 64 KB window and
  // a different length code 285 - so it has its own codec in compress, and
  // pointing it at the deflate decoder would produce plausible wrong bytes for
  // the members that use the extensions. sevenzip-deflate64.zip is 7-Zip's own,
  // and the member is compressible.txt, whose bytes python-methods.zip also
  // holds stored.
  Fixture fixture("sevenzip-deflate64.zip");
  ASSERT_EQ(fixture.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(fixture.archive(), &member), GARC_OK);
  EXPECT_EQ(garc_zip_member_method(fixture.archive()),
      GARC_ZIP_METHOD_DEFLATE64);
  EXPECT_STREQ(garc_zip_method_string(GARC_ZIP_METHOD_DEFLATE64),
      "enhanced deflate (deflate64)");
  GARC_Result status = GARC_ERR_INTERNAL;
  const std::string got = read_checked(fixture.archive(), &status);
  EXPECT_EQ(status, GARC_OK);
  EXPECT_EQ(got.size(), 1160u);

  Fixture methods("python-methods.zip");
  ASSERT_EQ(methods.open_result(), GARC_OK);
  std::string stored;
  while (garc_next(methods.archive(), &member) == GARC_OK) {
    if (garc_zip_member_method(methods.archive()) == GARC_ZIP_METHOD_STORED) {
      stored = read_all(methods.archive());
      break;
    }
  }
  EXPECT_EQ(got, stored);
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

TEST(Zip, CorpusBzip2MembersMatchTheStoredBytes) {
  // sevenzip-methods.zip's first member is method 12; python-methods.zip has
  // the same 1,160 bytes under bzip2 as under stored. Version needed is 46.
  Fixture methods("python-methods.zip");
  ASSERT_EQ(methods.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  std::string stored;
  std::string bzip2;
  while (garc_next(methods.archive(), &member) == GARC_OK) {
    const uint16_t method = garc_zip_member_method(methods.archive());
    if (method == GARC_ZIP_METHOD_STORED) {
      stored = read_all(methods.archive());
    }
    else if (method == GARC_ZIP_METHOD_BZIP2) {
      bzip2 = read_all(methods.archive());
    }
  }
  EXPECT_EQ(bzip2.size(), 1160u);
  EXPECT_EQ(bzip2, stored);

  Fixture seven("sevenzip-methods.zip");
  ASSERT_EQ(seven.open_result(), GARC_OK);
  ASSERT_EQ(garc_next(seven.archive(), &member), GARC_OK);
  EXPECT_EQ(garc_zip_member_method(seven.archive()), GARC_ZIP_METHOD_BZIP2);
  GARC_Result status = GARC_ERR_INTERNAL;
  const std::string got = read_checked(seven.archive(), &status);
  EXPECT_EQ(status, GARC_OK);
  EXPECT_EQ(got, stored);
}

TEST(Zip, CorpusLzmaMembersMatchTheStoredBytes) {
  // python-methods.zip carries the same 1,160 bytes as stored and as LZMA,
  // and its LZMA member is Python's version word 0x0409. sevenzip-lzma.zip is
  // 7-Zip's 0x0119. Both set bit 1 and a five-byte properties field. The
  // stored member is the oracle, so neither header is believed on its own.
  Fixture methods("python-methods.zip");
  ASSERT_EQ(methods.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  std::string stored;
  std::string lzma;
  while (garc_next(methods.archive(), &member) == GARC_OK) {
    const uint16_t method = garc_zip_member_method(methods.archive());
    if (method == GARC_ZIP_METHOD_STORED) {
      GARC_Result status = GARC_ERR_INTERNAL;
      stored = read_checked(methods.archive(), &status);
      EXPECT_EQ(status, GARC_OK);
    }
    else if (method == GARC_ZIP_METHOD_LZMA) {
      GARC_Result status = GARC_ERR_INTERNAL;
      lzma = read_checked(methods.archive(), &status);
      EXPECT_EQ(status, GARC_OK);
      EXPECT_EQ(garc_zip_member_flags(methods.archive()) & 0x0002u, 0x0002u);
    }
  }
  EXPECT_EQ(lzma.size(), 1160u);
  EXPECT_EQ(lzma, stored);

  Fixture seven("sevenzip-lzma.zip");
  ASSERT_EQ(seven.open_result(), GARC_OK);
  ASSERT_EQ(garc_next(seven.archive(), &member), GARC_OK);
  EXPECT_EQ(garc_zip_member_method(seven.archive()), GARC_ZIP_METHOD_LZMA);
  EXPECT_EQ(garc_zip_member_flags(seven.archive()) & 0x0002u, 0x0002u);
  GARC_Result status = GARC_ERR_INTERNAL;
  const std::string got = read_checked(seven.archive(), &status);
  EXPECT_EQ(status, GARC_OK);
  EXPECT_EQ(got, stored);
}

TEST(Zip, AnLzmaHeaderThatIsNotFivePropertiesIsCorrupt) {
  const struct {
    const char * name;
    const char * bytes;
    size_t length;
  } cases[] = {
    {"short", "abc", 3u},
    {"props-size", "\x19\x01\x04\x00xxxx", 8u},
    {"props-truncated", "\x19\x01\x05\x00", 4u},
    // Full nine bytes, properties size five, but the properties byte is not a
    // properties byte: 0xFF is past 9*5*5-1. The length and size fields alone
    // would pass, so this is the only arm that exercises zip_lzma_props_decode.
    {"props-byte", "\x19\x01\x05\x00\xff\x00\x00\x00\x00", 9u},
  };
  for (const auto & one : cases) {
    SCOPED_TRACE(one.name);
    garctest::ZipBuilder builder;
    builder.add("member", std::string(one.bytes, one.length));
    builder.last().method = GARC_ZIP_METHOD_LZMA;
    const std::vector<uint8_t> bytes = builder.build();
    GARC_Stream * stream = nullptr;
    ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
        GARC_OK);
    GARC_Archive * archive = nullptr;
    ASSERT_EQ(garc_open(stream, nullptr, &archive), GARC_OK);
    const GARC_Member * member = nullptr;
    EXPECT_EQ(garc_next(archive, &member), GARC_ERR_CORRUPT);
    garc_close(archive);
    garc_stream_destroy(stream);
  }
}

TEST(Zip, AMemberWithAnUnreadableMethodCanStillBeSkipped) {
  // The walk does not stop at a member it cannot decompress. Python's methods
  // fixture has stored, deflate, bzip2 and lzma in that order; all four are
  // readable now. All four members still have to be reported.
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
  // **With no password the refusal says so, and says only that.** Before
  // ZipCrypto was read this was GARC_ERR_UNSUPPORTED, which told a caller to wait
  // for a release when what it needed was a password.
  char buffer[16];
  size_t got = 0;
  EXPECT_EQ(garc_read_member(fixture.archive(), buffer, sizeof(buffer), &got),
      GARC_ERR_PASSWORD_REQUIRED);
}

//-----------------------------------------------------------------------------
// ZipCrypto, against three programs that decrypt the same archives
//-----------------------------------------------------------------------------

TEST(ZipCrypto, TheDecryptedReadingIsNotEmpty) {
  // The denominator. Every row of `decrypted.tsv` is one encrypted member, and a
  // missing or truncated file would make the tests below pass by iterating
  // nothing - which is how a corpus-driven suite goes quiet.
  const auto & rows = decrypted();
  ASSERT_FALSE(rows.empty()) << "no reading at " << data_path("decrypted.tsv");
  EXPECT_EQ(rows.size(), 5u);

  size_t zipcrypto = 0;
  size_t aes = 0;
  size_t with_plaintext = 0;
  size_t deflated = 0;
  for (const ZipDecryptedRow & row : rows) {
    if (row.scheme == "zipcrypto") {
      ++zipcrypto;
    }
    if (row.scheme == "aes") {
      ++aes;
    }
    if (row.have_plaintext) {
      ++with_plaintext;
    }
    if (row.method == GARC_ZIP_METHOD_DEFLATE) {
      ++deflated;
    }
  }
  // **Both layerings are present, and that is the point of the second fixture.**
  // ZipCrypto around stored and ZipCrypto around deflate are different shapes -
  // the cipher is outermost in both, so a reader that decrypts and decompresses
  // in the wrong order reads the stored members correctly and the deflated one
  // not at all. A corpus with only the stored form cannot tell.
  EXPECT_EQ(zipcrypto, 4u);
  EXPECT_GE(deflated, 1u) << "no encrypted member is compressed, so nothing here "
                             "exercises decrypt-then-inflate";
  EXPECT_EQ(aes, 1u) << "the AES row is phase H's committed expectation";
  // The AES row has no plaintext, because two of the three references refuse it.
  EXPECT_EQ(with_plaintext, 4u);
}

TEST(ZipCrypto, EveryEncryptedMemberReadsWhatThreeProgramsDecrypt) {
  // **The cross-check.** Each of these bytes came out of Python's zipfile,
  // unzip 6.00 and 7-Zip 25.01, and the generator writes the plaintext column
  // only where all three digests agreed - so a passing row is four independent
  // implementations of a 1994 cipher producing one answer. A test comparing
  // against an expectation written here would be this library agreeing with
  // itself about a cipher nobody else checked.
  size_t compared = 0;
  size_t refused = 0;
  for (const ZipDecryptedRow & row : decrypted()) {
    Fixture fixture(row.archive);
    ASSERT_EQ(fixture.open_result(), GARC_OK) << row.archive;
    ASSERT_EQ(garc_set_password(fixture.archive(), kCorpusPassword,
                  std::strlen(kCorpusPassword)),
        GARC_OK);

    const GARC_Member * member = nullptr;
    for (size_t index = 0; index <= row.index; ++index) {
      ASSERT_EQ(garc_next(fixture.archive(), &member), GARC_OK)
          << row.archive << ": fewer members than decrypted.tsv describes";
    }
    const std::string where = row.archive + " " + row.name;
    EXPECT_EQ(member_name(member), row.name) << where;
    EXPECT_EQ(member->size, row.size) << where;
    EXPECT_EQ(garc_zip_member_method(fixture.archive()), row.method) << where;
    EXPECT_EQ(garc_zip_member_encryption(fixture.archive()),
        row.scheme == "aes" ? GARC_ZIP_ENCRYPTION_AES
                            : GARC_ZIP_ENCRYPTION_ZIPCRYPTO) << where;

    if (!row.have_plaintext) {
      // AES. Python and unzip refuse method 99, so the plaintext column is `-`
      // and the sevenzip column is the digest this read has to match. The
      // header method stays 99; the comparison is the bytes, not that number.
      GARC_Result status = GARC_ERR_INTERNAL;
      const std::string bytes = read_checked(fixture.archive(), &status);
      EXPECT_EQ(status, GARC_OK) << where << ": " << garc_result_string(status);
      EXPECT_EQ(sha256_column(bytes), row.sevenzip) << where;
      ++compared;
      continue;
    }
    EXPECT_EQ(read_all(fixture.archive()), row.plaintext) << where;
    ++compared;
  }
  EXPECT_EQ(compared, 5u);
  EXPECT_EQ(refused, 0u);
}

TEST(ZipCrypto, TheCheckByteComesFromTheDosTimeWhenThereIsADataDescriptor) {
  // **A finding, asserted rather than described.** ZipCrypto's encryption header
  // ends in one check byte, and APPNOTE says it is the high byte of the member's
  // CRC-32. Info-ZIP sets general purpose flag bit 3 on every encrypted member it
  // writes - the sizes and the CRC go in a data descriptor *after* the data - so
  // it has no CRC to derive that byte from and uses the high byte of the DOS time
  // instead. A reader that only knew the CRC convention would reject the correct
  // password for every encrypted archive `zip` has ever produced.
  //
  // What makes this a test rather than a comment: the two bytes differ in this
  // fixture, so a reader taking the wrong one cannot pass by coincidence. The
  // measured values when this was written were a check byte of 0x0D against a
  // CRC whose high byte is 0x51.
  Fixture fixture("infozip-crypto.zip");
  ASSERT_EQ(fixture.open_result(), GARC_OK);
  ASSERT_EQ(garc_set_password(fixture.archive(), kCorpusPassword,
                std::strlen(kCorpusPassword)),
      GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(fixture.archive(), &member), GARC_OK);

  // Bit 3, which is what puts the check byte on the other convention.
  EXPECT_EQ(garc_zip_member_flags(fixture.archive()) & 0x0008u, 0x0008u);
  // And the CRC's high byte is not the check byte, which is what makes the
  // fixture discriminating. 0x0D is the DOS time's high byte; the CRC's is 0x51.
  EXPECT_EQ(garc_zip_member_crc32(fixture.archive()) >> 24, 0x51u)
      << "the fixture has moved and this test no longer separates the two "
         "conventions";
  EXPECT_EQ(read_all(fixture.archive()), "hello, archive\n");
}

TEST(ZipCrypto, AWrongPasswordIsRejectedBeforeAnyDataIsRead) {
  // The header's check byte, which is the cheap answer: one byte of evidence,
  // returned before a single byte of the member is handed over.
  Fixture fixture("infozip-crypto.zip");
  ASSERT_EQ(fixture.open_result(), GARC_OK);
  ASSERT_EQ(garc_set_password(fixture.archive(), "wrong", 5u), GARC_OK);

  const GARC_Member * member = nullptr;
  // **The walk is unaffected.** A zip's metadata is in the clear whatever the
  // password, so a wrong one must not make garc_next() fail - it would lose every
  // other member of the archive.
  ASSERT_EQ(garc_next(fixture.archive(), &member), GARC_OK);
  EXPECT_EQ(member_name(member), "hello.txt");
  EXPECT_EQ(member->size, 15u);

  char buffer[64];
  size_t got = 0;
  EXPECT_EQ(garc_read_member(fixture.archive(), buffer, sizeof(buffer), &got),
      GARC_ERR_PASSWORD_REJECTED);
  EXPECT_EQ(got, 0u) << "bytes were handed over with the refusal";
  // And the next member is still reachable, which is the half of "the walk is
  // unaffected" that a single-member assertion cannot make.
  ASSERT_EQ(garc_next(fixture.archive(), &member), GARC_OK);
  EXPECT_EQ(member_name(member), "sizes/one");
}

TEST(ZipCrypto, ASecondPasswordReplacesTheFirst) {
  // How a caller tries a list of passwords: set, read, and on
  // GARC_ERR_PASSWORD_REJECTED set another. The archive is not reopened, and the
  // member does not have to be walked to again - which is only true because the
  // keys are derived per call and the encryption header is read per member.
  Fixture fixture("infozip-crypto.zip");
  ASSERT_EQ(fixture.open_result(), GARC_OK);
  ASSERT_EQ(garc_set_password(fixture.archive(), "wrong", 5u), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(fixture.archive(), &member), GARC_OK);

  char buffer[64];
  size_t got = 0;
  ASSERT_EQ(garc_read_member(fixture.archive(), buffer, sizeof(buffer), &got),
      GARC_ERR_PASSWORD_REJECTED);

  ASSERT_EQ(garc_set_password(fixture.archive(), kCorpusPassword,
                std::strlen(kCorpusPassword)),
      GARC_OK);
  // The refusal was decided when the member became current, so the member has to
  // become current again for the new password to be applied. garc_find() is the
  // documented way back to a member by name, and it is what a caller retrying a
  // password would reach for.
  ASSERT_EQ(garc_find(fixture.archive(), "hello.txt", 9u, &member), GARC_OK);
  EXPECT_EQ(read_all(fixture.archive()), "hello, archive\n");
}

TEST(ZipCrypto, AnEmptyPasswordIsAPasswordAndNotTheAbsenceOfOne) {
  // The reason garc_set_password() takes a length rather than a string, and
  // the reason the state carries a flag beside the keys: "" is a password a writer
  // can have used, and it has to be distinguishable from never having been given
  // one. The two answers differ - GARC_ERR_PASSWORD_REJECTED against
  // GARC_ERR_PASSWORD_REQUIRED - so this is testable rather than merely tidy.
  Fixture fixture("infozip-crypto.zip");
  ASSERT_EQ(fixture.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(fixture.archive(), &member), GARC_OK);

  char buffer[64];
  size_t got = 0;
  EXPECT_EQ(garc_read_member(fixture.archive(), buffer, sizeof(buffer), &got),
      GARC_ERR_PASSWORD_REQUIRED);

  ASSERT_EQ(garc_set_password(fixture.archive(), "", 0u), GARC_OK);
  ASSERT_EQ(garc_find(fixture.archive(), "hello.txt", 9u, &member), GARC_OK);
  EXPECT_EQ(garc_read_member(fixture.archive(), buffer, sizeof(buffer), &got),
      GARC_ERR_PASSWORD_REJECTED);
}

TEST(ZipCrypto, APasswordSurvivesARewind) {
  // It is the archive's, not the walk's. A garc_find() that forgot it would refuse
  // a member the same walk had just read, which is the kind of bug that looks like
  // the cipher failing intermittently.
  Fixture fixture("infozip-crypto.zip");
  ASSERT_EQ(fixture.open_result(), GARC_OK);
  ASSERT_EQ(garc_set_password(fixture.archive(), kCorpusPassword,
                std::strlen(kCorpusPassword)),
      GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_find(fixture.archive(), "sizes/one", 9u, &member), GARC_OK);
  EXPECT_EQ(read_all(fixture.archive()), "x");
  ASSERT_EQ(garc_find(fixture.archive(), "hello.txt", 9u, &member), GARC_OK);
  EXPECT_EQ(read_all(fixture.archive()), "hello, archive\n");
}

TEST(ZipCrypto, APasswordIsRefusedOnAnArchiveThatIsNotAZip) {
  // The accessors return zero for a tar; a setter cannot, so it says no. Asserted
  // because a silent success would leave a caller thinking a tar could carry an
  // encrypted member.
  const std::vector<uint8_t> bytes = read_fixture(
      std::string(GARC_TEST_DATA) + "/tar/ustar-basic.tar");
  BufferSource source(bytes.data(), bytes.size(), true, true);
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK);
  GARC_Archive * archive = nullptr;
  ASSERT_EQ(garc_open(stream, nullptr, &archive), GARC_OK);
  ASSERT_EQ(garc_format(archive), GARC_FORMAT_TAR);
  EXPECT_EQ(garc_set_password(archive, "x", 1u), GARC_ERR_INVALID);
  EXPECT_EQ(garc_set_password(nullptr, "x", 1u), GARC_ERR_INVALID);
  garc_close(archive);
  garc_stream_destroy(stream);
}

TEST(ZipCrypto, ANullPasswordWithALengthIsRefused) {
  Fixture fixture("infozip-crypto.zip");
  ASSERT_EQ(fixture.open_result(), GARC_OK);
  EXPECT_EQ(garc_set_password(fixture.archive(), nullptr, 4u),
      GARC_ERR_INVALID);
  // And a NULL password of length zero is the empty password, not an error: the
  // two arms of that condition are separate lines in the implementation and this
  // is what stops one of them being written as the other.
  EXPECT_EQ(garc_set_password(fixture.archive(), nullptr, 0u), GARC_OK);
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
  // The walk succeeds. The bytes need a password, and the refusal says that
  // rather than that the method is unknown.
  char buffer[16];
  size_t got = 0;
  EXPECT_EQ(garc_read_member(fixture.archive(), buffer, sizeof(buffer), &got),
      GARC_ERR_PASSWORD_REQUIRED);
  EXPECT_EQ(got, 0u);
}

TEST(Zip, AWrongPasswordOnWinZipAesIsRejectedAndTheWalkContinues) {
  Fixture fixture("sevenzip-aes.zip");
  ASSERT_EQ(fixture.open_result(), GARC_OK);
  ASSERT_EQ(garc_set_password(fixture.archive(), "not-the-password", 16u),
      GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(fixture.archive(), &member), GARC_OK);
  EXPECT_EQ(garc_zip_member_method(fixture.archive()), GARC_ZIP_METHOD_AES);
  char buffer[16];
  size_t got = 1;
  EXPECT_EQ(garc_read_member(fixture.archive(), buffer, sizeof(buffer), &got),
      GARC_ERR_PASSWORD_REJECTED);
  EXPECT_EQ(got, 0u);
}

TEST(Zip, ASecondAesPasswordReplacesTheFirst) {
  Fixture fixture("sevenzip-aes.zip");
  ASSERT_EQ(fixture.open_result(), GARC_OK);
  ASSERT_EQ(garc_set_password(fixture.archive(), "not-the-password", 16u),
      GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(fixture.archive(), &member), GARC_OK);

  char buffer[64];
  size_t got = 0;
  ASSERT_EQ(garc_read_member(fixture.archive(), buffer, sizeof(buffer), &got),
      GARC_ERR_PASSWORD_REJECTED);

  ASSERT_EQ(garc_set_password(fixture.archive(), kCorpusPassword,
                std::strlen(kCorpusPassword)),
      GARC_OK);
  ASSERT_EQ(garc_find(fixture.archive(), "hello.txt", 9u, &member), GARC_OK);
  GARC_Result status = GARC_ERR_INTERNAL;
  EXPECT_EQ(read_checked(fixture.archive(), &status), "hello, archive\n");
  EXPECT_EQ(status, GARC_OK);
}

TEST(Zip, ASecondAesMemberDecryptsWithThePasswordAlreadySet) {
  const std::vector<uint8_t> bytes = two_aes_members();
  ASSERT_FALSE(bytes.empty());
  BufferSource source(bytes.data(), bytes.size(), true, true);
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK);
  GARC_Archive * archive = nullptr;
  ASSERT_EQ(garc_open(stream, nullptr, &archive), GARC_OK);
  ASSERT_EQ(garc_set_password(
                archive, kCorpusPassword, std::strlen(kCorpusPassword)),
      GARC_OK);

  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(archive, &member), GARC_OK);
  EXPECT_EQ(member_name(member), "one.txt");
  GARC_Result status = GARC_ERR_INTERNAL;
  EXPECT_EQ(read_checked(archive, &status), "one\n");
  EXPECT_EQ(status, GARC_OK);

  ASSERT_EQ(garc_next(archive, &member), GARC_OK);
  EXPECT_EQ(member_name(member), "two.txt");
  status = GARC_ERR_INTERNAL;
  EXPECT_EQ(read_checked(archive, &status), "two\n");
  EXPECT_EQ(status, GARC_OK);

  garc_close(archive);
  garc_stream_destroy(stream);
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

/** One walk of an archive, member by member, as a streamed read is compared. */
struct Walk {
  struct Entry {
    std::string name;
    GARC_Member_Type type;
    uint64_t size;
    std::string data;
    GARC_Result data_status;
    bool size_unknown = false;
    bool operator==(const Entry & other) const {
      return name == other.name && type == other.type && size == other.size
          && data == other.data && data_status == other.data_status;
    }
  };
  GARC_Result open_status = GARC_ERR_INTERNAL;
  GARC_Result end_status = GARC_ERR_INTERNAL;
  std::vector<Entry> entries;
};

Walk walk_fixture(const std::string & name, bool can_seek) {
  Walk walk;
  Fixture fixture(name, nullptr, can_seek, can_seek);
  walk.open_status = fixture.open_result();
  if (walk.open_status != GARC_OK) {
    return walk;
  }
  const GARC_Member * member = nullptr;
  GARC_Result result;
  while ((result = garc_next(fixture.archive(), &member)) == GARC_OK) {
    Walk::Entry entry;
    // member.h promises a pointer even for an empty name.
    EXPECT_NE(member->name, nullptr);
    entry.name = member_name(member);
    entry.size_unknown = member->size_unknown != 0;
    // A streamed walk cannot see the directory's symlink bit; see zip.h.
    entry.type = member->type == GARC_MEMBER_SYMLINK ? GARC_MEMBER_FILE
                                                      : member->type;
    entry.data = read_checked(fixture.archive(), &entry.data_status);
    // Read after the data, which is when a descriptor member's size is known.
    entry.size = member->size;
    walk.entries.push_back(entry);
  }
  walk.end_status = result;
  return walk;
}

TEST(Zip, EveryFixtureReadsTheSameFromAPipeOrIsRefusedByName) {
  // A zip on a pipe is walked by its local headers and checked against the
  // central directory at the end (zip.h). The seekable read is the reference:
  // every fixture must give the same members, the same bytes and the same
  // verdict on each member's data, or be one of the refusals named here.
  std::set<std::string> archives;
  for (const ZipOpeningRow & row : openings()) {
    archives.insert(row.archive);
  }
  ASSERT_EQ(archives.size(), 29u);
  size_t compared = 0;
  size_t descriptor_members = 0;
  for (const std::string & name : archives) {
    SCOPED_TRACE(name);
    const Walk seekable = walk_fixture(name, true);
    const Walk piped = walk_fixture(name, false);
    ASSERT_EQ(seekable.open_status, GARC_OK);
    ASSERT_EQ(seekable.end_status, GARC_END);
    if (name == "python-prologue.zip") {
      // Nothing at the front says zip; see the next test.
      EXPECT_EQ(piped.open_status, GARC_ERR_FORMAT);
      continue;
    }
    ASSERT_EQ(piped.open_status, GARC_OK);
    if (name == "infozip-crypto.zip" || name == "infozip-crypto-deflate.zip") {
      // ZipCrypto written by a streaming zip has descriptors, and an encrypted
      // member's data has no end a reader can find without the directory: the
      // member is listed, its data refused, and the walk cannot go past it.
      ASSERT_EQ(piped.entries.size(), 1u);
      EXPECT_EQ(piped.entries[0].name, seekable.entries[0].name);
      EXPECT_EQ(piped.entries[0].data_status, GARC_ERR_UNSUPPORTED);
      EXPECT_EQ(piped.end_status, GARC_ERR_UNSUPPORTED);
      continue;
    }
    if (name == "sevenzip-aes.zip") {
      // Sizes in the header, so the walk goes on; the data is still refused.
      ASSERT_EQ(piped.entries.size(), 1u);
      EXPECT_EQ(piped.entries[0].data_status, GARC_ERR_UNSUPPORTED);
      EXPECT_EQ(piped.end_status, GARC_END);
      continue;
    }
    EXPECT_EQ(piped.end_status, GARC_END);
    ASSERT_EQ(piped.entries.size(), seekable.entries.size());
    for (size_t i = 0; i < piped.entries.size(); ++i) {
      SCOPED_TRACE(seekable.entries[i].name);
      EXPECT_TRUE(piped.entries[i] == seekable.entries[i]);
      descriptor_members += piped.entries[i].size_unknown ? 1u : 0u;
      ++compared;
    }
  }
  // The denominators: a corpus that stopped holding descriptor members would
  // leave the interesting half of the streamed reader unexercised.
  EXPECT_GE(compared, 70u);
  EXPECT_GE(descriptor_members, 3u); // bsdtar-descriptors.zip's three files
}

GARC_Result append_bytes(void * ctx, const void * buffer, size_t size) {
  auto * out = static_cast<std::vector<uint8_t> *>(ctx);
  const uint8_t * bytes = static_cast<const uint8_t *>(buffer);
  out->insert(out->end(), bytes, bytes + size);
  return GARC_OK;
}

/**
 * A zip written to a pipe: a sink that cannot patch, so the writer's default
 * discipline uses descriptors where it must. With @p always it uses one on
 * every member, as GARC_ZIP_SIZES_DESCRIPTOR asks, into a memory sink.
 */
std::vector<uint8_t> descriptor_zip(GARC_Zip_Method method,
    const std::vector<std::pair<std::string, std::string>> & files,
    bool always = false) {
  std::vector<uint8_t> piped;
  GARC_Sink_Callbacks callbacks{};
  callbacks.write = append_bytes;
  callbacks.ctx = &piped;
  std::vector<uint8_t> bytes;
  GARC_Sink * sink = nullptr;
  if ((always ? garc_sink_create_memory(&sink)
              : garc_sink_create_callback(&callbacks, &sink))
      != GARC_OK) {
    return bytes;
  }
  GARC_Writer_Options options;
  garc_writer_options_default(&options);
  options.zip_method = method;
  options.zip_sizes = always ? GARC_ZIP_SIZES_DESCRIPTOR : GARC_ZIP_SIZES_AUTO;
  GARC_Writer * writer = nullptr;
  if (garc_writer_create(sink, GARC_FORMAT_ZIP, &options, &writer) != GARC_OK) {
    garc_sink_destroy(sink);
    return bytes;
  }
  bool ok = true;
  for (const auto & file : files) {
    GARC_Member member;
    std::memset(&member, 0, sizeof(member));
    member.name = file.first.data();
    member.name_length = file.first.size();
    member.type = GARC_MEMBER_FILE;
    member.size = file.second.size();
    member.mode = 0644;
    member.mode_valid = 1;
    if (!file.first.empty() && file.first.back() == '/') {
      member.type = GARC_MEMBER_DIRECTORY;
      member.mode = 0755;
    }
    else if (file.first.rfind("link:", 0) == 0) {
      // "link:<name>" is a symlink whose target is the data.
      member.name += 5;
      member.name_length -= 5;
      member.type = GARC_MEMBER_SYMLINK;
      member.mode = 0777;
      member.size = 0;
      member.link_target = file.second.data();
      member.link_target_length = file.second.size();
      ok = ok && garc_writer_add(writer, &member) == GARC_OK;
      continue;
    }
    ok = ok && garc_writer_add(writer, &member) == GARC_OK
        && garc_writer_write(writer, file.second.data(), file.second.size())
            == GARC_OK;
  }
  const void * raw = nullptr;
  size_t size = 0;
  if (ok && garc_writer_finish(writer) == GARC_OK) {
    if (!always) {
      bytes = piped;
    }
    else if (garc_sink_data(sink, &raw, &size) == GARC_OK && raw) {
      bytes.assign(static_cast<const uint8_t *>(raw),
          static_cast<const uint8_t *>(raw) + size);
    }
  }
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
  return bytes;
}

/** An archive over bytes, through a stream that cannot seek or say its size. */
class Piped {
public:
  explicit Piped(const std::vector<uint8_t> & bytes)
      : bytes_(bytes), source_(bytes_.data(), bytes_.size(), false, false) {
    if (garc_stream_create_callback(source_.callbacks(), &stream_) == GARC_OK) {
      open_result_ = garc_open(stream_, nullptr, &archive_);
    }
  }
  ~Piped() {
    garc_close(archive_);
    garc_stream_destroy(stream_);
  }
  Piped(const Piped &) = delete;
  Piped & operator=(const Piped &) = delete;
  GARC_Result open_result() const { return open_result_; }
  GARC_Archive * archive() const { return archive_; }

private:
  std::vector<uint8_t> bytes_;
  BufferSource source_;
  GARC_Stream * stream_ = nullptr;
  GARC_Archive * archive_ = nullptr;
  GARC_Result open_result_ = GARC_ERR_INTERNAL;
};

std::string patterned(size_t length, unsigned seed) {
  std::string out;
  for (size_t i = 0; i < length; ++i) {
    out.push_back(static_cast<char>("archive streaming "[(i * seed) % 18u]));
  }
  return out;
}

TEST(Zip, ItsOwnDescriptorArchivesReadBackFromAPipe) {
  // The methods whose decoder knows where its data ends. Three members each, so
  // the second local header is found from where the first member's descriptor
  // ended - which is the decoder's leftover input, handed back.
  const std::vector<std::pair<std::string, std::string>> files = {
      {"one.txt", patterned(70000, 7)},
      {"empty.txt", ""},
      {"three.txt", patterned(1234, 3)},
  };
  const GARC_Zip_Method methods[] = {GARC_ZIP_METHOD_DEFLATE,
      GARC_ZIP_METHOD_DEFLATE64, GARC_ZIP_METHOD_LZMA, GARC_ZIP_METHOD_ZSTD,
      GARC_ZIP_METHOD_BZIP2, GARC_ZIP_METHOD_XZ};
  for (GARC_Zip_Method method : methods) {
    SCOPED_TRACE(garc_zip_method_string(method));
    const std::vector<uint8_t> bytes = descriptor_zip(method, files);
    ASSERT_FALSE(bytes.empty());
    Piped piped(bytes);
    ASSERT_EQ(piped.open_result(), GARC_OK);
    const GARC_Member * member = nullptr;
    for (const auto & file : files) {
      ASSERT_EQ(garc_next(piped.archive(), &member), GARC_OK);
      EXPECT_EQ(member_name(member), file.first);
      // An empty member's header is complete even on a pipe (zip_write.c);
      // every other one has a descriptor and no size yet.
      EXPECT_EQ(member->size_unknown != 0, !file.second.empty());
      EXPECT_EQ(member->size, 0u);
      GARC_Result status = GARC_ERR_INTERNAL;
      EXPECT_EQ(read_checked(piped.archive(), &status), file.second);
      EXPECT_EQ(status, GARC_OK);
      // Known once the data has been read, as member.h promises.
      EXPECT_EQ(member->size, file.second.size());
    }
    EXPECT_EQ(garc_next(piped.archive(), &member), GARC_END);
  }
}

TEST(Zip, SkippingADescriptorMemberOnAPipeStillReachesTheNext) {
  // garc_next() without reading has to decode the member to find its end.
  const std::vector<std::pair<std::string, std::string>> files = {
      {"skipped.txt", patterned(5000, 5)}, {"read.txt", "after the skip\n"}};
  const std::vector<uint8_t> bytes = descriptor_zip(GARC_ZIP_METHOD_DEFLATE, files);
  Piped piped(bytes);
  ASSERT_EQ(piped.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(piped.archive(), &member), GARC_OK);
  ASSERT_EQ(garc_next(piped.archive(), &member), GARC_OK);
  EXPECT_EQ(member_name(member), "read.txt");
  EXPECT_EQ(read_all(piped.archive()), "after the skip\n");
  EXPECT_EQ(garc_next(piped.archive(), &member), GARC_END);
}

TEST(Zip, ADescriptorMemberWithNoEndOfItsOwnIsRefusedOnAPipe) {
  // LZMA whose header does not promise an end marker may stop at its size,
  // which the descriptor has and the walk does not: the member is listed, its
  // data refused, and the walk cannot find the next header - so it stops
  // there rather than guessing. Made from an LZMA member with the marker by
  // clearing the local header's flag; the directory keeps it, so the seekable
  // reading, the control, is unchanged. (Stored data has no end marker either,
  // and is read by the descriptor that fits it: see below.)
  {
    std::vector<uint8_t> bytes = descriptor_zip(GARC_ZIP_METHOD_LZMA,
        {{"first.txt", "first\n"}, {"second.txt", "second\n"}});
    ASSERT_FALSE(bytes.empty());
    ASSERT_EQ(0, std::memcmp(bytes.data(), "PK\x03\x04", 4));
    ASSERT_TRUE(bytes[6] & 0x02u) << "written with the end marker";
    bytes[6] = static_cast<uint8_t>(bytes[6] & ~0x02u);
    Piped piped(bytes);
    ASSERT_EQ(piped.open_result(), GARC_OK);
    const GARC_Member * member = nullptr;
    ASSERT_EQ(garc_next(piped.archive(), &member), GARC_OK);
    EXPECT_EQ(member_name(member), "first.txt");
    char buffer[16];
    size_t got = 0;
    EXPECT_EQ(garc_read_member(piped.archive(), buffer, sizeof(buffer), &got),
        GARC_ERR_UNSUPPORTED);
    EXPECT_EQ(garc_next(piped.archive(), &member), GARC_ERR_UNSUPPORTED);
    // The control: seekably the same bytes read, so the refusal is the pipe's.
    BufferSource source(bytes.data(), bytes.size(), true, true);
    GARC_Stream * stream = nullptr;
    ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK);
    GARC_Archive * archive = nullptr;
    ASSERT_EQ(garc_open(stream, nullptr, &archive), GARC_OK);
    ASSERT_EQ(garc_next(archive, &member), GARC_OK);
    EXPECT_EQ(read_all(archive), "first\n");
    ASSERT_EQ(garc_next(archive, &member), GARC_OK);
    EXPECT_EQ(read_all(archive), "second\n");
    garc_close(archive);
    garc_stream_destroy(stream);
  }
}

/** The general purpose flags of each local header, in order. */
std::vector<uint16_t> local_flags(const std::vector<uint8_t> & bytes) {
  std::vector<uint16_t> flags;
  const std::string haystack(bytes.begin(), bytes.end());
  for (size_t at = haystack.find(std::string("PK\x03\x04", 4));
       at != std::string::npos;
       at = haystack.find(std::string("PK\x03\x04", 4), at + 4)) {
    flags.push_back(static_cast<uint16_t>(bytes[at + 6] | (bytes[at + 7] << 8)));
  }
  return flags;
}

TEST(Zip, AMemberWhoseContentsAreKnownGetsNoDescriptorOnAPipe) {
  // A directory, an empty file and a symlink are known when they are added, so
  // the writer fills their local headers in even on a sink that cannot patch.
  // With a descriptor a stored member could not be read back from a pipe at
  // all (see the refusal test below); the deflated file still gets one.
  const std::vector<std::pair<std::string, std::string>> files = {
      {"dir/", ""}, {"dir/empty", ""}, {"link:dir/link", "empty"},
      {"dir/data.txt", patterned(3000, 5)}};
  const std::vector<uint8_t> bytes = descriptor_zip(GARC_ZIP_METHOD_DEFLATE, files);
  ASSERT_FALSE(bytes.empty());
  EXPECT_EQ(local_flags(bytes), (std::vector<uint16_t>{0, 0, 0, 0x0008u}));

  Piped piped(bytes);
  ASSERT_EQ(piped.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(piped.archive(), &member), GARC_OK);
  EXPECT_EQ(member->type, GARC_MEMBER_DIRECTORY);
  ASSERT_EQ(garc_next(piped.archive(), &member), GARC_OK);
  EXPECT_FALSE(member->size_unknown);
  EXPECT_EQ(read_all(piped.archive()), "");
  ASSERT_EQ(garc_next(piped.archive(), &member), GARC_OK);
  // A symlink is a file on a pipe, whose data is its target (zip.h).
  EXPECT_EQ(member_name(member), "dir/link");
  EXPECT_EQ(member->size, 5u);
  EXPECT_EQ(read_all(piped.archive()), "empty");
  ASSERT_EQ(garc_next(piped.archive(), &member), GARC_OK);
  EXPECT_TRUE(member->size_unknown);
  GARC_Result status = GARC_ERR_INTERNAL;
  EXPECT_EQ(read_checked(piped.archive(), &status), files[3].second);
  EXPECT_EQ(status, GARC_OK);
  EXPECT_EQ(garc_next(piped.archive(), &member), GARC_END);

  // The control on the flags: DESCRIPTOR asks for one on every member.
  EXPECT_EQ(local_flags(descriptor_zip(GARC_ZIP_METHOD_DEFLATE, files, true)),
      (std::vector<uint16_t>{0x0008u, 0x0008u, 0x0008u, 0x0008u}));
}

TEST(Zip, AStoredDirectoryWithADescriptorIsReadOnAPipe) {
  // Its descriptor follows the header at once, because a directory has no data.
  // The walk used to stop there and read the descriptor as the next header.
  const std::vector<uint8_t> bytes = descriptor_zip(GARC_ZIP_METHOD_DEFLATE,
      {{"dir/", ""}, {"dir/a.txt", "a\n"}}, true);
  ASSERT_EQ(local_flags(bytes), (std::vector<uint16_t>{0x0008u, 0x0008u}));
  Piped piped(bytes);
  ASSERT_EQ(piped.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(piped.archive(), &member), GARC_OK);
  EXPECT_EQ(member->type, GARC_MEMBER_DIRECTORY);
  ASSERT_EQ(garc_next(piped.archive(), &member), GARC_OK);
  EXPECT_EQ(member_name(member), "dir/a.txt");
  EXPECT_EQ(read_all(piped.archive()), "a\n");
  EXPECT_EQ(garc_next(piped.archive(), &member), GARC_END);
}

/**
 * A directory the way Java's ZipOutputStream writes one into a jar: deflated,
 * with a descriptor, its data the two bytes of an empty fixed-Huffman block.
 * No writer here produces that, so it is built by hand; @p data replaces the
 * empty block for the refusal.
 */
std::vector<uint8_t> java_directory_zip(const std::string & data,
    uint32_t declared_size) {
  std::string out;
  const auto put16 = [&](uint16_t v) {
    out.push_back(static_cast<char>(v & 0xffu));
    out.push_back(static_cast<char>(v >> 8));
  };
  const auto put32 = [&](uint32_t v) {
    put16(static_cast<uint16_t>(v & 0xffffu));
    put16(static_cast<uint16_t>(v >> 16));
  };
  const std::string name = "META-INF/";
  out += std::string("PK\x03\x04", 4);
  put16(20);
  put16(0x0808u); // descriptor and UTF-8, as Java sets them
  put16(8);
  put16(0);
  put16(0x2B29u);
  put32(0);
  put32(0);
  put32(0);
  put16(static_cast<uint16_t>(name.size()));
  put16(0);
  out += name;
  out += data;
  out += std::string("PK\x07\x08", 4);
  put32(0);
  put32(static_cast<uint32_t>(data.size()));
  put32(declared_size);
  const uint32_t central = static_cast<uint32_t>(out.size());
  out += std::string("PK\x01\x02", 4);
  put16(20);
  put16(20);
  put16(0x0808u);
  put16(8);
  put16(0);
  put16(0x2B29u);
  put32(0);
  put32(static_cast<uint32_t>(data.size()));
  put32(declared_size);
  put16(static_cast<uint16_t>(name.size()));
  put16(0);
  put16(0);
  put16(0);
  put16(0);
  put32(0x10u);
  put32(0);
  out += name;
  const uint32_t central_size = static_cast<uint32_t>(out.size()) - central;
  out += std::string("PK\x05\x06", 4);
  put16(0);
  put16(0);
  put16(1);
  put16(1);
  put32(central_size);
  put32(central);
  put16(0);
  return std::vector<uint8_t>(out.begin(), out.end());
}

TEST(Zip, AJarDirectoryWithADeflatedDescriptorIsReadOnAPipe) {
  const std::vector<uint8_t> bytes
      = java_directory_zip(std::string("\x03\x00", 2), 0);
  {
    // The control: seekably it is an ordinary directory.
    BufferSource source(bytes.data(), bytes.size(), true, true);
    GARC_Stream * stream = nullptr;
    ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK);
    GARC_Archive * archive = nullptr;
    ASSERT_EQ(garc_open(stream, nullptr, &archive), GARC_OK);
    const GARC_Member * member = nullptr;
    ASSERT_EQ(garc_next(archive, &member), GARC_OK);
    EXPECT_EQ(member->type, GARC_MEMBER_DIRECTORY);
    EXPECT_EQ(garc_next(archive, &member), GARC_END);
    garc_close(archive);
    garc_stream_destroy(stream);
  }
  Piped piped(bytes);
  ASSERT_EQ(piped.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(piped.archive(), &member), GARC_OK);
  EXPECT_EQ(member->type, GARC_MEMBER_DIRECTORY);
  EXPECT_EQ(member_name(member), "META-INF/");
  EXPECT_EQ(garc_next(piped.archive(), &member), GARC_END);
}

TEST(Zip, AJarDirectoryWhoseStreamHoldsDataIsCorruptOnAPipe) {
  // A deflate stream of one stored byte, "x": a directory claiming data.
  const std::vector<uint8_t> bytes
      = java_directory_zip(std::string("\x01\x01\x00\xfe\xffx", 6), 1);
  Piped piped(bytes);
  ASSERT_EQ(piped.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(piped.archive(), &member), GARC_OK);
  EXPECT_EQ(member->type, GARC_MEMBER_DIRECTORY);
  EXPECT_EQ(garc_next(piped.archive(), &member), GARC_ERR_CORRUPT);
}

TEST(Zip, ADirectoryThatDisagreesWithTheWalkIsCorruptAtTheEnd) {
  // The local headers are what a streamed walk believes, so the directory is the
  // check on them. One field changed in the central entry - the CRC, the size,
  // the name - must turn the end of the walk into GARC_ERR_CORRUPT. The control
  // is the unchanged archive ending in GARC_END.
  const std::vector<uint8_t> clean
      = descriptor_zip(GARC_ZIP_METHOD_DEFLATE, {{"member.txt", "member\n"}});
  ASSERT_FALSE(clean.empty());
  const std::string haystack(clean.begin(), clean.end());
  const size_t central = haystack.find(std::string("PK\x01\x02", 4));
  ASSERT_NE(central, std::string::npos);
  // CRC-32 at 16, compressed size at 20, size at 24, the name's first byte at 46.
  const size_t fields[] = {0, 16, 20, 24, 46};
  for (size_t field : fields) {
    SCOPED_TRACE(field);
    std::vector<uint8_t> bytes = clean;
    if (field) {
      bytes[central + field] ^= 0x01u;
    }
    Piped piped(bytes);
    ASSERT_EQ(piped.open_result(), GARC_OK);
    const GARC_Member * member = nullptr;
    ASSERT_EQ(garc_next(piped.archive(), &member), GARC_OK);
    GARC_Result status = GARC_ERR_INTERNAL;
    EXPECT_EQ(read_checked(piped.archive(), &status), "member\n");
    EXPECT_EQ(status, GARC_OK);
    EXPECT_EQ(garc_next(piped.archive(), &member),
        field ? GARC_ERR_CORRUPT : GARC_END);
  }
}

TEST(Zip, AnEndRecordThatDisagreesWithTheWalkIsRefusedOnAPipe) {
  // What the end record declares - how many members, how large the directory
  // is and where it starts, the comment and that nothing follows it - is what
  // garc_zip_open() refuses a seekable archive over, so a pipe that ignored it
  // would read to the end an archive every other reading refuses. Each field
  // was found unchecked by fuzz_zip's pipe-against-seek differential.
  const std::vector<uint8_t> clean
      = descriptor_zip(GARC_ZIP_METHOD_DEFLATE, {{"member.txt", "member\n"}});
  ASSERT_FALSE(clean.empty());
  const size_t eocd = clean.size() - 22u;
  ASSERT_EQ(std::string(clean.begin() + (std::ptrdiff_t)eocd,
                clean.begin() + (std::ptrdiff_t)eocd + 4),
      std::string("PK\x05\x06", 4));
  struct Case {
    const char * what;
    size_t field;     // offset in the end record, or 0 for none
    uint8_t value;    // what its low byte becomes
    bool trailing;    // append a byte after the record
    GARC_Result want;
  };
  const Case cases[] = {
      {"control", 0, 0, false, GARC_END},
      {"entries on this disk", 8, 2, false, GARC_ERR_CORRUPT},
      {"entries in all", 10, 2, false, GARC_ERR_CORRUPT},
      {"both counts", 0, 0, false, GARC_ERR_CORRUPT},
      {"directory size", 12, 0, false, GARC_ERR_CORRUPT},
      {"directory offset", 16, 1, false, GARC_ERR_CORRUPT},
      // A second disk holding only the end record would count no entries.
      {"disk number", 4, 1, false, GARC_ERR_CORRUPT},
      {"comment longer than what is left", 20, 9, false, GARC_ERR_CORRUPT},
      {"a byte after the end", 0, 0, true, GARC_ERR_FORMAT},
  };
  for (const Case & c : cases) {
    SCOPED_TRACE(c.what);
    std::vector<uint8_t> bytes = clean;
    if (c.field) {
      bytes[eocd + c.field] = c.value;
    }
    if (std::string(c.what) == "both counts") {
      bytes[eocd + 8] = 2;
      bytes[eocd + 10] = 2;
    }
    if (c.trailing) {
      bytes.push_back(0);
    }
    Piped piped(bytes);
    ASSERT_EQ(piped.open_result(), GARC_OK);
    const GARC_Member * member = nullptr;
    ASSERT_EQ(garc_next(piped.archive(), &member), GARC_OK);
    EXPECT_EQ(read_all(piped.archive()), "member\n");
    EXPECT_EQ(garc_next(piped.archive(), &member), c.want);
  }
}

TEST(Zip, AnAesFieldThatDisagreesWithTheDirectoryIsCorruptOnAPipe) {
  // The pipe's walk decides how an AES member is encrypted from the local
  // header; the directory's field must say the same key size and version, or
  // the archive reads two ways. fuzz_zip found the strength unchecked.
  const std::vector<uint8_t> clean = two_aes_members();
  ASSERT_FALSE(clean.empty());
  const std::string haystack(clean.begin(), clean.end());
  const size_t central = haystack.find(std::string("PK\x01\x02", 4));
  ASSERT_NE(central, std::string::npos);
  const size_t field = haystack.find(std::string("\x01\x99\x07\x00", 4), central);
  ASSERT_NE(field, std::string::npos);
  // 0 changes nothing; then the version's low byte, and the strength.
  for (size_t at : {size_t(0), field + 4, field + 8}) {
    SCOPED_TRACE(at);
    std::vector<uint8_t> bytes = clean;
    if (at) {
      bytes[at] = static_cast<uint8_t>(bytes[at] == 1 ? 2 : 1);
    }
    Piped piped(bytes);
    ASSERT_EQ(piped.open_result(), GARC_OK);
    const GARC_Member * member = nullptr;
    GARC_Result result;
    while ((result = garc_next(piped.archive(), &member)) == GARC_OK) {
    }
    EXPECT_EQ(result, at ? GARC_ERR_CORRUPT : GARC_END);
  }
}

TEST(Zip, TheCommentIsReadFromAPipeAsFromAFile) {
  // python-comments.zip has one; the streamed walk keeps it as the seekable
  // reader does, so garc_zip_comment() answers the same on both.
  const std::vector<uint8_t> bytes
      = read_fixture(data_path("python-comments.zip"));
  Fixture seekable("python-comments.zip");
  ASSERT_EQ(seekable.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  while (garc_next(seekable.archive(), &member) == GARC_OK) {
  }
  size_t want_length = 0;
  const char * want = garc_zip_archive_comment(seekable.archive(), &want_length);
  ASSERT_GT(want_length, 0u);
  Piped piped(bytes);
  ASSERT_EQ(piped.open_result(), GARC_OK);
  while (garc_next(piped.archive(), &member) == GARC_OK) {
  }
  size_t got_length = 0;
  const char * got = garc_zip_archive_comment(piped.archive(), &got_length);
  EXPECT_EQ(std::string(got, got_length), std::string(want, want_length));
}

TEST(Zip, AMemberTheDirectoryDoesNotListIsCorruptAtTheEnd) {
  // Two members walked, a directory claiming one: the count disagrees. Built by
  // splicing the first archive's members in front of a one-member directory.
  const std::vector<uint8_t> two = descriptor_zip(
      GARC_ZIP_METHOD_DEFLATE, {{"a.txt", "a\n"}, {"b.txt", "b\n"}});
  const std::vector<uint8_t> one
      = descriptor_zip(GARC_ZIP_METHOD_DEFLATE, {{"a.txt", "a\n"}});
  const std::string two_s(two.begin(), two.end());
  const std::string one_s(one.begin(), one.end());
  const size_t two_central = two_s.find(std::string("PK\x01\x02", 4));
  const size_t one_central = one_s.find(std::string("PK\x01\x02", 4));
  ASSERT_NE(two_central, std::string::npos);
  ASSERT_NE(one_central, std::string::npos);
  std::string spliced = two_s.substr(0, two_central) + one_s.substr(one_central);
  // The end record's directory offset now points at the wrong place, which a
  // streamed walk does not consult - the walk reaches the directory itself.
  std::vector<uint8_t> bytes(spliced.begin(), spliced.end());
  Piped piped(bytes);
  ASSERT_EQ(piped.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(piped.archive(), &member), GARC_OK);
  ASSERT_EQ(garc_next(piped.archive(), &member), GARC_OK);
  EXPECT_EQ(garc_next(piped.archive(), &member), GARC_ERR_CORRUPT);
}

TEST(Zip, AnEmptyNameIsAnEmptyStringOnBothPaths) {
  // A NULL name with a length of 0 is a memcpy(dst, NULL, 0) waiting in every
  // C caller, and tar never gave one. fuzz_tar found the pipe path giving it,
  // once a zip on a pipe stopped being refused; the seekable one did too.
  const std::vector<uint8_t> bytes = garctest::ZipBuilder().add("", "x").build();
  for (int piped = 0; piped < 2; ++piped) {
    SCOPED_TRACE(piped ? "pipe" : "seek");
    BufferSource source(bytes.data(), bytes.size(), !piped, !piped);
    GARC_Stream * stream = nullptr;
    ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK);
    GARC_Archive * archive = nullptr;
    ASSERT_EQ(garc_open(stream, nullptr, &archive), GARC_OK);
    const GARC_Member * member = nullptr;
    ASSERT_EQ(garc_next(archive, &member), GARC_OK);
    EXPECT_NE(member->name, nullptr);
    EXPECT_EQ(member->name_length, 0u);
    garc_close(archive);
    garc_stream_destroy(stream);
  }
}

/** Walk @p parts through a concatenation; the names and data, or a status. */
GARC_Result walk_parts(const std::vector<std::vector<uint8_t>> & parts,
    std::vector<std::pair<std::string, std::string>> * out) {
  std::vector<GARC_Stream *> streams;
  for (const auto & part : parts) {
    GARC_Stream * stream = nullptr;
    EXPECT_EQ(GARC_OK, garc_stream_create_memory(part.data(), part.size(), &stream));
    streams.push_back(stream);
  }
  GARC_Stream * whole = nullptr;
  GARC_Result result
      = garc_stream_create_concat(streams.data(), streams.size(), &whole);
  GARC_Archive * archive = nullptr;
  if (result == GARC_OK) {
    result = garc_open(whole, nullptr, &archive);
  }
  const GARC_Member * member = nullptr;
  while (result == GARC_OK && (result = garc_next(archive, &member)) == GARC_OK) {
    GARC_Result status = GARC_OK;
    const std::string data = read_checked(archive, &status);
    if (status != GARC_OK) {
      result = status;
      break;
    }
    out->emplace_back(member_name(member), data);
  }
  garc_close(archive);
  garc_stream_destroy(whole);
  for (GARC_Stream * stream : streams) {
    garc_stream_destroy(stream);
  }
  return result == GARC_END ? GARC_OK : result;
}

TEST(Zip, ASplitZipIsReadThroughTheConcatenationOfItsParts) {
  // Cut through members, headers and the central directory alike: a split
  // writer cuts at a size, not at a boundary, and the concatenation is what
  // puts the bytes back in a row.
  const std::vector<std::pair<std::string, std::string>> files = {
      {"one.txt", patterned(5000, 3)}, {"two.txt", patterned(7000, 5)},
      {"dir/three.txt", "three\n"}};
  // Stored, so the archive is as long as the data and every cut has bytes to
  // land in.
  const std::vector<uint8_t> whole = descriptor_zip(GARC_ZIP_METHOD_STORED, files, true);
  ASSERT_GT(whole.size(), 12000u);
  std::vector<std::pair<std::string, std::string>> want;
  {
    const std::vector<std::vector<uint8_t>> one = {whole};
    ASSERT_EQ(GARC_OK, walk_parts(one, &want));
  }
  ASSERT_EQ(want.size(), files.size());
  const size_t central = std::string(whole.begin(), whole.end())
                             .find(std::string("PK\x01\x02", 4));
  ASSERT_NE(central, std::string::npos);
  const std::vector<std::vector<size_t>> cut_sets = {
      {1000}, {100, 2000, 4100}, {central + 10}, {whole.size() - 30},
      {200, 400, 600, 800, 1000, 1200}};
  for (const auto & cuts : cut_sets) {
    SCOPED_TRACE(cuts.size());
    const auto parts = split_zip(whole, cuts);
    std::vector<std::pair<std::string, std::string>> got;
    EXPECT_EQ(GARC_OK, walk_parts(parts, &got));
    EXPECT_TRUE(got == want);
  }
}

TEST(Zip, ASplitZipWithoutAllItsPartsIsRefusedByName) {
  const std::vector<uint8_t> whole = descriptor_zip(GARC_ZIP_METHOD_STORED,
      {{"one.txt", patterned(5000, 3)}, {"two.txt", "two\n"}}, true);
  ASSERT_GT(whole.size(), 5000u);
  const auto parts = split_zip(whole, {2000, 4000});
  std::vector<std::pair<std::string, std::string>> got;
  // The last disk alone, which is what opening only the .zip of a split set was.
  EXPECT_EQ(GARC_ERR_UNSUPPORTED, walk_parts({parts.back()}, &got));
  // Two of the three: the end record says three disks.
  EXPECT_EQ(GARC_ERR_UNSUPPORTED, walk_parts({parts[1], parts[2]}, &got));
  // All three, out of order: the end record is not on the last disk, or the
  // offsets land on no header.
  got.clear();
  EXPECT_NE(GARC_OK, walk_parts({parts[2], parts[0], parts[1]}, &got));
}

/** Walk @p bytes off a pipe: the names and data, or the status that ended it. */
GARC_Result walk_piped(const std::vector<uint8_t> & bytes,
    std::vector<std::pair<std::string, std::string>> * out) {
  Piped piped(bytes);
  GARC_Result result = piped.open_result();
  const GARC_Member * member = nullptr;
  while (result == GARC_OK
      && (result = garc_next(piped.archive(), &member)) == GARC_OK) {
    GARC_Result status = GARC_OK;
    const std::string data = read_checked(piped.archive(), &status);
    if (status != GARC_OK) {
      return status;
    }
    out->emplace_back(member_name(member), data);
  }
  return result == GARC_END ? GARC_OK : result;
}

/** The volumes of a split set back in a row, as `cat` would give them. */
std::vector<uint8_t> joined(const std::vector<std::vector<uint8_t>> & parts) {
  std::vector<uint8_t> out;
  for (const auto & part : parts) {
    out.insert(out.end(), part.begin(), part.end());
  }
  return out;
}

TEST(Zip, ASplitZipIsReadFromAPipeOfItsPartsInOrder) {
  // A pipe has no boundaries, so each record says where its volume began -
  // its place in the stream less the offset its volume gave it - and those
  // must agree. Deflated, so that a descriptor member has an end of its own.
  const std::vector<std::pair<std::string, std::string>> files = {
      {"one.txt", patterned(5000, 3)}, {"two.txt", patterned(7000, 5)},
      {"dir/three.txt", "three\n"}};
  const std::vector<uint8_t> whole
      = descriptor_zip(GARC_ZIP_METHOD_DEFLATE, files, true);
  std::vector<std::pair<std::string, std::string>> want;
  ASSERT_EQ(GARC_OK, walk_piped(whole, &want));
  ASSERT_EQ(want.size(), files.size());
  const size_t central = std::string(whole.begin(), whole.end())
                             .find(std::string("PK\x01\x02", 4));
  ASSERT_NE(central, std::string::npos);
  const std::vector<std::vector<size_t>> cut_sets = {{100}, {20, 60, 90},
      {central + 10}, {whole.size() - 30}, {30, 60, central, central + 50}};
  for (const auto & cuts : cut_sets) {
    SCOPED_TRACE(cuts.size());
    const auto parts = split_zip(whole, cuts);
    std::vector<std::pair<std::string, std::string>> got;
    EXPECT_EQ(GARC_OK, walk_piped(joined(parts), &got));
    EXPECT_TRUE(got == want);
    // The seekable reader through the parts agrees.
    std::vector<std::pair<std::string, std::string>> seek;
    EXPECT_EQ(GARC_OK, walk_parts(parts, &seek));
    EXPECT_TRUE(seek == want);
  }
}

TEST(Zip, ASplitZipWhoseDisksDisagreeIsCorruptOnAPipe) {
  const std::vector<uint8_t> whole = descriptor_zip(GARC_ZIP_METHOD_DEFLATE,
      {{"one.txt", patterned(5000, 3)}, {"two.txt", "two\n"},
          {"three.txt", "three\n"}},
      true);
  const size_t central = std::string(whole.begin(), whole.end())
                             .find(std::string("PK\x01\x02", 4));
  ASSERT_NE(central, std::string::npos);
  // Each member on a disk of its own, and the directory on the last.
  const size_t second = std::string(whole.begin(), whole.end())
                            .find(std::string("PK\x03\x04", 4), 4);
  ASSERT_NE(second, std::string::npos);
  const std::vector<uint8_t> clean = joined(split_zip(whole, {second, central}));
  const size_t directory = clean.size() - 22u
      - (whole.size() - 22u - central); // where the directory is in the joined set
  std::vector<std::pair<std::string, std::string>> got;
  ASSERT_EQ(GARC_OK, walk_piped(clean, &got)) << "control";
  const size_t two = directory + 46u + 7u; // the second entry: "one.txt" is 7
  ASSERT_EQ(clean[two], 'P');
  ASSERT_EQ(clean[two + 34], 1u);
  struct Case {
    const char * what;
    size_t at;
    uint8_t value;
  };
  const Case cases[] = {
      // The second member's offset moved: its disk would begin somewhere the
      // third member's says it does not.
      {"an offset off by one", two + 42, static_cast<uint8_t>(clean[two + 42] + 1)},
      // The second member on disk 0: its volume would begin after the first's.
      {"a disk that went back", two + 34, 0},
      // The directory said to start on disk 0, after members on disk 1.
      {"the directory on an earlier disk", clean.size() - 22u + 6u, 0},
      // The end record's disk before the directory's.
      {"the last disk before the directory", clean.size() - 22u + 4u, 1},
  };
  for (const Case & c : cases) {
    SCOPED_TRACE(c.what);
    std::vector<uint8_t> bytes = clean;
    bytes[c.at] = c.value;
    got.clear();
    EXPECT_EQ(GARC_ERR_CORRUPT, walk_piped(bytes, &got));
  }
}

TEST(Zip, AZip64EndWhose16BitCountsDisagreeIsRefusedOnAPipe) {
  // garc_zip_open() reads the 16-bit end record before it looks for zip64,
  // and two counts that differ there are a split set - refused, on one
  // stream, for having no parts. The pipe takes zip64's values for the
  // archive's and must still refuse what the seekable reader does. fuzz_zip
  // found the counts unchecked once the pipe began reading split sets.
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  GARC_Writer_Options options;
  garc_writer_options_default(&options);
  options.zip_force_zip64 = 1;
  options.zip_method = GARC_ZIP_METHOD_DEFLATE;
  GARC_Writer * writer = nullptr;
  ASSERT_EQ(garc_writer_create(sink, GARC_FORMAT_ZIP, &options, &writer), GARC_OK);
  GARC_Member member;
  std::memset(&member, 0, sizeof(member));
  member.name = "member.txt";
  member.name_length = 10;
  member.type = GARC_MEMBER_FILE;
  member.size = 7;
  ASSERT_EQ(garc_writer_add(writer, &member), GARC_OK);
  ASSERT_EQ(garc_writer_write(writer, "member\n", 7), GARC_OK);
  ASSERT_EQ(garc_writer_finish(writer), GARC_OK);
  const void * data = nullptr;
  size_t length = 0;
  ASSERT_EQ(garc_sink_data(sink, &data, &length), GARC_OK);
  const std::vector<uint8_t> clean(static_cast<const uint8_t *>(data),
      static_cast<const uint8_t *>(data) + length);
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
  const size_t eocd = clean.size() - 22u;
  ASSERT_EQ(0, std::memcmp(clean.data() + eocd, "PK\x05\x06", 4));
  ASSERT_EQ(0, std::memcmp(clean.data() + eocd - 20u, "PK\x06\x07", 4));
  std::vector<std::pair<std::string, std::string>> got;
  ASSERT_EQ(GARC_OK, walk_piped(clean, &got)) << "control";
  for (const size_t field : {size_t(8), size_t(10)}) {
    SCOPED_TRACE(field == 8 ? "entries on this disk" : "entries in all");
    std::vector<uint8_t> bytes = clean;
    bytes[eocd + field] = 0x3f;
    bytes[eocd + field + 1] = 0xc3;
    got.clear();
    EXPECT_EQ(GARC_ERR_CORRUPT, walk_piped(bytes, &got));
    GARC_Stream * stream = nullptr;
    ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream), GARC_OK);
    GARC_Archive * archive = nullptr;
    EXPECT_EQ(GARC_ERR_UNSUPPORTED, garc_open(stream, nullptr, &archive));
    garc_close(archive);
    garc_stream_destroy(stream);
  }
}

namespace {

/**
 * Walk @p bytes off a pipe that hands over at most @p cap bytes a read and,
 * when @p fail_after is not SIZE_MAX, fails the read after that many.
 * Returns how the walk ended and, through @p reads, how many reads it took.
 */
GARC_Result walk_pipe_source(const std::vector<uint8_t> & bytes, size_t cap,
    size_t fail_after, size_t * reads,
    std::vector<std::pair<std::string, std::string>> * out) {
  BufferSource source(bytes.data(), bytes.size(), false, false);
  source.cap_reads(cap);
  if (fail_after != SIZE_MAX) {
    source.fail_reads_after(fail_after);
  }
  GARC_Stream * stream = nullptr;
  if (garc_stream_create_callback(source.callbacks(), &stream) != GARC_OK) {
    return GARC_ERR_OOM;
  }
  GARC_Archive * archive = nullptr;
  GARC_Result result = garc_open(stream, nullptr, &archive);
  const GARC_Member * member = nullptr;
  while (result == GARC_OK && (result = garc_next(archive, &member)) == GARC_OK) {
    GARC_Result status = GARC_OK;
    const std::string data = read_checked(archive, &status);
    if (status != GARC_OK) {
      result = status;
      break;
    }
    out->emplace_back(member_name(member), data);
  }
  garc_close(archive);
  garc_stream_destroy(stream);
  *reads = source.reads();
  return result == GARC_END ? GARC_OK : result;
}

/** Zips a pipe has to walk: descriptors, zip64, a comment, a split set. */
std::vector<std::pair<std::string, std::vector<uint8_t>>> pipe_population() {
  std::vector<std::pair<std::string, std::vector<uint8_t>>> out;
  const std::vector<std::pair<std::string, std::string>> files = {
      {"one.txt", patterned(9000, 3)}, {"dir/", ""}, {"empty.txt", ""},
      {"two.txt", patterned(300, 5)}};
  out.emplace_back("descriptors", descriptor_zip(GARC_ZIP_METHOD_DEFLATE, files));
  out.emplace_back("zstd descriptors", descriptor_zip(GARC_ZIP_METHOD_ZSTD, files));
  out.emplace_back("bzip2 descriptors", descriptor_zip(GARC_ZIP_METHOD_BZIP2, files));
  out.emplace_back("xz descriptors", descriptor_zip(GARC_ZIP_METHOD_XZ, files));
  out.emplace_back("stored descriptors", descriptor_zip(GARC_ZIP_METHOD_STORED,
      {{"one.txt", patterned(900, 3)}, {"sig.bin", std::string("a PK\x07\x08 b", 8)},
          {"two.txt", "two\n"}}));
  const std::vector<uint8_t> always = descriptor_zip(GARC_ZIP_METHOD_DEFLATE,
      {{"one.txt", patterned(9000, 3)}, {"two.txt", patterned(300, 5)},
          {"three.txt", "three\n"}},
      true);
  const size_t second = std::string(always.begin(), always.end())
                            .find(std::string("PK\x03\x04", 4), 4);
  out.emplace_back("split", joined(split_zip(always, {second, second + 40})));
  out.emplace_back("comment",
      garctest::ZipBuilder().add("a.txt", "alpha\n").add("b.txt", "beta\n")
          .comment("a comment").build());
  out.emplace_back("zip64",
      garctest::ZipBuilder().add("a.txt", "alpha\n").zip64().zip64_plain_counts()
          .build());
  return out;
}

} // namespace

TEST(Zip, APipeThatFailsAnywhereReportsTheFailure) {
  // Every read of the walk failed in turn, through a pipe that also hands over
  // a few bytes at a time: wherever the failure lands - a local header, a
  // codec's input, a descriptor, the directory, the end records - the walk
  // ends with the stream's own status, not a verdict on bytes it never saw.
  size_t points = 0;
  for (const auto & [label, bytes] : pipe_population()) {
    for (const size_t cap : {size_t(0), size_t(7), size_t(1)}) {
      SCOPED_TRACE(label + " in reads of " + std::to_string(cap));
      std::vector<std::pair<std::string, std::string>> want;
      size_t reads = 0;
      ASSERT_EQ(GARC_OK, walk_pipe_source(bytes, cap, SIZE_MAX, &reads, &want));
      ASSERT_FALSE(want.empty());
      for (size_t k = 0; k < reads; ++k) {
        std::vector<std::pair<std::string, std::string>> got;
        size_t unused = 0;
        EXPECT_EQ(GARC_ERR_IO, walk_pipe_source(bytes, cap, k, &unused, &got))
            << "failing read " << k << " of " << reads;
        ++points;
      }
    }
  }
  // Short reads are what make this a sweep: whole reads are a handful per
  // archive, and every arm past the first read would go unvisited. 4,850
  // when this was written.
  EXPECT_GT(points, 4500u) << points;
}

TEST(Zip, StoredMembersBehindADescriptorAreReadOnAPipe) {
  // The end is the first descriptor whose CRC-32 and sizes are the data's so
  // far. A descriptor's signature inside the data that does not fit is data,
  // and so is a whole stored zip, whose own descriptor fits its own member and
  // not the bytes around it.
  const std::vector<uint8_t> inner = descriptor_zip(
      GARC_ZIP_METHOD_STORED, {{"inner.txt", "inner\n"}});
  ASSERT_FALSE(inner.empty());
  const std::vector<std::pair<std::string, std::string>> files = {
      {"plain.txt", patterned(5000, 3)},
      {"empty.txt", ""},
      {"signature.bin", std::string("before PK\x07\x08 and after", 21)},
      {"tail-signature.bin", std::string("ends in PK\x07\x08", 12)},
      {"inner.zip", std::string(inner.begin(), inner.end())},
      {"last.txt", "last\n"}};
  for (const bool zip64 : {false, true}) {
    SCOPED_TRACE(zip64 ? "zip64 descriptors" : "32-bit descriptors");
    std::vector<uint8_t> bytes;
    if (!zip64) {
      bytes = descriptor_zip(GARC_ZIP_METHOD_STORED, files);
    }
    else {
      GARC_Sink * sink = nullptr;
      ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
      GARC_Writer_Options options;
      garc_writer_options_default(&options);
      options.zip_method = GARC_ZIP_METHOD_STORED;
      options.zip_sizes = GARC_ZIP_SIZES_DESCRIPTOR;
      options.zip_force_zip64 = 1;
      GARC_Writer * writer = nullptr;
      ASSERT_EQ(garc_writer_create(sink, GARC_FORMAT_ZIP, &options, &writer), GARC_OK);
      for (const auto & file : files) {
        GARC_Member member;
        std::memset(&member, 0, sizeof(member));
        member.name = file.first.data();
        member.name_length = file.first.size();
        member.type = GARC_MEMBER_FILE;
        member.size = file.second.size();
        ASSERT_EQ(garc_writer_add(writer, &member), GARC_OK);
        ASSERT_EQ(garc_writer_write(writer, file.second.data(), file.second.size()),
            GARC_OK);
      }
      ASSERT_EQ(garc_writer_finish(writer), GARC_OK);
      const void * raw = nullptr;
      size_t length = 0;
      ASSERT_EQ(garc_sink_data(sink, &raw, &length), GARC_OK);
      bytes.assign(static_cast<const uint8_t *>(raw),
          static_cast<const uint8_t *>(raw) + length);
      garc_writer_destroy(writer);
      garc_sink_destroy(sink);
    }
    // A descriptor on every member - but the empty one, whose header a pipe
    // writer fills in - or this is not the case it says it is.
    size_t described = 0;
    for (const uint16_t flags : local_flags(bytes)) {
      described += (flags & 0x0008u) ? 1u : 0u;
    }
    EXPECT_GE(described, files.size() - (zip64 ? 0u : 1u));
    for (const size_t cap : {size_t(0), size_t(1), size_t(5)}) {
      SCOPED_TRACE(cap);
      std::vector<std::pair<std::string, std::string>> got;
      size_t reads = 0;
      ASSERT_EQ(GARC_OK, walk_pipe_source(bytes, cap, SIZE_MAX, &reads, &got));
      EXPECT_TRUE(got == files);
    }
  }
}

TEST(Zip, AForgedDescriptorInStoredDataDoesNotReadAsGood) {
  // Data can hold a descriptor that fits the bytes before it, by design. The
  // walk then ends the member there - and the rest of the data, read as
  // what follows, or the directory, which has the real sizes, refuses the
  // archive: it is never read to its end.
  const std::string head = "the member ends here, says the forgery";
  uint8_t forged[16] = {'P', 'K', 7, 8};
  const uint32_t crc = gcomp_crc32_finalize(gcomp_crc32_update(GCOMP_CRC32_INIT,
      reinterpret_cast<const uint8_t *>(head.data()), head.size()));
  for (int i = 0; i < 4; ++i) {
    forged[4 + i] = static_cast<uint8_t>(crc >> (8 * i));
    forged[8 + i] = static_cast<uint8_t>(head.size() >> (8 * i));
    forged[12 + i] = static_cast<uint8_t>(head.size() >> (8 * i));
  }
  const std::string data = head + std::string(reinterpret_cast<char *>(forged), 16)
      + "and the rest of it";
  const std::vector<uint8_t> bytes = descriptor_zip(
      GARC_ZIP_METHOD_STORED, {{"forged.bin", data}, {"next.txt", "next\n"}});
  ASSERT_FALSE(bytes.empty());
  std::vector<std::pair<std::string, std::string>> got;
  size_t reads = 0;
  EXPECT_NE(GARC_OK, walk_pipe_source(bytes, 0, SIZE_MAX, &reads, &got));
  // Seekably, from the directory, it is the member it is.
  std::vector<std::pair<std::string, std::string>> seek;
  EXPECT_EQ(GARC_OK, walk_parts({bytes}, &seek));
  ASSERT_EQ(seek.size(), 2u);
  EXPECT_EQ(seek[0].second, data);
}

TEST(Zip, AnEncryptedMemberWhoseSizesDisagreeIsCorruptOnAPipe) {
  // The size checks garc_zip_next() makes before the password - a stored
  // payload is the size, framing removed - made for a member the pipe only
  // lists, its data refused for want of one. fuzz_zip found an AES-192 member
  // stored with 19 payload bytes and a size of 15 read to the end off a pipe.
  std::string plain = "fifteen bytes!!";
  std::string extra;
  garctest::ZipBuilder::append16(extra, 0x9901u);
  garctest::ZipBuilder::append16(extra, 7u);
  garctest::ZipBuilder::append16(extra, 2u); // AE-2
  extra += "AE";
  extra.push_back(2); // AES-192: 12 salt, 2 verifier, 10 tag
  garctest::ZipBuilder::append16(extra, 0u); // stored
  for (const size_t body : {plain.size(), plain.size() + 4u}) {
    SCOPED_TRACE(body);
    garctest::ZipBuilder builder;
    builder.add("hello.txt", std::string(24u + body, 'x'));
    builder.last().method = 99;
    builder.last().flags = 0x0001u;
    builder.last().crc = 0;
    builder.last().local_extra = extra;
    builder.last().central_extra = extra;
    builder.last().override_sizes = true;
    builder.last().central_size = static_cast<uint32_t>(plain.size());
    builder.last().central_compressed_size = static_cast<uint32_t>(24u + body);
    std::vector<uint8_t> bytes = builder.build();
    // The local header's sizes as the directory's.
    bytes[22] = static_cast<uint8_t>(plain.size());
    Piped piped(bytes);
    ASSERT_EQ(piped.open_result(), GARC_OK);
    const GARC_Member * member = nullptr;
    GARC_Result result;
    while ((result = garc_next(piped.archive(), &member)) == GARC_OK) {
    }
    EXPECT_EQ(result, body == plain.size() ? GARC_END : GARC_ERR_CORRUPT);
  }
}

TEST(Zip, StrongEncryptionIsRefusedByNameFromAFileAndFromAPipe) {
  // PKWARE's strong encryption is bits 0 and 6 together; nothing here reads
  // it, and both readers list the member and refuse its data by name rather
  // than take it for ZipCrypto. Bit 6 alone describes nothing and both ignore
  // it: fuzz_zip found the pipe refusing on it alone, and so skipping an LZMA
  // header the seekable reader checked.
  garctest::ZipBuilder builder;
  builder.add("secret.bin", std::string(40, 's'));
  builder.last().flags = 0x0041u;
  const std::vector<uint8_t> bytes = builder.build();
  for (const bool pipe : {false, true}) {
    SCOPED_TRACE(pipe ? "pipe" : "file");
    BufferSource source(bytes.data(), bytes.size(), !pipe, !pipe);
    GARC_Stream * stream = nullptr;
    ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK);
    GARC_Archive * archive = nullptr;
    ASSERT_EQ(garc_open(stream, nullptr, &archive), GARC_OK);
    garc_set_password(archive, "x", 1);
    const GARC_Member * member = nullptr;
    ASSERT_EQ(garc_next(archive, &member), GARC_OK);
    char buffer[16];
    size_t got = 0;
    EXPECT_EQ(garc_read_member(archive, buffer, sizeof(buffer), &got),
        GARC_ERR_UNSUPPORTED);
    EXPECT_EQ(garc_next(archive, &member), GARC_END);
    garc_close(archive);
    garc_stream_destroy(stream);
  }
}

TEST(Zip, AnEncryptionFlagOnlyTheLocalHeaderHasIsCorruptOnAPipe) {
  // The pipe decides whether a member is encrypted, or strongly encrypted,
  // from its local header and refuses its data; the seekable reader decides
  // from the directory and reads it, checking what the pipe never looked at.
  // So the bits must agree, or the archive reads two ways. fuzz_zip found the
  // strong-encryption bit unchecked, on an LZMA member whose header was bad.
  const std::vector<uint8_t> clean
      = garctest::ZipBuilder().add("a.txt", "alpha\n").build();
  for (const uint8_t bit : {uint8_t(0x01), uint8_t(0x40)}) {
    SCOPED_TRACE(static_cast<int>(bit));
    std::vector<uint8_t> bytes = clean;
    ASSERT_EQ(0, std::memcmp(bytes.data(), "PK\x03\x04", 4));
    bytes[6] = static_cast<uint8_t>(bytes[6] | bit);
    // Walked without reading the data, which is refused: the walk is refused
    // at the member (a ZipCrypto member shorter than its own header) or at the
    // directory, and is never read to its end.
    Piped piped(bytes);
    ASSERT_EQ(piped.open_result(), GARC_OK);
    const GARC_Member * member = nullptr;
    GARC_Result result;
    while ((result = garc_next(piped.archive(), &member)) == GARC_OK) {
    }
    EXPECT_EQ(result, GARC_ERR_CORRUPT);
  }
  Piped control(clean);
  ASSERT_EQ(control.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(control.archive(), &member), GARC_OK);
  EXPECT_EQ(garc_next(control.archive(), &member), GARC_END);
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

  garctest::MemStream out_capture;
  FILE * out = out_capture.file();
  ASSERT_NE(out, nullptr);
  garc_archive_dump(fixture.archive(), out);
  out_capture.close();
  const std::string text = out_capture.text();

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
