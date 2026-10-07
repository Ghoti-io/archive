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

#include <ghoti.io/security/sha256.h>

#include "test_helpers.h"
#include "zip_builder.h"
#include "zip_manifest.h"

using garctest::BufferSource;
using garctest::ZipDecryptedRow;
using garctest::ZipManifestRow;
using garctest::ZipNameRow;
using garctest::ZipOpeningRow;
using garctest::read_fixture;
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
  options.zip_password = kCorpusPassword;
  options.zip_password_length = std::strlen(kCorpusPassword);
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
    ASSERT_EQ(garc_zip_set_password(fixture.archive(), kCorpusPassword,
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
  // And the encrypted members are in it rather than skipped past, which is what
  // makes this test cover the cipher as well as the codec.
  EXPECT_GE(encrypted, 4u);
  EXPECT_GE(unsupported, 2u) << "ppmd, deflate64";
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
    ASSERT_EQ(garc_zip_set_password(fixture.archive(), kCorpusPassword,
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
  ASSERT_EQ(garc_zip_set_password(fixture.archive(), kCorpusPassword,
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
  ASSERT_EQ(garc_zip_set_password(fixture.archive(), "wrong", 5u), GARC_OK);

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
  ASSERT_EQ(garc_zip_set_password(fixture.archive(), "wrong", 5u), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(fixture.archive(), &member), GARC_OK);

  char buffer[64];
  size_t got = 0;
  ASSERT_EQ(garc_read_member(fixture.archive(), buffer, sizeof(buffer), &got),
      GARC_ERR_PASSWORD_REJECTED);

  ASSERT_EQ(garc_zip_set_password(fixture.archive(), kCorpusPassword,
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
  // The reason garc_zip_set_password() takes a length rather than a string, and
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

  ASSERT_EQ(garc_zip_set_password(fixture.archive(), "", 0u), GARC_OK);
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
  ASSERT_EQ(garc_zip_set_password(fixture.archive(), kCorpusPassword,
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
  EXPECT_EQ(garc_zip_set_password(archive, "x", 1u), GARC_ERR_INVALID);
  EXPECT_EQ(garc_zip_set_password(nullptr, "x", 1u), GARC_ERR_INVALID);
  garc_close(archive);
  garc_stream_destroy(stream);
}

TEST(ZipCrypto, ANullPasswordWithALengthIsRefused) {
  Fixture fixture("infozip-crypto.zip");
  ASSERT_EQ(fixture.open_result(), GARC_OK);
  EXPECT_EQ(garc_zip_set_password(fixture.archive(), nullptr, 4u),
      GARC_ERR_INVALID);
  // And a NULL password of length zero is the empty password, not an error: the
  // two arms of that condition are separate lines in the implementation and this
  // is what stops one of them being written as the other.
  EXPECT_EQ(garc_zip_set_password(fixture.archive(), nullptr, 0u), GARC_OK);
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
  ASSERT_EQ(garc_zip_set_password(fixture.archive(), "not-the-password", 16u),
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
  ASSERT_EQ(garc_zip_set_password(fixture.archive(), "not-the-password", 16u),
      GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(fixture.archive(), &member), GARC_OK);

  char buffer[64];
  size_t got = 0;
  ASSERT_EQ(garc_read_member(fixture.archive(), buffer, sizeof(buffer), &got),
      GARC_ERR_PASSWORD_REJECTED);

  ASSERT_EQ(garc_zip_set_password(fixture.archive(), kCorpusPassword,
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
  ASSERT_EQ(garc_zip_set_password(
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
