/**
 * @file
 *
 * ::garc_find(): a scan from the start of the archive, and the refusal on a
 * source that cannot be rewound.
 *
 * Four things these tests are careful about.
 *
 * **The rewind has to be a real rewind.** A find that only searched forward
 * would pass every test that looks for a member the cursor has not reached yet,
 * and fail the only one that matters - asking for something already walked past.
 * So each positive case here is run *after* the archive has been walked to the
 * end, which is the state a forward-only search cannot recover from.
 *
 * **What a walk accumulates has to be cleared, and the pax record sets are the
 * ones that bite.** A `g` set applies to every member after it, so a second walk
 * that started holding the first walk's records would report names and times
 * that are not in the header it is reading. `pax-global.tar` exists for this and
 * is asserted through the find rather than only through the first walk.
 *
 * **The archive does not have to start at offset zero.** ::garc_open() takes a
 * stream *positioned at* an archive, so a find that seeked to 0 would work on
 * every fixture read the obvious way and break on an archive inside anything
 * else. There is a test that puts a prologue in front of the bytes.
 *
 * **The caps count a walk, not a session.** A find rewinds, so the second pass
 * counts the same members again; carrying the totals forward would make
 * ::garc_find() fail with a limit on an archive that merely *approaches* one.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "tar_builder.h"
#include "tar_manifest.h"
#include "test_helpers.h"

using garctest::BufferSource;
using garctest::TarArchive;
using garctest::file_header;
using garctest::long_header;
using garctest::pax_header;
using garctest::pax_record;
using garctest::read_fixture;

namespace {

/** Where the committed fixtures are. */
std::string data_path(const std::string & name) {
  return std::string(GARC_TEST_DATA) + "/tar/" + name;
}

/** A member's name as a std::string, using the length rather than a NUL. */
std::string member_name(const GARC_Member * member) {
  return std::string(member->name, member->name_length);
}

/** One fixture, opened over a seekable memory stream. */
class Fixture {
public:
  explicit Fixture(const std::string & name)
      : bytes_(read_fixture(data_path(name))) {
    EXPECT_FALSE(bytes_.empty()) << name << " is empty or missing";
    EXPECT_EQ(GARC_OK,
        garc_stream_create_memory(bytes_.data(), bytes_.size(), &stream_));
    EXPECT_EQ(GARC_OK, garc_open(stream_, nullptr, &archive_));
  }

  /** As above, with @p limits instead of the defaults. */
  Fixture(const std::string & name, const GARC_Limits * limits)
      : bytes_(read_fixture(data_path(name))) {
    EXPECT_FALSE(bytes_.empty()) << name << " is empty or missing";
    EXPECT_EQ(GARC_OK,
        garc_stream_create_memory(bytes_.data(), bytes_.size(), &stream_));
    EXPECT_EQ(GARC_OK, garc_open(stream_, limits, &archive_));
  }

  ~Fixture() {
    garc_close(archive_);
    garc_stream_destroy(stream_);
  }

  Fixture(const Fixture &) = delete;
  Fixture & operator=(const Fixture &) = delete;

  GARC_Archive * archive() const { return archive_; }

  /** Walk to the end, so a later find has to go backwards to succeed. */
  void exhaust() {
    const GARC_Member * member = nullptr;
    GARC_Result result;
    while ((result = garc_next(archive_, &member)) == GARC_OK) {
    }
    EXPECT_EQ(GARC_END, result);
  }

  /** Every member's name, in order. */
  std::vector<std::string> walk() {
    std::vector<std::string> names;
    const GARC_Member * member = nullptr;
    while (garc_next(archive_, &member) == GARC_OK) {
      names.push_back(member_name(member));
    }
    return names;
  }

private:
  std::vector<uint8_t> bytes_;
  GARC_Stream * stream_ = nullptr;
  GARC_Archive * archive_ = nullptr;
};

/** An archive assembled in memory, for shapes the corpus does not contain. */
class Built {
public:
  explicit Built(std::vector<uint8_t> bytes) : bytes_(std::move(bytes)) {
    EXPECT_EQ(GARC_OK,
        garc_stream_create_memory(bytes_.data(), bytes_.size(), &stream_));
    EXPECT_EQ(GARC_OK, garc_open(stream_, nullptr, &archive_));
  }

  ~Built() {
    garc_close(archive_);
    garc_stream_destroy(stream_);
  }

  Built(const Built &) = delete;
  Built & operator=(const Built &) = delete;

  GARC_Archive * archive() const { return archive_; }

private:
  std::vector<uint8_t> bytes_;
  GARC_Stream * stream_ = nullptr;
  GARC_Archive * archive_ = nullptr;
};

/** garc_find() with a std::string, which is how every case here spells it. */
GARC_Result find(GARC_Archive * archive, const std::string & name,
    const GARC_Member ** out_member) {
  return garc_find(archive, name.data(), name.size(), out_member);
}

} // namespace

////////////////////////////////////////////////////////////////////////
// Finding, from anywhere in the walk
////////////////////////////////////////////////////////////////////////

TEST(Find, FindsTheFirstMember) {
  Fixture fixture("ustar-basic.tar");
  const GARC_Member * member = nullptr;
  ASSERT_EQ(GARC_OK, find(fixture.archive(), "hello.txt", &member));
  ASSERT_NE(nullptr, member);
  EXPECT_EQ("hello.txt", member_name(member));
}

TEST(Find, FindsTheLastMember) {
  Fixture fixture("ustar-basic.tar");
  const GARC_Member * member = nullptr;
  ASSERT_EQ(GARC_OK, find(fixture.archive(), "hardlink", &member));
  EXPECT_EQ("hardlink", member_name(member));
}

TEST(Find, FindsAMemberTheWalkHasAlreadyPassed) {
  // The case a forward-only search cannot answer, and the reason this function
  // rewinds rather than scanning from the cursor.
  Fixture fixture("ustar-basic.tar");
  fixture.exhaust();
  const GARC_Member * member = nullptr;
  ASSERT_EQ(GARC_OK, find(fixture.archive(), "hello.txt", &member));
  EXPECT_EQ("hello.txt", member_name(member));
}

TEST(Find, FindsBackwardsTwiceInARow) {
  // Each find must leave the archive in a state the next one can rewind from,
  // which a single find cannot demonstrate.
  Fixture fixture("ustar-sizes.tar");
  const GARC_Member * member = nullptr;
  ASSERT_EQ(GARC_OK, find(fixture.archive(), "sizes/block+1", &member));
  EXPECT_EQ("sizes/block+1", member_name(member));
  ASSERT_EQ(GARC_OK, find(fixture.archive(), "sizes/", &member));
  EXPECT_EQ("sizes/", member_name(member));
  ASSERT_EQ(GARC_OK, find(fixture.archive(), "sizes/block-1", &member));
  EXPECT_EQ("sizes/block-1", member_name(member));
}

TEST(Find, AMissingNameIsTheEndAndNotAnError) {
  Fixture fixture("ustar-basic.tar");
  const GARC_Member * member = nullptr;
  EXPECT_EQ(GARC_END, find(fixture.archive(), "not-in-here", &member));
  EXPECT_FALSE(garc_result_is_error(GARC_END));
  // And the archive is where a completed walk leaves it.
  const GARC_Member * after = nullptr;
  EXPECT_EQ(GARC_END, garc_next(fixture.archive(), &after));
}

TEST(Find, AnEmptyNameMatchesNothing) {
  Fixture fixture("ustar-basic.tar");
  const GARC_Member * member = nullptr;
  EXPECT_EQ(GARC_END, garc_find(fixture.archive(), nullptr, 0, &member));
}

////////////////////////////////////////////////////////////////////////
// What the cursor is afterwards
////////////////////////////////////////////////////////////////////////

TEST(Find, TheFoundMembersDataIsReadable) {
  Fixture fixture("ustar-basic.tar");
  fixture.exhaust();
  const GARC_Member * member = nullptr;
  ASSERT_EQ(GARC_OK, find(fixture.archive(), "hello.txt", &member));
  ASSERT_GT(member->size, 0u);

  std::string content;
  for (;;) {
    char buffer[64];
    size_t read = 0;
    ASSERT_EQ(GARC_OK,
        garc_read_member(fixture.archive(), buffer, sizeof(buffer), &read));
    if (!read) {
      break;
    }
    content.append(buffer, read);
  }
  EXPECT_EQ(member->size, content.size());
  // The bytes, not a substring of them: a find that positioned the cursor one
  // block out would still hand back the right *number* of bytes.
  EXPECT_EQ("hello, archive\n", content);
}

TEST(Find, TheWalkContinuesAfterTheFoundMember) {
  Fixture fixture("ustar-basic.tar");
  const GARC_Member * member = nullptr;
  ASSERT_EQ(GARC_OK, find(fixture.archive(), "emptydir/", &member));
  std::vector<std::string> rest = fixture.walk();
  EXPECT_EQ(std::vector<std::string>({"link-to-hello", "hardlink"}), rest);
}

TEST(Find, TheMemberCountBecomesTheFoundMembersPosition) {
  // Documented in reader.h rather than hidden: the count describes the walk that
  // is current, and a find starts a new one. After this find it is 4, because
  // four members were handed out to reach the fourth.
  Fixture fixture("ustar-basic.tar");
  fixture.exhaust();
  EXPECT_EQ(4u, garc_member_count(fixture.archive()));
  const GARC_Member * member = nullptr;
  ASSERT_EQ(GARC_OK, find(fixture.archive(), "hello.txt", &member));
  EXPECT_EQ(1u, garc_member_count(fixture.archive()));
  ASSERT_EQ(GARC_OK, find(fixture.archive(), "hardlink", &member));
  EXPECT_EQ(4u, garc_member_count(fixture.archive()));
}

////////////////////////////////////////////////////////////////////////
// The name is matched as bytes
////////////////////////////////////////////////////////////////////////

TEST(Find, ADirectoryIsFoundUnderTheNameTheArchiveCarries) {
  // `sizes/` is what the header says, so `sizes` is a different name. A find
  // that stripped the slash would be normalising where garc_next() does not.
  Fixture fixture("ustar-sizes.tar");
  const GARC_Member * member = nullptr;
  ASSERT_EQ(GARC_OK, find(fixture.archive(), "sizes/", &member));
  EXPECT_EQ("sizes/", member_name(member));
  EXPECT_EQ(GARC_END, find(fixture.archive(), "sizes", &member));
}

TEST(Find, ANonAsciiNameIsMatchedByItsBytes) {
  Fixture fixture("ustar-nonascii.tar");
  const GARC_Member * member = nullptr;
  ASSERT_EQ(GARC_OK, find(fixture.archive(), "na\xC3\xAFve.txt", &member));
  EXPECT_EQ("na\xC3\xAFve.txt", member_name(member));
}

TEST(Find, APrefixedNameIsFoundUnderTheJoinedName) {
  // ustar splits a long name across two fields and the reader joins them, so the
  // name to search for is the joined one - the find sees what garc_next() would
  // have reported, not the bytes of either field.
  Fixture fixture("ustar-prefix.tar");
  std::vector<std::string> names = fixture.walk();
  ASSERT_FALSE(names.empty());
  const std::string & last = names.back();
  ASSERT_NE(std::string::npos, last.find('/'));
  const GARC_Member * member = nullptr;
  ASSERT_EQ(GARC_OK, find(fixture.archive(), last, &member));
  EXPECT_EQ(last, member_name(member));
}

////////////////////////////////////////////////////////////////////////
// State a second walk must not inherit
////////////////////////////////////////////////////////////////////////

TEST(Find, APaxGlobalRecordSetIsReplayedAndNotInherited) {
  // The rewind's hardest case. A `g` set applies to every member after it, so a
  // second walk holding the first walk's records would apply them to the header
  // it is reading. Compared against the first walk's own answer, which is what
  // the corpus tests already pin against a reference.
  Fixture fixture("pax-global.tar");
  std::vector<std::string> first = fixture.walk();
  ASSERT_FALSE(first.empty());

  const GARC_Member * member = nullptr;
  ASSERT_EQ(GARC_OK, find(fixture.archive(), first.front(), &member));
  EXPECT_EQ(first.front(), member_name(member));

  std::vector<std::string> rest = fixture.walk();
  std::vector<std::string> again;
  again.push_back(first.front());
  for (const std::string & name : rest) {
    again.push_back(name);
  }
  EXPECT_EQ(first, again);
}

TEST(Find, APaxLongNameIsFoundAfterARewind) {
  Fixture fixture("pax-longname.tar");
  std::vector<std::string> names = fixture.walk();
  ASSERT_FALSE(names.empty());
  const GARC_Member * member = nullptr;
  ASSERT_EQ(GARC_OK, find(fixture.archive(), names.back(), &member));
  EXPECT_EQ(names.back(), member_name(member));
}

TEST(Find, AGnuLongNameIsFoundAfterARewind) {
  // The other carrier. An `L` member is not handed to the caller, so a rewind
  // that left have_long_name set would attach a stale name to the first header
  // of the second walk.
  Fixture fixture("gnu-longname.tar");
  std::vector<std::string> names = fixture.walk();
  ASSERT_FALSE(names.empty());
  const GARC_Member * member = nullptr;
  ASSERT_EQ(GARC_OK, find(fixture.archive(), names.back(), &member));
  EXPECT_EQ(names.back(), member_name(member));
  // And the first member of the archive still reads as itself.
  ASSERT_EQ(GARC_OK, find(fixture.archive(), names.front(), &member));
  EXPECT_EQ(names.front(), member_name(member));
}

TEST(Find, EveryFixtureFindsEveryOneOfItsOwnMembers) {
  // A sweep rather than a sample, and it is the cheapest check that the rewind
  // leaves *nothing* behind: every member of every fixture is looked up after
  // the archive has been walked to its end, so any state the second pass
  // inherits shows up as a name that cannot be found.
  const char * const fixtures[] = {
    "v7-basic.tar", "ustar-basic.tar", "ustar-sizes.tar", "ustar-modes.tar",
    "ustar-owners.tar", "ustar-prefix.tar", "ustar-nonascii.tar",
    "gnu-longname.tar", "gnu-longname-blocks.tar", "gnu-longlink.tar",
    "pax-basic.tar", "pax-longname.tar", "pax-longlink.tar", "pax-times.tar",
    "pax-global.tar",
  };
  size_t looked_up = 0;
  for (const char * name : fixtures) {
    SCOPED_TRACE(name);
    Fixture fixture(name);
    std::vector<std::string> names = fixture.walk();
    ASSERT_FALSE(names.empty());
    for (const std::string & wanted : names) {
      SCOPED_TRACE(wanted);
      const GARC_Member * member = nullptr;
      ASSERT_EQ(GARC_OK, find(fixture.archive(), wanted, &member));
      EXPECT_EQ(wanted, member_name(member));
      ++looked_up;
    }
  }
  // The denominator, asserted: a fixture list that silently stopped loading
  // would make every assertion above vacuous.
  EXPECT_GT(looked_up, 40u) << "only " << looked_up << " names were looked up";
}

////////////////////////////////////////////////////////////////////////
// The refusal
////////////////////////////////////////////////////////////////////////

TEST(Find, ASourceThatCannotSeekIsRefused) {
  std::vector<uint8_t> bytes = read_fixture(data_path("ustar-basic.tar"));
  ASSERT_FALSE(bytes.empty());
  BufferSource source(bytes.data(), bytes.size(), false, false);
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(GARC_OK, garc_stream_create_callback(source.callbacks(), &stream));
  GARC_Archive * archive = nullptr;
  ASSERT_EQ(GARC_OK, garc_open(stream, nullptr, &archive));

  const GARC_Member * member = nullptr;
  EXPECT_EQ(GARC_ERR_NOT_SEEKABLE, find(archive, "hello.txt", &member));
  EXPECT_EQ(nullptr, member);
  EXPECT_TRUE(garc_result_is_error(GARC_ERR_NOT_SEEKABLE));
  EXPECT_FALSE(garc_result_is_limit(GARC_ERR_NOT_SEEKABLE));

  // Refused before anything moved: the walk still begins at the first member.
  ASSERT_EQ(GARC_OK, garc_next(archive, &member));
  EXPECT_EQ("hello.txt", member_name(member));
  EXPECT_EQ(0u, source.seeks());

  garc_close(archive);
  garc_stream_destroy(stream);
}

TEST(Find, AFailingSeekIsReportedRatherThanIgnored) {
  std::vector<uint8_t> bytes = read_fixture(data_path("ustar-basic.tar"));
  ASSERT_FALSE(bytes.empty());
  BufferSource source(bytes.data(), bytes.size(), true, true);
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(GARC_OK, garc_stream_create_callback(source.callbacks(), &stream));
  GARC_Archive * archive = nullptr;
  ASSERT_EQ(GARC_OK, garc_open(stream, nullptr, &archive));
  source.fail_seeks();
  const GARC_Member * member = nullptr;
  EXPECT_EQ(GARC_ERR_IO, find(archive, "hello.txt", &member));
  garc_close(archive);
  garc_stream_destroy(stream);
}

TEST(Find, NullArgumentsAreRefused) {
  Fixture fixture("ustar-basic.tar");
  const GARC_Member * member = nullptr;
  EXPECT_EQ(GARC_ERR_INVALID, garc_find(nullptr, "x", 1, &member));
  EXPECT_EQ(GARC_ERR_INVALID, garc_find(fixture.archive(), nullptr, 1, &member));
  EXPECT_EQ(GARC_ERR_INVALID, garc_find(fixture.archive(), "x", 1, nullptr));
}

////////////////////////////////////////////////////////////////////////
// An archive that does not begin at offset zero
////////////////////////////////////////////////////////////////////////

TEST(Find, AnArchiveStartingPartWayThroughAStreamIsRewoundToItsOwnStart) {
  // garc_open() takes a stream *positioned at* an archive. A find that seeked to
  // 0 would work on every other test in this file and break here, which is why
  // the start offset is taken at open rather than assumed.
  std::vector<uint8_t> tar = read_fixture(data_path("ustar-basic.tar"));
  ASSERT_FALSE(tar.empty());
  const std::string prologue = "not part of the archive; 25 bytes long...";
  std::vector<uint8_t> bytes(prologue.begin(), prologue.end());
  const uint64_t offset = bytes.size();
  bytes.insert(bytes.end(), tar.begin(), tar.end());

  GARC_Stream * stream = nullptr;
  ASSERT_EQ(GARC_OK,
      garc_stream_create_memory(bytes.data(), bytes.size(), &stream));
  // The caller reads its own prologue, then hands the stream over.
  ASSERT_EQ(GARC_OK, garc_stream_seek(stream, offset));
  ASSERT_EQ(offset, garc_stream_tell(stream));

  GARC_Archive * archive = nullptr;
  ASSERT_EQ(GARC_OK, garc_open(stream, nullptr, &archive));
  const GARC_Member * member = nullptr;
  GARC_Result result;
  while ((result = garc_next(archive, &member)) == GARC_OK) {
  }
  ASSERT_EQ(GARC_END, result);

  ASSERT_EQ(GARC_OK, find(archive, "hello.txt", &member));
  EXPECT_EQ("hello.txt", member_name(member));
  ASSERT_EQ(GARC_OK, find(archive, "hardlink", &member));
  EXPECT_EQ("hardlink", member_name(member));

  garc_close(archive);
  garc_stream_destroy(stream);
}

////////////////////////////////////////////////////////////////////////
// Caps
////////////////////////////////////////////////////////////////////////

TEST(Find, ACapThatTheFirstWalkFitsDoesNotFireOnTheSecond) {
  // ustar-basic.tar has four members. With max_members at exactly four, a find
  // that carried the first walk's count forward would trip the cap on the fifth
  // member of a four-member archive.
  GARC_Limits limits;
  garc_limits_default(&limits);
  limits.max_members = 4;
  Fixture fixture("ustar-basic.tar", &limits);
  fixture.exhaust();
  const GARC_Member * member = nullptr;
  ASSERT_EQ(GARC_OK, find(fixture.archive(), "hardlink", &member));
  EXPECT_EQ("hardlink", member_name(member));
}

TEST(Find, ACapSmallerThanThePositionStillFires) {
  // The other direction, so the reset is not mistaken for the cap being
  // switched off: the scan is a walk and the caps apply to it.
  GARC_Limits limits;
  garc_limits_default(&limits);
  limits.max_members = 2;
  Fixture fixture("ustar-basic.tar", &limits);
  const GARC_Member * member = nullptr;
  EXPECT_EQ(GARC_ERR_LIMIT_MEMBERS, find(fixture.archive(), "hardlink", &member));
}

////////////////////////////////////////////////////////////////////////
// Two shapes the committed corpus cannot separate
////////////////////////////////////////////////////////////////////////

TEST(Find, AGlobalRecordSetAfterAMemberIsNotAppliedToItOnASecondWalk) {
  // **`pax-global.tar` cannot test this and the mutation testing said so.** Its
  // `g` record is the first thing in the archive, so a second walk re-reads it
  // and arrives at the same state whether or not the rewind cleared it - the two
  // behaviours are identical on that input.
  //
  // Here the `g` set comes *after* the first member, so at the end of a walk the
  // reader holds a global `uname` the first member does not have. A rewind that
  // inherited it would report the first member as owned by `ghost`.
  const std::string global = pax_record("uname", "ghost");
  TarArchive built;
  built.header(file_header("first.txt", 5u))
      .data("first")
      .header(pax_header('g', global.size()))
      .data(global)
      .header(file_header("second.txt", 6u))
      .data("second")
      .marker();

  Built archive(built.bytes());

  // Walk it once, which is what leaves the global set in hand.
  const GARC_Member * member = nullptr;
  std::string first_uname;
  int seen = 0;
  while (garc_next(archive.archive(), &member) == GARC_OK) {
    if (++seen == 1) {
      first_uname.assign(member->uname, member->uname_length);
    }
  }
  ASSERT_EQ(2, seen);
  EXPECT_EQ("", first_uname) << "the fixture is wrong: the first member should "
                               "have no owner name before the g record";

  // And now the same member, found rather than walked to.
  ASSERT_EQ(GARC_OK, find(archive.archive(), "first.txt", &member));
  EXPECT_EQ("first.txt", member_name(member));
  EXPECT_EQ(first_uname, std::string(member->uname, member->uname_length))
      << "a global record from later in the archive was applied to an earlier "
         "member";

  // The member that *is* covered by the global set still is, so the reset did
  // not simply switch global records off.
  ASSERT_EQ(GARC_OK, find(archive.archive(), "second.txt", &member));
  EXPECT_EQ("ghost", std::string(member->uname, member->uname_length));
}

TEST(Find, ALongNameLeftOverByAFailedWalkIsNotAppliedToTheFirstMember) {
  // The other equivalence the corpus hides. A GNU `L` carrier is always
  // consumed by the member right after it, so at the end of a *successful* walk
  // the pending-name flag is already clear and clearing it again changes
  // nothing. It is only set at the end of a walk that **stopped between the
  // carrier and its member** - so the archive has to fail there.
  const std::string stale = "stale-name-from-a-failed-walk";
  TarArchive built;
  built.header(file_header("real.txt", 4u))
      .data("real")
      .header(long_header('L', stale.size() + 1u))
      .data(stale + std::string(1, '\0'));
  // Where the named member's header should be: a block that is not a header at
  // all, so the walk fails with the carrier's name still pending.
  built.raw(std::vector<uint8_t>(512u, 0x41u));
  built.marker();

  Built archive(built.bytes());
  const GARC_Member * member = nullptr;
  ASSERT_EQ(GARC_OK, garc_next(archive.archive(), &member));
  EXPECT_EQ("real.txt", member_name(member));
  // The failure that leaves a name pending.
  ASSERT_TRUE(garc_result_is_error(garc_next(archive.archive(), &member)));

  ASSERT_EQ(GARC_OK, find(archive.archive(), "real.txt", &member));
  EXPECT_EQ("real.txt", member_name(member))
      << "a name left pending by a failed walk was applied to the first member "
         "of the next one";
}

TEST(Find, ATruncatedTailIsStillCorruptOnASecondWalk) {
  // `tar_saw_end_marker` is the last piece of per-walk state, and it decides
  // whether a partial trailing block is a clean end or damage. A rewind that
  // kept it would make the second walk over a truncated archive report the end
  // of a well-formed one - the difference between "this file is short" and "this
  // file is fine", on exactly the input where it matters.
  //
  // The archive here ends mid-block with no marker at all, so a walk must reach
  // GARC_ERR_CORRUPT rather than GARC_END.
  TarArchive built;
  built.header(file_header("only.txt", 4u)).data("only");
  built.raw(std::vector<uint8_t>(200u, 0u)); // a partial block, and no marker

  Built archive(built.bytes());
  const GARC_Member * member = nullptr;
  ASSERT_EQ(GARC_OK, garc_next(archive.archive(), &member));
  EXPECT_EQ("only.txt", member_name(member));
  ASSERT_EQ(GARC_ERR_CORRUPT, garc_next(archive.archive(), &member));

  // Found, so the walk stops before the damage.
  ASSERT_EQ(GARC_OK, find(archive.archive(), "only.txt", &member));
  EXPECT_EQ("only.txt", member_name(member));

  // And not found, so the walk runs into the damage again and says so. This is
  // the assertion the stale flag breaks: it would answer GARC_END.
  EXPECT_EQ(GARC_ERR_CORRUPT, find(archive.archive(), "absent.txt", &member));
}

int main(int argc, char ** argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
