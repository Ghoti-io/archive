/**
 * @file
 *
 * The tar header, on inputs no reference writes.
 *
 * The generated corpus covers what GNU tar produces; this covers the complement.
 * Every archive here is **hand-built** - said out loud because it is the
 * difference between an assertion about the format and an assertion about what
 * `tests/tar_builder.h` happens to construct - and each one is here because a
 * real writer will not produce it on request: damage, a spelling that went out
 * of use decades ago, or a field at a limit.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstdint>
#include <set>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "tar_builder.h"
#include "test_helpers.h"

// The accounting function and the archive struct are internal. The tests link
// the static archive, so a hidden symbol resolves; this is the one test here
// that needs it, and it needs it because the case it covers cannot be reached
// through the public API on a tar. See TheTotalCannotBeDefeatedByOverflow.
#include "reader/reader_internal.h"

using garctest::BufferSource;
using garctest::file_header;
using garctest::kTarBlock;
using garctest::long_header;
using garctest::TarArchive;
using garctest::TarHeader;

namespace {

/** Open a hand-built archive over a memory stream. */
struct Opened {
  GARC_Stream * stream = nullptr;
  GARC_Archive * archive = nullptr;
  std::vector<uint8_t> bytes;

  ~Opened() {
    garc_close(archive);
    garc_stream_destroy(stream);
  }
};

/** Open `bytes`, returning the result of garc_open(). */
GARC_Result open_bytes(Opened & opened, const std::vector<uint8_t> & bytes,
    const GARC_Limits * limits = nullptr) {
  opened.bytes = bytes;
  if (garc_stream_create_memory(
          opened.bytes.data(), opened.bytes.size(), &opened.stream)
      != GARC_OK) {
    return GARC_ERR_OOM;
  }
  return garc_open(opened.stream, limits, &opened.archive);
}

std::string name_of(const GARC_Member * member) {
  return std::string(member->name, member->name_length);
}

/** Read a member's whole data through repeated garc_read_member() calls. */
GARC_Result read_all(GARC_Archive * archive, std::string * out) {
  out->clear();
  char buffer[7]; // Deliberately not a divisor of a block, nor of any size here.
  for (;;) {
    size_t got = 0;
    GARC_Result result
        = garc_read_member(archive, buffer, sizeof(buffer), &got);
    if (result != GARC_OK) {
      return result;
    }
    if (!got) {
      return GARC_OK;
    }
    out->append(buffer, got);
  }
}

} // namespace

//-----------------------------------------------------------------------------
// The checksum
//-----------------------------------------------------------------------------

TEST(TarHeaderChecksum, ASignedSumIsAcceptedAndReported) {
  // Hand-built: no writer in the pinned container produces a signed checksum, so
  // the accepting branch cannot be put in a position to fail by any generated
  // fixture. The two sums differ only when a header holds a byte above 0x7F, so
  // the name carries one - without it this test would pass against a reader that
  // ignored the signed reading entirely.
  TarHeader header = file_header("caf\xC3\xA9.txt", 0);
  header.checksum(true);

  TarArchive archive;
  archive.header(header).marker();

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);

  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_EQ(name_of(member), "caf\xC3\xA9.txt");
  EXPECT_TRUE(garc_tar_member_checksum_was_signed(opened.archive))
      << "the unsigned reading matched, so this header does not test the "
         "signed one - check that the name still has a byte above 0x7F";
}

TEST(TarHeaderChecksum, TheUnsignedSumIsReportedAsUnsigned) {
  // The control for the test above. Without it, a reader that reported "signed"
  // unconditionally would pass that one.
  TarHeader header = file_header("caf\xC3\xA9.txt", 0);

  TarArchive archive;
  archive.header(header).marker();

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);

  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_FALSE(garc_tar_member_checksum_was_signed(opened.archive));
}

TEST(TarHeaderChecksum, AWrongSumIsNotAnArchive) {
  // The checksum is the only evidence a v7 block is a header at all, so a wrong
  // one has to be refused at identification rather than at the member.
  TarHeader header = file_header("hello.txt", 0);
  header.bytes[148] = '9'; // Corrupt the first digit of the checksum field.

  TarArchive archive;
  archive.header(header).marker();

  Opened opened;
  EXPECT_EQ(open_bytes(opened, archive.bytes()), GARC_ERR_FORMAT);
}

TEST(TarHeaderChecksum, AWrongSumPartwayThroughIsCorruptRatherThanTheEnd) {
  // Refusing at identification and refusing mid-archive are different answers:
  // the first says "not a tar" and the second says "a tar with damage in it".
  // A reader that returned GARC_END here would hand back a truncated listing
  // and call it complete.
  TarHeader good = file_header("first.txt", 0);
  TarHeader bad = file_header("second.txt", 0);
  bad.bytes[148] = '9';

  TarArchive archive;
  archive.header(good).header(bad).marker();

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);

  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_EQ(name_of(member), "first.txt");
  EXPECT_EQ(garc_next(opened.archive, &member), GARC_ERR_CORRUPT);
}

//-----------------------------------------------------------------------------
// Numeric fields
//-----------------------------------------------------------------------------

TEST(TarHeaderNumbers, EveryTerminatorSpellingReadsTheSameValue) {
  // A field may end with a NUL, a space, both, or nothing when the digits fill
  // it exactly. A reader that stops at the first space reads 0 from " 0000644";
  // one that requires a NUL rejects a full field. All four spell 0644 here, and
  // the assertion is that they agree - which is stronger than each being right,
  // because a single wrong-but-consistent answer would fail it.
  const std::vector<std::vector<uint8_t>> spellings = {
    {'0', '0', '0', '0', '6', '4', '4', 0},     // zero-padded, NUL
    {'0', '0', '0', '0', '6', '4', '4', ' '},   // zero-padded, space
    {' ', ' ', ' ', '6', '4', '4', ' ', 0},     // space-padded, both
    {'0', '0', '0', '0', '0', '6', '4', '4'},   // full field, no terminator
  };

  for (size_t i = 0; i < spellings.size(); ++i) {
    SCOPED_TRACE("spelling " + std::to_string(i));
    TarHeader header = file_header("hello.txt", 0);
    header.raw(100, spellings[i]);
    header.checksum();

    TarArchive archive;
    archive.header(header).marker();

    Opened opened;
    ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);
    const GARC_Member * member = nullptr;
    ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
    EXPECT_TRUE(member->mode_valid);
    EXPECT_EQ(member->mode, 0644u);
  }
}

TEST(TarHeaderNumbers, ABlankFieldIsZeroRatherThanCorrupt) {
  // v7 writers leave a field they have no value for blank, and the device
  // numbers are blank in almost every archive there is. A reader that refuses a
  // blank field rejects the whole variant.
  TarHeader header = file_header("hello.txt", 0);
  header.raw(108, std::vector<uint8_t>(8, ' ')); // uid
  header.raw(116, std::vector<uint8_t>(8, 0));   // gid, all NUL
  header.checksum();

  TarArchive archive;
  archive.header(header).marker();

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_EQ(member->uid, 0);
  EXPECT_EQ(member->gid, 0);
}

TEST(TarHeaderNumbers, ANonOctalDigitInAnyFieldIsCorrupt) {
  // Every numeric field has its own refusal arm, and corrupting only the size
  // field - which is what the first version of this test did - leaves the other
  // six looking covered because the file was. The device fields are read only for
  // a device member, so that row carries the typeflag that makes them live.
  struct Row {
    const char * what;
    size_t offset;
    size_t width;
    char typeflag;
  };
  const Row rows[] = {
    {"mode", 100, 8, '0'},
    {"uid", 108, 8, '0'},
    {"gid", 116, 8, '0'},
    {"size", 124, 12, '0'},
    {"mtime", 136, 12, '0'},
    {"devmajor", 329, 8, '3'},
    {"devminor", 337, 8, '3'},
  };

  for (const Row & row : rows) {
    SCOPED_TRACE(row.what);
    TarHeader header = file_header("thing", 0, 0644u, row.typeflag);
    // '9' is not an octal digit. Filling the field with it rather than one byte
    // means the refusal cannot come from a terminator rule instead.
    header.raw(row.offset, std::vector<uint8_t>(row.width, '9'));
    header.checksum();

    TarArchive archive;
    archive.header(header).marker();

    Opened opened;
    ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK) << row.what;
    const GARC_Member * member = nullptr;
    EXPECT_EQ(garc_next(opened.archive, &member), GARC_ERR_CORRUPT)
        << row.what << " was not refused";
  }
}

TEST(TarHeaderNumbers, ANonOctalDigitIsCorrupt) {
  // '8' and '9' are not octal. Reading them as 8 and 9 would give a size off by
  // a factor a reader then seeks by.
  TarHeader header = file_header("hello.txt", 0);
  header.raw(124, {'0', '0', '0', '0', '0', '0', '0', '0', '0', '9', '9', 0});
  header.checksum();

  TarArchive archive;
  archive.header(header).marker();

  Opened opened;
  // Identification uses the checksum, which is still right - the field is a
  // number this reader refuses rather than damage to the block.
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);
  const GARC_Member * member = nullptr;
  EXPECT_EQ(garc_next(opened.archive, &member), GARC_ERR_CORRUPT);
}

TEST(TarHeaderNumbers, ABase256SizeIsRead) {
  // 11 octal digits cap a size at 8 GB, which is why GNU's extension exists.
  // A value that needs more than the 12-byte field's octal capacity is the only
  // way to show the base-256 branch is reached.
  const uint64_t big = (uint64_t)1u << 34; // 16 GiB: past the octal ceiling.
  TarHeader header = file_header("huge", 0);
  header.base256(124, 12, big);
  header.checksum();

  TarArchive archive;
  archive.header(header);
  // No data: the size is a claim, and this test is about reading the claim.
  archive.marker();

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_EQ(member->size, big);
}

TEST(TarHeaderNumbers, ABase256MtimeCanBeNegative) {
  // A time before the epoch is why the negative form exists, and the sign lives
  // in bit 6 of the first byte rather than in a leading 0xFF - so a reader that
  // only handles 0x80 and 0xFF gets this wrong for values in between.
  TarHeader header = file_header("old", 0);
  // -1 over the whole field: the flag bit, then all ones.
  std::vector<uint8_t> field(12, 0xFFu);
  header.raw(136, field);
  header.checksum();

  TarArchive archive;
  archive.header(header).marker();

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_EQ(member->mtime_seconds, -1);
  EXPECT_EQ(member->mtime_source, GARC_TIME_TAR_OCTAL);
}

TEST(TarHeaderNumbers, ABase256ValueTooWideToRepresentIsRefused) {
  // A 12-byte field can spell 95 bits. Truncating to 64 would turn a nonsense
  // size into a plausible one, which is worse than refusing.
  TarHeader header = file_header("absurd", 0);
  std::vector<uint8_t> field(12, 0x11u);
  field[0] = 0x81u; // Flag set, sign clear, and value bits in the top byte.
  header.raw(124, field);
  header.checksum();

  TarArchive archive;
  archive.header(header).marker();

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);
  const GARC_Member * member = nullptr;
  EXPECT_EQ(garc_next(opened.archive, &member), GARC_ERR_CORRUPT);
}

//-----------------------------------------------------------------------------
// Member data and the cursor
//-----------------------------------------------------------------------------

TEST(TarData, ReadsExactlyTheDeclaredSizeAcrossBlockBoundaries) {
  // The buffer in read_all() is 7 bytes, so every size here is read in several
  // calls with the last one short - which is the shape a reader gets wrong by
  // returning the padding, or by stopping a block early.
  const std::vector<size_t> sizes = {0, 1, 7, 511, 512, 513, 1024};
  for (size_t size : sizes) {
    SCOPED_TRACE("size " + std::to_string(size));
    const std::string payload(size, 'z');

    TarArchive archive;
    archive.header(file_header("payload", size)).data(payload).marker();

    Opened opened;
    ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);
    const GARC_Member * member = nullptr;
    ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
    EXPECT_EQ(member->size, size);

    std::string got;
    ASSERT_EQ(read_all(opened.archive, &got), GARC_OK);
    EXPECT_EQ(got, payload);
    // And the archive ends cleanly, which is what says the padding was skipped
    // rather than read.
    EXPECT_EQ(garc_next(opened.archive, &member), GARC_END);
  }
}

TEST(TarData, TheNextMemberIsReachedWithoutReadingTheCurrentOne) {
  // A caller is never required to read bytes it does not want. This is the
  // ordinary case and the reason skip exists at all.
  TarArchive archive;
  archive.header(file_header("first", 1000)).data(std::string(1000, 'a'))
      .header(file_header("second", 3)).data("xyz")
      .marker();

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);

  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_EQ(name_of(member), "first");
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_EQ(name_of(member), "second");

  std::string got;
  ASSERT_EQ(read_all(opened.archive, &got), GARC_OK);
  EXPECT_EQ(got, "xyz");
}

TEST(TarData, TheSameHoldsOnAStreamThatCannotSeek) {
  // The skip above seeks. On a pipe it has to read and discard instead, and the
  // two paths have to land in the same place - which is the assertion, rather
  // than each merely succeeding.
  TarArchive archive;
  archive.header(file_header("first", 1000)).data(std::string(1000, 'a'))
      .header(file_header("second", 3)).data("xyz")
      .marker();

  std::vector<uint8_t> bytes = archive.bytes();
  BufferSource source(bytes.data(), bytes.size(), false, false);
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK);
  GARC_Archive * opened = nullptr;
  ASSERT_EQ(garc_open(stream, nullptr, &opened), GARC_OK);

  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened, &member), GARC_OK);
  ASSERT_EQ(garc_next(opened, &member), GARC_OK);
  EXPECT_EQ(name_of(member), "second");
  std::string got;
  ASSERT_EQ(read_all(opened, &got), GARC_OK);
  EXPECT_EQ(got, "xyz");

  garc_close(opened);
  garc_stream_destroy(stream);
}

TEST(TarData, AMemberDeclaringMoreThanItHasIsCorrupt) {
  // The container said the bytes were there. Reporting GARC_END instead would
  // hand back a short file and call it whole.
  TarArchive archive;
  archive.header(file_header("liar", 2000)).data(std::string(100, 'a'));
  // No marker: the archive simply stops inside the member's data.

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_EQ(member->size, 2000u);

  std::string got;
  EXPECT_EQ(read_all(opened.archive, &got), GARC_ERR_CORRUPT);
  // And what it did produce is what was there, rather than nothing: a caller
  // that has already consumed 100 bytes needs the failure, not a rewind.
  EXPECT_EQ(got.size(), 512u - 100u + 100u - 0u);
}

TEST(TarData, AReadCannotReachPastTheDeclaredSize) {
  // A member that declares *less* than it contains is the other direction, and
  // the dangerous one: a reader that keeps going hands the next header's bytes
  // to the caller as file contents.
  TarArchive archive;
  archive.header(file_header("short", 4)).data("abcdefgh")
      .header(file_header("next", 0)).marker();

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);

  std::string got;
  ASSERT_EQ(read_all(opened.archive, &got), GARC_OK);
  EXPECT_EQ(got, "abcd");

  // And the next header is still found, because the cursor moved by the declared
  // size plus its padding rather than by what was read.
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_EQ(name_of(member), "next");
}

TEST(TarData, ADirectoryWithAStaleSizeFieldCarriesNoData) {
  // Some writers leave a stale value in a directory's size field. A reader that
  // seeks by it walks into the next header and reports that header's bytes as
  // this member's contents - a wrong answer rather than an error.
  TarHeader header = file_header("adir/", 4096u, 0755u, '5');
  header.checksum();

  TarArchive archive;
  archive.header(header).header(file_header("after", 3)).data("abc").marker();

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_EQ(member->type, GARC_MEMBER_DIRECTORY);
  EXPECT_EQ(member->size, 0u) << "the stale size field was believed";

  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_EQ(name_of(member), "after");
}

TEST(TarData, ReadingWithNoCurrentMemberIsRejected) {
  TarArchive archive;
  archive.header(file_header("hello", 3)).data("abc").marker();

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);

  char buffer[4];
  size_t got = 0;
  EXPECT_EQ(garc_read_member(opened.archive, buffer, sizeof(buffer), &got),
      GARC_ERR_INVALID);
  EXPECT_EQ(garc_skip_member(opened.archive), GARC_ERR_INVALID);
  // And a NULL archive, which is a different arm from "no current member".
  EXPECT_EQ(garc_read_member(nullptr, buffer, sizeof(buffer), &got),
      GARC_ERR_INVALID);
  EXPECT_EQ(garc_skip_member(nullptr), GARC_ERR_INVALID);
  EXPECT_EQ(garc_read_member(opened.archive, buffer, sizeof(buffer), nullptr),
      GARC_ERR_INVALID);

  // And after the end, likewise: there is no current member there either.
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_END);
  EXPECT_EQ(garc_read_member(opened.archive, buffer, sizeof(buffer), &got),
      GARC_ERR_INVALID);
}

TEST(TarData, SkipMemberLeavesTheCursorWhereNextWould) {
  TarArchive archive;
  archive.header(file_header("first", 600)).data(std::string(600, 'a'))
      .header(file_header("second", 3)).data("xyz").marker();

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);

  char buffer[10];
  size_t got = 0;
  ASSERT_EQ(garc_read_member(opened.archive, buffer, sizeof(buffer), &got),
      GARC_OK);
  ASSERT_EQ(got, sizeof(buffer));
  ASSERT_EQ(garc_skip_member(opened.archive), GARC_OK);
  // Skipping twice is not an error: the second call has nothing to do.
  EXPECT_EQ(garc_skip_member(opened.archive), GARC_OK);

  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_EQ(name_of(member), "second");
}

//-----------------------------------------------------------------------------
// The end of the archive
//-----------------------------------------------------------------------------

TEST(TarEnd, OneZeroBlockEndsAnArchiveWhoseTailWasTrimmed) {
  // Writers pad the end to a record boundary and some strip the padding, so an
  // archive that ends after a single zero block is the normal shape of a trimmed
  // tail rather than damage.
  TarArchive archive;
  archive.header(file_header("hello", 0)).marker(1);

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_EQ(garc_next(opened.archive, &member), GARC_END);
}

TEST(TarEnd, AZeroBlockFollowedByAHeaderIsNotTheEnd) {
  // The other half of the rule above, and the reason a single zero block cannot
  // simply end the archive: GNU tar concatenates archives, which leaves markers
  // in the middle. A reader that stopped at the first would truncate a valid
  // archive and report success.
  TarArchive archive;
  archive.header(file_header("first", 0)).marker(1)
      .header(file_header("second", 0)).marker();

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_EQ(name_of(member), "first");
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_EQ(name_of(member), "second");
  EXPECT_EQ(garc_next(opened.archive, &member), GARC_END);
}

TEST(TarEnd, AnArchiveWithNoMarkerIsCorruptRatherThanComplete) {
  // `tar cf - x | head -c 1024` produces this. A reader that returned GARC_END
  // would hand a caller half a listing with nothing to distinguish it from a
  // whole one.
  TarArchive archive;
  archive.header(file_header("hello", 0));

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_EQ(garc_next(opened.archive, &member), GARC_ERR_CORRUPT);
}

TEST(TarEnd, APartialBlockBeforeTheMarkerIsCorrupt) {
  TarArchive archive;
  archive.header(file_header("hello", 0)).raw(std::vector<uint8_t>(100, 0x41u));

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_EQ(garc_next(opened.archive, &member), GARC_ERR_CORRUPT);
}

TEST(TarEnd, APartialBlockAfterTheMarkerIsTheEnd) {
  // The trimmed-tail case again, with the trim landing mid-block. A reader that
  // required whole blocks after the marker would reject an archive every
  // reference accepts.
  TarArchive archive;
  archive.header(file_header("hello", 0)).marker(1)
      .raw(std::vector<uint8_t>(100, 0));

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_EQ(garc_next(opened.archive, &member), GARC_END);
}

TEST(TarEnd, NextAfterTheEndKeepsSayingTheEnd) {
  // A caller that loops one extra time gets the same answer rather than a
  // rescan, and the member count does not move.
  TarArchive archive;
  archive.header(file_header("hello", 0)).marker();

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_END);
  EXPECT_EQ(garc_next(opened.archive, &member), GARC_END);
  EXPECT_EQ(garc_next(opened.archive, &member), GARC_END);
  EXPECT_EQ(garc_member_count(opened.archive), 1u);
}

TEST(TarEnd, AnArchiveOfNothingButZeroBlocksTerminatesRatherThanRecursing) {
  // A tar of a million zero blocks compresses to nothing, so this is reachable
  // from input: the zero-block case has to be a loop rather than a recursion.
  // 20,000 blocks is 10 MB, which is enough to overflow a stack frame per block
  // and cheap to build.
  TarArchive archive;
  archive.marker(20000);

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);
  const GARC_Member * member = nullptr;
  EXPECT_EQ(garc_next(opened.archive, &member), GARC_END);
}

//-----------------------------------------------------------------------------
// Types
//-----------------------------------------------------------------------------

TEST(TarType, EveryTypeflagMapsToItsType) {
  struct Row {
    char flag;
    GARC_Member_Type type;
  };
  const Row rows[] = {
    {'\0', GARC_MEMBER_FILE},  // v7's spelling of a regular file.
    {'0', GARC_MEMBER_FILE},
    {'7', GARC_MEMBER_FILE},   // Contiguous; no filesystem in use has one.
    {'1', GARC_MEMBER_HARDLINK},
    {'2', GARC_MEMBER_SYMLINK},
    {'3', GARC_MEMBER_CHAR_DEVICE},
    {'4', GARC_MEMBER_BLOCK_DEVICE},
    {'5', GARC_MEMBER_DIRECTORY},
    {'6', GARC_MEMBER_FIFO},
    // An unrecognised flag is OTHER, not a file. Extracting an unknown type as a
    // regular file is how a reader invents data.
    {'Z', GARC_MEMBER_OTHER},
  };

  for (const Row & row : rows) {
    SCOPED_TRACE(std::string("typeflag ") + row.flag);
    TarHeader header = file_header("thing", 0, 0644u, row.flag);
    header.checksum();

    TarArchive archive;
    archive.header(header).marker();

    Opened opened;
    ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);
    const GARC_Member * member = nullptr;
    ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
    EXPECT_EQ(member->type, row.type);
  }
}

TEST(TarType, DeviceNumbersAreReadOnlyForADevice) {
  // Blank in every other header there is, so reporting 0/0 as valid for a
  // regular file would be a number a caller could act on.
  TarHeader device = file_header("dev", 0, 0644u, '3');
  device.octal(329, 8, 5);  // devmajor
  device.octal(337, 8, 42); // devminor
  device.checksum();

  TarArchive archive;
  archive.header(device).header(file_header("plain", 0)).marker();

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_TRUE(member->device_valid);
  EXPECT_EQ(member->device_major, 5u);
  EXPECT_EQ(member->device_minor, 42u);

  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_FALSE(member->device_valid);
}

TEST(TarType, V7DoesNotReadThePrefixField) {
  // v7 has no prefix field; those bytes are whatever the writer left there. A
  // reader that always joins the prefix turns that padding into a directory
  // component - a name no tool agrees with.
  TarHeader header = file_header("plain.txt", 0);
  // Make it v7 by clearing the magic, and put something where ustar's prefix is.
  std::memset(header.bytes.data() + 257, 0, 8);
  header.field(345, 155, "junk/from/an/old/writer");
  header.checksum();

  TarArchive archive;
  archive.header(header).marker();

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_EQ(garc_tar_member_variant(opened.archive), GARC_TAR_V7);
  EXPECT_EQ(name_of(member), "plain.txt");
}

//-----------------------------------------------------------------------------
// GNU's carriers: the 'L' and 'K' members
//-----------------------------------------------------------------------------
//
// The generated corpus has what GNU tar writes: a payload of exactly strlen + 1,
// one carrier per field, and a real header behind it. Everything below is a
// payload no writer produces, and every one of them has a plausible wrong answer
// rather than a crash - a name that is a prefix of the right one, a name applied
// to the wrong member, or a member that is really an artefact of the format.

TEST(TarGnuCarrier, TheCarrierIsNeverReportedAsAMember) {
  // Hand-built, with the shortest possible long name, so that the assertion is
  // about the carrier rather than about a length. A reader that simply walks
  // headers reports two members here and the first is called "././@LongLink".
  const std::string name = "a-name-that-came-from-the-carrier";

  TarArchive archive;
  archive.header(long_header('L', name.size() + 1))
      .data(name + std::string(1, '\0'))
      .header(file_header("truncated-copy", 0))
      .marker();

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);

  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_EQ(name_of(member), name);
  // The variant is GNU although this header's magic is ustar's: the carrier is
  // GNU's construct, and a member read through one was not read as ustar.
  EXPECT_EQ(garc_tar_member_variant(opened.archive), GARC_TAR_GNU);
  EXPECT_EQ(garc_next(opened.archive, &member), GARC_END);
  EXPECT_EQ(garc_member_count(opened.archive), 1u);
}

TEST(TarGnuCarrier, ALinkTargetCarrierAndANameCarrierApplyTogether) {
  // Both in front of one header, which is legal and which GNU will write when a
  // symlink has a long name *and* a long target. A reader that handles one
  // carrier and then treats the next block as the header reports the second
  // carrier as the member.
  const std::string name = "a-very-long-name";
  const std::string target = "a-very-long-target";

  TarArchive archive;
  archive.header(long_header('L', name.size() + 1))
      .data(name + std::string(1, '\0'))
      .header(long_header('K', target.size() + 1))
      .data(target + std::string(1, '\0'))
      .header(file_header("short", 0, 0777u, '2'))
      .marker();

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);

  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_EQ(name_of(member), name);
  ASSERT_NE(member->link_target, nullptr);
  EXPECT_EQ(std::string(member->link_target, member->link_target_length),
      target);
  EXPECT_EQ(member->type, GARC_MEMBER_SYMLINK);
  // Three blocks of carrier and payload in front of the header, so this is also
  // the assertion that header_offset points at the first of them: a caller
  // re-reading the member from a later offset would get the truncated name.
  EXPECT_EQ(member->header_offset, 0u);
  EXPECT_EQ(member->data_offset, 5u * kTarBlock);
  EXPECT_EQ(garc_next(opened.archive, &member), GARC_END);
}

TEST(TarGnuCarrier, ACarrierAppliesOnlyToTheMemberBehindIt) {
  // The pax rule stated for GNU: a carrier describes the *next* member and
  // nothing after it. A reader that left the name in place would give both
  // members the long name and still round-trip, which is the shape that reads as
  // working.
  const std::string name = "only-the-first-member-has-this-name";

  TarArchive archive;
  archive.header(long_header('L', name.size() + 1))
      .data(name + std::string(1, '\0'))
      .header(file_header("first", 0))
      .header(file_header("second", 0))
      .marker();

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);

  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_EQ(name_of(member), name);
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_EQ(name_of(member), "second");
  // And the variant goes back to what the magic says, because this member was
  // not read through a carrier.
  EXPECT_EQ(garc_tar_member_variant(opened.archive), GARC_TAR_USTAR);
}

TEST(TarGnuCarrier, AShorterNameAfterALongerOneIsNotTheLongerOnesTail) {
  // The buffer is grown and kept across members, so a second, shorter name is
  // written into storage that still holds the first. A length not reset with the
  // contents reports the first name's tail behind the second - a name that is a
  // real path with extra components, which is exactly the answer a traversal
  // check would be asked about.
  const std::string longer(400, 'L');
  const std::string shorter(20, 's');

  TarArchive archive;
  archive.header(long_header('L', longer.size() + 1))
      .data(longer + std::string(1, '\0'))
      .header(file_header("first", 0))
      .header(long_header('L', shorter.size() + 1))
      .data(shorter + std::string(1, '\0'))
      .header(file_header("second", 0))
      .marker();

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);

  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_EQ(name_of(member), longer);
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_EQ(member->name_length, shorter.size());
  EXPECT_EQ(name_of(member), shorter);
}

TEST(TarGnuCarrier, APayloadWithContentBehindItsTerminatorIsRefused) {
  // The ambiguous shape, and the reason it is refused rather than read. The
  // payload declares 40 bytes and holds "safe/path", a NUL, and then more path:
  // this reader would report "safe/path" and a reader using the declared length
  // would report the whole thing. A member whose name depends on which reader is
  // asked is how a checked name and an extracted name come apart, so neither
  // answer is given.
  std::string payload = "safe/path";
  payload.push_back('\0');
  payload += "../../etc/cron.d/x";
  payload.push_back('\0');

  TarArchive archive;
  archive.header(long_header('L', payload.size()))
      .data(payload)
      .header(file_header("short", 0))
      .marker();

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);

  const GARC_Member * member = nullptr;
  EXPECT_EQ(garc_next(opened.archive, &member), GARC_ERR_CORRUPT);
}

TEST(TarGnuCarrier, APayloadWithNoTerminatorAtAllIsRead) {
  // The control for the test above, and a real variation: a writer that wrote
  // strlen rather than strlen + 1 leaves no terminator, and the payload is then
  // the whole field. Refusing this would reject archives over a spelling that
  // carries no ambiguity at all - there is exactly one reading.
  const std::string name(30, 'n');

  TarArchive archive;
  archive.header(long_header('L', name.size()))
      .data(name)
      .header(file_header("short", 0))
      .marker();

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);

  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_EQ(name_of(member), name);
}

TEST(TarGnuCarrier, AnEmptyPayloadIsRefusedRatherThanFallingBackToTheHeader) {
  // A carrier that carries nothing. The tempting reading is "no name here, use
  // the header's" - which silently produces the truncated name the carrier
  // existed to replace, so the archive reads as complete and one member is called
  // something else.
  //
  // Three spellings of empty, because the size field and the bytes can each say
  // it: a declared size of zero, a declared size whose bytes are all NUL, and a
  // 'K' rather than an 'L' - a link target the format cannot express as empty.
  {
    TarArchive archive;
    archive.header(long_header('L', 0))
        .header(file_header("truncated", 0))
        .marker();
    Opened opened;
    ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);
    const GARC_Member * member = nullptr;
    EXPECT_EQ(garc_next(opened.archive, &member), GARC_ERR_CORRUPT);
  }
  {
    TarArchive archive;
    archive.header(long_header('L', 4))
        .data(std::string(4, '\0'))
        .header(file_header("truncated", 0))
        .marker();
    Opened opened;
    ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);
    const GARC_Member * member = nullptr;
    EXPECT_EQ(garc_next(opened.archive, &member), GARC_ERR_CORRUPT);
  }
  {
    TarArchive archive;
    archive.header(long_header('K', 0))
        .header(file_header("link", 0, 0777u, '2'))
        .marker();
    Opened opened;
    ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);
    const GARC_Member * member = nullptr;
    EXPECT_EQ(garc_next(opened.archive, &member), GARC_ERR_CORRUPT);
  }
}

TEST(TarGnuCarrier, TwoCarriersOfTheSameKindAreRefused) {
  // Each carrier allocates its declared size, so a chain of them turns a few
  // hundred bytes of archive into as many allocations of the cap as there are
  // links. libarchive refuses the same shape for the same reason. The other
  // reading, last-one-wins, would make a member's name depend on how far a
  // reader got before it stopped.
  const std::string first(40, 'f');
  const std::string second(40, 's');

  TarArchive archive;
  archive.header(long_header('L', first.size() + 1))
      .data(first + std::string(1, '\0'))
      .header(long_header('L', second.size() + 1))
      .data(second + std::string(1, '\0'))
      .header(file_header("short", 0))
      .marker();

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);

  const GARC_Member * member = nullptr;
  EXPECT_EQ(garc_next(opened.archive, &member), GARC_ERR_CORRUPT);
}

TEST(TarGnuCarrier, ACarrierWithNothingBehindItIsRefused) {
  // The end of the archive where a header was owed. Both spellings: the marker,
  // and the stream simply stopping. Treating either as a clean end would report a
  // complete archive whose last member's name was read and then discarded.
  const std::string name(40, 'n');
  const std::string payload = name + std::string(1, '\0');

  {
    TarArchive archive;
    archive.header(long_header('L', payload.size()))
        .data(payload)
        .marker();
    Opened opened;
    ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);
    const GARC_Member * member = nullptr;
    EXPECT_EQ(garc_next(opened.archive, &member), GARC_ERR_CORRUPT);
  }
  {
    TarArchive archive;
    archive.header(long_header('L', payload.size())).data(payload);
    Opened opened;
    ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);
    const GARC_Member * member = nullptr;
    EXPECT_EQ(garc_next(opened.archive, &member), GARC_ERR_CORRUPT);
  }
}

TEST(TarGnuCarrier, APayloadShorterThanDeclaredIsRefused) {
  // The carrier says 600 bytes and the archive holds one block. Reporting the 512
  // bytes that were there would be a name that is a prefix of the real one, which
  // is a path - and a prefix of a path is a different path, not a damaged one.
  TarArchive archive;
  archive.header(long_header('L', 600)).data(std::string(500, 'n'));

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);

  const GARC_Member * member = nullptr;
  EXPECT_EQ(garc_next(opened.archive, &member), GARC_ERR_CORRUPT);
}

TEST(TarGnuCarrier, TheNameCapIsCheckedBeforeThePayloadIsAllocated) {
  // **This is the one place in the tar reader where a length is declared in one
  // block and the bytes arrive in the next**, so it is the one place a cap has to
  // fire on the declaration rather than on what was read. Checking afterwards
  // would mean allocating whatever a hostile archive asked for in order to find
  // out it was too much.
  //
  // The proof is the allocator: it is set to fail its next request, and the
  // expected answer is still the *limit*. A reader that allocated first would
  // return GARC_ERR_OOM here and pass a test that only asserted "not OK".
  TarArchive archive;
  archive.header(long_header('L', 1u << 20))
      .data(std::string(64, 'n'));
  std::vector<uint8_t> bytes = archive.bytes();

  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
      GARC_OK);

  GARC_Limits limits;
  garc_limits_default(&limits);
  limits.max_name_bytes = 64;

  // One allocation for the archive itself, then fail everything after it.
  garctest::FailingAllocator allocator(1, 16);
  GARC_Archive * opened = nullptr;
  ASSERT_EQ(garc_open_with_allocator(stream, &limits, allocator.get(), &opened),
      GARC_OK);

  const GARC_Member * member = nullptr;
  EXPECT_EQ(garc_next(opened, &member), GARC_ERR_LIMIT_NAME_BYTES);

  allocator.stop_failing();
  garc_close(opened);
  garc_stream_destroy(stream);
  EXPECT_EQ(allocator.live(), 0u);
}

TEST(TarGnuCarrier, TheNameCapAllowsExactlyOneByteForTheTerminator) {
  // The boundary, from both sides. GNU's payload is the name *and* its
  // terminator, and the cap is on the name - so a cap of N has to accept a
  // payload of N + 1 and refuse one of N + 2. A check written against the payload
  // rather than the name would refuse a name of exactly N, which is a cap that is
  // off by one in the direction nothing notices.
  const size_t cap = 64;

  {
    const std::string name(cap, 'n');
    TarArchive archive;
    archive.header(long_header('L', name.size() + 1))
        .data(name + std::string(1, '\0'))
        .header(file_header("short", 0))
        .marker();

    GARC_Limits limits;
    garc_limits_default(&limits);
    limits.max_name_bytes = cap;
    Opened opened;
    ASSERT_EQ(open_bytes(opened, archive.bytes(), &limits), GARC_OK);
    const GARC_Member * member = nullptr;
    ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
    EXPECT_EQ(member->name_length, cap);
  }
  {
    // One byte longer. The payload is cap + 2, which the declaration check
    // refuses on its own.
    const std::string name(cap + 1u, 'n');
    TarArchive archive;
    archive.header(long_header('L', name.size() + 1))
        .data(name + std::string(1, '\0'))
        .header(file_header("short", 0))
        .marker();

    GARC_Limits limits;
    garc_limits_default(&limits);
    limits.max_name_bytes = cap;
    Opened opened;
    ASSERT_EQ(open_bytes(opened, archive.bytes(), &limits), GARC_OK);
    const GARC_Member * member = nullptr;
    EXPECT_EQ(garc_next(opened.archive, &member), GARC_ERR_LIMIT_NAME_BYTES);
  }
  {
    // And the case the declaration check *cannot* see: a payload of cap + 1 whose
    // string really is cap + 1 bytes long, because the writer left no terminator.
    // garc_reader_account() is what refuses this, which is why the declaration
    // check is allowed its one byte of slack rather than being made exact.
    const std::string name(cap + 1u, 'n');
    TarArchive archive;
    archive.header(long_header('L', name.size()))
        .data(name)
        .header(file_header("short", 0))
        .marker();

    GARC_Limits limits;
    garc_limits_default(&limits);
    limits.max_name_bytes = cap;
    Opened opened;
    ASSERT_EQ(open_bytes(opened, archive.bytes(), &limits), GARC_OK);
    const GARC_Member * member = nullptr;
    EXPECT_EQ(garc_next(opened.archive, &member), GARC_ERR_LIMIT_NAME_BYTES);
  }
}

TEST(TarGnuCarrier, ACarrierIsNotCountedAsAMemberNorAgainstTheByteCaps) {
  // A carrier has a size and a name and is not a member, so neither the member
  // count nor the declared-byte total may move for it. A reader that accounted
  // for carriers would make max_members refuse an archive of half as many
  // members as it says, and the failure would look like a cap set too low.
  const std::string name(300, 'n');

  TarArchive archive;
  archive.header(long_header('L', name.size() + 1))
      .data(name + std::string(1, '\0'))
      .header(file_header("first", 10)).data(std::string(10, 'a'))
      .header(long_header('L', name.size() + 1))
      .data(name + std::string(1, '\0'))
      .header(file_header("second", 10)).data(std::string(10, 'b'))
      .marker();

  GARC_Limits limits;
  garc_limits_default(&limits);
  limits.max_members = 2;
  limits.max_total_bytes = 20;

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes(), &limits), GARC_OK);

  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_EQ(garc_next(opened.archive, &member), GARC_END);
  EXPECT_EQ(garc_member_count(opened.archive), 2u);
  // 20, not 622: the carriers' 301 bytes each are metadata.
  EXPECT_EQ(garc_total_declared_bytes(opened.archive), 20u);
}

TEST(TarGnuCarrier, AFailedStepLeavesNoNameForTheNextOne) {
  // The claim on a carried name is cleared at the start of every step, not where
  // the name is applied. Without that, a caller that carried on after a failure
  // would see the failed step's name on whatever header it reached next - a name
  // from one part of the archive attached to a member from another, which is a
  // real path on the wrong file.
  //
  // The archive is built so that the failure lands *after* the carrier succeeded
  // and *before* a member that is perfectly good: a carrier, its payload, a block
  // of rubbish, and then a real header. The first step reads the name and then
  // fails on the rubbish; the second must report "after" under its own name.
  const std::string carried(40, 'c');

  TarArchive archive;
  archive.header(long_header('L', carried.size() + 1))
      .data(carried + std::string(1, '\0'))
      .raw(std::vector<uint8_t>(kTarBlock, 0xABu))
      .header(file_header("after", 0))
      .marker();

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);

  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_ERR_CORRUPT);
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_EQ(name_of(member), "after");
  EXPECT_EQ(member->name_length, 5u);
  // And the variant, which the carrier also sets.
  EXPECT_EQ(garc_tar_member_variant(opened.archive), GARC_TAR_USTAR);
}

TEST(TarGnuCarrier, ReportsOutOfMemoryForThePayload) {
  // The carrier's payload is the only allocation the tar reader makes after the
  // archive itself, so it is the only one that can fail. An OOM here has to be
  // OOM rather than a corrupt archive: the bytes were fine.
  const std::string name(400, 'n');

  TarArchive archive;
  archive.header(long_header('L', name.size() + 1))
      .data(name + std::string(1, '\0'))
      .header(file_header("short", 0))
      .marker();
  std::vector<uint8_t> bytes = archive.bytes();

  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
      GARC_OK);

  // Request 0 is the archive; request 1 is the payload.
  garctest::FailingAllocator allocator(1);
  GARC_Archive * opened = nullptr;
  ASSERT_EQ(garc_open_with_allocator(stream, nullptr, allocator.get(), &opened),
      GARC_OK);

  const GARC_Member * member = nullptr;
  EXPECT_EQ(garc_next(opened, &member), GARC_ERR_OOM);

  allocator.stop_failing();
  garc_close(opened);
  garc_stream_destroy(stream);
  EXPECT_EQ(allocator.live(), 0u);
}

//-----------------------------------------------------------------------------
// Limits
//-----------------------------------------------------------------------------

TEST(TarLimits, EachCapFiresWithItsOwnStatus) {
  // The point of five constants rather than one: a test can assert *which* cap
  // fired. A shared code would make every row below indistinguishable, and an
  // absent cap indistinguishable from a defeated one.
  TarArchive archive;
  archive.header(file_header("aaa", 600)).data(std::string(600, 'a'))
      .header(file_header("bbb", 600)).data(std::string(600, 'b'))
      .header(file_header("ccc", 600)).data(std::string(600, 'c'))
      .marker();
  const std::vector<uint8_t> bytes = archive.bytes();

  {
    // One member allowed, so the second is refused.
    GARC_Limits limits;
    garc_limits_default(&limits);
    limits.max_members = 1;
    Opened opened;
    ASSERT_EQ(open_bytes(opened, bytes, &limits), GARC_OK);
    const GARC_Member * member = nullptr;
    ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
    EXPECT_EQ(garc_next(opened.archive, &member), GARC_ERR_LIMIT_MEMBERS);
  }
  {
    GARC_Limits limits;
    garc_limits_default(&limits);
    limits.max_member_bytes = 599;
    Opened opened;
    ASSERT_EQ(open_bytes(opened, bytes, &limits), GARC_OK);
    const GARC_Member * member = nullptr;
    EXPECT_EQ(garc_next(opened.archive, &member), GARC_ERR_LIMIT_MEMBER_BYTES);
  }
  {
    // Two members' worth, so the third crosses the sum. This is the cap no
    // codec can see: each member is inside max_member_bytes and it is the count
    // that multiplies.
    GARC_Limits limits;
    garc_limits_default(&limits);
    limits.max_total_bytes = 1200;
    Opened opened;
    ASSERT_EQ(open_bytes(opened, bytes, &limits), GARC_OK);
    const GARC_Member * member = nullptr;
    ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
    ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
    EXPECT_EQ(garc_total_declared_bytes(opened.archive), 1200u);
    EXPECT_EQ(garc_next(opened.archive, &member), GARC_ERR_LIMIT_TOTAL_BYTES);
  }
  {
    GARC_Limits limits;
    garc_limits_default(&limits);
    limits.max_name_bytes = 2;
    Opened opened;
    ASSERT_EQ(open_bytes(opened, bytes, &limits), GARC_OK);
    const GARC_Member * member = nullptr;
    EXPECT_EQ(garc_next(opened.archive, &member), GARC_ERR_LIMIT_NAME_BYTES);
  }
}

TEST(TarLimits, ACapAtExactlyTheBoundaryDoesNotFire) {
  // The control for the test above. A cap that fires one early would pass every
  // row there, and the only thing that separates "the cap works" from "the cap
  // is off by one" is asserting the boundary from both sides.
  TarArchive archive;
  archive.header(file_header("aaa", 600)).data(std::string(600, 'a'))
      .header(file_header("bbb", 600)).data(std::string(600, 'b'))
      .marker();
  const std::vector<uint8_t> bytes = archive.bytes();

  GARC_Limits limits;
  garc_limits_default(&limits);
  limits.max_members = 2;
  limits.max_member_bytes = 600;
  limits.max_total_bytes = 1200;
  limits.max_name_bytes = 3;

  Opened opened;
  ASSERT_EQ(open_bytes(opened, bytes, &limits), GARC_OK);
  const GARC_Member * member = nullptr;
  EXPECT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_EQ(garc_next(opened.archive, &member), GARC_END);
  EXPECT_EQ(garc_member_count(opened.archive), 2u);
  EXPECT_EQ(garc_total_declared_bytes(opened.archive), 1200u);
}

TEST(TarLimits, ZeroMeansUnlimited) {
  TarArchive archive;
  archive.header(file_header("aaa", 600)).data(std::string(600, 'a')).marker();

  GARC_Limits limits;
  std::memset(&limits, 0, sizeof(limits));

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes(), &limits), GARC_OK);
  const GARC_Member * member = nullptr;
  EXPECT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_EQ(garc_next(opened.archive, &member), GARC_END);
}

TEST(TarLimits, TheTotalCannotBeDefeatedByOverflow) {
  // **A white-box test, and it has to be.** The wrapping case cannot be reached
  // through the public API on a tar: a member's declared size is also the
  // distance garc_next() has to step over, so an archive whose sizes sum past
  // 2^64 fails on the skip long before a second one can be accounted. It becomes
  // reachable with zip, whose central directory hands over every size without
  // the reader walking through the data.
  //
  // So the accounting function is called directly, on a state a tar cannot
  // produce. Written the obvious way - `total + size > max` - the second call
  // below wraps to 0 and is allowed; written as a subtraction it is refused.
  // That is the whole difference between the two implementations, and without
  // this test nothing distinguishes them.
  GARC_Archive archive;
  std::memset(&archive, 0, sizeof(archive));
  garc_limits_default(&archive.limits);
  archive.limits.max_total_bytes = UINT64_MAX;
  archive.limits.max_member_bytes = 0;
  archive.limits.max_members = 0;
  archive.limits.max_name_bytes = 0;

  const uint64_t huge = (uint64_t)1u << 63;
  archive.member.name = "a";
  archive.member.name_length = 1;
  archive.member.size = huge;
  ASSERT_EQ(garc_reader_account(&archive), GARC_OK);
  EXPECT_EQ(garc_total_declared_bytes(&archive), huge);

  // 2^63 + 2^63 is 2^64, which wraps to zero. Under the cap by the wrong
  // arithmetic, over it by the right.
  archive.member.size = huge;
  EXPECT_EQ(garc_reader_account(&archive), GARC_ERR_LIMIT_TOTAL_BYTES);
  EXPECT_EQ(garc_total_declared_bytes(&archive), huge)
      << "the refused member was added to the total anyway";

  // And the boundary from the other side: one byte less than the remaining
  // headroom is allowed, so the refusal above is the cap and not an off-by-one.
  archive.member.size = UINT64_MAX - huge;
  EXPECT_EQ(garc_reader_account(&archive), GARC_OK);
  EXPECT_EQ(garc_total_declared_bytes(&archive), UINT64_MAX);
}

TEST(TarLimits, AHugeDeclaredSizeFailsOnTheStepRatherThanSilently) {
  // The reason the test above is white-box, asserted rather than described: a
  // member that declares more than the archive holds is caught when garc_next()
  // steps over it, as a corrupt archive. A reader that stepped by what it read
  // instead would find a header somewhere inside the data.
  // A megabyte: far more than this archive holds, and well under the default
  // max_member_bytes of 64 GiB. Going bigger than that default would have the
  // cap fire first and this test would then be asserting the cap rather than the
  // step - which is what the first attempt at it did.
  const uint64_t declared = (uint64_t)1u << 20;
  TarArchive archive;
  archive.header(file_header("a", declared))
      .header(file_header("b", 0)).marker();

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);
  EXPECT_EQ(member->size, declared);
  EXPECT_EQ(garc_next(opened.archive, &member), GARC_ERR_CORRUPT);
}

//-----------------------------------------------------------------------------
// Identification, open and close
//-----------------------------------------------------------------------------

TEST(TarOpen, SomethingThatIsNotATarIsRefusedAsAFormatError) {
  std::vector<uint8_t> bytes(2048, 0x41u); // "AAAA..."
  Opened opened;
  EXPECT_EQ(open_bytes(opened, bytes), GARC_ERR_FORMAT);
}

TEST(TarOpen, AStreamOfNoBytesIsCorruptRatherThanNotATar) {
  // An empty file is not "not a tar", it is nothing at all, and a caller telling
  // an empty file from a damaged one needs the difference.
  Opened opened;
  EXPECT_EQ(open_bytes(opened, std::vector<uint8_t>()), GARC_ERR_CORRUPT);
}

TEST(TarOpen, SomethingShorterThanOneBlockIsAFormatError) {
  TarArchive archive;
  archive.header(file_header("hello", 0));
  std::vector<uint8_t> bytes = archive.bytes();
  bytes.resize(200);

  Opened opened;
  EXPECT_EQ(open_bytes(opened, bytes), GARC_ERR_FORMAT);
}

TEST(TarOpen, RejectsBadArguments) {
  std::vector<uint8_t> bytes(512, 0);
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
      GARC_OK);
  GARC_Archive * archive = nullptr;
  EXPECT_EQ(garc_open(nullptr, nullptr, &archive), GARC_ERR_INVALID);
  EXPECT_EQ(garc_open(stream, nullptr, nullptr), GARC_ERR_INVALID);
  garc_stream_destroy(stream);

  const GARC_Member * member = nullptr;
  EXPECT_EQ(garc_next(nullptr, &member), GARC_ERR_INVALID);
  EXPECT_EQ(garc_format(nullptr), GARC_FORMAT_UNKNOWN);
  EXPECT_EQ(garc_member_count(nullptr), 0u);
  EXPECT_EQ(garc_total_declared_bytes(nullptr), 0u);
  EXPECT_EQ(garc_tar_member_variant(nullptr), GARC_TAR_NONE);
  garc_close(nullptr);
}

TEST(TarOpen, ReportsOutOfMemory) {
  TarArchive archive;
  archive.header(file_header("hello", 0)).marker();
  std::vector<uint8_t> bytes = archive.bytes();

  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
      GARC_OK);

  garctest::FailingAllocator allocator(0);
  GARC_Archive * opened = nullptr;
  EXPECT_EQ(garc_open_with_allocator(stream, nullptr, allocator.get(), &opened),
      GARC_ERR_OOM);
  EXPECT_EQ(opened, nullptr);
  EXPECT_EQ(allocator.live(), 0u);

  garc_stream_destroy(stream);
}

TEST(TarOpen, CloseDoesNotDestroyTheStream) {
  // The stream is borrowed. A close that destroyed it would make the borrowing
  // a lie the caller finds out about as a double free - so this reads from the
  // stream after closing the archive, which would be use-after-free if it did.
  TarArchive archive;
  archive.header(file_header("hello", 0)).marker();
  std::vector<uint8_t> bytes = archive.bytes();

  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
      GARC_OK);
  GARC_Archive * opened = nullptr;
  ASSERT_EQ(garc_open(stream, nullptr, &opened), GARC_OK);
  garc_close(opened);

  ASSERT_EQ(garc_stream_seek(stream, 0), GARC_OK);
  uint8_t byte = 0;
  EXPECT_EQ(garc_stream_read_exact(stream, &byte, 1), GARC_OK);
  EXPECT_EQ(byte, 'h');
  garc_stream_destroy(stream);
}

//-----------------------------------------------------------------------------
// Dumps
//-----------------------------------------------------------------------------

TEST(TarDump, AHostileNameCannotReachTheTerminal) {
  // A member name is attacker-controlled and a dump is something a person looks
  // at. An ANSI escape in a name would move the cursor or clear the screen, so
  // the output of a listing tool says whatever the archive wants; a newline is
  // the cheaper version, ending the line early and hiding what came next.
  TarHeader header = file_header("evil\x1b[2Jname", 0);
  header.checksum();

  TarArchive archive;
  archive.header(header).marker();

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);

  char * buffer = nullptr;
  size_t length = 0;
  FILE * sink = open_memstream(&buffer, &length);
  ASSERT_NE(sink, nullptr);
  garc_member_dump(member, sink);
  garc_archive_dump(opened.archive, sink);
  fclose(sink);

  const std::string text(buffer, length);
  free(buffer);

  EXPECT_EQ(text.find('\x1b'), std::string::npos)
      << "an escape byte reached the dump";
  EXPECT_NE(text.find("\\x1B"), std::string::npos)
      << "the escape byte was dropped rather than escaped";
  // And the rest of the line survived, which is what says the name was escaped
  // rather than truncated at the first odd byte.
  EXPECT_NE(text.find("name"), std::string::npos);
}

TEST(TarDump, NullIsAnsweredWithoutCrashing) {
  char * buffer = nullptr;
  size_t length = 0;
  FILE * sink = open_memstream(&buffer, &length);
  ASSERT_NE(sink, nullptr);
  garc_member_dump(nullptr, sink);
  garc_archive_dump(nullptr, sink);
  fclose(sink);
  EXPECT_NE(std::string(buffer, length).find("(null)"), std::string::npos);
  free(buffer);

  // And a NULL sink is ignored rather than crashing.
  garc_member_dump(nullptr, nullptr);
  garc_archive_dump(nullptr, nullptr);
}

TEST(TarDump, TheArchiveDumpNamesTheVariant) {
  TarArchive archive;
  archive.header(file_header("hello", 3)).data("abc").marker();

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened.archive, &member), GARC_OK);

  char * buffer = nullptr;
  size_t length = 0;
  FILE * sink = open_memstream(&buffer, &length);
  ASSERT_NE(sink, nullptr);
  garc_archive_dump(opened.archive, sink);
  fclose(sink);
  const std::string text(buffer, length);
  free(buffer);

  EXPECT_NE(text.find("format=tar"), std::string::npos);
  EXPECT_NE(text.find("ustar"), std::string::npos);
  EXPECT_NE(text.find("unsigned"), std::string::npos);
}

TEST(TarDump, EveryFieldShapeIsPrinted) {
  // garc_member_dump() has a branch per optional field, and a member the tar
  // reader produces never has some of them absent - it always fills in the mode
  // and the ids. So the absent cases are built directly, which is what the
  // public struct allows, and the present ones come from a real header.
  GARC_Member member;
  std::memset(&member, 0, sizeof(member));
  member.name = "a\\b"; // A backslash, which has to be escaped as \\.
  member.name_length = 3;
  member.type = GARC_MEMBER_SYMLINK;
  member.link_target = "target";
  member.link_target_length = 6;
  member.uname = "ghoti";
  member.uname_length = 5;
  member.gname = "ghotigroup";
  member.gname_length = 10;
  member.device_major = 5;
  member.device_minor = 42;
  member.device_valid = 1;
  member.mtime_source = GARC_TIME_PAX_DECIMAL;
  member.mtime_seconds = 1000000000;
  member.mtime_nanoseconds = 750044084u;
  // mode_valid and ids_valid deliberately left zero: those two "absent" arms are
  // unreachable through the tar reader and printing "0" for them would be a
  // number a caller could act on.

  char * buffer = nullptr;
  size_t length = 0;
  FILE * sink = open_memstream(&buffer, &length);
  ASSERT_NE(sink, nullptr);
  garc_member_dump(&member, sink);
  fclose(sink);
  const std::string text(buffer, length);
  free(buffer);

  EXPECT_NE(text.find("a\\\\b"), std::string::npos) << text;
  EXPECT_NE(text.find("link target: \"target\""), std::string::npos) << text;
  EXPECT_NE(text.find("uname: \"ghoti\""), std::string::npos) << text;
  EXPECT_NE(text.find("gname: \"ghotigroup\""), std::string::npos) << text;
  EXPECT_NE(text.find("device: 5/42"), std::string::npos) << text;
  EXPECT_NE(text.find("mode: absent"), std::string::npos) << text;
  EXPECT_NE(text.find("uid/gid: absent"), std::string::npos) << text;
  EXPECT_NE(text.find("pax decimal"), std::string::npos) << text;
  EXPECT_NE(text.find(".750044084"), std::string::npos) << text;
  EXPECT_NE(text.find("symlink"), std::string::npos) << text;
}

TEST(TarDump, AMemberWithNoTimeSaysSoRatherThanPrintingZero) {
  GARC_Member member;
  std::memset(&member, 0, sizeof(member));
  member.name = "x";
  member.name_length = 1;
  member.mtime_source = GARC_TIME_NONE;

  char * buffer = nullptr;
  size_t length = 0;
  FILE * sink = open_memstream(&buffer, &length);
  ASSERT_NE(sink, nullptr);
  garc_member_dump(&member, sink);
  fclose(sink);
  const std::string text(buffer, length);
  free(buffer);

  EXPECT_NE(text.find("mtime: none"), std::string::npos) << text;
}

TEST(TarDump, ANullNameIsPrintedAsSuchRatherThanDereferenced) {
  // A member with no name is not something the reader produces; a caller passing
  // a zeroed struct is. Dereferencing NULL in a debugging aid is a poor way to
  // find that out.
  GARC_Member member;
  std::memset(&member, 0, sizeof(member));

  char * buffer = nullptr;
  size_t length = 0;
  FILE * sink = open_memstream(&buffer, &length);
  ASSERT_NE(sink, nullptr);
  garc_member_dump(&member, sink);
  fclose(sink);
  const std::string text(buffer, length);
  free(buffer);
  EXPECT_NE(text.find("(null)"), std::string::npos) << text;
}

TEST(TarDump, AnArchiveWithNoCurrentMemberSaysSo) {
  TarArchive archive;
  archive.header(file_header("hello", 0)).marker();

  Opened opened;
  ASSERT_EQ(open_bytes(opened, archive.bytes()), GARC_OK);

  char * buffer = nullptr;
  size_t length = 0;
  FILE * sink = open_memstream(&buffer, &length);
  ASSERT_NE(sink, nullptr);
  garc_archive_dump(opened.archive, sink);
  fclose(sink);
  const std::string text(buffer, length);
  free(buffer);
  EXPECT_NE(text.find("member: (none)"), std::string::npos) << text;
}

//-----------------------------------------------------------------------------
// Stream failures
//-----------------------------------------------------------------------------

TEST(TarStreamFailure, AFailedReadDuringIdentificationIsForwarded) {
  // Identification reads the first block. A source that fails there must report
  // I/O rather than "not a tar" - a caller retrying a flaky disk needs to know
  // which it was.
  TarArchive archive;
  archive.header(file_header("hello", 0)).marker();
  std::vector<uint8_t> bytes = archive.bytes();

  BufferSource source(bytes.data(), bytes.size(), true, true);
  source.fail_reads(1);
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK);
  GARC_Archive * opened = nullptr;
  EXPECT_EQ(garc_open(stream, nullptr, &opened), GARC_ERR_IO);
  EXPECT_EQ(opened, nullptr);
  garc_stream_destroy(stream);
}

TEST(TarStreamFailure, AFailedReadOfAHeaderIsForwarded) {
  TarArchive archive;
  archive.header(file_header("first", 0)).header(file_header("second", 0))
      .marker();
  std::vector<uint8_t> bytes = archive.bytes();

  BufferSource source(bytes.data(), bytes.size(), true, true);
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK);
  GARC_Archive * opened = nullptr;
  ASSERT_EQ(garc_open(stream, nullptr, &opened), GARC_OK);

  const GARC_Member * member = nullptr;
  // The first member comes out of the identification window, so no read happens
  // for it. Arm the failure now, for the second header.
  ASSERT_EQ(garc_next(opened, &member), GARC_OK);
  source.fail_reads(1);
  EXPECT_EQ(garc_next(opened, &member), GARC_ERR_IO);

  garc_close(opened);
  garc_stream_destroy(stream);
}

TEST(TarStreamFailure, AFailedReadOfMemberDataIsForwarded) {
  TarArchive archive;
  archive.header(file_header("hello", 600)).data(std::string(600, 'a')).marker();
  std::vector<uint8_t> bytes = archive.bytes();

  BufferSource source(bytes.data(), bytes.size(), true, true);
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK);
  GARC_Archive * opened = nullptr;
  ASSERT_EQ(garc_open(stream, nullptr, &opened), GARC_OK);

  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened, &member), GARC_OK);
  source.fail_reads(1);
  char buffer[16];
  size_t got = 0;
  EXPECT_EQ(garc_read_member(opened, buffer, sizeof(buffer), &got),
      GARC_ERR_IO);

  garc_close(opened);
  garc_stream_destroy(stream);
}

TEST(TarStreamFailure, AFailedSkipIsForwarded) {
  TarArchive archive;
  archive.header(file_header("first", 600)).data(std::string(600, 'a'))
      .header(file_header("second", 0)).marker();
  std::vector<uint8_t> bytes = archive.bytes();

  BufferSource source(bytes.data(), bytes.size(), true, true);
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK);
  GARC_Archive * opened = nullptr;
  ASSERT_EQ(garc_open(stream, nullptr, &opened), GARC_OK);

  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened, &member), GARC_OK);
  source.fail_seeks();
  // garc_next() steps over the unread data, which on this source is a seek.
  EXPECT_EQ(garc_next(opened, &member), GARC_ERR_IO);
  // And skip_member reports it too, rather than claiming to have skipped.
  EXPECT_EQ(garc_skip_member(opened), GARC_ERR_INVALID)
      << "there should be no current member after a failed next";

  garc_close(opened);
  garc_stream_destroy(stream);
}

TEST(TarStreamFailure, AFailedReadOfACarrierPayloadIsForwarded) {
  // The payload is read from the stream after the carrier's header, so a failure
  // there is a failure of the archive rather than a corrupt name. GARC_ERR_IO and
  // not GARC_ERR_CORRUPT: the bytes were never seen, so nothing is known about
  // them, and a reader that reported corruption would accuse the archive of the
  // stream's fault.
  const std::string name(400, 'n');

  TarArchive archive;
  archive.header(long_header('L', name.size() + 1))
      .data(name + std::string(1, '\0'))
      .header(file_header("short", 0))
      .marker();
  std::vector<uint8_t> bytes = archive.bytes();

  BufferSource source(bytes.data(), bytes.size(), false, false);
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK);
  GARC_Archive * opened = nullptr;
  ASSERT_EQ(garc_open(stream, nullptr, &opened), GARC_OK);

  // Armed after the open, because identification reads the first block and an
  // arm before it would test a failure during identification instead - which is
  // a different branch, already covered above.
  source.fail_reads(1);

  const GARC_Member * member = nullptr;
  EXPECT_EQ(garc_next(opened, &member), GARC_ERR_IO);

  garc_close(opened);
  garc_stream_destroy(stream);
}

TEST(TarStreamFailure, AFailedSkipOfACarriersPaddingIsForwarded) {
  // The payload is padded to a block like any member's data, so there is a skip
  // between the last byte of the name and the header it describes. On a seekable
  // stream that skip is a seek, and a seek that fails leaves the cursor somewhere
  // unknown - so the only safe answer is the failure, not the name that was
  // already read.
  const std::string name(400, 'n');

  TarArchive archive;
  archive.header(long_header('L', name.size() + 1))
      .data(name + std::string(1, '\0'))
      .header(file_header("short", 0))
      .marker();
  std::vector<uint8_t> bytes = archive.bytes();

  BufferSource source(bytes.data(), bytes.size(), true, true);
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK);
  GARC_Archive * opened = nullptr;
  ASSERT_EQ(garc_open(stream, nullptr, &opened), GARC_OK);

  source.fail_seeks();

  const GARC_Member * member = nullptr;
  EXPECT_EQ(garc_next(opened, &member), GARC_ERR_IO);
  EXPECT_GT(source.seeks(), 0u)
      << "no seek was attempted, so the failure came from somewhere else and "
         "this test is not asserting what it says";

  garc_close(opened);
  garc_stream_destroy(stream);
}

TEST(TarStreamFailure, SkipMemberForwardsAFailure) {
  TarArchive archive;
  archive.header(file_header("first", 600)).data(std::string(600, 'a')).marker();
  std::vector<uint8_t> bytes = archive.bytes();

  BufferSource source(bytes.data(), bytes.size(), true, true);
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK);
  GARC_Archive * opened = nullptr;
  ASSERT_EQ(garc_open(stream, nullptr, &opened), GARC_OK);

  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(opened, &member), GARC_OK);
  source.fail_seeks();
  EXPECT_EQ(garc_skip_member(opened), GARC_ERR_IO);

  garc_close(opened);
  garc_stream_destroy(stream);
}

TEST(TarStrings, EveryEnumHasAStringAndNoneShareOne) {
  // The same closed-enum sweep test_core.cpp does for the result codes, for the
  // four enums this module adds. A constant added without a string lands here.
  auto distinct = [](auto lookup, int count) {
    std::set<std::string> seen;
    for (int i = 0; i < count; ++i) {
      const char * text = lookup(i);
      EXPECT_NE(text, nullptr);
      EXPECT_STRNE(text, "invalid") << "value " << i << " falls through";
      EXPECT_TRUE(seen.insert(text).second)
          << "value " << i << " shares its string: " << text;
    }
    EXPECT_STREQ(lookup(count), "invalid");
  };

  distinct([](int i) {
    return garc_member_type_string(static_cast<GARC_Member_Type>(i));
  }, GARC_MEMBER_TYPE_COUNT);
  distinct([](int i) {
    return garc_name_encoding_string(static_cast<GARC_Name_Encoding>(i));
  }, GARC_NAME_ENCODING_COUNT);
  distinct([](int i) {
    return garc_time_source_string(static_cast<GARC_Time_Source>(i));
  }, GARC_TIME_SOURCE_COUNT);
  distinct([](int i) {
    return garc_tar_variant_string(static_cast<GARC_Tar_Variant>(i));
  }, GARC_TAR_VARIANT_COUNT);
  distinct([](int i) {
    return garc_format_string(static_cast<GARC_Format>(i));
  }, GARC_FORMAT_COUNT);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
