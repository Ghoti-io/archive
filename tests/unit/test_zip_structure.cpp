/**
 * @file
 *
 * What the zip reader refuses, and the well-formed twin of every refusal.
 *
 * **No tool writes these archives, which is why they are built here.** Every
 * fixture in `tests/data/zip/` came out of Info-ZIP, libarchive, 7-Zip or
 * Python's zipfile, and not one of them has a local header that contradicts its
 * central directory, a declared member count that is wrong, or a zip64 field one
 * value short. Those are the inputs a reader's refusals exist for, and a refusal
 * no input reaches is a branch nobody has run.
 *
 * **Every test here turns exactly one thing.** `ZipBuilder` with no knob turned
 * produces an archive this library reads, and `TheControlIsRead` is that archive:
 * if it ever failed, every refusal below would be measuring the builder instead
 * of the reader.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "failing_allocator.h"
#include "test_helpers.h"
#include "zip_builder.h"

using garctest::BufferSource;
using garctest::FailingAllocator;
using garctest::ZipBuilder;

namespace {

/** An archive opened over bytes a test built. */
class Built {
public:
  explicit Built(const std::vector<uint8_t> & bytes,
      const GARC_Limits * limits = nullptr, bool can_seek = true)
      : bytes_(bytes), source_(bytes_.data(), bytes_.size(), can_seek, true) {
    if (garc_stream_create_callback(source_.callbacks(), &stream_) != GARC_OK) {
      return;
    }
    open_result_ = garc_open(stream_, limits, &archive_);
  }

  ~Built() {
    garc_close(archive_);
    garc_stream_destroy(stream_);
  }

  Built(const Built &) = delete;
  Built & operator=(const Built &) = delete;

  GARC_Result open_result() const { return open_result_; }
  GARC_Archive * archive() const { return archive_; }

  /** Walk to the end, returning the status that stopped the walk. */
  GARC_Result walk(size_t * out_members = nullptr) {
    const GARC_Member * member = nullptr;
    size_t count = 0;
    GARC_Result result;
    while ((result = garc_next(archive_, &member)) == GARC_OK) {
      ++count;
    }
    if (out_members) {
      *out_members = count;
    }
    return result;
  }

private:
  std::vector<uint8_t> bytes_;
  BufferSource source_;
  GARC_Stream * stream_ = nullptr;
  GARC_Archive * archive_ = nullptr;
  GARC_Result open_result_ = GARC_ERR_INTERNAL;
};

/** Two members and nothing wrong with them. */
std::vector<uint8_t> control() {
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.add("second.txt", "and another\n");
  return builder.build();
}

/**
 * Compress bytes with one of `compress`'s codecs, through this library's sink.
 *
 * **The payload of a compressed zip member has to come from somewhere, and no
 * tool here will write one to order.** `ZipBuilder` stores what it is given, so a
 * test about method 8 needs the deflate bytes; this makes them with the public
 * compressing sink, which is the same codec the reader will use to undo them.
 *
 * What that does and does not test is worth being clear about: it does *not* show
 * that deflate is implemented correctly - that is `compress`'s question, and the
 * corpus answers the container's half by handing the reader payloads four real
 * writers produced. What it tests is the **routing**: that a member declaring
 * method 8 reaches the deflate decoder with the right bounds, and one declaring
 * 93 reaches zstd.
 */
std::string compress_with(const char * method, const std::string & plain) {
  GARC_Sink * memory = nullptr;
  if (garc_sink_create_memory(&memory) != GARC_OK) {
    return std::string();
  }
  GARC_Sink * packer = nullptr;
  if (garc_sink_create_compress(memory, method, nullptr, &packer) != GARC_OK) {
    garc_sink_destroy(memory);
    return std::string();
  }
  std::string out;
  if (garc_sink_write(packer, plain.data(), plain.size()) == GARC_OK
      && garc_sink_finish(packer) == GARC_OK) {
    const void * bytes = nullptr;
    size_t length = 0;
    if (garc_sink_data(memory, &bytes, &length) == GARC_OK) {
      out.assign(static_cast<const char *>(bytes), length);
    }
  }
  garc_sink_destroy(packer);
  garc_sink_destroy(memory);
  return out;
}

/** Add a member whose stored bytes are a real codec stream of `plain`. */
void add_compressed(ZipBuilder & builder, const std::string & name,
    const std::string & plain, uint16_t method, const char * codec) {
  const std::string packed = compress_with(codec, plain);
  builder.add(name, packed);
  builder.last().method = method;
  builder.last().crc = ZipBuilder::crc32(plain);
  builder.last().override_sizes = true;
  builder.last().central_compressed_size = static_cast<uint32_t>(packed.size());
  builder.last().central_size = static_cast<uint32_t>(plain.size());
}

/**
 * Every shape a sweep has to cover, because each reads something the others do
 * not.
 *
 * **A sweep over one archive cannot see the arms the others reach.** The comment
 * is read by its own call, so is the extra field, so is a symlink's target, and a
 * zip64 archive reads a locator and a second end record before any of it - each
 * of those is a separate allocation and a separate read, with a separate failure
 * arm. A failure sweep whose population was the plain control archive would run
 * hundreds of iterations and never touch four of them, and would report clean.
 */
std::vector<std::pair<std::string, std::vector<uint8_t>>> shapes() {
  std::vector<std::pair<std::string, std::vector<uint8_t>>> out;
  out.emplace_back("plain", control());

  {
    ZipBuilder builder;
    builder.add("hello.txt", "hello, archive\n");
    builder.comment("a comment, read by a call of its own");
    out.emplace_back("comment", builder.build());
  }
  {
    std::string extra;
    ZipBuilder::append16(extra, 0x5455u);
    ZipBuilder::append16(extra, 5u);
    extra.push_back(0x01);
    ZipBuilder::append32(extra, 1000000000u);
    ZipBuilder builder;
    builder.add("hello.txt", "hello, archive\n");
    builder.last().central_extra = extra;
    out.emplace_back("extra field", builder.build());
  }
  {
    ZipBuilder builder;
    builder.add("link", "../elsewhere");
    builder.last().external_attributes = 0120777u << 16;
    out.emplace_back("symlink", builder.build());
  }
  {
    ZipBuilder builder;
    builder.add("hello.txt", "hello, archive\n");
    builder.zip64();
    out.emplace_back("zip64", builder.build());
  }
  {
    // A deflated member, which reads through a decoder and a bounded view of the
    // stream rather than from the stream itself - two more objects to allocate and
    // a different read arm.
    ZipBuilder builder;
    add_compressed(builder, "packed.txt", std::string(600u, 'p'),
        GARC_ZIP_METHOD_DEFLATE, "deflate");
    out.emplace_back("deflated", builder.build());
  }
  return out;
}

//-----------------------------------------------------------------------------
// The control
//-----------------------------------------------------------------------------

TEST(ZipStructure, TheControlIsRead) {
  // **The test every other test in this file depends on.** If this fails, each
  // refusal below is measuring the builder rather than the reader - which is the
  // shape a malformed-input suite goes wrong in silently.
  Built built(control());
  ASSERT_EQ(built.open_result(), GARC_OK);
  EXPECT_EQ(garc_zip_declared_members(built.archive()), 2u);
  size_t members = 0;
  EXPECT_EQ(built.walk(&members), GARC_END);
  EXPECT_EQ(members, 2u);
}

TEST(ZipStructure, TheControlsMemberIsReadable) {
  Built built(control());
  ASSERT_EQ(built.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  char buffer[64];
  size_t got = 0;
  ASSERT_EQ(garc_read_member(built.archive(), buffer, sizeof(buffer), &got),
      GARC_OK);
  EXPECT_EQ(std::string(buffer, got), "hello, archive\n");
  // The DOS fields the builder writes are the corpus's second, so a reader that
  // got the conversion wrong would disagree with the corpus tests as well.
  EXPECT_EQ(member->mtime_seconds, 1000000000);
  EXPECT_EQ(member->mtime_source, GARC_TIME_ZIP_DOS);
}

//-----------------------------------------------------------------------------
// Finding the end record
//-----------------------------------------------------------------------------

TEST(ZipStructure, ThreeBytesAreNotEnoughToIdentifyAnything) {
  // Identification looks at four bytes, so a shorter file cannot be claimed from
  // the front - and the backwards scan needs 22. GARC_ERR_FORMAT is the honest
  // answer: nothing about these bytes says zip.
  const std::vector<uint8_t> bytes = {'P', 'K', 5};
  Built built(bytes);
  EXPECT_EQ(built.open_result(), GARC_ERR_FORMAT);
}

TEST(ZipStructure, AFileTooSmallForAnEndRecordIsNotAZip) {
  const std::vector<uint8_t> bytes = {'P', 'K', 5, 6, 0, 0};
  Built built(bytes);
  EXPECT_EQ(built.open_result(), GARC_ERR_CORRUPT)
      << "the first bytes say zip, so this is a truncated zip and not a mystery";
}

TEST(ZipStructure, AnEndRecordWhoseCommentLengthIsWrongIsNotTheRecord) {
  // The validating half of the backwards scan. The record is there, its signature
  // is there, and its comment length does not account for the bytes after it - so
  // it is not the record, and there is no other.
  std::vector<uint8_t> bytes = control();
  // The comment length is the last two bytes of the record, which is the end of
  // the file when there is no comment.
  bytes[bytes.size() - 2u] = 9u;
  Built built(bytes);
  EXPECT_EQ(built.open_result(), GARC_ERR_CORRUPT);
}

TEST(ZipStructure, BytesAfterTheEndRecordHideTheArchive) {
  // **A zip has to end where the stream ends.** The comment length is what says
  // how much follows the record, so bytes beyond it are bytes no conforming
  // reader can account for - and scanning further would mean finding a signature
  // inside member data, which `python-data-decoy.zip` proves is a real risk.
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.trailer("appended bytes nobody declared");
  Built built(builder.build());
  EXPECT_EQ(built.open_result(), GARC_ERR_CORRUPT);
}

TEST(ZipStructure, ACommentIsAcceptedWhenItsLengthIsRight) {
  // The twin of the two tests above: the same trailing bytes, declared.
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.comment("a declared comment");
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  size_t length = 0;
  const char * comment = garc_zip_archive_comment(built.archive(), &length);
  ASSERT_NE(comment, nullptr);
  EXPECT_EQ(std::string(comment, length), "a declared comment");
}

TEST(ZipStructure, TheLastValidEndRecordWins) {
  // A comment holding a *complete and self-consistent* end record - its own
  // comment length accounts for exactly the bytes after it - is indistinguishable
  // from the real one by anything in the format. Two valid records, and the one
  // nearer the end is taken, which is what unzip and libarchive do; this test
  // exists so the choice is written down rather than being whichever way the loop
  // happened to run.
  //
  // The decoy here describes an empty archive, so taking it is visible: the
  // archive reads as having no members instead of one.
  std::string decoy("PK\x05\x06", 4);
  ZipBuilder::append16(decoy, 0u);  // this disk
  ZipBuilder::append16(decoy, 0u);  // the central directory's disk
  ZipBuilder::append16(decoy, 0u);  // entries here
  ZipBuilder::append16(decoy, 0u);  // entries total
  ZipBuilder::append32(decoy, 0u);  // central directory size
  ZipBuilder::append32(decoy, 0u);  // central directory offset
  ZipBuilder::append16(decoy, 0u);  // its own comment length: nothing follows

  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.comment(decoy);
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  EXPECT_EQ(garc_zip_declared_members(built.archive()), 0u)
      << "the decoy is the last valid record, and that is the one every reader "
         "takes";
}

//-----------------------------------------------------------------------------
// The end record's own fields
//-----------------------------------------------------------------------------

TEST(ZipStructure, AMultiDiskArchiveIsRefusedByName) {
  // Every count in the record is per-disk, and the other disks are files this
  // stream does not have. A reader that ignored the numbers would report the last
  // disk's members as the whole archive, which is a wrong answer rather than a
  // failure.
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.disk(1u, 0u);
  Built built(builder.build());
  EXPECT_EQ(built.open_result(), GARC_ERR_UNSUPPORTED);
}

TEST(ZipStructure, ACentralDirectoryOnAnotherDiskIsRefused) {
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.disk(0u, 3u);
  Built built(builder.build());
  EXPECT_EQ(built.open_result(), GARC_ERR_UNSUPPORTED);
}

TEST(ZipStructure, EntriesOnThisDiskDifferingFromTheTotalIsRefused) {
  // The one field combination that says "spanned" without setting a disk number.
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.add("second.txt", "and another\n");
  builder.entries_here(1);
  Built built(builder.build());
  EXPECT_EQ(built.open_result(), GARC_ERR_UNSUPPORTED);
}

TEST(ZipStructure, ADeclaredCentralDirectorySizeLargerThanTheFileIsRefused) {
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.declared_central_size(1u << 20);
  Built built(builder.build());
  EXPECT_EQ(built.open_result(), GARC_ERR_CORRUPT);
}

TEST(ZipStructure, ACentralDirectoryOffsetPastItsOwnStartIsRefused) {
  // The offset and the size together say where the directory is; an offset beyond
  // what the size allows cannot be resolved into a position, and guessing would
  // be a seek into a member's data.
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.declared_central_offset(1u << 20);
  Built built(builder.build());
  EXPECT_EQ(built.open_result(), GARC_ERR_CORRUPT);
}

TEST(ZipStructure, ADeclaredMemberCountHigherThanTheDirectoryHoldsIsRefused) {
  // The count is what bounds the walk, so the failure has to arrive as the walk
  // runs out rather than at open: nothing in the end record is inconsistent.
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.declared_members(3);
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  size_t members = 0;
  EXPECT_EQ(built.walk(&members), GARC_ERR_CORRUPT);
  EXPECT_EQ(members, 1u) << "the members that were there are still reported";
}

TEST(ZipStructure, ADeclaredMemberCountLowerThanTheDirectoryHoldsStopsEarly) {
  // The other direction, and **not** an error: the count is the archive's own
  // statement of what it holds, and a directory with something after the last
  // declared entry is what a writer that appended without updating the count
  // leaves. Reading past the count would be reading bytes the archive does not
  // claim are members.
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.add("second.txt", "and another\n");
  builder.declared_members(1);
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  size_t members = 0;
  EXPECT_EQ(built.walk(&members), GARC_END);
  EXPECT_EQ(members, 1u);
}

//-----------------------------------------------------------------------------
// The central directory's entries
//-----------------------------------------------------------------------------

TEST(ZipStructure, ACentralEntryWithTheWrongSignatureIsRefused) {
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.add("second.txt", "and another\n");
  builder.break_signature('c', 1u);
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  size_t members = 0;
  EXPECT_EQ(built.walk(&members), GARC_ERR_CORRUPT);
  EXPECT_EQ(members, 1u);
}

TEST(ZipStructure, AWrongDeclaredDirectorySizeReadsAsAStubAndThenFails) {
  // **A finding rather than a design.** The base offset is computed as (where the
  // directory turned out to be) minus (where it says it is), so a declared size
  // that is too small is indistinguishable from bytes in front of the archive:
  // the reader concludes there is a stub, shifts every offset by the difference,
  // and lands in the first member's data instead of on the directory. The failure
  // is therefore a signature mismatch and not a size check - which is fine, since
  // it fails closed, but it means the size check further down is *not* what this
  // input reaches. AnEntryClaimingALongerNameThanFitsIsRefused is the one that
  // reaches it.
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.declared_central_size(20);
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  EXPECT_NE(garc_zip_base_offset(built.archive()), 0u)
      << "the difference was absorbed into the base offset";
  EXPECT_EQ(built.walk(), GARC_ERR_CORRUPT);
}

TEST(ZipStructure, AnEntryClaimingALongerNameThanFitsIsRefused) {
  // The entry's own lengths are what can run it past the end of the directory
  // without moving anything else: a name length of 300 for a nine-byte name. The
  // bytes beyond the directory are the end record and the comment, so a reader
  // that took the claim would report a name made of its own end record.
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.last().override_name_length = true;
  builder.last().name_length = 300u;
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  EXPECT_EQ(built.walk(), GARC_ERR_CORRUPT);
}

TEST(ZipStructure, AnEntryOnAnotherDiskIsRefused) {
  // The end record said one disk and this entry says its local header is on
  // another. Reading it here would mean reading whatever is at that offset in
  // *this* file.
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.last().disk_start = 2u;
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  EXPECT_EQ(built.walk(), GARC_ERR_UNSUPPORTED);
}

//-----------------------------------------------------------------------------
// The local header, which is read for one thing and checked for two
//-----------------------------------------------------------------------------

TEST(ZipStructure, ALocalHeaderWithTheWrongSignatureIsRefused) {
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.break_signature('l', 0u);
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  EXPECT_EQ(built.walk(), GARC_ERR_CORRUPT);
}

TEST(ZipStructure, ALocalHeaderNamingADifferentMemberIsRefused) {
  // **The ambiguity attack, in its simplest form.** The central directory says
  // one name and the local header says another, so the archive says two things
  // about which member this is - and a reader that reported one while extracting
  // the other is the whole class of zip confusion bugs. No writer in the corpus
  // disagrees with itself, so refusing costs nothing real.
  ZipBuilder builder;
  builder.add("innocent.txt", "hello, archive\n");
  // Exactly as long as "innocent.txt", so the length check passes and the bytes
  // are what differ - otherwise this would be the same test as the one below.
  builder.last().local_name = "evil.txt1234";
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  EXPECT_EQ(built.walk(), GARC_ERR_CORRUPT);
}

TEST(ZipStructure, ALocalHeaderNameOfADifferentLengthIsRefused) {
  ZipBuilder builder;
  builder.add("innocent.txt", "hello, archive\n");
  builder.last().local_name = "short";
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  EXPECT_EQ(built.walk(), GARC_ERR_CORRUPT);
}

TEST(ZipStructure, ALocalOffsetInsideTheCentralDirectoryIsRefused) {
  // A member whose local header is said to be inside the directory itself. The
  // signature check would usually catch it; this is the check that does not
  // depend on what happens to be at that offset.
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  ZipBuilder probe;
  probe.add("hello.txt", "hello, archive\n");
  const std::vector<uint8_t> reference = probe.build();
  builder.last().override_local_offset = true;
  // The directory starts right after the one member, so its own offset is the
  // first thing beyond the data.
  builder.last().local_offset = static_cast<uint32_t>(reference.size() - 22u - 55u);
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  EXPECT_EQ(built.walk(), GARC_ERR_CORRUPT);
}

TEST(ZipStructure, AStoredMemberWhoseSizesDisagreeIsRefused) {
  // Stored means the two sizes are one number. A member that says otherwise
  // describes something the method cannot do, and both numbers are things a
  // reader seeks by.
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.last().override_sizes = true;
  builder.last().central_size = 15u;
  builder.last().central_compressed_size = 9u;
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  EXPECT_EQ(built.walk(), GARC_ERR_CORRUPT);
}

TEST(ZipStructure, AMemberWhoseDataIsShorterThanDeclaredFailsOnTheRead) {
  // The declared size is what the archive said; whether the bytes are there is
  // answered by reading them. Truncating the file after the local header leaves
  // the central directory intact, so the walk succeeds and the read is where it
  // shows up.
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  std::vector<uint8_t> bytes = builder.build();
  const std::vector<uint8_t> whole = bytes;
  // Rewrite the data so the file is shorter without moving the directory: not
  // possible, so this instead points the member at the very end of the file,
  // where fewer than fifteen bytes remain.
  ZipBuilder truncated;
  truncated.add("hello.txt", "hello, archive\n");
  truncated.last().override_local_offset = true;
  truncated.last().local_offset = static_cast<uint32_t>(whole.size() - 30u - 9u);
  Built built(truncated.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  // Either the local header check or the short read refuses it; what must not
  // happen is a successful read of fifteen bytes that are not there.
  const GARC_Result result = built.walk();
  EXPECT_TRUE(result == GARC_ERR_CORRUPT) << garc_result_string(result);
}

//-----------------------------------------------------------------------------
// zip64 fields
//-----------------------------------------------------------------------------

TEST(ZipStructure, AZipSixtyFourMarkerWithNoExtraFieldIsRefused) {
  // 0xFFFFFFFF means "the real value is in a 0x0001 field". With no such field,
  // taking the marker as the value would report a member of 4 GiB minus one.
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.last().override_sizes = true;
  builder.last().central_size = 0xFFFFFFFFu;
  builder.last().central_compressed_size = 15u;
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  EXPECT_EQ(built.walk(), GARC_ERR_CORRUPT);
}

TEST(ZipStructure, AZipSixtyFourFieldTooShortForItsMarkersIsRefused) {
  // Two markers, one value. The field's own length is the only thing that can
  // say so, and a reader that read the second value anyway would read the
  // following extra field's header as the high half of a size.
  std::string extra;
  ZipBuilder::append16(extra, 0x0001u);
  ZipBuilder::append16(extra, 8u);
  ZipBuilder::append64(extra, 15u);

  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.last().override_sizes = true;
  builder.last().central_size = 0xFFFFFFFFu;
  builder.last().central_compressed_size = 0xFFFFFFFFu;
  builder.last().central_extra = extra;
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  EXPECT_EQ(built.walk(), GARC_ERR_CORRUPT);
}

TEST(ZipStructure, AZipSixtyFourFieldSuppliesOnlyTheMarkedValues) {
  // The twin: one marker, one value, and the compressed size stays in its 32-bit
  // field. This is the layout `zip -fz` actually writes, so it is the one a
  // reader that consumed the values positionally would get wrong.
  std::string extra;
  ZipBuilder::append16(extra, 0x0001u);
  ZipBuilder::append16(extra, 8u);
  ZipBuilder::append64(extra, 15u);

  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.last().override_sizes = true;
  builder.last().central_size = 0xFFFFFFFFu;
  builder.last().central_compressed_size = 15u;
  builder.last().central_extra = extra;
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  EXPECT_EQ(member->size, 15u);
  EXPECT_EQ(garc_zip_member_compressed_size(built.archive()), 15u);
  EXPECT_TRUE(garc_zip_member_used_zip64(built.archive()));
}

//-----------------------------------------------------------------------------
// Extra fields that are not well-formed
//-----------------------------------------------------------------------------

TEST(ZipStructure, AnExtraFieldRunningPastTheBlockStopsTheWalkOverIt) {
  // A field whose declared length exceeds what is left. The bytes after it are
  // not fields, so the walk stops - and what came *before* it still applies,
  // which is what this checks: the timestamp is read and the truncated field
  // behind it is ignored rather than making the member unreadable.
  std::string extra;
  ZipBuilder::append16(extra, 0x5455u);      // extended timestamp
  ZipBuilder::append16(extra, 5u);
  extra.push_back(0x01);                      // flags: mtime present
  ZipBuilder::append32(extra, 1000000000u);
  ZipBuilder::append16(extra, 0x7875u);      // Unix uid/gid
  ZipBuilder::append16(extra, 200u);          // ...and a length nothing backs
  extra.push_back(0x01);

  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.last().central_extra = extra;
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  EXPECT_EQ(member->mtime_source, GARC_TIME_ZIP_UNIX);
  EXPECT_EQ(member->mtime_seconds, 1000000000);
  EXPECT_FALSE(member->ids_valid) << "the truncated field supplied nothing";
}

TEST(ZipStructure, AUnixIdFieldWithAnImpossibleWidthSuppliesNothing) {
  // The 0x7875 field's ids are length-prefixed, and a length of nine has no
  // meaning: this library refuses the field rather than reading eight bytes and
  // a stray one.
  std::string extra;
  ZipBuilder::append16(extra, 0x7875u);
  ZipBuilder::append16(extra, 12u);
  extra.push_back(0x01);  // version
  extra.push_back(0x09);  // uid width: too wide to be a uid
  for (int i = 0; i < 9; ++i) {
    extra.push_back(0x00);
  }

  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.last().central_extra = extra;
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  EXPECT_FALSE(member->ids_valid);
}

TEST(ZipStructure, AUnixIdFieldOfTheOrdinaryShapeIsRead) {
  // The twin of the two above: a well-formed 0x7875, which Info-ZIP writes by
  // default and which the corpus's `infozip-extras.zip` carries.
  std::string extra;
  ZipBuilder::append16(extra, 0x7875u);
  ZipBuilder::append16(extra, 11u);
  extra.push_back(0x01);
  extra.push_back(0x04);
  ZipBuilder::append32(extra, 1234u);
  extra.push_back(0x04);
  ZipBuilder::append32(extra, 5678u);

  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.last().central_extra = extra;
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  ASSERT_TRUE(member->ids_valid);
  EXPECT_EQ(member->uid, 1234);
  EXPECT_EQ(member->gid, 5678);
}

TEST(ZipStructure, AnNtfsTimestampSuppliesNanosecondsAndWins) {
  // 100-nanosecond intervals since 1601, which is the only sub-second time a zip
  // can carry. The value here is 2001-09-09T01:46:40.1234567Z, so the fraction
  // is visible and the DOS field's whole second is not the answer.
  const uint64_t filetime = (1000000000ull + 11644473600ull) * 10000000ull
      + 1234567ull;
  std::string attribute;
  ZipBuilder::append16(attribute, 0x0001u);
  ZipBuilder::append16(attribute, 24u);
  ZipBuilder::append64(attribute, filetime);
  ZipBuilder::append64(attribute, filetime);
  ZipBuilder::append64(attribute, filetime);

  std::string extra;
  ZipBuilder::append16(extra, 0x000Au);
  ZipBuilder::append16(extra, static_cast<uint16_t>(4u + attribute.size()));
  ZipBuilder::append32(extra, 0u);  // reserved
  extra += attribute;

  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.last().central_extra = extra;
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  EXPECT_EQ(member->mtime_source, GARC_TIME_ZIP_NTFS);
  EXPECT_EQ(member->mtime_seconds, 1000000000);
  EXPECT_EQ(member->mtime_nanoseconds, 123456700u);
}

TEST(ZipStructure, ADosDateOutOfRangeIsNoTimeRatherThanAWrongOne) {
  // A date field of zero has month 0 and day 0. The arithmetic would answer with
  // a date that does not exist, so the member is reported as carrying no usable
  // time - which is what it carries.
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.last().dos_date = 0u;
  builder.last().dos_time = 0u;
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  EXPECT_EQ(member->mtime_source, GARC_TIME_NONE);
  EXPECT_EQ(member->mtime_seconds, 0);
}

TEST(ZipStructure, TheDosConversionAgreesWithTimegmAcrossTheRange) {
  // A sweep rather than one value, because the civil-date arithmetic has a leap
  // year rule, a century rule and a 400-year rule, and one date exercises none of
  // them. `timegm` is the independent implementation; the library cannot use it
  // because it is POSIX rather than C17, which is exactly why it is a useful
  // oracle here.
  const struct {
    unsigned year, month, day, hour, minute, second;
  } cases[] = {
    {1980, 1, 1, 0, 0, 0},      // the epoch of the DOS field itself
    {1999, 12, 31, 23, 59, 58}, // the last even second of the century
    {2000, 2, 29, 12, 0, 0},    // a leap day in a year divisible by 400
    {2001, 9, 9, 1, 46, 40},    // the corpus's second
    {2024, 2, 29, 6, 30, 30},   // an ordinary leap day
    {2100, 3, 1, 0, 0, 0},      // the day after a century that is not a leap year
    {2107, 12, 31, 23, 59, 58}, // the last date the seven-bit year can express
  };
  for (const auto & one : cases) {
    const uint16_t date = static_cast<uint16_t>(((one.year - 1980u) << 9)
        | (one.month << 5) | one.day);
    const uint16_t time = static_cast<uint16_t>((one.hour << 11)
        | (one.minute << 5) | (one.second / 2u));
    ZipBuilder builder;
    builder.add("hello.txt", "x");
    builder.last().dos_date = date;
    builder.last().dos_time = time;
    Built built(builder.build());
    ASSERT_EQ(built.open_result(), GARC_OK);
    const GARC_Member * member = nullptr;
    ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);

    std::tm parts = {};
    parts.tm_year = static_cast<int>(one.year) - 1900;
    parts.tm_mon = static_cast<int>(one.month) - 1;
    parts.tm_mday = static_cast<int>(one.day);
    parts.tm_hour = static_cast<int>(one.hour);
    parts.tm_min = static_cast<int>(one.minute);
    parts.tm_sec = static_cast<int>(one.second);
    EXPECT_EQ(member->mtime_seconds, static_cast<int64_t>(timegm(&parts)))
        << one.year << "-" << one.month << "-" << one.day;
    EXPECT_EQ(member->mtime_source, GARC_TIME_ZIP_DOS);
  }
}

//-----------------------------------------------------------------------------
// Types, and the host byte that decides whether the mode means anything
//-----------------------------------------------------------------------------

TEST(ZipStructure, AWindowsMadeArchiveHasNoModeBitsToRead) {
  // The mode lives in the high half of external_file_attributes and is only
  // meaningful when `version made by` says Unix. On a DOS or Windows archive that
  // half is zero rather than absent, so a reader that read it unconditionally
  // would report a mode of 0000 for every member of a perfectly ordinary zip.
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.last().version_made_by = 0x0014u;  // host 0: FAT
  builder.last().external_attributes = 0x20u; // the DOS "archive" bit
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  EXPECT_FALSE(member->mode_valid);
  EXPECT_EQ(member->type, GARC_MEMBER_FILE);
  EXPECT_EQ(garc_zip_member_external_attributes(built.archive()), 0x20u);
}

TEST(ZipStructure, TheDosDirectoryBitMakesADirectoryWithoutATrailingSlash) {
  ZipBuilder builder;
  builder.add("folder", "");
  builder.last().version_made_by = 0x0014u;
  builder.last().external_attributes = 0x10u;
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  EXPECT_EQ(member->type, GARC_MEMBER_DIRECTORY);
}

TEST(ZipStructure, ATrailingSlashIsADirectoryWhateverTheModeSays) {
  // The convention every tool follows, and the only thing a DOS-made archive
  // has. It wins over the mode bits, which here claim a regular file.
  ZipBuilder builder;
  builder.add("folder/", "");
  builder.last().external_attributes = 0100644u << 16;
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  EXPECT_EQ(member->type, GARC_MEMBER_DIRECTORY);
}

TEST(ZipStructure, EveryUnixFileTypeMapsToItsOwnMemberType) {
  // The S_IFMT values, each read out of the same field, so a mapping that
  // collapsed two of them would show up here rather than in whichever archive
  // first carried a fifo.
  const struct {
    uint32_t mode;
    GARC_Member_Type type;
  } cases[] = {
    {0100644u, GARC_MEMBER_FILE},
    {0040755u, GARC_MEMBER_DIRECTORY},
    {0120777u, GARC_MEMBER_SYMLINK},
    {0010644u, GARC_MEMBER_FIFO},
    {0020644u, GARC_MEMBER_CHAR_DEVICE},
    {0060644u, GARC_MEMBER_BLOCK_DEVICE},
    {0140644u, GARC_MEMBER_OTHER},  // a socket, which no archive should hold
    {0000644u, GARC_MEMBER_FILE},   // no type bits at all, as Python writes
  };
  for (const auto & one : cases) {
    ZipBuilder builder;
    builder.add("thing", one.type == GARC_MEMBER_SYMLINK ? "target" : "");
    builder.last().external_attributes = one.mode << 16;
    Built built(builder.build());
    ASSERT_EQ(built.open_result(), GARC_OK) << std::oct << one.mode;
    const GARC_Member * member = nullptr;
    ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK) << std::oct << one.mode;
    EXPECT_EQ(member->type, one.type) << std::oct << one.mode;
  }
}

TEST(ZipStructure, ASymlinkTargetIsTheMembersData) {
  // zip has no link name field. The target is the member's contents, which is why
  // reporting it means reading data during the walk.
  ZipBuilder builder;
  builder.add("link", "../../etc/passwd");
  builder.last().external_attributes = 0120777u << 16;
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  ASSERT_EQ(member->type, GARC_MEMBER_SYMLINK);
  ASSERT_NE(member->link_target, nullptr);
  EXPECT_EQ(std::string(member->link_target, member->link_target_length),
      "../../etc/passwd");
  // And the data is still readable as data, because the target being metadata
  // here is this library's reading rather than the archive's.
  char buffer[64];
  size_t got = 0;
  ASSERT_EQ(garc_read_member(built.archive(), buffer, sizeof(buffer), &got),
      GARC_OK);
  EXPECT_EQ(std::string(buffer, got), "../../etc/passwd");
}

TEST(ZipStructure, ASymlinkTargetLongerThanTheNameCapIsNotRead) {
  // The eager read is bounded by the same cap a name is, because a target is a
  // path: a member claiming a gigabyte-long symlink target must not make the walk
  // allocate one. The member is still reported, and its data still readable.
  GARC_Limits limits;
  garc_limits_default(&limits);
  limits.max_name_bytes = 8u;
  ZipBuilder builder;
  builder.add("link", "a-target-longer-than-eight-bytes");
  builder.last().external_attributes = 0120777u << 16;
  Built built(builder.build(), &limits);
  ASSERT_EQ(built.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  EXPECT_EQ(member->type, GARC_MEMBER_SYMLINK);
  EXPECT_EQ(member->link_target, nullptr);
  EXPECT_EQ(member->link_target_length, 0u);
}

//-----------------------------------------------------------------------------
// The zip64 end record and its locator
//-----------------------------------------------------------------------------

TEST(ZipStructure, AZipSixtyFourEndRecordIsTheControlForTheRestOfThem) {
  // The archive `zip -fz` writes: markers in the ordinary end record, and the
  // real counts in a zip64 record behind the locator. The corpus has one of these
  // and no broken one, which is why the rest of this section is built.
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.add("second.txt", "and another\n");
  builder.zip64();
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  EXPECT_TRUE(garc_zip_has_zip64_end_record(built.archive()));
  EXPECT_EQ(garc_zip_declared_members(built.archive()), 2u);
  size_t members = 0;
  EXPECT_EQ(built.walk(&members), GARC_END);
  EXPECT_EQ(members, 2u);
}

TEST(ZipStructure, AZipSixtyFourLocatorNamingAnotherDiskIsRefused) {
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.zip64().zip64_disk(1u, 0u, 1u);
  Built built(builder.build());
  EXPECT_EQ(built.open_result(), GARC_ERR_UNSUPPORTED);
}

TEST(ZipStructure, AZipSixtyFourLocatorCountingSeveralDisksIsRefused) {
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.zip64().zip64_disk(0u, 0u, 4u);
  Built built(builder.build());
  EXPECT_EQ(built.open_result(), GARC_ERR_UNSUPPORTED);
}

TEST(ZipStructure, AZipSixtyFourRecordNamingAnotherDiskIsRefused) {
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.zip64().zip64_disk(0u, 7u, 1u);
  Built built(builder.build());
  EXPECT_EQ(built.open_result(), GARC_ERR_UNSUPPORTED);
}

TEST(ZipStructure, ALocatorWithNoRecordBehindItIsCorruptRatherThanNotAZip) {
  // The end record was found and is a zip's, so this is a zip whose zip64 half is
  // broken - GARC_ERR_FORMAT here would send a caller looking for the wrong
  // problem. Both candidate positions are tried before giving up: the offset the
  // locator states, and the 56 bytes immediately in front of it.
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.zip64().zip64_break_record();
  Built built(builder.build());
  EXPECT_EQ(built.open_result(), GARC_ERR_CORRUPT);
}

TEST(ZipStructure, MarkersWithNoZipSixtyFourRecordAreCorrupt) {
  // 0xFFFFFFFF in the end record's size and offset with no locator behind it.
  // Reading the markers as values would report a 4 GiB central directory at a 4
  // GiB offset, and then fail somewhere less informative.
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.zip64_markers_only();
  Built built(builder.build());
  EXPECT_EQ(built.open_result(), GARC_ERR_CORRUPT);
}

TEST(ZipStructure, EveryZipSixtyFourSizeIsTakenFromTheFieldThatOverflowed) {
  // All three values in one field, in the order the specification gives:
  // uncompressed size, compressed size, local header offset. The corpus's
  // `zip -fz` archive carries only the first, so this is where the other two are
  // exercised - and a reader that consumed them in a different order would pass
  // there and fail here.
  ZipBuilder probe;
  probe.add("hello.txt", "hello, archive\n");
  const std::vector<uint8_t> reference = probe.build();
  // The local header is at zero in the reference, which is the value the extra
  // field will carry.
  std::string extra;
  ZipBuilder::append16(extra, 0x0001u);
  ZipBuilder::append16(extra, 24u);
  ZipBuilder::append64(extra, 15u);  // uncompressed
  ZipBuilder::append64(extra, 15u);  // compressed
  ZipBuilder::append64(extra, 0u);   // local header offset

  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.last().override_sizes = true;
  builder.last().central_size = 0xFFFFFFFFu;
  builder.last().central_compressed_size = 0xFFFFFFFFu;
  builder.last().override_local_offset = true;
  builder.last().local_offset = 0xFFFFFFFFu;
  builder.last().central_extra = extra;
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  EXPECT_EQ(member->size, 15u);
  EXPECT_EQ(garc_zip_member_compressed_size(built.archive()), 15u);
  EXPECT_EQ(member->header_offset, 0u);
  EXPECT_TRUE(garc_zip_member_used_zip64(built.archive()));
  (void)reference;
}

TEST(ZipStructure, AZipSixtyFourFieldMissingItsLastValueIsRefused) {
  // Three markers, two values. The third read would take the next extra field's
  // header as the high half of an offset.
  std::string extra;
  ZipBuilder::append16(extra, 0x0001u);
  ZipBuilder::append16(extra, 16u);
  ZipBuilder::append64(extra, 15u);
  ZipBuilder::append64(extra, 15u);

  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.last().override_sizes = true;
  builder.last().central_size = 0xFFFFFFFFu;
  builder.last().central_compressed_size = 0xFFFFFFFFu;
  builder.last().override_local_offset = true;
  builder.last().local_offset = 0xFFFFFFFFu;
  builder.last().central_extra = extra;
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  EXPECT_EQ(built.walk(), GARC_ERR_CORRUPT);
}

//-----------------------------------------------------------------------------
// Extra fields this library does not act on, and ones that are malformed
//-----------------------------------------------------------------------------

TEST(ZipStructure, AnUnknownExtraFieldIsSkippedByItsOwnLength) {
  // The ids are an open vocabulary: real writers emit fields for Mac resource
  // forks, for ACLs, for their own version numbers. Refusing an unknown id would
  // refuse most real archives, so the length is what the walk trusts - and the
  // field after it still has to be read, which is what this checks.
  std::string extra;
  ZipBuilder::append16(extra, 0x4D63u);  // a Macintosh field
  ZipBuilder::append16(extra, 6u);
  extra += "ignore";
  ZipBuilder::append16(extra, 0x5455u);  // and a timestamp behind it
  ZipBuilder::append16(extra, 5u);
  extra.push_back(0x01);
  ZipBuilder::append32(extra, 1000000000u);

  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.last().central_extra = extra;
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  EXPECT_EQ(member->mtime_source, GARC_TIME_ZIP_UNIX);
  EXPECT_EQ(garc_zip_member_extra_length(built.archive()), 19u);
}

TEST(ZipStructure, AUnixIdFieldThatEndsAfterItsVersionByteSuppliesNothing) {
  std::string extra;
  ZipBuilder::append16(extra, 0x7875u);
  ZipBuilder::append16(extra, 3u);
  extra.push_back(0x01);  // version
  extra.push_back(0x04);  // a uid width with no bytes behind it
  extra.push_back(0x00);
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.last().central_extra = extra;
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  EXPECT_FALSE(member->ids_valid);
}

TEST(ZipStructure, AUnixIdFieldWithNoGidSuppliesNothing) {
  // A well-formed uid and then nothing. Half a field is not a field: reporting
  // the uid with a gid of zero would be inventing the gid.
  std::string extra;
  ZipBuilder::append16(extra, 0x7875u);
  ZipBuilder::append16(extra, 6u);
  extra.push_back(0x01);
  extra.push_back(0x04);
  ZipBuilder::append32(extra, 1234u);
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.last().central_extra = extra;
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  EXPECT_FALSE(member->ids_valid);
}

TEST(ZipStructure, AnNtfsAttributeRunningPastItsFieldIsIgnored) {
  // The NTFS field is tagged attributes inside a field, so it has two lengths and
  // both can lie. An attribute that claims more than the field holds ends the walk
  // over the attributes, and the member keeps the DOS time it already had.
  std::string extra;
  ZipBuilder::append16(extra, 0x000Au);
  ZipBuilder::append16(extra, 12u);
  ZipBuilder::append32(extra, 0u);       // reserved
  ZipBuilder::append16(extra, 0x0001u);  // tag 1
  ZipBuilder::append16(extra, 200u);     // ...whose size nothing backs
  ZipBuilder::append32(extra, 0u);

  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.last().central_extra = extra;
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  EXPECT_EQ(member->mtime_source, GARC_TIME_ZIP_DOS);
  EXPECT_EQ(member->mtime_seconds, 1000000000);
}

TEST(ZipStructure, ALocatorWhoseOffsetIsUnreadableFallsBackToTheRecordBehindIt) {
  // The locator's offset is one of the offsets a stub shifts, so it can point
  // nowhere in an archive that is otherwise fine. The record is where it always
  // is - immediately in front of the locator - and trying that second position is
  // what makes such an archive readable rather than a refusal.
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.zip64().zip64_locator_offset(1u << 30);
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  EXPECT_TRUE(garc_zip_has_zip64_end_record(built.archive()));
  size_t members = 0;
  EXPECT_EQ(built.walk(&members), GARC_END);
  EXPECT_EQ(members, 1u);
}

TEST(ZipStructure, AZipSixtyFourFieldWithNoRoomForItsFirstValueIsRefused) {
  // The first marked field has nowhere to read from: four bytes of payload where
  // eight are owed. Separate from the "missing its last value" case because the
  // check is per value and the first one is the one a reader is likeliest to
  // assume is there.
  std::string extra;
  ZipBuilder::append16(extra, 0x0001u);
  ZipBuilder::append16(extra, 4u);
  ZipBuilder::append32(extra, 15u);

  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.last().override_sizes = true;
  builder.last().central_size = 0xFFFFFFFFu;
  builder.last().central_compressed_size = 15u;
  builder.last().central_extra = extra;
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  EXPECT_EQ(built.walk(), GARC_ERR_CORRUPT);
}

TEST(ZipStructure, ANegativeNtfsTimestampIsBeforeTheEpochRatherThanHuge) {
  // A FILETIME counts from 1601, so every date between 1601 and 1970 is a value
  // this library has to report as a negative second. Computing it in unsigned
  // arithmetic and casting would report 1963 as some time in 2554, which is the
  // shape of defect that passes every test written with a modern date.
  //
  // 1963-11-22T18:30:00Z, which is 8,164 days and change before the epoch.
  const int64_t seconds = -193000200;
  const uint64_t filetime
      = (uint64_t)((int64_t)11644473600 + seconds) * 10000000ull;
  std::string attribute;
  ZipBuilder::append16(attribute, 0x0001u);
  ZipBuilder::append16(attribute, 24u);
  ZipBuilder::append64(attribute, filetime);
  ZipBuilder::append64(attribute, filetime);
  ZipBuilder::append64(attribute, filetime);
  std::string extra;
  ZipBuilder::append16(extra, 0x000Au);
  ZipBuilder::append16(extra, static_cast<uint16_t>(4u + attribute.size()));
  ZipBuilder::append32(extra, 0u);
  extra += attribute;

  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.last().central_extra = extra;
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  EXPECT_EQ(member->mtime_source, GARC_TIME_ZIP_NTFS);
  EXPECT_EQ(member->mtime_seconds, seconds);
  EXPECT_EQ(member->mtime_nanoseconds, 0u);
}

TEST(ZipStructure, TheDumpNamesTheStubAndTheEncryption) {
  // Two lines the dump only prints for the archives that have them, so nothing
  // else in the suite reaches them: a base offset that is not zero, and a member
  // with a cipher.
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.last().flags = 0x0001u;  // encrypted, as far as the header says
  builder.prologue(std::string(64u, 'S'));
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  EXPECT_EQ(garc_zip_member_encryption(built.archive()),
      GARC_ZIP_ENCRYPTION_ZIPCRYPTO);

  char * buffer = nullptr;
  size_t length = 0;
  FILE * out = open_memstream(&buffer, &length);
  ASSERT_NE(out, nullptr);
  garc_archive_dump(built.archive(), out);
  fclose(out);
  const std::string text(buffer, length);
  free(buffer);
  EXPECT_NE(text.find("64 bytes in front of the archive"), std::string::npos)
      << text;
  EXPECT_NE(text.find("ZipCrypto"), std::string::npos) << text;
}

//-----------------------------------------------------------------------------
// Streams that fail
//-----------------------------------------------------------------------------

TEST(ZipStructure, AFailedScanForTheEndRecordIsNotACaseOfNotAnArchive) {
  // A file whose front says nothing, on a stream whose *second* read fails. The
  // scan is where the failure lands, and it has to come back as the I/O failure
  // it is: answering GARC_ERR_FORMAT would send a caller to look at bytes that
  // are fine.
  std::vector<uint8_t> bytes(4096u, 'Z');
  BufferSource source(bytes.data(), bytes.size(), true, true);
  source.fail_reads_after(1u, 1u);
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK);
  GARC_Archive * archive = nullptr;
  EXPECT_EQ(garc_open(stream, nullptr, &archive), GARC_ERR_IO);
  garc_close(archive);
  garc_stream_destroy(stream);
}

TEST(ZipStructure, AStreamThatCannotSeekBackIsAnIoFailureAndNotACorruptArchive) {
  // **The distinction a caller acts on.** A read that fails is a broken disk or a
  // closed socket; a corrupt archive is a bad file. Reporting one as the other
  // sends whoever reads the status to the wrong place, and the zip reader seeks
  // for every record it reads.
  const std::vector<uint8_t> bytes = control();
  BufferSource source(bytes.data(), bytes.size(), true, true);
  source.fail_seeks();
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK);
  GARC_Archive * archive = nullptr;
  EXPECT_EQ(garc_open(stream, nullptr, &archive), GARC_ERR_IO);
  garc_close(archive);
  garc_stream_destroy(stream);
}

TEST(ZipStructure, AReadFailureAtEveryStageIsReportedAsItself) {
  // A sweep over both axes: which archive shape, and which read fails. The reader
  // reads the end record, a locator, a zip64 record, the comment, a central
  // directory entry, a name, an extra field, a local header, a local name, a
  // symlink's target and a member's data through separate arms, and each reports a
  // failure separately.
  //
  // What is asserted is that the status is a failure and never a success: a read
  // that failed must not leave the walk reporting a member built out of whatever
  // was in the buffer.
  size_t io_failures = 0;
  for (const auto & shape : shapes()) {
    for (size_t stage = 0; stage < 24u; ++stage) {
      BufferSource source(shape.second.data(), shape.second.size(), true, true);
      source.fail_reads_after(stage, 1u);
      GARC_Stream * stream = nullptr;
      ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK);
      GARC_Archive * archive = nullptr;
      const GARC_Result opened = garc_open(stream, nullptr, &archive);
      if (opened == GARC_OK) {
        const GARC_Member * member = nullptr;
        GARC_Result result;
        while ((result = garc_next(archive, &member)) == GARC_OK) {
          char buffer[64];
          size_t got = 0;
          while (garc_read_member(archive, buffer, sizeof(buffer), &got) == GARC_OK
              && got) {
            // Reading through, so the data arm is reached too.
          }
        }
        if (result == GARC_ERR_IO) {
          ++io_failures;
        }
        garc_close(archive);
      }
      else {
        EXPECT_TRUE(opened == GARC_ERR_IO || opened == GARC_ERR_CORRUPT
            || opened == GARC_ERR_FORMAT)
            << shape.first << " stage " << stage << ": "
            << garc_result_string(opened);
        if (opened == GARC_ERR_IO) {
          ++io_failures;
        }
      }
      garc_stream_destroy(stream);
    }
  }
  // The sweep has to actually break something, or it is a hundred passes through
  // a working reader.
  EXPECT_GE(io_failures, 10u);
}

TEST(ZipStructure, ASeekFailureAtEveryStageIsReportedAsItself) {
  // The companion of the read sweep. A zip seeks before every read, so the seek
  // arms are a second set of failure paths - and a reader that checked only the
  // read's status would carry on from wherever the cursor happened to be, which
  // is how a member's data becomes another member's header.
  size_t io_failures = 0;
  for (const auto & shape : shapes()) {
    for (size_t stage = 0; stage < 12u; ++stage) {
      BufferSource source(shape.second.data(), shape.second.size(), true, true);
      source.fail_seeks_after(stage);
      GARC_Stream * stream = nullptr;
      ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK);
      GARC_Archive * archive = nullptr;
      const GARC_Result opened = garc_open(stream, nullptr, &archive);
      if (opened == GARC_OK) {
        const GARC_Member * member = nullptr;
        GARC_Result result;
        while ((result = garc_next(archive, &member)) == GARC_OK) {
          char buffer[64];
          size_t got = 0;
          while (garc_read_member(archive, buffer, sizeof(buffer), &got) == GARC_OK
              && got) {
          }
        }
        if (result == GARC_ERR_IO) {
          ++io_failures;
        }
        garc_close(archive);
      }
      else {
        EXPECT_EQ(opened, GARC_ERR_IO) << shape.first << " stage " << stage;
        ++io_failures;
      }
      garc_stream_destroy(stream);
    }
  }
  EXPECT_GE(io_failures, 10u);
}

TEST(ZipStructure, AStreamThatCannotReportItsSizeIsAnIoFailure) {
  // The scan starts from the end, so the size is the first thing it needs. A
  // stream that has a seek and no size is a shape the stream API allows, and the
  // failure has to be the stream's rather than "not an archive".
  const std::vector<uint8_t> bytes = control();
  BufferSource source(bytes.data(), bytes.size(), true, true);
  source.fail_size();
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK);
  GARC_Archive * archive = nullptr;
  EXPECT_EQ(garc_open(stream, nullptr, &archive), GARC_ERR_IO);
  garc_close(archive);
  garc_stream_destroy(stream);
}

//-----------------------------------------------------------------------------
// A stub in front, and an archive that does not start at zero
//-----------------------------------------------------------------------------

TEST(ZipStructure, AStubInFrontIsMeasuredAndApplied) {
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.prologue(std::string(1000u, 'S'));
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  EXPECT_EQ(garc_zip_base_offset(built.archive()), 1000u);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  EXPECT_EQ(member->header_offset, 1000u);
  char buffer[64];
  size_t got = 0;
  ASSERT_EQ(garc_read_member(built.archive(), buffer, sizeof(buffer), &got),
      GARC_OK);
  EXPECT_EQ(std::string(buffer, got), "hello, archive\n");
}

//-----------------------------------------------------------------------------
// Compressed members
//-----------------------------------------------------------------------------

/** Read a member's whole data, returning the status that ended it. */
GARC_Result read_member(GARC_Archive * archive, std::string * out) {
  char buffer[128];
  size_t got = 0;
  GARC_Result result;
  while ((result = garc_read_member(archive, buffer, sizeof(buffer), &got))
          == GARC_OK
      && got) {
    out->append(buffer, got);
  }
  return result;
}

TEST(ZipStructure, ADeflatedMemberIsDecompressedAndItsCrcChecked) {
  const std::string plain(2000u, 'a');
  ZipBuilder builder;
  add_compressed(builder, "packed.txt", plain, GARC_ZIP_METHOD_DEFLATE,
      "deflate");
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  EXPECT_EQ(member->size, plain.size());
  EXPECT_LT(garc_zip_member_compressed_size(built.archive()), plain.size())
      << "the payload is supposed to be smaller than the plaintext";
  std::string out;
  EXPECT_EQ(read_member(built.archive(), &out), GARC_OK);
  EXPECT_EQ(out, plain);
}

TEST(ZipStructure, AZstdMemberReachesTheZstdDecoder) {
  // Method 93. No writer in the corpus produces one - 7-Zip refuses `-mm=zstd`
  // for the zip container and Python gains ZIP_ZSTANDARD only in 3.14 - so this
  // is the only place the routing is exercised. What it shows is that a member
  // declaring 93 reaches zstd rather than deflate; the next test is the control
  // for that claim.
  const std::string plain = "zstd in a zip, which nothing here will write\n";
  ZipBuilder builder;
  add_compressed(builder, "packed.zst", plain, GARC_ZIP_METHOD_ZSTD, "zstd");
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  EXPECT_EQ(garc_zip_member_method(built.archive()), GARC_ZIP_METHOD_ZSTD);
  std::string out;
  EXPECT_EQ(read_member(built.archive(), &out), GARC_OK);
  EXPECT_EQ(out, plain);
}

TEST(ZipStructure, AMethodThatDoesNotMatchThePayloadIsRefused) {
  // The same bytes with the wrong number on them. A reader that ignored the
  // method - or pointed every method at deflate - would produce plausible
  // nonsense here instead of a refusal.
  const std::string plain(500u, 'b');
  ZipBuilder builder;
  add_compressed(builder, "mislabelled", plain, GARC_ZIP_METHOD_ZSTD,
      "deflate");
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  std::string out;
  const GARC_Result result = read_member(built.archive(), &out);
  EXPECT_NE(result, GARC_OK) << "read " << out.size() << " bytes";
  EXPECT_NE(out, plain);
}

TEST(ZipStructure, EnhancedDeflateIsNotPointedAtTheDeflateDecoder) {
  // **Method 9 is not RFC 1951.** It allows a 64 KB window and a different
  // length code, so a member using either would decode to plausible wrong bytes -
  // and one that used neither would decode correctly, which is what makes this
  // the dangerous kind of nearly-right. Refused by name, with the number
  // available.
  const std::string plain(500u, 'c');
  ZipBuilder builder;
  add_compressed(builder, "enhanced", plain, GARC_ZIP_METHOD_DEFLATE64,
      "deflate");
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  char buffer[64];
  size_t got = 0;
  EXPECT_EQ(garc_read_member(built.archive(), buffer, sizeof(buffer), &got),
      GARC_ERR_UNSUPPORTED);
  EXPECT_EQ(garc_zip_member_method(built.archive()), GARC_ZIP_METHOD_DEFLATE64);
}

TEST(ZipStructure, AWrongCrcIsRefusedOnTheCallThatEndsTheMember) {
  // The data is fine and the declared checksum is not, which is the only thing a
  // CRC catches that a size cannot. The refusal arrives on the call that returns
  // zero bytes: reporting it on the call that hands over the last of the data
  // would make the caller lose those bytes to an error return.
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.last().crc = 0xDEADBEEFu;
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  char buffer[64];
  size_t got = 0;
  ASSERT_EQ(garc_read_member(built.archive(), buffer, sizeof(buffer), &got),
      GARC_OK);
  EXPECT_EQ(std::string(buffer, got), "hello, archive\n")
      << "the data is still handed over";
  EXPECT_EQ(garc_read_member(built.archive(), buffer, sizeof(buffer), &got),
      GARC_ERR_CORRUPT);
}

TEST(ZipStructure, AWrongCrcOnADeflatedMemberIsRefusedToo) {
  const std::string plain(300u, 'd');
  ZipBuilder builder;
  add_compressed(builder, "packed.txt", plain, GARC_ZIP_METHOD_DEFLATE,
      "deflate");
  builder.last().crc ^= 1u;
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  std::string out;
  EXPECT_EQ(read_member(built.archive(), &out), GARC_ERR_CORRUPT);
  EXPECT_EQ(out, plain) << "and the bytes were still handed over first";
}

TEST(ZipStructure, APartialReadGetsNoCrcVerdict) {
  // Half a member has no checksum to compare against, so a caller that stops
  // early is told nothing rather than told something false.
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.last().crc = 0xDEADBEEFu;
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  char buffer[4];
  size_t got = 0;
  EXPECT_EQ(garc_read_member(built.archive(), buffer, sizeof(buffer), &got),
      GARC_OK);
  EXPECT_EQ(got, 4u);
  // And the walk continues, because the member was never finished.
  EXPECT_EQ(garc_next(built.archive(), &member), GARC_END);
}

TEST(ZipStructure, ASkippedMemberGetsNoVerdictAndCostsNoReads) {
  // Skipping a zip member reads nothing and seeks nothing: the next member's
  // position is in the central directory. So the wrong CRC below is never
  // noticed, which is the point - a skip says the bytes are not wanted.
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.last().crc = 0xDEADBEEFu;
  builder.add("second.txt", "and another\n");
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  EXPECT_EQ(garc_skip_member(built.archive()), GARC_OK);
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  EXPECT_EQ(std::string(member->name, member->name_length), "second.txt");
  std::string out;
  EXPECT_EQ(read_member(built.archive(), &out), GARC_OK);
  EXPECT_EQ(out, "and another\n");
}

TEST(ZipStructure, AMemberThatExpandsPastItsDeclaredSizeIsBounded) {
  // **The bomb, and the tight bound.** A zip declares each member's uncompressed
  // size before any of its bytes are read, so the decoder's output cap is set to
  // exactly that - no ratio and no guess. What must not happen is 5,000 bytes out
  // of a member that declared 16.
  const std::string plain(5000u, 'e');
  ZipBuilder builder;
  add_compressed(builder, "bomb", plain, GARC_ZIP_METHOD_DEFLATE, "deflate");
  builder.last().central_size = 16u;
  builder.last().crc = ZipBuilder::crc32(plain.substr(0, 16));
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  EXPECT_EQ(member->size, 16u);
  std::string out;
  const GARC_Result result = read_member(built.archive(), &out);
  EXPECT_LE(out.size(), 16u) << garc_result_string(result);
}

TEST(ZipStructure, ATruncatedCompressedMemberIsCorrupt) {
  // The declared size says 2,000 bytes and the payload runs out first. From
  // outside the decoder that is indistinguishable from a short read, and both are
  // the same answer: the archive said the bytes were there.
  const std::string plain(2000u, 'f');
  const std::string packed = compress_with("deflate", plain);
  ASSERT_GT(packed.size(), 8u);
  ZipBuilder builder;
  builder.add("packed.txt", packed.substr(0, packed.size() - 4u));
  builder.last().method = GARC_ZIP_METHOD_DEFLATE;
  builder.last().crc = ZipBuilder::crc32(plain);
  builder.last().override_sizes = true;
  builder.last().central_compressed_size
      = static_cast<uint32_t>(packed.size() - 4u);
  builder.last().central_size = static_cast<uint32_t>(plain.size());
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  std::string out;
  EXPECT_EQ(read_member(built.archive(), &out), GARC_ERR_CORRUPT);
  EXPECT_LT(out.size(), plain.size());
}

TEST(ZipStructure, AMemberDeclaringMoreDataThanFitsBeforeTheDirectoryIsRefused) {
  // A stored member whose declared size reaches into the central directory. Read
  // without this check it would be handed the directory's own bytes as its
  // contents - the CRC would refuse it afterwards, and afterwards is too late for
  // a caller who ignored the status.
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  builder.last().override_sizes = true;
  builder.last().central_size = 400u;
  builder.last().central_compressed_size = 400u;
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  EXPECT_EQ(built.walk(), GARC_ERR_CORRUPT);
}

TEST(ZipStructure, ACompressedStreamThatEndsEarlyButValidlyIsCorrupt) {
  // **Different from a truncated payload.** The deflate stream here is complete -
  // final block, correct checksums, nothing cut - and it produces 1,000 bytes for
  // a member that declared 2,000. The decoder is happy and the archive is not
  // telling the truth, so the refusal has to come from the size rather than from
  // the codec.
  const std::string half(1000u, 'i');
  const std::string packed = compress_with("deflate", half);
  ZipBuilder builder;
  builder.add("packed.txt", packed);
  builder.last().method = GARC_ZIP_METHOD_DEFLATE;
  builder.last().crc = ZipBuilder::crc32(std::string(2000u, 'i'));
  builder.last().override_sizes = true;
  builder.last().central_compressed_size = static_cast<uint32_t>(packed.size());
  builder.last().central_size = 2000u;
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  std::string out;
  EXPECT_EQ(read_member(built.archive(), &out), GARC_ERR_CORRUPT);
  EXPECT_EQ(out, half) << "the bytes that were there are still handed over";
}

TEST(ZipStructure, AReadOfNoBytesIsNotTheEndOfTheMember) {
  // A zero-capacity read is a question about nothing, and the answer has to be
  // zero bytes *without* the member being over - otherwise a caller with an empty
  // buffer would be told the data had ended, and the CRC verdict would arrive
  // before any of the bytes had been read.
  ZipBuilder builder;
  builder.add("hello.txt", "hello, archive\n");
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  char buffer[4];
  size_t got = 42u;
  EXPECT_EQ(garc_read_member(built.archive(), buffer, 0u, &got), GARC_OK);
  EXPECT_EQ(got, 0u);
  std::string out;
  EXPECT_EQ(read_member(built.archive(), &out), GARC_OK);
  EXPECT_EQ(out, "hello, archive\n");
}

TEST(ZipStructure, TheDecoderStopsAtTheMembersLastByte) {
  // **What the bounded view is for.** Two deflated members back to back: the
  // first member's decoder has to stop where its compressed size ends rather than
  // reading the second member's local header as more deflate data.
  const std::string first(1000u, 'g');
  const std::string second(1000u, 'h');
  ZipBuilder builder;
  add_compressed(builder, "first.txt", first, GARC_ZIP_METHOD_DEFLATE,
      "deflate");
  add_compressed(builder, "second.txt", second, GARC_ZIP_METHOD_DEFLATE,
      "deflate");
  Built built(builder.build());
  ASSERT_EQ(built.open_result(), GARC_OK);
  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  std::string out;
  EXPECT_EQ(read_member(built.archive(), &out), GARC_OK);
  EXPECT_EQ(out, first);
  ASSERT_EQ(garc_next(built.archive(), &member), GARC_OK);
  out.clear();
  EXPECT_EQ(read_member(built.archive(), &out), GARC_OK);
  EXPECT_EQ(out, second);
}

//-----------------------------------------------------------------------------
// Allocation failure
//-----------------------------------------------------------------------------

TEST(ZipStructure, AFailedAllocationIsReportedRatherThanCrashed) {
  // The scan allocates its window, the comment its buffer, each member its name,
  // an extra field its own, a symlink's target another. A failure in any of them
  // has to come back as GARC_ERR_OOM with nothing leaked, which is what the
  // allocator that fails on demand is for - and which archive shape is being
  // opened decides which of those allocations even happens, so the sweep runs over
  // all of them.
  for (const auto & shape : shapes()) {
  for (size_t budget = 0; budget < 8u; ++budget) {
    FailingAllocator allocator(budget);
    const std::vector<uint8_t> & bytes = shape.second;
    BufferSource source(bytes.data(), bytes.size(), true, true);
    // The stream gets the default allocator on purpose: with the failing one it
    // would be the first request refused, and every budget would then measure
    // the stream's constructor rather than the archive's.
    GARC_Stream * stream = nullptr;
    ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK)
        << budget;
    GARC_Archive * archive = nullptr;
    const GARC_Result opened = garc_open_with_allocator(stream, nullptr,
        allocator.get(), &archive);
    if (opened == GARC_OK) {
      const GARC_Member * member = nullptr;
      while (garc_next(archive, &member) == GARC_OK) {
        // Walking on whatever budget is left; the point is that a failure is a
        // status rather than a crash, wherever it lands.
      }
      garc_close(archive);
    }
    else {
      EXPECT_EQ(opened, GARC_ERR_OOM) << shape.first << " budget " << budget;
    }
    garc_stream_destroy(stream);
  }
  }
}

} // namespace

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
