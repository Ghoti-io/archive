/**
 * @file
 *
 * Writing tar, and reading it back.
 *
 * Three kinds of assertion here, and the order matters because the cheap ones
 * are the weak ones.
 *
 * **The bytes.** A handful of tests spell out the header a field at a time -
 * `0000644\0` and not `000644 \0`, `ustar\0` and `00`, six checksum digits then a
 * NUL then a space. Those spellings are decisions measured against three
 * reference writers that disagree about them (`tools/oracle/`), so they are
 * pinned as bytes rather than left to be whatever the code happens to emit.
 *
 * **The round trip through this library's own reader.** Necessary and not
 * sufficient: a writer and a reader that share a misunderstanding agree
 * perfectly. `notes/` records this as "parse-write-parse scores the writer free".
 * It is here because it is what catches a field written into the wrong offset,
 * and it is *labelled* as a consistency check between two halves rather than as a
 * check against the format. What checks the writer against the format is
 * `make check-oracle`, which hands what this writes to GNU tar, bsdtar and
 * `tarfile`.
 *
 * **The thresholds, from both sides.** Every place where a value stops fitting a
 * ustar field is tested at the last value that fits and the first that does not,
 * because a cap tested from one side cannot tell a cap that is off by one from a
 * cap that is right. The `GARC_TAR_USTAR` variant is what makes those assertions
 * sharp: it turns "a record appeared" into a status.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <map>

#include "tar_manifest.h"
#include "test_helpers.h"

using garctest::BufferDrain;
using garctest::FailingAllocator;
using garctest::ManifestRow;
using garctest::manifest_load;
using garctest::read_fixture;

namespace {

std::string data_path(const std::string & name) {
  return std::string(GARC_TEST_DATA) + "/tar/" + name;
}

/**
 * Every fixture, taken from the manifest rather than from the directory.
 *
 * The population a sweep measures has to come from the list of what should be
 * there. A directory listing would quietly shrink with the corpus; the manifest
 * is what `check-corpus-hashes` already guards.
 */
std::vector<std::string> corpus_archives() {
  const std::map<std::string, std::vector<ManifestRow>> rows
      = manifest_load(data_path("manifest.tsv"));
  std::vector<std::string> names;
  for (const auto & entry : rows) {
    names.push_back(entry.first);
  }
  return names;
}

/** A member with its own copies of everything, so it outlives a garc_next(). */
struct Captured {
  std::string name;
  std::string link;
  std::string uname;
  std::string gname;
  std::string data;
  GARC_Member_Type type = GARC_MEMBER_FILE;
  GARC_Name_Encoding name_encoding = GARC_NAME_UNDECLARED;
  uint64_t size = 0;
  int64_t mtime_seconds = 0;
  uint32_t mtime_nanoseconds = 0;
  GARC_Time_Source mtime_source = GARC_TIME_NONE;
  uint32_t mode = 0;
  int mode_valid = 0;
  int64_t uid = 0;
  int64_t gid = 0;
  int ids_valid = 0;
  uint32_t device_major = 0;
  uint32_t device_minor = 0;
  int device_valid = 0;
  GARC_Tar_Variant variant = GARC_TAR_NONE;

  /** Fill in a GARC_Member pointing at this object's own storage. */
  GARC_Member as_member() const {
    GARC_Member member;
    std::memset(&member, 0, sizeof(member));
    member.name = name.data();
    member.name_length = name.size();
    member.name_encoding = name_encoding;
    if (!link.empty()) {
      member.link_target = link.data();
      member.link_target_length = link.size();
    }
    if (!uname.empty()) {
      member.uname = uname.data();
      member.uname_length = uname.size();
    }
    if (!gname.empty()) {
      member.gname = gname.data();
      member.gname_length = gname.size();
    }
    member.type = type;
    member.size = size;
    member.mtime_seconds = mtime_seconds;
    member.mtime_nanoseconds = mtime_nanoseconds;
    member.mtime_source = mtime_source;
    member.mode = mode;
    member.mode_valid = mode_valid;
    member.uid = uid;
    member.gid = gid;
    member.ids_valid = ids_valid;
    member.device_major = device_major;
    member.device_minor = device_minor;
    member.device_valid = device_valid;
    return member;
  }
};

/** An ordinary file member, which each test then varies in one way. */
Captured plain_file(const std::string & name, const std::string & data) {
  Captured member;
  member.name = name;
  member.data = data;
  member.size = data.size();
  member.type = GARC_MEMBER_FILE;
  member.mode = 0644;
  member.mode_valid = 1;
  member.uid = 1000;
  member.gid = 1000;
  member.ids_valid = 1;
  member.mtime_seconds = 1700000000;
  member.mtime_source = GARC_TIME_TAR_OCTAL;
  return member;
}

/** Write these members into a fresh memory sink and return its bytes. */
GARC_Result build(const std::vector<Captured> & members, std::string * out,
    const GARC_Writer_Options * options = nullptr) {
  GARC_Sink * sink = nullptr;
  if (garc_sink_create_memory(&sink) != GARC_OK) {
    return GARC_ERR_OOM;
  }
  GARC_Writer * writer = nullptr;
  GARC_Result result
      = garc_writer_create(sink, GARC_FORMAT_TAR, options, &writer);
  for (size_t i = 0; result == GARC_OK && i < members.size(); ++i) {
    const GARC_Member m = members[i].as_member();
    result = garc_writer_add(writer, &m);
    if (result == GARC_OK && !members[i].data.empty()) {
      result = garc_writer_write(
          writer, members[i].data.data(), members[i].data.size());
    }
  }
  if (result == GARC_OK) {
    result = garc_writer_finish(writer);
  }
  if (result == GARC_OK && out) {
    const void * data = nullptr;
    size_t size = 0;
    if (garc_sink_data(sink, &data, &size) == GARC_OK) {
      out->assign(static_cast<const char *>(data), size);
    }
  }
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
  return result;
}

/** Read every member of an archive, data included. */
GARC_Result read_all(const std::string & bytes, std::vector<Captured> * out) {
  GARC_Stream * stream = nullptr;
  if (garc_stream_create_memory(bytes.data(), bytes.size(), &stream)
      != GARC_OK) {
    return GARC_ERR_OOM;
  }
  GARC_Archive * archive = nullptr;
  GARC_Result result = garc_open(stream, nullptr, &archive);
  const GARC_Member * member = nullptr;
  while (result == GARC_OK
      && (result = garc_next(archive, &member)) == GARC_OK) {
    Captured got;
    got.name.assign(member->name, member->name_length);
    if (member->link_target) {
      got.link.assign(member->link_target, member->link_target_length);
    }
    if (member->uname) {
      got.uname.assign(member->uname, member->uname_length);
    }
    if (member->gname) {
      got.gname.assign(member->gname, member->gname_length);
    }
    got.type = member->type;
    got.name_encoding = member->name_encoding;
    got.size = member->size;
    got.mtime_seconds = member->mtime_seconds;
    got.mtime_nanoseconds = member->mtime_nanoseconds;
    got.mtime_source = member->mtime_source;
    got.mode = member->mode;
    got.mode_valid = member->mode_valid;
    got.uid = member->uid;
    got.gid = member->gid;
    got.ids_valid = member->ids_valid;
    got.device_major = member->device_major;
    got.device_minor = member->device_minor;
    got.device_valid = member->device_valid;
    got.variant = garc_tar_member_variant(archive);

    char buffer[1024];
    size_t got_bytes = 0;
    GARC_Result data_result;
    while ((data_result = garc_read_member(archive, buffer, sizeof(buffer),
                &got_bytes))
            == GARC_OK
        && got_bytes) {
      got.data.append(buffer, got_bytes);
    }
    if (data_result != GARC_OK) {
      result = data_result;
      break;
    }
    out->push_back(got);
  }
  garc_close(archive);
  garc_stream_destroy(stream);
  return result == GARC_END ? GARC_OK : result;
}

/** The octal size field of the header block at @p offset. */
size_t size_at(const std::string & bytes, size_t offset) {
  size_t size = 0;
  for (size_t i = 0; i < 12; ++i) {
    const char c = bytes[offset + 124 + i];
    if (c < '0' || c > '7') {
      break;
    }
    size = size * 8 + static_cast<size_t>(c - '0');
  }
  return size;
}

/**
 * The offset of every header block, found by walking rather than by scanning.
 *
 * A scan of every 512-byte boundary would also read a member's *data* as
 * headers, and a test whose fixture happens to have an `x` at byte 156 of a data
 * block would then count a carrier that is not there. Walking costs three lines
 * and cannot.
 */
std::vector<size_t> header_offsets(const std::string & bytes) {
  std::vector<size_t> offsets;
  size_t off = 0;
  while (off + 512 <= bytes.size()
      && bytes.compare(off, 512, std::string(512, '\0')) != 0) {
    offsets.push_back(off);
    const size_t size = size_at(bytes, off);
    off += 512 + (size + 511) / 512 * 512;
  }
  return offsets;
}

/** The typeflag of the header block at @p offset. */
char type_at(const std::string & bytes, size_t offset) {
  return offset + 512 <= bytes.size() ? bytes[offset + 156] : '\0';
}

/** How many extended-header members the archive contains. */
size_t carrier_count(const std::string & bytes) {
  size_t found = 0;
  for (size_t off : header_offsets(bytes)) {
    if (type_at(bytes, off) == 'x' || type_at(bytes, off) == 'g') {
      found++;
    }
  }
  return found;
}

/** The offset of the first header that is not a carrier. */
size_t member_header(const std::string & bytes) {
  for (size_t off : header_offsets(bytes)) {
    if (type_at(bytes, off) != 'x' && type_at(bytes, off) != 'g') {
      return off;
    }
  }
  return 0;
}

/** The records of the first extended header, if there is one. */
std::string records_of(const std::string & bytes) {
  for (size_t off : header_offsets(bytes)) {
    if (type_at(bytes, off) == 'x') {
      return bytes.substr(off + 512, size_at(bytes, off));
    }
  }
  return {};
}

/** Add one member and return without finishing, so a header can be inspected. */
GARC_Result header_only(const Captured & member, std::string * out,
    const GARC_Writer_Options * options = nullptr) {
  GARC_Sink * sink = nullptr;
  if (garc_sink_create_memory(&sink) != GARC_OK) {
    return GARC_ERR_OOM;
  }
  GARC_Writer * writer = nullptr;
  GARC_Result result
      = garc_writer_create(sink, GARC_FORMAT_TAR, options, &writer);
  if (result == GARC_OK) {
    const GARC_Member m = member.as_member();
    result = garc_writer_add(writer, &m);
  }
  if (result == GARC_OK && out) {
    const void * data = nullptr;
    size_t size = 0;
    if (garc_sink_data(sink, &data, &size) == GARC_OK) {
      out->assign(static_cast<const char *>(data), size);
    }
  }
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
  return result;
}

GARC_Writer_Options ustar_options() {
  GARC_Writer_Options options;
  garc_writer_options_default(&options);
  options.tar_variant = GARC_TAR_USTAR;
  return options;
}

} // namespace

//-----------------------------------------------------------------------------
// Options and creation
//-----------------------------------------------------------------------------

TEST(WriterOptions, TheDefaultIsPaxWithNoRecordPadding) {
  GARC_Writer_Options options;
  std::memset(&options, 0xEE, sizeof(options));
  garc_writer_options_default(&options);
  EXPECT_EQ(options.tar_variant, GARC_TAR_PAX);
  EXPECT_EQ(options.blocking_factor, 0u);
}

TEST(WriterOptions, NullIsIgnored) {
  garc_writer_options_default(nullptr);
}

TEST(WriterCreate, RejectsANullSinkAndANullOutput) {
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  GARC_Writer * writer = nullptr;
  EXPECT_EQ(
      garc_writer_create(nullptr, GARC_FORMAT_TAR, nullptr, &writer),
      GARC_ERR_INVALID);
  EXPECT_EQ(garc_writer_create(sink, GARC_FORMAT_TAR, nullptr, nullptr),
      GARC_ERR_INVALID);
  garc_sink_destroy(sink);
}

TEST(WriterCreate, AZeroedOptionsStructIsRefusedRatherThanDefaulted) {
  // GARC_TAR_NONE names no format. A zero that silently meant pax would make
  // the variant field unreadable at the call site; NULL is how a caller says
  // they do not mind.
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  GARC_Writer_Options options;
  std::memset(&options, 0, sizeof(options));
  GARC_Writer * writer = nullptr;
  EXPECT_EQ(garc_writer_create(sink, GARC_FORMAT_TAR, &options, &writer),
      GARC_ERR_INVALID);
  EXPECT_EQ(writer, nullptr);
  garc_sink_destroy(sink);
}

TEST(WriterCreate, RefusesTheFormatsItReadsAndDoesNotWrite) {
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  GARC_Writer * writer = nullptr;
  for (GARC_Tar_Variant variant : {GARC_TAR_V7, GARC_TAR_GNU}) {
    GARC_Writer_Options options;
    garc_writer_options_default(&options);
    options.tar_variant = variant;
    EXPECT_EQ(garc_writer_create(sink, GARC_FORMAT_TAR, &options, &writer),
        GARC_ERR_UNSUPPORTED)
        << garc_tar_variant_string(variant);
  }
  garc_sink_destroy(sink);
}

TEST(WriterCreate, AnUnnamedFormatIsInvalidAndAnUnwrittenOneIsUnsupported) {
  // Two different answers, because they are two different mistakes: a caller
  // who has not said what to write, and one who asked for something this
  // library does not write yet.
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  GARC_Writer * writer = nullptr;
  EXPECT_EQ(
      garc_writer_create(sink, GARC_FORMAT_UNKNOWN, nullptr, &writer),
      GARC_ERR_INVALID);
  EXPECT_EQ(garc_writer_create(sink, GARC_FORMAT_COUNT, nullptr, &writer),
      GARC_ERR_UNSUPPORTED);
  garc_sink_destroy(sink);
}

TEST(WriterCreate, ReportsAllocationFailureAndNothingIsWrittenBeforeTheFirstAdd) {
  BufferDrain drain;
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_callback(drain.callbacks(), &sink), GARC_OK);
  FailingAllocator allocator(0);
  GARC_Writer * writer = nullptr;
  EXPECT_EQ(garc_writer_create_with_allocator(
                sink, GARC_FORMAT_TAR, nullptr, allocator.get(), &writer),
      GARC_ERR_OOM);
  EXPECT_EQ(writer, nullptr);
  EXPECT_EQ(drain.writes(), 0u);
  garc_sink_destroy(sink);
}

TEST(WriterDestroy, NullIsIgnoredAndTheCountersAnswerForNull) {
  garc_writer_destroy(nullptr);
  EXPECT_EQ(garc_writer_member_count(nullptr), 0u);
  EXPECT_EQ(garc_writer_data_remaining(nullptr), 0u);
}

//-----------------------------------------------------------------------------
// The bytes
//-----------------------------------------------------------------------------

TEST(WriterBytes, AnOrdinaryFileHeaderIsSpelledFieldByField) {
  // The spellings here are decisions, not accidents: GNU tar writes seven octal
  // digits and a NUL where libarchive writes six, a space and a NUL, and both
  // are legal. The wider one is chosen because it holds one more octal digit,
  // which is one more doubling before a pax record becomes necessary.
  std::string bytes;
  ASSERT_EQ(build({plain_file("notes.txt", "hello")}, &bytes), GARC_OK);

  ASSERT_GE(bytes.size(), 512u * 4u);
  EXPECT_EQ(bytes.substr(0, 9), std::string("notes.txt"));
  EXPECT_EQ(bytes[9], '\0');
  EXPECT_EQ(bytes.substr(100, 8), std::string("0000644\0", 8));
  EXPECT_EQ(bytes.substr(108, 8), std::string("0001750\0", 8));
  EXPECT_EQ(bytes.substr(116, 8), std::string("0001750\0", 8));
  EXPECT_EQ(bytes.substr(124, 12), std::string("00000000005\0", 12));
  EXPECT_EQ(bytes.substr(136, 12), std::string("14524770400\0", 12));
  EXPECT_EQ(bytes[156], '0');
  EXPECT_EQ(bytes.substr(257, 6), std::string("ustar\0", 6));
  EXPECT_EQ(bytes.substr(263, 2), std::string("00"));
  // Six octal digits, a NUL, a space. Both references write exactly this.
  EXPECT_EQ(bytes[148 + 6], '\0');
  EXPECT_EQ(bytes[148 + 7], ' ');
  for (size_t i = 0; i < 6; ++i) {
    EXPECT_GE(bytes[148 + i], '0') << i;
    EXPECT_LE(bytes[148 + i], '7') << i;
  }
  // The prefix and the device fields are left as NUL rather than written as
  // zeros: a blank field is how tar says it has no value, and `0000000` is a
  // number a caller could act on.
  EXPECT_EQ(bytes.substr(329, 16), std::string(16, '\0'));
  EXPECT_EQ(bytes.substr(345, 155), std::string(155, '\0'));

  EXPECT_EQ(bytes.substr(512, 5), std::string("hello"));
  EXPECT_EQ(bytes.substr(517, 507), std::string(507, '\0'));
  EXPECT_EQ(bytes.substr(1024, 1024), std::string(1024, '\0'));
  EXPECT_EQ(bytes.size(), 2048u);
}

TEST(WriterBytes, TheChecksumIsTheOneTheReaderComputes) {
  std::string bytes;
  ASSERT_EQ(build({plain_file("a", "")}, &bytes), GARC_OK);
  // Recomputed here rather than compared against a constant, so that a change
  // to any other field cannot be absorbed by a stale expectation.
  unsigned long sum = 0;
  for (size_t i = 0; i < 512; ++i) {
    sum += (i >= 148 && i < 156)
        ? static_cast<unsigned long>(' ')
        : static_cast<unsigned long>(static_cast<unsigned char>(bytes[i]));
  }
  char expected[8];
  std::snprintf(expected, sizeof(expected), "%06lo", sum);
  EXPECT_EQ(bytes.substr(148, 6), std::string(expected, 6));
}

TEST(WriterBytes, AnEmptyArchiveIsTwoZeroBlocks) {
  std::string bytes;
  ASSERT_EQ(build({}, &bytes), GARC_OK);
  EXPECT_EQ(bytes, std::string(1024, '\0'));
}

TEST(WriterBytes, TheBlockingFactorPadsToARecord) {
  GARC_Writer_Options options;
  garc_writer_options_default(&options);
  options.blocking_factor = 20;
  std::string bytes;
  ASSERT_EQ(build({plain_file("a", "x")}, &bytes, &options), GARC_OK);
  EXPECT_EQ(bytes.size(), 10240u);
  // And the archive inside it is unchanged: padding is padding.
  std::vector<Captured> back;
  ASSERT_EQ(read_all(bytes, &back), GARC_OK);
  ASSERT_EQ(back.size(), 1u);
  EXPECT_EQ(back[0].name, "a");
}

TEST(WriterBytes, ABlockingFactorTheArchiveAlreadyFillsAddsNothing) {
  GARC_Writer_Options options;
  garc_writer_options_default(&options);
  options.blocking_factor = 4; // 2048 bytes, which is what this archive is.
  std::string bytes;
  ASSERT_EQ(build({plain_file("notes.txt", "hello")}, &bytes, &options),
      GARC_OK);
  EXPECT_EQ(bytes.size(), 2048u);
}

TEST(WriterBytes, PaddingIsExactWhenTheDataAlreadyFillsABlock) {
  // `(512 - size % 512) % 512`, and the outer modulo is the whole of it: without
  // it a member whose size is a multiple of 512 - a zero-byte one included - gets
  // a whole block of padding it does not need, and a reader then sees a zero
  // block where the next header should be and calls that the end of it.
  struct Case {
    uint64_t size;
    size_t blocks; // header, data, and the two zero blocks.
  };
  const Case cases[] = {{0u, 3u}, {512u, 4u}, {1024u, 5u}, {1u, 4u}};
  for (const Case & one : cases) {
    std::string bytes;
    ASSERT_EQ(
        build({plain_file("a", std::string((size_t)one.size, 'x'))}, &bytes),
        GARC_OK)
        << one.size;
    EXPECT_EQ(bytes.size(), one.blocks * 512u) << one.size;
    std::vector<Captured> back;
    ASSERT_EQ(read_all(bytes, &back), GARC_OK) << one.size;
    ASSERT_EQ(back.size(), 1u) << one.size;
    EXPECT_EQ(back[0].size, one.size) << one.size;
  }
  // And with a member behind it, so that a spurious block of padding shows up as
  // a member the reader never reaches rather than only as a longer archive.
  std::string bytes;
  ASSERT_EQ(build({plain_file("a", std::string(512, 'x')), plain_file("b", "")},
                &bytes),
      GARC_OK);
  EXPECT_EQ(bytes.size(), 512u * 5u);
  std::vector<Captured> back;
  ASSERT_EQ(read_all(bytes, &back), GARC_OK);
  ASSERT_EQ(back.size(), 2u);
  EXPECT_EQ(back[1].name, "b");
}

TEST(WriterBytes, DataIsPaddedToABlockAndTheNextHeaderStartsThere) {
  std::string bytes;
  ASSERT_EQ(build({plain_file("a", std::string(513, 'x')),
                      plain_file("b", "y")},
                &bytes),
      GARC_OK);
  // header, two data blocks, header, one data block, two zero blocks.
  EXPECT_EQ(bytes.size(), 512u * 7u);
  EXPECT_EQ(bytes.substr(512 * 3, 1), std::string("b"));
}

//-----------------------------------------------------------------------------
// The round trip through this library's own reader
//-----------------------------------------------------------------------------

TEST(WriterRoundTrip, EveryTypeThisLibraryNamesComesBackAsItself) {
  // The write side maps a type onto a typeflag and the read side maps it back,
  // and they are two switch statements. This is what keeps them agreeing.
  std::vector<Captured> members;
  for (GARC_Member_Type type : {GARC_MEMBER_FILE, GARC_MEMBER_DIRECTORY,
           GARC_MEMBER_SYMLINK, GARC_MEMBER_HARDLINK, GARC_MEMBER_FIFO,
           GARC_MEMBER_CHAR_DEVICE, GARC_MEMBER_BLOCK_DEVICE}) {
    Captured member = plain_file(
        std::string("m") + garc_member_type_string(type), "");
    member.type = type;
    member.size = 0;
    if (type == GARC_MEMBER_SYMLINK || type == GARC_MEMBER_HARDLINK) {
      member.link = "target";
    }
    if (type == GARC_MEMBER_CHAR_DEVICE || type == GARC_MEMBER_BLOCK_DEVICE) {
      member.device_major = 7;
      member.device_minor = 42;
      member.device_valid = 1;
    }
    members.push_back(member);
  }
  std::string bytes;
  ASSERT_EQ(build(members, &bytes), GARC_OK);
  std::vector<Captured> back;
  ASSERT_EQ(read_all(bytes, &back), GARC_OK);
  ASSERT_EQ(back.size(), members.size());
  for (size_t i = 0; i < members.size(); ++i) {
    EXPECT_EQ(back[i].type, members[i].type) << members[i].name;
    EXPECT_EQ(back[i].name, members[i].name);
    EXPECT_EQ(back[i].link, members[i].link) << members[i].name;
    EXPECT_EQ(back[i].device_valid, members[i].device_valid)
        << members[i].name;
    EXPECT_EQ(back[i].device_major, members[i].device_major);
    EXPECT_EQ(back[i].device_minor, members[i].device_minor);
  }
}

TEST(WriterRoundTrip, EveryFieldTarCarriesComesBackUnchanged) {
  Captured member = plain_file("dir/file.bin", "0123456789");
  member.uname = "corey";
  member.gname = "staff";
  member.mode = 04755;
  member.uid = 65534;
  member.gid = 12;
  member.mtime_seconds = -5;
  member.mtime_nanoseconds = 250000000;
  member.mtime_source = GARC_TIME_PAX_DECIMAL;
  std::string bytes;
  ASSERT_EQ(build({member}, &bytes), GARC_OK);
  std::vector<Captured> back;
  ASSERT_EQ(read_all(bytes, &back), GARC_OK);
  ASSERT_EQ(back.size(), 1u);
  EXPECT_EQ(back[0].name, member.name);
  EXPECT_EQ(back[0].data, member.data);
  EXPECT_EQ(back[0].size, member.size);
  EXPECT_EQ(back[0].uname, member.uname);
  EXPECT_EQ(back[0].gname, member.gname);
  EXPECT_EQ(back[0].mode, member.mode);
  EXPECT_EQ(back[0].uid, member.uid);
  EXPECT_EQ(back[0].gid, member.gid);
  EXPECT_EQ(back[0].mtime_seconds, member.mtime_seconds);
  EXPECT_EQ(back[0].mtime_nanoseconds, member.mtime_nanoseconds);
  EXPECT_EQ(back[0].mtime_source, GARC_TIME_PAX_DECIMAL);
}

TEST(WriterRoundTrip, AnInvalidModeComesBackValidAndZero) {
  // The one field the round trip cannot preserve, and it is a fact about tar
  // rather than a defect: every tar header *has* a mode field, so a writer
  // cannot un-have one. Asserted rather than hidden in a tolerance.
  Captured member = plain_file("a", "");
  member.mode = 0777;
  member.mode_valid = 0;
  member.ids_valid = 0;
  member.uid = 42;
  std::string bytes;
  ASSERT_EQ(build({member}, &bytes), GARC_OK);
  std::vector<Captured> back;
  ASSERT_EQ(read_all(bytes, &back), GARC_OK);
  ASSERT_EQ(back.size(), 1u);
  EXPECT_EQ(back[0].mode_valid, 1);
  EXPECT_EQ(back[0].mode, 0u);
  EXPECT_EQ(back[0].ids_valid, 1);
  EXPECT_EQ(back[0].uid, 0);
}

TEST(WriterRoundTrip, ADirectoryKeepsWhateverTrailingSlashItWasGiven) {
  // Nothing is normalised. The typeflag is what says it is a directory, and a
  // writer that appended a slash would be deciding something the caller is
  // better placed to decide.
  for (const char * name : {"adir", "adir/"}) {
    Captured member = plain_file(name, "");
    member.type = GARC_MEMBER_DIRECTORY;
    std::string bytes;
    ASSERT_EQ(build({member}, &bytes), GARC_OK) << name;
    std::vector<Captured> back;
    ASSERT_EQ(read_all(bytes, &back), GARC_OK) << name;
    ASSERT_EQ(back.size(), 1u);
    EXPECT_EQ(back[0].name, std::string(name));
    EXPECT_EQ(back[0].type, GARC_MEMBER_DIRECTORY) << name;
  }
}

//-----------------------------------------------------------------------------
// The name, and the ustar split
//-----------------------------------------------------------------------------

TEST(WriterName, AName255BytesLongNeedsNoRecordAtAll) {
  // The ustar split: 155 bytes of prefix, an implied slash, 100 bytes of name.
  // Only one of the three reference writers does this; the other two write a
  // `path=` record and truncate. Splitting means a reader that knows only ustar
  // gets the *whole* name rather than its first hundred bytes.
  const std::string name = std::string(155, 'd') + "/" + std::string(99, 'e');
  ASSERT_EQ(name.size(), 255u);
  std::string bytes;
  ASSERT_EQ(build({plain_file(name, "")}, &bytes), GARC_OK);
  EXPECT_EQ(carrier_count(bytes), 0u);
  EXPECT_EQ(bytes.substr(345, 155), std::string(155, 'd'));
  EXPECT_EQ(bytes.substr(0, 99), std::string(99, 'e'));
  std::vector<Captured> back;
  ASSERT_EQ(read_all(bytes, &back), GARC_OK);
  ASSERT_EQ(back.size(), 1u);
  EXPECT_EQ(back[0].name, name);
  // No records, so nothing made it pax: the archive is plain ustar.
  EXPECT_EQ(back[0].variant, GARC_TAR_USTAR);
}

TEST(WriterName, TheLastUsableSlashIsTheSplit) {
  // So the name field holds the basename, which is what makes a ustar-only
  // reader's answer read like a path rather than like a fragment.
  const std::string name
      = std::string(40, 'a') + "/" + std::string(40, 'b') + "/"
      + std::string(30, 'c');
  ASSERT_EQ(name.size(), 112u);
  std::string bytes;
  ASSERT_EQ(build({plain_file(name, "")}, &bytes), GARC_OK);
  EXPECT_EQ(carrier_count(bytes), 0u);
  EXPECT_EQ(bytes.substr(0, 30), std::string(30, 'c'));
  EXPECT_EQ(bytes.substr(345, 81),
      std::string(40, 'a') + "/" + std::string(40, 'b'));
}

TEST(WriterName, ANameWithNoUsableSlashGetsARecordAndATruncatedField) {
  // libarchive splits this anyway, at a slash that leaves the middle of the path
  // out - a ustar-only reader then sees a path with a directory silently
  // missing. GNU tar and tarfile truncate, and so does this: every answer here
  // is wrong, and a recognisably wrong one beats a plausibly wrong one.
  const std::string name = std::string(160, 'c');
  std::string bytes;
  ASSERT_EQ(build({plain_file(name, "")}, &bytes), GARC_OK);
  ASSERT_EQ(carrier_count(bytes), 1u);
  const std::string records = records_of(bytes);
  EXPECT_NE(records.find("path=" + name + "\n"), std::string::npos);
  // The header behind it holds the first 100 bytes and an empty prefix.
  EXPECT_EQ(bytes.substr(1024, 100), std::string(100, 'c'));
  EXPECT_EQ(bytes.substr(1024 + 345, 155), std::string(155, '\0'));
  std::vector<Captured> back;
  ASSERT_EQ(read_all(bytes, &back), GARC_OK);
  ASSERT_EQ(back.size(), 1u);
  EXPECT_EQ(back[0].name, name);
  EXPECT_EQ(back[0].variant, GARC_TAR_PAX);
  // POSIX says a record's bytes are UTF-8, and these are, so the name the
  // record carried is declared where the header field's would not be.
  EXPECT_EQ(back[0].name_encoding, GARC_NAME_UTF8);
}

TEST(WriterName, ASplitThatWouldDropAComponentIsNotTaken) {
  // 140 + 1 + 80 + 1 + 78. The only slashes are at 140 and 221: 221 is past the
  // 155-byte prefix, and 140 leaves 159 bytes for a 100-byte field. So there is
  // no usable split, and the middle component must not be silently dropped.
  const std::string name = std::string(140, 'f') + "/" + std::string(80, 'g')
      + "/" + std::string(78, 'h');
  ASSERT_EQ(name.size(), 300u);
  std::string bytes;
  ASSERT_EQ(build({plain_file(name, "")}, &bytes), GARC_OK);
  ASSERT_EQ(carrier_count(bytes), 1u);
  EXPECT_EQ(bytes.substr(1024 + 345, 155), std::string(155, '\0'));
  EXPECT_EQ(bytes.substr(1024, 100), std::string(100, 'f'));
  std::vector<Captured> back;
  ASSERT_EQ(read_all(bytes, &back), GARC_OK);
  ASSERT_EQ(back.size(), 1u);
  EXPECT_EQ(back[0].name, name);
}

TEST(WriterName, TheBoundaryIsAt100BytesWithNoSlash) {
  for (size_t length : {99u, 100u, 101u}) {
    const std::string name(length, 'a');
    std::string bytes;
    ASSERT_EQ(build({plain_file(name, "")}, &bytes), GARC_OK) << length;
    EXPECT_EQ(carrier_count(bytes), length > 100u ? 1u : 0u) << length;
    std::vector<Captured> back;
    ASSERT_EQ(read_all(bytes, &back), GARC_OK) << length;
    ASSERT_EQ(back.size(), 1u);
    EXPECT_EQ(back[0].name, name) << length;
  }
}

TEST(WriterName, AOneBytePrefixIsASplitAndALeadingSlashIsNot) {
  // The smallest split the format allows, and the case just below it. Both parts
  // have to be non-empty: a cut at index 0 would leave the prefix empty, and the
  // reader does not put a separator back in front of a name whose prefix is
  // absent - so a leading `/` cannot be expressed by the split at all and the
  // name would come back one byte shorter, absolute turned relative with no error
  // anywhere. A hostile archive's absolute name is exactly this shape.
  const std::string smallest = "a/" + std::string(100, 'b');
  ASSERT_EQ(smallest.size(), 102u);
  std::string bytes;
  ASSERT_EQ(build({plain_file(smallest, "")}, &bytes), GARC_OK);
  EXPECT_EQ(carrier_count(bytes), 0u);
  EXPECT_EQ(bytes.substr(345, 1), std::string("a"));
  EXPECT_EQ(bytes.substr(0, 100), std::string(100, 'b'));

  const std::string absolute = "/" + std::string(100, 'c');
  ASSERT_EQ(absolute.size(), 101u);
  std::string other;
  ASSERT_EQ(build({plain_file(absolute, "")}, &other), GARC_OK);
  EXPECT_EQ(carrier_count(other), 1u);
  const size_t header = member_header(other);
  EXPECT_EQ(other.substr(header + 345, 155), std::string(155, '\0'));

  for (const std::string & name : {smallest, absolute}) {
    std::string written;
    ASSERT_EQ(build({plain_file(name, "")}, &written), GARC_OK);
    std::vector<Captured> back;
    ASSERT_EQ(read_all(written, &back), GARC_OK);
    ASSERT_EQ(back.size(), 1u);
    EXPECT_EQ(back[0].name, name);
    // And the classifier still sees the absolute one for what it is, because
    // nothing was normalised on the way out.
    EXPECT_EQ((garc_name_check(back[0].name.data(), back[0].name.size())
                  & GARC_NAME_ABSOLUTE)
            != 0u,
        name[0] == '/');
  }
}

TEST(WriterName, APrefixOneByteTooLongIsNotASplit) {
  // The prefix field is 155 bytes. A name whose only slash sits at 156 has no
  // usable split, and taking it anyway would write one byte past the field - into
  // the twelve bytes of padding at the end of the block, where the reader never
  // looks, so the name would come back a byte short with no error anywhere.
  const std::string name = std::string(156, 'd') + "/" + std::string(90, 'e');
  ASSERT_EQ(name.size(), 247u);
  std::string bytes;
  ASSERT_EQ(build({plain_file(name, "")}, &bytes), GARC_OK);
  ASSERT_EQ(carrier_count(bytes), 1u);
  const size_t header = member_header(bytes);
  EXPECT_EQ(bytes.substr(header + 345, 155), std::string(155, '\0'));
  EXPECT_EQ(bytes.substr(header + 500, 12), std::string(12, '\0'));
  std::vector<Captured> back;
  ASSERT_EQ(read_all(bytes, &back), GARC_OK);
  ASSERT_EQ(back.size(), 1u);
  EXPECT_EQ(back[0].name, name);

  // And the control at 155, which is a split and needs no record.
  const std::string fits = std::string(155, 'd') + "/" + std::string(90, 'e');
  std::string other;
  ASSERT_EQ(build({plain_file(fits, "")}, &other), GARC_OK);
  EXPECT_EQ(carrier_count(other), 0u);
  EXPECT_EQ(other.substr(345, 155), std::string(155, 'd'));
}

TEST(WriterName, ATrailingSlashIsNotASplitPoint) {
  // The part after the slash would be empty, and a header whose name field is
  // empty is how an archive says the name is elsewhere. 101 bytes ending in a
  // slash with no other slash therefore needs a record.
  const std::string name = std::string(100, 'a') + "/";
  std::string bytes;
  ASSERT_EQ(build({plain_file(name, "")}, &bytes), GARC_OK);
  EXPECT_EQ(carrier_count(bytes), 1u);
  std::vector<Captured> back;
  ASSERT_EQ(read_all(bytes, &back), GARC_OK);
  ASSERT_EQ(back.size(), 1u);
  EXPECT_EQ(back[0].name, name);
}

TEST(WriterName, RawBytesInALongNameAreDeclaredBinaryRatherThanUtf8) {
  // POSIX says a record's bytes are UTF-8, so writing bytes that are not without
  // saying so would put a claim in the archive that this library's own reader
  // reports back as GARC_NAME_UTF8 - a declaration made by the writer rather
  // than by the data.
  std::string name(160, 'a');
  name[5] = static_cast<char>(0x80); // A continuation byte with no lead.
  ASSERT_NE(garc_name_check(name.data(), name.size()) & GARC_NAME_NOT_UTF8, 0u);
  std::string bytes;
  ASSERT_EQ(build({plain_file(name, "")}, &bytes), GARC_OK);
  const std::string records = records_of(bytes);
  EXPECT_NE(records.find("hdrcharset=BINARY\n"), std::string::npos);
  // hdrcharset comes first, because a reader processing records in order has to
  // know how to read the ones after it.
  EXPECT_EQ(records.find("hdrcharset"), records.find(" ") + 1u);
  std::vector<Captured> back;
  ASSERT_EQ(read_all(bytes, &back), GARC_OK);
  ASSERT_EQ(back.size(), 1u);
  EXPECT_EQ(back[0].name, name);
  EXPECT_EQ(back[0].name_encoding, GARC_NAME_UNDECLARED);
}

TEST(WriterName, ALongLinkTargetGetsItsOwnRecord) {
  Captured member = plain_file("link", "");
  member.type = GARC_MEMBER_SYMLINK;
  member.size = 0;
  member.link = std::string(120, 't');
  std::string bytes;
  ASSERT_EQ(build({member}, &bytes), GARC_OK);
  ASSERT_EQ(carrier_count(bytes), 1u);
  EXPECT_NE(records_of(bytes).find("linkpath=" + member.link + "\n"),
      std::string::npos);
  // And the field behind it holds the first hundred bytes.
  EXPECT_EQ(bytes.substr(1024 + 157, 100), std::string(100, 't'));
  std::vector<Captured> back;
  ASSERT_EQ(read_all(bytes, &back), GARC_OK);
  ASSERT_EQ(back.size(), 1u);
  EXPECT_EQ(back[0].link, member.link);
}

TEST(WriterName, TheLinkTargetBoundaryIsAt100Bytes) {
  for (size_t length : {100u, 101u}) {
    Captured member = plain_file("link", "");
    member.type = GARC_MEMBER_SYMLINK;
    member.size = 0;
    member.link = std::string(length, 't');
    std::string bytes;
    ASSERT_EQ(build({member}, &bytes), GARC_OK) << length;
    EXPECT_EQ(carrier_count(bytes), length > 100u ? 1u : 0u) << length;
    std::vector<Captured> back;
    ASSERT_EQ(read_all(bytes, &back), GARC_OK) << length;
    ASSERT_EQ(back.size(), 1u);
    EXPECT_EQ(back[0].link, member.link) << length;
  }
}

TEST(WriterName, TheOwnerNameBoundaryIsAt32Bytes) {
  for (size_t length : {32u, 33u}) {
    Captured member = plain_file("a", "");
    member.uname = std::string(length, 'u');
    member.gname = std::string(length, 'g');
    std::string bytes;
    ASSERT_EQ(build({member}, &bytes), GARC_OK) << length;
    EXPECT_EQ(carrier_count(bytes), length > 32u ? 1u : 0u) << length;
    std::vector<Captured> back;
    ASSERT_EQ(read_all(bytes, &back), GARC_OK) << length;
    ASSERT_EQ(back.size(), 1u);
    EXPECT_EQ(back[0].uname, member.uname) << length;
    EXPECT_EQ(back[0].gname, member.gname) << length;
  }
}

//-----------------------------------------------------------------------------
// Numbers that outgrow their fields
//-----------------------------------------------------------------------------

TEST(WriterNumbers, TheSizeBoundaryIsElevenOctalDigits) {
  // 8589934591 is 0o77777777777, the largest an 11-digit field holds. One more
  // needs base-256 in the field and a `size=` record beside it, and both say the
  // same number - which is the opposite of the reader's "one payload, two
  // readings" refusal, and is why writing base-256 here is safe.
  for (uint64_t size : {uint64_t{8589934591}, uint64_t{8589934592}}) {
    Captured member = plain_file("big", "");
    member.size = size;
    std::string bytes;
    // The header only: the data would be eight gigabytes of it.
    ASSERT_EQ(header_only(member, &bytes), GARC_OK) << size;
    const bool octal = size <= 8589934591u;
    EXPECT_EQ(carrier_count(bytes), octal ? 0u : 1u) << size;
    // The member's own header, not the carrier in front of it.
    const size_t header = member_header(bytes);
    if (octal) {
      EXPECT_EQ(bytes.substr(header + 124, 12),
          std::string("77777777777\0", 12));
    } else {
      EXPECT_EQ(static_cast<unsigned char>(bytes[header + 124]) & 0x80u, 0x80u);
      EXPECT_NE(records_of(bytes).find("size=8589934592\n"), std::string::npos);
    }
  }
}

TEST(WriterNumbers, ASizeNoFieldCanCarryIsRefused) {
  // Base-256 is two's complement, so a size at or above 2^63 would read back
  // negative - which is the range garc_next() refuses from the other side.
  Captured member = plain_file("huge", "");
  member.size = uint64_t{1} << 63;
  std::string bytes;
  EXPECT_EQ(header_only(member, &bytes), GARC_ERR_UNSUPPORTED);
}

TEST(WriterNumbers, ANegativeTimeIsBase256AndARecord) {
  Captured member = plain_file("old", "");
  member.mtime_seconds = -1;
  std::string bytes;
  ASSERT_EQ(build({member}, &bytes), GARC_OK);
  ASSERT_EQ(carrier_count(bytes), 1u);
  EXPECT_NE(records_of(bytes).find("mtime=-1\n"), std::string::npos);
  EXPECT_EQ(static_cast<unsigned char>(bytes[1024 + 136]), 0xFFu);
  std::vector<Captured> back;
  ASSERT_EQ(read_all(bytes, &back), GARC_OK);
  ASSERT_EQ(back.size(), 1u);
  EXPECT_EQ(back[0].mtime_seconds, -1);
}

TEST(WriterNumbers, AFractionalTimeBeforeTheEpochFloors) {
  // The reader turns `-1.5` into -2 seconds and 500000000 nanoseconds, because
  // the nanoseconds it reports are unsigned. Writing that back has to produce
  // `-1.5` again and not `-2.5`.
  Captured member = plain_file("old", "");
  member.mtime_seconds = -2;
  member.mtime_nanoseconds = 500000000;
  member.mtime_source = GARC_TIME_PAX_DECIMAL;
  std::string bytes;
  ASSERT_EQ(build({member}, &bytes), GARC_OK);
  EXPECT_NE(records_of(bytes).find("mtime=-1.500000000\n"), std::string::npos);
  std::vector<Captured> back;
  ASSERT_EQ(read_all(bytes, &back), GARC_OK);
  ASSERT_EQ(back.size(), 1u);
  EXPECT_EQ(back[0].mtime_seconds, -2);
  EXPECT_EQ(back[0].mtime_nanoseconds, 500000000u);
}

TEST(WriterNumbers, APaxTimeSourceAsksForARecordEvenForAWholeSecond) {
  // GARC_Time_Source is an input as well as a report: a member read out of a pax
  // archive and written back into one has to come back saying it came from a
  // record, or the round trip loses which field answered.
  Captured member = plain_file("a", "");
  member.mtime_seconds = 1700000000;
  member.mtime_nanoseconds = 0;
  member.mtime_source = GARC_TIME_PAX_DECIMAL;
  std::string bytes;
  ASSERT_EQ(build({member}, &bytes), GARC_OK);
  ASSERT_EQ(carrier_count(bytes), 1u);
  EXPECT_NE(records_of(bytes).find("mtime=1700000000\n"), std::string::npos);
  std::vector<Captured> back;
  ASSERT_EQ(read_all(bytes, &back), GARC_OK);
  ASSERT_EQ(back.size(), 1u);
  EXPECT_EQ(back[0].mtime_source, GARC_TIME_PAX_DECIMAL);
  EXPECT_EQ(back[0].mtime_nanoseconds, 0u);
}

TEST(WriterNumbers, ATimeTheOctalFieldCannotHoldComesBackAsARecordsTime) {
  // The one field a round trip cannot always keep, and the writer's fuzz harness
  // found it on its first run by asserting that it could. A negative time can
  // only be written as a record, and a record *is* GARC_TIME_PAX_DECIMAL - so a
  // caller who said the time came from tar's octal field is told otherwise, and
  // the archive is right either way.
  const int64_t seconds[] = {-1, 8589934592};
  for (int64_t value : seconds) {
    Captured member = plain_file("a", "");
    member.mtime_seconds = value;
    member.mtime_source = GARC_TIME_TAR_OCTAL;
    std::string bytes;
    ASSERT_EQ(build({member}, &bytes), GARC_OK) << value;
    ASSERT_EQ(carrier_count(bytes), 1u) << value;
    std::vector<Captured> back;
    ASSERT_EQ(read_all(bytes, &back), GARC_OK) << value;
    ASSERT_EQ(back.size(), 1u);
    EXPECT_EQ(back[0].mtime_seconds, value) << value;
    EXPECT_EQ(back[0].mtime_source, GARC_TIME_PAX_DECIMAL) << value;
    EXPECT_EQ(back[0].mtime_nanoseconds, 0u) << value;
  }
  // And the control either side: a time the field holds keeps its source.
  Captured member = plain_file("a", "");
  member.mtime_seconds = 8589934591;
  member.mtime_source = GARC_TIME_TAR_OCTAL;
  std::string bytes;
  ASSERT_EQ(build({member}, &bytes), GARC_OK);
  EXPECT_EQ(carrier_count(bytes), 0u);
  std::vector<Captured> back;
  ASSERT_EQ(read_all(bytes, &back), GARC_OK);
  ASSERT_EQ(back.size(), 1u);
  EXPECT_EQ(back[0].mtime_source, GARC_TIME_TAR_OCTAL);
}

TEST(WriterNumbers, NoTimeAtAllIsWrittenAsZeroAndNoRecord) {
  Captured member = plain_file("a", "");
  member.mtime_seconds = 1700000000;
  member.mtime_source = GARC_TIME_NONE;
  std::string bytes;
  ASSERT_EQ(build({member}, &bytes), GARC_OK);
  EXPECT_EQ(carrier_count(bytes), 0u);
  EXPECT_EQ(bytes.substr(136, 12), std::string("00000000000\0", 12));
}

TEST(WriterNumbers, TheOwnerIdBoundaryIsSevenOctalDigits) {
  for (int64_t uid : {int64_t{2097151}, int64_t{2097152}}) {
    Captured member = plain_file("a", "");
    member.uid = uid;
    member.gid = uid;
    std::string bytes;
    ASSERT_EQ(build({member}, &bytes), GARC_OK) << uid;
    const bool octal = uid <= 2097151;
    EXPECT_EQ(carrier_count(bytes), octal ? 0u : 1u) << uid;
    std::vector<Captured> back;
    ASSERT_EQ(read_all(bytes, &back), GARC_OK) << uid;
    ASSERT_EQ(back.size(), 1u);
    EXPECT_EQ(back[0].uid, uid) << uid;
    EXPECT_EQ(back[0].gid, uid) << uid;
  }
}

TEST(WriterNumbers, AModeTooWideForOctalIsBase256WithNoRecordToCarryIt) {
  // There is no pax key for `mode` in this reader's vocabulary, so base-256 is
  // the only place the value can go - which still makes the archive something a
  // 1988 reader cannot read, and the ustar variant has to say so.
  Captured member = plain_file("a", "");
  member.mode = 0xFFFFFFFFu;
  std::string bytes;
  ASSERT_EQ(build({member}, &bytes), GARC_OK);
  EXPECT_EQ(carrier_count(bytes), 0u);
  EXPECT_EQ(static_cast<unsigned char>(bytes[100]) & 0x80u, 0x80u);
  std::vector<Captured> back;
  ASSERT_EQ(read_all(bytes, &back), GARC_OK);
  ASSERT_EQ(back.size(), 1u);
  EXPECT_EQ(back[0].mode, 0xFFFFFFFFu);

  const GARC_Writer_Options options = ustar_options();
  std::string refused;
  EXPECT_EQ(header_only(member, &refused, &options), GARC_ERR_UNSUPPORTED);
}

//-----------------------------------------------------------------------------
// The ustar variant, which turns "a record appeared" into a status
//-----------------------------------------------------------------------------

TEST(WriterUstar, WhatFitsIsWrittenAndWhatDoesNotIsRefused) {
  const GARC_Writer_Options options = ustar_options();

  struct Case {
    const char * what;
    Captured member;
    bool fits;
  };
  std::vector<Case> cases;
  {
    Captured m = plain_file(
        std::string(155, 'd') + "/" + std::string(99, 'e'), "");
    cases.push_back({"a 255-byte name that splits", m, true});
  }
  {
    Captured m = plain_file(std::string(160, 'c'), "");
    cases.push_back({"a 160-byte name that does not", m, false});
  }
  {
    Captured m = plain_file("a", "");
    m.mtime_seconds = -1;
    cases.push_back({"a time before the epoch", m, false});
  }
  {
    Captured m = plain_file("a", "");
    m.mtime_nanoseconds = 1;
    m.mtime_source = GARC_TIME_PAX_DECIMAL;
    cases.push_back({"a sub-second time", m, false});
  }
  {
    Captured m = plain_file("a", "");
    m.size = 8589934592u;
    cases.push_back({"a size over eight gigabytes", m, false});
  }
  {
    Captured m = plain_file("link", "");
    m.type = GARC_MEMBER_SYMLINK;
    m.size = 0;
    m.link = std::string(101, 't');
    cases.push_back({"a 101-byte link target", m, false});
  }
  {
    Captured m = plain_file("a", "");
    m.uname = std::string(33, 'u');
    cases.push_back({"a 33-byte owner name", m, false});
  }

  for (const Case & one : cases) {
    std::string bytes;
    const GARC_Result result = header_only(one.member, &bytes, &options);
    if (one.fits) {
      EXPECT_EQ(result, GARC_OK) << one.what;
      EXPECT_EQ(carrier_count(bytes), 0u) << one.what;
    } else {
      EXPECT_EQ(result, GARC_ERR_UNSUPPORTED) << one.what;
    }
  }
}

TEST(WriterUstar, ARefusedMemberIsNotCounted) {
  const GARC_Writer_Options options = ustar_options();
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  GARC_Writer * writer = nullptr;
  ASSERT_EQ(garc_writer_create(sink, GARC_FORMAT_TAR, &options, &writer),
      GARC_OK);

  const Captured bad = plain_file(std::string(160, 'c'), "");
  const GARC_Member m = bad.as_member();
  EXPECT_EQ(garc_writer_add(writer, &m), GARC_ERR_UNSUPPORTED);
  EXPECT_EQ(garc_writer_member_count(writer), 0u);
  EXPECT_EQ(garc_sink_tell(sink), 0u);

  // And the writer is still usable, which is what makes the refusal a decision
  // rather than a failure: the caller can shorten the name and carry on.
  const Captured good = plain_file("c", "");
  const GARC_Member m2 = good.as_member();
  EXPECT_EQ(garc_writer_add(writer, &m2), GARC_OK);
  EXPECT_EQ(garc_writer_member_count(writer), 1u);
  EXPECT_EQ(garc_writer_finish(writer), GARC_OK);

  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
}

//-----------------------------------------------------------------------------
// What a member may not be
//-----------------------------------------------------------------------------

TEST(WriterRefusals, EachOneIsItsOwnCase) {
  struct Case {
    const char * what;
    Captured member;
  };
  std::vector<Case> cases;
  {
    Captured m = plain_file("", "");
    cases.push_back({"an empty name", m});
  }
  {
    Captured m = plain_file(std::string("a\0b", 3), "");
    cases.push_back({"a NUL inside the name", m});
  }
  {
    Captured m = plain_file("link", "");
    m.type = GARC_MEMBER_SYMLINK;
    m.link = std::string("a\0b", 3);
    cases.push_back({"a NUL inside the link target", m});
  }
  {
    Captured m = plain_file("a", "");
    m.uname = std::string("u\0v", 3);
    cases.push_back({"a NUL inside the owner name", m});
  }
  {
    Captured m = plain_file("a", "");
    m.gname = std::string("g\0h", 3);
    cases.push_back({"a NUL inside the group name", m});
  }
  {
    Captured m = plain_file("odd", "");
    m.type = GARC_MEMBER_OTHER;
    cases.push_back({"a type with no typeflag", m});
  }
  {
    Captured m = plain_file("adir", "");
    m.type = GARC_MEMBER_DIRECTORY;
    m.size = 10;
    cases.push_back({"a directory with a size", m});
  }
  {
    Captured m = plain_file("link", "");
    m.type = GARC_MEMBER_SYMLINK;
    cases.push_back({"a symlink with no target", m});
  }
  {
    Captured m = plain_file("link", "");
    m.type = GARC_MEMBER_HARDLINK;
    cases.push_back({"a hard link with no target", m});
  }
  {
    Captured m = plain_file("dev", "");
    m.type = GARC_MEMBER_CHAR_DEVICE;
    cases.push_back({"a device with no numbers", m});
  }
  {
    Captured m = plain_file("a", "");
    m.mtime_nanoseconds = 1;
    m.mtime_source = GARC_TIME_TAR_OCTAL;
    cases.push_back({"a sub-second time from the octal field", m});
  }
  {
    Captured m = plain_file("a", "");
    m.mtime_nanoseconds = 1;
    m.mtime_source = GARC_TIME_NONE;
    cases.push_back({"a sub-second time from no field", m});
  }
  {
    Captured m = plain_file("a", "");
    m.mtime_nanoseconds = 1000000000;
    m.mtime_source = GARC_TIME_PAX_DECIMAL;
    cases.push_back({"a whole second of nanoseconds", m});
  }

  for (const Case & one : cases) {
    std::string bytes;
    EXPECT_EQ(header_only(one.member, &bytes), GARC_ERR_INVALID) << one.what;
  }
}

TEST(WriterRefusals, ALengthWithNoBytesBehindIt) {
  // Checked rather than treated as zero: the pointer is what gets read, and a
  // caller that set one and not the other has said something it did not mean.
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  GARC_Writer * writer = nullptr;
  ASSERT_EQ(garc_writer_create(sink, GARC_FORMAT_TAR, nullptr, &writer),
      GARC_OK);
  for (int which = 0; which < 3; ++which) {
    GARC_Member member;
    std::memset(&member, 0, sizeof(member));
    member.name = "a";
    member.name_length = 1;
    member.type = GARC_MEMBER_FILE;
    if (which == 0) {
      member.link_target_length = 4;
    } else if (which == 1) {
      member.uname_length = 4;
    } else {
      member.gname_length = 4;
    }
    EXPECT_EQ(garc_writer_add(writer, &member), GARC_ERR_INVALID) << which;
  }
  EXPECT_EQ(garc_writer_add(writer, nullptr), GARC_ERR_INVALID);
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
}

TEST(WriterRefusals, ALinkTargetOnANonLinkIsWrittenRatherThanRefused) {
  // The reader reports a linkname field whatever the typeflag says, because a
  // hostile archive can carry one - so refusing it here would make an archive
  // this library reads and cannot write back.
  Captured member = plain_file("a", "");
  member.link = "somewhere";
  std::string bytes;
  ASSERT_EQ(build({member}, &bytes), GARC_OK);
  std::vector<Captured> back;
  ASSERT_EQ(read_all(bytes, &back), GARC_OK);
  ASSERT_EQ(back.size(), 1u);
  EXPECT_EQ(back[0].link, "somewhere");
  EXPECT_EQ(back[0].type, GARC_MEMBER_FILE);
}

//-----------------------------------------------------------------------------
// The data accounting
//-----------------------------------------------------------------------------

TEST(WriterData, RemainingCountsDownAndTheBoundaryIsTheDeclaredSize) {
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  GARC_Writer * writer = nullptr;
  ASSERT_EQ(garc_writer_create(sink, GARC_FORMAT_TAR, nullptr, &writer),
      GARC_OK);
  EXPECT_EQ(garc_writer_data_remaining(writer), 0u);

  const Captured member = plain_file("a", "12345");
  const GARC_Member m = member.as_member();
  ASSERT_EQ(garc_writer_add(writer, &m), GARC_OK);
  EXPECT_EQ(garc_writer_data_remaining(writer), 5u);
  ASSERT_EQ(garc_writer_write(writer, "12", 2), GARC_OK);
  EXPECT_EQ(garc_writer_data_remaining(writer), 3u);
  // One byte past is refused and writes nothing, so the count does not move.
  EXPECT_EQ(garc_writer_write(writer, "1234", 4), GARC_ERR_INVALID);
  EXPECT_EQ(garc_writer_data_remaining(writer), 3u);
  // Exactly the remainder is accepted.
  ASSERT_EQ(garc_writer_write(writer, "345", 3), GARC_OK);
  EXPECT_EQ(garc_writer_data_remaining(writer), 0u);
  EXPECT_EQ(garc_writer_write(writer, "x", 1), GARC_ERR_INVALID);
  EXPECT_EQ(garc_writer_finish(writer), GARC_OK);

  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
}

TEST(WriterData, AZeroLengthWriteIsAcceptedWhileAMemberIsOpen) {
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  GARC_Writer * writer = nullptr;
  ASSERT_EQ(garc_writer_create(sink, GARC_FORMAT_TAR, nullptr, &writer),
      GARC_OK);
  const Captured member = plain_file("a", "x");
  const GARC_Member m = member.as_member();
  ASSERT_EQ(garc_writer_add(writer, &m), GARC_OK);
  EXPECT_EQ(garc_writer_write(writer, nullptr, 0), GARC_OK);
  EXPECT_EQ(garc_writer_write(writer, "x", 0), GARC_OK);
  EXPECT_EQ(garc_writer_data_remaining(writer), 1u);
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
}

TEST(WriterData, AShortMemberIsRefusedByBothWaysOfClosingOne) {
  // The header already says how many bytes there are. Padding to fit would make
  // the archive claim data it does not have, and letting it through would put
  // the next header where no reader is looking for one.
  for (int finish : {0, 1}) {
    GARC_Sink * sink = nullptr;
    ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
    GARC_Writer * writer = nullptr;
    ASSERT_EQ(garc_writer_create(sink, GARC_FORMAT_TAR, nullptr, &writer),
        GARC_OK);
    const Captured member = plain_file("a", "12345");
    const GARC_Member m = member.as_member();
    ASSERT_EQ(garc_writer_add(writer, &m), GARC_OK);
    ASSERT_EQ(garc_writer_write(writer, "12", 2), GARC_OK);
    if (finish) {
      EXPECT_EQ(garc_writer_finish(writer), GARC_ERR_INVALID);
    } else {
      const Captured next = plain_file("b", "");
      const GARC_Member m2 = next.as_member();
      EXPECT_EQ(garc_writer_add(writer, &m2), GARC_ERR_INVALID);
      EXPECT_EQ(garc_writer_member_count(writer), 1u);
    }
    garc_writer_destroy(writer);
    garc_sink_destroy(sink);
  }
}

TEST(WriterData, WritingWithNoMemberIsRefused) {
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  GARC_Writer * writer = nullptr;
  ASSERT_EQ(garc_writer_create(sink, GARC_FORMAT_TAR, nullptr, &writer),
      GARC_OK);
  EXPECT_EQ(garc_writer_write(writer, "x", 1), GARC_ERR_INVALID);
  EXPECT_EQ(garc_writer_write(nullptr, "x", 1), GARC_ERR_INVALID);
  // A member with no data refuses a byte for the same reason: its size is zero.
  Captured member = plain_file("adir", "");
  member.type = GARC_MEMBER_DIRECTORY;
  const GARC_Member m = member.as_member();
  ASSERT_EQ(garc_writer_add(writer, &m), GARC_OK);
  EXPECT_EQ(garc_writer_write(writer, "x", 1), GARC_ERR_INVALID);
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
}

TEST(WriterFinish, TheArchiveAcceptsNothingAfterIt) {
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  GARC_Writer * writer = nullptr;
  ASSERT_EQ(garc_writer_create(sink, GARC_FORMAT_TAR, nullptr, &writer),
      GARC_OK);
  ASSERT_EQ(garc_writer_finish(writer), GARC_OK);
  const uint64_t after = garc_sink_tell(sink);

  EXPECT_EQ(garc_writer_finish(writer), GARC_ERR_INVALID);
  const Captured member = plain_file("a", "");
  const GARC_Member m = member.as_member();
  EXPECT_EQ(garc_writer_add(writer, &m), GARC_ERR_INVALID);
  EXPECT_EQ(garc_writer_write(writer, "x", 1), GARC_ERR_INVALID);
  EXPECT_EQ(garc_sink_tell(sink), after);

  EXPECT_EQ(garc_writer_finish(nullptr), GARC_ERR_INVALID);
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
}

TEST(WriterFinish, DestroyingWithoutFinishingLeavesATruncatedArchive) {
  // On purpose: finishing can fail and a destructor cannot report it, so a
  // destructor that finished silently would turn an abandoned archive into a
  // complete-looking one.
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  GARC_Writer * writer = nullptr;
  ASSERT_EQ(garc_writer_create(sink, GARC_FORMAT_TAR, nullptr, &writer),
      GARC_OK);
  const Captured member = plain_file("a", "x");
  const GARC_Member m = member.as_member();
  ASSERT_EQ(garc_writer_add(writer, &m), GARC_OK);
  ASSERT_EQ(garc_writer_write(writer, "x", 1), GARC_OK);
  garc_writer_destroy(writer);

  const void * data = nullptr;
  size_t size = 0;
  ASSERT_EQ(garc_sink_data(sink, &data, &size), GARC_OK);
  // The header and one byte of data, and not even the padding after it: the
  // padding is owed by whichever call closes the member, and no call did. That
  // is the shape an abandoned write leaves - visibly unfinished rather than a
  // block short of an end marker, which a reader could mistake for a trimmed
  // tail.
  EXPECT_EQ(size, 513u);
  std::vector<Captured> back;
  EXPECT_EQ(read_all(std::string(static_cast<const char *>(data), size), &back),
      GARC_ERR_CORRUPT);
  garc_sink_destroy(sink);
}

//-----------------------------------------------------------------------------
// When the sink and the allocator refuse
//-----------------------------------------------------------------------------

TEST(WriterFailures, ARefusedWriteIsReportedAndNothingIsCounted) {
  BufferDrain drain;
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_callback(drain.callbacks(), &sink), GARC_OK);
  GARC_Writer * writer = nullptr;
  ASSERT_EQ(garc_writer_create(sink, GARC_FORMAT_TAR, nullptr, &writer),
      GARC_OK);

  const Captured member = plain_file("a", "x");
  const GARC_Member m = member.as_member();
  drain.fail_writes(1);
  EXPECT_EQ(garc_writer_add(writer, &m), GARC_ERR_IO);
  EXPECT_EQ(garc_writer_member_count(writer), 0u);
  EXPECT_EQ(garc_sink_tell(sink), 0u);

  // And again with the sink working, to show the writer was left usable.
  ASSERT_EQ(garc_writer_add(writer, &m), GARC_OK);
  ASSERT_EQ(garc_writer_write(writer, "x", 1), GARC_OK);
  drain.fail_writes(1);
  EXPECT_EQ(garc_writer_finish(writer), GARC_ERR_IO);
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
}

TEST(WriterFailures, AFailureWritingTheDataIsReported) {
  BufferDrain drain;
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_callback(drain.callbacks(), &sink), GARC_OK);
  GARC_Writer * writer = nullptr;
  ASSERT_EQ(garc_writer_create(sink, GARC_FORMAT_TAR, nullptr, &writer),
      GARC_OK);
  const Captured member = plain_file("a", "x");
  const GARC_Member m = member.as_member();
  ASSERT_EQ(garc_writer_add(writer, &m), GARC_OK);
  drain.fail_writes(1);
  EXPECT_EQ(garc_writer_write(writer, "x", 1), GARC_ERR_IO);
  // The byte was not taken, so the member still owes it.
  EXPECT_EQ(garc_writer_data_remaining(writer), 1u);
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
}

TEST(WriterFailures, AFailedRecordAllocationIsReportedAndWritesNothing) {
  BufferDrain drain;
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_callback(drain.callbacks(), &sink), GARC_OK);
  // Request 0 is the writer object; the record buffer is the next one.
  FailingAllocator allocator(1, 0);
  GARC_Writer * writer = nullptr;
  ASSERT_EQ(garc_writer_create_with_allocator(
                sink, GARC_FORMAT_TAR, nullptr, allocator.get(), &writer),
      GARC_OK);
  const Captured member = plain_file(std::string(160, 'c'), "");
  const GARC_Member m = member.as_member();
  EXPECT_EQ(garc_writer_add(writer, &m), GARC_ERR_OOM);
  EXPECT_TRUE(allocator.failed());
  EXPECT_EQ(drain.writes(), 0u);
  EXPECT_EQ(garc_writer_member_count(writer), 0u);
  allocator.stop_failing();
  garc_writer_destroy(writer);
  EXPECT_EQ(allocator.live(), 0u);
  garc_sink_destroy(sink);
}

TEST(WriterFailures, TheRecordBufferIsReusedAcrossMembers) {
  // One buffer rather than one per member: an archive of long names would
  // otherwise allocate and free once each. Counted through the allocator,
  // because the bytes cannot tell.
  FailingAllocator allocator(static_cast<size_t>(-1));
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory_with_allocator(allocator.get(), &sink),
      GARC_OK);
  GARC_Writer * writer = nullptr;
  ASSERT_EQ(garc_writer_create_with_allocator(
                sink, GARC_FORMAT_TAR, nullptr, allocator.get(), &writer),
      GARC_OK);
  size_t after_first = 0;
  for (int i = 0; i < 5; ++i) {
    const Captured member
        = plain_file(std::string(160, static_cast<char>('a' + i)), "");
    const GARC_Member m = member.as_member();
    ASSERT_EQ(garc_writer_add(writer, &m), GARC_OK) << i;
    if (i == 0) {
      after_first = allocator.requests();
    }
  }
  // Nothing beyond the first member's buffer and whatever the sink grew.
  EXPECT_EQ(allocator.requests(), after_first);
  ASSERT_EQ(garc_writer_finish(writer), GARC_OK);
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
  EXPECT_EQ(allocator.live(), 0u);
}

TEST(WriterFailures, OneMembersRecordsDoNotLeakIntoTheNext) {
  // The buffer is reused, so its length has to be reset per member. A member
  // that needs no records must get none.
  std::string bytes;
  ASSERT_EQ(build({plain_file(std::string(160, 'c'), ""), plain_file("b", "")},
                &bytes),
      GARC_OK);
  EXPECT_EQ(carrier_count(bytes), 1u);
  std::vector<Captured> back;
  ASSERT_EQ(read_all(bytes, &back), GARC_OK);
  ASSERT_EQ(back.size(), 2u);
  EXPECT_EQ(back[0].name, std::string(160, 'c'));
  EXPECT_EQ(back[1].name, "b");
  EXPECT_EQ(back[1].variant, GARC_TAR_USTAR);
}

//-----------------------------------------------------------------------------
// The record encoding itself
//-----------------------------------------------------------------------------

TEST(WriterRecords, TheSelfReferentialLengthCountsItself) {
  // `len SP key = value LF`, where len is the length of the whole record
  // including the digits of len. A 90-byte owner name is the case where that
  // bites: everything but the digits is 98 bytes, which needs two digits for 100
  // and three for 101, so the naive answer is one short of its own statement.
  Captured member = plain_file("a", "");
  member.uname = std::string(90, 'u');
  std::string bytes;
  ASSERT_EQ(build({member}, &bytes), GARC_OK);
  const std::string records = records_of(bytes);
  ASSERT_EQ(records.size(), 101u);
  EXPECT_EQ(records.substr(0, 10), std::string("101 uname="));
  EXPECT_EQ(records[100], '\n');
  std::vector<Captured> back;
  ASSERT_EQ(read_all(bytes, &back), GARC_OK);
  ASSERT_EQ(back.size(), 1u);
  EXPECT_EQ(back[0].uname, member.uname);
}

TEST(WriterRecords, EveryRecordLengthIsItsOwnLength) {
  // The reader parses the length and then expects the record to end exactly
  // there, so a length one out is caught - but only for the lengths a test
  // happens to produce. Sweeping the value length across a power-of-ten boundary
  // checks the arithmetic rather than one instance of it.
  for (size_t length = 80; length <= 120; ++length) {
    Captured member = plain_file("a", "");
    member.uname = std::string(length, 'u');
    std::string bytes;
    ASSERT_EQ(build({member}, &bytes), GARC_OK) << length;
    const std::string records = records_of(bytes);
    // "<digits> uname=<value>\n"
    const size_t space = records.find(' ');
    ASSERT_NE(space, std::string::npos) << length;
    EXPECT_EQ(std::stoul(records.substr(0, space)), records.size()) << length;
    std::vector<Captured> back;
    ASSERT_EQ(read_all(bytes, &back), GARC_OK) << length;
    ASSERT_EQ(back.size(), 1u);
    EXPECT_EQ(back[0].uname, member.uname) << length;
  }
}

TEST(WriterRecords, TheWidestTimesAreWrittenInFull) {
  // The buffer a number record is formatted into is sized by argument rather
  // than guarded by a runtime check, so the extremes that would overflow one
  // sized by guesswork are pinned here as bytes.
  struct Case {
    int64_t seconds;
    uint32_t nanoseconds;
    const char * expected;
  };
  const Case cases[] = {
    {INT64_MIN, 0, "mtime=-9223372036854775808\n"},
    {INT64_MAX, 0, "mtime=9223372036854775807\n"},
    // -2^63 seconds plus half a second is -(2^63 - 0.5).
    {INT64_MIN, 500000000, "mtime=-9223372036854775807.500000000\n"},
    {INT64_MAX, 999999999, "mtime=9223372036854775807.999999999\n"},
  };
  for (const Case & one : cases) {
    Captured member = plain_file("a", "");
    member.mtime_seconds = one.seconds;
    member.mtime_nanoseconds = one.nanoseconds;
    member.mtime_source = one.nanoseconds ? GARC_TIME_PAX_DECIMAL
                                          : GARC_TIME_TAR_OCTAL;
    std::string bytes;
    ASSERT_EQ(build({member}, &bytes), GARC_OK) << one.expected;
    EXPECT_NE(records_of(bytes).find(one.expected), std::string::npos)
        << one.expected << " in " << records_of(bytes);
    std::vector<Captured> back;
    ASSERT_EQ(read_all(bytes, &back), GARC_OK) << one.expected;
    ASSERT_EQ(back.size(), 1u);
    EXPECT_EQ(back[0].mtime_seconds, one.seconds) << one.expected;
    EXPECT_EQ(back[0].mtime_nanoseconds, one.nanoseconds) << one.expected;
  }
}

TEST(WriterRecords, TheCarriersOwnHeaderCarriesNothingOfTheMembers) {
  // A reader that extracted the carrier - the bug the carrier rules exist to
  // prevent - must not be handed the member's mode to apply to it.
  Captured member = plain_file(std::string(160, 'c'), "");
  member.mode = 04777;
  member.uid = 1234;
  member.gid = 5678;
  member.mtime_seconds = 1700000000;
  std::string bytes;
  ASSERT_EQ(build({member}, &bytes), GARC_OK);
  ASSERT_EQ(carrier_count(bytes), 1u);
  EXPECT_EQ(bytes.substr(0, 15), std::string("././@PaxHeader\0", 15));
  EXPECT_EQ(bytes.substr(100, 8), std::string("0000000\0", 8));
  EXPECT_EQ(bytes.substr(108, 8), std::string("0000000\0", 8));
  EXPECT_EQ(bytes.substr(116, 8), std::string("0000000\0", 8));
  EXPECT_EQ(bytes.substr(136, 12), std::string("00000000000\0", 12));
  EXPECT_EQ(bytes[156], 'x');
  EXPECT_EQ(bytes.substr(257, 6), std::string("ustar\0", 6));
  EXPECT_EQ(bytes.substr(345, 155), std::string(155, '\0'));
}

TEST(WriterRecords, RawBytesInAnyValueOfTheSetDeclareBinaryForAllOfIt) {
  // hdrcharset applies to the record set, not to one record, so it is decided
  // over every value in the set at once - which means a long link target or a
  // long owner name reaches it as well as a long name.
  const std::string raw(1, static_cast<char>(0xFF));
  struct Case {
    const char * what;
    Captured member;
  };
  std::vector<Case> cases;
  {
    Captured m = plain_file("link", "");
    m.type = GARC_MEMBER_SYMLINK;
    m.size = 0;
    m.link = std::string(120, 't') + raw;
    cases.push_back({"a long link target", m});
  }
  {
    Captured m = plain_file("a", "");
    m.uname = std::string(40, 'u') + raw;
    cases.push_back({"a long owner name", m});
  }
  {
    Captured m = plain_file("a", "");
    m.gname = std::string(40, 'g') + raw;
    cases.push_back({"a long group name", m});
  }
  for (const Case & one : cases) {
    std::string bytes;
    ASSERT_EQ(build({one.member}, &bytes), GARC_OK) << one.what;
    EXPECT_NE(records_of(bytes).find("hdrcharset=BINARY\n"), std::string::npos)
        << one.what;
    std::vector<Captured> back;
    ASSERT_EQ(read_all(bytes, &back), GARC_OK) << one.what;
    ASSERT_EQ(back.size(), 1u);
    EXPECT_EQ(back[0].link, one.member.link) << one.what;
    EXPECT_EQ(back[0].uname, one.member.uname) << one.what;
    EXPECT_EQ(back[0].gname, one.member.gname) << one.what;
  }
}

TEST(WriterRecords, AFailedAllocationForTheCharsetRecordIsReported) {
  // The first record of the set, so it is the one that reaches the allocator
  // first and the arm a later record's failure cannot cover.
  BufferDrain drain;
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_callback(drain.callbacks(), &sink), GARC_OK);
  FailingAllocator allocator(1, 0);
  GARC_Writer * writer = nullptr;
  ASSERT_EQ(garc_writer_create_with_allocator(
                sink, GARC_FORMAT_TAR, nullptr, allocator.get(), &writer),
      GARC_OK);
  Captured member = plain_file(std::string(160, 'a'), "");
  member.name[5] = static_cast<char>(0x80);
  const GARC_Member m = member.as_member();
  EXPECT_EQ(garc_writer_add(writer, &m), GARC_ERR_OOM);
  EXPECT_EQ(drain.writes(), 0u);
  allocator.stop_failing();
  garc_writer_destroy(writer);
  EXPECT_EQ(allocator.live(), 0u);
  garc_sink_destroy(sink);
}

TEST(WriterFailures, AFailureWritingTheEndMarkerIsReported) {
  // An empty archive, so that closing a member cannot be what fails first.
  BufferDrain drain;
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_callback(drain.callbacks(), &sink), GARC_OK);
  GARC_Writer * writer = nullptr;
  ASSERT_EQ(garc_writer_create(sink, GARC_FORMAT_TAR, nullptr, &writer),
      GARC_OK);
  drain.fail_writes(1);
  EXPECT_EQ(garc_writer_finish(writer), GARC_ERR_IO);
  // Not finished, so it can be tried again once whatever blocked the sink is
  // cleared.
  EXPECT_EQ(garc_writer_finish(writer), GARC_OK);
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
}

TEST(WriterFailures, AFailureWritingTheRecordBlocksIsReported) {
  BufferDrain drain;
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_callback(drain.callbacks(), &sink), GARC_OK);
  GARC_Writer * writer = nullptr;
  ASSERT_EQ(garc_writer_create(sink, GARC_FORMAT_TAR, nullptr, &writer),
      GARC_OK);
  const Captured member = plain_file(std::string(160, 'c'), "");
  const GARC_Member m = member.as_member();
  // Four writes go into a member with records: the extended header's own block,
  // its records, the padding after them, and the member's header. Failing only
  // the first would leave three arms looking covered because the function was.
  for (size_t which = 0; which < 4; ++which) {
    drain.fail_write_at(which);
    EXPECT_EQ(garc_writer_add(writer, &m), GARC_ERR_IO) << which;
    EXPECT_EQ(garc_writer_member_count(writer), 0u) << which;
  }
  // And with nothing failing it succeeds, so the four above were the arms and not
  // four spellings of one refusal.
  EXPECT_EQ(garc_writer_add(writer, &m), GARC_OK);
  EXPECT_EQ(garc_writer_member_count(writer), 1u);
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
}

//-----------------------------------------------------------------------------
// The dump
//-----------------------------------------------------------------------------

TEST(WriterDump, SaysWhatTheWriterIsDoing) {
  char * buffer = nullptr;
  size_t length = 0;
  FILE * out = open_memstream(&buffer, &length);
  ASSERT_NE(out, nullptr);

  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  GARC_Writer * writer = nullptr;
  ASSERT_EQ(garc_writer_create(sink, GARC_FORMAT_TAR, nullptr, &writer),
      GARC_OK);
  const Captured member = plain_file("a", "12345");
  const GARC_Member m = member.as_member();
  ASSERT_EQ(garc_writer_add(writer, &m), GARC_OK);
  garc_writer_dump(writer, out);
  ASSERT_EQ(fflush(out), 0);
  const std::string text(buffer, length);
  EXPECT_NE(text.find("tar"), std::string::npos) << text;
  EXPECT_NE(text.find("pax"), std::string::npos) << text;
  EXPECT_NE(text.find("members=1"), std::string::npos) << text;
  EXPECT_NE(text.find("5 data bytes owed"), std::string::npos) << text;

  fclose(out);
  free(buffer);
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
}

TEST(WriterDump, NullWriterAndNullStreamAreBothHandled) {
  char * buffer = nullptr;
  size_t length = 0;
  FILE * out = open_memstream(&buffer, &length);
  ASSERT_NE(out, nullptr);
  garc_writer_dump(nullptr, out);
  ASSERT_EQ(fflush(out), 0);
  EXPECT_NE(std::string(buffer, length).find("null"), std::string::npos);
  fclose(out);
  free(buffer);
  garc_writer_dump(nullptr, nullptr);
}

//-----------------------------------------------------------------------------
// The corpus, run backwards
//-----------------------------------------------------------------------------

TEST(WriterCorpus, EveryFixtureSurvivesBeingReadAndWrittenAndReadAgain) {
  // **Necessary and not sufficient.** A writer and a reader that share a
  // misunderstanding agree perfectly, so this catches a field in the wrong
  // offset and not a field with the wrong meaning. `make check-oracle` is what
  // asks something other than this library.
  //
  // The refused members are counted rather than skipped quietly: a fixture that
  // started being refused would otherwise shrink the population without
  // shrinking the score.
  const std::vector<std::string> fixtures = corpus_archives();
  ASSERT_FALSE(fixtures.empty())
      << "tests/data/tar/manifest.tsv is missing or empty; the corpus is "
         "gitignored and regenerated with `make corpus`";
  size_t compared = 0;
  for (const std::string & fixture : fixtures) {
    const std::vector<uint8_t> raw = read_fixture(data_path(fixture));
    ASSERT_FALSE(raw.empty()) << fixture;
    const std::string original(
        reinterpret_cast<const char *>(raw.data()), raw.size());
    std::vector<Captured> first;
    ASSERT_EQ(read_all(original, &first), GARC_OK) << fixture;

    std::string rewritten;
    ASSERT_EQ(build(first, &rewritten), GARC_OK) << fixture;
    std::vector<Captured> second;
    ASSERT_EQ(read_all(rewritten, &second), GARC_OK) << fixture;

    ASSERT_EQ(second.size(), first.size()) << fixture;
    for (size_t i = 0; i < first.size(); ++i) {
      EXPECT_EQ(second[i].name, first[i].name) << fixture << " #" << i;
      EXPECT_EQ(second[i].type, first[i].type) << fixture << " #" << i;
      EXPECT_EQ(second[i].size, first[i].size) << fixture << " #" << i;
      EXPECT_EQ(second[i].data, first[i].data) << fixture << " #" << i;
      EXPECT_EQ(second[i].link, first[i].link) << fixture << " #" << i;
      EXPECT_EQ(second[i].uname, first[i].uname) << fixture << " #" << i;
      EXPECT_EQ(second[i].gname, first[i].gname) << fixture << " #" << i;
      EXPECT_EQ(second[i].mode, first[i].mode) << fixture << " #" << i;
      EXPECT_EQ(second[i].uid, first[i].uid) << fixture << " #" << i;
      EXPECT_EQ(second[i].gid, first[i].gid) << fixture << " #" << i;
      EXPECT_EQ(second[i].mtime_seconds, first[i].mtime_seconds)
          << fixture << " #" << i;
      EXPECT_EQ(second[i].mtime_nanoseconds, first[i].mtime_nanoseconds)
          << fixture << " #" << i;
      EXPECT_EQ(second[i].mtime_source, first[i].mtime_source)
          << fixture << " #" << i;
      compared++;
    }
  }
  // The whole corpus, so a fixture that stopped being read would show up as a
  // smaller number rather than as nothing at all.
  EXPECT_EQ(compared, 91u);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
