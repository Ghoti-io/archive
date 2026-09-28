/**
 * @file
 *
 * Writing zip, and reading back what was written.
 *
 * **The load-bearing test here is a round trip, and the reason is that the
 * expectation is free.** An archive this library writes is an archive this
 * library reads, so the member that comes back either is the member that went in
 * or it is not - and every field of it is compared, not a chosen few. No
 * expectation written by hand can be as complete, and none of the byte-level
 * assertions below would catch a field written into the wrong record.
 *
 * What a round trip **cannot** say is that the bytes are a zip rather than
 * something only this library agrees about. That is `check-zip-writer`'s job: it
 * hands every archive written here to unzip, bsdtar, 7-Zip and Python and reads
 * back what they say. The tests in this file are the ones that can run without a
 * container.
 *
 * Three fields do not survive a round trip, and each is a property of the format:
 *
 * - **An odd mtime second, and any time outside 1980-2107.** The DOS field has
 *   two-second resolution, so the writer adds a 0x5455 extended timestamp when
 *   and only when the DOS pair cannot carry the time exactly - which means the
 *   time survives and `mtime_source` changes from `GARC_TIME_ZIP_DOS` to
 *   `GARC_TIME_ZIP_UNIX`. A test asserts that swap rather than working around it.
 * - **Sub-second times.** Nothing this writer emits carries one; only 7-Zip's
 *   NTFS field does, and writing that is not in this cut.
 * - **An owner.** zip has no uid or gid field outside a vendor extra, so
 *   `ids_valid` comes back clear however it went in.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <ghoti.io/compress/compress.h>

#include "test_helpers.h"
#include "zip/zip_internal.h"

using garctest::BufferDrain;
using garctest::BufferSource;
using garctest::FailingAllocator;

namespace {

/** What a member looks like going in, so a test states only what it varies. */
struct Spec {
  std::string name;
  GARC_Member_Type type = GARC_MEMBER_FILE;
  std::string data;
  std::string link;
  uint32_t mode = 0644;
  bool mode_valid = true;
  int64_t mtime = 1000000000; // 2001-09-09T01:46:40Z, an even second in range.
  GARC_Time_Source mtime_source = GARC_TIME_ZIP_DOS;
};

/** Fill in a GARC_Member from a Spec. Borrows the Spec's strings. */
GARC_Member member_of(const Spec & spec) {
  GARC_Member member;
  std::memset(&member, 0, sizeof(member));
  member.name = spec.name.data();
  member.name_length = spec.name.size();
  member.type = spec.type;
  // **The declared size is the Spec's data length whatever the type**, which is
  // how the "carries no data" refusals are expressed: a directory or a symlink
  // with a non-empty `data` is a member declaring bytes it will not be allowed to
  // write. Deriving it only for a file made those cases unreachable and two of
  // them silently passed.
  member.size = spec.data.size();
  member.mode = spec.mode;
  member.mode_valid = spec.mode_valid ? 1 : 0;
  member.mtime_seconds = spec.mtime;
  member.mtime_source = spec.mtime_source;
  if (!spec.link.empty()) {
    member.link_target = spec.link.data();
    member.link_target_length = spec.link.size();
  }
  return member;
}

/** An archive built into memory, with the writer kept alive beside it. */
class Built {
public:
  explicit Built(GARC_Zip_Sizes sizes = GARC_ZIP_SIZES_AUTO,
      bool force_zip64 = false,
      GARC_Zip_Method method = GARC_ZIP_METHOD_STORED) {
    if (garc_sink_create_memory(&sink_) != GARC_OK) {
      return;
    }
    GARC_Writer_Options options;
    garc_writer_options_default(&options);
    options.zip_sizes = sizes;
    options.zip_force_zip64 = force_zip64 ? 1 : 0;
    options.zip_method = method;
    create_result_
        = garc_writer_create(sink_, GARC_FORMAT_ZIP, &options, &writer_);
  }

  ~Built() {
    garc_writer_destroy(writer_);
    garc_sink_destroy(sink_);
  }

  Built(const Built &) = delete;
  Built & operator=(const Built &) = delete;

  GARC_Result create_result() const { return create_result_; }
  GARC_Writer * writer() const { return writer_; }
  GARC_Sink * sink() const { return sink_; }

  /** Add a member and write its data, which is what a caller's loop does. */
  GARC_Result add(const Spec & spec) {
    const GARC_Member member = member_of(spec);
    GARC_Result result = garc_writer_add(writer_, &member);
    if (result != GARC_OK || spec.type != GARC_MEMBER_FILE
        || spec.data.empty()) {
      return result;
    }
    return garc_writer_write(writer_, spec.data.data(), spec.data.size());
  }

  GARC_Result finish() { return garc_writer_finish(writer_); }

  std::vector<uint8_t> bytes() const {
    const void * data = nullptr;
    size_t size = 0;
    if (garc_sink_data(sink_, &data, &size) != GARC_OK) {
      return {};
    }
    const uint8_t * raw = static_cast<const uint8_t *>(data);
    return std::vector<uint8_t>(raw, raw + size);
  }

private:
  GARC_Sink * sink_ = nullptr;
  GARC_Writer * writer_ = nullptr;
  GARC_Result create_result_ = GARC_ERR_INTERNAL;
};

/** One member as the reader reports it, for comparison against its Spec. */
struct ReadBack {
  std::string name;
  GARC_Member_Type type = GARC_MEMBER_OTHER;
  std::string data;
  std::string link;
  uint64_t size = 0;
  uint64_t compressed_size = 0;
  uint32_t mode = 0;
  bool mode_valid = false;
  int64_t mtime = 0;
  GARC_Time_Source mtime_source = GARC_TIME_NONE;
  uint16_t method = 0;
  uint16_t flags = 0;
  uint32_t crc = 0;
  bool used_zip64 = false;
  /**
   * The *central* extra field's length, captured during the walk.
   *
   * Recorded here rather than asked afterwards, which is the mistake the first
   * version of this file made: garc_zip_member_extra_length() reports the
   * **current** member's length, and by the time Roundtrip's constructor has
   * finished the current member is the last one. Two tests asserted a number that
   * belonged to a different member and happened to be wrong in a way that read
   * like a writer bug.
   */
  size_t extra_length = 0;
  GARC_Result read_result = GARC_OK;
};

/** What was written, as this library's own reader sees it. */
class Roundtrip {
public:
  explicit Roundtrip(const std::vector<uint8_t> & bytes)
      : bytes_(bytes), source_(bytes_.data(), bytes_.size(), true, true) {
    if (garc_stream_create_callback(source_.callbacks(), &stream_) != GARC_OK) {
      return;
    }
    open_result_ = garc_open(stream_, nullptr, &archive_);
    if (open_result_ != GARC_OK) {
      return;
    }
    const GARC_Member * member = nullptr;
    GARC_Result result;
    while ((result = garc_next(archive_, &member)) == GARC_OK) {
      ReadBack seen;
      seen.name.assign(member->name, member->name_length);
      seen.type = member->type;
      if (member->link_target) {
        seen.link.assign(member->link_target, member->link_target_length);
      }
      seen.size = member->size;
      seen.compressed_size = garc_zip_member_compressed_size(archive_);
      seen.mode = member->mode;
      seen.mode_valid = member->mode_valid != 0;
      seen.mtime = member->mtime_seconds;
      seen.mtime_source = member->mtime_source;
      seen.method = garc_zip_member_method(archive_);
      seen.flags = garc_zip_member_flags(archive_);
      seen.crc = garc_zip_member_crc32(archive_);
      seen.used_zip64 = garc_zip_member_used_zip64(archive_) != 0;
      seen.extra_length = garc_zip_member_extra_length(archive_);

      char buffer[512];
      size_t got = 0;
      GARC_Result data;
      while ((data = garc_read_member(archive_, buffer, sizeof(buffer), &got))
              == GARC_OK
          && got) {
        seen.data.append(buffer, got);
      }
      // GARC_OK here is also the CRC verdict: it arrives on the call that returns
      // zero bytes, so a member that reads to its end and reports OK is one whose
      // bytes match the CRC the writer declared.
      seen.read_result = data;
      members_.push_back(seen);
    }
    walk_result_ = result;
  }

  ~Roundtrip() {
    garc_close(archive_);
    garc_stream_destroy(stream_);
  }

  Roundtrip(const Roundtrip &) = delete;
  Roundtrip & operator=(const Roundtrip &) = delete;

  GARC_Result open_result() const { return open_result_; }
  GARC_Result walk_result() const { return walk_result_; }
  GARC_Archive * archive() const { return archive_; }
  const std::vector<ReadBack> & members() const { return members_; }

private:
  std::vector<uint8_t> bytes_;
  BufferSource source_;
  GARC_Stream * stream_ = nullptr;
  GARC_Archive * archive_ = nullptr;
  GARC_Result open_result_ = GARC_ERR_INTERNAL;
  GARC_Result walk_result_ = GARC_ERR_INTERNAL;
  std::vector<ReadBack> members_;
};

/** The members every discipline is tested over: one of each thing zip can hold. */
std::vector<Spec> corpus() {
  std::vector<Spec> out;
  Spec file;
  file.name = "hello.txt";
  file.data = "hello, archive\n";
  out.push_back(file);

  Spec directory;
  directory.name = "notes/";
  directory.type = GARC_MEMBER_DIRECTORY;
  directory.mode = 0755;
  out.push_back(directory);

  Spec link;
  link.name = "link-to-hello";
  link.type = GARC_MEMBER_SYMLINK;
  link.link = "hello.txt";
  link.mode = 0777;
  out.push_back(link);

  // A zero-length member, which is where a reader that seeks by size lands
  // exactly on the next header whether its arithmetic is right or not.
  Spec empty;
  empty.name = "empty";
  out.push_back(empty);

  // Bigger than one write of the reader's buffer, so the data path loops.
  Spec big;
  big.name = "big.bin";
  big.data = std::string(2000u, 'q');
  out.push_back(big);

  // A name that is not ASCII, which is what makes the UTF-8 flag mean something.
  Spec utf8;
  utf8.name = "na\xC3\xAFve.txt";
  utf8.data = "a non-ASCII name\n";
  out.push_back(utf8);
  return out;
}

/** Find a little-endian field in the archive's bytes. */
uint32_t le32(const std::vector<uint8_t> & bytes, size_t at) {
  return (uint32_t)bytes[at] | ((uint32_t)bytes[at + 1] << 8)
      | ((uint32_t)bytes[at + 2] << 16) | ((uint32_t)bytes[at + 3] << 24);
}

uint16_t le16(const std::vector<uint8_t> & bytes, size_t at) {
  return (uint16_t)((uint32_t)bytes[at] | ((uint32_t)bytes[at + 1] << 8));
}

/** Whether the archive holds this four-byte signature anywhere. */
bool holds(const std::vector<uint8_t> & bytes, const char * signature) {
  for (size_t i = 0; i + 4u <= bytes.size(); ++i) {
    if (std::memcmp(bytes.data() + i, signature, 4) == 0) {
      return true;
    }
  }
  return false;
}

/**
 * Bytes deflate cannot shrink.
 *
 * A linear congruential generator rather than `rand()`, so the same bytes come out
 * on every host and in every order the tests run in: a compressed size asserted
 * against is only meaningful if the input is fixed. The sequence is not
 * cryptographic and does not need to be - it needs to have no runs and no skewed
 * byte frequency, which is what defeats both halves of deflate.
 */
std::string incompressible(size_t length) {
  std::string out;
  out.reserve(length);
  uint32_t state = 0x13579BDFu;
  for (size_t i = 0; i < length; ++i) {
    state = state * 1103515245u + 12345u;
    out.push_back((char)(uint8_t)(state >> 16));
  }
  return out;
}

/** Both methods, named, so a sweep says which one failed. */
std::vector<std::pair<const char *, GARC_Zip_Method>> methods() {
  return {
    {"stored", GARC_ZIP_METHOD_STORED},
    {"deflate", GARC_ZIP_METHOD_DEFLATE},
  };
}

/** Every discipline, named, so a sweep says which one failed. */
std::vector<std::pair<const char *, GARC_Zip_Sizes>> disciplines() {
  return {
    {"auto", GARC_ZIP_SIZES_AUTO},
    {"descriptor", GARC_ZIP_SIZES_DESCRIPTOR},
    {"local", GARC_ZIP_SIZES_LOCAL},
  };
}

} // namespace

//-----------------------------------------------------------------------------
// The round trip, which is where the expectations come from
//-----------------------------------------------------------------------------

TEST(ZipWrite, EveryMemberSurvivesEveryDiscipline) {
  // **The same archive three ways, and all three must read identically.** That is
  // the plan's requirement for this phase stated as a test: a data descriptor and
  // a patched local header are two ways of saying one thing, so an archive built
  // either way has to come back the same. A reader that believed the local header
  // instead of the central directory would pass this for two of the three.
  for (const auto & discipline : disciplines()) {
  for (const auto & method : methods()) {
    SCOPED_TRACE(discipline.first);
    SCOPED_TRACE(method.first);
    Built built(discipline.second, false, method.second);
    ASSERT_EQ(built.create_result(), GARC_OK);
    const std::vector<Spec> specs = corpus();
    for (const Spec & spec : specs) {
      ASSERT_EQ(built.add(spec), GARC_OK) << spec.name;
    }
    ASSERT_EQ(built.finish(), GARC_OK);

    Roundtrip trip(built.bytes());
    ASSERT_EQ(trip.open_result(), GARC_OK);
    EXPECT_EQ(garc_format(trip.archive()), GARC_FORMAT_ZIP);
    EXPECT_EQ(trip.walk_result(), GARC_END);
    ASSERT_EQ(trip.members().size(), specs.size());

    for (size_t i = 0; i < specs.size(); ++i) {
      const Spec & spec = specs[i];
      const ReadBack & seen = trip.members()[i];
      SCOPED_TRACE(spec.name);

      EXPECT_EQ(seen.name, spec.name);
      EXPECT_EQ(seen.type, spec.type);
      EXPECT_EQ(seen.read_result, GARC_OK) << garc_result_string(seen.read_result);
      // **The method is the option's, except where the member has no data**, which
      // is the one rule the writer applies over the caller's choice: deflating
      // nothing costs two bytes and buys nothing, and every reference stores it.
      // A directory reaches that by having no data at all.
      const bool deflatable = spec.type == GARC_MEMBER_FILE
          && !spec.data.empty();
      const uint16_t expected_method
          = deflatable ? method.second : GARC_ZIP_METHOD_STORED;
      EXPECT_EQ(seen.method, expected_method);
      if (expected_method == GARC_ZIP_METHOD_STORED) {
        // Stored, so the two sizes are one number - and for a symlink that number
        // is the length of the target this writer put there on the caller's behalf.
        EXPECT_EQ(seen.size, seen.compressed_size);
      }

      if (spec.type == GARC_MEMBER_SYMLINK) {
        EXPECT_EQ(seen.link, spec.link);
        EXPECT_EQ(seen.data, spec.link)
            << "a zip symlink's target IS its data, so both must report it";
        EXPECT_EQ(seen.size, spec.link.size());
      }
      else {
        EXPECT_EQ(seen.data, spec.data);
        EXPECT_EQ(seen.size, spec.data.size());
      }

      // The mode: permissions from the caller's field, type bits composed from
      // the type. A caller copying out of a tar supplies only permissions, so a
      // writer that took `mode` whole would turn every symlink into a file.
      ASSERT_TRUE(seen.mode_valid);
      EXPECT_EQ(seen.mode & 07777u, spec.mode);
      const uint32_t expected_type = spec.type == GARC_MEMBER_DIRECTORY
          ? 0040000u
          : (spec.type == GARC_MEMBER_SYMLINK ? 0120000u : 0100000u);
      EXPECT_EQ(seen.mode & 0170000u, expected_type);

      // An even second inside the DOS range, so the DOS pair carries it exactly
      // and no extended timestamp was needed.
      EXPECT_EQ(seen.mtime, spec.mtime);
      EXPECT_EQ(seen.mtime_source, GARC_TIME_ZIP_DOS);
    }
  }
  }
}

TEST(ZipWrite, TheDisciplinesDifferInTheBytesAndNotInTheReading) {
  // The other half of the claim above: the three archives read the same and are
  // *not* the same bytes. Without this, a bug that ignored the option would pass
  // the round-trip test three times over.
  std::vector<std::vector<uint8_t>> written;
  for (const auto & discipline : disciplines()) {
    Built built(discipline.second);
    ASSERT_EQ(built.create_result(), GARC_OK);
    Spec file;
    file.name = "hello.txt";
    file.data = "hello, archive\n";
    ASSERT_EQ(built.add(file), GARC_OK);
    ASSERT_EQ(built.finish(), GARC_OK);
    written.push_back(built.bytes());
  }
  // AUTO over a memory sink patches, so it is the same archive as LOCAL.
  EXPECT_EQ(written[0], written[2])
      << "AUTO over a patchable sink should produce the LOCAL form";
  EXPECT_NE(written[0], written[1]);
  // And the descriptor form is longer by exactly one descriptor: signature, CRC,
  // and two 32-bit sizes.
  EXPECT_EQ(written[1].size(), written[0].size() + 16u);
}

TEST(ZipWrite, ADescriptorLeavesTheLocalHeaderEmptyAndTheDirectoryFull) {
  // The bytes, because this is the one claim the round trip cannot make: the
  // reader deliberately does not consult the local header's sizes, so it reads
  // both forms identically and could not tell which was written.
  Built descriptor(GARC_ZIP_SIZES_DESCRIPTOR);
  ASSERT_EQ(descriptor.create_result(), GARC_OK);
  Spec file;
  file.name = "hello.txt";
  file.data = "hello, archive\n";
  ASSERT_EQ(descriptor.add(file), GARC_OK);
  ASSERT_EQ(descriptor.finish(), GARC_OK);
  const std::vector<uint8_t> streamed = descriptor.bytes();

  // The local header: flag bit 3 set, and the CRC and both sizes zero.
  EXPECT_EQ(le16(streamed, 6u) & 0x0008u, 0x0008u);
  EXPECT_EQ(le32(streamed, 14u), 0u) << "the CRC field should be empty";
  EXPECT_EQ(le32(streamed, 18u), 0u) << "the compressed size should be empty";
  EXPECT_EQ(le32(streamed, 22u), 0u) << "the size should be empty";
  EXPECT_TRUE(holds(streamed, "PK\x07\x08"))
      << "a descriptor signature should be in the archive";

  Built local(GARC_ZIP_SIZES_LOCAL);
  ASSERT_EQ(local.create_result(), GARC_OK);
  ASSERT_EQ(local.add(file), GARC_OK);
  ASSERT_EQ(local.finish(), GARC_OK);
  const std::vector<uint8_t> patched = local.bytes();

  EXPECT_EQ(le16(patched, 6u) & 0x0008u, 0u) << "bit 3 should be clear";
  EXPECT_NE(le32(patched, 14u), 0u) << "the CRC should have been filled in";
  EXPECT_EQ(le32(patched, 18u), 15u);
  EXPECT_EQ(le32(patched, 22u), 15u);
  EXPECT_FALSE(holds(patched, "PK\x07\x08"))
      << "no descriptor should have been written";
  // And the two archives agree about the CRC, which is the point of writing it
  // twice: the descriptor's value and the patched field are the same number.
  const size_t at = streamed.size() - 22u; // The end record.
  (void)at;
  EXPECT_EQ(le32(patched, 14u), le32(streamed, streamed.size() - 22u - 46u
      - file.name.size() + 16u))
      << "the central directory's CRC should match in both forms";
}

TEST(ZipWrite, AutoFallsBackToDescriptorsOnASinkThatCannotPatch) {
  // The question garc_sink_is_seekable() exists to answer, asked through the
  // writer. A drain with no `patch` is what a socket is.
  BufferDrain drain;
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_callback(drain.callbacks(), &sink), GARC_OK);
  GARC_Writer_Options options;
  garc_writer_options_default(&options);
  GARC_Writer * writer = nullptr;
  ASSERT_EQ(garc_writer_create(sink, GARC_FORMAT_ZIP, &options, &writer),
      GARC_OK);
  Spec file;
  file.name = "hello.txt";
  file.data = "hello, archive\n";
  const GARC_Member member = member_of(file);
  ASSERT_EQ(garc_writer_add(writer, &member), GARC_OK);
  ASSERT_EQ(garc_writer_write(writer, file.data.data(), file.data.size()),
      GARC_OK);
  ASSERT_EQ(garc_writer_finish(writer), GARC_OK);

  const std::vector<uint8_t> bytes = drain.bytes();
  EXPECT_EQ(le16(bytes, 6u) & 0x0008u, 0x0008u)
      << "a sink that cannot patch has to get a data descriptor";
  EXPECT_EQ(drain.patches(), 0u);
  // And it still reads, which is the whole point of the fallback.
  Roundtrip trip(bytes);
  ASSERT_EQ(trip.open_result(), GARC_OK);
  ASSERT_EQ(trip.members().size(), 1u);
  EXPECT_EQ(trip.members()[0].data, file.data);

  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
}

TEST(ZipWrite, LocalOverASinkThatCannotPatchIsRefusedByName) {
  // GARC_ERR_NOT_SEEKABLE, before a byte is written. The caller asked for a form
  // of archive this sink cannot produce, which is a different thing from a feature
  // this library lacks - and failing later would leave a truncated archive behind.
  BufferDrain drain;
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_callback(drain.callbacks(), &sink), GARC_OK);
  GARC_Writer_Options options;
  garc_writer_options_default(&options);
  options.zip_sizes = GARC_ZIP_SIZES_LOCAL;
  GARC_Writer * writer = nullptr;
  EXPECT_EQ(garc_writer_create(sink, GARC_FORMAT_ZIP, &options, &writer),
      GARC_ERR_NOT_SEEKABLE);
  EXPECT_EQ(writer, nullptr);
  EXPECT_TRUE(drain.bytes().empty());

  // The same options over a drain that can patch succeed, which is what says the
  // refusal is about the sink and not about the option.
  BufferDrain patchable;
  patchable.allow_patch();
  GARC_Sink * other = nullptr;
  ASSERT_EQ(garc_sink_create_callback(patchable.callbacks(), &other), GARC_OK);
  ASSERT_EQ(garc_writer_create(other, GARC_FORMAT_ZIP, &options, &writer),
      GARC_OK);
  garc_writer_destroy(writer);
  garc_sink_destroy(other);
  garc_sink_destroy(sink);
}

//-----------------------------------------------------------------------------
// Times, and the one extra field this writer emits
//-----------------------------------------------------------------------------

TEST(ZipWrite, AnExtendedTimestampIsWrittenOnlyWhenTheDosFieldCannotCarryTheTime) {
  // **The conditional is what keeps "write the minimum" true.** An archive whose
  // every mtime is an even second in range has no extra fields in it at all; one
  // with an odd second has nine bytes on that member and nothing on the others.
  // Both halves are asserted, because a writer that always emitted it would pass
  // the round trip and a writer that never did would too.
  struct Case {
    const char * name;
    int64_t mtime;
    /** What the member's time should be on the way back. */
    int64_t expected;
    /** Which field should have answered for it. */
    GARC_Time_Source source;
  };
  // **Three outcomes, not two**, which the first version of this test got wrong.
  // The DOS pair runs from 1980 to 2107 with two-second resolution; the 0x5455
  // extra holds a signed 32-bit second, so it runs from 1901 to 2038 exactly. So a
  // time can be exact in the DOS pair, rescued by the extra, or beyond both.
  const std::vector<Case> cases = {
    {"even.txt", 1000000000, 1000000000, GARC_TIME_ZIP_DOS},
    {"odd.txt", 1000000001, 1000000001, GARC_TIME_ZIP_UNIX},
    // Before 1980, which the DOS date cannot express at all.
    {"ancient.txt", 0, 0, GARC_TIME_ZIP_UNIX},
    // Negative, and the arm that would break an unsigned conversion.
    {"before-epoch.txt", -86400, -86400, GARC_TIME_ZIP_UNIX},
    // The first second the DOS field can hold, which is the boundary.
    {"dos-epoch.txt", 315532800, 315532800, GARC_TIME_ZIP_DOS},
    // One second before it.
    {"just-before.txt", 315532799, 315532799, GARC_TIME_ZIP_UNIX},
    // The last second the DOS field can express, which is *past* what the extra
    // field can - so the DOS pair is the better of the two here and no extra is
    // written.
    {"dos-max.txt", 4354819198, 4354819198, GARC_TIME_ZIP_DOS},
    // **Past both**, which is the case that found a defect: the extra field was
    // being written with the low 32 bits of the time, so 2108 came back as 1971.
    // Now neither field can hold it, the DOS clamp stands alone, and the loss is
    // visible rather than wrong.
    {"after-2107.txt", 4354819200, 4354819198, GARC_TIME_ZIP_DOS},
    // And below what the extra field can hold, where the clamp stands for the same
    // reason at the other end.
    {"before-1901.txt", -2147483649LL, 315532800, GARC_TIME_ZIP_DOS},
  };

  Built built;
  ASSERT_EQ(built.create_result(), GARC_OK);
  for (const Case & one : cases) {
    Spec spec;
    spec.name = one.name;
    spec.data = "x";
    spec.mtime = one.mtime;
    ASSERT_EQ(built.add(spec), GARC_OK) << one.name;
  }
  ASSERT_EQ(built.finish(), GARC_OK);

  Roundtrip trip(built.bytes());
  ASSERT_EQ(trip.open_result(), GARC_OK);
  ASSERT_EQ(trip.members().size(), cases.size());
  size_t exact = 0;
  size_t rescued = 0;
  for (size_t i = 0; i < cases.size(); ++i) {
    SCOPED_TRACE(cases[i].name);
    const ReadBack & seen = trip.members()[i];
    EXPECT_EQ(seen.mtime, cases[i].expected);
    EXPECT_EQ(seen.mtime_source, cases[i].source);
    if (cases[i].source == GARC_TIME_ZIP_DOS) {
      ++exact;
      EXPECT_EQ(seen.extra_length, 0u)
          << "the DOS pair answered, so no extra field should have been written";
    }
    else {
      ++rescued;
      // **The source changes, and that is the finding rather than a wart.** The
      // time survives a round trip; what does not survive is which field carried
      // it, because the DOS pair could not.
      EXPECT_EQ(seen.extra_length, 9u) << "id, length, flags, and four bytes";
    }
  }
  // Both arms reached, or the conditional is untested in one direction.
  // Both arms reached several times over, and the counts pin which cases fall
  // where - a change in the rule moves them rather than passing quietly.
  EXPECT_EQ(exact, 5u);
  EXPECT_EQ(rescued, 4u);
}

TEST(ZipWrite, AMemberWithNoTimeGetsNeitherAnExtraFieldNorAnInventedOne) {
  // zip has no way to say "no time": the DOS field is mandatory. So the member
  // gets the clamp and no extended timestamp, which is the honest answer - an
  // extra field carrying a time the caller never supplied would be worse.
  Built built;
  ASSERT_EQ(built.create_result(), GARC_OK);
  Spec spec;
  spec.name = "timeless.txt";
  spec.data = "x";
  spec.mtime = 0;
  spec.mtime_source = GARC_TIME_NONE;
  ASSERT_EQ(built.add(spec), GARC_OK);
  ASSERT_EQ(built.finish(), GARC_OK);

  Roundtrip trip(built.bytes());
  ASSERT_EQ(trip.open_result(), GARC_OK);
  ASSERT_EQ(trip.members().size(), 1u);
  EXPECT_EQ(trip.members()[0].extra_length, 0u);
  EXPECT_EQ(trip.members()[0].mtime_source, GARC_TIME_ZIP_DOS);
  EXPECT_EQ(trip.members()[0].mtime, 315532800)
      << "clamped to the earliest the DOS field can express";
}

//-----------------------------------------------------------------------------
// zip64, which is per field and per record
//-----------------------------------------------------------------------------

TEST(ZipWrite, NoZip64FieldAppearsUntilOneIsNeeded) {
  // The lower side of the threshold. The upper side is a 4 GiB member, which is
  // why GARC_Writer_Options.zip_force_zip64 exists - and the two tests together
  // are the "a test either side of it" the plan asks for.
  Built built;
  ASSERT_EQ(built.create_result(), GARC_OK);
  for (const Spec & spec : corpus()) {
    ASSERT_EQ(built.add(spec), GARC_OK);
  }
  ASSERT_EQ(built.finish(), GARC_OK);
  const std::vector<uint8_t> bytes = built.bytes();

  EXPECT_FALSE(holds(bytes, "PK\x06\x06")) << "no zip64 end record";
  EXPECT_FALSE(holds(bytes, "PK\x06\x07")) << "no zip64 locator";
  Roundtrip trip(built.bytes());
  ASSERT_EQ(trip.open_result(), GARC_OK);
  EXPECT_FALSE(garc_zip_has_zip64_end_record(trip.archive()));
  for (const ReadBack & seen : trip.members()) {
    EXPECT_FALSE(seen.used_zip64) << seen.name;
  }
  // And `version needed` says 2.0, not 4.5, which is the field an old reader
  // consults before it decides whether it can cope.
  EXPECT_EQ(le16(bytes, 4u), 20u);
}

TEST(ZipWrite, ForcedZip64MarksTheFieldsAndWritesBothEndRecords) {
  Built built(GARC_ZIP_SIZES_LOCAL, true);
  ASSERT_EQ(built.create_result(), GARC_OK);
  for (const Spec & spec : corpus()) {
    ASSERT_EQ(built.add(spec), GARC_OK);
  }
  ASSERT_EQ(built.finish(), GARC_OK);
  const std::vector<uint8_t> bytes = built.bytes();

  EXPECT_TRUE(holds(bytes, "PK\x06\x06"));
  EXPECT_TRUE(holds(bytes, "PK\x06\x07"));
  EXPECT_EQ(le16(bytes, 4u), 45u) << "version needed should say 4.5";
  // **The local header marks both sizes and the directory marks one**, which is
  // the asymmetry `zip -fz` produces and the reason the two records' extra fields
  // are different lengths. In the local header the compressed size is unknown when
  // the header is written; in the directory it is known and fits.
  EXPECT_EQ(le32(bytes, 18u), 0xFFFFFFFFu);
  EXPECT_EQ(le32(bytes, 22u), 0xFFFFFFFFu);
  EXPECT_EQ(le16(bytes, 28u), 20u) << "a 16-byte zip64 payload, plus its header";

  Roundtrip trip(built.bytes());
  ASSERT_EQ(trip.open_result(), GARC_OK);
  EXPECT_TRUE(garc_zip_has_zip64_end_record(trip.archive()));
  ASSERT_EQ(trip.members().size(), corpus().size());
  for (size_t i = 0; i < trip.members().size(); ++i) {
    SCOPED_TRACE(trip.members()[i].name);
    EXPECT_TRUE(trip.members()[i].used_zip64);
    EXPECT_EQ(trip.members()[i].read_result, GARC_OK);
    // The directory's payload is eight bytes - the uncompressed size alone -
    // against sixteen in the local header, which is the asymmetry above.
    EXPECT_EQ(trip.members()[i].extra_length, 12u);
  }
}

TEST(ZipWrite, AZip64MemberGetsASixtyFourBitDataDescriptor) {
  // **The descriptor's own layout depends on the member's zip64-ness**, and it has
  // no length field of its own - so a reader works out whether the sizes are four
  // bytes or eight from the local header's version and extra field. Getting that
  // wrong makes the *next* local header unfindable in a streamed archive, which is
  // why the two options have to be tested together rather than one at a time.
  Built built(GARC_ZIP_SIZES_DESCRIPTOR, true);
  ASSERT_EQ(built.create_result(), GARC_OK);
  for (const Spec & spec : corpus()) {
    ASSERT_EQ(built.add(spec), GARC_OK);
  }
  ASSERT_EQ(built.finish(), GARC_OK);
  const std::vector<uint8_t> bytes = built.bytes();

  // Both flags: bit 3 for the descriptor and the zip64 markers in the header.
  EXPECT_EQ(le16(bytes, 6u) & 0x0008u, 0x0008u);
  EXPECT_EQ(le32(bytes, 18u), 0xFFFFFFFFu);
  EXPECT_TRUE(holds(bytes, "PK\x07\x08"));

  // And the whole archive still reads, member for member, which is the statement
  // the layout has to satisfy.
  Roundtrip trip(built.bytes());
  ASSERT_EQ(trip.open_result(), GARC_OK);
  EXPECT_EQ(trip.walk_result(), GARC_END);
  const std::vector<Spec> specs = corpus();
  ASSERT_EQ(trip.members().size(), specs.size());
  for (size_t i = 0; i < specs.size(); ++i) {
    SCOPED_TRACE(specs[i].name);
    EXPECT_TRUE(trip.members()[i].used_zip64);
    EXPECT_EQ(trip.members()[i].read_result, GARC_OK);
    EXPECT_EQ(trip.members()[i].data,
        specs[i].type == GARC_MEMBER_SYMLINK ? specs[i].link : specs[i].data);
  }
  // 24 bytes of descriptor per member against 16, which is the difference the
  // eight-byte size fields make. Six members, so 48 bytes more than the
  // 32-bit form of the same archive.
  Built narrow(GARC_ZIP_SIZES_DESCRIPTOR, false);
  ASSERT_EQ(narrow.create_result(), GARC_OK);
  for (const Spec & spec : corpus()) {
    ASSERT_EQ(narrow.add(spec), GARC_OK);
  }
  ASSERT_EQ(narrow.finish(), GARC_OK);
  EXPECT_GT(bytes.size(), narrow.bytes().size() + 6u * 8u);
}

TEST(ZipWrite, ForcedZip64AndAnExtendedTimestampCoexist) {
  // Two extra fields in one record, which is the case an offset computed from one
  // of them gets wrong. The order is zip64 then the timestamp, and the reader has
  // to find the second after the first.
  Built built(GARC_ZIP_SIZES_LOCAL, true);
  ASSERT_EQ(built.create_result(), GARC_OK);
  Spec spec;
  spec.name = "odd.txt";
  spec.data = "odd second\n";
  spec.mtime = 1000000001;
  ASSERT_EQ(built.add(spec), GARC_OK);
  ASSERT_EQ(built.finish(), GARC_OK);

  Roundtrip trip(built.bytes());
  ASSERT_EQ(trip.open_result(), GARC_OK);
  ASSERT_EQ(trip.members().size(), 1u);
  EXPECT_TRUE(trip.members()[0].used_zip64);
  EXPECT_EQ(trip.members()[0].mtime, 1000000001);
  EXPECT_EQ(trip.members()[0].mtime_source, GARC_TIME_ZIP_UNIX);
  EXPECT_EQ(trip.members()[0].data, spec.data);
  // 12 bytes of zip64 plus 9 of timestamp, in the central record.
  EXPECT_EQ(trip.members()[0].extra_length, 21u);
}

//-----------------------------------------------------------------------------
// What the writer refuses
//-----------------------------------------------------------------------------

TEST(ZipWrite, TheRefusalsAreRefusedAndTheArchiveStaysWritable) {
  // Each refusal, and after each one the writer still works: a member whose header
  // was never written leaves no member open, so the next add must succeed. Without
  // that, one refused member would poison the archive.
  struct Case {
    const char * what;
    Spec spec;
    GARC_Result expected;
  };
  std::vector<Case> cases;
  {
    Spec spec;
    spec.name = "";
    cases.push_back({"an empty name", spec, GARC_ERR_INVALID});
  }
  {
    Spec spec;
    spec.name = std::string("nul\0inside", 10);
    cases.push_back({"a NUL in the name", spec, GARC_ERR_INVALID});
  }
  {
    Spec spec;
    spec.name = std::string(65536u, 'n');
    cases.push_back({"a name the length field cannot hold", spec,
        GARC_ERR_UNSUPPORTED});
  }
  {
    Spec spec;
    spec.name = "dir/";
    spec.type = GARC_MEMBER_DIRECTORY;
    spec.data = "x";
    cases.push_back({"a directory with a size", spec, GARC_ERR_INVALID});
  }
  {
    Spec spec;
    spec.name = "link";
    spec.type = GARC_MEMBER_SYMLINK;
    cases.push_back({"a symlink with no target", spec, GARC_ERR_INVALID});
  }
  {
    Spec spec;
    spec.name = "link";
    spec.type = GARC_MEMBER_SYMLINK;
    spec.link = std::string("bad\0target", 10);
    cases.push_back({"a NUL in a link target", spec, GARC_ERR_INVALID});
  }
  {
    // The writer supplies a symlink's data itself, so a declared size is a
    // promise the caller would not be allowed to keep - and would disagree with
    // the target's length if it were honoured.
    Spec spec;
    spec.name = "link";
    spec.type = GARC_MEMBER_SYMLINK;
    spec.link = "hello.txt";
    spec.data = "x";
    cases.push_back({"a symlink with a declared size", spec, GARC_ERR_INVALID});
  }
  {
    Spec spec;
    spec.name = "fifo";
    spec.type = GARC_MEMBER_FIFO;
    cases.push_back({"a fifo, which zip has no convention for", spec,
        GARC_ERR_UNSUPPORTED});
  }
  {
    Spec spec;
    spec.name = "dev";
    spec.type = GARC_MEMBER_CHAR_DEVICE;
    cases.push_back({"a device", spec, GARC_ERR_UNSUPPORTED});
  }
  {
    Spec spec;
    spec.name = "hard";
    spec.type = GARC_MEMBER_HARDLINK;
    spec.link = "hello.txt";
    cases.push_back({"a hard link", spec, GARC_ERR_UNSUPPORTED});
  }
  {
    Spec spec;
    spec.name = "other";
    spec.type = GARC_MEMBER_OTHER;
    cases.push_back({"GARC_MEMBER_OTHER, which is a reading and not a thing to "
                     "write", spec, GARC_ERR_UNSUPPORTED});
  }

  for (const Case & one : cases) {
    SCOPED_TRACE(one.what);
    Built built;
    ASSERT_EQ(built.create_result(), GARC_OK);
    const GARC_Member member = member_of(one.spec);
    EXPECT_EQ(garc_writer_add(built.writer(), &member), one.expected);
    EXPECT_EQ(garc_writer_member_count(built.writer()), 0u)
        << "a refused member must not be counted";

    Spec good;
    good.name = "after.txt";
    good.data = "still writable\n";
    ASSERT_EQ(built.add(good), GARC_OK) << "the archive was left unusable";
    ASSERT_EQ(built.finish(), GARC_OK);
    Roundtrip trip(built.bytes());
    ASSERT_EQ(trip.open_result(), GARC_OK);
    ASSERT_EQ(trip.members().size(), 1u);
    EXPECT_EQ(trip.members()[0].name, "after.txt");
  }
}

TEST(ZipWrite, AShortMemberIsRefusedRatherThanPadded) {
  // The same rule the tar writer has, and it matters more here: the central
  // directory would carry a size the data does not have, and the directory is what
  // a reader believes.
  Built built;
  ASSERT_EQ(built.create_result(), GARC_OK);
  Spec spec;
  spec.name = "short.txt";
  spec.data = "twenty bytes exactly";
  const GARC_Member member = member_of(spec);
  ASSERT_EQ(garc_writer_add(built.writer(), &member), GARC_OK);
  ASSERT_EQ(garc_writer_write(built.writer(), "five ", 5), GARC_OK);
  EXPECT_EQ(garc_writer_data_remaining(built.writer()), 15u);

  Spec next;
  next.name = "next.txt";
  const GARC_Member other = member_of(next);
  EXPECT_EQ(garc_writer_add(built.writer(), &other), GARC_ERR_INVALID);
  EXPECT_EQ(garc_writer_finish(built.writer()), GARC_ERR_INVALID);

  // And delivering the rest makes both work, which is what says the refusal was
  // about the shortfall and not about the member.
  ASSERT_EQ(garc_writer_write(built.writer(), "fifteen more!!!", 15), GARC_OK);
  EXPECT_EQ(garc_writer_finish(built.writer()), GARC_OK);
  Roundtrip trip(built.bytes());
  ASSERT_EQ(trip.open_result(), GARC_OK);
  ASSERT_EQ(trip.members().size(), 1u);
  EXPECT_EQ(trip.members()[0].data, "five fifteen more!!!");
  EXPECT_EQ(trip.members()[0].read_result, GARC_OK) << "the CRC should verify";
}

TEST(ZipWrite, WritingMoreThanDeclaredIsRefusedAtTheCallThatWouldDoIt) {
  Built built;
  ASSERT_EQ(built.create_result(), GARC_OK);
  Spec spec;
  spec.name = "small.txt";
  spec.data = "five!";
  const GARC_Member member = member_of(spec);
  ASSERT_EQ(garc_writer_add(built.writer(), &member), GARC_OK);
  EXPECT_EQ(garc_writer_write(built.writer(), "six!!!", 6), GARC_ERR_INVALID);
  // The bytes were not written, so the member is still exactly short.
  EXPECT_EQ(garc_writer_data_remaining(built.writer()), 5u);
  ASSERT_EQ(garc_writer_write(built.writer(), "five!", 5), GARC_OK);
  ASSERT_EQ(built.finish(), GARC_OK);
  Roundtrip trip(built.bytes());
  ASSERT_EQ(trip.open_result(), GARC_OK);
  EXPECT_EQ(trip.members()[0].data, "five!");
}

TEST(ZipWrite, AZipWriterIgnoresTheTarVariantField) {
  // A caller copying an archive from tar to zip should not have to clear a field
  // that describes the format they are no longer writing. GARC_TAR_NONE is what a
  // zeroed struct holds and is refused for a tar; here it means nothing.
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  GARC_Writer_Options options;
  std::memset(&options, 0, sizeof(options));
  GARC_Writer * writer = nullptr;
  EXPECT_EQ(garc_writer_create(sink, GARC_FORMAT_ZIP, &options, &writer),
      GARC_OK);
  // And the same zeroed struct is still refused for a tar, which is what says the
  // check was not simply deleted.
  GARC_Writer * tar_writer = nullptr;
  EXPECT_EQ(garc_writer_create(sink, GARC_FORMAT_TAR, &options, &tar_writer),
      GARC_ERR_INVALID);
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
}

TEST(ZipWrite, ASizeDisciplineFromNowhereIsRefused) {
  // GARC_ZIP_SIZES_COUNT is not a discipline, and neither is anything past it.
  // Refused at create, like GARC_TAR_NONE, so a caller who computed the value and
  // got it wrong is told rather than handed whichever branch fell through.
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  GARC_Writer_Options options;
  garc_writer_options_default(&options);
  GARC_Writer * writer = nullptr;
  options.zip_sizes = GARC_ZIP_SIZES_COUNT;
  EXPECT_EQ(garc_writer_create(sink, GARC_FORMAT_ZIP, &options, &writer),
      GARC_ERR_INVALID);
  options.zip_sizes = static_cast<GARC_Zip_Sizes>(99);
  EXPECT_EQ(garc_writer_create(sink, GARC_FORMAT_ZIP, &options, &writer),
      GARC_ERR_INVALID);
  EXPECT_EQ(writer, nullptr);
  garc_sink_destroy(sink);
}

TEST(ZipWrite, AnEmptyArchiveIsTwentyTwoBytesAndReadsAsZeroMembers) {
  // The smallest zip there is: one end record. `python-empty.zip` in the corpus is
  // the same 22 bytes from a different writer, and unzip warns about it.
  Built built;
  ASSERT_EQ(built.create_result(), GARC_OK);
  ASSERT_EQ(built.finish(), GARC_OK);
  EXPECT_EQ(built.bytes().size(), 22u);
  Roundtrip trip(built.bytes());
  ASSERT_EQ(trip.open_result(), GARC_OK);
  EXPECT_EQ(garc_zip_declared_members(trip.archive()), 0u);
  EXPECT_TRUE(trip.members().empty());
  EXPECT_EQ(trip.walk_result(), GARC_END);
}

TEST(ZipWrite, TheDumpNamesTheDisciplineAndTheDirectory) {
  Built built(GARC_ZIP_SIZES_DESCRIPTOR);
  ASSERT_EQ(built.create_result(), GARC_OK);
  Spec spec;
  spec.name = "hello.txt";
  spec.data = "hello, archive\n";
  ASSERT_EQ(built.add(spec), GARC_OK);

  char * buffer = nullptr;
  size_t length = 0;
  FILE * out = open_memstream(&buffer, &length);
  ASSERT_NE(out, nullptr);
  garc_writer_dump(built.writer(), out);
  fclose(out);
  const std::string text(buffer, length);
  free(buffer);

  EXPECT_NE(text.find("format=zip"), std::string::npos) << text;
  EXPECT_NE(text.find("sizes=data descriptor"), std::string::npos) << text;
  EXPECT_NE(text.find("method=stored"), std::string::npos) << text;
  EXPECT_NE(text.find("directory:"), std::string::npos) << text;
  EXPECT_STREQ(garc_zip_sizes_string(GARC_ZIP_SIZES_AUTO), "auto");
  EXPECT_STREQ(garc_zip_sizes_string(GARC_ZIP_SIZES_LOCAL), "local header");
  EXPECT_STREQ(garc_zip_sizes_string(GARC_ZIP_SIZES_COUNT), "unknown");
}

//-----------------------------------------------------------------------------
// Deflate
//-----------------------------------------------------------------------------

TEST(ZipWrite, DeflateShrinksACompressibleMemberAndTheBytesComeBack) {
  // The claim the round-trip sweep above cannot make, because it compares a
  // member against its Spec and a member that was stored satisfies that too: the
  // archive has to be *smaller* than the data in it. Without this, a writer that
  // set method 8 in the header and then stored the bytes would pass every
  // assertion in this file - our own reader would inflate nothing and get the
  // right answer, because a stored byte run is not a valid deflate stream and the
  // reader would refuse it... which is exactly why the size is asserted rather
  // than the reading.
  Built built(GARC_ZIP_SIZES_LOCAL, false, GARC_ZIP_METHOD_DEFLATE);
  ASSERT_EQ(built.create_result(), GARC_OK);
  Spec spec;
  spec.name = "compressible.txt";
  spec.data = std::string(4000u, 'a') + std::string(4000u, 'b');
  ASSERT_EQ(built.add(spec), GARC_OK);
  ASSERT_EQ(built.finish(), GARC_OK);

  Roundtrip trip(built.bytes());
  ASSERT_EQ(trip.open_result(), GARC_OK);
  ASSERT_EQ(trip.members().size(), 1u);
  const ReadBack & seen = trip.members()[0];
  EXPECT_EQ(seen.method, GARC_ZIP_METHOD_DEFLATE);
  EXPECT_EQ(seen.data, spec.data);
  EXPECT_EQ(seen.size, spec.data.size());
  EXPECT_LT(seen.compressed_size, seen.size);
  // And the whole archive is smaller than the member's data, which no amount of
  // header arithmetic can fake.
  EXPECT_LT(built.bytes().size(), spec.data.size());
}

TEST(ZipWrite, DataThatDoesNotCompressStillComesBackByteForByte) {
  // The other end of the same path, and the one that exercises the drain loop:
  // 64 KiB of bytes with no structure produce more than one buffer's worth of
  // output from a single garc_writer_write(), so the encoder has to be emptied
  // more than once for one call. A loop that assumed one pass would truncate the
  // member, and the CRC is what would catch it.
  Built built(GARC_ZIP_SIZES_DESCRIPTOR, false, GARC_ZIP_METHOD_DEFLATE);
  ASSERT_EQ(built.create_result(), GARC_OK);
  Spec spec;
  spec.name = "noise.bin";
  spec.data = incompressible(65536u);
  ASSERT_EQ(built.add(spec), GARC_OK);
  ASSERT_EQ(built.finish(), GARC_OK);

  Roundtrip trip(built.bytes());
  ASSERT_EQ(trip.open_result(), GARC_OK);
  ASSERT_EQ(trip.members().size(), 1u);
  const ReadBack & seen = trip.members()[0];
  EXPECT_EQ(seen.method, GARC_ZIP_METHOD_DEFLATE);
  EXPECT_EQ(seen.read_result, GARC_OK) << "the CRC is the verdict on the bytes";
  EXPECT_EQ(seen.data, spec.data);
  // Larger than it went in, which is deflate's stored-block overhead and is the
  // case writer.h says this writer does not fall back from. Asserted rather than
  // tolerated, because it is the reason garc_zip_deflate_bound() exists.
  EXPECT_GT(seen.compressed_size, seen.size);
  EXPECT_LE(seen.compressed_size, garc_zip_deflate_bound(seen.size));
}

TEST(ZipWrite, ADeflatedMemberWrittenInPiecesIsOneStream) {
  // A caller writes a member in whatever sized pieces it has, and every piece
  // goes into one deflate stream rather than one per call. A writer that finished
  // the stream per write would produce a member every reader refuses after the
  // first block, and a writer that reset the encoder per write would produce
  // plausible bytes that decode to the wrong thing.
  Built built(GARC_ZIP_SIZES_LOCAL, false, GARC_ZIP_METHOD_DEFLATE);
  ASSERT_EQ(built.create_result(), GARC_OK);
  const std::string whole = std::string(500u, 'x') + incompressible(500u)
      + std::string(500u, 'y');
  Spec spec;
  spec.name = "pieces.bin";
  spec.data = whole;
  const GARC_Member member = member_of(spec);
  ASSERT_EQ(garc_writer_add(built.writer(), &member), GARC_OK);
  // Deliberately uneven, including a zero-length write, which a caller reading
  // from a socket will make sooner or later.
  const size_t cuts[] = {1u, 0u, 13u, 486u, 1000u};
  size_t at = 0;
  for (size_t take : cuts) {
    ASSERT_EQ(garc_writer_write(built.writer(), whole.data() + at, take),
        GARC_OK);
    at += take;
  }
  ASSERT_EQ(at, whole.size());
  ASSERT_EQ(built.finish(), GARC_OK);

  Roundtrip trip(built.bytes());
  ASSERT_EQ(trip.open_result(), GARC_OK);
  ASSERT_EQ(trip.members().size(), 1u);
  EXPECT_EQ(trip.members()[0].data, whole);
  EXPECT_EQ(trip.members()[0].read_result, GARC_OK);
}

TEST(ZipWrite, TwoDeflatedMembersAreTwoIndependentStreams) {
  // One encoder, reset between members - which is what makes this worth a test of
  // its own. An encoder carried over would leave the second member's stream
  // continuing the first's, and the second member would decode to nothing or to
  // rubbish depending on where the window happened to point.
  Built built(GARC_ZIP_SIZES_LOCAL, false, GARC_ZIP_METHOD_DEFLATE);
  ASSERT_EQ(built.create_result(), GARC_OK);
  Spec first;
  first.name = "first.txt";
  first.data = std::string(3000u, 'p');
  Spec second;
  second.name = "second.txt";
  // The same bytes, so a member that borrowed the first one's window would come
  // out *shorter* than the first - which is the shape of the bug, and is what the
  // size comparison below refuses.
  second.data = first.data;
  ASSERT_EQ(built.add(first), GARC_OK);
  ASSERT_EQ(built.add(second), GARC_OK);
  ASSERT_EQ(built.finish(), GARC_OK);

  Roundtrip trip(built.bytes());
  ASSERT_EQ(trip.open_result(), GARC_OK);
  ASSERT_EQ(trip.members().size(), 2u);
  EXPECT_EQ(trip.members()[0].data, first.data);
  EXPECT_EQ(trip.members()[1].data, second.data);
  EXPECT_EQ(trip.members()[0].crc, trip.members()[1].crc);
  EXPECT_EQ(trip.members()[0].compressed_size,
      trip.members()[1].compressed_size)
      << "the same bytes twice must compress to the same size twice";
}

TEST(ZipWrite, DeflateAndStoredAreDifferentBytesAndTheSameArchive) {
  // The option has to reach the bytes. Both archives hold the same member with
  // the same name, time, mode and CRC, and differ in their method, their
  // compressed size, and their length.
  std::vector<std::vector<uint8_t>> written;
  std::vector<uint32_t> crcs;
  for (const auto & method : methods()) {
    Built built(GARC_ZIP_SIZES_LOCAL, false, method.second);
    ASSERT_EQ(built.create_result(), GARC_OK);
    Spec spec;
    spec.name = "same.txt";
    spec.data = std::string(2048u, 'z');
    ASSERT_EQ(built.add(spec), GARC_OK);
    ASSERT_EQ(built.finish(), GARC_OK);
    written.push_back(built.bytes());
    Roundtrip trip(built.bytes());
    ASSERT_EQ(trip.open_result(), GARC_OK);
    ASSERT_EQ(trip.members().size(), 1u);
    EXPECT_EQ(trip.members()[0].method, method.second);
    EXPECT_EQ(trip.members()[0].data, spec.data);
    crcs.push_back(trip.members()[0].crc);
  }
  EXPECT_NE(written[0], written[1]);
  EXPECT_LT(written[1].size(), written[0].size());
  // **The CRC is of the uncompressed bytes in both**, which is the one field a
  // writer that checksummed its own output would get wrong - and every reader
  // would then reject the deflated member while accepting the stored one.
  EXPECT_EQ(crcs[0], crcs[1]);
}

TEST(ZipWrite, AMemberWithNoDataIsStoredHoweverTheOptionReads) {
  // Stated on its own as well as inside the sweep, because it is a rule this
  // writer applies over the caller's choice and the sweep would still pass if it
  // were dropped for one type.
  Built built(GARC_ZIP_SIZES_LOCAL, false, GARC_ZIP_METHOD_DEFLATE);
  ASSERT_EQ(built.create_result(), GARC_OK);
  Spec empty;
  empty.name = "empty";
  Spec directory;
  directory.name = "dir/";
  directory.type = GARC_MEMBER_DIRECTORY;
  Spec file;
  file.name = "full.txt";
  file.data = "something\n";
  ASSERT_EQ(built.add(empty), GARC_OK);
  ASSERT_EQ(built.add(directory), GARC_OK);
  ASSERT_EQ(built.add(file), GARC_OK);
  ASSERT_EQ(built.finish(), GARC_OK);

  Roundtrip trip(built.bytes());
  ASSERT_EQ(trip.open_result(), GARC_OK);
  ASSERT_EQ(trip.members().size(), 3u);
  EXPECT_EQ(trip.members()[0].method, GARC_ZIP_METHOD_STORED);
  EXPECT_EQ(trip.members()[0].compressed_size, 0u);
  EXPECT_EQ(trip.members()[1].method, GARC_ZIP_METHOD_STORED);
  EXPECT_EQ(trip.members()[1].compressed_size, 0u);
  EXPECT_EQ(trip.members()[2].method, GARC_ZIP_METHOD_DEFLATE);
}

TEST(ZipWrite, ASymlinkTargetIsStoredEvenWhenEverythingElseIsDeflated) {
  // **A finding this test is the record of.** The first version of this writer
  // deflated a symlink's target along with everything else - consistently, since a
  // zip symlink's target *is* its data - and the target then came back empty from
  // this library's own reader, which reads one eagerly only when it is stored.
  // That limit is deliberate and argued where it is written; what was wrong was
  // the writer producing an archive that ran into it.
  //
  // Checking the corpus settled which side to fix: every symlink in it is stored,
  // including the ones Info-ZIP wrote and the ones in the malicious fixtures. A
  // target is a path, so deflate rarely helps and every reader wants to read it.
  Built built(GARC_ZIP_SIZES_LOCAL, false, GARC_ZIP_METHOD_DEFLATE);
  ASSERT_EQ(built.create_result(), GARC_OK);
  Spec link;
  link.name = "link";
  link.type = GARC_MEMBER_SYMLINK;
  // Long and repetitive, so deflate would unambiguously have shrunk it: a writer
  // that stored it only because the target was too short to compress would pass a
  // weaker version of this test.
  link.link = std::string(200u, 'd') + "/target";
  link.mode = 0777;
  Spec file;
  file.name = "beside.txt";
  file.data = std::string(2000u, 'e');
  ASSERT_EQ(built.add(link), GARC_OK);
  ASSERT_EQ(built.add(file), GARC_OK);
  ASSERT_EQ(built.finish(), GARC_OK);

  Roundtrip trip(built.bytes());
  ASSERT_EQ(trip.open_result(), GARC_OK);
  ASSERT_EQ(trip.members().size(), 2u);
  const ReadBack & seen = trip.members()[0];
  EXPECT_EQ(seen.type, GARC_MEMBER_SYMLINK);
  EXPECT_EQ(seen.method, GARC_ZIP_METHOD_STORED);
  EXPECT_EQ(seen.link, link.link) << "a stored target is read eagerly";
  EXPECT_EQ(seen.data, link.link);
  EXPECT_EQ(seen.compressed_size, seen.size);
  // And the member beside it is deflated, so this is the symlink's rule rather
  // than the option failing to arrive.
  EXPECT_EQ(trip.members()[1].method, GARC_ZIP_METHOD_DEFLATE);
  EXPECT_LT(trip.members()[1].compressed_size, trip.members()[1].size);
}

TEST(ZipWrite, ADeflatedMemberFillsTheSizeFieldsOfEveryDiscipline) {
  // The bytes, not the reading: a descriptor's compressed size and a patched
  // header's have to be the *compressed* number, and this library's reader
  // consults neither - it reads the central directory. So a writer that put the
  // uncompressed size in the local header would pass every round trip here and
  // fail on the first reader that streams, which is what check-zip-writer is for
  // and what this test is the in-process half of.
  for (const auto & discipline : disciplines()) {
    SCOPED_TRACE(discipline.first);
    Built built(discipline.second, false, GARC_ZIP_METHOD_DEFLATE);
    ASSERT_EQ(built.create_result(), GARC_OK);
    Spec spec;
    spec.name = "a.txt";
    spec.data = std::string(3000u, 'k');
    ASSERT_EQ(built.add(spec), GARC_OK);
    ASSERT_EQ(built.finish(), GARC_OK);
    const std::vector<uint8_t> bytes = built.bytes();

    Roundtrip trip(bytes);
    ASSERT_EQ(trip.open_result(), GARC_OK);
    ASSERT_EQ(trip.members().size(), 1u);
    const uint64_t compressed = trip.members()[0].compressed_size;
    ASSERT_LT(compressed, spec.data.size());

    const uint16_t flags = le16(bytes, 6u);
    if (flags & 0x0008u) {
      // The descriptor sits immediately after the data, which starts after the
      // header and the name.
      const size_t data_at = 30u + spec.name.size();
      ASSERT_EQ(std::memcmp(bytes.data() + data_at + compressed, "PK\x07\x08", 4),
          0);
      EXPECT_EQ(le32(bytes, data_at + (size_t)compressed + 8u),
          (uint32_t)compressed);
      EXPECT_EQ(le32(bytes, data_at + (size_t)compressed + 12u),
          (uint32_t)spec.data.size());
      // And the header itself says nothing.
      EXPECT_EQ(le32(bytes, 18u), 0u);
    }
    else {
      EXPECT_EQ(le32(bytes, 18u), (uint32_t)compressed);
      EXPECT_EQ(le32(bytes, 22u), (uint32_t)spec.data.size());
    }
  }
}

TEST(ZipWrite, TheDeflateBoundBoundsWhatDeflateActuallyProduces) {
  // **The instrument that caught the first version of this function.** It spelled
  // RFC 1951's own worst case - five bytes of stored-block header per 65535 bytes -
  // and compress's encoder reserves rather more, so the constant was below the
  // implementation's real bound for every size over 65534. The library now asks
  // compress, which makes the comparison against `gcomp_encode_bound()` a
  // tautology; what is worth asserting instead is that the bound bounds the thing
  // it is named after, measured by compressing bytes chosen to defeat deflate.
  const size_t sizes[] = {1u, 2u, 1000u, 65534u, 65535u, 65536u, 65537u,
      131071u, 200000u};
  for (size_t size : sizes) {
    SCOPED_TRACE(size);
    const uint64_t bound = garc_zip_deflate_bound((uint64_t)size);
    EXPECT_GE(bound, (uint64_t)size) << "a bound below the input is no bound";

    // What the writer actually produces for the worst input there is, read back
    // out of the archive it wrote.
    Built built(GARC_ZIP_SIZES_LOCAL, false, GARC_ZIP_METHOD_DEFLATE);
    ASSERT_EQ(built.create_result(), GARC_OK);
    Spec spec;
    spec.name = "noise.bin";
    spec.data = incompressible(size);
    ASSERT_EQ(built.add(spec), GARC_OK);
    ASSERT_EQ(built.finish(), GARC_OK);
    Roundtrip trip(built.bytes());
    ASSERT_EQ(trip.open_result(), GARC_OK);
    ASSERT_EQ(trip.members().size(), 1u);
    EXPECT_LE(trip.members()[0].compressed_size, bound);
    EXPECT_EQ(trip.members()[0].data, spec.data);
  }
  // Monotonic, and saturating rather than wrapping at the top: the writer compares
  // the answer against 4 GiB, and a wrapped one would compare below it. UINT64_MAX
  // is a size no member has and a caller can still declare, which is what makes
  // the saturating arm reachable from here at all.
  EXPECT_GT(garc_zip_deflate_bound(1u << 20), garc_zip_deflate_bound(1u << 19));
  EXPECT_EQ(garc_zip_deflate_bound(UINT64_MAX), UINT64_MAX);
}

TEST(ZipWrite, ADeflatedMemberNearTheThresholdGetsZip64WithoutBeingAskedTo) {
  // The consequence of deciding zip64 on the bound rather than on the declared
  // size, stated where it can be read: the threshold moves down by deflate's
  // overhead. Asserted through the bound rather than by writing a 4 GiB member,
  // which is the only part of this that a test can afford - and the arithmetic is
  // the whole of the rule.
  const uint64_t marker = 0xFFFFFFFFu;
  // A member this big fits a 32-bit compressed-size field when stored and cannot
  // be promised to when deflated.
  const uint64_t near = marker - 16u;
  EXPECT_LT(near, marker);
  EXPECT_GE(garc_zip_deflate_bound(near), marker)
      << "the bound is what moves the threshold, so it must cross it first";
  // And well below it nothing moves, which is what keeps every ordinary member out
  // of zip64. 256 MiB is two orders of magnitude inside the bound's slack.
  EXPECT_LT(garc_zip_deflate_bound(1u << 28), marker);
}

TEST(ZipWrite, AMethodBesideStoredAndDeflateIsRefusedAtCreate) {
  // Including the ones this library can read. Refused at create rather than at the
  // first member, so that a caller who asked for zstd members is told before any
  // bytes exist - and with GARC_ERR_UNSUPPORTED rather than GARC_ERR_INVALID,
  // because the value is a real zip method and the answer is that this writer does
  // not produce it.
  const GARC_Zip_Method refused[] = {GARC_ZIP_METHOD_ZSTD,
      GARC_ZIP_METHOD_DEFLATE64, GARC_ZIP_METHOD_BZIP2, GARC_ZIP_METHOD_LZMA,
      GARC_ZIP_METHOD_XZ, GARC_ZIP_METHOD_AES, GARC_ZIP_METHOD_IMPLODED};
  for (GARC_Zip_Method method : refused) {
    SCOPED_TRACE(garc_zip_method_string((uint16_t)method));
    GARC_Sink * sink = nullptr;
    ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
    GARC_Writer_Options options;
    garc_writer_options_default(&options);
    options.zip_method = method;
    GARC_Writer * writer = nullptr;
    EXPECT_EQ(garc_writer_create(sink, GARC_FORMAT_ZIP, &options, &writer),
        GARC_ERR_UNSUPPORTED);
    EXPECT_EQ(writer, nullptr);
    garc_sink_destroy(sink);
  }
  // And a tar writer is not asked about it, the same way it is not asked about the
  // sizes: a caller copying an archive from zip to tar should not have to clear a
  // field that describes the format they have left.
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  GARC_Writer_Options options;
  garc_writer_options_default(&options);
  options.zip_method = GARC_ZIP_METHOD_ZSTD;
  GARC_Writer * writer = nullptr;
  EXPECT_EQ(garc_writer_create(sink, GARC_FORMAT_TAR, &options, &writer),
      GARC_OK);
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
}

TEST(ZipWrite, TheDefaultMethodIsStoredAndIsAlsoTheZeroValue) {
  // Both halves, because the second is why the first is what it is:
  // GARC_Writer_Options is written so that a zero-filled struct behaves like the
  // defaults or is refused outright, and a default of deflate would make this the
  // one field where memset and NULL disagree.
  GARC_Writer_Options options;
  std::memset(&options, 0xFF, sizeof(options));
  garc_writer_options_default(&options);
  EXPECT_EQ(options.zip_method, GARC_ZIP_METHOD_STORED);
  EXPECT_EQ((int)GARC_ZIP_METHOD_STORED, 0);
  EXPECT_STREQ(garc_zip_method_string(GARC_ZIP_METHOD_DEFLATE), "deflate");
}

//-----------------------------------------------------------------------------
// Failure, at every stage
//-----------------------------------------------------------------------------

TEST(ZipWrite, AWriteFailureAtEveryStageIsReportedAndNothingIsClaimed) {
  // A sweep over which write fails. A zip member is a header, a name, an extra
  // field, the data, a descriptor, and later a directory entry and an end record -
  // separate calls, separate arms. What is asserted is that the failure arrives as
  // a status and that the member count never counts a member whose header failed.
  // **Two option sets, because forced zip64 writes records the default never
  // does**: an extra field per local header, a zip64 end record and a locator. A
  // sweep over the default options alone runs every iteration without touching
  // four of the writer's calls to the sink, and reports clean - which is the
  // failure this library's own shapes() comment is about, met again from the
  // writing side.
  size_t failures = 0;
  for (int forced = 0; forced < 2; ++forced) {
  for (const auto & method : methods()) {
  SCOPED_TRACE(forced ? "forced zip64" : "default");
  SCOPED_TRACE(method.first);
  // Far enough to reach the end of the archive: six members at three or four
  // writes each, then the directory, the two zip64 records and the end record. A
  // bound that stopped inside the members would leave those four writes in the
  // population and never reach them.
  for (size_t stage = 0; stage < 32u; ++stage) {
    SCOPED_TRACE(stage);
    BufferDrain drain;
    drain.fail_write_at(stage);
    GARC_Sink * sink = nullptr;
    ASSERT_EQ(garc_sink_create_callback(drain.callbacks(), &sink), GARC_OK);
    GARC_Writer_Options options;
    garc_writer_options_default(&options);
    options.zip_force_zip64 = forced;
    // **And the method, because deflate has writes stored does not.** The final
    // block of a member's deflate stream goes out from garc_zip_write_close_member()
    // rather than from the caller's write, so a sweep over stored alone never puts
    // that call in a position to fail.
    options.zip_method = method.second;
    GARC_Writer * writer = nullptr;
    ASSERT_EQ(garc_writer_create(sink, GARC_FORMAT_ZIP, &options, &writer),
        GARC_OK);

    GARC_Result last = GARC_OK;
    for (const Spec & spec : corpus()) {
      const GARC_Member member = member_of(spec);
      last = garc_writer_add(writer, &member);
      if (last != GARC_OK) {
        break;
      }
      if (spec.type == GARC_MEMBER_FILE && !spec.data.empty()) {
        last = garc_writer_write(writer, spec.data.data(), spec.data.size());
        if (last != GARC_OK) {
          break;
        }
      }
    }
    if (last == GARC_OK) {
      last = garc_writer_finish(writer);
    }
    if (last != GARC_OK) {
      EXPECT_EQ(last, GARC_ERR_IO) << garc_result_string(last);
      ++failures;
    }
    garc_writer_destroy(writer);
    garc_sink_destroy(sink);
  }
  }
  }
  // The sweep has to break something, or it is a hundred passes through a working
  // writer.
  EXPECT_GE(failures, 100u);
}

TEST(ZipWrite, ASinkFailureDuringADeflatedMemberIsReported) {
  // **The arm the sweep above cannot reach, and why it cannot.** A deflated member
  // of a few hundred bytes produces no output at all until its stream is finished -
  // the encoder is still holding everything - so every write the caller makes
  // succeeds without touching the sink, and the sweep's failing stage lands on the
  // next member's header instead. The failure inside garc_writer_write() needs a
  // member big enough and awkward enough that the encoder has to flush mid-call,
  // which is 64 KiB of bytes with no structure in them.
  size_t failures = 0;
  for (size_t stage = 0; stage < 12u; ++stage) {
    SCOPED_TRACE(stage);
    BufferDrain drain;
    drain.fail_write_at(stage);
    GARC_Sink * sink = nullptr;
    ASSERT_EQ(garc_sink_create_callback(drain.callbacks(), &sink), GARC_OK);
    GARC_Writer_Options options;
    garc_writer_options_default(&options);
    options.zip_method = GARC_ZIP_METHOD_DEFLATE;
    GARC_Writer * writer = nullptr;
    ASSERT_EQ(garc_writer_create(sink, GARC_FORMAT_ZIP, &options, &writer),
        GARC_OK);

    Spec spec;
    spec.name = "noise.bin";
    spec.data = incompressible(65536u);
    const GARC_Member member = member_of(spec);
    GARC_Result last = garc_writer_add(writer, &member);
    if (last == GARC_OK) {
      last = garc_writer_write(writer, spec.data.data(), spec.data.size());
    }
    if (last == GARC_OK) {
      last = garc_writer_finish(writer);
    }
    if (last != GARC_OK) {
      EXPECT_EQ(last, GARC_ERR_IO) << garc_result_string(last);
      ++failures;
    }
    garc_writer_destroy(writer);
    garc_sink_destroy(sink);
  }
  // Header, name, then seven buffers of compressed output, then the descriptor or
  // the directory: every stage in this range is a write that happens.
  EXPECT_EQ(failures, 12u);
}

TEST(ZipWrite, APatchFailureIsReportedRatherThanLeavingAWrongHeader) {
  // The arm only the patching discipline has. A local header left saying zero
  // where the directory says fifteen is still readable by this library - it
  // deliberately does not consult those fields - so a swallowed failure here would
  // be invisible to every other test in this file.
  BufferDrain drain;
  drain.allow_patch();
  drain.fail_patches(1);
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_callback(drain.callbacks(), &sink), GARC_OK);
  GARC_Writer_Options options;
  garc_writer_options_default(&options);
  options.zip_sizes = GARC_ZIP_SIZES_LOCAL;
  GARC_Writer * writer = nullptr;
  ASSERT_EQ(garc_writer_create(sink, GARC_FORMAT_ZIP, &options, &writer),
      GARC_OK);

  Spec spec;
  spec.name = "hello.txt";
  spec.data = "hello, archive\n";
  const GARC_Member member = member_of(spec);
  ASSERT_EQ(garc_writer_add(writer, &member), GARC_OK);
  ASSERT_EQ(garc_writer_write(writer, spec.data.data(), spec.data.size()),
      GARC_OK);
  // The patch happens when the member closes, which is at finish here.
  EXPECT_EQ(garc_writer_finish(writer), GARC_ERR_IO);
  EXPECT_EQ(drain.patches(), 1u);
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
}

TEST(ZipWrite, AnAllocationFailureAtEveryBudgetIsAStatus) {
  // The central directory grows once per member and the name buffer once per
  // member that has a longer name than the last, so a zip writer allocates where
  // a tar writer does not. Every budget, because which allocation is the first to
  // fail is what decides whether the failure lands in add, in finish, or nowhere.
  for (int forced = 0; forced < 2; ++forced) {
  for (const auto & method : methods()) {
  SCOPED_TRACE(forced ? "forced zip64" : "default");
  SCOPED_TRACE(method.first);
  // Wide enough to reach the per-member extra-field append, which only happens
  // when a member has an extra field at all - so the forced pass is what puts that
  // allocation in the population.
  for (size_t budget = 0; budget < 20u; ++budget) {
    SCOPED_TRACE(budget);
    FailingAllocator allocator(budget);
    GARC_Sink * sink = nullptr;
    // The sink gets the default allocator: with the failing one it would be the
    // first request refused and every budget would measure the sink's constructor.
    ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
    GARC_Writer_Options options;
    garc_writer_options_default(&options);
    options.zip_force_zip64 = forced;
    // The deflate pass is what puts the encoder's output buffer in the population:
    // one allocation per archive, made on the first member that needs a codec.
    options.zip_method = method.second;
    GARC_Writer * writer = nullptr;
    const GARC_Result created = garc_writer_create_with_allocator(
        sink, GARC_FORMAT_ZIP, &options, allocator.get(), &writer);
    if (created != GARC_OK) {
      EXPECT_EQ(created, GARC_ERR_OOM);
      garc_sink_destroy(sink);
      continue;
    }

    GARC_Result last = GARC_OK;
    for (const Spec & spec : corpus()) {
      const GARC_Member member = member_of(spec);
      last = garc_writer_add(writer, &member);
      if (last != GARC_OK) {
        break;
      }
      if (spec.type == GARC_MEMBER_FILE && !spec.data.empty()) {
        last = garc_writer_write(writer, spec.data.data(), spec.data.size());
        if (last != GARC_OK) {
          break;
        }
      }
    }
    if (last == GARC_OK) {
      last = garc_writer_finish(writer);
    }
    if (last != GARC_OK) {
      EXPECT_EQ(last, GARC_ERR_OOM) << garc_result_string(last);
    }
    allocator.stop_failing();
    garc_writer_destroy(writer);
    garc_sink_destroy(sink);
    EXPECT_EQ(allocator.live(), 0u) << "destroy left a block behind";
  }
  }
  }
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
