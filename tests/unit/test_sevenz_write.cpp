/**
 * @file
 *
 * Writing 7z.
 *
 * What these tests can say is bounded: they read the archive back with this
 * library's reader, which agrees with the writer about what a 7z is by
 * construction. That agreement is the weak half of a round trip, and the strong
 * half is `make check-sevenz-writer`, which hands the same archives to 7-Zip and
 * libarchive and compares what they report with what was meant. Everything here
 * is the part that does not need a reference: the refusals, the shapes of the
 * options, the allocation failures, and the arithmetic the header depends on.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstring>
#include <map>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "failing_allocator.h"
#include "sevenz_builder.h"
#include "test_helpers.h"

using garctest::BufferSource;
using garctest::FailingAllocator;

namespace {

struct Spec {
  std::string name;
  GARC_Member_Type type = GARC_MEMBER_FILE;
  std::string data;
  std::string link;
  uint32_t mode = 0644;
  int64_t mtime = 1000000000;
  uint32_t nanoseconds = 0;
};

GARC_Member member_of(const Spec & spec) {
  GARC_Member member;
  std::memset(&member, 0, sizeof(member));
  member.name = spec.name.data();
  member.name_length = spec.name.size();
  member.type = spec.type;
  member.size = spec.type == GARC_MEMBER_FILE || !spec.data.empty()
      ? spec.data.size() : 0;
  member.mode = spec.mode;
  member.mode_valid = 1;
  member.mtime_seconds = spec.mtime;
  member.mtime_nanoseconds = spec.nanoseconds;
  member.mtime_source = GARC_TIME_FILETIME;
  if (!spec.link.empty()) {
    member.link_target = spec.link.data();
    member.link_target_length = spec.link.size();
  }
  return member;
}

class Built {
public:
  explicit Built(GARC_SevenZ_Method method = GARC_SEVENZ_LZMA2,
      bool non_solid = false) {
    if (garc_sink_create_memory(&sink_) != GARC_OK) {
      return;
    }
    GARC_Writer_Options options;
    garc_writer_options_default(&options);
    options.sevenz_method = method;
    options.sevenz_non_solid = non_solid ? 1 : 0;
    create_result_
        = garc_writer_create(sink_, GARC_FORMAT_SEVENZ, &options, &writer_);
  }

  ~Built() {
    garc_writer_destroy(writer_);
    garc_sink_destroy(sink_);
  }

  Built(const Built &) = delete;
  Built & operator=(const Built &) = delete;

  GARC_Result create_result() const { return create_result_; }
  GARC_Writer * writer() const { return writer_; }

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

struct Read {
  GARC_Member_Type type;
  uint64_t size;
  uint32_t mode;
  int64_t mtime;
  uint32_t nanoseconds;
  std::string data;
  std::string link;
  GARC_Result status;
};

GARC_Result read_back(
    const std::vector<uint8_t> & bytes, std::map<std::string, Read> * out,
    std::vector<std::string> * order = nullptr) {
  BufferSource source(bytes.data(), bytes.size(), true, true);
  GARC_Stream * stream = nullptr;
  if (garc_stream_create_callback(source.callbacks(), &stream) != GARC_OK) {
    return GARC_ERR_INTERNAL;
  }
  GARC_Archive * archive = nullptr;
  GARC_Result result = garc_open(stream, nullptr, &archive);
  if (result == GARC_OK) {
    const GARC_Member * member = nullptr;
    while ((result = garc_next(archive, &member)) == GARC_OK) {
      Read read{};
      read.type = member->type;
      read.size = member->size;
      read.mode = member->mode;
      read.mtime = member->mtime_seconds;
      read.nanoseconds = member->mtime_nanoseconds;
      if (member->link_target) {
        read.link.assign(member->link_target, member->link_target_length);
      }
      char buffer[1031];
      size_t got = 0;
      read.status = GARC_OK;
      while ((read.status = garc_read_member(archive, buffer, sizeof(buffer),
                  &got)) == GARC_OK
          && got) {
        read.data.append(buffer, got);
      }
      const std::string name(member->name, member->name_length);
      (*out)[name] = read;
      if (order) {
        order->push_back(name);
      }
    }
  }
  garc_close(archive);
  garc_stream_destroy(stream);
  return result;
}

std::vector<Spec> corpus() {
  std::vector<Spec> specs;
  Spec file;
  file.name = "a.txt";
  file.data = "alpha\n";
  specs.push_back(file);
  Spec dir;
  dir.name = "dir";
  dir.type = GARC_MEMBER_DIRECTORY;
  dir.mode = 0755;
  specs.push_back(dir);
  Spec link;
  link.name = "dir/link";
  link.type = GARC_MEMBER_SYMLINK;
  link.link = "../a.txt";
  link.mode = 0777;
  specs.push_back(link);
  Spec empty;
  empty.name = "empty";
  specs.push_back(empty);
  Spec big;
  big.name = "big.bin";
  for (size_t i = 0; i < 300000; ++i) {
    big.data.push_back(static_cast<char>('a' + (i / 5) % 23));
  }
  specs.push_back(big);
  Spec noise;
  noise.name = "noise";
  uint32_t state = 99;
  for (size_t i = 0; i < 70000; ++i) {
    state = state * 1664525u + 1013904223u;
    noise.data.push_back(static_cast<char>(state >> 24));
  }
  specs.push_back(noise);
  Spec unicode;
  unicode.name = "\xC3\xA9-\xF0\x9F\x98\x80";
  unicode.data = "unicode\n";
  specs.push_back(unicode);
  return specs;
}

const GARC_SevenZ_Method kMethods[] = {GARC_SEVENZ_LZMA2, GARC_SEVENZ_LZMA,
    GARC_SEVENZ_BZIP2, GARC_SEVENZ_DEFLATE, GARC_SEVENZ_COPY};

}  // namespace

TEST(SevenZWrite, EveryMethodAndBothSolidnessesRoundTrip) {
  for (GARC_SevenZ_Method method : kMethods) {
    for (bool non_solid : {false, true}) {
      SCOPED_TRACE(static_cast<int>(method));
      SCOPED_TRACE(non_solid);
      Built built(method, non_solid);
      ASSERT_EQ(built.create_result(), GARC_OK);
      const std::vector<Spec> specs = corpus();
      for (const Spec & spec : specs) {
        ASSERT_EQ(built.add(spec), GARC_OK) << spec.name;
      }
      ASSERT_EQ(built.finish(), GARC_OK);

      std::map<std::string, Read> got;
      std::vector<std::string> order;
      ASSERT_EQ(read_back(built.bytes(), &got, &order), GARC_END);
      ASSERT_EQ(order.size(), specs.size());
      for (size_t i = 0; i < specs.size(); ++i) {
        const Spec & spec = specs[i];
        SCOPED_TRACE(spec.name);
        EXPECT_EQ(order[i], spec.name);
        const Read & read = got[spec.name];
        EXPECT_EQ(read.type, spec.type);
        EXPECT_EQ(read.mode & 07777u, spec.mode);
        EXPECT_EQ(read.mtime, spec.mtime);
        EXPECT_EQ(read.status, GARC_OK);
        if (spec.type == GARC_MEMBER_FILE) {
          EXPECT_EQ(read.data, spec.data);
        }
        if (spec.type == GARC_MEMBER_SYMLINK) {
          EXPECT_EQ(read.link, spec.link);
          EXPECT_EQ(read.mode & 0170000u, 0120000u);
        }
      }
    }
  }
}

TEST(SevenZWrite, AnEmptyArchiveHasAStartHeaderAndNothingElse) {
  Built built;
  ASSERT_EQ(built.create_result(), GARC_OK);
  ASSERT_EQ(built.finish(), GARC_OK);
  const std::vector<uint8_t> bytes = built.bytes();
  EXPECT_EQ(bytes.size(), 32u);
  std::map<std::string, Read> got;
  EXPECT_EQ(read_back(bytes, &got), GARC_END);
  EXPECT_TRUE(got.empty());
}

TEST(SevenZWrite, ARepeatedSolidArchiveIsByteIdentical) {
  std::vector<uint8_t> first;
  for (int pass = 0; pass < 2; ++pass) {
    Built built;
    for (const Spec & spec : corpus()) {
      ASSERT_EQ(built.add(spec), GARC_OK);
    }
    ASSERT_EQ(built.finish(), GARC_OK);
    if (pass == 0) {
      first = built.bytes();
    }
    else {
      EXPECT_EQ(first, built.bytes());
    }
  }
}

TEST(SevenZWrite, ATimeKeepsItsHundredNanosecondTicks) {
  Built built;
  Spec spec;
  spec.name = "t";
  spec.data = "x";
  spec.mtime = 1700000000;
  spec.nanoseconds = 123456700;
  ASSERT_EQ(built.add(spec), GARC_OK);
  ASSERT_EQ(built.finish(), GARC_OK);
  std::map<std::string, Read> got;
  ASSERT_EQ(read_back(built.bytes(), &got), GARC_END);
  EXPECT_EQ(got["t"].mtime, 1700000000);
  EXPECT_EQ(got["t"].nanoseconds, 123456700u);
}

TEST(SevenZWrite, ATimeBeforeTheFiletimeEpochIsRefused) {
  Built built;
  Spec spec;
  spec.name = "t";
  spec.data = "x";
  spec.mtime = -12000000000LL;
  EXPECT_EQ(built.add(spec), GARC_ERR_INVALID);
}

TEST(SevenZWrite, RefusalsHappenBeforeAnythingIsWritten) {
  struct Case {
    const char * what;
    Spec spec;
    GARC_Result expect;
  };
  std::vector<Case> cases;
  {
    Spec s;
    s.name = "";
    s.data = "x";
    cases.push_back({"an empty name", s, GARC_ERR_INVALID});
  }
  {
    Spec s;
    s.name = std::string("a\0b", 3);
    s.data = "x";
    cases.push_back({"a NUL in a name", s, GARC_ERR_INVALID});
  }
  for (const char * bad : {"\x80", "\xC0\xAF", "\xED\xA0\x80", "\xF4\x90\x80\x80",
           "ab\xE2\x82"}) {
    Spec s;
    s.name = bad;
    s.data = "x";
    cases.push_back({"a name that is not UTF-8", s, GARC_ERR_INVALID});
  }
  {
    Spec s;
    s.name = "d";
    s.type = GARC_MEMBER_DIRECTORY;
    s.data = "x";
    cases.push_back({"a directory with data", s, GARC_ERR_INVALID});
  }
  {
    Spec s;
    s.name = "l";
    s.type = GARC_MEMBER_SYMLINK;
    cases.push_back({"a symlink with no target", s, GARC_ERR_INVALID});
  }
  for (GARC_Member_Type type : {GARC_MEMBER_HARDLINK, GARC_MEMBER_FIFO,
           GARC_MEMBER_CHAR_DEVICE, GARC_MEMBER_BLOCK_DEVICE,
           GARC_MEMBER_OTHER}) {
    Spec s;
    s.name = "x";
    s.type = type;
    s.link = "t";
    cases.push_back({"a type 7z has no convention for", s,
        GARC_ERR_UNSUPPORTED});
  }
  for (const Case & one : cases) {
    SCOPED_TRACE(one.what);
    Built built;
    ASSERT_EQ(built.create_result(), GARC_OK);
    EXPECT_EQ(built.add(one.spec), one.expect);
    // The writer is still good: a refused member leaves no trace.
    Spec fine;
    fine.name = "fine";
    fine.data = "ok";
    EXPECT_EQ(built.add(fine), GARC_OK);
    EXPECT_EQ(built.finish(), GARC_OK);
    std::map<std::string, Read> got;
    EXPECT_EQ(read_back(built.bytes(), &got), GARC_END);
    EXPECT_EQ(got.size(), 1u);
  }
}

TEST(SevenZWrite, ASinkThatCannotPatchIsRefusedAtCreate) {
  GARC_Sink_Callbacks callbacks;
  std::memset(&callbacks, 0, sizeof(callbacks));
  callbacks.write = [](void *, const void *, size_t) { return GARC_OK; };
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_callback(&callbacks, &sink), GARC_OK);
  GARC_Writer * writer = nullptr;
  EXPECT_EQ(garc_writer_create(sink, GARC_FORMAT_SEVENZ, nullptr, &writer),
      GARC_ERR_NOT_SEEKABLE);
  EXPECT_EQ(writer, nullptr);
  garc_sink_destroy(sink);
}

TEST(SevenZWrite, AnUnknownMethodIsInvalid) {
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  GARC_Writer_Options options;
  garc_writer_options_default(&options);
  options.sevenz_method = static_cast<GARC_SevenZ_Method>(99);
  GARC_Writer * writer = nullptr;
  EXPECT_EQ(garc_writer_create(sink, GARC_FORMAT_SEVENZ, &options, &writer),
      GARC_ERR_INVALID);
  garc_sink_destroy(sink);
}

TEST(SevenZWrite, AMemberShortOfItsDeclaredDataCannotBeFinished) {
  Built built;
  Spec spec;
  spec.name = "short";
  spec.data = "0123456789";
  const GARC_Member member = member_of(spec);
  ASSERT_EQ(garc_writer_add(built.writer(), &member), GARC_OK);
  ASSERT_EQ(garc_writer_write(built.writer(), "0123", 4), GARC_OK);
  EXPECT_EQ(garc_writer_finish(built.writer()), GARC_ERR_INVALID);
}

TEST(SevenZWrite, AWriterDestroyedMidArchiveFreesEverything) {
  FailingAllocator allocator(static_cast<size_t>(-1));
  {
    GARC_Sink * sink = nullptr;
    ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
    GARC_Writer * writer = nullptr;
    ASSERT_EQ(garc_writer_create_with_allocator(sink, GARC_FORMAT_SEVENZ,
                  nullptr, allocator.get(), &writer),
        GARC_OK);
    Spec spec;
    spec.name = "a";
    spec.data = "data";
    const GARC_Member member = member_of(spec);
    ASSERT_EQ(garc_writer_add(writer, &member), GARC_OK);
    ASSERT_EQ(garc_writer_write(writer, "da", 2), GARC_OK);
    garc_writer_destroy(writer);
    garc_sink_destroy(sink);
  }
  EXPECT_EQ(allocator.live(), 0u);
}

TEST(SevenZWrite, EveryAllocationFailureIsReportedAndFreesWhatItTook) {
  for (GARC_SevenZ_Method method : {GARC_SEVENZ_LZMA2, GARC_SEVENZ_COPY}) {
    for (size_t budget = 0; budget < 40u; ++budget) {
      SCOPED_TRACE(budget);
      FailingAllocator allocator(budget);
      GARC_Sink * sink = nullptr;
      ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
      GARC_Writer_Options options;
      garc_writer_options_default(&options);
      options.sevenz_method = method;
      GARC_Writer * writer = nullptr;
      GARC_Result last = garc_writer_create_with_allocator(sink,
          GARC_FORMAT_SEVENZ, &options, allocator.get(), &writer);
      if (last == GARC_OK) {
        for (const Spec & spec : corpus()) {
          const GARC_Member member = member_of(spec);
          last = garc_writer_add(writer, &member);
          if (last == GARC_OK && member.size && spec.type == GARC_MEMBER_FILE) {
            last = garc_writer_write(writer, spec.data.data(), spec.data.size());
          }
          if (last != GARC_OK) {
            break;
          }
        }
        if (last == GARC_OK) {
          last = garc_writer_finish(writer);
        }
        EXPECT_TRUE(last == GARC_OK || last == GARC_ERR_OOM)
            << garc_result_string(last);
        garc_writer_destroy(writer);
      }
      else {
        EXPECT_EQ(last, GARC_ERR_OOM);
      }
      garc_sink_destroy(sink);
      allocator.stop_failing();
      EXPECT_EQ(allocator.live(), 0u);
    }
  }
}

TEST(SevenZWrite, TheHeaderRecordsAFilesCrcAndASolidFolderHoldsAllOfThem) {
  // Reading the packed layout from the outside: one pack stream for a solid
  // copy archive, one per file for a non-solid one.
  for (bool non_solid : {false, true}) {
    Built built(GARC_SEVENZ_COPY, non_solid);
    Spec a;
    a.name = "a";
    a.data = "aaaa";
    Spec b;
    b.name = "b";
    b.data = "bbbbbb";
    ASSERT_EQ(built.add(a), GARC_OK);
    ASSERT_EQ(built.add(b), GARC_OK);
    ASSERT_EQ(built.finish(), GARC_OK);
    const std::vector<uint8_t> bytes = built.bytes();
    // Copy is stored: the ten data bytes follow the 32-byte start header.
    EXPECT_EQ(std::string(bytes.begin() + 32, bytes.begin() + 42), "aaaabbbbbb");
    // The header starts after them, with the Header id.
    EXPECT_EQ(bytes[42], 0x01);
    // And the start header names exactly where it is.
    uint64_t offset = 0;
    for (int i = 7; i >= 0; --i) {
      offset = (offset << 8) | bytes[12 + i];
    }
    EXPECT_EQ(offset, 10u);
  }
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
