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

#include <algorithm>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "failing_allocator.h"
#include "sevenz_builder.h"
#include "tar_manifest.h"
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
      bool non_solid = false, const std::string * password = nullptr,
      bool encrypt_header = false, uint32_t key_power = 1) {
    if (garc_sink_create_memory(&sink_) != GARC_OK) {
      return;
    }
    GARC_Writer_Options options;
    garc_writer_options_default(&options);
    options.sevenz_method = method;
    options.sevenz_non_solid = non_solid ? 1 : 0;
    if (password) {
      // Power 1 by default: a test pays 2 rounds a key rather than 2^19.
      options.password = password->data();
      options.password_length = password->size();
      options.sevenz_encrypt_header = encrypt_header ? 1 : 0;
      options.sevenz_key_power = key_power;
    }
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
    std::vector<std::string> * order = nullptr,
    const std::string * password = nullptr) {
  BufferSource source(bytes.data(), bytes.size(), true, true);
  GARC_Stream * stream = nullptr;
  if (garc_stream_create_callback(source.callbacks(), &stream) != GARC_OK) {
    return GARC_ERR_INTERNAL;
  }
  GARC_Archive * archive = nullptr;
  GARC_Result result = garc_open(stream, nullptr, &archive);
  if (result == GARC_OK && password) {
    result = garc_set_password(archive, password->data(), password->size());
  }
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
    GARC_SEVENZ_BZIP2, GARC_SEVENZ_DEFLATE, GARC_SEVENZ_DEFLATE64,
    GARC_SEVENZ_COPY};

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

//-----------------------------------------------------------------------------
// AES
//-----------------------------------------------------------------------------

namespace {

const std::string kSecret = "s\xC3\xA9" "cret-\xF0\x9F\x98\x80";

bool contains(const std::vector<uint8_t> & bytes, const std::string & needle) {
  // Compared as unsigned: char is signed here, and 0xF1 is not '\xF1' to ==.
  return std::search(bytes.begin(), bytes.end(), needle.begin(), needle.end(),
             [](uint8_t a, char b) { return a == static_cast<uint8_t>(b); })
      != bytes.end();
}

/** A name as the plain header stores it: UTF-16LE. */
std::string utf16_of(const std::string & ascii) {
  std::string out;
  for (char c : ascii) {
    out.push_back(c);
    out.push_back('\0');
  }
  return out;
}

/** A file member with these bytes. */
Spec file_of(const char * name, const std::string & data) {
  Spec spec;
  spec.name = name;
  spec.data = data;
  return spec;
}

} // namespace

TEST(SevenZWriteAes, EveryMethodAndBothSolidnessesRoundTripEncrypted) {
  for (GARC_SevenZ_Method method : kMethods) {
    for (bool non_solid : {false, true}) {
      for (bool header : {false, true}) {
        SCOPED_TRACE(static_cast<int>(method));
        SCOPED_TRACE(non_solid);
        SCOPED_TRACE(header ? "header encrypted" : "header plain");
        Built built(method, non_solid, &kSecret, header);
        ASSERT_EQ(built.create_result(), GARC_OK);
        const std::vector<Spec> specs = corpus();
        for (const Spec & spec : specs) {
          ASSERT_EQ(built.add(spec), GARC_OK) << spec.name;
        }
        ASSERT_EQ(built.finish(), GARC_OK);
        const std::vector<uint8_t> bytes = built.bytes();

        std::map<std::string, Read> got;
        ASSERT_EQ(read_back(bytes, &got, nullptr, &kSecret), GARC_END);
        ASSERT_EQ(got.size(), specs.size());
        for (const Spec & spec : specs) {
          SCOPED_TRACE(spec.name);
          const Read & read = got[spec.name];
          EXPECT_EQ(read.status, GARC_OK);
          if (spec.type == GARC_MEMBER_FILE) {
            EXPECT_TRUE(read.data == spec.data);
          }
          if (spec.type == GARC_MEMBER_SYMLINK) {
            EXPECT_EQ(read.link, spec.link);
          }
        }
        // Not one of the data's bytes is in the clear.
        EXPECT_FALSE(contains(bytes, "unicode\n"));
        EXPECT_FALSE(contains(bytes, "../a.txt"));
        // The names are, exactly when the header is not encrypted.
        EXPECT_EQ(contains(bytes, utf16_of("big.bin")), !header);

        std::map<std::string, Read> locked;
        if (header) {
          EXPECT_EQ(read_back(bytes, &locked), GARC_ERR_PASSWORD_REQUIRED);
          EXPECT_TRUE(locked.empty());
        }
        else {
          ASSERT_EQ(read_back(bytes, &locked), GARC_END);
          EXPECT_EQ(locked["big.bin"].status, GARC_ERR_PASSWORD_REQUIRED);
          EXPECT_EQ(locked["dir"].status, GARC_OK);
          EXPECT_EQ(locked["empty"].status, GARC_OK);
        }
        const std::string wrong = "not it";
        std::map<std::string, Read> refused;
        if (header) {
          EXPECT_EQ(read_back(bytes, &refused, nullptr, &wrong),
              GARC_ERR_PASSWORD_OR_CORRUPT);
        }
        else {
          ASSERT_EQ(read_back(bytes, &refused, nullptr, &wrong), GARC_END);
          EXPECT_EQ(refused["big.bin"].status, GARC_ERR_PASSWORD_OR_CORRUPT);
        }
      }
    }
  }
}

TEST(SevenZWriteAes, TheCoderIsWrittenAs7ZipWritesIt) {
  // 0x24 (an id of four bytes, with properties), 06 F1 07 01, eighteen bytes of
  // properties: 0x40 | 19, the IV's nibble 15, sixteen bytes of IV. At the
  // default power, which is 7-Zip's.
  Built built(GARC_SEVENZ_LZMA2, false, &kSecret, false, 0);
  ASSERT_EQ(built.create_result(), GARC_OK);
  ASSERT_EQ(built.add(file_of("f", "data")), GARC_OK);
  ASSERT_EQ(built.finish(), GARC_OK);
  const std::vector<uint8_t> bytes = built.bytes();
  EXPECT_TRUE(contains(bytes, std::string("\x24\x06\xF1\x07\x01\x12\x53\x0F", 8)));
  std::map<std::string, Read> got;
  ASSERT_EQ(read_back(bytes, &got, nullptr, &kSecret), GARC_END);
  EXPECT_EQ(got["f"].data, "data");
}

TEST(SevenZWriteAes, EveryFolderAndEveryArchiveHasAnIvOfItsOwn) {
  // The same plaintext under the same key: two archives, and two folders in a
  // non-solid one, must not share ciphertext.
  std::vector<std::vector<uint8_t>> made;
  for (int i = 0; i < 2; ++i) {
    Built built(GARC_SEVENZ_COPY, true, &kSecret);
    ASSERT_EQ(built.create_result(), GARC_OK);
    ASSERT_EQ(built.add(file_of("one", std::string(64, 'x'))), GARC_OK);
    ASSERT_EQ(built.add(file_of("two", std::string(64, 'x'))), GARC_OK);
    ASSERT_EQ(built.finish(), GARC_OK);
    made.push_back(built.bytes());
  }
  ASSERT_GE(made[0].size(), 160u);
  ASSERT_GE(made[1].size(), 96u);
  // The packed area is the two folders' 64 bytes each, after the start header.
  const std::string a(made[0].begin() + 32, made[0].begin() + 96);
  const std::string b(made[0].begin() + 96, made[0].begin() + 160);
  const std::string c(made[1].begin() + 32, made[1].begin() + 96);
  EXPECT_NE(a, b);
  EXPECT_NE(a, c);
  EXPECT_EQ(a.find(std::string(16, 'x')), std::string::npos);
}

TEST(SevenZWriteAes, AnEmptyPasswordEncrypts) {
  const std::string empty;
  Built built(GARC_SEVENZ_COPY, false, &empty);
  ASSERT_EQ(built.create_result(), GARC_OK);
  ASSERT_EQ(built.add(file_of("f", "visible?")), GARC_OK);
  ASSERT_EQ(built.finish(), GARC_OK);
  EXPECT_FALSE(contains(built.bytes(), "visible?"));
  std::map<std::string, Read> got;
  ASSERT_EQ(read_back(built.bytes(), &got, nullptr, &empty), GARC_END);
  EXPECT_EQ(got["f"].data, "visible?");
}

TEST(SevenZWriteAes, OptionsThatCannotBeHonouredAreInvalidAtCreate) {
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  auto create = [&](GARC_Format format, auto edit) {
    GARC_Writer_Options options;
    garc_writer_options_default(&options);
    edit(options);
    GARC_Writer * writer = nullptr;
    const GARC_Result result = garc_writer_create(sink, format, &options, &writer);
    garc_writer_destroy(writer);
    return result;
  };
  EXPECT_EQ(create(GARC_FORMAT_SEVENZ, [](GARC_Writer_Options & o) {
    o.sevenz_encrypt_header = 1;
  }), GARC_ERR_INVALID) << "a header to encrypt with no password";
  EXPECT_EQ(create(GARC_FORMAT_SEVENZ, [](GARC_Writer_Options & o) {
    o.password = "x";
    o.password_length = 1;
    o.sevenz_key_power = 25;
  }), GARC_ERR_INVALID) << "a power 7-Zip refuses to read";
  EXPECT_EQ(create(GARC_FORMAT_SEVENZ, [](GARC_Writer_Options & o) {
    o.password = "\xFF";
    o.password_length = 1;
  }), GARC_ERR_INVALID) << "a password that is not UTF-8";
  for (GARC_Format format : {GARC_FORMAT_TAR, GARC_FORMAT_CPIO, GARC_FORMAT_AR}) {
    EXPECT_EQ(create(format, [](GARC_Writer_Options & o) {
      o.password = "x";
      o.password_length = 1;
    }), GARC_ERR_INVALID) << "a password for a format with no encryption";
  }
  garc_sink_destroy(sink);
}

TEST(SevenZWriteAes, EveryAllocationFailureIsReportedAndFreesWhatItTook) {
  // The copy coder and small members, so that a budget is cheap and the sweep
  // can run to the first one that finishes: what is under test is the
  // encryption's allocations - the key's buffer, the cipher's, the sealed
  // header's record - and not LZMA2's, which the sweep above covers.
  std::vector<Spec> small;
  for (const Spec & spec : corpus()) {
    Spec cut = spec;
    if (cut.data.size() > 3000u) {
      cut.data.resize(3000u);
    }
    small.push_back(cut);
  }
  for (bool header : {false, true}) {
    bool finished = false;
    for (size_t budget = 0; budget < 400u && !finished; ++budget) {
      SCOPED_TRACE(budget);
      FailingAllocator allocator(budget);
      GARC_Sink * sink = nullptr;
      ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
      GARC_Writer_Options options;
      garc_writer_options_default(&options);
      options.sevenz_method = GARC_SEVENZ_COPY;
      options.password = kSecret.data();
      options.password_length = kSecret.size();
      options.sevenz_encrypt_header = header ? 1 : 0;
      options.sevenz_key_power = 1;
      GARC_Writer * writer = nullptr;
      GARC_Result last = garc_writer_create_with_allocator(sink,
          GARC_FORMAT_SEVENZ, &options, allocator.get(), &writer);
      if (last == GARC_OK) {
        for (const Spec & spec : small) {
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
        finished = last == GARC_OK;
        garc_writer_destroy(writer);
      }
      else {
        EXPECT_EQ(last, GARC_ERR_OOM);
      }
      garc_sink_destroy(sink);
      allocator.stop_failing();
      EXPECT_EQ(allocator.live(), 0u);
    }
    EXPECT_TRUE(finished) << "never reached a finished archive";
  }
}

//-----------------------------------------------------------------------------
// Branch filters, BCJ2 among them
//-----------------------------------------------------------------------------

namespace {

/** x86-ish bytes: E8, E9 and 0F 8x with displacements inside the file. */
std::string x86ish(uint32_t seed, size_t size) {
  std::string out;
  uint32_t x = seed;
  auto next = [&x]() {
    x = x * 1103515245u + 12345u;
    return x >> 16;
  };
  while (out.size() < size) {
    const uint32_t r = next() % 100u;
    if (r < 6u) {
      out.push_back(static_cast<char>(r < 3u ? 0xE8 : 0xE9));
      const uint32_t rel = next() % 0x1000u;
      for (unsigned k = 0; k < 4u; ++k) {
        out.push_back(static_cast<char>((rel >> (8u * k)) & 0xFFu));
      }
    }
    else if (r < 8u) {
      out.push_back(0x0F);
      out.push_back(static_cast<char>(0x80 + next() % 16u));
    }
    else {
      out.push_back(static_cast<char>(next() & 0xFFu));
    }
  }
  out.resize(size);
  return out;
}

/** The corpus with two programs in it, which is what a filter is for. */
std::vector<Spec> program_corpus() {
  std::vector<Spec> specs = corpus();
  Spec one;
  one.name = "bin/one";
  one.data = x86ish(1, 20000);
  specs.push_back(one);
  Spec two;
  two.name = "bin/two";
  two.data = x86ish(2, 7000) + std::string("\xE8\x01\x02", 3);
  specs.push_back(two);
  return specs;
}

const GARC_SevenZ_Filter kFilters[] = {GARC_SEVENZ_FILTER_BCJ2,
    GARC_SEVENZ_FILTER_X86, GARC_SEVENZ_FILTER_PPC, GARC_SEVENZ_FILTER_IA64,
    GARC_SEVENZ_FILTER_ARM, GARC_SEVENZ_FILTER_ARMT, GARC_SEVENZ_FILTER_SPARC,
    GARC_SEVENZ_FILTER_ARM64, GARC_SEVENZ_FILTER_RISCV};

/** Write @p specs through @p filter; the archive's bytes, or empty. */
std::vector<uint8_t> write_filtered(const std::vector<Spec> & specs,
    GARC_SevenZ_Method method, GARC_SevenZ_Filter filter, bool non_solid,
    const std::string * password = nullptr, bool header = false) {
  GARC_Sink * sink = nullptr;
  if (garc_sink_create_memory(&sink) != GARC_OK) {
    return {};
  }
  GARC_Writer_Options options;
  garc_writer_options_default(&options);
  options.sevenz_method = method;
  options.sevenz_filter = filter;
  options.sevenz_non_solid = non_solid ? 1 : 0;
  if (password) {
    options.password = password->data();
    options.password_length = password->size();
    options.sevenz_encrypt_header = header ? 1 : 0;
    options.sevenz_key_power = 1;
  }
  GARC_Writer * writer = nullptr;
  std::vector<uint8_t> bytes;
  if (garc_writer_create(sink, GARC_FORMAT_SEVENZ, &options, &writer) == GARC_OK) {
    GARC_Result result = GARC_OK;
    for (const Spec & spec : specs) {
      const GARC_Member member = member_of(spec);
      result = garc_writer_add(writer, &member);
      if (result == GARC_OK && member.size && spec.type == GARC_MEMBER_FILE) {
        result = garc_writer_write(writer, spec.data.data(), spec.data.size());
      }
      if (result != GARC_OK) {
        break;
      }
    }
    if (result == GARC_OK && garc_writer_finish(writer) == GARC_OK) {
      const void * data = nullptr;
      size_t size = 0;
      if (garc_sink_data(sink, &data, &size) == GARC_OK) {
        const uint8_t * raw = static_cast<const uint8_t *>(data);
        bytes.assign(raw, raw + size);
      }
    }
  }
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
  return bytes;
}

} // namespace

TEST(SevenZWriteFilter, EveryFilterRoundTripsSolidOrNotAndEncryptedOrNot) {
  const std::vector<Spec> specs = program_corpus();
  const std::string password = "filters";
  // BCJ2, which has a folder layout of its own, through everything: three
  // methods (copy makes CALL and JUMP copy too), solid or not, plain, data
  // encrypted, header too. The one-stream filters are one coder more in a
  // chain the other tests already cover, so once each, with LZMA2.
  for (GARC_SevenZ_Filter filter : kFilters) {
    const bool bcj2 = filter == GARC_SEVENZ_FILTER_BCJ2;
    for (GARC_SevenZ_Method method : {GARC_SEVENZ_LZMA2, GARC_SEVENZ_COPY,
             GARC_SEVENZ_DEFLATE}) {
      if (!bcj2 && method != GARC_SEVENZ_LZMA2) {
        continue;
      }
      for (bool non_solid : {false, true}) {
        for (int aes = 0; aes < 3; ++aes) {
          if (!bcj2 && (non_solid || aes == 1)) {
            continue;
          }
          SCOPED_TRACE(static_cast<int>(filter));
          SCOPED_TRACE(static_cast<int>(method));
          SCOPED_TRACE(non_solid);
          SCOPED_TRACE(aes);
          const std::vector<uint8_t> bytes = write_filtered(specs, method,
              filter, non_solid, aes ? &password : nullptr, aes == 2);
          ASSERT_FALSE(bytes.empty());
          std::map<std::string, Read> got;
          ASSERT_EQ(read_back(bytes, &got, nullptr, aes ? &password : nullptr),
              GARC_END);
          ASSERT_EQ(got.size(), specs.size());
          for (const Spec & spec : specs) {
            SCOPED_TRACE(spec.name);
            EXPECT_EQ(got[spec.name].status, GARC_OK);
            if (spec.type == GARC_MEMBER_FILE) {
              EXPECT_TRUE(got[spec.name].data == spec.data);
            }
            if (spec.type == GARC_MEMBER_SYMLINK) {
              EXPECT_EQ(got[spec.name].link, spec.link);
            }
          }
        }
      }
    }
  }
}

TEST(SevenZWriteFilter, Bcj2WritesTheFourStreams7ZipWrote) {
  // 7-Zip's bcj2-copy.7z is the corpus's files through BCJ2 with Copy for all
  // three of its other coders, so its packed area is the four streams raw:
  // MAIN, the range coder, CALL, JUMP. The same files, in the same order,
  // through this writer must give the same bytes - which checks the
  // conversion rule, the range coder and the stream order against 7-Zip.
  const std::vector<uint8_t> theirs = garctest::read_fixture(
      std::string(GARC_TEST_DATA) + "/sevenz/bcj2-copy.7z");
  ASSERT_FALSE(theirs.empty());
  std::vector<Spec> specs;
  {
    BufferSource source(theirs.data(), theirs.size(), true, true);
    GARC_Stream * stream = nullptr;
    ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK);
    GARC_Archive * archive = nullptr;
    ASSERT_EQ(garc_open(stream, nullptr, &archive), GARC_OK);
    const GARC_Member * member = nullptr;
    while (garc_next(archive, &member) == GARC_OK) {
      if (member->type != GARC_MEMBER_FILE || !member->size) {
        continue;
      }
      Spec spec;
      spec.name.assign(member->name, member->name_length);
      char buffer[1024];
      size_t got = 0;
      while (garc_read_member(archive, buffer, sizeof(buffer), &got) == GARC_OK
          && got) {
        spec.data.append(buffer, got);
      }
      specs.push_back(spec);
    }
    garc_close(archive);
    garc_stream_destroy(stream);
  }
  ASSERT_GT(specs.size(), 5u);
  const std::vector<uint8_t> ours = write_filtered(
      specs, GARC_SEVENZ_COPY, GARC_SEVENZ_FILTER_BCJ2, false);
  ASSERT_FALSE(ours.empty());
  size_t total = 0;
  for (const Spec & spec : specs) {
    total += spec.data.size();
  }
  // The packed area is MAIN plus CALL and JUMP - the data, less nothing, as
  // conversion only moves bytes - plus the range coder's few.
  ASSERT_GT(ours.size(), 32u + total);
  size_t same = 0;
  while (32u + same < ours.size() && 32u + same < theirs.size()
      && ours[32u + same] == theirs[32u + same]) {
    ++same;
  }
  EXPECT_GT(same, total) << "the streams part at byte " << same;
}

TEST(SevenZWriteFilter, Bcj2ConvertsTheBranchesItShould) {
  // Not just a round trip that a filter doing nothing would pass: the packed
  // area must have fewer E8 displacements left in it than the input has.
  const std::vector<Spec> specs = {[] {
    Spec s;
    s.name = "p";
    s.data = x86ish(9, 30000);
    return s;
  }()};
  const std::vector<uint8_t> plain
      = write_filtered(specs, GARC_SEVENZ_COPY, GARC_SEVENZ_FILTER_NONE, false);
  const std::vector<uint8_t> bcj2
      = write_filtered(specs, GARC_SEVENZ_COPY, GARC_SEVENZ_FILTER_BCJ2, false);
  ASSERT_FALSE(plain.empty());
  ASSERT_FALSE(bcj2.empty());
  // Copy: the plain archive holds the input as it was. BCJ2's MAIN, which
  // comes first, holds it with the converted displacements taken out.
  const std::string input = specs[0].data;
  EXPECT_TRUE(std::equal(input.begin(), input.end(), plain.begin() + 32,
      [](char a, uint8_t b) { return static_cast<uint8_t>(a) == b; }));
  EXPECT_FALSE(std::equal(input.begin(), input.begin() + 2000, bcj2.begin() + 32,
      [](char a, uint8_t b) { return static_cast<uint8_t>(a) == b; }));
}

TEST(SevenZWriteFilter, AnUnknownFilterIsInvalid) {
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  GARC_Writer_Options options;
  garc_writer_options_default(&options);
  options.sevenz_filter = static_cast<GARC_SevenZ_Filter>(99);
  GARC_Writer * writer = nullptr;
  EXPECT_EQ(garc_writer_create(sink, GARC_FORMAT_SEVENZ, &options, &writer),
      GARC_ERR_INVALID);
  EXPECT_EQ(writer, nullptr);
  garc_sink_destroy(sink);
}

TEST(SevenZWriteFilter, EveryAllocationFailureIsReportedAndFreesWhatItTook) {
  std::vector<Spec> small;
  for (const Spec & spec : program_corpus()) {
    Spec cut = spec;
    if (cut.data.size() > 1500u) {
      cut.data.resize(1500u);
    }
    small.push_back(cut);
  }
  const std::string password = "sweep";
  for (GARC_SevenZ_Filter filter : {GARC_SEVENZ_FILTER_BCJ2,
           GARC_SEVENZ_FILTER_X86}) {
    for (bool aes : {false, true}) {
      if (filter != GARC_SEVENZ_FILTER_BCJ2 && aes) {
        continue;
      }
      SCOPED_TRACE(static_cast<int>(filter));
      SCOPED_TRACE(aes);
      bool finished = false;
      for (size_t budget = 0; budget < 600u && !finished; ++budget) {
        FailingAllocator allocator(budget);
        GARC_Sink * sink = nullptr;
        ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
        GARC_Writer_Options options;
        garc_writer_options_default(&options);
        options.sevenz_method = GARC_SEVENZ_LZMA2;
        options.sevenz_filter = filter;
        options.sevenz_non_solid = 1;
        if (aes) {
          options.password = password.data();
          options.password_length = password.size();
          options.sevenz_encrypt_header = 1;
          options.sevenz_key_power = 1;
        }
        GARC_Writer * writer = nullptr;
        GARC_Result last = garc_writer_create_with_allocator(sink,
            GARC_FORMAT_SEVENZ, &options, allocator.get(), &writer);
        if (last == GARC_OK) {
          for (const Spec & spec : small) {
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
              << garc_result_string(last) << " at budget " << budget;
          finished = last == GARC_OK;
          garc_writer_destroy(writer);
        }
        else {
          EXPECT_EQ(last, GARC_ERR_OOM);
        }
        garc_sink_destroy(sink);
        allocator.stop_failing();
        EXPECT_EQ(allocator.live(), 0u) << "budget " << budget;
      }
      EXPECT_TRUE(finished) << "never reached a finished archive";
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
