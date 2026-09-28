/**
 * @file
 *
 * A codec in front of a stream, and behind a sink: `tar.gz`, `tar.zst`,
 * `tar.lz4`, `tar` through zlib.
 *
 * Four things these tests are careful about, and each is a way this pair could
 * pass while being wrong.
 *
 * **A round trip proves nothing on its own.** A compressing sink that wrote its
 * input through unchanged and a decompressing stream that read it back would
 * round-trip perfectly. So every codec here is also asserted to have *changed*
 * the bytes, and the recovered archive is compared against the tar the writer
 * produced with no codec at all - an external statement of what the answer is.
 *
 * **A truncated codec stream must not read as a short archive.** Skipping
 * ::garc_sink_finish() leaves the inner sink holding a stream with no trailer,
 * and the failure mode to avoid is not an error - it is the decoder returning
 * the members it did get and then zero bytes, which the tar reader would read as
 * a perfectly good smaller archive. The test asserts a failure, not a mismatch.
 *
 * **The loops have to iterate.** The staging buffer is 10240 bytes, and a
 * 200-byte archive exercises neither the read loop's refill nor the write
 * loop's drain. One archive here is deliberately large enough to go round both
 * several times, and one read is done a byte at a time, which is what puts the
 * `finish()` drain in a position to matter: with an output buffer smaller than a
 * codec block, zstd hands over *everything* from finish.
 *
 * **What compress does is asserted, not assumed.** Concatenated members are read
 * by zstd and refused by the other three - a difference between codecs in
 * another library, measured before this code was written. Both halves are
 * asserted here, so a change next door shows up as a failure in a test that
 * names the behaviour rather than as a silent change in what an archive means.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <ghoti.io/compress/compress.h>
#include <ghoti.io/compress/options.h>

#include "codec/codec_internal.h"
#include "test_helpers.h"

using garctest::BufferDrain;
using garctest::FailingAllocator;

namespace {

/** Every codec this library is expected to compose with. */
const char * const kMethods[] = {"gzip", "zstd", "lz4", "zlib"};

/** One member's worth of content, repeated to @p size bytes. */
std::string filler(size_t size, char seed) {
  std::string out;
  out.reserve(size);
  for (size_t i = 0; i < size; ++i) {
    out.push_back(static_cast<char>(seed + static_cast<char>(i % 23)));
  }
  return out;
}

/** A member to write, and therefore also what to expect back. */
struct Entry {
  std::string name;
  std::string data;
};

/**
 * Write @p entries as a pax tar into @p sink.
 *
 * @param sink Where the tar goes.
 * @param entries The members.
 * @return ::GARC_OK, or the first failure.
 */
GARC_Result write_tar(GARC_Sink * sink, const std::vector<Entry> & entries) {
  GARC_Writer * writer = nullptr;
  GARC_Result result
      = garc_writer_create(sink, GARC_FORMAT_TAR, nullptr, &writer);
  if (result != GARC_OK) {
    return result;
  }
  for (const Entry & entry : entries) {
    GARC_Member member;
    memset(&member, 0, sizeof(member));
    member.name = entry.name.c_str();
    member.name_length = entry.name.size();
    member.type = GARC_MEMBER_FILE;
    member.size = entry.data.size();
    member.mode = 0644;
    member.mode_valid = 1;
    member.mtime_seconds = 1000000000;
    member.mtime_source = GARC_TIME_TAR_OCTAL;
    result = garc_writer_add(writer, &member);
    if (result == GARC_OK && !entry.data.empty()) {
      result = garc_writer_write(writer, entry.data.data(), entry.data.size());
    }
    if (result != GARC_OK) {
      garc_writer_destroy(writer);
      return result;
    }
  }
  result = garc_writer_finish(writer);
  garc_writer_destroy(writer);
  return result;
}

/** The bytes a memory sink holds. */
std::string collected(const GARC_Sink * sink) {
  const void * data = nullptr;
  size_t size = 0;
  if (garc_sink_data(sink, &data, &size) != GARC_OK) {
    return {};
  }
  return std::string(static_cast<const char *>(data), size);
}

/** The tar these entries make with no codec involved. */
std::string plain_tar(const std::vector<Entry> & entries) {
  GARC_Sink * sink = nullptr;
  if (garc_sink_create_memory(&sink) != GARC_OK) {
    return {};
  }
  std::string out;
  if (write_tar(sink, entries) == GARC_OK) {
    out = collected(sink);
  }
  garc_sink_destroy(sink);
  return out;
}

/**
 * Compress a tar of @p entries with @p method.
 *
 * @param method The codec.
 * @param entries The members.
 * @param out_packed Receives the compressed bytes.
 * @param out_logical Receives what the compressing sink's own offset said.
 * @param finish Whether to call garc_sink_finish().
 * @return ::GARC_OK, or the first failure.
 */
GARC_Result pack(const char * method, const std::vector<Entry> & entries,
    std::string * out_packed, uint64_t * out_logical = nullptr,
    bool finish = true) {
  GARC_Sink * file = nullptr;
  GARC_Result result = garc_sink_create_memory(&file);
  if (result != GARC_OK) {
    return result;
  }
  GARC_Sink * packer = nullptr;
  result = garc_sink_create_compress(file, method, nullptr, &packer);
  if (result != GARC_OK) {
    garc_sink_destroy(file);
    return result;
  }
  result = write_tar(packer, entries);
  if (result == GARC_OK && finish) {
    result = garc_sink_finish(packer);
  }
  if (result == GARC_OK) {
    if (out_logical) {
      *out_logical = garc_sink_tell(packer);
    }
    *out_packed = collected(file);
  }
  garc_sink_destroy(packer);
  garc_sink_destroy(file);
  return result;
}

/** One member, as read back out of an archive. */
struct Recovered {
  std::string name;
  std::string data;
};

/**
 * Read an archive out of @p packed through @p method.
 *
 * @param method The codec.
 * @param packed The compressed bytes.
 * @param out_members Receives the members.
 * @param chunk How many bytes to ask for at a time; 0 means a large buffer.
 * @return ::GARC_OK when the whole archive was walked, or the first failure.
 */
GARC_Result unpack(const char * method, const std::string & packed,
    std::vector<Recovered> * out_members, size_t chunk = 0) {
  GARC_Stream * file = nullptr;
  GARC_Result result
      = garc_stream_create_memory(packed.data(), packed.size(), &file);
  if (result != GARC_OK) {
    return result;
  }
  GARC_Stream * plain = nullptr;
  result = garc_stream_create_decompress(file, method, nullptr, &plain);
  if (result != GARC_OK) {
    garc_stream_destroy(file);
    return result;
  }

  GARC_Archive * archive = nullptr;
  result = garc_open(plain, nullptr, &archive);
  if (result == GARC_OK) {
    const GARC_Member * member = nullptr;
    while ((result = garc_next(archive, &member)) == GARC_OK) {
      Recovered got;
      got.name.assign(member->name, member->name_length);
      std::vector<char> buffer(chunk ? chunk : 65536u);
      for (;;) {
        size_t read = 0;
        result = garc_read_member(archive, buffer.data(), buffer.size(), &read);
        if (result != GARC_OK || !read) {
          break;
        }
        got.data.append(buffer.data(), read);
      }
      if (result != GARC_OK) {
        break;
      }
      out_members->push_back(got);
    }
    if (result == GARC_END) {
      result = GARC_OK;
    }
    garc_close(archive);
  }
  garc_stream_destroy(plain);
  garc_stream_destroy(file);
  return result;
}

/** Two members, small enough that the whole archive is one staging buffer. */
std::vector<Entry> small_entries() {
  return {{"notes/hello.txt", "Hello, tar.\n"}, {"notes/empty.txt", ""}};
}

/**
 * Big enough that both loops go round several times.
 *
 * 300 KiB against a 10240-byte staging buffer is about thirty refills on the way
 * in and at least that many drains on the way out. The content is not
 * incompressible - a codec that could not shrink it would make the "the bytes
 * changed" assertion below vacuous - and not uniform either, so lz4 and gzip
 * both have real work rather than a run-length trick.
 */
std::vector<Entry> big_entries() {
  return {{"big/a", filler(150000, 'a')}, {"big/b", filler(160000, 'Q')}};
}

} // namespace

////////////////////////////////////////////////////////////////////////
// The round trip, and that a codec was involved at all
////////////////////////////////////////////////////////////////////////

TEST(Codec, EveryMethodRoundTripsASmallArchive) {
  const std::vector<Entry> entries = small_entries();
  for (const char * method : kMethods) {
    SCOPED_TRACE(method);
    std::string packed;
    ASSERT_EQ(GARC_OK, pack(method, entries, &packed));
    std::vector<Recovered> got;
    ASSERT_EQ(GARC_OK, unpack(method, packed, &got));
    ASSERT_EQ(entries.size(), got.size());
    for (size_t i = 0; i < entries.size(); ++i) {
      EXPECT_EQ(entries[i].name, got[i].name);
      EXPECT_EQ(entries[i].data, got[i].data);
    }
  }
}

TEST(Codec, EveryMethodRoundTripsAnArchiveLargerThanTheStagingBuffer) {
  const std::vector<Entry> entries = big_entries();
  for (const char * method : kMethods) {
    SCOPED_TRACE(method);
    std::string packed;
    ASSERT_EQ(GARC_OK, pack(method, entries, &packed));
    std::vector<Recovered> got;
    ASSERT_EQ(GARC_OK, unpack(method, packed, &got));
    ASSERT_EQ(entries.size(), got.size());
    for (size_t i = 0; i < entries.size(); ++i) {
      EXPECT_EQ(entries[i].name, got[i].name);
      EXPECT_EQ(entries[i].data, got[i].data);
    }
  }
}

TEST(Codec, TheBytesAreNotTheTarTheWriterProduced) {
  // Without this, a sink that wrote its input through unchanged would pass every
  // round-trip test in this file.
  const std::vector<Entry> entries = big_entries();
  const std::string plain = plain_tar(entries);
  ASSERT_FALSE(plain.empty());
  for (const char * method : kMethods) {
    SCOPED_TRACE(method);
    std::string packed;
    ASSERT_EQ(GARC_OK, pack(method, entries, &packed));
    EXPECT_NE(plain, packed);
    EXPECT_LT(packed.size(), plain.size());
  }
}

TEST(Codec, WhatComesBackIsTheTarTheWriterWouldHaveWritten) {
  // Compared against the uncompressed tar rather than against the member list,
  // so that a codec pair which lost a padding block somewhere is caught even
  // though every member still reads correctly.
  const std::vector<Entry> entries = small_entries();
  const std::string plain = plain_tar(entries);
  ASSERT_FALSE(plain.empty());
  for (const char * method : kMethods) {
    SCOPED_TRACE(method);
    std::string packed;
    ASSERT_EQ(GARC_OK, pack(method, entries, &packed));

    GARC_Stream * file = nullptr;
    ASSERT_EQ(GARC_OK,
        garc_stream_create_memory(packed.data(), packed.size(), &file));
    GARC_Stream * plain_stream = nullptr;
    ASSERT_EQ(GARC_OK,
        garc_stream_create_decompress(file, method, nullptr, &plain_stream));
    std::string recovered;
    for (;;) {
      char buffer[777];
      size_t read = 0;
      ASSERT_EQ(GARC_OK,
          garc_stream_read(plain_stream, buffer, sizeof(buffer), &read));
      if (!read) {
        break;
      }
      recovered.append(buffer, read);
    }
    EXPECT_EQ(plain, recovered);
    garc_stream_destroy(plain_stream);
    garc_stream_destroy(file);
  }
}

TEST(Codec, AByteAtATimeReadsTheWholeArchive) {
  // The case that made the finish() drain load-bearing: with an output buffer
  // smaller than a codec block, zstd produces nothing from update() and hands
  // over everything from finish(). A reader that stopped when update went quiet
  // would report an empty archive here.
  const std::vector<Entry> entries = small_entries();
  for (const char * method : kMethods) {
    SCOPED_TRACE(method);
    std::string packed;
    ASSERT_EQ(GARC_OK, pack(method, entries, &packed));
    std::vector<Recovered> got;
    ASSERT_EQ(GARC_OK, unpack(method, packed, &got, 1));
    ASSERT_EQ(entries.size(), got.size());
    EXPECT_EQ(entries[0].data, got[0].data);
  }
}

////////////////////////////////////////////////////////////////////////
// Finishing, and what happens without it
////////////////////////////////////////////////////////////////////////

TEST(Codec, WithoutFinishingTheStreamIsRefusedRatherThanShort) {
  const std::vector<Entry> entries = small_entries();
  for (const char * method : kMethods) {
    SCOPED_TRACE(method);
    std::string packed;
    ASSERT_EQ(GARC_OK, pack(method, entries, &packed, nullptr, false));
    std::vector<Recovered> got;
    const GARC_Result result = unpack(method, packed, &got);
    // The point is the status. A short archive that read cleanly would be the
    // dangerous answer, and "fewer members" is what that looks like.
    EXPECT_TRUE(garc_result_is_error(result))
        << "unfinished " << method << " read as a complete archive with "
        << got.size() << " members";
  }
}

TEST(Codec, FinishingTwiceIsHarmless) {
  GARC_Sink * file = nullptr;
  ASSERT_EQ(GARC_OK, garc_sink_create_memory(&file));
  GARC_Sink * packer = nullptr;
  ASSERT_EQ(GARC_OK, garc_sink_create_compress(file, "gzip", nullptr, &packer));
  ASSERT_EQ(GARC_OK, write_tar(packer, small_entries()));
  ASSERT_EQ(GARC_OK, garc_sink_finish(packer));
  const size_t once = collected(file).size();
  EXPECT_EQ(GARC_OK, garc_sink_finish(packer));
  EXPECT_EQ(once, collected(file).size());
  garc_sink_destroy(packer);
  garc_sink_destroy(file);
}

TEST(Codec, WritingAfterFinishingIsRefused) {
  GARC_Sink * file = nullptr;
  ASSERT_EQ(GARC_OK, garc_sink_create_memory(&file));
  GARC_Sink * packer = nullptr;
  ASSERT_EQ(GARC_OK, garc_sink_create_compress(file, "gzip", nullptr, &packer));
  ASSERT_EQ(GARC_OK, garc_sink_finish(packer));
  EXPECT_EQ(GARC_ERR_INVALID, garc_sink_write(packer, "x", 1));
  garc_sink_destroy(packer);
  garc_sink_destroy(file);
}

TEST(Codec, FinishIsOkOnASinkWithNothingToFinish) {
  // Uniform on purpose: a caller ends whatever sink it was handed with one call,
  // and a status meaning "this kind needs no finishing" would have to be told
  // apart from a failure at every call site.
  GARC_Sink * memory = nullptr;
  ASSERT_EQ(GARC_OK, garc_sink_create_memory(&memory));
  EXPECT_EQ(GARC_OK, garc_sink_finish(memory));
  garc_sink_destroy(memory);

  BufferDrain drain;
  GARC_Sink * callback = nullptr;
  ASSERT_EQ(GARC_OK, garc_sink_create_callback(drain.callbacks(), &callback));
  EXPECT_EQ(GARC_OK, garc_sink_finish(callback));
  garc_sink_destroy(callback);
}

TEST(Codec, FinishRejectsNull) {
  EXPECT_EQ(GARC_ERR_INVALID, garc_sink_finish(nullptr));
}

TEST(Codec, AFailingInnerSinkIsReportedByFinish) {
  // The trailer is written in finish(), so this is the one write whose failure
  // no earlier call can report.
  BufferDrain drain;
  GARC_Sink * file = nullptr;
  ASSERT_EQ(GARC_OK, garc_sink_create_callback(drain.callbacks(), &file));
  GARC_Sink * packer = nullptr;
  ASSERT_EQ(GARC_OK, garc_sink_create_compress(file, "gzip", nullptr, &packer));
  ASSERT_EQ(GARC_OK, write_tar(packer, small_entries()));
  drain.fail_writes(1);
  EXPECT_EQ(GARC_ERR_IO, garc_sink_finish(packer));
  garc_sink_destroy(packer);
  garc_sink_destroy(file);
}

////////////////////////////////////////////////////////////////////////
// The two offsets
////////////////////////////////////////////////////////////////////////

TEST(Codec, TheSinkCountsUncompressedBytesAndTheInnerOneCountsCompressed) {
  // A writer pads from garc_sink_tell(), so a compressing sink reporting its
  // compressed length would put the blocking boundary in the wrong place.
  const std::vector<Entry> entries = big_entries();
  const std::string plain = plain_tar(entries);
  ASSERT_FALSE(plain.empty());

  GARC_Sink * file = nullptr;
  ASSERT_EQ(GARC_OK, garc_sink_create_memory(&file));
  GARC_Sink * packer = nullptr;
  ASSERT_EQ(GARC_OK, garc_sink_create_compress(file, "gzip", nullptr, &packer));
  ASSERT_EQ(GARC_OK, write_tar(packer, entries));
  ASSERT_EQ(GARC_OK, garc_sink_finish(packer));

  EXPECT_EQ(plain.size(), garc_sink_tell(packer));
  EXPECT_EQ(collected(file).size(), garc_sink_tell(file));
  EXPECT_LT(garc_sink_tell(file), garc_sink_tell(packer));
  garc_sink_destroy(packer);
  garc_sink_destroy(file);
}

////////////////////////////////////////////////////////////////////////
// What compress does, asserted rather than assumed
////////////////////////////////////////////////////////////////////////

namespace {

/** Two independently compressed archives, concatenated. */
std::string two_streams(const char * method) {
  std::string first;
  std::string second;
  if (pack(method, {{"first.txt", "one"}}, &first) != GARC_OK) {
    return {};
  }
  if (pack(method, {{"second.txt", "two"}}, &second) != GARC_OK) {
    return {};
  }
  return first + second;
}

} // namespace

TEST(Codec, ConcatenatedMembersAreRefusedWhereTheCodecStopsAtTheFirst) {
  // Measured against compress 0.0.0: gzip, lz4 and zlib stop after one member
  // and leave the rest unconsumed, so ignoring the remainder would hand back
  // the first archive and call it the whole thing. RFC 1952 allows the
  // concatenation and `cat a.gz b.gz` produces it, which is why this is a
  // refusal and not a theoretical case.
  for (const char * method : {"gzip", "lz4", "zlib"}) {
    SCOPED_TRACE(method);
    const std::string both = two_streams(method);
    ASSERT_FALSE(both.empty());
    std::vector<Recovered> got;
    EXPECT_EQ(GARC_ERR_CORRUPT, unpack(method, both, &got));
  }
}

TEST(Codec, ConcatenatedFramesAreReadWhereTheCodecReadsThemAll) {
  // zstd is the exception, and the asymmetry is asserted rather than described:
  // if compress ever makes gzip read a second member, the test above fails and
  // this one says what the new behaviour should look like.
  const std::string both = two_streams("zstd");
  ASSERT_FALSE(both.empty());
  std::vector<Recovered> got;
  // Both members come back, and that is two deliberate behaviours meeting
  // rather than one accident. zstd consumes every frame, so the decompressing
  // stream yields both tars end to end; and the reader records an
  // end-of-archive marker but decides the end from what *follows* it, because a
  // writer's trailing padding is often stripped and a reader that insisted on
  // the second zero block would reject those archives (src/tar/tar_read.c says
  // so where it does it). So the two tars read as one archive of two members.
  EXPECT_EQ(GARC_OK, unpack("zstd", both, &got));
  ASSERT_EQ(2u, got.size());
  EXPECT_EQ("first.txt", got[0].name);
  EXPECT_EQ("second.txt", got[1].name);
}

TEST(Codec, TheCodecsOwnOutputCapIsItsOwnStatus) {
  // compress's decoder caps its output (512 MiB by default). A cap in another
  // library is still a cap a caller might raise, so it has a status of its own
  // rather than sharing GARC_ERR_LIMIT_TOTAL_BYTES - which lives in
  // GARC_Limits, where raising it would change nothing.
  std::string packed;
  ASSERT_EQ(GARC_OK, pack("gzip", big_entries(), &packed));

  gcomp_options_t * options = nullptr;
  ASSERT_EQ(GCOMP_OK, gcomp_options_create(&options));
  ASSERT_EQ(GCOMP_OK,
      gcomp_options_set_uint64(options, "limits.max_output_bytes", 4096));

  GARC_Stream * file = nullptr;
  ASSERT_EQ(GARC_OK,
      garc_stream_create_memory(packed.data(), packed.size(), &file));
  GARC_Stream * plain = nullptr;
  ASSERT_EQ(GARC_OK,
      garc_stream_create_decompress(file, "gzip", options, &plain));

  GARC_Result result = GARC_OK;
  size_t total = 0;
  for (;;) {
    char buffer[4096];
    size_t read = 0;
    result = garc_stream_read(plain, buffer, sizeof(buffer), &read);
    if (result != GARC_OK || !read) {
      break;
    }
    total += read;
  }
  EXPECT_EQ(GARC_ERR_LIMIT_CODEC_BYTES, result);
  EXPECT_TRUE(garc_result_is_limit(result));
  EXPECT_FALSE(garc_result_is_limit(GARC_ERR_CORRUPT));
  EXPECT_LT(total, 310000u) << "the cap did not stop anything";

  garc_stream_destroy(plain);
  garc_stream_destroy(file);
  gcomp_options_destroy(options);
}

////////////////////////////////////////////////////////////////////////
// Refusals and bad arguments
////////////////////////////////////////////////////////////////////////

TEST(Codec, CorruptCompressedBytesAreReported) {
  std::string packed;
  ASSERT_EQ(GARC_OK, pack("gzip", small_entries(), &packed));
  ASSERT_GT(packed.size(), 20u);
  // Into the deflate data rather than the header, so the failure is the codec
  // rejecting the stream rather than refusing to start.
  packed[packed.size() / 2] = static_cast<char>(packed[packed.size() / 2] ^ 0xFF);
  std::vector<Recovered> got;
  EXPECT_TRUE(garc_result_is_error(unpack("gzip", packed, &got)));
}

TEST(Codec, AMethodCompressDoesNotHaveIsUnsupported) {
  GARC_Sink * file = nullptr;
  ASSERT_EQ(GARC_OK, garc_sink_create_memory(&file));
  GARC_Sink * packer = nullptr;
  EXPECT_EQ(GARC_ERR_UNSUPPORTED,
      garc_sink_create_compress(file, "no-such-codec", nullptr, &packer));
  EXPECT_EQ(nullptr, packer);
  garc_sink_destroy(file);

  GARC_Stream * stream = nullptr;
  ASSERT_EQ(GARC_OK, garc_stream_create_memory("", 0, &stream));
  GARC_Stream * plain = nullptr;
  EXPECT_EQ(GARC_ERR_UNSUPPORTED,
      garc_stream_create_decompress(stream, "no-such-codec", nullptr, &plain));
  EXPECT_EQ(nullptr, plain);
  garc_stream_destroy(stream);
}

TEST(Codec, NullArgumentsAreRefused) {
  GARC_Sink * sink = nullptr;
  GARC_Stream * stream = nullptr;
  GARC_Sink * memory = nullptr;
  ASSERT_EQ(GARC_OK, garc_sink_create_memory(&memory));
  GARC_Stream * source = nullptr;
  ASSERT_EQ(GARC_OK, garc_stream_create_memory("", 0, &source));

  EXPECT_EQ(GARC_ERR_INVALID,
      garc_sink_create_compress(nullptr, "gzip", nullptr, &sink));
  EXPECT_EQ(GARC_ERR_INVALID,
      garc_sink_create_compress(memory, nullptr, nullptr, &sink));
  EXPECT_EQ(GARC_ERR_INVALID,
      garc_sink_create_compress(memory, "gzip", nullptr, nullptr));
  EXPECT_EQ(GARC_ERR_INVALID,
      garc_stream_create_decompress(nullptr, "gzip", nullptr, &stream));
  EXPECT_EQ(GARC_ERR_INVALID,
      garc_stream_create_decompress(source, nullptr, nullptr, &stream));
  EXPECT_EQ(GARC_ERR_INVALID,
      garc_stream_create_decompress(source, "gzip", nullptr, nullptr));

  garc_stream_destroy(source);
  garc_sink_destroy(memory);
}

TEST(Codec, ADecompressingStreamHasNeitherSeekNorSize) {
  // Not a refusal this file implements: seek and size are optional callbacks and
  // a codec stream supplies neither, which is the same shape as a pipe. It is
  // also why a compressed tar can never gain an index.
  std::string packed;
  ASSERT_EQ(GARC_OK, pack("gzip", small_entries(), &packed));
  GARC_Stream * file = nullptr;
  ASSERT_EQ(GARC_OK,
      garc_stream_create_memory(packed.data(), packed.size(), &file));
  GARC_Stream * plain = nullptr;
  ASSERT_EQ(GARC_OK,
      garc_stream_create_decompress(file, "gzip", nullptr, &plain));

  EXPECT_EQ(GARC_ERR_UNSUPPORTED, garc_stream_seek(plain, 0));
  uint64_t size = 0;
  EXPECT_EQ(GARC_ERR_UNSUPPORTED, garc_stream_size(plain, &size));

  // And the reader walks it anyway.
  std::vector<Recovered> got;
  ASSERT_EQ(GARC_OK, unpack("gzip", packed, &got));
  EXPECT_EQ(2u, got.size());

  garc_stream_destroy(plain);
  garc_stream_destroy(file);
}

TEST(Codec, AFailingSourceIsReported) {
  std::string packed;
  ASSERT_EQ(GARC_OK, pack("gzip", small_entries(), &packed));
  garctest::BufferSource source(packed.data(), packed.size(), false, false);
  GARC_Stream * file = nullptr;
  ASSERT_EQ(GARC_OK, garc_stream_create_callback(source.callbacks(), &file));
  GARC_Stream * plain = nullptr;
  ASSERT_EQ(GARC_OK,
      garc_stream_create_decompress(file, "gzip", nullptr, &plain));
  source.fail_reads(1);
  char buffer[64];
  size_t read = 0;
  EXPECT_EQ(GARC_ERR_IO, garc_stream_read(plain, buffer, sizeof(buffer), &read));
  garc_stream_destroy(plain);
  garc_stream_destroy(file);
}

TEST(Codec, AZeroSizedReadIsAnsweredBeforeTheCodecSeesIt) {
  // garc_stream_read() answers a zero-length read itself, so this pins the
  // behaviour a caller sees rather than a guard inside the codec - which is why
  // there is no such guard: it would be a line nothing could reach.
  std::string packed;
  ASSERT_EQ(GARC_OK, pack("gzip", small_entries(), &packed));
  GARC_Stream * file = nullptr;
  ASSERT_EQ(GARC_OK,
      garc_stream_create_memory(packed.data(), packed.size(), &file));
  GARC_Stream * plain = nullptr;
  ASSERT_EQ(GARC_OK,
      garc_stream_create_decompress(file, "gzip", nullptr, &plain));
  size_t read = 1;
  EXPECT_EQ(GARC_OK, garc_stream_read(plain, nullptr, 0, &read));
  EXPECT_EQ(0u, read);
  garc_stream_destroy(plain);
  garc_stream_destroy(file);
}

////////////////////////////////////////////////////////////////////////
// Allocation failure
////////////////////////////////////////////////////////////////////////

TEST(Codec, EveryAllocationOnTheWayToASinkCanFail) {
  // One request at a time rather than all of them, because failing every
  // allocation cannot tell a leak on the second path from one on the third.
  GARC_Sink * file = nullptr;
  ASSERT_EQ(GARC_OK, garc_sink_create_memory(&file));
  for (size_t nth = 0; nth < 4; ++nth) {
    SCOPED_TRACE(nth);
    FailingAllocator allocator(nth);
    GARC_Sink * packer = nullptr;
    const GARC_Result result = garc_sink_create_compress_with_allocator(
        file, "gzip", nullptr, allocator.get(), &packer);
    if (result == GARC_OK) {
      garc_sink_destroy(packer);
    } else {
      EXPECT_EQ(GARC_ERR_OOM, result);
      EXPECT_EQ(nullptr, packer);
    }
    EXPECT_EQ(0u, allocator.live()) << "leaked on request " << nth;
  }
  garc_sink_destroy(file);
}

TEST(Codec, EveryAllocationOnTheWayToAStreamCanFail) {
  GARC_Stream * file = nullptr;
  ASSERT_EQ(GARC_OK, garc_stream_create_memory("", 0, &file));
  for (size_t nth = 0; nth < 4; ++nth) {
    SCOPED_TRACE(nth);
    FailingAllocator allocator(nth);
    GARC_Stream * plain = nullptr;
    const GARC_Result result = garc_stream_create_decompress_with_allocator(
        file, "gzip", nullptr, allocator.get(), &plain);
    if (result == GARC_OK) {
      garc_stream_destroy(plain);
    } else {
      EXPECT_EQ(GARC_ERR_OOM, result);
      EXPECT_EQ(nullptr, plain);
    }
    EXPECT_EQ(0u, allocator.live()) << "leaked on request " << nth;
  }
  garc_stream_destroy(file);
}

////////////////////////////////////////////////////////////////////////
// The status table
////////////////////////////////////////////////////////////////////////

TEST(Codec, EveryCompressStatusMapsToSomethingChosen) {
  // Enumerated rather than sampled. Three of these rows are all the public API
  // can provoke, and the other five would be a wrong status arriving silently -
  // GCOMP_ERR_MEMORY reported as an internal error rather than GARC_ERR_OOM is a
  // caller who retries instead of freeing something.
  EXPECT_EQ(GARC_OK, garc_codec_result(GCOMP_OK));
  EXPECT_EQ(GARC_ERR_INVALID, garc_codec_result(GCOMP_ERR_INVALID_ARG));
  EXPECT_EQ(GARC_ERR_OOM, garc_codec_result(GCOMP_ERR_MEMORY));
  EXPECT_EQ(GARC_ERR_LIMIT_CODEC_BYTES, garc_codec_result(GCOMP_ERR_LIMIT));
  EXPECT_EQ(GARC_ERR_CORRUPT, garc_codec_result(GCOMP_ERR_CORRUPT));
  EXPECT_EQ(GARC_ERR_UNSUPPORTED, garc_codec_result(GCOMP_ERR_UNSUPPORTED));
  EXPECT_EQ(GARC_ERR_INTERNAL, garc_codec_result(GCOMP_ERR_INTERNAL));
  EXPECT_EQ(GARC_ERR_IO, garc_codec_result(GCOMP_ERR_IO));
}

TEST(Codec, NoCompressStatusMapsToEndOrToALimitThatIsNotItsOwn) {
  // Two claims about the table as a whole rather than about a row. GARC_END is
  // not a failure, so a codec failure mapped onto it would be read as the end of
  // an archive; and the only cap a codec can report is its own.
  for (int i = 0; i <= GCOMP_ERR_IO; ++i) {
    const gcomp_status_t status = static_cast<gcomp_status_t>(i);
    const GARC_Result result = garc_codec_result(status);
    SCOPED_TRACE(i);
    EXPECT_NE(GARC_END, result);
    if (garc_result_is_limit(result)) {
      EXPECT_EQ(GARC_ERR_LIMIT_CODEC_BYTES, result);
    }
    EXPECT_EQ(status == GCOMP_OK, result == GARC_OK);
  }
}

////////////////////////////////////////////////////////////////////////
// Two arms the round trips do not reach
////////////////////////////////////////////////////////////////////////

TEST(Codec, ReadingPastTheEndKeepsReturningZero) {
  // A caller that reads once more after the end should get another zero rather
  // than a failure or a restarted decoder.
  std::string packed;
  ASSERT_EQ(GARC_OK, pack("gzip", small_entries(), &packed));
  GARC_Stream * file = nullptr;
  ASSERT_EQ(GARC_OK,
      garc_stream_create_memory(packed.data(), packed.size(), &file));
  GARC_Stream * plain = nullptr;
  ASSERT_EQ(GARC_OK,
      garc_stream_create_decompress(file, "gzip", nullptr, &plain));
  char buffer[4096];
  size_t read = 0;
  do {
    ASSERT_EQ(GARC_OK, garc_stream_read(plain, buffer, sizeof(buffer), &read));
  } while (read);
  for (int i = 0; i < 3; ++i) {
    read = 1;
    EXPECT_EQ(GARC_OK, garc_stream_read(plain, buffer, sizeof(buffer), &read));
    EXPECT_EQ(0u, read);
  }
  garc_stream_destroy(plain);
  garc_stream_destroy(file);
}

TEST(Codec, AFailingInnerSinkDuringTheDataIsReported) {
  // Distinct from the failure during finish(): this is the write of a codec
  // block in the middle of a member, which is the arm the small archives never
  // reach because they produce no output until finish.
  BufferDrain drain;
  GARC_Sink * file = nullptr;
  ASSERT_EQ(GARC_OK, garc_sink_create_callback(drain.callbacks(), &file));
  GARC_Sink * packer = nullptr;
  ASSERT_EQ(GARC_OK, garc_sink_create_compress(file, "gzip", nullptr, &packer));
  drain.fail_writes(1);
  // Large enough that the encoder hands over a block before the archive ends.
  EXPECT_EQ(GARC_ERR_IO, write_tar(packer, big_entries()));
  garc_sink_destroy(packer);
  garc_sink_destroy(file);
}

////////////////////////////////////////////////////////////////////////
// The refusal a compressed archive cannot leave
////////////////////////////////////////////////////////////////////////

TEST(Codec, FindRefusesACompressedArchiveBecauseItCannotBeRewound) {
  // The item phase C owed, and the reason it waited for a garc_find to refuse
  // on. A codec stream has no seek, so there is no way back to the start and no
  // index to consult instead - and the refusal has a status of its own rather
  // than being GARC_ERR_UNSUPPORTED, because finding is implemented and it is
  // *this stream* that cannot do it.
  const std::vector<Entry> entries = small_entries();
  for (const char * method : kMethods) {
    SCOPED_TRACE(method);
    std::string packed;
    ASSERT_EQ(GARC_OK, pack(method, entries, &packed));

    GARC_Stream * file = nullptr;
    ASSERT_EQ(GARC_OK,
        garc_stream_create_memory(packed.data(), packed.size(), &file));
    // The *inner* stream is a memory stream and seeks perfectly well. That is
    // the point of checking here: what refuses is the decompressing wrapper, so
    // a caller cannot get random access by handing over a seekable file.
    EXPECT_TRUE(garc_stream_is_seekable(file));

    GARC_Stream * plain = nullptr;
    ASSERT_EQ(GARC_OK,
        garc_stream_create_decompress(file, method, nullptr, &plain));
    EXPECT_FALSE(garc_stream_is_seekable(plain));

    GARC_Archive * archive = nullptr;
    ASSERT_EQ(GARC_OK, garc_open(plain, nullptr, &archive));
    const GARC_Member * found = nullptr;
    EXPECT_EQ(GARC_ERR_NOT_SEEKABLE,
        garc_find(archive, "notes/hello.txt", 15, &found));
    EXPECT_EQ(nullptr, found);

    // And the refusal moved nothing: the walk still starts at the first member.
    const GARC_Member * member = nullptr;
    ASSERT_EQ(GARC_OK, garc_next(archive, &member));
    EXPECT_EQ("notes/hello.txt",
        std::string(member->name, member->name_length));

    garc_close(archive);
    garc_stream_destroy(plain);
    garc_stream_destroy(file);
  }
}

TEST(Codec, TheSameArchiveUncompressedIsFindable) {
  // The other half of the claim. Without this the refusal above would pass just
  // as well if garc_find() refused everything.
  const std::string plain = plain_tar(small_entries());
  ASSERT_FALSE(plain.empty());
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(GARC_OK,
      garc_stream_create_memory(plain.data(), plain.size(), &stream));
  GARC_Archive * archive = nullptr;
  ASSERT_EQ(GARC_OK, garc_open(stream, nullptr, &archive));
  const GARC_Member * found = nullptr;
  ASSERT_EQ(GARC_OK, garc_find(archive, "notes/empty.txt", 15, &found));
  ASSERT_NE(nullptr, found);
  EXPECT_EQ("notes/empty.txt", std::string(found->name, found->name_length));
  garc_close(archive);
  garc_stream_destroy(stream);
}

int main(int argc, char ** argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
