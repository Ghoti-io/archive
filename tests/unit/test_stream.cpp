/**
 * @file
 *
 * The byte stream every reader will read through.
 *
 * Two things these tests are careful about. The four combinations of
 * seekable/not and known-size/not are each exercised, because a suite that
 * only uses a memory stream tests one of the four and a caller reading from a
 * pipe has another. And a short read and a read *failure* are asserted
 * separately: the first is the end of the stream and the second is a failure
 * to reach it, and a stream that folds them together makes a truncated archive
 * and a broken disk look alike.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "test_helpers.h"

using garctest::BufferSource;
using garctest::FailingAllocator;

namespace {

/** Sixteen distinguishable bytes, so an off-by-one in an offset shows up. */
std::vector<uint8_t> sample() {
  std::vector<uint8_t> bytes(16);
  for (size_t i = 0; i < bytes.size(); ++i) {
    bytes[i] = static_cast<uint8_t>(0x10 + i);
  }
  return bytes;
}

} // namespace

//-----------------------------------------------------------------------------
// Construction
//-----------------------------------------------------------------------------

TEST(StreamCreate, MemoryRejectsANullOutput) {
  std::vector<uint8_t> bytes = sample();
  EXPECT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), nullptr),
      GARC_ERR_INVALID);
}

TEST(StreamCreate, MemoryRejectsNullDataWithANonZeroSize) {
  GARC_Stream * stream = nullptr;
  EXPECT_EQ(garc_stream_create_memory(nullptr, 8, &stream), GARC_ERR_INVALID);
  EXPECT_EQ(stream, nullptr);
}

TEST(StreamCreate, MemoryAcceptsNullDataWithAZeroSize) {
  // An empty archive is a real input, and a caller with nothing to read should
  // not have to invent a one-byte buffer to say so.
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_memory(nullptr, 0, &stream), GARC_OK);
  ASSERT_NE(stream, nullptr);

  uint64_t size = 1;
  EXPECT_EQ(garc_stream_size(stream, &size), GARC_OK);
  EXPECT_EQ(size, 0u);
  garc_stream_destroy(stream);
}

TEST(StreamCreate, CallbackRequiresARead) {
  // seek and size are optional and their absence is a property. read is not
  // optional, because without it there is no stream.
  GARC_Stream_Callbacks callbacks{};
  GARC_Stream * stream = nullptr;
  EXPECT_EQ(garc_stream_create_callback(&callbacks, &stream),
      GARC_ERR_INVALID);
  EXPECT_EQ(garc_stream_create_callback(nullptr, &stream), GARC_ERR_INVALID);
  EXPECT_EQ(stream, nullptr);
}

TEST(StreamCreate, CallbackCopiesTheCallbacksStruct) {
  // The header promises the struct need not outlive the call. A stream holding
  // a pointer to it instead would work in every test that keeps the struct
  // alive, which is every test written without thinking about it.
  std::vector<uint8_t> bytes = sample();
  BufferSource source(bytes.data(), bytes.size(), true, true);

  GARC_Stream * stream = nullptr;
  {
    GARC_Stream_Callbacks scratch = *source.callbacks();
    ASSERT_EQ(garc_stream_create_callback(&scratch, &stream), GARC_OK);
    std::memset(&scratch, 0, sizeof(scratch));
  }

  uint8_t buffer[4] = {0};
  EXPECT_EQ(garc_stream_read_exact(stream, buffer, sizeof(buffer)), GARC_OK);
  EXPECT_EQ(buffer[0], 0x10);
  garc_stream_destroy(stream);
}

TEST(StreamCreate, ReportsOutOfMemory) {
  std::vector<uint8_t> bytes = sample();
  FailingAllocator allocator(0);
  GARC_Stream * stream = nullptr;
  EXPECT_EQ(garc_stream_create_memory_with_allocator(
                bytes.data(), bytes.size(), allocator.get(), &stream),
      GARC_ERR_OOM);
  EXPECT_EQ(stream, nullptr);
  EXPECT_TRUE(allocator.failed());
  EXPECT_EQ(allocator.live(), 0u);
}

TEST(StreamCreate, TheCallbackConstructorReportsOutOfMemoryToo) {
  // Both constructors allocate, so both have this arm; testing it on one of
  // them leaves the other's untested, and the coverage report is how that was
  // noticed rather than a reader spotting the asymmetry.
  std::vector<uint8_t> bytes = sample();
  BufferSource source(bytes.data(), bytes.size(), true, true);
  FailingAllocator allocator(0);
  GARC_Stream * stream = nullptr;
  EXPECT_EQ(garc_stream_create_callback_with_allocator(
                source.callbacks(), allocator.get(), &stream),
      GARC_ERR_OOM);
  EXPECT_EQ(stream, nullptr);
  EXPECT_TRUE(allocator.failed());
  EXPECT_EQ(allocator.live(), 0u);
}

TEST(StreamCreate, FreesThroughTheAllocatorItWasGiven) {
  std::vector<uint8_t> bytes = sample();
  FailingAllocator allocator(static_cast<size_t>(-1));
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_memory_with_allocator(
                bytes.data(), bytes.size(), allocator.get(), &stream),
      GARC_OK);
  EXPECT_EQ(allocator.live(), 1u);
  garc_stream_destroy(stream);
  EXPECT_EQ(allocator.live(), 0u);
}

TEST(StreamCreate, DestroyIgnoresNull) {
  garc_stream_destroy(nullptr);
}

//-----------------------------------------------------------------------------
// Properties
//-----------------------------------------------------------------------------

TEST(StreamProperties, MemoryIsSeekableAndKnowsItsSize) {
  std::vector<uint8_t> bytes = sample();
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
      GARC_OK);

  EXPECT_TRUE(garc_stream_is_seekable(stream));
  uint64_t size = 0;
  EXPECT_EQ(garc_stream_size(stream, &size), GARC_OK);
  EXPECT_EQ(size, bytes.size());
  garc_stream_destroy(stream);
}

TEST(StreamProperties, EachOfTheFourCallbackShapesReportsItself) {
  std::vector<uint8_t> bytes = sample();
  for (int seekable = 0; seekable <= 1; ++seekable) {
    for (int sized = 0; sized <= 1; ++sized) {
      BufferSource source(
          bytes.data(), bytes.size(), seekable != 0, sized != 0);
      GARC_Stream * stream = nullptr;
      ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream),
          GARC_OK)
          << "seekable=" << seekable << " sized=" << sized;

      EXPECT_EQ(garc_stream_is_seekable(stream) != 0, seekable != 0);

      uint64_t size = 0;
      GARC_Result result = garc_stream_size(stream, &size);
      if (sized) {
        EXPECT_EQ(result, GARC_OK);
        EXPECT_EQ(size, bytes.size());
      } else {
        // Not zero. A stream of no bytes and a stream of unknown length are
        // different facts, and one integer cannot carry both.
        EXPECT_EQ(result, GARC_ERR_UNSUPPORTED);
      }
      garc_stream_destroy(stream);
    }
  }
}

TEST(StreamProperties, NullIsAnsweredWithoutCrashing) {
  EXPECT_EQ(garc_stream_tell(nullptr), 0u);
  EXPECT_FALSE(garc_stream_is_seekable(nullptr));
  uint64_t size = 0;
  EXPECT_EQ(garc_stream_size(nullptr, &size), GARC_ERR_INVALID);
}

TEST(StreamProperties, SizeRejectsANullOutput) {
  std::vector<uint8_t> bytes = sample();
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
      GARC_OK);
  EXPECT_EQ(garc_stream_size(stream, nullptr), GARC_ERR_INVALID);
  garc_stream_destroy(stream);
}

//-----------------------------------------------------------------------------
// Reading
//-----------------------------------------------------------------------------

TEST(StreamRead, AdvancesTellByWhatItRead) {
  std::vector<uint8_t> bytes = sample();
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
      GARC_OK);

  uint8_t buffer[6] = {0};
  size_t got = 0;
  ASSERT_EQ(garc_stream_read(stream, buffer, sizeof(buffer), &got), GARC_OK);
  EXPECT_EQ(got, sizeof(buffer));
  EXPECT_EQ(garc_stream_tell(stream), sizeof(buffer));
  EXPECT_EQ(buffer[0], 0x10);
  EXPECT_EQ(buffer[5], 0x15);
  garc_stream_destroy(stream);
}

TEST(StreamRead, AShortReadAtTheEndIsNotAnError) {
  std::vector<uint8_t> bytes = sample();
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
      GARC_OK);
  ASSERT_EQ(garc_stream_seek(stream, bytes.size() - 3), GARC_OK);

  uint8_t buffer[8] = {0};
  size_t got = 99;
  EXPECT_EQ(garc_stream_read(stream, buffer, sizeof(buffer), &got), GARC_OK);
  EXPECT_EQ(got, 3u);
  EXPECT_EQ(garc_stream_tell(stream), bytes.size());

  // And again at the end: zero bytes, still not an error.
  got = 99;
  EXPECT_EQ(garc_stream_read(stream, buffer, sizeof(buffer), &got), GARC_OK);
  EXPECT_EQ(got, 0u);
  garc_stream_destroy(stream);
}

TEST(StreamRead, AZeroLengthReadDoesNotReachTheCallback) {
  std::vector<uint8_t> bytes = sample();
  BufferSource source(bytes.data(), bytes.size(), true, true);
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK);

  size_t got = 99;
  EXPECT_EQ(garc_stream_read(stream, nullptr, 0, &got), GARC_OK);
  EXPECT_EQ(got, 0u);
  EXPECT_EQ(source.reads(), 0u);
  garc_stream_destroy(stream);
}

TEST(StreamRead, RejectsBadArguments) {
  std::vector<uint8_t> bytes = sample();
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
      GARC_OK);

  uint8_t buffer[4] = {0};
  size_t got = 0;
  EXPECT_EQ(garc_stream_read(nullptr, buffer, sizeof(buffer), &got),
      GARC_ERR_INVALID);
  EXPECT_EQ(garc_stream_read(stream, buffer, sizeof(buffer), nullptr),
      GARC_ERR_INVALID);
  EXPECT_EQ(garc_stream_read(stream, nullptr, 4, &got), GARC_ERR_INVALID);
  // Nothing was consumed by any of those.
  EXPECT_EQ(garc_stream_tell(stream), 0u);
  garc_stream_destroy(stream);
}

TEST(StreamRead, ACallbackFailureIsNotAShortRead) {
  std::vector<uint8_t> bytes = sample();
  BufferSource source(bytes.data(), bytes.size(), true, true);
  source.fail_reads(1);
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK);

  uint8_t buffer[4] = {0};
  size_t got = 99;
  EXPECT_EQ(garc_stream_read(stream, buffer, sizeof(buffer), &got),
      GARC_ERR_IO);
  // The offset did not move, so a caller retrying reads the same bytes.
  EXPECT_EQ(garc_stream_tell(stream), 0u);
  garc_stream_destroy(stream);
}

TEST(StreamRead, ACallbackClaimingMoreThanItWasAskedForIsRefused) {
  // Nothing legitimate does this; the check exists so that a bad callback
  // fails where it is, rather than moving the offset past bytes it never
  // wrote and surfacing as a truncated archive later.
  GARC_Stream_Callbacks callbacks{};
  callbacks.read = &garctest::overclaiming_read;
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_callback(&callbacks, &stream), GARC_OK);

  uint8_t buffer[4] = {0};
  size_t got = 0;
  EXPECT_EQ(garc_stream_read(stream, buffer, sizeof(buffer), &got),
      GARC_ERR_INTERNAL);
  EXPECT_EQ(garc_stream_tell(stream), 0u);
  garc_stream_destroy(stream);
}

//-----------------------------------------------------------------------------
// read_exact
//-----------------------------------------------------------------------------

TEST(StreamReadExact, ReassemblesAcrossShortReads) {
  // A callback is allowed to serve less than it was asked for, and a header is
  // a fixed number of bytes. This is the loop every parser would otherwise
  // write, so it is written once here.
  std::vector<uint8_t> bytes = sample();
  BufferSource source(bytes.data(), bytes.size(), false, false);
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK);

  uint8_t buffer[16] = {0};
  ASSERT_EQ(garc_stream_read_exact(stream, buffer, sizeof(buffer)), GARC_OK);
  EXPECT_EQ(std::memcmp(buffer, bytes.data(), bytes.size()), 0);
  EXPECT_EQ(garc_stream_tell(stream), bytes.size());
  garc_stream_destroy(stream);
}

TEST(StreamReadExact, AStreamEndingInsideTheStructureIsCorrupt) {
  // Not GARC_ERR_IO: the stream did what it was asked and there were no more
  // bytes. The archive said there was a header here and there is not.
  std::vector<uint8_t> bytes = sample();
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
      GARC_OK);

  uint8_t buffer[32] = {0};
  EXPECT_EQ(garc_stream_read_exact(stream, buffer, sizeof(buffer)),
      GARC_ERR_CORRUPT);
  garc_stream_destroy(stream);
}

TEST(StreamReadExact, ForwardsAReadFailureAsIo) {
  std::vector<uint8_t> bytes = sample();
  BufferSource source(bytes.data(), bytes.size(), true, true);
  source.fail_reads(1);
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK);

  uint8_t buffer[4] = {0};
  EXPECT_EQ(garc_stream_read_exact(stream, buffer, sizeof(buffer)),
      GARC_ERR_IO);
  garc_stream_destroy(stream);
}

TEST(StreamReadExact, ZeroBytesSucceedsAndRejectsBadArguments) {
  std::vector<uint8_t> bytes = sample();
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
      GARC_OK);

  EXPECT_EQ(garc_stream_read_exact(stream, nullptr, 0), GARC_OK);
  EXPECT_EQ(garc_stream_read_exact(nullptr, nullptr, 0), GARC_ERR_INVALID);
  uint8_t buffer[4] = {0};
  EXPECT_EQ(garc_stream_read_exact(stream, nullptr, 4), GARC_ERR_INVALID);
  EXPECT_EQ(garc_stream_read_exact(nullptr, buffer, 4), GARC_ERR_INVALID);
  garc_stream_destroy(stream);
}

//-----------------------------------------------------------------------------
// Seeking
//-----------------------------------------------------------------------------

TEST(StreamSeek, LandsWhereItWasAskedAndTheEndIsLegal) {
  std::vector<uint8_t> bytes = sample();
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
      GARC_OK);

  ASSERT_EQ(garc_stream_seek(stream, 9), GARC_OK);
  EXPECT_EQ(garc_stream_tell(stream), 9u);
  uint8_t byte = 0;
  ASSERT_EQ(garc_stream_read_exact(stream, &byte, 1), GARC_OK);
  EXPECT_EQ(byte, 0x19);

  // Exactly the end is where a completed read leaves the stream, so seeking
  // there has to be allowed.
  EXPECT_EQ(garc_stream_seek(stream, bytes.size()), GARC_OK);
  EXPECT_EQ(garc_stream_tell(stream), bytes.size());

  // One past it is not.
  EXPECT_EQ(garc_stream_seek(stream, bytes.size() + 1), GARC_ERR_IO);
  garc_stream_destroy(stream);
}

TEST(StreamSeek, AFailedSeekLeavesTheOffsetAlone) {
  std::vector<uint8_t> bytes = sample();
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
      GARC_OK);
  ASSERT_EQ(garc_stream_seek(stream, 4), GARC_OK);

  EXPECT_EQ(garc_stream_seek(stream, bytes.size() + 100), GARC_ERR_IO);
  EXPECT_EQ(garc_stream_tell(stream), 4u);
  garc_stream_destroy(stream);
}

TEST(StreamSeek, ANonSeekableStreamRefusesRatherThanFailing) {
  // GARC_ERR_UNSUPPORTED, not GARC_ERR_IO: the stream is not broken, it
  // cannot do this. zip needs to tell those apart before it starts.
  std::vector<uint8_t> bytes = sample();
  BufferSource source(bytes.data(), bytes.size(), false, true);
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK);

  EXPECT_FALSE(garc_stream_is_seekable(stream));
  EXPECT_EQ(garc_stream_seek(stream, 4), GARC_ERR_UNSUPPORTED);
  EXPECT_EQ(garc_stream_tell(stream), 0u);
  garc_stream_destroy(stream);
}

TEST(StreamSeek, RejectsNull) {
  EXPECT_EQ(garc_stream_seek(nullptr, 0), GARC_ERR_INVALID);
}

//-----------------------------------------------------------------------------
// Skipping
//-----------------------------------------------------------------------------

TEST(StreamSkip, SeeksWhenItCanAndReadsWhenItCannot) {
  // The same skip, over the same bytes, on a stream that can seek and one that
  // cannot. Both must land in the same place; only one of them moves bytes.
  std::vector<uint8_t> bytes = sample();

  BufferSource seekable(bytes.data(), bytes.size(), true, true);
  GARC_Stream * a = nullptr;
  ASSERT_EQ(garc_stream_create_callback(seekable.callbacks(), &a), GARC_OK);
  ASSERT_EQ(garc_stream_skip(a, 12), GARC_OK);
  EXPECT_EQ(garc_stream_tell(a), 12u);
  EXPECT_EQ(seekable.bytes_read(), 0u);
  EXPECT_EQ(seekable.seeks(), 1u);

  BufferSource pipe(bytes.data(), bytes.size(), false, false);
  GARC_Stream * b = nullptr;
  ASSERT_EQ(garc_stream_create_callback(pipe.callbacks(), &b), GARC_OK);
  ASSERT_EQ(garc_stream_skip(b, 12), GARC_OK);
  EXPECT_EQ(garc_stream_tell(b), 12u);
  EXPECT_EQ(pipe.bytes_read(), 12u);

  // And the next byte is the same one either way, which is the assertion that
  // makes the two paths interchangeable rather than merely both successful.
  uint8_t from_a = 0;
  uint8_t from_b = 0;
  ASSERT_EQ(garc_stream_read_exact(a, &from_a, 1), GARC_OK);
  ASSERT_EQ(garc_stream_read_exact(b, &from_b, 1), GARC_OK);
  EXPECT_EQ(from_a, 0x1C);
  EXPECT_EQ(from_b, 0x1C);

  garc_stream_destroy(a);
  garc_stream_destroy(b);
}

TEST(StreamSkip, SkippingPastTheEndIsCorruptWhereTheEndIsKnowable) {
  // Three of the four shapes can say so, and this asserts which three rather
  // than asserting the same thing four times. The seekable-and-sized one is
  // the trap: an ordinary file lets you seek past its end, so without the size
  // check it would succeed here and fail at the next read instead - a long way
  // from the lying length that caused it.
  std::vector<uint8_t> bytes = sample();
  for (int seekable = 0; seekable <= 1; ++seekable) {
    for (int sized = 0; sized <= 1; ++sized) {
      BufferSource source(
          bytes.data(), bytes.size(), seekable != 0, sized != 0);
      GARC_Stream * stream = nullptr;
      ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream),
          GARC_OK);
      GARC_Result result = garc_stream_skip(stream, bytes.size() + 1);
      if (sized || !seekable) {
        EXPECT_EQ(result, GARC_ERR_CORRUPT)
            << "seekable=" << seekable << " sized=" << sized;
      } else {
        // Seekable with no size: the library has nothing to check the target
        // against, so the answer is this source's seek refusing.
        EXPECT_EQ(result, GARC_ERR_IO);
      }
      garc_stream_destroy(stream);
    }
  }
}

TEST(StreamSkip, AnAcceptingSeekWithNoSizeDefersTheTruncationToTheNextRead) {
  // The one gap skip cannot close, asserted rather than left implicit: a source
  // that both seeks and does not know its length is taken at its word, exactly
  // as lseek() past the end of a file is. The truncation is still caught - at
  // the read, as GARC_ERR_CORRUPT - and supplying a size callback is what moves
  // the report back to the skip.
  std::vector<uint8_t> bytes = sample();
  BufferSource source(bytes.data(), bytes.size(), true, false);
  source.allow_seek_past_end();
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK);

  EXPECT_EQ(garc_stream_skip(stream, bytes.size() + 4), GARC_OK);
  EXPECT_EQ(garc_stream_tell(stream), bytes.size() + 4);

  uint8_t byte = 0;
  EXPECT_EQ(garc_stream_read_exact(stream, &byte, 1), GARC_ERR_CORRUPT);
  garc_stream_destroy(stream);
}

TEST(StreamSkip, AMemoryStreamSkipPastTheEndIsCorrupt) {
  std::vector<uint8_t> bytes = sample();
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
      GARC_OK);
  EXPECT_EQ(garc_stream_skip(stream, bytes.size() + 1), GARC_ERR_CORRUPT);
  garc_stream_destroy(stream);
}

TEST(StreamSkip, ALengthThatOverflowsTheOffsetIsCorrupt) {
  // A container declaring a size that wraps the 64-bit offset is lying, and
  // wrapping round to a plausible offset would hide it.
  std::vector<uint8_t> bytes = sample();
  BufferSource source(bytes.data(), bytes.size(), false, false);
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK);

  uint8_t byte = 0;
  ASSERT_EQ(garc_stream_read_exact(stream, &byte, 1), GARC_OK);
  EXPECT_EQ(garc_stream_skip(stream, UINT64_MAX), GARC_ERR_CORRUPT);
  garc_stream_destroy(stream);
}

TEST(StreamSkip, SkippingNothingIsFreeAndSucceeds) {
  std::vector<uint8_t> bytes = sample();
  BufferSource source(bytes.data(), bytes.size(), true, true);
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK);

  EXPECT_EQ(garc_stream_skip(stream, 0), GARC_OK);
  EXPECT_EQ(garc_stream_tell(stream), 0u);
  EXPECT_EQ(source.reads(), 0u);
  EXPECT_EQ(source.seeks(), 0u);
  garc_stream_destroy(stream);
}

TEST(StreamSkip, SkipsMoreThanOneChunkOnANonSeekableStream) {
  // The discard loop runs in 4 KiB chunks, so a skip inside one chunk never
  // exercises the loop at all.
  std::vector<uint8_t> bytes(10000, 0x5A);
  BufferSource source(bytes.data(), bytes.size(), false, false);
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK);

  ASSERT_EQ(garc_stream_skip(stream, 9999), GARC_OK);
  EXPECT_EQ(garc_stream_tell(stream), 9999u);
  EXPECT_GT(source.reads(), 2u);
  garc_stream_destroy(stream);
}

TEST(StreamSkip, ForwardsAFailureFromEitherPath) {
  std::vector<uint8_t> bytes = sample();

  // A failing seek on a seekable stream.
  BufferSource seekable(bytes.data(), bytes.size(), true, true);
  seekable.fail_seeks();
  GARC_Stream * a = nullptr;
  ASSERT_EQ(garc_stream_create_callback(seekable.callbacks(), &a), GARC_OK);
  EXPECT_EQ(garc_stream_skip(a, 4), GARC_ERR_IO);
  EXPECT_EQ(garc_stream_tell(a), 0u);
  garc_stream_destroy(a);

  // A failing read on one that has to discard.
  BufferSource pipe(bytes.data(), bytes.size(), false, false);
  pipe.fail_reads(1);
  GARC_Stream * b = nullptr;
  ASSERT_EQ(garc_stream_create_callback(pipe.callbacks(), &b), GARC_OK);
  EXPECT_EQ(garc_stream_skip(b, 4), GARC_ERR_IO);
  garc_stream_destroy(b);
}

TEST(StreamSkip, AFailingSizeCallbackIsForwardedRatherThanIgnored) {
  // skip asks for the size before it does anything. A source that cannot answer
  // is not the same as one that has no size callback at all: the first is a
  // failure and the second is a property, and skipping silently past the
  // failure would turn an I/O error into an unchecked length.
  std::vector<uint8_t> bytes = sample();
  BufferSource source(bytes.data(), bytes.size(), true, true);
  source.fail_size();
  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK);

  EXPECT_EQ(garc_stream_skip(stream, 4), GARC_ERR_IO);
  EXPECT_EQ(garc_stream_tell(stream), 0u);
  // And garc_stream_size() forwards it as well, rather than reporting
  // "unsupported", which would say the stream cannot answer when it failed to.
  uint64_t size = 0;
  EXPECT_EQ(garc_stream_size(stream, &size), GARC_ERR_IO);
  garc_stream_destroy(stream);
}

TEST(StreamSkip, WhereAFailedSkipLeavesTheOffsetDependsOnTheShape) {
  // Found by the fuzz harness on its first run, which asserted one rule for
  // both paths. A seekable stream is restored; a non-seekable one has already
  // consumed what it read and reports how far it got, which is where the
  // archive ran out. Asserted here so the asymmetry is a decision on the record
  // rather than whatever the code happens to do.
  std::vector<uint8_t> bytes = sample();

  BufferSource seekable(bytes.data(), bytes.size(), true, true);
  GARC_Stream * a = nullptr;
  ASSERT_EQ(garc_stream_create_callback(seekable.callbacks(), &a), GARC_OK);
  ASSERT_EQ(garc_stream_skip(a, 4), GARC_OK);
  EXPECT_EQ(garc_stream_skip(a, 100), GARC_ERR_CORRUPT);
  EXPECT_EQ(garc_stream_tell(a), 4u);
  garc_stream_destroy(a);

  BufferSource pipe(bytes.data(), bytes.size(), false, false);
  GARC_Stream * b = nullptr;
  ASSERT_EQ(garc_stream_create_callback(pipe.callbacks(), &b), GARC_OK);
  ASSERT_EQ(garc_stream_skip(b, 4), GARC_OK);
  EXPECT_EQ(garc_stream_skip(b, 100), GARC_ERR_CORRUPT);
  EXPECT_EQ(garc_stream_tell(b), bytes.size());
  garc_stream_destroy(b);
}

TEST(StreamSkip, RejectsNull) {
  EXPECT_EQ(garc_stream_skip(nullptr, 1), GARC_ERR_INVALID);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
