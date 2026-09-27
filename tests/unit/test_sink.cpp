/**
 * @file
 *
 * The byte sink every writer writes through.
 *
 * Two things these tests are careful about, and both are the read side's
 * asymmetries rather than restatements of it.
 *
 * **A failed write must leave the count alone.** A sink's offset is what a
 * writer computes padding from, so a write that failed and advanced the count
 * anyway produces an archive padded to the wrong boundary - which every reader
 * then reports as a corrupt header a long way from the cause. Every failure
 * arm here asserts ::garc_sink_tell() as well as the status.
 *
 * **Growth is asserted through the allocator, not through the bytes.** A memory
 * sink that reallocated on every write and one that doubled hand back identical
 * bytes, so the bytes cannot tell them apart; the request count can. The same
 * instrument is what puts the exact-size retry in a position to fail, which is
 * the one arm a sink with room to spare never reaches.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "test_helpers.h"

using garctest::BufferDrain;
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

/** What a memory sink holds, as a vector, for comparison. */
std::vector<uint8_t> collected(const GARC_Sink * sink) {
  const void * data = nullptr;
  size_t size = 0;
  if (garc_sink_data(sink, &data, &size) != GARC_OK) {
    return {};
  }
  const uint8_t * bytes = static_cast<const uint8_t *>(data);
  return std::vector<uint8_t>(bytes, bytes + size);
}

} // namespace

//-----------------------------------------------------------------------------
// Construction
//-----------------------------------------------------------------------------

TEST(SinkCreate, MemoryRejectsANullOutput) {
  EXPECT_EQ(garc_sink_create_memory(nullptr), GARC_ERR_INVALID);
}

TEST(SinkCreate, CallbackRejectsANullOutput) {
  BufferDrain drain;
  EXPECT_EQ(garc_sink_create_callback(drain.callbacks(), nullptr),
      GARC_ERR_INVALID);
}

TEST(SinkCreate, CallbackRejectsNullCallbacks) {
  GARC_Sink * sink = nullptr;
  EXPECT_EQ(garc_sink_create_callback(nullptr, &sink), GARC_ERR_INVALID);
  EXPECT_EQ(sink, nullptr);
}

TEST(SinkCreate, CallbackRejectsAMissingWrite) {
  // write is the whole interface, so its absence is not a property the way a
  // stream's missing seek is - there would be nothing left.
  GARC_Sink_Callbacks callbacks{};
  callbacks.ctx = nullptr;
  callbacks.write = nullptr;
  GARC_Sink * sink = nullptr;
  EXPECT_EQ(garc_sink_create_callback(&callbacks, &sink), GARC_ERR_INVALID);
  EXPECT_EQ(sink, nullptr);
}

TEST(SinkCreate, AMemorySinkAllocatesNothingUntilItIsWrittenTo) {
  FailingAllocator allocator(static_cast<size_t>(-1));
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory_with_allocator(allocator.get(), &sink),
      GARC_OK);
  // One block: the sink object. The buffer is not among them.
  EXPECT_EQ(allocator.requests(), 1u);
  EXPECT_EQ(allocator.live(), 1u);
  garc_sink_destroy(sink);
  EXPECT_EQ(allocator.live(), 0u);
}

TEST(SinkCreate, AMemorySinkReportsAllocationFailure) {
  FailingAllocator allocator(0);
  GARC_Sink * sink = nullptr;
  EXPECT_EQ(garc_sink_create_memory_with_allocator(allocator.get(), &sink),
      GARC_ERR_OOM);
  EXPECT_EQ(sink, nullptr);
  EXPECT_EQ(allocator.live(), 0u);
}

TEST(SinkCreate, ACallbackSinkReportsAllocationFailure) {
  BufferDrain drain;
  FailingAllocator allocator(0);
  GARC_Sink * sink = nullptr;
  EXPECT_EQ(garc_sink_create_callback_with_allocator(
                drain.callbacks(), allocator.get(), &sink),
      GARC_ERR_OOM);
  EXPECT_EQ(sink, nullptr);
  EXPECT_EQ(allocator.live(), 0u);
}

TEST(SinkCreate, TheCallbacksStructNeedNotOutliveTheCall) {
  // Copied at create, so a caller may build it on the stack. ctx is borrowed
  // and does have to outlive the sink, which is why the drain does.
  BufferDrain drain;
  GARC_Sink * sink = nullptr;
  {
    GARC_Sink_Callbacks copy = *drain.callbacks();
    ASSERT_EQ(garc_sink_create_callback(&copy, &sink), GARC_OK);
    std::memset(&copy, 0, sizeof(copy));
  }
  std::vector<uint8_t> bytes = sample();
  EXPECT_EQ(garc_sink_write(sink, bytes.data(), bytes.size()), GARC_OK);
  EXPECT_EQ(drain.bytes(), bytes);
  garc_sink_destroy(sink);
}

//-----------------------------------------------------------------------------
// Writing
//-----------------------------------------------------------------------------

TEST(SinkWrite, AMemorySinkKeepsWhatItIsGiven) {
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  std::vector<uint8_t> bytes = sample();
  EXPECT_EQ(garc_sink_write(sink, bytes.data(), bytes.size()), GARC_OK);
  EXPECT_EQ(garc_sink_tell(sink), bytes.size());
  EXPECT_EQ(collected(sink), bytes);
  garc_sink_destroy(sink);
}

TEST(SinkWrite, WritesAppendInOrder) {
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  ASSERT_EQ(garc_sink_write(sink, "abc", 3), GARC_OK);
  ASSERT_EQ(garc_sink_write(sink, "de", 2), GARC_OK);
  const void * data = nullptr;
  size_t size = 0;
  ASSERT_EQ(garc_sink_data(sink, &data, &size), GARC_OK);
  EXPECT_EQ(std::string(static_cast<const char *>(data), size), "abcde");
  EXPECT_EQ(garc_sink_tell(sink), 5u);
  garc_sink_destroy(sink);
}

TEST(SinkWrite, RejectsANullSink) {
  std::vector<uint8_t> bytes = sample();
  EXPECT_EQ(garc_sink_write(nullptr, bytes.data(), bytes.size()),
      GARC_ERR_INVALID);
}

TEST(SinkWrite, RejectsNullDataWithANonZeroSize) {
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  EXPECT_EQ(garc_sink_write(sink, nullptr, 8), GARC_ERR_INVALID);
  EXPECT_EQ(garc_sink_tell(sink), 0u);
  garc_sink_destroy(sink);
}

TEST(SinkWrite, AZeroLengthWriteNeverReachesTheCallback) {
  // Not merely "returns OK": a callback wrapping write(2) would see a zero-byte
  // write as a no-op and one wrapping something else might not, so the library
  // promises not to make the call at all.
  BufferDrain drain;
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_callback(drain.callbacks(), &sink), GARC_OK);
  EXPECT_EQ(garc_sink_write(sink, nullptr, 0), GARC_OK);
  EXPECT_EQ(garc_sink_write(sink, "x", 0), GARC_OK);
  EXPECT_EQ(drain.writes(), 0u);
  EXPECT_EQ(garc_sink_tell(sink), 0u);
  garc_sink_destroy(sink);
}

TEST(SinkWrite, ACallbackSinkPassesTheBytesStraightThrough) {
  BufferDrain drain;
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_callback(drain.callbacks(), &sink), GARC_OK);
  std::vector<uint8_t> bytes = sample();
  EXPECT_EQ(garc_sink_write(sink, bytes.data(), bytes.size()), GARC_OK);
  EXPECT_EQ(drain.writes(), 1u);
  EXPECT_EQ(drain.bytes(), bytes);
  EXPECT_EQ(garc_sink_tell(sink), bytes.size());
  garc_sink_destroy(sink);
}

TEST(SinkWrite, AFailedWriteLeavesTheOffsetWhereItWas) {
  BufferDrain drain;
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_callback(drain.callbacks(), &sink), GARC_OK);
  ASSERT_EQ(garc_sink_write(sink, "abc", 3), GARC_OK);
  drain.fail_writes(1);
  EXPECT_EQ(garc_sink_write(sink, "de", 2), GARC_ERR_IO);
  // The offset is what a writer pads from. Counting a refused write would pad
  // the next member to the wrong boundary and every reader would report the
  // damage at the header after it.
  EXPECT_EQ(garc_sink_tell(sink), 3u);
  // And the sink is still usable, which is what makes the offset worth trusting.
  EXPECT_EQ(garc_sink_write(sink, "de", 2), GARC_OK);
  EXPECT_EQ(garc_sink_tell(sink), 5u);
  EXPECT_EQ(drain.bytes(),
      std::vector<uint8_t>({'a', 'b', 'c', 'd', 'e'}));
  garc_sink_destroy(sink);
}

//-----------------------------------------------------------------------------
// Growth
//-----------------------------------------------------------------------------

TEST(SinkGrowth, AMemorySinkGrowsAndKeepsEverything) {
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  // Well past the first allocation, in small pieces, so that a growth that
  // dropped or duplicated a tail shows up as a wrong byte rather than a wrong
  // length.
  std::vector<uint8_t> expected;
  for (size_t i = 0; i < 4000; ++i) {
    uint8_t byte = static_cast<uint8_t>(i * 7u);
    ASSERT_EQ(garc_sink_write(sink, &byte, 1), GARC_OK);
    expected.push_back(byte);
  }
  EXPECT_EQ(garc_sink_tell(sink), expected.size());
  EXPECT_EQ(collected(sink), expected);
  garc_sink_destroy(sink);
}

TEST(SinkGrowth, GrowthIsGeometricRatherThanOnceAWrite) {
  // The bytes cannot tell these apart, so the allocator is the instrument. A
  // sink reallocating per write would ask 20001 times.
  FailingAllocator allocator(static_cast<size_t>(-1));
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory_with_allocator(allocator.get(), &sink),
      GARC_OK);
  uint8_t byte = 0x5A;
  for (size_t i = 0; i < 20000; ++i) {
    ASSERT_EQ(garc_sink_write(sink, &byte, 1), GARC_OK);
  }
  // The object, plus one allocation per doubling from 10240: 10240, 20480.
  EXPECT_EQ(allocator.requests(), 3u);
  garc_sink_destroy(sink);
  EXPECT_EQ(allocator.live(), 0u);
}

TEST(SinkGrowth, ARefusedDoublingRetriesAtTheExactSize) {
  // The arm a sink with room to spare never reaches, and the reason the retry
  // is not merely an overflow guard: an overflow-only fallback needs a host
  // holding SIZE_MAX bytes and so is a line no test can put in a position to
  // fail. Refusing the geometric request alone leaves the exact one, which is
  // smaller, and the write succeeds.
  FailingAllocator allocator(1, 1);
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory_with_allocator(allocator.get(), &sink),
      GARC_OK);
  std::vector<uint8_t> bytes = sample();
  EXPECT_EQ(garc_sink_write(sink, bytes.data(), bytes.size()), GARC_OK);
  EXPECT_TRUE(allocator.failed());
  EXPECT_EQ(collected(sink), bytes);
  // Exactly the bytes asked for were reserved, so the next write reallocs again.
  size_t before = allocator.requests();
  EXPECT_EQ(garc_sink_write(sink, bytes.data(), bytes.size()), GARC_OK);
  EXPECT_GT(allocator.requests(), before);
  allocator.stop_failing();
  garc_sink_destroy(sink);
  EXPECT_EQ(allocator.live(), 0u);
}

TEST(SinkGrowth, BothCapacitiesRefusedIsOutOfMemory) {
  // run = 2 is what it takes to fail one logical append, because the retry
  // makes it cost two requests. run = 1 cannot fail it at all, which is the
  // previous test.
  FailingAllocator allocator(1, 2);
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory_with_allocator(allocator.get(), &sink),
      GARC_OK);
  std::vector<uint8_t> bytes = sample();
  EXPECT_EQ(garc_sink_write(sink, bytes.data(), bytes.size()), GARC_ERR_OOM);
  // Nothing was kept, and the offset did not move.
  EXPECT_EQ(garc_sink_tell(sink), 0u);
  allocator.stop_failing();
  EXPECT_TRUE(collected(sink).empty());
  garc_sink_destroy(sink);
  EXPECT_EQ(allocator.live(), 0u);
}

TEST(SinkGrowth, AWriteThatFitsAsksForNothing) {
  FailingAllocator allocator(static_cast<size_t>(-1));
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory_with_allocator(allocator.get(), &sink),
      GARC_OK);
  ASSERT_EQ(garc_sink_write(sink, "abc", 3), GARC_OK);
  size_t after_first = allocator.requests();
  ASSERT_EQ(garc_sink_write(sink, "de", 2), GARC_OK);
  EXPECT_EQ(allocator.requests(), after_first);
  garc_sink_destroy(sink);
  EXPECT_EQ(allocator.live(), 0u);
}

//-----------------------------------------------------------------------------
// Fill
//-----------------------------------------------------------------------------

TEST(SinkFill, ZeroIsASuccessfulNoOp) {
  // "Pad to a boundary you are already on" is the common case, not a special
  // one: a member whose size is a multiple of 512 needs no padding at all.
  BufferDrain drain;
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_callback(drain.callbacks(), &sink), GARC_OK);
  EXPECT_EQ(garc_sink_fill(sink, 0, 0), GARC_OK);
  EXPECT_EQ(drain.writes(), 0u);
  EXPECT_EQ(garc_sink_tell(sink), 0u);
  garc_sink_destroy(sink);
}

TEST(SinkFill, WritesTheByteAsked) {
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  ASSERT_EQ(garc_sink_fill(sink, 0xAB, 3), GARC_OK);
  EXPECT_EQ(collected(sink), std::vector<uint8_t>({0xAB, 0xAB, 0xAB}));
  garc_sink_destroy(sink);
}

TEST(SinkFill, SpansMoreThanOneChunk) {
  // 512 is the chunk, so 1200 crosses it twice and ends part way through the
  // third - which is where a loop that wrote a whole chunk each time would
  // overshoot.
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  ASSERT_EQ(garc_sink_fill(sink, 0x00, 1200), GARC_OK);
  EXPECT_EQ(garc_sink_tell(sink), 1200u);
  std::vector<uint8_t> got = collected(sink);
  ASSERT_EQ(got.size(), 1200u);
  EXPECT_EQ(std::count(got.begin(), got.end(), 0x00), 1200);
  garc_sink_destroy(sink);
}

TEST(SinkFill, AFailurePartWayThroughStopsAndReportsIt) {
  BufferDrain drain;
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_callback(drain.callbacks(), &sink), GARC_OK);
  drain.fail_writes(1);
  EXPECT_EQ(garc_sink_fill(sink, 0, 1200), GARC_ERR_IO);
  EXPECT_EQ(garc_sink_tell(sink), 0u);
  // Stopped at the first refusal rather than running the whole loop and
  // reporting the last answer, which would write 688 bytes after the failure.
  EXPECT_EQ(drain.writes(), 1u);
  EXPECT_TRUE(drain.bytes().empty());
  garc_sink_destroy(sink);
}

TEST(SinkFill, AFailureAfterTheFirstChunkKeepsWhatWentBefore) {
  BufferDrain drain;
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_callback(drain.callbacks(), &sink), GARC_OK);
  ASSERT_EQ(garc_sink_write(sink, "abc", 3), GARC_OK);
  drain.fail_writes(1);
  EXPECT_EQ(garc_sink_fill(sink, 0, 4), GARC_ERR_IO);
  EXPECT_EQ(garc_sink_tell(sink), 3u);
  garc_sink_destroy(sink);
}

TEST(SinkFill, RejectsANullSink) {
  EXPECT_EQ(garc_sink_fill(nullptr, 0, 4), GARC_ERR_INVALID);
}

//-----------------------------------------------------------------------------
// Borrowing the bytes
//-----------------------------------------------------------------------------

TEST(SinkData, AnUnwrittenMemorySinkLendsANonNullPointerAndAZeroLength) {
  // So that a caller need not special-case an empty archive - and so that a
  // NULL return can keep meaning failure.
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  const void * data = nullptr;
  size_t size = 1;
  EXPECT_EQ(garc_sink_data(sink, &data, &size), GARC_OK);
  EXPECT_NE(data, nullptr);
  EXPECT_EQ(size, 0u);
  garc_sink_destroy(sink);
}

TEST(SinkData, ACallbackSinkHasNoBytesToLend) {
  // GARC_ERR_UNSUPPORTED rather than an empty buffer: a sink holding no bytes
  // and a sink that never holds any are different facts.
  BufferDrain drain;
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_callback(drain.callbacks(), &sink), GARC_OK);
  ASSERT_EQ(garc_sink_write(sink, "abc", 3), GARC_OK);
  const void * data = nullptr;
  size_t size = 0;
  EXPECT_EQ(garc_sink_data(sink, &data, &size), GARC_ERR_UNSUPPORTED);
  garc_sink_destroy(sink);
}

TEST(SinkData, RejectsNullArguments) {
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  const void * data = nullptr;
  size_t size = 0;
  EXPECT_EQ(garc_sink_data(nullptr, &data, &size), GARC_ERR_INVALID);
  EXPECT_EQ(garc_sink_data(sink, nullptr, &size), GARC_ERR_INVALID);
  EXPECT_EQ(garc_sink_data(sink, &data, nullptr), GARC_ERR_INVALID);
  garc_sink_destroy(sink);
}

//-----------------------------------------------------------------------------
// Lifetime
//-----------------------------------------------------------------------------

TEST(SinkDestroy, NullIsIgnored) {
  garc_sink_destroy(nullptr);
}

TEST(SinkTell, NullIsZero) {
  EXPECT_EQ(garc_sink_tell(nullptr), 0u);
}

TEST(SinkDestroy, ACallbackSinksContextIsNotTouched) {
  // A sink that closed what its callback wraps would be a sink a caller cannot
  // use twice, so the drain is still good for a second one.
  BufferDrain drain;
  GARC_Sink * first = nullptr;
  ASSERT_EQ(garc_sink_create_callback(drain.callbacks(), &first), GARC_OK);
  ASSERT_EQ(garc_sink_write(first, "ab", 2), GARC_OK);
  garc_sink_destroy(first);

  GARC_Sink * second = nullptr;
  ASSERT_EQ(garc_sink_create_callback(drain.callbacks(), &second), GARC_OK);
  ASSERT_EQ(garc_sink_write(second, "cd", 2), GARC_OK);
  garc_sink_destroy(second);

  EXPECT_EQ(drain.bytes(), std::vector<uint8_t>({'a', 'b', 'c', 'd'}));
  // And each sink counts its own bytes, rather than where the drain is.
  EXPECT_EQ(drain.writes(), 2u);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
