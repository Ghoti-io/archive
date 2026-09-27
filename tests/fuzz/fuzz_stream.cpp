/**
 * @file
 *
 * libFuzzer harness for the byte stream.
 *
 * There is no format parser yet, so what this fuzzes is the thing every parser
 * will sit on: the read, skip and seek path, over all four shapes of stream a
 * caller can supply. That is worth fuzzing on its own account, because the
 * shapes are where the arithmetic is - a 64-bit offset, a declared length that
 * may exceed the stream, and a discard loop - and a parser reached through only
 * the memory shape would exercise one of the four.
 *
 * **The first byte is an options byte**, as every harness in the suite spells
 * it, and here it chooses the stream shape and the operation programme. That is
 * what lets one harness cover the seekable and non-seekable paths rather than
 * whichever one the constructor happened to pick.
 *
 * The invariants asserted, each of which a wrong answer can satisfy by
 * accident on a single input and not across a corpus:
 *
 * - `tell` never exceeds the stream's size on a stream that reports one, unless
 *   a seek put it there deliberately.
 * - `tell` advances by exactly what `read` reported.
 * - A failing read or seek moves nothing, and a failing skip moves nothing on a
 *   seekable stream and no further than it was asked on one that cannot seek.
 *   That asymmetry is not a wart the harness tolerates - the harness is what
 *   found it, on its first run, by asserting one rule for both paths.
 * - `read_exact` of n bytes either succeeds having produced n, or fails.
 *
 * Build with: make fuzz-stream
 * Run:        make fuzz-run-stream FUZZ_TIME=300
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <ghoti.io/archive/archive.h>

#include "../failing_allocator.h"

namespace {

/** Report a broken invariant and stop, so libFuzzer records the input. */
[[noreturn]] void broken(const char * what) {
  std::fprintf(stderr, "stream invariant broken: %s\n", what);
  std::abort();
}

#define REQUIRE(cond, what)                                                    \
  do {                                                                         \
    if (!(cond)) {                                                             \
      broken(what);                                                            \
    }                                                                          \
  } while (0)

/**
 * A callback source over a buffer, with seekability and known-size as flags.
 *
 * A near-twin of tests/test_helpers.h's BufferSource, and deliberately not
 * shared with it: that one is C++ with gtest's conventions around it and holds
 * counters the harness has no use for, and this one has to stay free of
 * anything that allocates on a path the fuzzer measures.
 */
struct Source {
  const uint8_t * data;
  size_t size;
  size_t pos;
};

GARC_Result source_read(
    void * ctx, void * buffer, size_t size, size_t * out_read) {
  Source * self = static_cast<Source *>(ctx);
  size_t remaining = self->pos < self->size ? self->size - self->pos : 0;
  size_t take = size < remaining ? size : remaining;
  if (take) {
    std::memcpy(buffer, self->data + self->pos, take);
    self->pos += take;
  }
  *out_read = take;
  return GARC_OK;
}

GARC_Result source_seek(void * ctx, uint64_t offset) {
  Source * self = static_cast<Source *>(ctx);
  if (offset > self->size) {
    return GARC_ERR_IO;
  }
  self->pos = static_cast<size_t>(offset);
  return GARC_OK;
}

GARC_Result source_size(void * ctx, uint64_t * out_size) {
  const Source * self = static_cast<const Source *>(ctx);
  *out_size = self->size;
  return GARC_OK;
}

/** Read a little-endian 64-bit value from the programme, or zero past its end. */
uint64_t take_u64(const uint8_t *& cursor, const uint8_t * end) {
  uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    uint8_t byte = cursor < end ? *cursor++ : 0u;
    value |= static_cast<uint64_t>(byte) << (8 * i);
  }
  return value;
}

/** Run one operation programme against one stream, checking the invariants. */
void exercise(GARC_Stream * stream, const uint8_t * programme,
    const uint8_t * end, bool sized, uint64_t total) {
  uint8_t scratch[64];
  int budget = 256; // So that a long programme cannot become a timeout.

  while (programme < end && budget-- > 0) {
    uint8_t op = *programme++;
    uint64_t before = garc_stream_tell(stream);

    switch (op & 0x03u) {
      case 0: { // read
        size_t want = static_cast<size_t>(op >> 2) % (sizeof(scratch) + 1u);
        size_t got = 12345;
        GARC_Result result = garc_stream_read(stream, scratch, want, &got);
        if (result == GARC_OK) {
          REQUIRE(got <= want, "read produced more than was asked for");
          REQUIRE(garc_stream_tell(stream) == before + got,
              "tell did not advance by what read reported");
        } else {
          REQUIRE(garc_stream_tell(stream) == before,
              "a failed read moved the offset");
        }
        break;
      }
      case 1: { // read_exact
        size_t want = static_cast<size_t>(op >> 2) % (sizeof(scratch) + 1u);
        GARC_Result result = garc_stream_read_exact(stream, scratch, want);
        if (result == GARC_OK) {
          REQUIRE(garc_stream_tell(stream) == before + want,
              "read_exact succeeded without producing every byte");
        }
        break;
      }
      case 2: { // skip
        uint64_t count = take_u64(programme, end);
        GARC_Result result = garc_stream_skip(stream, count);
        if (result == GARC_OK) {
          REQUIRE(garc_stream_tell(stream) == before + count,
              "a successful skip landed somewhere else");
          if (sized) {
            REQUIRE(garc_stream_tell(stream) <= total,
                "a successful skip went past a known end");
          }
        } else {
          // A seekable stream is left where it was; a non-seekable one has
          // already consumed what it read and cannot put it back, so all that
          // can be asked of it is that it did not overshoot. stream.h says so.
          if (garc_stream_is_seekable(stream)) {
            REQUIRE(garc_stream_tell(stream) == before,
                "a failed skip moved a seekable stream's offset");
          } else {
            // `before + count` is the bound, and computing it directly wraps
            // for the count the library refuses precisely because it overflows.
            // The harness reported that wrap as an overshoot on its second run:
            // the check has to do the arithmetic the way the library does, or
            // it accuses correct code.
            uint64_t bound = count > UINT64_MAX - before
                ? UINT64_MAX
                : before + count;
            REQUIRE(garc_stream_tell(stream) >= before
                    && garc_stream_tell(stream) <= bound,
                "a failed skip overshot what it was asked to skip");
          }
        }
        break;
      }
      default: { // seek
        uint64_t offset = take_u64(programme, end);
        GARC_Result result = garc_stream_seek(stream, offset);
        if (result == GARC_OK) {
          REQUIRE(garc_stream_tell(stream) == offset,
              "a successful seek landed somewhere else");
        } else {
          REQUIRE(garc_stream_tell(stream) == before,
              "a failed seek moved the offset");
        }
        break;
      }
    }
  }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  if (size < 2) {
    return 0;
  }

  const uint8_t options = data[0];
  const bool seekable = (options & 0x01u) != 0;
  const bool sized = (options & 0x02u) != 0;
  const bool memory = (options & 0x04u) != 0;
  // The nth allocation is refused when the options byte asks for it, so the
  // OOM arm is walked by the same corpus rather than by a separate campaign.
  const bool starve = (options & 0x08u) != 0;
  const size_t fail_at = (options >> 4) & 0x0Fu;

  // The rest splits into the bytes the stream serves and the programme that
  // drives it. Half each, so that neither is starved on a short input.
  const uint8_t * body = data + 1;
  const size_t body_size = size - 1;
  const size_t served = body_size / 2u;

  garctest::FailingAllocator allocator(
      starve ? fail_at : static_cast<size_t>(-1));

  Source source{body, served, 0};
  GARC_Stream_Callbacks callbacks{};
  callbacks.ctx = &source;
  callbacks.read = &source_read;
  callbacks.seek = seekable ? &source_seek : nullptr;
  callbacks.size = sized ? &source_size : nullptr;

  GARC_Stream * stream = nullptr;
  GARC_Result created = memory
      ? garc_stream_create_memory_with_allocator(
            body, served, allocator.get(), &stream)
      : garc_stream_create_callback_with_allocator(
            &callbacks, allocator.get(), &stream);

  if (created != GARC_OK) {
    REQUIRE(stream == nullptr, "a failed create handed back a stream");
    REQUIRE(created == GARC_ERR_OOM || created == GARC_ERR_INVALID,
        "create failed for a reason it does not document");
    return 0;
  }
  REQUIRE(stream != nullptr, "create succeeded without producing a stream");

  // A memory stream is always seekable and always sized, whatever the options
  // byte said, and the harness has to agree with the library about which shape
  // it is looking at or every invariant below is checked against the wrong one.
  const bool is_sized = memory ? true : sized;
  uint64_t total = 0;
  if (is_sized) {
    REQUIRE(garc_stream_size(stream, &total) == GARC_OK,
        "a sized stream refused to report its size");
    REQUIRE(total == served, "a stream reported a size it was not given");
  } else {
    REQUIRE(garc_stream_size(stream, &total) == GARC_ERR_UNSUPPORTED,
        "an unsized stream answered with a size");
  }
  REQUIRE(garc_stream_is_seekable(stream) == (memory || seekable ? 1 : 0),
      "a stream disagreed about whether it can seek");

  exercise(stream, body + served, data + size, is_sized, total);

  allocator.stop_failing();
  garc_stream_destroy(stream);
  REQUIRE(allocator.live() == 0u, "destroy left a block behind");
  return 0;
}
