/**
 * @file
 *
 * libFuzzer harness for the tar reader.
 *
 * **The first byte is an options byte**, as every harness in the suite spells it.
 * Here it chooses the stream shape, the caps, and whether each member's data is
 * read or skipped - so one harness covers the pipe and the file, the default caps
 * and caps tight enough to fire, and both cursor disciplines. A harness that
 * always read from memory with the default caps would leave the discard loop, the
 * limit arms and the skip path unexplored while reporting coverage of the parser.
 *
 * The invariants, each of which a wrong answer can satisfy by accident on one
 * input and not across a corpus:
 *
 * - Every result is one the header documents. A status from nowhere is a bug
 *   even when nothing crashes.
 * - The offset never goes backwards, and never exceeds the input.
 * - A member's data never yields more bytes than the member declared. This is
 *   the one that catches a reader leaking the next header into a caller's buffer.
 * - The declared total never exceeds the cap while calls are succeeding, and the
 *   member count never exceeds max_members.
 * - A refusal is final in the sense that matters: after a failure there is no
 *   current member, so read_member must refuse too.
 *
 * Build with: make fuzz-tar
 * Run:        make fuzz-run-tar FUZZ_TIME=300
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

[[noreturn]] void broken(const char * what) {
  std::fprintf(stderr, "tar invariant broken: %s\n", what);
  std::abort();
}

#define REQUIRE(cond, what)                                                    \
  do {                                                                         \
    if (!(cond)) {                                                             \
      broken(what);                                                            \
    }                                                                          \
  } while (0)

/** A callback source over a buffer, with seekability and known-size as flags. */
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

/** Whether a result is one garc_next() or garc_read_member() documents. */
bool documented(GARC_Result result) {
  switch (result) {
    case GARC_OK:
    case GARC_END:
    case GARC_ERR_IO:
    case GARC_ERR_FORMAT:
    case GARC_ERR_UNSUPPORTED:
    case GARC_ERR_CORRUPT:
    case GARC_ERR_OOM:
    case GARC_ERR_INVALID:
    case GARC_ERR_LIMIT_MEMBERS:
    case GARC_ERR_LIMIT_MEMBER_BYTES:
    case GARC_ERR_LIMIT_TOTAL_BYTES:
    case GARC_ERR_LIMIT_NAME_BYTES:
    case GARC_ERR_LIMIT_EXTRA_BYTES:
      return true;
    // GARC_ERR_INTERNAL is deliberately absent. It means this library's own
    // invariant failed, which no input should be able to cause - so reaching it
    // is a finding rather than a documented answer.
    default:
      return false;
  }
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  if (size < 2) {
    return 0;
  }

  const uint8_t options = data[0];
  const bool memory = (options & 0x01u) != 0;
  const bool seekable = (options & 0x02u) != 0;
  const bool sized = (options & 0x04u) != 0;
  const bool read_data = (options & 0x08u) != 0;
  const bool tight_caps = (options & 0x10u) != 0;
  const bool starve = (options & 0x20u) != 0;
  const size_t fail_at = (options >> 6) & 0x03u;

  const uint8_t * body = data + 1;
  const size_t body_size = size - 1;

  GARC_Limits limits;
  garc_limits_default(&limits);
  if (tight_caps) {
    // Small enough that a plausible archive reaches them. The default caps are
    // sized to stop a bomb, so no input a fuzzer builds in a second gets near
    // them - which would leave every limit arm unexplored.
    limits.max_members = 4;
    limits.max_member_bytes = 4096;
    limits.max_total_bytes = 8192;
    limits.max_name_bytes = 64;
  }

  garctest::FailingAllocator allocator(
      starve ? fail_at : static_cast<size_t>(-1));

  Source source{body, body_size, 0};
  GARC_Stream_Callbacks callbacks{};
  callbacks.ctx = &source;
  callbacks.read = &source_read;
  callbacks.seek = seekable ? &source_seek : nullptr;
  callbacks.size = sized ? &source_size : nullptr;

  GARC_Stream * stream = nullptr;
  GARC_Result created = memory
      ? garc_stream_create_memory(body, body_size, &stream)
      : garc_stream_create_callback(&callbacks, &stream);
  if (created != GARC_OK) {
    return 0;
  }

  GARC_Archive * archive = nullptr;
  GARC_Result opened = garc_open_with_allocator(
      stream, &limits, allocator.get(), &archive);
  if (opened != GARC_OK) {
    REQUIRE(documented(opened), "open returned a status it does not document");
    REQUIRE(archive == nullptr, "a failed open handed back an archive");
    allocator.stop_failing();
    garc_stream_destroy(stream);
    REQUIRE(allocator.live() == 0u, "a failed open leaked");
    return 0;
  }
  REQUIRE(archive != nullptr, "open succeeded without producing an archive");

  uint64_t last_offset = 0;
  const GARC_Member * member = nullptr;
  GARC_Result result;
  int budget = 4096; // So that a long archive cannot become a timeout.

  while (budget-- > 0 && (result = garc_next(archive, &member)) == GARC_OK) {
    REQUIRE(member != nullptr, "GARC_OK without a member");
    REQUIRE(member->name != nullptr, "a member with no name pointer");

    const uint64_t offset = garc_stream_tell(stream);
    REQUIRE(offset >= last_offset, "the offset went backwards");
    REQUIRE(offset <= body_size, "the offset passed the end of the input");
    last_offset = offset;

    REQUIRE(garc_member_count(archive) <= limits.max_members,
        "the member count passed max_members");
    REQUIRE(garc_total_declared_bytes(archive) <= limits.max_total_bytes,
        "the declared total passed max_total_bytes");
    REQUIRE(member->size <= limits.max_member_bytes,
        "a member passed max_member_bytes");
    REQUIRE(member->name_length <= limits.max_name_bytes,
        "a name passed max_name_bytes");

    if (read_data) {
      uint64_t produced = 0;
      uint8_t buffer[97]; // Not a divisor of a block, so the last read is short.
      for (;;) {
        size_t got = 0;
        GARC_Result read = garc_read_member(
            archive, buffer, sizeof(buffer), &got);
        if (read != GARC_OK) {
          REQUIRE(documented(read),
              "read_member returned a status it does not document");
          break;
        }
        if (!got) {
          break;
        }
        produced += got;
        // The one that catches a reader leaking the next header's bytes into the
        // caller's buffer as file contents.
        REQUIRE(produced <= member->size,
            "read_member produced more than the member declared");
      }
    }
  }

  if (budget >= 0) {
    REQUIRE(documented(result), "next returned a status it does not document");
    if (result != GARC_OK && result != GARC_END) {
      // After a failure there is no current member, so a caller that ignores the
      // status cannot be handed bytes belonging to a member never reported.
      uint8_t buffer[16];
      size_t got = 0;
      REQUIRE(garc_read_member(archive, buffer, sizeof(buffer), &got)
              == GARC_ERR_INVALID,
          "read_member served bytes after a failed next");
    }
  }

  allocator.stop_failing();
  garc_close(archive);
  garc_stream_destroy(stream);
  REQUIRE(allocator.live() == 0u, "close left a block behind");
  return 0;
}
