/**
 * @file
 *
 * libFuzzer harness for the ar and cpio readers.
 *
 * **The first byte is an options byte**, as every harness in the suite spells it:
 * the caps (default or tight), whether each member's data is read or skipped,
 * whether an allocation fails, and **whether the stream can seek**. Both formats
 * are streams and are read from pipes, where the identification window has to
 * be drained into the first member's data; a harness that only used the memory
 * stream would never run that path.
 *
 * The invariants:
 *
 * - Every result is one the headers document. GARC_ERR_INTERNAL is a finding.
 * - A member's data never yields more bytes than the member declared.
 * - The member count never passes `max_members`, and the caps hold.
 * - After a failed next there is no current member, so read_member refuses.
 * - The walk does not leak: with a counting allocator, everything allocated is
 *   freed, however early the walk stopped.
 *
 * Build with: make fuzz-arcpio
 * Run:        make fuzz-run-arcpio FUZZ_TIME=300
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include <ghoti.io/archive/archive.h>

#include "../failing_allocator.h"

namespace {

[[noreturn]] void broken(const char * what) {
  std::fprintf(stderr, "arcpio invariant broken: %s\n", what);
  std::abort();
}

#define REQUIRE(cond, what) \
  do { \
    if (!(cond)) { \
      broken(what); \
    } \
  } while (0)

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
    case GARC_ERR_NOT_SEEKABLE:
    case GARC_ERR_LIMIT_MEMBERS:
    case GARC_ERR_LIMIT_MEMBER_BYTES:
    case GARC_ERR_LIMIT_TOTAL_BYTES:
    case GARC_ERR_LIMIT_NAME_BYTES:
    case GARC_ERR_LIMIT_EXTRA_BYTES:
    case GARC_ERR_LIMIT_CODEC_BYTES:
      return true;
    default:
      return false;
  }
}

struct Source {
  const uint8_t * data;
  size_t size;
  size_t at;
};

GARC_Result pipe_read(void * ctx, void * buffer, size_t size, size_t * out_read) {
  Source * source = static_cast<Source *>(ctx);
  // Short reads, as a pipe gives them.
  size_t take = size < 7u ? size : 7u;
  if (take > source->size - source->at) {
    take = source->size - source->at;
  }
  std::memcpy(buffer, source->data + source->at, take);
  source->at += take;
  *out_read = take;
  return GARC_OK;
}

bool walk(const uint8_t * body, size_t body_size, const GARC_Limits & limits,
    const GARC_Allocator * allocator, bool read_data, bool seekable) {
  GARC_Stream * stream = nullptr;
  Source source{body, body_size, 0};
  if (seekable) {
    if (garc_stream_create_memory(body, body_size, &stream) != GARC_OK) {
      return false;
    }
  }
  else {
    GARC_Stream_Callbacks callbacks;
    std::memset(&callbacks, 0, sizeof(callbacks));
    callbacks.ctx = &source;
    callbacks.read = pipe_read;
    if (garc_stream_create_callback(&callbacks, &stream) != GARC_OK) {
      return false;
    }
  }
  GARC_Archive * archive = nullptr;
  const GARC_Result opened
      = garc_open_with_allocator(stream, &limits, allocator, &archive);
  if (opened != GARC_OK) {
    REQUIRE(documented(opened), "open returned a status it does not document");
    REQUIRE(archive == nullptr, "a failed open handed back an archive");
    garc_stream_destroy(stream);
    return false;
  }
  REQUIRE(archive != nullptr, "open succeeded without producing an archive");
  if (garc_format(archive) != GARC_FORMAT_AR
      && garc_format(archive) != GARC_FORMAT_CPIO) {
    garc_close(archive);
    garc_stream_destroy(stream);
    return false;
  }

  const GARC_Member * member = nullptr;
  GARC_Result result;
  int budget = 2048;
  while (budget-- > 0 && (result = garc_next(archive, &member)) == GARC_OK) {
    REQUIRE(member != nullptr, "GARC_OK without a member");
    REQUIRE(member->name != nullptr || member->name_length == 0,
        "a member with a length and no name pointer");
    REQUIRE(garc_member_count(archive) <= limits.max_members,
        "the member count passed max_members");
    REQUIRE(garc_total_declared_bytes(archive) <= limits.max_total_bytes,
        "the declared total passed max_total_bytes");
    REQUIRE(member->size <= limits.max_member_bytes,
        "a member passed max_member_bytes");
    REQUIRE(member->name_length <= limits.max_name_bytes,
        "a name passed max_name_bytes");
    if (!read_data) {
      continue;
    }
    uint64_t produced = 0;
    uint8_t buffer[97];
    for (;;) {
      size_t got = 0;
      const GARC_Result read
          = garc_read_member(archive, buffer, sizeof(buffer), &got);
      if (read != GARC_OK) {
        REQUIRE(documented(read),
            "read_member returned a status it does not document");
        break;
      }
      if (!got) {
        break;
      }
      produced += got;
      REQUIRE(produced <= member->size,
          "read_member produced more than the member declared");
    }
  }
  if (budget >= 0) {
    REQUIRE(documented(result), "next returned a status it does not document");
    if (result != GARC_OK && result != GARC_END) {
      uint8_t buffer[16];
      size_t got = 0;
      REQUIRE(garc_read_member(archive, buffer, sizeof(buffer), &got)
              == GARC_ERR_INVALID,
          "read_member served bytes after a failed next");
    }
  }
  garc_close(archive);
  garc_stream_destroy(stream);
  return true;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  if (size < 2) {
    return 0;
  }
  const uint8_t options = data[0];
  const bool read_data = (options & 0x01u) != 0;
  const bool tight_caps = (options & 0x02u) != 0;
  const bool starve = (options & 0x04u) != 0;
  const size_t fail_at = (options >> 5) & 0x07u;

  GARC_Limits limits;
  garc_limits_default(&limits);
  if (tight_caps) {
    limits.max_members = 4;
    limits.max_member_bytes = 4096;
    limits.max_total_bytes = 8192;
    limits.max_name_bytes = 64;
  }

  const bool seekable = (options & 0x08u) != 0;
  std::vector<uint8_t> body(data + 1, data + size);
  garctest::FailingAllocator allocator(
      starve ? fail_at : static_cast<size_t>(-1));
  const bool opened = walk(body.data(), body.size(), limits, allocator.get(),
      read_data, seekable);
  allocator.stop_failing();
  if (opened) {
    REQUIRE(allocator.live() == 0u, "the walk leaked");
  }
  return 0;
}
