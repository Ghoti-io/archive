/**
 * @file
 *
 * libFuzzer harness for the 7z reader.
 *
 * **The first byte is an options byte**, as every harness in the suite spells it:
 * the caps (default or tight), whether each member's data is read or skipped, and
 * whether an allocation fails - so one harness covers the limit arms, both cursor
 * disciplines and the error paths. A 7z needs a seekable, sized stream, so there
 * is no stream-shape axis.
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
 * Build with: make fuzz-sevenz
 * Run:        make fuzz-run-sevenz FUZZ_TIME=300
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
  std::fprintf(stderr, "sevenz invariant broken: %s\n", what);
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

bool walk(const uint8_t * body, size_t body_size, const GARC_Limits & limits,
    const GARC_Allocator * allocator, bool read_data) {
  GARC_Stream * stream = nullptr;
  if (garc_stream_create_memory(body, body_size, &stream) != GARC_OK) {
    return false;
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
  if (garc_format(archive) != GARC_FORMAT_SEVENZ) {
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

/** CRC-32 as 7z stores it; written out so the harness depends on nothing. */
uint32_t crc32_of(const uint8_t * data, size_t length) {
  uint32_t crc = 0xFFFFFFFFu;
  for (size_t i = 0; i < length; ++i) {
    crc ^= data[i];
    for (int bit = 0; bit < 8; ++bit) {
      crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
    }
  }
  return ~crc;
}

uint64_t le64(const uint8_t * p) {
  uint64_t v = 0;
  for (int i = 7; i >= 0; --i) {
    v = (v << 8) | p[i];
  }
  return v;
}

/**
 * Make the two CRCs that guard the headers agree with whatever the fuzzer wrote.
 *
 * Without this almost every mutation is refused by a checksum at open, and the
 * parser behind it - which is where the counts, the offsets and the coder graph
 * are - sees nothing the fuzzer produced. The reader's CRC checks are real and
 * are tested elsewhere; here they are made to pass so the bytes they guard are
 * explored.
 */
void repair_crcs(std::vector<uint8_t> * bytes) {
  if (bytes->size() < 32u || std::memcmp(bytes->data(), "7z\xBC\xAF\x27\x1C", 6)) {
    return;
  }
  uint8_t * b = bytes->data();
  const uint64_t offset = le64(b + 12);
  const uint64_t length = le64(b + 20);
  if (offset <= bytes->size() && length <= bytes->size()
      && 32u + offset + length <= bytes->size()) {
    const uint32_t crc = crc32_of(b + 32u + offset, static_cast<size_t>(length));
    for (int i = 0; i < 4; ++i) {
      b[28 + i] = static_cast<uint8_t>(crc >> (8 * i));
    }
  }
  const uint32_t start = crc32_of(b + 12, 20);
  for (int i = 0; i < 4; ++i) {
    b[8 + i] = static_cast<uint8_t>(start >> (8 * i));
  }
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

  std::vector<uint8_t> body(data + 1, data + size);
  if ((options & 0x08u) == 0) {
    repair_crcs(&body);
  }
  garctest::FailingAllocator allocator(
      starve ? fail_at : static_cast<size_t>(-1));
  const bool opened = walk(
      body.data(), body.size(), limits, allocator.get(), read_data);
  allocator.stop_failing();
  if (opened) {
    REQUIRE(allocator.live() == 0u, "the walk leaked");
  }
  return 0;
}
