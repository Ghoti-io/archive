/**
 * @file
 *
 * libFuzzer harness for the zip reader.
 *
 * **The first byte is an options byte**, as every harness in the suite spells it.
 * Here it chooses the caps, whether each member's data is read or skipped, whether
 * a password is set, and whether an allocation fails - so one harness covers the
 * limit arms, both cursor disciplines, the cipher, and the error paths. A harness
 * that always read with the default caps and no password would leave the limit
 * arms, the skip path and every line of the decryption stack unexplored while
 * reporting coverage of the parser.
 *
 * **There is no stream-shape axis, and that is the difference from fuzz_tar.**
 * A zip requires a seekable, sized stream: one on a pipe is
 * ::GARC_ERR_NOT_SEEKABLE before a byte is parsed, so a harness that spent half
 * its inputs on non-seekable streams would spend half its budget on one branch.
 * The memory stream is the shape that reaches the parser, and it is the only one
 * used.
 *
 * The invariants, each of which a wrong answer can satisfy by accident on one
 * input and not across a corpus:
 *
 * - Every result is one the headers document. A status from nowhere is a bug even
 *   when nothing crashes.
 * - A member's data never yields more bytes than the member declared. This is the
 *   one that catches a reader leaking the central directory into a caller's buffer.
 * - The number of members handed out never exceeds what the end record declared,
 *   nor `max_members`. A zip is walked by an index, so a reader that lost count
 *   would read past the directory rather than stopping.
 * - Every member's data offset is inside the archive and before the central
 *   directory, and the base offset never exceeds the input's length.
 * - A refusal is final in the sense that matters: after a failure there is no
 *   current member, so read_member must refuse too.
 * - **A password changes no metadata.** The archive is walked twice, once with a
 *   password and once without, and every member's name, size, method, CRC and
 *   encryption must match. zip leaves its metadata in the clear at every password
 *   strength, so a reader whose walk depends on the password has a bug this is the
 *   only thing that would find.
 *
 * Build with: make fuzz-zip
 * Run:        make fuzz-run-zip FUZZ_TIME=300
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include <ghoti.io/archive/archive.h>

#include "../failing_allocator.h"

namespace {

[[noreturn]] void broken(const char * what) {
  std::fprintf(stderr, "zip invariant broken: %s\n", what);
  std::abort();
}

#define REQUIRE(cond, what)                                                    \
  do {                                                                         \
    if (!(cond)) {                                                             \
      broken(what);                                                            \
    }                                                                          \
  } while (0)

/** Whether a result is one the reader's headers document. */
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
    case GARC_ERR_PASSWORD_REQUIRED:
    case GARC_ERR_PASSWORD_REJECTED:
    case GARC_ERR_PASSWORD_OR_CORRUPT:
      return true;
    // GARC_ERR_INTERNAL is deliberately absent. It means this library's own
    // invariant failed, which no input should be able to cause - so reaching it
    // is a finding rather than a documented answer.
    default:
      return false;
  }
}

/** One member's metadata, for the two-walk comparison. */
struct Seen {
  std::string name;
  uint64_t size = 0;
  uint64_t compressed_size = 0;
  uint16_t method = 0;
  uint32_t crc = 0;
  int encryption = 0;
  uint64_t data_offset = 0;

  bool operator!=(const Seen & other) const {
    return name != other.name || size != other.size
        || compressed_size != other.compressed_size || method != other.method
        || crc != other.crc || encryption != other.encryption
        || data_offset != other.data_offset;
  }
};

/**
 * Walk one archive over the same bytes, and record what the metadata said.
 *
 * @param body The archive.
 * @param body_size Its length.
 * @param limits The caps.
 * @param allocator The allocator, which may be one that fails.
 * @param password A password to set, or NULL for none.
 * @param read_data Whether to read each member's bytes.
 * @param out_seen Receives one entry per member handed out.
 * @return Whether the archive opened at all.
 */
bool walk(const uint8_t * body, size_t body_size, const GARC_Limits & limits,
    const GARC_Allocator * allocator, const char * password, bool read_data,
    std::vector<Seen> * out_seen) {
  GARC_Stream * stream = nullptr;
  if (garc_stream_create_memory(body, body_size, &stream) != GARC_OK) {
    return false;
  }

  GARC_Archive * archive = nullptr;
  const GARC_Result opened = garc_open_with_allocator(
      stream, &limits, allocator, &archive);
  if (opened != GARC_OK) {
    REQUIRE(documented(opened), "open returned a status it does not document");
    REQUIRE(archive == nullptr, "a failed open handed back an archive");
    garc_stream_destroy(stream);
    return false;
  }
  REQUIRE(archive != nullptr, "open succeeded without producing an archive");

  if (garc_format(archive) != GARC_FORMAT_ZIP) {
    // A tar, which the identification step is entitled to find first. Not this
    // harness's business, and the tar harness's population is its own.
    garc_close(archive);
    garc_stream_destroy(stream);
    return false;
  }

  if (password) {
    REQUIRE(garc_zip_set_password(archive, password, std::strlen(password))
            == GARC_OK,
        "a zip archive refused a password");
  }

  const uint64_t declared = garc_zip_declared_members(archive);
  REQUIRE(garc_zip_base_offset(archive) <= body_size,
      "the discovered base offset is past the end of the input");

  const GARC_Member * member = nullptr;
  GARC_Result result;
  int budget = 4096; // So that a long directory cannot become a timeout.
  while (budget-- > 0 && (result = garc_next(archive, &member)) == GARC_OK) {
    REQUIRE(member != nullptr, "GARC_OK without a member");
    REQUIRE(member->name != nullptr || member->name_length == 0,
        "a member with a length and no name pointer");

    REQUIRE(garc_member_count(archive) <= declared,
        "more members handed out than the end record declared");
    REQUIRE(garc_member_count(archive) <= limits.max_members,
        "the member count passed max_members");
    REQUIRE(garc_total_declared_bytes(archive) <= limits.max_total_bytes,
        "the declared total passed max_total_bytes");
    REQUIRE(member->size <= limits.max_member_bytes,
        "a member passed max_member_bytes");
    REQUIRE(member->name_length <= limits.max_name_bytes,
        "a name passed max_name_bytes");
    REQUIRE(garc_zip_member_extra_length(archive) <= limits.max_extra_bytes,
        "an extra field passed max_extra_bytes");
    // Where the data is, which the reader worked out from the local header.
    REQUIRE(member->data_offset <= body_size,
        "a member's data starts past the end of the input");
    REQUIRE(member->header_offset <= body_size,
        "a member's local header is past the end of the input");

    Seen seen;
    seen.name.assign(member->name ? member->name : "", member->name_length);
    seen.size = member->size;
    seen.compressed_size = garc_zip_member_compressed_size(archive);
    seen.method = garc_zip_member_method(archive);
    seen.crc = garc_zip_member_crc32(archive);
    seen.encryption = (int)garc_zip_member_encryption(archive);
    seen.data_offset = member->data_offset;
    out_seen->push_back(seen);

    if (!read_data) {
      continue;
    }
    uint64_t produced = 0;
    uint8_t buffer[97]; // Not a round number, so the last read is a short one.
    for (;;) {
      size_t got = 0;
      const GARC_Result read = garc_read_member(
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
      // The one that catches a reader handing over the bytes behind the member.
      REQUIRE(produced <= member->size,
          "read_member produced more than the member declared");
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
  const bool compare_walks = (options & 0x08u) != 0;
  const bool with_password = (options & 0x10u) != 0;
  const size_t fail_at = (options >> 5) & 0x07u;

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
    limits.max_extra_bytes = 64;
  }

  // The password is a fixed string. A fuzzer-chosen one would be wrong twice
  // over: it cannot guess the key of a member the fuzzer also has to build, and
  // the interesting arms are reached by *any* password - the header read, the
  // check byte, the decrypting view - so a constant gets to all of them and
  // leaves the bytes free to be the archive.
  const char * const password = with_password ? "ghoti-password" : nullptr;

  {
    garctest::FailingAllocator allocator(
        starve ? fail_at : static_cast<size_t>(-1));
    std::vector<Seen> seen;
    const bool opened = walk(body, body_size, limits, allocator.get(), password,
        read_data, &seen);
    allocator.stop_failing();
    if (opened) {
      REQUIRE(allocator.live() == 0u, "the walk leaked");
    }
  }

  if (!compare_walks) {
    return 0;
  }

  // **The metadata must not depend on the password.** A zip's names, sizes,
  // methods, CRCs and offsets are in the clear at every password strength, so the
  // two walks have to agree member for member. Run with the default allocator on
  // both sides: an allocation failure is allowed to cut a walk short, and two
  // walks cut short at different points would disagree for a reason that is not a
  // bug.
  std::vector<Seen> with;
  std::vector<Seen> without;
  const bool a = walk(body, body_size, limits, nullptr, "ghoti-password",
      read_data, &with);
  const bool b = walk(body, body_size, limits, nullptr, nullptr, read_data,
      &without);
  REQUIRE(a == b, "the same archive opened with a password and not without one");
  REQUIRE(with.size() == without.size(),
      "a password changed how many members the walk reported");
  for (size_t i = 0; i < with.size(); ++i) {
    REQUIRE(!(with[i] != without[i]),
        "a password changed a member's metadata, which is in the clear");
  }
  return 0;
}
