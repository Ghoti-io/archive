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
 **Every input is walked twice by shape: from memory, and from a pipe.** A zip
 * on a stream that cannot seek is read by its local headers and checked against
 * its directory at the end (zip.h), which is a second parser over the same
 * bytes - so it gets the same invariants, and one of its own below.
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
 * - **A streamed walk that ends cleanly agrees with the seekable one.** The
 *   piped walk believes the local headers, and its whole defence is the check
 *   against the directory at the end. If that check passes, every member it
 *   handed over must be the member the directory-first walk reports - same name,
 *   sizes, method, CRC, encryption and data offset - or an archive can show a
 *   streaming reader one thing and every other reader another.
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
  /** Off a pipe, sizes and CRC that follow the data and were never reached. */
  bool sizes_unread = false;

  bool operator!=(const Seen & other) const {
    const bool sizes = sizes_unread || other.sizes_unread
        || (size == other.size && compressed_size == other.compressed_size
            && crc == other.crc);
    return name != other.name || !sizes || method != other.method
        || encryption != other.encryption
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
/** A pipe over a buffer: reads, and nothing else. */
struct Pipe {
  const uint8_t * bytes;
  size_t size;
  size_t at = 0;
};

GARC_Result pipe_read(void * ctx, void * buffer, size_t size, size_t * out_read) {
  Pipe * pipe = static_cast<Pipe *>(ctx);
  const size_t left = pipe->size - pipe->at;
  const size_t n = size < left ? size : left;
  if (n) {
    std::memcpy(buffer, pipe->bytes + pipe->at, n);
  }
  pipe->at += n;
  *out_read = n;
  return GARC_OK;
}

/** How a walk ended, for the streamed-against-seekable comparison. */
struct Ended {
  bool opened = false;
  GARC_Result last = GARC_ERR_INTERNAL; ///< What ended the walk.
};

/**
 * Whether the end record at the end of @p body says more than one disk.
 *
 * Read as the pipe reads it: the 22-byte record whose comment runs exactly
 * to the end, and the zip64 locator's disk count before it when there is one.
 */
bool declares_disks(const uint8_t * body, size_t size) {
  auto le16 = [body](size_t at) { return (uint32_t)(body[at] | (body[at + 1] << 8)); };
  auto le32 = [&](size_t at) { return le16(at) | (le16(at + 2) << 16); };
  for (size_t comment = 0; comment <= 0xFFFFu && comment + 22u <= size; ++comment) {
    const size_t at = size - 22u - comment;
    if (std::memcmp(body + at, "PK\x05\x06", 4) != 0 || le16(at + 20) != comment) {
      continue;
    }
    if (le16(at + 4) != 0u || le16(at + 6) != 0u) {
      return true;
    }
    return at >= 20u && std::memcmp(body + at - 20u, "PK\x06\x07", 4) == 0
        && le32(at - 20u + 16u) > 1u;
  }
  return false;
}

/** How the bytes reach the reader. */
enum class Shape { memory, pipe, two_parts };

Ended walk(const uint8_t * body, size_t body_size, const GARC_Limits & limits,
    const GARC_Allocator * allocator, const char * password, bool read_data,
    Shape shape, std::vector<Seen> * out_seen) {
  Ended ended;
  const bool piped = shape == Shape::pipe;
  GARC_Stream * stream = nullptr;
  GARC_Stream * halves[2] = {nullptr, nullptr};
  Pipe pipe{body, body_size};
  GARC_Stream_Callbacks callbacks{};
  callbacks.read = pipe_read;
  callbacks.ctx = &pipe;
  GARC_Result made = GARC_OK;
  if (shape == Shape::two_parts) {
    // Cut where the body's first byte says, so a fuzzer can move the cut.
    const size_t cut = body_size ? (size_t)body[0] * body_size / 256u : 0u;
    made = garc_stream_create_memory(body, cut, &halves[0]);
    if (made == GARC_OK) {
      made = garc_stream_create_memory(body + cut, body_size - cut, &halves[1]);
    }
    if (made == GARC_OK) {
      made = garc_stream_create_concat(halves, 2, &stream);
    }
  }
  else {
    made = piped ? garc_stream_create_callback(&callbacks, &stream)
                 : garc_stream_create_memory(body, body_size, &stream);
  }
  if (made != GARC_OK) {
    garc_stream_destroy(stream);
    garc_stream_destroy(halves[0]);
    garc_stream_destroy(halves[1]);
    return ended;
  }

  GARC_Archive * archive = nullptr;
  const GARC_Result opened = garc_open_with_allocator(
      stream, &limits, allocator, &archive);
  if (opened != GARC_OK) {
    REQUIRE(documented(opened), "open returned a status it does not document");
    REQUIRE(archive == nullptr, "a failed open handed back an archive");
    garc_stream_destroy(stream);
    garc_stream_destroy(halves[0]);
    garc_stream_destroy(halves[1]);
    return ended;
  }
  REQUIRE(archive != nullptr, "open succeeded without producing an archive");

  if (garc_format(archive) != GARC_FORMAT_ZIP) {
    // A tar, which the identification step is entitled to find first. Not this
    // harness's business, and the tar harness's population is its own.
    garc_close(archive);
    garc_stream_destroy(stream);
    garc_stream_destroy(halves[0]);
    garc_stream_destroy(halves[1]);
    return ended;
  }

  if (password) {
    // The allocator is allowed to fail. An out-of-memory here is that failure,
    // and the password was not stored, so the archive is unchanged.
    const GARC_Result set = garc_zip_set_password(archive, password,
        std::strlen(password));
    if (set == GARC_ERR_OOM) {
      garc_close(archive);
      garc_stream_destroy(stream);
      garc_stream_destroy(halves[0]);
      garc_stream_destroy(halves[1]);
      return ended;
    }
    REQUIRE(set == GARC_OK, "a zip archive refused a password");
  }

  const uint64_t declared = garc_zip_declared_members(archive);
  REQUIRE(garc_zip_base_offset(archive) <= body_size,
      "the discovered base offset is past the end of the input");

  const GARC_Member * member = nullptr;
  GARC_Result result;
  int budget = 4096; // So that a long directory cannot become a timeout.
  while (budget-- > 0 && (result = garc_next(archive, &member)) == GARC_OK) {
    REQUIRE(member != nullptr, "GARC_OK without a member");
    REQUIRE(member->name != nullptr, "a member with no name pointer");

    // A pipe has not reached the end record yet, so there is nothing declared.
    REQUIRE(piped || garc_member_count(archive) <= declared,
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
    // Off a pipe, a member with a data descriptor has its CRC and compressed
    // size only once its data is read - a directory too, whose size is known.
    seen.sizes_unread = piped && (garc_zip_member_flags(archive) & 0x0008u);
    out_seen->push_back(seen);

    if (!read_data) {
      continue;
    }
    uint64_t produced = 0;
    bool clean = false;
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
        clean = true;
        break;
      }
      produced += got;
      // The one that catches a reader handing over the bytes behind the member.
      // A member off a pipe whose sizes follow its data declares nothing yet,
      // so the cap is what bounds it.
      REQUIRE(produced <= (member->size_unknown ? limits.max_member_bytes
                                                : member->size),
          "read_member produced more than the member declared");
    }
    REQUIRE(!member->size_unknown || !clean || produced == member->size,
        "a member's size, once known, is not the size of its data");
    if (out_seen->back().sizes_unread && clean) {
      // Known now, and from here on comparable with the seekable walk's.
      out_seen->back().size = member->size;
      out_seen->back().compressed_size = garc_zip_member_compressed_size(archive);
      out_seen->back().crc = garc_zip_member_crc32(archive);
      out_seen->back().sizes_unread = false;
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
  garc_stream_destroy(halves[0]);
  garc_stream_destroy(halves[1]);
  ended.opened = true;
  ended.last = budget >= 0 ? result : GARC_ERR_INTERNAL;
  return ended;
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
        read_data, Shape::memory, &seen).opened;
    allocator.stop_failing();
    if (opened) {
      REQUIRE(allocator.live() == 0u, "the walk leaked");
    }
  }
  {
    // The same input off a pipe, under the same allocator rule.
    garctest::FailingAllocator allocator(
        starve ? fail_at : static_cast<size_t>(-1));
    std::vector<Seen> seen;
    const bool opened = walk(body, body_size, limits, allocator.get(), password,
        read_data, Shape::pipe, &seen).opened;
    allocator.stop_failing();
    if (opened) {
      REQUIRE(allocator.live() == 0u, "the piped walk leaked");
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
  const Ended a_end = walk(body, body_size, limits, nullptr, "ghoti-password",
      read_data, Shape::memory, &with);
  const Ended b_end = walk(body, body_size, limits, nullptr, nullptr, read_data,
      Shape::memory, &without);
  const bool a = a_end.opened;
  const bool b = b_end.opened;
  REQUIRE(a == b, "the same archive opened with a password and not without one");
  REQUIRE(with.size() == without.size(),
      "a password changed how many members the walk reported");
  for (size_t i = 0; i < with.size(); ++i) {
    REQUIRE(!(with[i] != without[i]),
        "a password changed a member's metadata, which is in the clear");
  }

  // **A streamed walk that the directory approved is the seekable walk.**
  // Except for a split zip, which a pipe of its volumes reads and one stream
  // of memory refuses, having no parts to place its disks in.
  std::vector<Seen> piped;
  const Ended p_end = walk(body, body_size, limits, nullptr, nullptr, read_data,
      Shape::pipe, &piped);
  const bool split_set = declares_disks(body, body_size);
  if (p_end.opened && p_end.last == GARC_END && !split_set) {
    REQUIRE(b && b_end.last == GARC_END,
        "a pipe read to the end an archive the seekable reader refuses");
    REQUIRE(piped.size() == without.size(),
        "a pipe and a seek found different numbers of members");
    for (size_t i = 0; i < piped.size(); ++i) {
      REQUIRE(!(piped[i] != without[i]),
          "a pipe handed over a member the directory describes differently");
    }
  }
  // **Cut in two, a single-disk zip is the same zip.** The concatenation puts
  // the bytes back in a row and a one-disk archive does not ask about parts,
  // so wherever the cut falls the walk must be the memory walk. (An archive
  // that declares disks is refused from memory, and may read here: that is
  // the split path being fuzzed, with only the general invariants.)
  std::vector<Seen> split;
  const Ended s_end = walk(body, body_size, limits, nullptr, nullptr, read_data,
      Shape::two_parts, &split);
  if (split_set && p_end.opened && p_end.last == GARC_END && s_end.opened
      && s_end.last == GARC_END) {
    // A split set the pipe read, and the cut happened to fall where its
    // second disk begins: the two readings of it must be one.
    REQUIRE(split.size() == piped.size(),
        "a split zip read differently from a pipe and from its parts");
    for (size_t i = 0; i < split.size(); ++i) {
      REQUIRE(!(split[i] != piped[i]),
          "a split zip's member read differently from a pipe and from its parts");
    }
  }
  if (b && b_end.last == GARC_END) {
    REQUIRE(s_end.opened && s_end.last == GARC_END,
        "a zip read from memory was refused when cut in two");
    REQUIRE(split.size() == without.size(),
        "cutting a zip in two changed how many members it has");
    for (size_t i = 0; i < split.size(); ++i) {
      REQUIRE(!(split[i] != without[i]),
          "cutting a zip in two changed a member");
    }
  }
  return 0;
}
