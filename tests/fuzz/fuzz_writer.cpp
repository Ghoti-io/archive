/**
 * @file
 *
 * libFuzzer harness for the tar writer, checked against the reader.
 *
 * **This is the one harness here with an expected value.** The other three check
 * invariants that hold by construction - `tell` advances by exactly what `read`
 * reported, a traversal implies a parent component, prefixing `safe/` cannot turn a
 * contained name into an escape - which is real and is not the same as knowing the
 * answer. This one knows it for free, because an archive it writes is an archive
 * the reader reads, and the members that come back either are the members that
 * went in or they are not. `notes/` records the limit of that: a writer and a reader
 * that share a misunderstanding agree perfectly, so what this finds is a field in
 * the wrong offset, a length off by one, a padding rule applied twice - not a
 * field with the wrong meaning. `make check-oracle` asks something other than
 * this library.
 *
 * The input is carved into a member rather than used as bytes, because a writer
 * takes a struct and not a stream: the first bytes choose the type, the variant
 * and the field lengths, and the rest are the name, the link target, the owner
 * names and the data. A carve that produces a member the writer refuses is not a
 * wasted execution - the refusals are most of what a writer decides, and the
 * harness checks that a refusal wrote nothing at all.
 *
 * The invariants:
 *
 * - **A refusal writes nothing.** Not "writes less": the offset must be exactly
 *   where it was, because a half-written header is an archive no reader recovers
 *   and the caller was told the call failed.
 * - **What is written is a multiple of 512.** Every tar structure is blocks.
 * - **A member survives the round trip**: name bytes, type, size, data, link
 *   target, owner names, mode, ids and the time with its source.
 * - **Writing twice produces identical bytes.** A writer whose output depended on
 *   anything but its input - a wall clock in a carrier header, an uninitialised
 *   byte in a block, a buffer not reset between members - is what this catches,
 *   and it is the property that makes a corpus reproducible at all.
 * - **ustar refuses a superset of what pax refuses.** Anything pax cannot write,
 *   ustar cannot either; the reverse is the whole point of having two variants.
 *
 * It also drives the failing allocator, so the out-of-memory arms are walked by
 * the same corpus rather than by a campaign of their own.
 *
 * Build with: make fuzz-writer
 * Run:        make fuzz-run-writer FUZZ_TIME=300
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

namespace {

[[noreturn]] void broken(const char * what) {
  std::fprintf(stderr, "writer invariant broken: %s\n", what);
  std::abort();
}

#define REQUIRE(cond, what)                                                    \
  do {                                                                         \
    if (!(cond)) {                                                             \
      broken(what);                                                            \
    }                                                                          \
  } while (0)

/** An allocator that refuses the nth request, for the out-of-memory arms. */
struct Refusing {
  GARC_Allocator allocator{};
  size_t fail_at = static_cast<size_t>(-1);
  size_t requests = 0;

  Refusing() {
    allocator.ctx = this;
    allocator.malloc_fn = &Refusing::malloc_cb;
    allocator.calloc_fn = &Refusing::calloc_cb;
    allocator.realloc_fn = &Refusing::realloc_cb;
    allocator.free_fn = &Refusing::free_cb;
  }

  bool refuse() { return requests++ >= fail_at; }

  static void * malloc_cb(void * ctx, size_t size) {
    Refusing * self = static_cast<Refusing *>(ctx);
    return self->refuse() ? nullptr : std::malloc(size ? size : 1);
  }
  static void * calloc_cb(void * ctx, size_t n, size_t size) {
    Refusing * self = static_cast<Refusing *>(ctx);
    if (n && size > static_cast<size_t>(-1) / n) {
      return nullptr;
    }
    if (self->refuse()) {
      return nullptr;
    }
    const size_t total = n * size;
    return std::calloc(1, total ? total : 1);
  }
  static void * realloc_cb(void * ctx, void * ptr, size_t size) {
    Refusing * self = static_cast<Refusing *>(ctx);
    return self->refuse() ? nullptr : std::realloc(ptr, size ? size : 1);
  }
  static void free_cb(void *, void * ptr) { std::free(ptr); }
};

/** A byte reader over the fuzz input, which runs out rather than overrunning. */
struct Carver {
  const uint8_t * data;
  size_t size;
  size_t at = 0;

  uint8_t byte() { return at < size ? data[at++] : 0u; }

  /** Up to @p most bytes, however many are left. */
  std::string take(size_t most) {
    const size_t available = at < size ? size - at : 0u;
    const size_t want = most < available ? most : available;
    std::string out(reinterpret_cast<const char *>(data + at), want);
    at += want;
    return out;
  }
};

/** What one member came back as. */
struct Captured {
  std::string name;
  std::string link;
  std::string uname;
  std::string gname;
  std::string data;
  GARC_Member_Type type = GARC_MEMBER_FILE;
  uint64_t size = 0;
  int64_t mtime_seconds = 0;
  uint32_t mtime_nanoseconds = 0;
  GARC_Time_Source mtime_source = GARC_TIME_NONE;
  uint32_t mode = 0;
  int64_t uid = 0;
  int64_t gid = 0;
};

/** Write one member into a memory sink. The bytes come back in `out`. */
GARC_Result write_one(const GARC_Member & member, const std::string & data,
    const GARC_Writer_Options & options, const GARC_Allocator * allocator,
    std::string * out, uint64_t * out_offset_after_failure) {
  GARC_Sink * sink = nullptr;
  if (garc_sink_create_memory_with_allocator(allocator, &sink) != GARC_OK) {
    return GARC_ERR_OOM;
  }
  GARC_Writer * writer = nullptr;
  GARC_Result result = garc_writer_create_with_allocator(
      sink, GARC_FORMAT_TAR, &options, allocator, &writer);
  if (result == GARC_OK) {
    result = garc_writer_add(writer, &member);
    if (result != GARC_OK && out_offset_after_failure) {
      *out_offset_after_failure = garc_sink_tell(sink);
    }
  }
  if (result == GARC_OK && !data.empty()) {
    result = garc_writer_write(writer, data.data(), data.size());
  }
  if (result == GARC_OK) {
    result = garc_writer_finish(writer);
  }
  if (result == GARC_OK && out) {
    const void * bytes = nullptr;
    size_t length = 0;
    if (garc_sink_data(sink, &bytes, &length) == GARC_OK) {
      out->assign(static_cast<const char *>(bytes), length);
    }
  }
  garc_writer_destroy(writer);
  garc_sink_destroy(sink);
  return result;
}

/** Read every member back. */
GARC_Result read_all(const std::string & bytes, std::vector<Captured> * out) {
  GARC_Stream * stream = nullptr;
  if (garc_stream_create_memory(bytes.data(), bytes.size(), &stream)
      != GARC_OK) {
    return GARC_ERR_OOM;
  }
  GARC_Archive * archive = nullptr;
  GARC_Result result = garc_open(stream, nullptr, &archive);
  const GARC_Member * member = nullptr;
  while (result == GARC_OK
      && (result = garc_next(archive, &member)) == GARC_OK) {
    Captured got;
    got.name.assign(member->name, member->name_length);
    if (member->link_target) {
      got.link.assign(member->link_target, member->link_target_length);
    }
    if (member->uname) {
      got.uname.assign(member->uname, member->uname_length);
    }
    if (member->gname) {
      got.gname.assign(member->gname, member->gname_length);
    }
    got.type = member->type;
    got.size = member->size;
    got.mtime_seconds = member->mtime_seconds;
    got.mtime_nanoseconds = member->mtime_nanoseconds;
    got.mtime_source = member->mtime_source;
    got.mode = member->mode;
    got.uid = member->uid;
    got.gid = member->gid;

    char buffer[512];
    size_t read = 0;
    GARC_Result data_result;
    while ((data_result
               = garc_read_member(archive, buffer, sizeof(buffer), &read))
            == GARC_OK
        && read) {
      got.data.append(buffer, read);
    }
    if (data_result != GARC_OK) {
      result = data_result;
      break;
    }
    out->push_back(got);
  }
  garc_close(archive);
  garc_stream_destroy(stream);
  return result == GARC_END ? GARC_OK : result;
}

const GARC_Member_Type kTypes[] = {
  GARC_MEMBER_FILE,
  GARC_MEMBER_DIRECTORY,
  GARC_MEMBER_SYMLINK,
  GARC_MEMBER_HARDLINK,
  GARC_MEMBER_FIFO,
  GARC_MEMBER_CHAR_DEVICE,
  GARC_MEMBER_BLOCK_DEVICE,
  GARC_MEMBER_OTHER,
};

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  Carver carver{data, size};

  const uint8_t selector = carver.byte();
  const uint8_t flags = carver.byte();
  const uint8_t name_length = carver.byte();
  const uint8_t link_length = carver.byte();
  const uint8_t owner_length = carver.byte();
  const uint8_t oom = carver.byte();

  GARC_Writer_Options options;
  garc_writer_options_default(&options);
  if (selector & 0x40u) {
    options.tar_variant = GARC_TAR_USTAR;
  }
  options.blocking_factor = (selector & 0x80u) ? (selector & 0x1Fu) : 0u;

  const std::string name = carver.take(name_length);
  const std::string link = carver.take(link_length);
  const std::string uname = carver.take(owner_length);
  const std::string gname = carver.take(owner_length);
  const std::string payload = carver.take(1024);

  GARC_Member member;
  std::memset(&member, 0, sizeof(member));
  member.name = name.data();
  member.name_length = name.size();
  member.type = kTypes[selector % (sizeof(kTypes) / sizeof(kTypes[0]))];
  if (!link.empty()) {
    member.link_target = link.data();
    member.link_target_length = link.size();
  }
  if (!uname.empty()) {
    member.uname = uname.data();
    member.uname_length = uname.size();
  }
  if (!gname.empty()) {
    member.gname = gname.data();
    member.gname_length = gname.size();
  }
  member.mode = static_cast<uint32_t>(flags) << 4;
  member.mode_valid = (flags & 1u) != 0u;
  member.uid = (flags & 2u) ? -2 : static_cast<int64_t>(flags) * 100000;
  member.gid = static_cast<int64_t>(flags);
  member.ids_valid = (flags & 4u) != 0u;
  // A negative time, a fraction, and no time at all are all reachable, because
  // each takes a different arm of the record builder.
  member.mtime_seconds = (flags & 8u) ? -static_cast<int64_t>(flags)
                                     : static_cast<int64_t>(flags) * 1000000000;
  if (flags & 16u) {
    member.mtime_source = GARC_TIME_PAX_DECIMAL;
    member.mtime_nanoseconds = static_cast<uint32_t>(flags) * 1000000u;
  } else {
    member.mtime_source = (flags & 32u) ? GARC_TIME_NONE : GARC_TIME_TAR_OCTAL;
  }
  if (member.type == GARC_MEMBER_CHAR_DEVICE
      || member.type == GARC_MEMBER_BLOCK_DEVICE) {
    member.device_valid = (flags & 64u) != 0u;
    member.device_major = flags;
    member.device_minor = static_cast<uint32_t>(name_length);
  }
  // Only a data-carrying member may declare a size, and the writer refuses one
  // that declares more than it delivers - so the declaration is the payload's
  // length rather than a number of its own.
  const std::string data_for_member
      = (member.type == GARC_MEMBER_FILE) ? payload : std::string();
  member.size = data_for_member.size();

  Refusing refusing;
  if (oom) {
    refusing.fail_at = oom - 1u;
  }

  std::string bytes;
  uint64_t offset_after_failure = 0;
  const GARC_Result result = write_one(member, data_for_member, options,
      refusing.allocator.ctx ? &refusing.allocator : nullptr, &bytes,
      &offset_after_failure);

  if (result != GARC_OK) {
    // A refusal writes nothing at all. Not "writes less": a half-written header
    // is an archive no reader recovers, and the caller was told it failed.
    REQUIRE(offset_after_failure == 0u, "a refused member left bytes behind");
    return 0;
  }

  REQUIRE(bytes.size() % 512u == 0u, "an archive that is not whole blocks");
  if (options.blocking_factor) {
    const size_t record = static_cast<size_t>(options.blocking_factor) * 512u;
    REQUIRE(bytes.size() % record == 0u,
        "an archive not padded to its blocking factor");
  }

  // Determinism. A writer whose output depended on anything but its input is
  // what makes a corpus irreproducible, and a wall clock in a carrier header is
  // how that happens.
  std::string again;
  REQUIRE(write_one(member, data_for_member, options, nullptr, &again, nullptr)
          == GARC_OK,
      "a member written once and refused the second time");
  REQUIRE(again == bytes, "two writes of one member produced different bytes");

  std::vector<Captured> back;
  const GARC_Result read = read_all(bytes, &back);
  REQUIRE(read == GARC_OK, "an archive this library wrote and cannot read");
  REQUIRE(back.size() == 1u, "one member written, a different number read");

  const Captured & got = back[0];
  REQUIRE(got.name == name, "the name changed in the round trip");
  REQUIRE(got.type == member.type, "the type changed in the round trip");
  REQUIRE(got.size == member.size, "the size changed in the round trip");
  REQUIRE(got.data == data_for_member, "the data changed in the round trip");
  REQUIRE(got.link == link, "the link target changed in the round trip");
  REQUIRE(got.uname == uname, "the owner name changed in the round trip");
  REQUIRE(got.gname == gname, "the group name changed in the round trip");
  REQUIRE(got.mode == (member.mode_valid ? member.mode : 0u),
      "the mode changed in the round trip");
  REQUIRE(got.uid == (member.ids_valid ? member.uid : 0),
      "the owner id changed in the round trip");
  REQUIRE(got.gid == (member.ids_valid ? member.gid : 0),
      "the group id changed in the round trip");
  REQUIRE(got.mtime_seconds
          == (member.mtime_source == GARC_TIME_NONE ? 0
                                                    : member.mtime_seconds),
      "the time changed in the round trip");
  REQUIRE(got.mtime_nanoseconds == member.mtime_nanoseconds,
      "the sub-second time changed in the round trip");
  // **The one field the round trip cannot always keep, and the harness found it
  // on its first run.** A time the octal field cannot hold - anything negative,
  // or above 8589934591 - can only be written as a record, and a record *is*
  // GARC_TIME_PAX_DECIMAL however the caller asked for it. So the promise holds
  // exactly where the format can keep it, and the condition says where that is
  // rather than the assertion being dropped.
  const bool octal_can_hold = member.mtime_source != GARC_TIME_NONE
      && member.mtime_seconds >= 0 && member.mtime_seconds <= 8589934591;
  const GARC_Time_Source expected_source
      = (member.mtime_source == GARC_TIME_PAX_DECIMAL || !octal_can_hold)
      ? GARC_TIME_PAX_DECIMAL
      : GARC_TIME_TAR_OCTAL;
  REQUIRE(got.mtime_source
          == (member.mtime_source == GARC_TIME_NONE ? GARC_TIME_TAR_OCTAL
                                                    : expected_source),
      "which field the time came from changed in the round trip");

  // ustar refuses a superset of what pax refuses, so anything that wrote as
  // ustar must write as pax. The reverse is the whole point of two variants.
  if (options.tar_variant == GARC_TAR_USTAR) {
    GARC_Writer_Options as_pax = options;
    as_pax.tar_variant = GARC_TAR_PAX;
    std::string pax_bytes;
    REQUIRE(write_one(member, data_for_member, as_pax, nullptr, &pax_bytes,
                nullptr)
            == GARC_OK,
        "a member ustar accepted and pax refused");
    // And a ustar archive needs no extended header, so pax writes the same bytes
    // for it: the variant changes what is *refused*, not what is emitted for
    // something both can say.
    REQUIRE(pax_bytes == bytes,
        "pax and ustar disagreed about a member both can express");
  }

  return 0;
}
