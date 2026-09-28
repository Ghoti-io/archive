/**
 * @file
 *
 * libFuzzer harness for ::garc_find(), whose oracle is ::garc_next().
 *
 * **The walk is the answer and the find has to agree with it.** A find is a
 * rewind followed by the same walk, so anything the first walk reported must come
 * back identical - and every piece of state that survives the rewind shows up
 * here as a member whose name cannot be found, or one found with the wrong
 * metadata. That is the whole reason this harness exists: unit tests can only
 * plant the state I thought of, and the rewind's job is to clear state I did not.
 *
 * **The first two bytes are options**, where the suite's other harnesses use
 * one. The first chooses the stream shape, the caps, whether a find is also tried
 * on a freshly opened archive, whether the found member's data is read, and which
 * of the recorded names is asked for first - so the order of lookups is not the
 * order of the archive, which is what makes a find that only searches forward
 * fail here.
 *
 * The second exists for one line that the first could not reach: how many bytes
 * of prologue sit in front of the archive. ::garc_open() takes a stream
 * *positioned at* an archive, so the offset it must rewind to is not always zero,
 * and a harness that always opened at zero could not tell `start_offset` from a
 * constant. Putting it on an axis of its own rather than folding it into a spare
 * bit of the first byte keeps the two independent.
 *
 * The invariants:
 *
 * - **Every name the walk reported is findable**, and the member found is
 *   field-for-field the one the walk reported at that name's *first* occurrence.
 *   Duplicated names are a tar's business and a find returns the first.
 * - **A name no member has is ::GARC_END**, which is not an error.
 * - **A non-seekable source is always ::GARC_ERR_NOT_SEEKABLE**, whatever the
 *   archive contains, and the walk afterwards is undisturbed - the refusal
 *   happens before anything moves.
 * - **::garc_member_count() after a find is the found member's position**, as the
 *   walk numbered it.
 * - **Two finds for the same name agree**, so a find leaves the archive in a
 *   state the next one can rewind from.
 * - **A found member's data never exceeds its declared size**, which is the same
 *   leak the tar harness watches for, checked on a cursor a rewind positioned.
 * - Every result is one the header documents, ::GARC_ERR_INTERNAL excluded.
 *
 * Build with: make fuzz-find
 * Run:        make fuzz-run-find FUZZ_TIME=300
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <ghoti.io/archive/archive.h>

namespace {

[[noreturn]] void broken(const char * what) {
  std::fprintf(stderr, "find invariant broken: %s\n", what);
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

/** Whether a result is one garc_find() documents. */
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
    // GARC_ERR_INTERNAL is deliberately absent, for the reason the tar harness
    // gives: it means this library's own invariant failed, so no input should be
    // able to produce it.
    default:
      return false;
  }
}

/**
 * The longest name this harness will remember.
 *
 * A name longer than this is *skipped* rather than truncated. Truncating would
 * ask garc_find() for a name no member has and then blame it for answering
 * GARC_END - a harness asserting its own mistake, which is worse than a gap.
 */
constexpr size_t kNameMax = 512u;

/** How many names to record. The find is a scan, so this bounds the work. */
constexpr size_t kNamesMax = 6u;

/** One borrowed byte string, copied so it outlives the next garc_next(). */
struct Text {
  uint8_t bytes[kNameMax];
  size_t length;
};

/**
 * Copy a member's borrowed string, or refuse if it does not fit.
 *
 * @param out Where to put it.
 * @param from The bytes.
 * @param length How many.
 * @return false when it is too long to record, which skips the member.
 */
bool capture(Text * out, const char * from, size_t length) {
  if (length > kNameMax) {
    return false;
  }
  if (length) {
    std::memcpy(out->bytes, from, length);
  }
  out->length = length;
  return true;
}

/** Whether a captured string equals a borrowed one. */
bool matches(const Text & want, const char * got, size_t length) {
  return want.length == length
      && (!length || std::memcmp(want.bytes, got, length) == 0);
}

/**
 * What the walk said about one member, kept so the find can be checked.
 *
 * **Every field a reader fills is here, and the first version of this harness
 * left `uname` out.** With it missing, a rewind that inherited the previous
 * walk's pax *global* record set - which is exactly what a `g` record carries -
 * produced a member that differed only in its owner name, and the comparison
 * said the two were the same. A field left out of an oracle is a field the
 * oracle cannot see.
 */
struct Recorded {
  Text name;
  Text link_target;
  Text uname;
  Text gname;
  uint64_t position; ///< garc_member_count() when the walk reported it.
  uint64_t size;
  GARC_Member_Type type;
  GARC_Name_Encoding name_encoding;
  int64_t mtime_seconds;
  uint32_t mtime_nanoseconds;
  GARC_Time_Source mtime_source;
  uint32_t mode;
  int mode_valid;
  int64_t uid;
  int64_t gid;
  int ids_valid;
  uint32_t device_major;
  uint32_t device_minor;
  int device_valid;
  uint64_t header_offset;
  uint64_t data_offset;
};

/** Whether two members agree on everything a reader fills in. */
bool same(const Recorded & want, const GARC_Member * got) {
  return matches(want.name, got->name, got->name_length)
      && matches(want.link_target, got->link_target, got->link_target_length)
      && matches(want.uname, got->uname, got->uname_length)
      && matches(want.gname, got->gname, got->gname_length)
      && got->size == want.size && got->type == want.type
      && got->name_encoding == want.name_encoding
      && got->mtime_seconds == want.mtime_seconds
      && got->mtime_nanoseconds == want.mtime_nanoseconds
      && got->mtime_source == want.mtime_source && got->mode == want.mode
      && got->mode_valid == want.mode_valid && got->uid == want.uid
      && got->gid == want.gid && got->ids_valid == want.ids_valid
      && got->device_major == want.device_major
      && got->device_minor == want.device_minor
      && got->device_valid == want.device_valid
      // The same member is in the same place. A find that landed on a different
      // copy of an identical name would pass everything above.
      && got->header_offset == want.header_offset
      && got->data_offset == want.data_offset;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  if (size < 3) {
    return 0;
  }

  const uint8_t options = data[0];
  const bool memory = (options & 0x01u) != 0;
  const bool seekable = (options & 0x02u) != 0;
  const bool sized = (options & 0x04u) != 0;
  const bool find_first = (options & 0x08u) != 0;
  const bool tight_caps = (options & 0x10u) != 0;
  const bool read_data = (options & 0x20u) != 0;
  const size_t rotate = (options >> 6) & 0x03u;

  // How far into the stream the archive begins. Bounded small: the point is that
  // it is not zero, not that it is large.
  const size_t prologue = data[1] & 0x0Fu;

  const uint8_t * body = data + 2;
  const size_t body_size = size - 2;

  GARC_Limits limits;
  garc_limits_default(&limits);
  if (tight_caps) {
    // Small enough that a plausible archive reaches them, so the limit arms are
    // explored on the rewind's walk as well as the first one. The interesting
    // case is a cap the first walk fits and the second must too.
    limits.max_members = 4;
    limits.max_member_bytes = 4096;
    limits.max_total_bytes = 8192;
    limits.max_name_bytes = 256;
  }

  // The bytes the stream sees: the prologue, then the archive. The prologue is
  // 0xBB rather than zeros so that a reader which ignored the start offset would
  // find something that is definitely not a header there.
  static uint8_t framed[1u << 16];
  size_t framed_size = 0;
  const uint8_t * whole = body;
  size_t whole_size = body_size;
  size_t start = 0;
  if (prologue && body_size + prologue <= sizeof(framed)) {
    std::memset(framed, 0xBB, prologue);
    std::memcpy(framed + prologue, body, body_size);
    framed_size = prologue + body_size;
    whole = framed;
    whole_size = framed_size;
    start = prologue;
  }

  Source source{whole, whole_size, 0};
  GARC_Stream_Callbacks callbacks{};
  callbacks.ctx = &source;
  callbacks.read = &source_read;
  callbacks.seek = seekable ? &source_seek : nullptr;
  callbacks.size = sized ? &source_size : nullptr;

  GARC_Stream * stream = nullptr;
  const GARC_Result created = memory
      ? garc_stream_create_memory(whole, whole_size, &stream)
      : garc_stream_create_callback(&callbacks, &stream);
  if (created != GARC_OK) {
    return 0;
  }
  const bool can_seek = garc_stream_is_seekable(stream) != 0;

  if (start) {
    // What a caller does when it has read its own header first. A stream that
    // cannot seek cannot be positioned, so those keep their archive at zero.
    if (!can_seek || garc_stream_seek(stream, start) != GARC_OK) {
      garc_stream_destroy(stream);
      return 0;
    }
  }

  GARC_Archive * archive = nullptr;
  const GARC_Result opened
      = garc_open(stream, &limits, &archive);
  if (opened != GARC_OK) {
    garc_stream_destroy(stream);
    return 0;
  }

  // A name no tar can hold: a NUL is refused in a header field and in a pax
  // record, so this cannot be any member's name and the answer must be GARC_END.
  static const char kAbsent[] = "fuzz\0absent\0name";
  const size_t absent_length = sizeof(kAbsent) - 1u;

  // ------------------------------------------------------------------
  // The refusal, asserted before the walk so that "it did not move the
  // cursor" is a claim about a fresh archive rather than about a finished one.
  // ------------------------------------------------------------------
  if (!can_seek) {
    const GARC_Member * refused = nullptr;
    const GARC_Result result
        = garc_find(archive, kAbsent, absent_length, &refused);
    REQUIRE(result == GARC_ERR_NOT_SEEKABLE,
        "a non-seekable source answered something other than NOT_SEEKABLE");
    REQUIRE(refused == nullptr, "a refused find handed back a member");
    // And again, so that the refusal is not a one-shot.
    REQUIRE(garc_find(archive, kAbsent, absent_length, &refused)
            == GARC_ERR_NOT_SEEKABLE,
        "the second find on a non-seekable source answered differently");
  }

  // ------------------------------------------------------------------
  // Walk, recording what the archive says. This is the oracle, and it has to be
  // the *first* thing that touches the archive.
  //
  // **The first version of this harness put an exploratory find before the walk
  // and the harness found its own bug in 356 executions.** A find that fails
  // part way - a corrupt block before the name it was looking for - leaves the
  // cursor where it stopped, and a walk resumed from there resyncs onto a later
  // header and reports names that genuinely *cannot* be reached from the start.
  // Asserting those were findable was asserting something garc_find() does not
  // promise. The oracle is a walk that began at the beginning; "find on a fresh
  // archive" is covered below on an archive opened for the purpose.
  // ------------------------------------------------------------------
  Recorded recorded[kNamesMax];
  size_t recorded_count = 0;

  // **Names *seen*, which is not the same list as names *recorded*.** A member
  // whose strings do not all fit is skipped, and without this a later member
  // with the same name would be recorded in its place - then a find would
  // correctly return the *earlier* one and the comparison would call it wrong.
  // The fuzzer found exactly that at 3.7M executions, on an archive with two
  // empty-named members whose first had an over-long link target.
  //
  // Twice the recorded bound, so a few unrecordable members do not exhaust it;
  // once it is full, nothing more is recorded, because first-occurrence can no
  // longer be guaranteed.
  Text seen[kNamesMax * 2u];
  size_t seen_count = 0;
  const GARC_Member * member = nullptr;
  GARC_Result result;
  int budget = 4096; // So that a long archive cannot become a timeout.

  while (budget-- > 0 && (result = garc_next(archive, &member)) == GARC_OK) {
    REQUIRE(member != nullptr, "GARC_OK without a member");
    REQUIRE(member->name != nullptr, "a member with no name pointer");

    if (recorded_count < kNamesMax && seen_count < kNamesMax * 2u) {
      // Only the first occurrence of a name, because that is what a find
      // returns. Recording a later one would make the comparison below assert
      // something garc_find() does not promise.
      bool already = false;
      for (size_t i = 0; i < seen_count; ++i) {
        if (matches(seen[i], member->name, member->name_length)) {
          already = true;
          break;
        }
      }
      // Noted as seen whatever happens next, so that a member skipped below
      // does not leave its name free for a later one to claim.
      if (!already && capture(&seen[seen_count], member->name,
                         member->name_length)) {
        ++seen_count;
      }
      Recorded & slot = recorded[recorded_count];
      // Every string or none: a member with one too long to hold is skipped
      // rather than recorded with a truncated field, which would make the
      // comparison below assert against something no member has.
      if (!already
          && capture(&slot.name, member->name, member->name_length)
          && capture(&slot.link_target, member->link_target,
                 member->link_target_length)
          && capture(&slot.uname, member->uname, member->uname_length)
          && capture(&slot.gname, member->gname, member->gname_length)) {
        slot.position = garc_member_count(archive);
        slot.size = member->size;
        slot.type = member->type;
        slot.name_encoding = member->name_encoding;
        slot.mtime_seconds = member->mtime_seconds;
        slot.mtime_nanoseconds = member->mtime_nanoseconds;
        slot.mtime_source = member->mtime_source;
        slot.mode = member->mode;
        slot.mode_valid = member->mode_valid;
        slot.uid = member->uid;
        slot.gid = member->gid;
        slot.ids_valid = member->ids_valid;
        slot.device_major = member->device_major;
        slot.device_minor = member->device_minor;
        slot.device_valid = member->device_valid;
        slot.header_offset = member->header_offset;
        slot.data_offset = member->data_offset;
        ++recorded_count;
      }
    }
  }
  if (budget >= 0) {
    REQUIRE(documented(result), "next returned a status it does not document");
  }

  if (!can_seek) {
    // Nothing below applies, and the walk above already proved the refusal did
    // not disturb it: an archive whose first find was refused still walked.
    garc_close(archive);
    garc_stream_destroy(stream);
    return 0;
  }

  // ------------------------------------------------------------------
  // Every recorded name must come back, identical, in an order the archive
  // does not choose.
  // ------------------------------------------------------------------
  for (size_t n = 0; n < recorded_count; ++n) {
    // Rotated, so a find that searched forward from the cursor rather than from
    // the start fails here on most inputs rather than on a lucky few.
    const Recorded & want
        = recorded[(n + rotate * 3u + 1u) % recorded_count];

    const GARC_Member * found = nullptr;
    const GARC_Result first
        = garc_find(archive, want.name.bytes, want.name.length, &found);
    REQUIRE(documented(first), "find returned a status it does not document");
    REQUIRE(first == GARC_OK,
        "a name the walk reported could not be found again");
    REQUIRE(found != nullptr, "GARC_OK without a member");
    REQUIRE(same(want, found),
        "the found member disagrees with the one the walk reported");
    REQUIRE(garc_member_count(archive) == want.position,
        "the member count after a find is not the found member's position");

    if (read_data) {
      // The same leak the tar harness watches for, on a cursor a rewind placed.
      uint64_t produced = 0;
      uint8_t buffer[97]; // Not a divisor of a block, so the last read is short.
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
        REQUIRE(produced <= found->size,
            "read_member produced more than the found member declared");
      }
    }

    // Twice, so that a find leaves the archive in a state the next can rewind
    // from - which the first find cannot demonstrate about itself.
    const GARC_Member * again = nullptr;
    const GARC_Result second
        = garc_find(archive, want.name.bytes, want.name.length, &again);
    REQUIRE(second == first, "the same find answered differently twice");
    REQUIRE(again != nullptr && same(want, again),
        "the second find disagreed with the first");
  }

  // And a name that cannot exist, after all that rewinding.
  const GARC_Member * absent = nullptr;
  const GARC_Result missing
      = garc_find(archive, kAbsent, absent_length, &absent);
  REQUIRE(documented(missing), "find returned a status it does not document");
  REQUIRE(missing != GARC_OK, "a name no tar can hold was found");

  // ------------------------------------------------------------------
  // A find as the first thing that happens to an archive, on an archive opened
  // for it. The rewind has nothing to clear in that state, which is a different
  // path through reader_rewind() from the one every find above took - and doing
  // it on a second archive is what keeps the oracle above valid.
  // ------------------------------------------------------------------
  if (find_first && recorded_count) {
    GARC_Stream * fresh = nullptr;
    if (garc_stream_create_memory(whole, whole_size, &fresh) == GARC_OK
        && (!start || garc_stream_seek(fresh, start) == GARC_OK)) {
      GARC_Archive * reopened = nullptr;
      if (garc_open(fresh, &limits, &reopened) == GARC_OK) {
        const Recorded & want = recorded[0];
        const GARC_Member * found = nullptr;
        const GARC_Result result
            = garc_find(reopened, want.name.bytes, want.name.length, &found);
        REQUIRE(documented(result),
            "find returned a status it does not document");
        REQUIRE(result == GARC_OK,
            "the first member a walk reported was not found on a fresh archive");
        REQUIRE(found != nullptr && same(want, found),
            "a find on a fresh archive disagreed with the walk");
        REQUIRE(garc_member_count(reopened) == want.position,
            "the member count after a find on a fresh archive is wrong");
        garc_close(reopened);
      }
      garc_stream_destroy(fresh);
    }
  }

  garc_close(archive);
  garc_stream_destroy(stream);
  return 0;
}
