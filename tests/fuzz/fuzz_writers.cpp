/**
 * @file
 *
 * libFuzzer harness for every writer, checked against the reader and against
 * itself.
 *
 * `fuzz_writer.cpp` is the tar writer's, one member deep, with every field the
 * tar header has. This one is wide rather than deep: the first bytes choose a
 * format - zip, 7z, ar, cpio, shar, or tar again - its options, the shape of the
 * sink, and up to four members, and the rest are their names, link targets and
 * data. The members a writer refuses are dropped from what is expected, and
 * the archive is judged against the ones it accepted.
 *
 * The invariants:
 *
 * - **What was accepted is what comes back**, in order: the name (zip adds `/`
 *   to a directory's), the type, the data, and a symlink's target - which zip
 *   and 7z store as the member's data, so either place counts. shar is never
 *   read, so for it the check is that a finished script ends `exit 0`.
 * - **Writing twice produces identical bytes.**
 * - **A sink that refuses one write never yields a wrong archive.** The writer
 *   may refuse for good, and then it must write nothing more and every later
 *   call must return the same status. Or it may carry on, and then the finished
 *   archive must be byte for byte what an undisturbed run wrote. A format that
 *   keeps state between calls (zip, 7z, shar) may not carry on.
 * - **A sparse member reads back as its real content.** One byte after the
 *   members (0 when the input has run out, so a seed from before it reads as
 *   it did) can make the first file a sparse one: its data is cut into runs
 *   with holes the input chooses, tar writes it as pax sparse 1.0, and every
 *   other format must refuse it before writing anything.
 * - **An allocation failure is reported, and frees what it took** - the second
 *   half is LeakSanitizer's, which every fuzz build links.
 *
 * Build with: make fuzz-writers
 * Run:        make fuzz-run-writers FUZZ_TIME=300
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
  std::fprintf(stderr, "writers invariant broken: %s\n", what);
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

  std::string take(size_t most) {
    const size_t available = at < size ? size - at : 0u;
    const size_t want = most < available ? most : available;
    std::string out(reinterpret_cast<const char *>(data + at), want);
    at += want;
    return out;
  }
};

/**
 * A sink over a string: patching or not, and optionally refusing exactly one
 * write - the first that would pass @ref budget bytes - and accepting after.
 */
struct Sink {
  std::string bytes;
  size_t budget = static_cast<size_t>(-1);
  bool refused = false;
  int asked_after = 0;

  static GARC_Result write(void * ctx, const void * buffer, size_t size) {
    Sink * self = static_cast<Sink *>(ctx);
    if (self->refused) {
      ++self->asked_after;
    }
    else if (self->bytes.size() + size > self->budget) {
      self->refused = true;
      return GARC_ERR_IO;
    }
    self->bytes.append(static_cast<const char *>(buffer), size);
    return GARC_OK;
  }

  static GARC_Result patch(
      void * ctx, uint64_t offset, const void * buffer, size_t size) {
    Sink * self = static_cast<Sink *>(ctx);
    if (self->refused) {
      ++self->asked_after;
    }
    std::memcpy(&self->bytes[static_cast<size_t>(offset)], buffer, size);
    return GARC_OK;
  }
};

/** One member as the fuzz input describes it. */
struct Spec {
  GARC_Member_Type type = GARC_MEMBER_FILE;
  std::string name;
  std::string link;
  std::string data;
  uint32_t mode = 0;
  int mode_valid = 0;
  /** For a sparse member, its runs; @ref data is then the runs' bytes. */
  std::vector<GARC_Sparse_Region> runs;
  bool sparse = false;
  uint64_t real_size = 0;
  /** The file the runs make, holes as zeros, for the round trip. */
  std::string content;
};

GARC_Member member_of(const Spec & spec) {
  GARC_Member member;
  std::memset(&member, 0, sizeof(member));
  member.name = spec.name.data();
  member.name_length = spec.name.size();
  member.name_encoding = GARC_NAME_UTF8;
  member.type = spec.type;
  if (!spec.link.empty()) {
    member.link_target = spec.link.data();
    member.link_target_length = spec.link.size();
  }
  member.size = spec.data.size();
  if (spec.sparse) {
    static const GARC_Sparse_Region none = {0, 0};
    member.size = spec.real_size;
    member.sparse_regions = spec.runs.empty() ? &none : spec.runs.data();
    member.sparse_region_count = spec.runs.size();
  }
  member.mode = spec.mode;
  member.mode_valid = spec.mode_valid;
  member.mtime_seconds = 1000000000;
  member.mtime_source = GARC_TIME_NONE;
  return member;
}

/** What one run of the writer did. */
struct Run {
  GARC_Result created = GARC_OK;
  GARC_Result first = GARC_OK;      ///< The first failure, or GARC_OK.
  GARC_Result retry = GARC_OK;      ///< That call made again.
  std::vector<GARC_Result> after;   ///< Every call after the retry failed.
  bool finished = false;
  std::vector<size_t> accepted;     ///< Which specs the writer took.
  std::string bytes;
  int asked_after = 0;
  bool refused = false;
};

Run write_all(GARC_Format format, const GARC_Writer_Options & options,
    const std::vector<Spec> & specs, bool patchable, size_t budget,
    const GARC_Allocator * allocator) {
  Run run;
  Sink sink;
  sink.budget = budget;
  GARC_Sink_Callbacks callbacks{};
  callbacks.write = Sink::write;
  if (patchable) {
    callbacks.patch = Sink::patch;
  }
  callbacks.ctx = &sink;
  GARC_Sink * s = nullptr;
  if (garc_sink_create_callback(&callbacks, &s) != GARC_OK) {
    run.created = GARC_ERR_OOM;
    return run;
  }
  GARC_Writer * writer = nullptr;
  run.created
      = garc_writer_create_with_allocator(s, format, &options, allocator, &writer);
  if (run.created != GARC_OK) {
    garc_sink_destroy(s);
    return run;
  }

  // One call at a time, as a caller would make them. A refused add drops the
  // member and goes on; any other failure is tried once more, and after that
  // the rest of the calls are made only to see what they return.
  auto call = [&](auto && make) -> bool {
    GARC_Result result = make();
    if (run.first != GARC_OK) {
      run.after.push_back(result);
      return false;
    }
    if (result == GARC_OK) {
      return true;
    }
    GARC_Result again = make();
    if (again == GARC_OK) {
      return true;
    }
    run.first = result;
    run.retry = again;
    return false;
  };

  for (size_t i = 0; i < specs.size(); ++i) {
    const Spec & spec = specs[i];
    const GARC_Member member = member_of(spec);
    if (run.first == GARC_OK) {
      const uint64_t before = garc_sink_tell(s);
      const GARC_Result added = garc_writer_add(writer, &member);
      if (added == GARC_ERR_INVALID || added == GARC_ERR_UNSUPPORTED) {
        if (garc_sink_tell(s) == before) {
          continue; // refused before anything was written: skip the member
        }
      }
      if (added != GARC_OK) {
        // Not a clean refusal: the same rule as any other call.
        GARC_Result again = garc_writer_add(writer, &member);
        if (again != GARC_OK) {
          run.first = added;
          run.retry = again;
          continue;
        }
      }
    }
    else {
      run.after.push_back(garc_writer_add(writer, &member));
      continue;
    }
    run.accepted.push_back(i);
    if (!spec.data.empty()) {
      const size_t half = spec.data.size() / 2;
      call([&] { return garc_writer_write(writer, spec.data.data(), half); });
      call([&] {
        return garc_writer_write(
            writer, spec.data.data() + half, spec.data.size() - half);
      });
    }
  }
  run.finished = call([&] { return garc_writer_finish(writer); });
  garc_writer_destroy(writer);
  garc_sink_destroy(s);
  run.bytes = sink.bytes;
  run.asked_after = sink.asked_after;
  run.refused = sink.refused;
  return run;
}

/** What one member came back as. */
struct Got {
  std::string name;
  std::string link;
  std::string data;
  GARC_Member_Type type = GARC_MEMBER_FILE;
};

GARC_Result read_all(const std::string & bytes, std::vector<Got> * out) {
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
    Got got;
    got.name.assign(member->name, member->name_length);
    if (member->link_target) {
      got.link.assign(member->link_target, member->link_target_length);
    }
    got.type = member->type;
    char buffer[1024];
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

const GARC_Format kFormats[] = {GARC_FORMAT_ZIP, GARC_FORMAT_SEVENZ,
    GARC_FORMAT_AR, GARC_FORMAT_CPIO, GARC_FORMAT_SHAR, GARC_FORMAT_TAR};

const GARC_Member_Type kTypes[] = {GARC_MEMBER_FILE, GARC_MEMBER_FILE,
    GARC_MEMBER_DIRECTORY, GARC_MEMBER_SYMLINK, GARC_MEMBER_HARDLINK,
    GARC_MEMBER_FIFO};

const GARC_Zip_Method kZipMethods[] = {GARC_ZIP_METHOD_STORED,
    GARC_ZIP_METHOD_DEFLATE, GARC_ZIP_METHOD_DEFLATE64, GARC_ZIP_METHOD_BZIP2,
    GARC_ZIP_METHOD_ZSTD, GARC_ZIP_METHOD_XZ, GARC_ZIP_METHOD_LZMA,
    GARC_ZIP_METHOD_STORED};

const GARC_SevenZ_Method kSevenZMethods[] = {GARC_SEVENZ_LZMA2,
    GARC_SEVENZ_LZMA, GARC_SEVENZ_BZIP2, GARC_SEVENZ_DEFLATE,
    GARC_SEVENZ_DEFLATE64, GARC_SEVENZ_COPY, GARC_SEVENZ_COPY,
    GARC_SEVENZ_LZMA2};

bool keeps_state(GARC_Format format) {
  return format == GARC_FORMAT_ZIP || format == GARC_FORMAT_SEVENZ
      || format == GARC_FORMAT_SHAR;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  Carver carver{data, size};

  const uint8_t selector = carver.byte();
  const uint8_t variant = carver.byte();
  const uint8_t sink_shape = carver.byte();
  const uint8_t oom = carver.byte();
  const uint8_t count = carver.byte();

  const GARC_Format format = kFormats[selector % 6u];
  GARC_Writer_Options options;
  garc_writer_options_default(&options);
  options.zip_method = kZipMethods[variant & 7u];
  options.sevenz_method = kSevenZMethods[(variant >> 3) & 7u];
  options.sevenz_non_solid = (variant & 0x40u) != 0u;
  options.cpio_variant = (variant & 0x80u) ? GARC_CPIO_ODC : GARC_CPIO_NEWC;
  options.shar_uuencode = (variant & 0x40u) != 0u;
  const bool patchable = (sink_shape & 1u) == 0u;

  std::vector<Spec> specs;
  for (unsigned i = 0; i < (count & 3u) + 1u; ++i) {
    Spec spec;
    const uint8_t shape = carver.byte();
    spec.type = kTypes[shape % (sizeof(kTypes) / sizeof(kTypes[0]))];
    spec.name = carver.take(carver.byte() % 48u);
    spec.link = carver.take(carver.byte() % 24u);
    if (spec.type == GARC_MEMBER_FILE) {
      const size_t length = static_cast<size_t>(carver.byte()) * 9u;
      spec.data = carver.take(length);
    }
    spec.mode_valid = (shape & 0x80u) != 0u;
    spec.mode = (static_cast<uint32_t>(shape) << 2) & 0777u;
    specs.push_back(spec);
  }
  const uint8_t holes = carver.byte();
  for (Spec & spec : specs) {
    if (!(holes & 1u) || spec.type != GARC_MEMBER_FILE) {
      continue;
    }
    // Cut the data into up to four runs, each after a hole the input sizes -
    // up to 64 KiB, so the padding and merging of runs both happen.
    const size_t pieces = ((holes >> 1) & 3u) + 1u;
    uint64_t at = 0;
    size_t used = 0;
    for (size_t p = 0; p < pieces; ++p) {
      at += static_cast<uint64_t>(carver.byte()) * 257u;
      const size_t length = p + 1u == pieces
          ? spec.data.size() - used : (spec.data.size() - used) / 2u;
      spec.runs.push_back({at, static_cast<uint64_t>(length)});
      at += length;
      used += length;
    }
    spec.real_size = at + static_cast<uint64_t>(carver.byte()) * 131u;
    spec.content.assign(static_cast<size_t>(spec.real_size), '\0');
    used = 0;
    for (const GARC_Sparse_Region & run : spec.runs) {
      spec.content.replace(static_cast<size_t>(run.offset),
          static_cast<size_t>(run.length), spec.data, used,
          static_cast<size_t>(run.length));
      used += static_cast<size_t>(run.length);
    }
    spec.sparse = true;
    break;
  }

  // The undisturbed run is the reference for everything below.
  const Run whole = write_all(format, options, specs, patchable,
      static_cast<size_t>(-1), nullptr);
  if (whole.created != GARC_OK) {
    // 7z on a sink that cannot patch is refused at create, which is the one
    // create-time refusal an ordinary carve reaches.
    REQUIRE(format == GARC_FORMAT_SEVENZ && !patchable,
        "a writer refused at create on an ordinary sink");
    return 0;
  }
  REQUIRE(whole.first == GARC_OK || whole.first == GARC_ERR_INVALID
          || whole.first == GARC_ERR_UNSUPPORTED,
      "a writer failed on a sink that never refused");

  if (whole.finished) {
    // Determinism.
    const Run again = write_all(format, options, specs, patchable,
        static_cast<size_t>(-1), nullptr);
    REQUIRE(again.finished && again.bytes == whole.bytes,
        "two runs of one input produced different bytes");

    if (format == GARC_FORMAT_SHAR) {
      REQUIRE(whole.bytes.size() >= 7u
              && whole.bytes.compare(whole.bytes.size() - 7u, 7u, "exit 0\n") == 0,
          "a finished shar does not end exit 0");
    }
    else {
      std::vector<Got> back;
      REQUIRE(read_all(whole.bytes, &back) == GARC_OK,
          "an archive this library wrote and cannot read");
      REQUIRE(back.size() == whole.accepted.size(),
          "a different number of members came back than were accepted");
      for (size_t k = 0; k < back.size(); ++k) {
        const Spec & spec = specs[whole.accepted[k]];
        const Got & got = back[k];
        std::string name = got.name;
        if (format == GARC_FORMAT_ZIP && spec.type == GARC_MEMBER_DIRECTORY
            && !name.empty() && name.back() == '/'
            && (spec.name.empty() || spec.name.back() != '/')) {
          name.pop_back();
        }
        REQUIRE(name == spec.name, "a name changed in the round trip");
        REQUIRE(got.type == spec.type, "a type changed in the round trip");
        if (spec.type == GARC_MEMBER_FILE) {
          REQUIRE(got.data == (spec.sparse ? spec.content : spec.data),
              "data changed in the round trip");
        }
        if (spec.type == GARC_MEMBER_SYMLINK) {
          REQUIRE(got.link == spec.link
                  || (got.link.empty() && got.data == spec.link),
              "a link target changed in the round trip");
        }
      }
    }

    // A sink that refuses one write, at a point the input chooses.
    if (!whole.bytes.empty() && (sink_shape & 2u)) {
      const size_t budget = (static_cast<size_t>(sink_shape >> 2) * 131u
                                + static_cast<size_t>(oom))
          % whole.bytes.size();
      const Run blip
          = write_all(format, options, specs, patchable, budget, nullptr);
      if (blip.created != GARC_OK) {
        REQUIRE(format == GARC_FORMAT_SEVENZ && blip.created == GARC_ERR_IO,
            "a create failed on a sink with room for its first write");
      }
      else if (blip.first != GARC_OK) {
        REQUIRE(!blip.finished, "a failed writer finished");
        REQUIRE(blip.retry == blip.first,
            "a failed writer answered its retry differently");
        for (GARC_Result later : blip.after) {
          REQUIRE(later == blip.first,
              "a failed writer answered a later call differently");
        }
        REQUIRE(blip.asked_after == 0, "a failed writer went on writing");
      }
      else if (blip.refused) {
        REQUIRE(!keeps_state(format), "a writer that keeps state recovered");
        REQUIRE(blip.finished && blip.bytes == whole.bytes,
            "a writer recovered into a different archive");
      }
    }
  }

  // Allocation failure: reported, and the result is never a wrong archive.
  if (oom) {
    Refusing refusing;
    refusing.fail_at = oom - 1u;
    const Run starved = write_all(
        format, options, specs, patchable, static_cast<size_t>(-1),
        &refusing.allocator);
    if (starved.created == GARC_OK && starved.finished && whole.finished) {
      REQUIRE(starved.bytes == whole.bytes,
          "a writer that met an allocation failure finished a different archive");
    }
  }
  return 0;
}
