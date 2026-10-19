/*
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * Copyright (C) 2026 Corey Pennycuff
 *
 * This file is part of Ghoti.io Archive.
 *
 * Ghoti.io Archive is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * Ghoti.io Archive is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file
 *
 * Reading PKWARE's early zip methods: shrink (1), reduce (2 to 5), implode (6).
 *
 * Two kinds of evidence, and the difference matters.
 *
 * **Real members** (`GARC_LEGACY_ZIP_DIR`) are archives other projects keep as
 * test data, written by PKZIP-era programs; `compress` fetches them with
 * `tools/legacy_zip/fetch.sh`, pinned by hash, and they are not committed here
 * either. They are the only evidence that the *container's* half is right: the
 * factor from the method number and the dictionary and tree bits from the flags.
 * No reference in the image writes these methods, so a byte-equal oracle does
 * not exist, and each member's own CRC-32 is the check.
 *
 * **Built members** are made with `compress`'s encoders, so they show routing -
 * that a member reaches the right decoder with the right keys - and nothing
 * about whether the codec agrees with PKWARE. Each routing test has a control
 * that turns the one thing it is about and must fail.
 */

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <ghoti.io/compress/options.h>

#include "test_helpers.h"
#include "zip_builder.h"

using garctest::ZipBuilder;

namespace {

/** Bit 1 and bit 2 of the general purpose flags, which implode reads. */
constexpr uint16_t kImplode8K = 0x0002u;
constexpr uint16_t kImplodeLiterals = 0x0004u;

std::string words(size_t length) {
  static const char * w[] = {"the ", "quick ", "brown ", "fox ", "jumps ",
      "over ", "lazy ", "dog ", "and ", "then ", "sleeps. "};
  std::string out;
  uint32_t seed = 7u;
  while (out.size() < length) {
    seed = seed * 1103515245u + 12345u;
    out += w[(seed >> 16) % 11u];
  }
  out.resize(length);
  return out;
}

std::string noise(size_t length) {
  std::string out;
  uint32_t seed = 99u;
  while (out.size() < length) {
    seed = seed * 1103515245u + 12345u;
    out.push_back(static_cast<char>(seed >> 16));
  }
  return out;
}

/** The shapes every method is run over: text, a run, noise, and a mix. */
std::vector<std::pair<const char *, std::string>> samples() {
  return {
    {"text", words(6000)},
    {"zeros", std::string(20000, '\0')},
    {"noise", noise(3000)},
    {"mixed", words(2000) + noise(500) + std::string(900, 'z') + words(2000)},
    {"one byte", "x"},
  };
}

/** Compress with one of the early methods; options are set by the caller. */
std::string pack(const char * method, gcomp_options_t * options,
    const std::string & plain) {
  GARC_Sink * memory = nullptr;
  if (garc_sink_create_memory(&memory) != GARC_OK) {
    return std::string();
  }
  GARC_Sink * packer = nullptr;
  if (garc_sink_create_compress(memory, method, options, &packer) != GARC_OK) {
    garc_sink_destroy(memory);
    return std::string();
  }
  std::string out;
  if (garc_sink_write(packer, plain.data(), plain.size()) == GARC_OK
      && garc_sink_finish(packer) == GARC_OK) {
    const void * bytes = nullptr;
    size_t length = 0;
    if (garc_sink_data(memory, &bytes, &length) == GARC_OK) {
      out.assign(static_cast<const char *>(bytes), length);
    }
  }
  garc_sink_destroy(packer);
  garc_sink_destroy(memory);
  return out;
}

/** A one-member zip whose payload is already packed. */
std::vector<uint8_t> zip_of(const std::string & packed,
    const std::string & plain, uint16_t method, uint16_t flags,
    uint32_t declared = UINT32_MAX) {
  ZipBuilder builder;
  builder.add("m.bin", packed);
  builder.last().method = method;
  builder.last().flags = flags;
  builder.last().crc = ZipBuilder::crc32(plain);
  builder.last().override_sizes = true;
  builder.last().central_compressed_size = static_cast<uint32_t>(packed.size());
  builder.last().central_size = declared == UINT32_MAX
      ? static_cast<uint32_t>(plain.size()) : declared;
  return builder.build();
}

/** What reading the one member gave: its bytes and the call that ended it. */
struct Read {
  GARC_Result open = GARC_ERR_INTERNAL;
  GARC_Result next = GARC_ERR_INTERNAL;
  GARC_Result end = GARC_ERR_INTERNAL;
  std::string bytes;
  uint16_t method = 0xFFFFu;
};

Read read_one(const std::vector<uint8_t> & zip) {
  Read r;
  GARC_Stream * stream = nullptr;
  if (garc_stream_create_memory(zip.data(), zip.size(), &stream) != GARC_OK) {
    return r;
  }
  GARC_Archive * archive = nullptr;
  r.open = garc_open(stream, nullptr, &archive);
  if (r.open == GARC_OK) {
    const GARC_Member * member = nullptr;
    r.next = garc_next(archive, &member);
    if (r.next == GARC_OK) {
      r.method = garc_zip_member_method(archive);
      char buffer[512];
      size_t got = 0;
      while ((r.end = garc_read_member(archive, buffer, sizeof(buffer), &got))
              == GARC_OK
          && got) {
        r.bytes.append(buffer, got);
      }
    }
  }
  garc_close(archive);
  garc_stream_destroy(stream);
  return r;
}

} // namespace

TEST(ZipLegacy, ShrinkRoutesToTheShrinkDecoder) {
  for (const auto & sample : samples()) {
    const std::string packed = pack("shrink", nullptr, sample.second);
    ASSERT_FALSE(packed.empty()) << sample.first;
    const Read r = read_one(
        zip_of(packed, sample.second, GARC_ZIP_METHOD_SHRUNK, 0));
    EXPECT_EQ(r.end, GARC_OK) << sample.first;
    EXPECT_EQ(r.method, GARC_ZIP_METHOD_SHRUNK) << sample.first;
    EXPECT_EQ(r.bytes, sample.second) << sample.first;
  }
}

TEST(ZipLegacy, ReduceTakesItsFactorFromTheMethodNumber) {
  for (int64_t factor = 1; factor <= 4; ++factor) {
    for (const auto & sample : samples()) {
      gcomp_options_t * options = nullptr;
      ASSERT_EQ(gcomp_options_create(&options), GCOMP_OK);
      ASSERT_EQ(gcomp_options_set_int64(options, "reduce.factor", factor),
          GCOMP_OK);
      const std::string packed = pack("reduce", options, sample.second);
      gcomp_options_destroy(options);
      ASSERT_FALSE(packed.empty()) << sample.first << " factor " << factor;
      const uint16_t method = static_cast<uint16_t>(factor + 1);
      const Read r = read_one(zip_of(packed, sample.second, method, 0));
      EXPECT_EQ(r.end, GARC_OK) << sample.first << " factor " << factor;
      EXPECT_EQ(r.bytes, sample.second) << sample.first << " factor " << factor;
    }
  }
}

TEST(ZipLegacy, ReduceWithTheWrongFactorDoesNotReadAsTheSameBytes) {
  // The control: the factor is the only thing that differs from the test above,
  // and text at factor 4 is not text at factor 1. If the reader ignored the
  // method number this would pass its CRC.
  const std::string plain = words(6000);
  gcomp_options_t * options = nullptr;
  ASSERT_EQ(gcomp_options_create(&options), GCOMP_OK);
  ASSERT_EQ(gcomp_options_set_int64(options, "reduce.factor", 4), GCOMP_OK);
  const std::string packed = pack("reduce", options, plain);
  gcomp_options_destroy(options);
  ASSERT_FALSE(packed.empty());
  const Read right = read_one(
      zip_of(packed, plain, GARC_ZIP_METHOD_REDUCED_4, 0));
  EXPECT_EQ(right.end, GARC_OK);
  const Read wrong = read_one(
      zip_of(packed, plain, GARC_ZIP_METHOD_REDUCED_1, 0));
  EXPECT_TRUE(wrong.end != GARC_OK || wrong.bytes != plain);
}

TEST(ZipLegacy, ImplodeTakesItsDictionaryAndTreesFromTheFlags) {
  const uint64_t dictionaries[] = {4096u, 8192u};
  for (const uint64_t dictionary : dictionaries) {
    for (const bool literals : {false, true}) {
      for (const auto & sample : samples()) {
        gcomp_options_t * options = nullptr;
        ASSERT_EQ(gcomp_options_create(&options), GCOMP_OK);
        ASSERT_EQ(gcomp_options_set_uint64(
                      options, "implode.dictionary_size", dictionary),
            GCOMP_OK);
        ASSERT_EQ(
            gcomp_options_set_bool(options, "implode.literal_tree", literals),
            GCOMP_OK);
        const std::string packed = pack("implode", options, sample.second);
        gcomp_options_destroy(options);
        ASSERT_FALSE(packed.empty()) << sample.first;
        uint16_t flags = 0;
        if (dictionary == 8192u) {
          flags |= kImplode8K;
        }
        if (literals) {
          flags |= kImplodeLiterals;
        }
        const Read r = read_one(
            zip_of(packed, sample.second, GARC_ZIP_METHOD_IMPLODED, flags));
        EXPECT_EQ(r.end, GARC_OK)
            << sample.first << " dict " << dictionary << " literals "
            << literals;
        EXPECT_EQ(r.bytes, sample.second)
            << sample.first << " dict " << dictionary << " literals "
            << literals;
      }
    }
  }
}

TEST(ZipLegacy, ImplodeWithEitherFlagFlippedDoesNotReadAsTheSameBytes) {
  // Controls. Each flag is turned alone; text is long enough that a different
  // distance width or a missing literal tree cannot decode to the same bytes.
  const std::string plain = words(6000);
  gcomp_options_t * options = nullptr;
  ASSERT_EQ(gcomp_options_create(&options), GCOMP_OK);
  ASSERT_EQ(gcomp_options_set_uint64(options, "implode.dictionary_size", 8192u),
      GCOMP_OK);
  ASSERT_EQ(gcomp_options_set_bool(options, "implode.literal_tree", true),
      GCOMP_OK);
  const std::string packed = pack("implode", options, plain);
  gcomp_options_destroy(options);
  ASSERT_FALSE(packed.empty());
  const uint16_t right = kImplode8K | kImplodeLiterals;
  const Read ok = read_one(zip_of(packed, plain, GARC_ZIP_METHOD_IMPLODED, right));
  EXPECT_EQ(ok.end, GARC_OK);
  for (const uint16_t flags : {static_cast<uint16_t>(right & ~kImplode8K),
           static_cast<uint16_t>(right & ~kImplodeLiterals)}) {
    const Read wrong = read_one(
        zip_of(packed, plain, GARC_ZIP_METHOD_IMPLODED, flags));
    EXPECT_TRUE(wrong.end != GARC_OK || wrong.bytes != plain)
        << "flags " << flags;
  }
}

TEST(ZipLegacy, ADamagedPayloadIsRefusedNotMisread) {
  const std::string plain = words(6000);
  const std::string packed = pack("shrink", nullptr, plain);
  ASSERT_GT(packed.size(), 40u);
  // Cut short: the declared size is not met.
  const Read cut = read_one(zip_of(packed.substr(0, packed.size() / 2), plain,
      GARC_ZIP_METHOD_SHRUNK, 0));
  EXPECT_NE(cut.end, GARC_OK);
  // One byte changed: the member's own CRC-32 is what notices.
  std::string flipped = packed;
  flipped[flipped.size() / 2] = static_cast<char>(flipped[flipped.size() / 2] ^ 0x5A);
  const Read bad = read_one(zip_of(flipped, plain, GARC_ZIP_METHOD_SHRUNK, 0));
  EXPECT_TRUE(bad.end != GARC_OK || bad.bytes != plain);
  EXPECT_NE(bad.end, GARC_OK);
}

TEST(ZipLegacy, ADeclaredSizeSmallerThanTheStreamIsABoundNotAnInvitation) {
  // A member that says it is 100 bytes and expands to 20,000 is a bomb; the
  // declared size is the decoder's cap, and the answer is a limit or corruption,
  // never 20,000 bytes handed over.
  const std::string plain(20000, '\0');
  const char * methods[] = {"shrink", "reduce", "implode"};
  const uint16_t numbers[] = {GARC_ZIP_METHOD_SHRUNK, GARC_ZIP_METHOD_REDUCED_4,
      GARC_ZIP_METHOD_IMPLODED};
  for (size_t i = 0; i < 3u; ++i) {
    const std::string packed = pack(methods[i], nullptr, plain);
    ASSERT_FALSE(packed.empty()) << methods[i];
    uint16_t flags = 0;
    if (numbers[i] == GARC_ZIP_METHOD_IMPLODED) {
      // The encoder's defaults: 8 KiB dictionary and a literal tree.
      flags = kImplode8K | kImplodeLiterals;
    }
    const Read r = read_one(zip_of(packed, plain, numbers[i], flags, 100u));
    EXPECT_LE(r.bytes.size(), 100u) << methods[i];
  }
}

TEST(ZipLegacy, EveryRealMemberFromOtherProgramsReadsAndItsCrcVerifies) {
  const char * dir = std::getenv("GARC_LEGACY_ZIP_DIR");
  if (!dir || !*dir) {
    if (std::getenv("GHOTI_CORPUS_REQUIRED")) {
      FAIL() << "GARC_LEGACY_ZIP_DIR is unset and GHOTI_CORPUS_REQUIRED is set";
    }
    GTEST_SKIP() << "GARC_LEGACY_ZIP_DIR names a directory of real shrink, "
                    "reduce and implode archives; compress's "
                    "tools/legacy_zip/fetch.sh puts them in "
                    "third_party/legacy_zip/";
  }
  size_t archives = 0;
  size_t members = 0;
  bool seen[7] = {false, false, false, false, false, false, false};
  for (const auto & entry : std::filesystem::directory_iterator(dir)) {
    if (entry.path().extension() != ".zip") {
      continue;
    }
    ++archives;
    const std::string name = entry.path().string();
    FILE * file = std::fopen(name.c_str(), "rb");
    ASSERT_NE(file, nullptr) << name;
    std::vector<uint8_t> bytes;
    uint8_t chunk[4096];
    size_t got = 0;
    while ((got = std::fread(chunk, 1, sizeof(chunk), file)) > 0) {
      bytes.insert(bytes.end(), chunk, chunk + got);
    }
    std::fclose(file);

    GARC_Stream * stream = nullptr;
    ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
        GARC_OK);
    GARC_Archive * archive = nullptr;
    ASSERT_EQ(garc_open(stream, nullptr, &archive), GARC_OK) << name;
    const GARC_Member * member = nullptr;
    GARC_Result result;
    while ((result = garc_next(archive, &member)) == GARC_OK) {
      const uint16_t method = garc_zip_member_method(archive);
      if (method < 7u) {
        seen[method] = true;
      }
      char buffer[1024];
      size_t read = 0;
      uint64_t total = 0;
      GARC_Result end;
      while ((end = garc_read_member(archive, buffer, sizeof(buffer), &read))
              == GARC_OK
          && read) {
        total += read;
      }
      // OK here is the member's own CRC-32 agreeing with what came out.
      EXPECT_EQ(end, GARC_OK) << name << " method " << method;
      EXPECT_EQ(total, member->size) << name << " method " << method;
      ++members;
    }
    EXPECT_EQ(result, GARC_END) << name;
    garc_close(archive);
    garc_stream_destroy(stream);
  }
  // The denominator: a directory that held no archive, or none of a method,
  // would otherwise pass having proved nothing about it.
  EXPECT_GE(archives, 1u);
  EXPECT_GE(members, 1u);
  EXPECT_TRUE(seen[1]) << "no shrink member";
  EXPECT_TRUE(seen[2] || seen[3] || seen[4] || seen[5]) << "no reduce member";
  EXPECT_TRUE(seen[6]) << "no implode member";
}

TEST(ZipDeflate64, ReachesTheDeflate64DecoderAndNotTheDeflateOne) {
  // A block repeated 40,000 bytes later: a distance deflate cannot code (its
  // window is 32 KiB) and deflate64 codes with its extra distance codes. The same
  // payload declared as method 8 is the control - if the reader pointed method 9
  // at the deflate decoder, both would behave alike, and they must not.
  std::string plain = noise(1000);
  plain += words(39000);
  plain += plain.substr(0, 1000);
  const std::string packed = pack("deflate64", nullptr, plain);
  ASSERT_FALSE(packed.empty());
  const Read nine = read_one(zip_of(packed, plain, GARC_ZIP_METHOD_DEFLATE64, 0));
  EXPECT_EQ(nine.end, GARC_OK);
  EXPECT_EQ(nine.bytes, plain);
  const Read eight = read_one(zip_of(packed, plain, GARC_ZIP_METHOD_DEFLATE, 0));
  EXPECT_TRUE(eight.end != GARC_OK || eight.bytes != plain);
}

TEST(ZipLegacy, WritesFuzzSeedsWhenAsked) {
  // Not a check: with GARC_SEED_DIR set it writes one built archive per method
  // and variant, each behind the fuzz harness's options byte, so the seeds in
  // tests/fuzz/corpus/zip can be regenerated rather than remembered. Without it
  // the test does nothing.
  const char * dir = std::getenv("GARC_SEED_DIR");
  if (!dir || !*dir) {
    GTEST_SKIP() << "GARC_SEED_DIR is not set";
  }
  struct Seed {
    std::string name;
    std::vector<uint8_t> zip;
  };
  std::vector<Seed> seeds;
  const std::string plain = words(3000) + noise(200) + std::string(500, 'q');
  seeds.push_back({"shrink",
      zip_of(pack("shrink", nullptr, plain), plain, GARC_ZIP_METHOD_SHRUNK, 0)});
  for (int64_t factor = 1; factor <= 4; ++factor) {
    gcomp_options_t * options = nullptr;
    ASSERT_EQ(gcomp_options_create(&options), GCOMP_OK);
    ASSERT_EQ(gcomp_options_set_int64(options, "reduce.factor", factor), GCOMP_OK);
    const std::string packed = pack("reduce", options, plain);
    gcomp_options_destroy(options);
    seeds.push_back({"reduce" + std::to_string(factor),
        zip_of(packed, plain, static_cast<uint16_t>(factor + 1), 0)});
  }
  for (const uint64_t dictionary : {4096u, 8192u}) {
    for (const bool literals : {false, true}) {
      gcomp_options_t * options = nullptr;
      ASSERT_EQ(gcomp_options_create(&options), GCOMP_OK);
      ASSERT_EQ(gcomp_options_set_uint64(
                    options, "implode.dictionary_size", dictionary),
          GCOMP_OK);
      ASSERT_EQ(gcomp_options_set_bool(options, "implode.literal_tree", literals),
          GCOMP_OK);
      const std::string packed = pack("implode", options, plain);
      gcomp_options_destroy(options);
      const uint16_t flags = static_cast<uint16_t>(
          (dictionary == 8192u ? kImplode8K : 0)
          | (literals ? kImplodeLiterals : 0));
      seeds.push_back({"implode" + std::to_string(dictionary)
              + (literals ? "lit" : "nolit"),
          zip_of(packed, plain, GARC_ZIP_METHOD_IMPLODED, flags)});
    }
  }
  std::string far = noise(1000) + words(39000);
  far += far.substr(0, 1000);
  seeds.push_back({"deflate64far",
      zip_of(pack("deflate64", nullptr, far), far, GARC_ZIP_METHOD_DEFLATE64, 0)});
  for (const Seed & seed : seeds) {
    const std::string path = std::string(dir) + "/" + seed.name;
    FILE * file = std::fopen(path.c_str(), "wb");
    ASSERT_NE(file, nullptr) << path;
    const uint8_t options_byte = 0;
    std::fwrite(&options_byte, 1, 1, file);
    std::fwrite(seed.zip.data(), 1, seed.zip.size(), file);
    std::fclose(file);
  }
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
