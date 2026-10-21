/**
 * @file
 *
 * Building 7z archives whose folders use BCJ2 and 7-Zip's AES, for tests.
 *
 * `sevenz_builder.h` writes copy folders. This writes a folder of any shape -
 * coders, bind pairs, packed streams - so that a test can put a BCJ2 or an
 * AES coder where 7-Zip would and then break one thing. It also holds the two
 * encoders those folders need: BCJ2 (a range coder, the scan, the conversion)
 * and AES (the key derivation and CBC over the security library's block
 * cipher).
 *
 * **These encoders were written from the same descriptions as the decoders**
 * (`notes/archive/BCJ2-DESCRIPTION.md`, `7Z-AES-DESCRIPTION.md`), so a round
 * trip through them cannot find a misreading the two share. What can is the
 * corpus, which 7-Zip wrote: every 7-Zip archive decodes, and the BCJ2 encoder
 * here reproduces the four streams of `bcj2-copy.7z` byte for byte.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#ifndef GHOTI_IO_GARC_TESTS_SEVENZ_CODERS_H
#define GHOTI_IO_GARC_TESTS_SEVENZ_CODERS_H

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include <ghoti.io/security/aes.h>
#include <ghoti.io/security/sha256.h>

#include "sevenz_builder.h"

namespace garctest {

//-----------------------------------------------------------------------------
// BCJ2
//-----------------------------------------------------------------------------

/** The four streams BCJ2 encodes into. */
struct Bcj2Streams {
  std::string main, call, jump, rc;
};

/** The LZMA-style range encoder BCJ2's decision bits are coded with. */
class Bcj2RangeEncoder {
public:
  explicit Bcj2RangeEncoder(std::string * out) : out_(out) {
    for (uint16_t & p : prob_) {
      p = 1024u;
    }
  }

  void bit(unsigned slot, int value) {
    uint16_t & p = prob_[slot];
    const uint32_t bound = (range_ >> 11) * p;
    if (!value) {
      range_ = bound;
      p = static_cast<uint16_t>(p + ((2048u - p) >> 5));
    }
    else {
      low_ += bound;
      range_ -= bound;
      p = static_cast<uint16_t>(p - (p >> 5));
    }
    while (range_ < (1u << 24)) {
      range_ <<= 8;
      shift();
    }
  }

  void flush() {
    for (int i = 0; i < 5; ++i) {
      shift();
    }
  }

private:
  void shift() {
    if (static_cast<uint32_t>(low_) < 0xFF000000u || (low_ >> 32) != 0) {
      const uint8_t carry = static_cast<uint8_t>(low_ >> 32);
      uint8_t temp = cache_;
      do {
        out_->push_back(static_cast<char>(static_cast<uint8_t>(temp + carry)));
        temp = 0xFF;
      } while (--pending_ != 0);
      cache_ = static_cast<uint8_t>(low_ >> 24);
    }
    ++pending_;
    low_ = (low_ & 0x00FFFFFFu) << 8;
  }

  std::string * out_;
  uint64_t low_ = 0;
  uint32_t range_ = 0xFFFFFFFFu;
  uint8_t cache_ = 0;
  uint64_t pending_ = 1;
  uint16_t prob_[258];
};

/**
 * Encode @p in with BCJ2, converting a branch when @p convert says so.
 *
 * @p convert is asked about every candidate that has four bytes after it,
 * with the candidate's offset and its displacement as a signed 32-bit value;
 * a candidate with fewer is never converted. 7-Zip's own rule since 23 is
 * ::bcj2_seven_zip_rule.
 */
template <typename Convert>
Bcj2Streams bcj2_encode(const std::string & in, Convert convert) {
  Bcj2Streams s;
  Bcj2RangeEncoder rc(&s.rc);
  const size_t n = in.size();
  uint8_t prev = 0;
  size_t i = 0;
  while (i < n) {
    const uint8_t b = static_cast<uint8_t>(in[i]);
    s.main.push_back(static_cast<char>(b));
    const bool candidate = b == 0xE8u || b == 0xE9u
        || (prev == 0x0Fu && (b & 0xF0u) == 0x80u);
    if (!candidate) {
      prev = b;
      ++i;
      continue;
    }
    const unsigned slot = b == 0xE8u ? 2u + prev : (b == 0xE9u ? 1u : 0u);
    bool yes = false;
    uint32_t rel = 0;
    if (i + 5u <= n) {
      for (unsigned k = 0; k < 4u; ++k) {
        rel |= static_cast<uint32_t>(static_cast<uint8_t>(in[i + 1u + k]))
            << (8u * k);
      }
      yes = convert(i, static_cast<int32_t>(rel));
    }
    rc.bit(slot, yes ? 1 : 0);
    if (!yes) {
      prev = b;
      ++i;
      continue;
    }
    const uint32_t absolute = static_cast<uint32_t>(i + 5u) + rel;
    std::string & to = b == 0xE8u ? s.call : s.jump;
    for (int k = 3; k >= 0; --k) {
      to.push_back(static_cast<char>(static_cast<uint8_t>(absolute >> (8 * k))));
    }
    prev = static_cast<uint8_t>(in[i + 4u]);
    i += 5u;
  }
  rc.flush();
  return s;
}

/**
 * 7-Zip's relative limit since 23: a signed displacement in [-L, L).
 *
 * The whole of its rule over a single file; over a solid folder 7-Zip also
 * requires the target to land inside the branch's own file, which
 * ::bcj2_seven_zip_files adds.
 */
inline bool bcj2_seven_zip_rule(size_t, int32_t rel) {
  const int64_t limit = 0x0F000000;
  return rel >= -limit && rel < limit;
}

/**
 * 7-Zip's rule over a folder of several files, as `7z` 25.01 applies it.
 *
 * The relative limit, and a target - the offset in the branch's own file of
 * the byte after the displacement, plus the displacement - in [0, file size).
 * The description left open whether the C++ coder sets a file size; matching
 * `bcj2-copy.7z` byte for byte is what settled that it does.
 *
 * @param files Each file's start in the folder and its size, in order.
 */
inline auto bcj2_seven_zip_files(
    const std::vector<std::pair<size_t, size_t>> & files) {
  return [files](size_t at, int32_t rel) {
    if (!bcj2_seven_zip_rule(at, rel)) {
      return false;
    }
    for (const auto & f : files) {
      if (at >= f.first && at < f.first + f.second) {
        const int64_t target = static_cast<int64_t>(at - f.first) + 5 + rel;
        return target >= 0 && target < static_cast<int64_t>(f.second);
      }
    }
    return false;
  };
}

//-----------------------------------------------------------------------------
// 7-Zip's AES
//-----------------------------------------------------------------------------

/** A UTF-8 string as the UTF-16LE bytes 7-Zip keys with. */
inline std::string sz_utf16le(const std::string & utf8) {
  std::string out;
  for (size_t i = 0; i < utf8.size();) {
    const uint8_t c = static_cast<uint8_t>(utf8[i]);
    uint32_t cp = c;
    size_t n = 1;
    if (c >= 0xF0u) {
      cp = c & 0x07u;
      n = 4;
    }
    else if (c >= 0xE0u) {
      cp = c & 0x0Fu;
      n = 3;
    }
    else if (c >= 0xC0u) {
      cp = c & 0x1Fu;
      n = 2;
    }
    for (size_t k = 1; k < n; ++k) {
      cp = (cp << 6) | (static_cast<uint8_t>(utf8[i + k]) & 0x3Fu);
    }
    i += n;
    auto unit = [&out](uint32_t u) {
      out.push_back(static_cast<char>(u & 0xFFu));
      out.push_back(static_cast<char>(u >> 8));
    };
    if (cp >= 0x10000u) {
      unit(0xD800u | ((cp - 0x10000u) >> 10));
      unit(0xDC00u | ((cp - 0x10000u) & 0x3FFu));
    }
    else {
      unit(cp);
    }
  }
  return out;
}

/** The key for cycle power @p power: hashed, or raw for 63. */
inline std::string sz_aes_key(const std::string & password, unsigned power,
    const std::string & salt) {
  const std::string pw = sz_utf16le(password);
  if (power == 63u) {
    std::string key = (salt + pw).substr(0, 32);
    key.resize(32, '\0');
    return key;
  }
  GSEC_Sha256 sha;
  gsec_sha256_init(&sha);
  for (uint64_t i = 0; i < (uint64_t(1) << power); ++i) {
    std::string unit = salt + pw;
    for (unsigned k = 0; k < 8u; ++k) {
      unit.push_back(static_cast<char>((i >> (8u * k)) & 0xFFu));
    }
    gsec_sha256_update(&sha, unit.data(), unit.size());
  }
  unsigned char digest[32];
  gsec_sha256_final(&sha, digest);
  return std::string(reinterpret_cast<const char *>(digest), 32);
}

/** AES-256-CBC with zero padding to a whole block, as 7-Zip writes it. */
inline std::string sz_aes_encrypt(const std::string & key,
    const std::string & iv16, const std::string & plain) {
  GSEC_Aes aes;
  gsec_aes_encrypt_init(&aes, key.data(), key.size());
  std::string data = plain;
  data.resize((plain.size() + 15u) / 16u * 16u, '\0');
  unsigned char chain[16];
  for (size_t k = 0; k < 16u; ++k) {
    chain[k] = static_cast<unsigned char>(iv16[k]);
  }
  for (size_t at = 0; at < data.size(); at += 16u) {
    unsigned char block[16];
    for (size_t k = 0; k < 16u; ++k) {
      block[k] = static_cast<unsigned char>(data[at + k]) ^ chain[k];
    }
    gsec_aes_encrypt_block(&aes, block, chain);
    for (size_t k = 0; k < 16u; ++k) {
      data[at + k] = static_cast<char>(chain[k]);
    }
  }
  gsec_aes_encrypt_wipe(&aes);
  return data;
}

/** AES coder properties: cycle power, salt and IV, as 7-Zip lays them out. */
inline std::string sz_aes_props(unsigned power, const std::string & salt,
    const std::string & iv) {
  std::string p;
  if (salt.empty() && iv.empty()) {
    p.push_back(static_cast<char>(power));
    return p;
  }
  uint8_t b0 = static_cast<uint8_t>(power);
  uint8_t b1 = 0;
  if (!salt.empty()) {
    b0 |= 0x80u;
    b1 |= static_cast<uint8_t>((salt.size() - 1u) << 4);
  }
  if (!iv.empty()) {
    b0 |= 0x40u;
    b1 |= static_cast<uint8_t>(iv.size() - 1u);
  }
  p.push_back(static_cast<char>(b0));
  p.push_back(static_cast<char>(b1));
  return p + salt + iv;
}

//-----------------------------------------------------------------------------
// A folder of any shape
//-----------------------------------------------------------------------------

/** One coder of a hand-built folder. */
struct SzCoder {
  std::string id;      ///< The method id bytes.
  uint32_t num_in = 1; ///< Streams it takes.
  std::string props;   ///< Its properties; empty for none.
};

/** One folder: its coders, bind pairs, packed in-streams and out sizes. */
struct SzFolder {
  std::vector<SzCoder> coders;
  std::vector<std::pair<uint32_t, uint32_t>> binds; ///< (in, out).
  std::vector<uint32_t> packed;                     ///< In-stream indices.
  std::vector<uint64_t> unpack;                     ///< Per out-stream.
};

/** The streams-info record for one folder over the given packed sizes. */
inline std::string sz_streams_info(uint64_t pack_pos,
    const std::vector<uint64_t> & pack_sizes, const SzFolder & f,
    bool folder_crc, uint32_t crc) {
  std::string h;
  h.push_back(0x06);
  sz_number(h, pack_pos);
  sz_number(h, pack_sizes.size());
  h.push_back(0x09);
  for (uint64_t size : pack_sizes) {
    sz_number(h, size);
  }
  h.push_back(0x00);
  h.push_back(0x07);
  h.push_back(0x0B);
  sz_number(h, 1);
  h.push_back(0x00);
  sz_number(h, f.coders.size());
  for (const SzCoder & c : f.coders) {
    uint8_t flag = static_cast<uint8_t>(c.id.size());
    if (c.num_in != 1u) {
      flag |= 0x10u;
    }
    if (!c.props.empty()) {
      flag |= 0x20u;
    }
    h.push_back(static_cast<char>(flag));
    h += c.id;
    if (c.num_in != 1u) {
      sz_number(h, c.num_in);
      sz_number(h, 1);
    }
    if (!c.props.empty()) {
      sz_number(h, c.props.size());
      h += c.props;
    }
  }
  for (const auto & bind : f.binds) {
    sz_number(h, bind.first);
    sz_number(h, bind.second);
  }
  if (f.packed.size() > 1u) {
    for (uint32_t in : f.packed) {
      sz_number(h, in);
    }
  }
  h.push_back(0x0C);
  for (uint64_t size : f.unpack) {
    sz_number(h, size);
  }
  if (folder_crc) {
    h.push_back(0x0A);
    h.push_back(0x01);
    sz_u32(h, crc);
  }
  h.push_back(0x00);
  return h;
}

/**
 * An archive of one file whose data is the whole of one folder.
 *
 * @p packs are the packed streams in order; @p data is what the folder decodes
 * to, for the CRC-32 the file is given. When @p header_key is not empty, the
 * header is itself encrypted - AES alone, with cycle power 0, no salt and
 * @p header_iv - and the start header points at an encoded header.
 */
inline std::string sz_folder_archive(const std::vector<std::string> & packs,
    const SzFolder & folder, const std::string & name, const std::string & data,
    const std::string & header_key = std::string(),
    const std::string & header_iv = std::string()) {
  std::string packed;
  std::vector<uint64_t> sizes;
  for (const std::string & p : packs) {
    packed += p;
    sizes.push_back(p.size());
  }
  std::string h;
  h.push_back(0x01);
  h.push_back(0x04);
  h += sz_streams_info(0, sizes, folder, false, 0);
  h.push_back(0x08);
  h.push_back(0x0A);
  h.push_back(0x01);
  sz_u32(h, sz_crc(data));
  h.push_back(0x00);
  h.push_back(0x00);
  h.push_back(0x05);
  sz_number(h, 1);
  std::string names;
  names.push_back(0x00);
  for (char c : name) {
    names.push_back(c);
    names.push_back(0x00);
  }
  names.push_back(0x00);
  names.push_back(0x00);
  h.push_back(0x11);
  sz_number(h, names.size());
  h += names;
  h.push_back(0x00);
  h.push_back(0x00);
  if (header_key.empty()) {
    return SzBuilder::assemble(packed, h);
  }
  std::string iv16 = header_iv;
  iv16.resize(16, '\0');
  const std::string sealed = sz_aes_encrypt(header_key, iv16, h);
  SzFolder hf;
  hf.coders.push_back({std::string("\x06\xF1\x07\x01", 4), 1,
      sz_aes_props(0, "", header_iv)});
  hf.packed = {0};
  hf.unpack = {h.size()};
  std::string enc;
  enc.push_back(0x17);
  enc += sz_streams_info(packed.size(), {sealed.size()}, hf, true, sz_crc(h));
  enc.push_back(0x00);
  return SzBuilder::assemble(packed + sealed, enc);
}

/** The AES method id. */
inline std::string sz_aes_id() { return std::string("\x06\xF1\x07\x01", 4); }

/** The BCJ2 method id. */
inline std::string sz_bcj2_id() { return std::string("\x03\x03\x01\x1B", 4); }

} // namespace garctest

#endif // GHOTI_IO_GARC_TESTS_SEVENZ_CODERS_H
