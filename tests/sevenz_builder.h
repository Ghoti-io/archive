/**
 * @file
 *
 * Building a 7z byte by byte, so that a test can break exactly one thing.
 *
 * The corpus is what 7-Zip wrote, which is why a passing row means something and
 * why it contains no header whose folder sizes disagree with its substreams, no
 * file count larger than the bytes that could hold it, and no stored CRC that is
 * wrong. This builds a well-formed archive - copy coder, one packed stream per
 * folder, plain header - from an entry list, and `header()` returns the header
 * bytes so a test can change one and `assemble()` the archive around the result
 * with every CRC recomputed. The **control** is the archive with nothing
 * changed: it must be read without complaint, and a malformed-input test whose
 * control also fails is testing the builder.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#ifndef GHOTI_IO_GARC_TEST_SEVENZ_BUILDER_H
#define GHOTI_IO_GARC_TEST_SEVENZ_BUILDER_H

#include <cstdint>
#include <string>
#include <vector>

namespace garctest {

/** CRC-32, written out here so the tests do not depend on the code under test. */
inline uint32_t sz_crc(const std::string & data) {
  uint32_t crc = 0xFFFFFFFFu;
  for (unsigned char byte : data) {
    crc ^= byte;
    for (int bit = 0; bit < 8; ++bit) {
      crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
    }
  }
  return ~crc;
}

/** 7z's variable-length number. */
inline void sz_number(std::string & out, uint64_t value) {
  unsigned char first = 0;
  unsigned char mask = 0x80;
  int extra = 0;
  for (; extra < 8; ++extra) {
    if (value < (1ull << (7 * (extra + 1)))) {
      first |= static_cast<unsigned char>(value >> (8 * extra));
      break;
    }
    first |= mask;
    mask = static_cast<unsigned char>(mask >> 1);
  }
  out.push_back(static_cast<char>(first));
  for (int i = 0; i < extra; ++i) {
    out.push_back(static_cast<char>((value >> (8 * i)) & 0xFF));
  }
}

inline void sz_u32(std::string & out, uint32_t value) {
  for (int i = 0; i < 4; ++i) {
    out.push_back(static_cast<char>((value >> (8 * i)) & 0xFF));
  }
}

inline void sz_u64(std::string & out, uint64_t value) {
  for (int i = 0; i < 8; ++i) {
    out.push_back(static_cast<char>((value >> (8 * i)) & 0xFF));
  }
}

/** One entry of the archive being built. */
struct SzEntry {
  std::u16string name;
  std::string data;
  bool directory = false;
  bool empty_file = false;
  bool anti = false;
  bool has_attr = false;
  uint32_t attr = 0;
  bool has_mtime = false;
  uint64_t mtime = 0;
  /** Added to the stored CRC, so a test can store one that is wrong. */
  uint32_t crc_error = 0;

  bool has_stream() const { return !directory && !empty_file && !anti; }
};

class SzBuilder {
public:
  SzBuilder & add(const std::u16string & name, const std::string & data) {
    SzEntry entry;
    entry.name = name;
    entry.data = data;
    entry.empty_file = data.empty();
    entries_.push_back(entry);
    return *this;
  }

  SzBuilder & add(const char * name, const std::string & data) {
    return add(widen(name), data);
  }

  SzBuilder & add_directory(const char * name) {
    SzEntry entry;
    entry.name = widen(name);
    entry.directory = true;
    entries_.push_back(entry);
    return *this;
  }

  SzEntry & last() { return entries_.back(); }

  /** One folder per file, rather than one folder holding them all. */
  SzBuilder & solid(bool on) {
    solid_ = on;
    return *this;
  }

  static std::u16string widen(const char * text) {
    std::u16string out;
    for (; *text; ++text) {
      out.push_back(static_cast<unsigned char>(*text));
    }
    return out;
  }

  /** The concatenated packed streams. */
  std::string packed() const {
    std::string out;
    for (const SzEntry & entry : entries_) {
      if (entry.has_stream()) {
        out += entry.data;
      }
    }
    return out;
  }

  /** The plain header. */
  std::string header() const {
    std::string h;
    h.push_back(0x01);
    std::vector<const SzEntry *> streams;
    for (const SzEntry & entry : entries_) {
      if (entry.has_stream()) {
        streams.push_back(&entry);
      }
    }
    if (!streams.empty()) {
      h.push_back(0x04);
      // PackInfo: one packed stream per folder.
      const size_t folders = solid_ ? 1u : streams.size();
      h.push_back(0x06);
      sz_number(h, 0);
      sz_number(h, folders);
      h.push_back(0x09);
      if (solid_) {
        sz_number(h, packed().size());
      }
      else {
        for (const SzEntry * entry : streams) {
          sz_number(h, entry->data.size());
        }
      }
      h.push_back(0x00);
      // UnpackInfo: copy coder, no properties.
      h.push_back(0x07);
      h.push_back(0x0B);
      sz_number(h, folders);
      h.push_back(0x00);
      for (size_t i = 0; i < folders; ++i) {
        sz_number(h, 1);
        h.push_back(0x01);
        h.push_back(0x00);
      }
      h.push_back(0x0C);
      if (solid_) {
        sz_number(h, packed().size());
      }
      else {
        for (const SzEntry * entry : streams) {
          sz_number(h, entry->data.size());
        }
      }
      h.push_back(0x00);
      // SubStreamsInfo.
      h.push_back(0x08);
      if (solid_) {
        h.push_back(0x0D);
        sz_number(h, streams.size());
        h.push_back(0x09);
        for (size_t i = 0; i + 1 < streams.size(); ++i) {
          sz_number(h, streams[i]->data.size());
        }
      }
      h.push_back(0x0A);
      h.push_back(0x01);
      for (const SzEntry * entry : streams) {
        sz_u32(h, sz_crc(entry->data) + entry->crc_error);
      }
      h.push_back(0x00);
      h.push_back(0x00);
    }
    h.push_back(0x05);
    sz_number(h, entries_.size());
    std::string empty_stream;
    std::string empty_file;
    std::string anti;
    bool any_empty = false;
    bool any_empty_file = false;
    bool any_anti = false;
    std::vector<bool> es;
    std::vector<bool> ef;
    std::vector<bool> an;
    for (const SzEntry & entry : entries_) {
      es.push_back(!entry.has_stream());
      if (!entry.has_stream()) {
        any_empty = true;
        ef.push_back(entry.empty_file);
        an.push_back(entry.anti);
        any_empty_file |= entry.empty_file;
        any_anti |= entry.anti;
      }
    }
    auto bits = [](const std::vector<bool> & v) {
      std::string out((v.size() + 7) / 8, '\0');
      for (size_t i = 0; i < v.size(); ++i) {
        if (v[i]) {
          out[i / 8] = static_cast<char>(out[i / 8] | (0x80 >> (i % 8)));
        }
      }
      return out;
    };
    if (any_empty) {
      const std::string b = bits(es);
      h.push_back(0x0E);
      sz_number(h, b.size());
      h += b;
    }
    if (any_empty_file) {
      const std::string b = bits(ef);
      h.push_back(0x0F);
      sz_number(h, b.size());
      h += b;
    }
    if (any_anti) {
      const std::string b = bits(an);
      h.push_back(0x10);
      sz_number(h, b.size());
      h += b;
    }
    std::string names;
    names.push_back(0x00);
    for (const SzEntry & entry : entries_) {
      for (char16_t unit : entry.name) {
        names.push_back(static_cast<char>(unit & 0xFF));
        names.push_back(static_cast<char>(unit >> 8));
      }
      names.push_back(0x00);
      names.push_back(0x00);
    }
    h.push_back(0x11);
    sz_number(h, names.size());
    h += names;
    std::vector<bool> defined;
    bool any = false;
    std::string stamps;
    for (const SzEntry & entry : entries_) {
      defined.push_back(entry.has_mtime);
      if (entry.has_mtime) {
        any = true;
        sz_u64(stamps, entry.mtime);
      }
    }
    if (any) {
      std::string body;
      body.push_back(0x00);
      body += bits(defined);
      body.push_back(0x00);
      body += stamps;
      h.push_back(0x14);
      sz_number(h, body.size());
      h += body;
    }
    defined.clear();
    any = false;
    std::string attrs;
    for (const SzEntry & entry : entries_) {
      defined.push_back(entry.has_attr);
      if (entry.has_attr) {
        any = true;
        sz_u32(attrs, entry.attr);
      }
    }
    if (any) {
      std::string body;
      body.push_back(0x00);
      body += bits(defined);
      body.push_back(0x00);
      body += attrs;
      h.push_back(0x15);
      sz_number(h, body.size());
      h += body;
    }
    h.push_back(0x00);
    h.push_back(0x00);
    return h;
  }

  /** The archive: signature header, packed streams, then @p header_bytes. */
  static std::string assemble(
      const std::string & packed, const std::string & header_bytes) {
    std::string start;
    sz_u64(start, packed.size());
    sz_u64(start, header_bytes.size());
    sz_u32(start, sz_crc(header_bytes));
    std::string out("7z\xBC\xAF\x27\x1C", 6);
    out.push_back(0x00);
    out.push_back(0x04);
    sz_u32(out, sz_crc(start));
    out += start;
    out += packed;
    out += header_bytes;
    return out;
  }

  std::string build() const { return assemble(packed(), header()); }

private:
  std::vector<SzEntry> entries_;
  bool solid_ = true;
};

} // namespace garctest

#endif // GHOTI_IO_GARC_TEST_SEVENZ_BUILDER_H
