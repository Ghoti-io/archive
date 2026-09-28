/**
 * @file
 *
 * Building a zip byte by byte, so that a test can break exactly one thing.
 *
 * **The corpus cannot do this job and this cannot do the corpus's.** Every
 * archive in `tests/data/zip/` was written by a real tool, which is what makes a
 * passing comparison mean something - and it is also why none of them has a
 * local header that disagrees with its central directory, a declared member count
 * that is wrong, or a zip64 field that is one value short. No tool writes those.
 * A reader's refusals are most of its safety, and a refusal with no input that
 * reaches it is a branch nobody has run.
 *
 * So this builds a well-formed archive from a member list, and every field a
 * refusal depends on has a knob. The **control** is the archive with no knob
 * turned: `ZipBuilder().add("a.txt", "x").build()` must be read without complaint,
 * and every test below turns exactly one thing from that starting point. A
 * malformed-input test whose well-formed twin also fails is testing the builder.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#ifndef GHOTI_IO_GARC_TEST_ZIP_BUILDER_H
#define GHOTI_IO_GARC_TEST_ZIP_BUILDER_H

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace garctest {

/**
 * The zip64 end record's size, which its own second field declares minus twelve.
 *
 * Spelled here rather than taken from the library's header, because a builder
 * that took its constants from the code under test would agree with it by
 * construction - including about a constant that was wrong.
 */
static const size_t GARC_ZIP_ZIP64_EOCD_SIZE_TEST = 56u;

/** One member to write. */
struct ZipBuilderMember {
  std::string name;
  std::string data;
  uint16_t method = 0;
  uint16_t flags = 0;
  uint32_t crc = 0;
  /** What the *local* header says its name is, when that should differ. */
  std::string local_name;
  /** What the central directory says the local header offset is, when overridden. */
  bool override_local_offset = false;
  uint32_t local_offset = 0;
  /** Extra field bytes for the central directory entry. */
  std::string central_extra;
  /** Extra field bytes for the local header. */
  std::string local_extra;
  /**
   * The DOS date and time fields, defaulting to 2001-09-09T01:46:40Z.
   *
   * The same second every fixture in the corpus carries, so a builder-made
   * archive and a tool-made one are comparable. The values are
   * `((2001-1980) << 9) | (9 << 5) | 9` and `(1 << 11) | (46 << 5) | (40 / 2)` -
   * written as hex here and checked by ZipStructure.TheControlsMemberIsReadable,
   * because a default nobody checks is a default that silently moves every test
   * that relies on it.
   */
  uint16_t dos_time = 0x0DD4u;
  uint16_t dos_date = 0x2B29u;
  /** External attributes; the default is a Unix 0100644. */
  uint32_t external_attributes = 0100644u << 16;
  uint16_t version_made_by = 0x031Eu;
  /** Override the 32-bit sizes in the central directory, for zip64 markers. */
  bool override_sizes = false;
  uint32_t central_size = 0;
  uint32_t central_compressed_size = 0;
  /** Claim a name longer than the one written, to run the entry past the end. */
  bool override_name_length = false;
  uint16_t name_length = 0;
  /** The disk the entry claims its local header is on; 0 is the only readable one. */
  uint16_t disk_start = 0;
};

/**
 * A zip under construction.
 *
 * Local headers, then the central directory, then the end record - which is the
 * order the bytes go in and the reverse of the order they are read in.
 */
class ZipBuilder {
public:
  ZipBuilder & add(const std::string & name, const std::string & data) {
    ZipBuilderMember member;
    member.name = name;
    member.data = data;
    member.crc = crc32(data);
    members_.push_back(member);
    return *this;
  }

  /** The member most recently added, to turn one of its knobs. */
  ZipBuilderMember & last() { return members_.back(); }

  /** Bytes in front of the archive, which its offsets do not count. */
  ZipBuilder & prologue(const std::string & bytes) {
    prologue_ = bytes;
    return *this;
  }

  /** The archive comment, whose length the end record declares. */
  ZipBuilder & comment(const std::string & bytes) {
    comment_ = bytes;
    return *this;
  }

  /** Bytes after the end record that its comment length does *not* cover. */
  ZipBuilder & trailer(const std::string & bytes) {
    trailer_ = bytes;
    return *this;
  }

  /** Claim a different number of entries than were written. */
  ZipBuilder & declared_members(int count) {
    declared_ = count;
    return *this;
  }

  /** Claim a different central directory size than was written. */
  ZipBuilder & declared_central_size(int64_t size) {
    declared_central_size_ = size;
    return *this;
  }

  /** Claim a different central directory offset than was written. */
  ZipBuilder & declared_central_offset(int64_t offset) {
    declared_central_offset_ = offset;
    return *this;
  }

  /** The disk numbers in the end record, which must be zero to be read. */
  ZipBuilder & disk(uint16_t this_disk, uint16_t central_disk) {
    disk_ = this_disk;
    central_disk_ = central_disk;
    return *this;
  }

  /** Make the entry count on this disk differ from the total. */
  ZipBuilder & entries_here(int count) {
    entries_here_ = count;
    return *this;
  }

  /**
   * Write a zip64 end record and its locator, with markers in the 32-bit fields.
   *
   * What `zip -fz` produces, and the only way to reach the zip64 half of the
   * reader from a built archive - no fixture in the corpus can be made to have a
   * broken one.
   */
  ZipBuilder & zip64() {
    zip64_ = true;
    return *this;
  }

  /** Write the 32-bit markers in the end record with **no** zip64 record. */
  ZipBuilder & zip64_markers_only() {
    zip64_markers_only_ = true;
    return *this;
  }

  /** The disk numbers in the zip64 records, which must be zero to be read. */
  ZipBuilder & zip64_disk(uint32_t locator_disk, uint32_t record_disk,
      uint32_t total_disks = 1u) {
    zip64_locator_disk_ = locator_disk;
    zip64_record_disk_ = record_disk;
    zip64_total_disks_ = total_disks;
    return *this;
  }

  /**
   * Make the locator state a different offset for the zip64 end record.
   *
   * A value past the end of the file makes the first candidate position
   * unreadable, which is what sends the reader to the second - the 56 bytes in
   * front of the locator, where the record actually is. That path is how an
   * archive behind a stub is read, because the locator's offset is one of the
   * offsets the stub shifts.
   */
  ZipBuilder & zip64_locator_offset(uint64_t offset) {
    zip64_locator_offset_ = static_cast<int64_t>(offset);
    return *this;
  }

  /** Break the zip64 end record's signature, leaving the locator pointing at it. */
  ZipBuilder & zip64_break_record() {
    zip64_break_record_ = true;
    return *this;
  }

  /** Corrupt a signature: 'c' for a central entry, 'l' for a local header. */
  ZipBuilder & break_signature(char which, size_t index) {
    break_signature_ = which;
    break_index_ = index;
    return *this;
  }

  /** Write the bytes. */
  std::vector<uint8_t> build() {
    std::string out = prologue_;
    std::vector<uint32_t> offsets;

    for (size_t i = 0; i < members_.size(); ++i) {
      const ZipBuilderMember & member = members_[i];
      offsets.push_back(static_cast<uint32_t>(out.size() - prologue_.size()));
      const std::string local_name
          = member.local_name.empty() ? member.name : member.local_name;
      std::string header;
      header += (break_signature_ == 'l' && break_index_ == i)
          ? std::string("PK\x03\x05", 4) : std::string("PK\x03\x04", 4);
      append16(header, 20u);
      append16(header, member.flags);
      append16(header, member.method);
      append16(header, member.dos_time);
      append16(header, member.dos_date);
      append32(header, member.crc);
      append32(header, static_cast<uint32_t>(member.data.size()));
      append32(header, static_cast<uint32_t>(member.data.size()));
      append16(header, static_cast<uint16_t>(local_name.size()));
      append16(header, static_cast<uint16_t>(member.local_extra.size()));
      out += header;
      out += local_name;
      out += member.local_extra;
      out += member.data;
    }

    const uint32_t central_start
        = static_cast<uint32_t>(out.size() - prologue_.size());
    for (size_t i = 0; i < members_.size(); ++i) {
      const ZipBuilderMember & member = members_[i];
      std::string entry;
      entry += (break_signature_ == 'c' && break_index_ == i)
          ? std::string("PK\x01\x03", 4) : std::string("PK\x01\x02", 4);
      append16(entry, member.version_made_by);
      append16(entry, 20u);
      append16(entry, member.flags);
      append16(entry, member.method);
      append16(entry, member.dos_time);
      append16(entry, member.dos_date);
      append32(entry, member.crc);
      append32(entry, member.override_sizes
          ? member.central_compressed_size
          : static_cast<uint32_t>(member.data.size()));
      append32(entry, member.override_sizes
          ? member.central_size
          : static_cast<uint32_t>(member.data.size()));
      append16(entry, member.override_name_length
          ? member.name_length
          : static_cast<uint16_t>(member.name.size()));
      append16(entry, static_cast<uint16_t>(member.central_extra.size()));
      append16(entry, 0u); // comment length
      append16(entry, member.disk_start);
      append16(entry, 0u); // internal attributes
      append32(entry, member.external_attributes);
      append32(entry, member.override_local_offset ? member.local_offset
                                                   : offsets[i]);
      out += entry;
      out += member.name;
      out += member.central_extra;
    }
    const uint32_t central_size
        = static_cast<uint32_t>(out.size() - prologue_.size() - central_start);

    // zip64: the end record and its locator go between the central directory and
    // the ordinary end record, which is where a reader finds them by looking at
    // the 20 bytes in front of the one it already found.
    uint64_t zip64_record_at = 0;
    if (zip64_) {
      zip64_record_at = out.size() - prologue_.size();
      std::string record(zip64_break_record_ ? "PK\x06\x05" : "PK\x06\x06", 4);
      append64(record, GARC_ZIP_ZIP64_EOCD_SIZE_TEST - 12u); // size of what follows
      append16(record, 45u); // version made by
      append16(record, 45u); // version needed
      append32(record, zip64_record_disk_);
      append32(record, zip64_record_disk_);
      append64(record, members_.size());
      append64(record, members_.size());
      append64(record, central_size);
      append64(record, central_start);
      out += record;

      std::string locator("PK\x06\x07", 4);
      append32(locator, zip64_locator_disk_);
      append64(locator, zip64_locator_offset_ >= 0
          ? static_cast<uint64_t>(zip64_locator_offset_) : zip64_record_at);
      append32(locator, zip64_total_disks_);
      out += locator;
    }

    std::string eocd("PK\x05\x06", 4);
    append16(eocd, disk_);
    append16(eocd, central_disk_);
    append16(eocd, static_cast<uint16_t>(entries_here_ >= 0
        ? entries_here_
        : (declared_ >= 0 ? declared_ : static_cast<int>(members_.size()))));
    append16(eocd, static_cast<uint16_t>(declared_ >= 0
        ? declared_ : static_cast<int>(members_.size())));
    if (zip64_ || zip64_markers_only_) {
      // The markers that say "the real values are in the zip64 record". A writer
      // producing zip64 records writes these whatever the values would have been,
      // which is why a reader has to look for the locator rather than waiting for
      // a marker to tell it to.
      append32(eocd, 0xFFFFFFFFu);
      append32(eocd, 0xFFFFFFFFu);
    }
    else {
      append32(eocd, static_cast<uint32_t>(declared_central_size_ >= 0
          ? declared_central_size_ : central_size));
      append32(eocd, static_cast<uint32_t>(declared_central_offset_ >= 0
          ? declared_central_offset_ : central_start));
    }
    append16(eocd, static_cast<uint16_t>(comment_.size()));
    out += eocd;
    out += comment_;
    out += trailer_;

    return std::vector<uint8_t>(out.begin(), out.end());
  }

  /** CRC-32, so a well-formed archive has a correct one. */
  static uint32_t crc32(const std::string & data) {
    static uint32_t table[256];
    static bool ready = false;
    if (!ready) {
      for (uint32_t i = 0; i < 256u; ++i) {
        uint32_t value = i;
        for (int bit = 0; bit < 8; ++bit) {
          value = (value & 1u) ? (0xEDB88320u ^ (value >> 1)) : (value >> 1);
        }
        table[i] = value;
      }
      ready = true;
    }
    uint32_t crc = 0xFFFFFFFFu;
    for (char byte : data) {
      crc = table[(crc ^ static_cast<uint8_t>(byte)) & 0xFFu] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFFu;
  }

  static void append16(std::string & out, uint16_t value) {
    out.push_back(static_cast<char>(value & 0xFFu));
    out.push_back(static_cast<char>((value >> 8) & 0xFFu));
  }

  static void append32(std::string & out, uint32_t value) {
    append16(out, static_cast<uint16_t>(value & 0xFFFFu));
    append16(out, static_cast<uint16_t>((value >> 16) & 0xFFFFu));
  }

  static void append64(std::string & out, uint64_t value) {
    append32(out, static_cast<uint32_t>(value & 0xFFFFFFFFu));
    append32(out, static_cast<uint32_t>((value >> 32) & 0xFFFFFFFFu));
  }

private:
  std::vector<ZipBuilderMember> members_;
  std::string prologue_;
  std::string comment_;
  std::string trailer_;
  int declared_ = -1;
  int entries_here_ = -1;
  int64_t declared_central_size_ = -1;
  int64_t declared_central_offset_ = -1;
  uint16_t disk_ = 0;
  uint16_t central_disk_ = 0;
  bool zip64_ = false;
  bool zip64_markers_only_ = false;
  bool zip64_break_record_ = false;
  uint32_t zip64_locator_disk_ = 0;
  uint32_t zip64_record_disk_ = 0;
  uint32_t zip64_total_disks_ = 1u;
  int64_t zip64_locator_offset_ = -1;
  char break_signature_ = 0;
  size_t break_index_ = 0;
};

} // namespace garctest

#endif // GHOTI_IO_GARC_TEST_ZIP_BUILDER_H
