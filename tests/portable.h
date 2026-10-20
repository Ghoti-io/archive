/**
 * @file
 *
 * The POSIX conveniences the tests used, made portable.
 *
 * `open_memstream`, `fmemopen` and `timegm` are POSIX or BSD, not C17, and the
 * Windows C runtime has none of them, so tests that called them did not compile
 * for win64. `tmpfile()` is no substitute there either: the Windows runtime
 * creates it in the root of the current drive, which an ordinary user often
 * cannot write. So a captured stream is a cutil temporary file, which goes in
 * the system's temporary directory on every platform.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#ifndef GHOTI_IO_GARC_TEST_PORTABLE_H
#define GHOTI_IO_GARC_TEST_PORTABLE_H

#include <cstdint>
#include <cstdio>
#include <ctime>
#include <string>

#include <ghoti.io/cutil/file.h>

namespace garctest {

/**
 * A `FILE *` whose contents can be read back as a string, in place of
 * `open_memstream`.
 *
 * `file()` is NULL if the temporary could not be made, which a test asserts as
 * it asserted the `open_memstream` result. `text()` may be called at any time
 * and leaves the stream at its end. `close()` is the old `fclose`, and the
 * destructor does it if the test did not.
 */
class MemStream {
public:
  MemStream() {
    if (gcu_file_temp_create(&temp_, nullptr, "garc-capture", nullptr)
        == GCU_FILE_OK) {
      file_ = gcu_file_temp_stream(&temp_);
    }
  }

  ~MemStream() { gcu_file_temp_abort(&temp_); }

  MemStream(const MemStream &) = delete;
  MemStream & operator=(const MemStream &) = delete;

  FILE * file() const { return file_; }

  /** Everything written so far. */
  std::string text() {
    if (!file_) {
      return text_;
    }
    std::fflush(file_);
    std::rewind(file_);
    std::string out;
    char buffer[4096];
    size_t got = 0;
    while ((got = std::fread(buffer, 1, sizeof(buffer), file_)) > 0) {
      out.append(buffer, got);
    }
    std::fseek(file_, 0, SEEK_END);
    return out;
  }

  /** Stop writing; the text stays readable. */
  void close() {
    if (file_) {
      text_ = text();
      file_ = nullptr;
      gcu_file_temp_abort(&temp_);
    }
  }

private:
  GCU_File_Temp temp_{};
  FILE * file_ = nullptr;
  std::string text_;
};

/**
 * Seconds since the epoch for a broken-down UTC time, in place of `timegm`.
 *
 * Days from the civil date by the proleptic Gregorian rule, which is what
 * `timegm` computes and needs no time zone database.
 */
inline int64_t utc_seconds(const std::tm & t) {
  int64_t year = static_cast<int64_t>(t.tm_year) + 1900;
  const int64_t month = static_cast<int64_t>(t.tm_mon) + 1;
  year -= month <= 2 ? 1 : 0;
  const int64_t era = (year >= 0 ? year : year - 399) / 400;
  const int64_t yoe = year - era * 400;
  const int64_t doy = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + t.tm_mday - 1;
  const int64_t doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  const int64_t days = era * 146097 + doe - 719468;
  return days * 86400 + static_cast<int64_t>(t.tm_hour) * 3600
      + static_cast<int64_t>(t.tm_min) * 60 + t.tm_sec;
}

} // namespace garctest

#endif // GHOTI_IO_GARC_TEST_PORTABLE_H
