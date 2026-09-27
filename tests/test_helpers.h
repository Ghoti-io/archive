/**
 * @file
 *
 * Shared test helpers: the failing allocator, and the four stream shapes a
 * caller can hand this library.
 *
 * The stream shapes are the point. A memory stream is seekable and knows its
 * size, so a suite that only ever uses one tests exactly one of four
 * combinations, and the other three are what a caller reading from a pipe, a
 * socket, or a stream still being written actually has. Two features tested
 * alone leave their product untested, and seekability and known-size are two
 * features.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#ifndef GHOTI_IO_GARC_TEST_TEST_HELPERS_H
#define GHOTI_IO_GARC_TEST_TEST_HELPERS_H

#include <cstdint>
#include <cstring>
#include <vector>

#include <ghoti.io/archive/archive.h>

#include "failing_allocator.h"

namespace garctest {

/**
 * A callback stream over a buffer, whose seekability and known-size are
 * constructor parameters.
 *
 * `can_seek = false, knows_size = false` is a pipe. `true, false` is a stream
 * being appended to. `false, true` is a socket whose length arrived in a
 * header. `true, true` is a file, which is the only one a memory stream can
 * stand in for.
 */
class BufferSource {
public:
  BufferSource(const void * data, size_t size, bool can_seek, bool knows_size)
      : bytes_(static_cast<const uint8_t *>(data),
            static_cast<const uint8_t *>(data) + size) {
    callbacks_.ctx = this;
    callbacks_.read = &BufferSource::read_cb;
    callbacks_.seek = can_seek ? &BufferSource::seek_cb : nullptr;
    callbacks_.size = knows_size ? &BufferSource::size_cb : nullptr;
  }

  BufferSource(const BufferSource &) = delete;
  BufferSource & operator=(const BufferSource &) = delete;

  const GARC_Stream_Callbacks * callbacks() const { return &callbacks_; }

  /** Reads served, so a test can show a skip did not read on a seekable one. */
  size_t reads() const { return reads_; }

  /** Seeks served. */
  size_t seeks() const { return seeks_; }

  /** Bytes handed over, which a read-and-discard skip moves and a seek does
   *  not. */
  size_t bytes_read() const { return bytes_read_; }

  /**
   * Make the next @p count reads report ::GARC_ERR_IO.
   *
   * A real read failure is not a short read, and the two have to be
   * distinguishable: a short read is the end of the stream and an error is a
   * failure to reach it.
   */
  void fail_reads(size_t count) { failing_reads_ = count; }

  /** Make every seek report ::GARC_ERR_IO. */
  void fail_seeks() { seek_fails_ = true; }

  /**
   * Accept a seek past the end, the way an ordinary file does.
   *
   * lseek() past the end of a file succeeds; the read afterwards returns
   * nothing. A source that refuses instead is the friendlier of the two and is
   * not the one a caller wrapping a FILE * will write, so both have to be
   * covered.
   */
  void allow_seek_past_end() { permissive_seek_ = true; }

  /** Make every size query report ::GARC_ERR_IO. */
  void fail_size() { size_fails_ = true; }

private:
  static GARC_Result read_cb(
      void * ctx, void * buffer, size_t size, size_t * out_read) {
    BufferSource * self = static_cast<BufferSource *>(ctx);
    self->reads_++;
    if (self->failing_reads_) {
      self->failing_reads_--;
      return GARC_ERR_IO;
    }
    // pos_ can sit past the end, because allow_seek_past_end() lets a seek put
    // it there the way lseek() does. Clamping rather than subtracting blindly:
    // the subtraction underflows and hands back a huge count, which reads as a
    // successful read of bytes that do not exist.
    size_t remaining =
        self->pos_ < self->bytes_.size() ? self->bytes_.size() - self->pos_ : 0;
    size_t take = size < remaining ? size : remaining;
    if (take) {
      std::memcpy(buffer, self->bytes_.data() + self->pos_, take);
      self->pos_ += take;
    }
    self->bytes_read_ += take;
    *out_read = take;
    return GARC_OK;
  }

  static GARC_Result seek_cb(void * ctx, uint64_t offset) {
    BufferSource * self = static_cast<BufferSource *>(ctx);
    self->seeks_++;
    if (self->seek_fails_) {
      return GARC_ERR_IO;
    }
    if (offset > self->bytes_.size() && !self->permissive_seek_) {
      return GARC_ERR_IO;
    }
    self->pos_ = static_cast<size_t>(offset);
    return GARC_OK;
  }

  static GARC_Result size_cb(void * ctx, uint64_t * out_size) {
    const BufferSource * self = static_cast<const BufferSource *>(ctx);
    if (self->size_fails_) {
      return GARC_ERR_IO;
    }
    *out_size = self->bytes_.size();
    return GARC_OK;
  }

  std::vector<uint8_t> bytes_;
  GARC_Stream_Callbacks callbacks_{};
  size_t pos_ = 0;
  size_t reads_ = 0;
  size_t seeks_ = 0;
  size_t bytes_read_ = 0;
  size_t failing_reads_ = 0;
  bool seek_fails_ = false;
  bool permissive_seek_ = false;
  bool size_fails_ = false;
};

/**
 * A read callback that lies about how much it read, claiming more than it was
 * asked for.
 *
 * Nothing legitimate does this. It exists because the library checks for it,
 * and a check nothing exercises is a check nobody knows is there.
 */
inline GARC_Result overclaiming_read(
    void * ctx, void * buffer, size_t size, size_t * out_read) {
  (void)ctx;
  (void)buffer;
  *out_read = size + 1u;
  return GARC_OK;
}

} // namespace garctest

#endif // GHOTI_IO_GARC_TEST_TEST_HELPERS_H
