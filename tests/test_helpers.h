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

  /**
   * Let @p successes reads through, then fail the next @p count.
   *
   * fail_reads() cannot reach a failure arm that is only taken after the format
   * reader has already read something - and a zip reads its end record, its
   * central directory, a local header and a member's data through four different
   * arms, each of which reports a read failure separately. This is how a test
   * picks one of them.
   */
  void fail_reads_after(size_t successes, size_t count = 1) {
    reads_before_failing_ = successes;
    failing_reads_ = count;
  }

  /** Let @p successes seeks through, then fail every seek after them. */
  void fail_seeks_after(size_t successes) {
    seeks_before_failing_ = successes;
    seek_fails_ = true;
  }

private:
  static GARC_Result read_cb(
      void * ctx, void * buffer, size_t size, size_t * out_read) {
    BufferSource * self = static_cast<BufferSource *>(ctx);
    self->reads_++;
    if (self->reads_before_failing_) {
      self->reads_before_failing_--;
    }
    else if (self->failing_reads_) {
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
    if (self->seeks_before_failing_) {
      self->seeks_before_failing_--;
    }
    else if (self->seek_fails_) {
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
  /** Reads to let through before failing_reads_ starts counting. */
  size_t reads_before_failing_ = 0;
  /** Seeks to let through before seek_fails_ applies. */
  size_t seeks_before_failing_ = 0;
  size_t seeks_ = 0;
  size_t bytes_read_ = 0;
  size_t failing_reads_ = 0;
  bool seek_fails_ = false;
  bool permissive_seek_ = false;
  bool size_fails_ = false;
};

/**
 * A callback sink that collects what it is given, and can refuse.
 *
 * The mirror of BufferSource, and it needs no shape parameters because a sink
 * has only one operation - which is the argument sink.h makes for it being a
 * type of its own rather than a stream with a `write` added.
 */
class BufferDrain {
public:
  BufferDrain() {
    callbacks_.ctx = this;
    callbacks_.write = &BufferDrain::write_cb;
  }

  BufferDrain(const BufferDrain &) = delete;
  BufferDrain & operator=(const BufferDrain &) = delete;

  const GARC_Sink_Callbacks * callbacks() const { return &callbacks_; }

  /** Everything accepted so far, in order. */
  const std::vector<uint8_t> & bytes() const { return bytes_; }

  /**
   * Calls served, refused ones included.
   *
   * A writer that pads a block one byte at a time and one that pads it in a
   * single call produce identical bytes, so the count is the only way to assert
   * which happened - and the difference is 511 calls per member on a socket.
   */
  size_t writes() const { return writes_; }

  /** Make the next @p count writes report ::GARC_ERR_IO. */
  void fail_writes(size_t count) { failing_writes_ = count; }

  /**
   * Make the write with this index - counting from the next one - fail.
   *
   * `fail_writes(1)` can only reach the first write of a sequence, so a call that
   * makes several - a tar extended header is a header block, its records, and the
   * padding after them - would have its second and third arms left untested by a
   * sweep that looked like it covered them.
   */
  void fail_write_at(size_t index) {
    skip_writes_ = index;
    failing_writes_ = 1;
  }

private:
  static GARC_Result write_cb(void * ctx, const void * buffer, size_t size) {
    BufferDrain * self = static_cast<BufferDrain *>(ctx);
    self->writes_++;
    if (self->skip_writes_) {
      self->skip_writes_--;
    } else if (self->failing_writes_) {
      self->failing_writes_--;
      // All or nothing: a refused write keeps none of the bytes, which is what
      // lets a test assert that a failed write left the sink's count alone.
      return GARC_ERR_IO;
    }
    const uint8_t * in = static_cast<const uint8_t *>(buffer);
    self->bytes_.insert(self->bytes_.end(), in, in + size);
    return GARC_OK;
  }

  GARC_Sink_Callbacks callbacks_{};
  std::vector<uint8_t> bytes_;
  size_t writes_ = 0;
  size_t failing_writes_ = 0;
  size_t skip_writes_ = 0;
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
