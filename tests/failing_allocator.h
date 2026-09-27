/**
 * @file
 *
 * An allocator that refuses a nominated allocation, for driving the error
 * arms that a working allocator can never reach.
 *
 * Its own header, with no gtest in it, because both the unit tests and the
 * fuzz harnesses need it and a second copy would drift. The fuzzers reach it
 * as "../failing_allocator.h"; tests/test_helpers.h pulls it in for everything
 * else.
 *
 * Adapted from model's, which is where the three-setting argument below was
 * measured.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#ifndef GHOTI_IO_GARC_TEST_FAILING_ALLOCATOR_H
#define GHOTI_IO_GARC_TEST_FAILING_ALLOCATOR_H

#include <cstddef>
#include <cstdlib>

#include <ghoti.io/archive/allocator.h>

namespace garctest {

/**
 * An allocator that refuses one nominated request and serves every other.
 *
 * Allocation failure is a code path, and it is one an allocator that always
 * succeeds never reaches. An allocator that always fails is no better: it
 * reaches the first arm and no other.
 *
 * So the refusal is a dial. Constructed with `n`, this serves every request
 * but the nth; sweeping n from zero upwards walks a single refusal through the
 * whole of a call, one site at a time.
 *
 * **How many requests to refuse is a parameter, and all three settings are
 * needed.** Each was arrived at in model by planting a defect the previous
 * setting could not see:
 *
 * - `run = 0`, every request from the nth onwards. What genuine exhaustion
 *   looks like, and the only setting that fails a cutil growable array at all:
 *   its `reserve_n()` answers a refused 1.5x growth by retrying at the exact
 *   size needed, on purpose, so refusing one request never fails an append.
 * - `run = 1`, the nth request alone. The only setting that can show a refusal
 *   being survived *and losing something*: under sustained refusal an arm that
 *   gives up quietly carries on, asks for the next allocation, is refused
 *   again, and the call ends up failing for the right reason by accident.
 * - `run = 2`, the nth and the one after. What it takes to fail a single
 *   *append* rather than a single request, since that retry makes one logical
 *   append cost two. `run = 1` cannot fail an append at all and `run = 0`
 *   cannot survive one; a quiet give-up in an append arm is invisible to both.
 *
 * `run = 2` does not subsume `run = 1`: where two unrelated single-request
 * sites sit next to each other it refuses both, and a defect at the first can
 * be hidden by the call dying correctly at the second.
 *
 * It also counts live blocks, because an abandoned call has two ways to be
 * wrong and the interesting one is silent: reporting the failure and keeping
 * what it had already built. `live()` is the check for that, and it means the
 * sweep does not depend on running under a sanitizer to be worth anything.
 *
 * Refusal is spelled exactly as the allocator contract spells it - NULL, with
 * the caller's block untouched on a realloc, since a realloc() that fails must
 * leave the original allocation alone.
 */
class FailingAllocator {
public:
  /**
   * Refuse @p run requests starting at request number @p fail_at.
   *
   * @param fail_at The first request to refuse, counting from zero.
   *   `(size_t)-1` refuses none, which is how a call's cost is measured before
   *   the sweep walks it.
   * @param run How many consecutive requests to refuse; 0 means every one from
   *   @p fail_at onwards. See the note above: the three settings see three
   *   different things and none of them sees all of it.
   */
  explicit FailingAllocator(size_t fail_at, size_t run = 1)
      : fail_at_(fail_at), run_(run) {
    allocator_.ctx = this;
    allocator_.malloc_fn = &FailingAllocator::malloc_cb;
    allocator_.calloc_fn = &FailingAllocator::calloc_cb;
    allocator_.realloc_fn = &FailingAllocator::realloc_cb;
    allocator_.free_fn = &FailingAllocator::free_cb;
  }

  // Neither copyable nor movable: the struct handed to the library holds a
  // pointer back to this object.
  FailingAllocator(const FailingAllocator &) = delete;
  FailingAllocator & operator=(const FailingAllocator &) = delete;

  const GARC_Allocator * get() const { return &allocator_; }

  /** Whether a nominated request happened, i.e. a refusal was served. */
  bool failed() const { return failed_; }

  /** Blocks handed out and not yet given back. */
  size_t live() const { return live_; }

  /** Requests made, refused ones included. */
  size_t requests() const { return requests_; }

  /**
   * Stop refusing, without forgetting that a refusal was served.
   *
   * An object carries the allocator it was built with, so whatever a test does
   * with it afterwards - reading from it, destroying it - comes back through
   * this object. Leaving the refusal armed would make those fail too, and a
   * sweep would end up measuring its own instrument. `failed()` still reports
   * what happened while it was armed.
   */
  void stop_failing() { fail_at_ = static_cast<size_t>(-1); }

private:
  /** Whether this request is refused, and record it if so. */
  bool refuse() {
    size_t index = requests_++;
    if (index < fail_at_) {
      return false;
    }
    // Subtraction rather than fail_at_ + run_, which overflows for the
    // (size_t)-1 that means "refuse nothing".
    if (run_ != 0 && index - fail_at_ >= run_) {
      return false;
    }
    failed_ = true;
    return true;
  }

  static void * malloc_cb(void * ctx, size_t size) {
    FailingAllocator * self = static_cast<FailingAllocator *>(ctx);
    if (self->refuse()) {
      return nullptr;
    }
    // A zero-size request must still yield a usable pointer, so that NULL
    // always means failure; see allocator.h.
    void * p = std::malloc(size ? size : 1);
    if (p) {
      self->live_++;
    }
    return p;
  }

  static void * calloc_cb(void * ctx, size_t nitems, size_t size) {
    FailingAllocator * self = static_cast<FailingAllocator *>(ctx);
    // Overflow is an allocation failure, not a truncated block (allocator.h).
    // It is not the nominated refusal either, so it does not consume it.
    if (nitems && size > static_cast<size_t>(-1) / nitems) {
      return nullptr;
    }
    if (self->refuse()) {
      return nullptr;
    }
    size_t total = nitems * size;
    void * p = std::calloc(1, total ? total : 1);
    if (p) {
      self->live_++;
    }
    return p;
  }

  static void * realloc_cb(void * ctx, void * ptr, size_t size) {
    FailingAllocator * self = static_cast<FailingAllocator *>(ctx);
    if (self->refuse()) {
      return nullptr; // The caller's block is still theirs and still valid.
    }
    void * p = std::realloc(ptr, size ? size : 1);
    if (p && !ptr) {
      self->live_++;
    }
    return p;
  }

  static void free_cb(void * ctx, void * ptr) {
    FailingAllocator * self = static_cast<FailingAllocator *>(ctx);
    if (ptr) {
      self->live_--;
    }
    std::free(ptr);
  }

  GARC_Allocator allocator_{};
  size_t fail_at_;
  size_t run_;
  size_t requests_ = 0;
  size_t live_ = 0;
  bool failed_ = false;
};

} // namespace garctest

#endif // GHOTI_IO_GARC_TEST_FAILING_ALLOCATOR_H
