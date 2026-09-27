/**
 * @file
 *
 * libFuzzer harness for the member-name classifier.
 *
 * The cheapest harness in this library and one of the more useful, because
 * ::garc_name_check() is a **pure function of its bytes**: no options byte, no
 * stream shape, no allocator. Whatever the fuzzer produces is a valid input, so
 * every execution explores the parser rather than the setup.
 *
 * Surviving is the weakest thing it checks. The invariants below are structural -
 * each one is a relation between findings that holds by construction, so a wrong
 * answer breaks one of them rather than merely looking odd:
 *
 * - Every bit set is a bit this build knows about. A finding from nowhere means
 *   the mask and the enum have come apart.
 * - ::GARC_NAME_EMPTY is set exactly when there are no bytes.
 * - A traversal implies a parent component: the only place the escape flag is set
 *   is the `..` arm, so one without the other is an arithmetic bug.
 * - ::GARC_NAME_WINDOWS_TRAVERSAL implies a backslash, and never appears beside
 *   ::GARC_NAME_TRAVERSAL - it is asked only when the POSIX reading does not
 *   escape, so reporting both would be saying the same thing twice.
 * - **Prefixing a component can only make an escape less likely.** `safe/` adds
 *   one to the depth before anything else runs, so if the prefixed name escapes
 *   then the bare one did too. That is the metamorphic property a depth counter
 *   that drifted by one would break, and it needs no expected answer to check.
 *
 * Build with: make fuzz-name
 * Run:        make fuzz-run-name FUZZ_TIME=300
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

#include <ghoti.io/archive/archive.h>

namespace {

[[noreturn]] void broken(const char * what) {
  std::fprintf(stderr, "name invariant broken: %s\n", what);
  std::abort();
}

#define REQUIRE(cond, what)                                                    \
  do {                                                                         \
    if (!(cond)) {                                                             \
      broken(what);                                                            \
    }                                                                          \
  } while (0)

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t * data, size_t size) {
  const char * name = reinterpret_cast<const char *>(data);
  const uint32_t findings = garc_name_check(name, size);

  REQUIRE((findings & ~GARC_NAME_FINDING_ALL) == 0u,
      "a finding outside GARC_NAME_FINDING_ALL");
  REQUIRE(((findings & GARC_NAME_EMPTY) != 0u) == (size == 0u),
      "GARC_NAME_EMPTY does not match having no bytes");

  if (findings & GARC_NAME_TRAVERSAL) {
    REQUIRE(findings & GARC_NAME_PARENT_COMPONENT,
        "a traversal with no parent component in it");
  }
  if (findings & GARC_NAME_WINDOWS_TRAVERSAL) {
    REQUIRE(findings & GARC_NAME_BACKSLASH,
        "a backslash traversal in a name with no backslash");
    REQUIRE(!(findings & GARC_NAME_TRAVERSAL),
        "both traversal findings on one name");
  }

  // The metamorphic check. A leading component can only add depth, so it cannot
  // turn a name that stays inside into one that escapes.
  std::string prefixed("safe/");
  prefixed.append(name, size);
  const uint32_t deeper = garc_name_check(prefixed.data(), prefixed.size());
  if (deeper & GARC_NAME_TRAVERSAL) {
    REQUIRE(findings & GARC_NAME_TRAVERSAL,
        "prefixing a component turned a contained name into an escape");
  }
  // And the prefix itself is never an escape, whatever follows it.
  REQUIRE(!(deeper & GARC_NAME_ABSOLUTE),
      "a name beginning with a component is absolute");

  return 0;
}
