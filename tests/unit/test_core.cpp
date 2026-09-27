/**
 * @file
 *
 * The result vocabulary, the two result predicates, the default limits, and
 * the version the library reports at run time.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <set>
#include <string>

#include <gtest/gtest.h>

#include "test_helpers.h"

TEST(Result, StringIsDistinctAndPresentForEveryConstant) {
  // RESULT_COUNT closes the enum so that this loop is exhaustive by
  // construction: a constant added without a string shows up here rather than
  // the next time somebody prints one.
  std::set<std::string> seen;
  for (int i = 0; i < GARC_RESULT_COUNT; ++i) {
    GARC_Result result = static_cast<GARC_Result>(i);
    const char * text = garc_result_string(result);
    ASSERT_NE(text, nullptr) << "result " << i;
    EXPECT_STRNE(text, "") << "result " << i;
    EXPECT_STRNE(text, "Unknown error")
        << "result " << i << " falls through to the default arm";
    EXPECT_TRUE(seen.insert(text).second)
        << "result " << i << " shares its string with an earlier one: " << text;
  }
}

TEST(Result, StringForAValueOutsideTheEnumIsTheUnknownArm) {
  EXPECT_STREQ(garc_result_string(GARC_RESULT_COUNT), "Unknown error");
  EXPECT_STREQ(
      garc_result_string(static_cast<GARC_Result>(9999)), "Unknown error");
}

TEST(Result, EveryLimitStringNamesWhichLimit) {
  // Five constants buy nothing if the message a caller prints is the same for
  // all of them.
  const GARC_Result limits[] = {
    GARC_ERR_LIMIT_MEMBERS,
    GARC_ERR_LIMIT_MEMBER_BYTES,
    GARC_ERR_LIMIT_TOTAL_BYTES,
    GARC_ERR_LIMIT_NAME_BYTES,
    GARC_ERR_LIMIT_EXTRA_BYTES,
  };
  for (GARC_Result result : limits) {
    std::string text = garc_result_string(result);
    EXPECT_NE(text.find("Limit exceeded: "), std::string::npos) << text;
    EXPECT_GT(text.size(), std::strlen("Limit exceeded: ")) << text;
  }
}

TEST(Result, IsErrorIsFalseForExactlyOkAndEnd) {
  // The end of a well-formed archive is not a failure. A caller writing
  // `result != GARC_OK` would report one on every complete read, which is why
  // the predicate exists and why this asserts both directions.
  for (int i = 0; i < GARC_RESULT_COUNT; ++i) {
    GARC_Result result = static_cast<GARC_Result>(i);
    bool expected = !(result == GARC_OK || result == GARC_END);
    EXPECT_EQ(garc_result_is_error(result) != 0, expected)
        << garc_result_string(result);
  }
}

TEST(Result, IsLimitIsTrueForExactlyTheFiveLimitCodes) {
  int limit_count = 0;
  for (int i = 0; i < GARC_RESULT_COUNT; ++i) {
    GARC_Result result = static_cast<GARC_Result>(i);
    if (garc_result_is_limit(result)) {
      ++limit_count;
      // A limit is a failure. If one ever stops being, the two predicates
      // disagree and a caller believing either is wrong.
      EXPECT_TRUE(garc_result_is_error(result))
          << garc_result_string(result) << " is a limit but not an error";
    }
  }
  EXPECT_EQ(limit_count, 5);
  EXPECT_FALSE(garc_result_is_limit(GARC_OK));
  EXPECT_FALSE(garc_result_is_limit(GARC_ERR_CORRUPT));
  EXPECT_FALSE(garc_result_is_limit(GARC_RESULT_COUNT));
}

TEST(Limits, DefaultMatchesTheNamedConstants) {
  // The constants are what the header documents. A test reading the struct
  // back against literals would pin whatever the initialiser happens to say.
  GARC_Limits limits;
  std::memset(&limits, 0xAA, sizeof(limits));
  garc_limits_default(&limits);

  EXPECT_EQ(limits.max_members, GARC_DEFAULT_MAX_MEMBERS);
  EXPECT_EQ(limits.max_member_bytes, GARC_DEFAULT_MAX_MEMBER_BYTES);
  EXPECT_EQ(limits.max_total_bytes, GARC_DEFAULT_MAX_TOTAL_BYTES);
  EXPECT_EQ(limits.max_name_bytes, GARC_DEFAULT_MAX_NAME_BYTES);
  EXPECT_EQ(limits.max_extra_bytes, GARC_DEFAULT_MAX_EXTRA_BYTES);
}

TEST(Limits, EveryDefaultIsBounded) {
  // core.h claims every default is non-zero, because zero means unlimited and
  // a member's declared size is read before any of its bytes are. A field
  // added to the struct and left out of the initialiser lands here as a zero.
  GARC_Limits limits;
  garc_limits_default(&limits);

  EXPECT_NE(limits.max_members, 0u);
  EXPECT_NE(limits.max_member_bytes, 0u);
  EXPECT_NE(limits.max_total_bytes, 0u);
  EXPECT_NE(limits.max_name_bytes, 0u);
  EXPECT_NE(limits.max_extra_bytes, 0u);
}

TEST(Limits, TotalIsAtLeastOneMemberWorth) {
  // A total below the per-member cap would make the per-member cap
  // unreachable, so one of the two would be testing nothing.
  GARC_Limits limits;
  garc_limits_default(&limits);
  EXPECT_GE(limits.max_total_bytes, limits.max_member_bytes);
}

TEST(Limits, DefaultIgnoresNull) {
  garc_limits_default(nullptr);
}

TEST(Allocator, DefaultSuppliesAllFourFunctions) {
  const GARC_Allocator * allocator = garc_allocator_default();
  ASSERT_NE(allocator, nullptr);
  EXPECT_NE(allocator->malloc_fn, nullptr);
  EXPECT_NE(allocator->calloc_fn, nullptr);
  EXPECT_NE(allocator->realloc_fn, nullptr);
  EXPECT_NE(allocator->free_fn, nullptr);
}

TEST(Version, RuntimeAgreesWithTheCompiledMacros) {
  // These differ only when a shared library has been upgraded underneath a
  // binary, which is the case they exist to make visible. In this test binary
  // they must agree.
  EXPECT_STREQ(garc_version_string(), GARC_VERSION_STRING);
  EXPECT_EQ(garc_version_number(), GARC_VERSION_NUMBER);
}

TEST(Version, PackingIsOneBytePerComponent) {
  EXPECT_EQ(GARC_MAKE_VERSION(1, 2, 3), 0x010203u);
  EXPECT_LT(GARC_MAKE_VERSION(1, 2, 3), GARC_MAKE_VERSION(1, 3, 0));
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
