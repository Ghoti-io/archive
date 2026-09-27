/**
 * @file
 *
 * tar's numeric header fields, at the field level.
 *
 * **White-box, and deliberately.** The parser is reached directly rather than
 * through a header, because the field width is one of its parameters and the two
 * widths a tar header uses - 8 and 12 bytes - land on different branches of the
 * base-256 arithmetic. A 12-byte field carries 95 bits of two's complement and
 * has to have its leading bits checked for sign extension before any are
 * dropped; an 8-byte field carries 63 and does not. Going through a header would
 * reach one of those and leave the other looking covered because the file was.
 *
 * The declarations are internal; the tests link the static archive, which is
 * what makes a hidden symbol resolvable.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstdint>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <ghoti.io/archive/archive.h>

#include "tar/tar_internal.h"

namespace {

/** A field of `width` bytes from a list, NUL-padded to the width. */
std::vector<uint8_t> field(std::vector<uint8_t> bytes, size_t width) {
  bytes.resize(width, 0);
  return bytes;
}

uint64_t parse_uint(const std::vector<uint8_t> & bytes,
    GARC_Result * out_result = nullptr) {
  uint64_t value = 0xDEADBEEFu;
  GARC_Result result
      = garc_tar_parse_uint(bytes.data(), bytes.size(), &value);
  if (out_result) {
    *out_result = result;
  }
  return value;
}

int64_t parse_int(const std::vector<uint8_t> & bytes,
    GARC_Result * out_result = nullptr) {
  int64_t value = -99;
  GARC_Result result = garc_tar_parse_int(bytes.data(), bytes.size(), &value);
  if (out_result) {
    *out_result = result;
  }
  return value;
}

/** Base-256 of `value` in `width` bytes, the way GNU tar writes it. */
std::vector<uint8_t> base256(uint64_t value, size_t width) {
  std::vector<uint8_t> bytes(width, 0);
  for (size_t i = width; i-- > 0;) {
    bytes[i] = static_cast<uint8_t>(value & 0xFFu);
    value >>= 8;
  }
  bytes[0] = static_cast<uint8_t>(bytes[0] | 0x80u);
  return bytes;
}

} // namespace

//-----------------------------------------------------------------------------
// Octal
//-----------------------------------------------------------------------------

TEST(TarNumberOctal, EveryPaddingAndTerminatorSpelling) {
  GARC_Result result = GARC_ERR_INTERNAL;

  // Zero-padded with a NUL: what every modern writer produces.
  EXPECT_EQ(parse_uint({'0', '0', '0', '0', '6', '4', '4', 0}, &result), 0644u);
  EXPECT_EQ(result, GARC_OK);
  // Space-terminated.
  EXPECT_EQ(parse_uint({'0', '0', '0', '0', '6', '4', '4', ' '}), 0644u);
  // Space-padded at the front, which POSIX permits.
  EXPECT_EQ(parse_uint({' ', ' ', ' ', ' ', '6', '4', '4', 0}), 0644u);
  // NUL-padded at the front, which it does not and which occurs anyway.
  EXPECT_EQ(parse_uint({0, 0, 0, 0, '6', '4', '4', 0}), 0644u);
  // Full field, no terminator at all.
  EXPECT_EQ(parse_uint({'0', '0', '0', '0', '0', '6', '4', '4'}), 0644u);
  // Both terminators.
  EXPECT_EQ(parse_uint({'6', '4', '4', ' ', 0, 0, 0, 0}), 0644u);
}

TEST(TarNumberOctal, ABlankFieldIsZero) {
  // v7 writers leave a field they have no value for blank, and the device
  // numbers are blank in almost every archive there is.
  GARC_Result result = GARC_ERR_INTERNAL;
  EXPECT_EQ(parse_uint(std::vector<uint8_t>(8, ' '), &result), 0u);
  EXPECT_EQ(result, GARC_OK);
  EXPECT_EQ(parse_uint(std::vector<uint8_t>(8, 0), &result), 0u);
  EXPECT_EQ(result, GARC_OK);
  // Padding then a terminator, with no digits between: the same case by a
  // different route through the parser.
  EXPECT_EQ(parse_uint({' ', ' ', 0, 0, 0, 0, 0, 0}, &result), 0u);
  EXPECT_EQ(result, GARC_OK);
}

TEST(TarNumberOctal, ANonOctalDigitIsRefused) {
  GARC_Result result = GARC_OK;
  parse_uint({'0', '0', '0', '0', '0', '0', '8', 0}, &result);
  EXPECT_EQ(result, GARC_ERR_CORRUPT) << "'8' is not an octal digit";
  parse_uint({'0', '0', '0', '0', '0', '0', 'x', 0}, &result);
  EXPECT_EQ(result, GARC_ERR_CORRUPT);
}

TEST(TarNumberOctal, DigitsAfterATerminatorAreRefused) {
  // A field of digits, a NUL, then more digits is not a number. Reading only the
  // part before the NUL is how a reader disagrees with the writer about a size
  // while both think they are right.
  GARC_Result result = GARC_OK;
  parse_uint({'6', '4', '4', 0, '7', '7', '7', 0}, &result);
  EXPECT_EQ(result, GARC_ERR_CORRUPT);
}

TEST(TarNumberOctal, AFullTwelveByteFieldReadsItsWholeValue) {
  // 11 octal digits is 8 GB and the reason base-256 exists; the digit before
  // that ceiling has to be read, not truncated.
  const uint64_t want = 077777777777ull; // The largest an 11-digit field holds.
  EXPECT_EQ(parse_uint({'7', '7', '7', '7', '7', '7', '7', '7', '7', '7', '7', 0}),
      want);
}

//-----------------------------------------------------------------------------
// Base-256
//-----------------------------------------------------------------------------

TEST(TarNumberBase256, ATwelveByteFieldCarriesALargeValue) {
  // The 12-byte path: 95 bits wide, so the leading bits are checked for sign
  // extension and peeled before the remaining 64 are read.
  const uint64_t big = (uint64_t)1u << 34;
  GARC_Result result = GARC_ERR_INTERNAL;
  EXPECT_EQ(parse_uint(base256(big, 12), &result), big);
  EXPECT_EQ(result, GARC_OK);
}

TEST(TarNumberBase256, AnEightByteFieldTakesTheNarrowPath) {
  // 7 + 8*7 = 63 bits, which is under 64 - so no peeling happens and a different
  // branch of the arithmetic runs. A test that only used 12-byte fields would
  // leave this one unexecuted while the file looked covered.
  const uint64_t value = 0x00123456789ABCDEull & (((uint64_t)1u << 62) - 1u);
  GARC_Result result = GARC_ERR_INTERNAL;
  EXPECT_EQ(parse_uint(base256(value, 8), &result), value);
  EXPECT_EQ(result, GARC_OK);
}

TEST(TarNumberBase256, NegativeValuesAtBothWidths) {
  // A time before the epoch is why the negative form exists. -1 is all ones,
  // which is the only spelling GNU writes; a smaller negative exercises the
  // arithmetic rather than the special case.
  GARC_Result result = GARC_ERR_INTERNAL;
  EXPECT_EQ(parse_int(std::vector<uint8_t>(12, 0xFFu), &result), -1);
  EXPECT_EQ(result, GARC_OK);
  EXPECT_EQ(parse_int(std::vector<uint8_t>(8, 0xFFu), &result), -1);
  EXPECT_EQ(result, GARC_OK);

  // -2 in an 8-byte field: 0xFF followed by six 0xFF and 0xFE.
  std::vector<uint8_t> minus_two(8, 0xFFu);
  minus_two[7] = 0xFEu;
  EXPECT_EQ(parse_int(minus_two, &result), -2);
  EXPECT_EQ(result, GARC_OK);

  // And in a 12-byte field, where the leading bytes are peeled first.
  std::vector<uint8_t> wide(12, 0xFFu);
  wide[11] = 0x00u;
  EXPECT_EQ(parse_int(wide, &result), -256);
  EXPECT_EQ(result, GARC_OK);
}

TEST(TarNumberBase256, TheSignIsBitSixRatherThanAWholeLeadingByte) {
  // The encoding is a two's-complement integer over the whole field, with bit 7
  // of the first byte as the flag and bit 6 as the sign - so 0x80 and 0xFF are
  // only the two commonest leading bytes, not the whole scheme. Reading it as
  // "0x80 means positive and the rest is the magnitude" discards six value bits
  // of the first byte, which for this field is the difference between 2^61 and 0.
  std::vector<uint8_t> bytes(8, 0);
  bytes[0] = 0xA0u; // Flag set, sign clear, and bit 5 of the value set.
  GARC_Result result = GARC_ERR_INTERNAL;
  const uint64_t got = parse_uint(bytes, &result);
  EXPECT_EQ(result, GARC_OK);
  EXPECT_EQ(got, (uint64_t)0x20u << 56)
      << "the first byte's value bits were dropped";
}

TEST(TarNumberBase256, AValueTooWideToRepresentIsRefused) {
  // A 12-byte field spells 95 bits. Truncating to 64 turns a nonsense size into a
  // plausible one, which is worse than refusing.
  std::vector<uint8_t> bytes(12, 0x11u);
  bytes[0] = 0x81u; // Flag set, sign clear, value bits in the top byte.
  GARC_Result result = GARC_OK;
  parse_uint(bytes, &result);
  EXPECT_EQ(result, GARC_ERR_CORRUPT);
}

TEST(TarNumberBase256, SignBitsThatContradictTheValueAreRefused) {
  // A 12-byte field whose dropped sign bits say negative over a 64-bit value
  // whose own top bit is clear. GNU never writes this, and reading it as a large
  // positive number would turn a malformed field into a plausible size.
  GARC_Result result = GARC_OK;
  std::vector<uint8_t> wide(12, 0);
  wide[0] = 0xFFu;
  wide[1] = 0xFFu;
  wide[2] = 0xFFu;
  wide[3] = 0xFFu;
  // Bytes 4..11 are zero, so the value's top bit is clear while the four leading
  // bytes said negative.
  parse_int(wide, &result);
  EXPECT_EQ(result, GARC_ERR_CORRUPT);
}

TEST(TarNumberBase256, TheMostNegativeValueAtEachWidth) {
  // The extremes of the negative reconstruction, which is where the arithmetic
  // goes wrong if it is written the obvious way. At 8 bytes the width is 63 bits,
  // so 2^63 is not representable as an int64_t - and `pattern - (int64_t)span`
  // therefore converts out of range and then overflows. The release build gave
  // the right answer regardless; UBSan is what reported it.
  GARC_Result result = GARC_ERR_INTERNAL;

  // -1 at 8 bytes: every value bit set, which is the largest `pattern` the
  // negative branch can be handed and so the case the overflow hit.
  EXPECT_EQ(parse_int(std::vector<uint8_t>(8, 0xFFu), &result), -1);
  EXPECT_EQ(result, GARC_OK);

  // The most negative value an 8-byte field can hold: sign set, nothing else.
  std::vector<uint8_t> floor8(8, 0);
  floor8[0] = 0xC0u;
  EXPECT_EQ(parse_int(floor8, &result), -((int64_t)1 << 62));
  EXPECT_EQ(result, GARC_OK);

  // And at 12 bytes, where the leading bits are peeled and the remaining width is
  // exactly 64 - a different branch with its own way to overflow. The four
  // leading bytes are sign extension and byte 4 carries the 64-bit value's own
  // sign bit; zeroing byte 4 as well would be the *contradiction* case above, not
  // this one, which is what the first version of this did.
  std::vector<uint8_t> floor12(12, 0);
  floor12[0] = 0xFFu;
  floor12[1] = 0xFFu;
  floor12[2] = 0xFFu;
  floor12[3] = 0xFFu;
  floor12[4] = 0x80u;
  EXPECT_EQ(parse_int(floor12, &result), INT64_MIN);
  EXPECT_EQ(result, GARC_OK);
}

TEST(TarNumberBase256, AtTheNarrowWidthThereIsNoSuchContradiction) {
  // The other half of the test above, and the reason the parser does not check
  // for one here. At 8 bytes nothing is peeled, so the value's sign bit *is* bit
  // 6 of the first byte - the bit the sign was read from. They are one bit, so
  // they cannot disagree, and 0xC0 followed by zeros is a legitimate -2^62
  // rather than a malformed field.
  //
  // A first draft asserted GARC_ERR_CORRUPT here and the parser had the code to
  // produce it. Both were wrong: the refusal was unreachable, which is dead code
  // in a parser reading as a guard somebody relies on. Written down because the
  // test is what found it.
  std::vector<uint8_t> narrow(8, 0);
  narrow[0] = 0xC0u; // Flag and sign set; every value bit clear.
  GARC_Result result = GARC_ERR_INTERNAL;
  EXPECT_EQ(parse_int(narrow, &result), -((int64_t)1 << 62));
  EXPECT_EQ(result, GARC_OK);
}

TEST(TarNumberBase256, ANegativeValueInAnUnsignedFieldIsRefused) {
  // A negative size, uid or device number is not something the field can
  // legitimately carry, and clamping to zero would make a hostile archive look
  // like an empty file.
  GARC_Result result = GARC_OK;
  parse_uint(std::vector<uint8_t>(12, 0xFFu), &result);
  EXPECT_EQ(result, GARC_ERR_CORRUPT);
}

TEST(TarNumberBase256, AValuePastInt64MaxIsRefusedInAnUnsignedField) {
  // The unsigned parser goes through the signed one, so a magnitude above
  // INT64_MAX has nowhere to go. A 12-byte field can spell one.
  std::vector<uint8_t> bytes(12, 0);
  bytes[0] = 0x80u;
  bytes[4] = 0xFFu; // Sets the top bit of the 64-bit value.
  GARC_Result result = GARC_OK;
  parse_uint(bytes, &result);
  EXPECT_EQ(result, GARC_ERR_CORRUPT);
}

//-----------------------------------------------------------------------------
// Arguments
//-----------------------------------------------------------------------------

TEST(TarNumberOctal, AFieldWideEnoughToOverflowIsRefused) {
  // tar's widest field is 12 bytes, which is 36 bits of octal and cannot
  // overflow - but the width is a parameter of this function rather than a
  // constant, so the guard is real and this is the only way to reach it. Called
  // directly with a 30-byte field of sevens, which is 90 bits.
  std::vector<uint8_t> wide(30, '7');
  GARC_Result result = GARC_OK;
  parse_uint(wide, &result);
  EXPECT_EQ(result, GARC_ERR_CORRUPT);
}

TEST(TarNumberOctal, AValuePastInt64MaxInASignedFieldIsRefused) {
  // The same width trick for the signed parser, and the value has to be chosen
  // rather than just made long: 22 sevens trips the octal parser's own overflow
  // guard first and would test that instead. 1 followed by 21 zeros is 8^21,
  // which is exactly 2^63 - one past INT64_MAX, and small enough on the way up
  // that the guard does not fire.
  std::vector<uint8_t> wide(22, '0');
  wide[0] = '1';
  GARC_Result result = GARC_OK;
  parse_int(wide, &result);
  EXPECT_EQ(result, GARC_ERR_CORRUPT);
  // The control: one digit fewer is 2^60 and is read.
  std::vector<uint8_t> narrower(21, '0');
  narrower[0] = '1';
  EXPECT_EQ(parse_int(narrower, &result), (int64_t)1 << 60);
  EXPECT_EQ(result, GARC_OK);
}

TEST(TarNumberBase256, ALeadingByteThatIsNotPureSignExtensionIsRefused) {
  // The peel loop: every bit above the 64th has to be a copy of the sign, and a
  // byte in the middle of the run that is not is a value too wide to represent.
  // Distinct from the first-byte check, which the value-too-wide test covers.
  std::vector<uint8_t> bytes(12, 0);
  bytes[0] = 0x80u; // Flag set, sign clear, so the peel expects 0x00 bytes.
  bytes[2] = 0x01u; // ...and finds one that is not, above bit 63.
  GARC_Result result = GARC_OK;
  parse_uint(bytes, &result);
  EXPECT_EQ(result, GARC_ERR_CORRUPT);
}

TEST(TarNumber, RejectsBadArguments) {
  uint64_t unsigned_value = 0;
  int64_t signed_value = 0;
  const uint8_t bytes[8] = {'0', '0', '0', '0', '0', '0', '0', 0};

  EXPECT_EQ(garc_tar_parse_uint(nullptr, 8, &unsigned_value), GARC_ERR_INVALID);
  EXPECT_EQ(garc_tar_parse_uint(bytes, 0, &unsigned_value), GARC_ERR_INVALID);
  EXPECT_EQ(garc_tar_parse_uint(bytes, 8, nullptr), GARC_ERR_INVALID);
  EXPECT_EQ(garc_tar_parse_int(nullptr, 8, &signed_value), GARC_ERR_INVALID);
  EXPECT_EQ(garc_tar_parse_int(bytes, 0, &signed_value), GARC_ERR_INVALID);
  EXPECT_EQ(garc_tar_parse_int(bytes, 8, nullptr), GARC_ERR_INVALID);
}

TEST(TarNumber, IdentifyRefusesNullAndShortInput) {
  EXPECT_FALSE(garc_tar_identify(nullptr, 512));
  const std::vector<uint8_t> block(512, 0);
  EXPECT_FALSE(garc_tar_identify(block.data(), 511))
      << "nothing shorter than a block can be identified";
  EXPECT_TRUE(garc_tar_identify(block.data(), 512))
      << "a zero block is an empty archive";
  EXPECT_FALSE(garc_tar_block_is_header(nullptr));
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
