/*
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * Copyright (C) 2026 Corey Pennycuff
 *
 * This file is part of Ghoti.io Archive.
 *
 * Ghoti.io Archive is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * Ghoti.io Archive is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * @file
 *
 * Reading zip's numbers: little-endian integers, and two kinds of time.
 *
 * Every multi-byte field in a zip is little-endian, which is a fact about the
 * format and not about the host - so these are shifts over bytes rather than
 * casts over memory. A `memcpy` into a `uint32_t` would be correct only on a
 * little-endian machine and would also be a strict-aliasing question nobody
 * wants to have to answer twice.
 *
 * The two times are harder than the integers, and for different reasons. See
 * ::garc_zip_dos_to_epoch() for the one that has no time zone and
 * ::garc_zip_filetime_to_epoch() for the one that counts from 1601.
 */

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/zip.h>
#include <stdint.h>

#include "zip/zip_internal.h"

uint16_t garc_zip_le16(const uint8_t * bytes) {
  return (uint16_t)((uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8));
}

uint32_t garc_zip_le32(const uint8_t * bytes) {
  return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8)
      | ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

uint64_t garc_zip_le64(const uint8_t * bytes) {
  return (uint64_t)garc_zip_le32(bytes)
      | ((uint64_t)garc_zip_le32(bytes + 4) << 32);
}

/**
 * Days from 1970-01-01 to a proleptic Gregorian date.
 *
 * Howard Hinnant's `days_from_civil`, which is exact for every year in range and
 * has no table, no loop and no leap-year special case to get wrong. The
 * alternative was `timegm`, which is not in C17 - and `mktime`, which is, reads
 * the `TZ` environment variable. A reader whose answer depended on the caller's
 * time zone would give two answers for one archive, which is the defect
 * `locale-sensitive-conversions` describes in another costume.
 *
 * @param year The year, four digits.
 * @param month 1 to 12.
 * @param day 1 to 31.
 * @return Days since 1970-01-01, negative before it.
 */
static int64_t days_from_civil(int64_t year, unsigned month, unsigned day) {
  year -= month <= 2u;
  const int64_t era = (year >= 0 ? year : year - 399) / 400;
  const unsigned year_of_era = (unsigned)(year - era * 400);
  const unsigned day_of_year
      = (153u * (month + (month > 2u ? -3u : 9u)) + 2u) / 5u + day - 1u;
  const unsigned day_of_era = year_of_era * 365u + year_of_era / 4u
      - year_of_era / 100u + day_of_year;
  return era * 146097 + (int64_t)day_of_era - 719468;
}

GARC_Result garc_zip_dos_to_epoch(
    uint16_t date, uint16_t time, int64_t * out_seconds) {
  const unsigned year = 1980u + (unsigned)(date >> 9);
  const unsigned month = (unsigned)((date >> 5) & 0x0Fu);
  const unsigned day = (unsigned)(date & 0x1Fu);
  const unsigned hour = (unsigned)(time >> 11);
  const unsigned minute = (unsigned)((time >> 5) & 0x3Fu);
  // Two-second resolution: the field holds the second divided by two, which is
  // why every mtime in the corpus is an even second - an odd one could not
  // survive the round trip and a fixture that could not would be testing the
  // format's rounding rather than this library.
  const unsigned second = (unsigned)((time & 0x1Fu) * 2u);

  // **An out-of-range field is not a time.** A date of zero - which is what a
  // writer with nothing to say puts there - has month 0 and day 0, and feeding
  // those to the arithmetic below produces a real-looking answer for a date that
  // does not exist. Refusing here, and reporting GARC_TIME_NONE, says the
  // archive carried no usable time; inventing 1979-11-30 would say it carried
  // one.
  if (month < 1u || month > 12u || day < 1u || day > 31u || hour > 23u
      || minute > 59u || second > 58u) {
    return GARC_ERR_CORRUPT;
  }

  // **Interpreted as UTC, which is a decision and not a reading.** The MS-DOS
  // date/time field carries no zone and never has: it is whatever the clock on
  // the writing machine said. Every other choice is worse - guessing the
  // reader's zone makes one archive two answers, and refusing to convert makes
  // GARC_Member.mtime_seconds unfillable - so this converts as if the field were
  // UTC and GARC_TIME_ZIP_DOS is how a caller knows that is what happened.
  const int64_t days = days_from_civil((int64_t)year, month, day);
  *out_seconds = days * 86400 + (int64_t)hour * 3600 + (int64_t)minute * 60
      + (int64_t)second;
  return GARC_OK;
}

void garc_zip_put16(uint8_t * bytes, uint16_t value) {
  bytes[0] = (uint8_t)(value & 0xFFu);
  bytes[1] = (uint8_t)((value >> 8) & 0xFFu);
}

void garc_zip_put32(uint8_t * bytes, uint32_t value) {
  for (unsigned i = 0; i < 4u; ++i) {
    bytes[i] = (uint8_t)((value >> (8u * i)) & 0xFFu);
  }
}

void garc_zip_put64(uint8_t * bytes, uint64_t value) {
  for (unsigned i = 0; i < 8u; ++i) {
    bytes[i] = (uint8_t)((value >> (8u * i)) & 0xFFu);
  }
}

/**
 * The civil date that many days after 1970-01-01.
 *
 * The inverse of days_from_civil(), and Hinnant's again for the same reason: no
 * table, no loop, and exact for every year the DOS field can express. It is here
 * rather than in the writer because the pair has to agree, and two functions in
 * one file that are each other's inverse can be tested against each other for
 * every day in range - which `ZipNumber.EveryDosDateRoundTrips` does.
 *
 * @param days Days since 1970-01-01.
 * @param out_year Receives the year.
 * @param out_month Receives 1 to 12.
 * @param out_day Receives 1 to 31.
 */
static void civil_from_days(int64_t days, int64_t * out_year,
    unsigned * out_month, unsigned * out_day) {
  days += 719468;
  const int64_t era = (days >= 0 ? days : days - 146096) / 146097;
  const unsigned day_of_era = (unsigned)(days - era * 146097);
  const unsigned year_of_era = (day_of_era - day_of_era / 1460u
      + day_of_era / 36524u - day_of_era / 146096u) / 365u;
  const int64_t year = (int64_t)year_of_era + era * 400;
  const unsigned day_of_year
      = day_of_era - (365u * year_of_era + year_of_era / 4u
          - year_of_era / 100u);
  const unsigned month_prime = (5u * day_of_year + 2u) / 153u;
  *out_day = day_of_year - (153u * month_prime + 2u) / 5u + 1u;
  *out_month = month_prime + (month_prime < 10u ? 3u : -9u);
  *out_year = year + (*out_month <= 2u);
}

/** 1980-01-01T00:00:00Z, the earliest time a DOS date field can express. */
#define GARC_ZIP_DOS_EPOCH ((int64_t)315532800)

/** 2107-12-31T23:59:58Z, the latest. */
#define GARC_ZIP_DOS_MAX ((int64_t)4354819198)

int garc_zip_epoch_to_dos(
    int64_t seconds, uint16_t * out_date, uint16_t * out_time) {
  // **Clamped rather than refused, and the return value says which happened.**
  // Every real zip writer clamps: the DOS field is the only time a zip is
  // required to carry, so refusing a member whose mtime predates 1980 would
  // refuse a member for a reason the format has an answer to. What the answer
  // costs is precision, and a caller that needs to know is told - which is what
  // the extended timestamp field this writer also emits is for.
  int exact = 1;
  if (seconds < GARC_ZIP_DOS_EPOCH) {
    seconds = GARC_ZIP_DOS_EPOCH;
    exact = 0;
  }
  else if (seconds > GARC_ZIP_DOS_MAX) {
    seconds = GARC_ZIP_DOS_MAX;
    exact = 0;
  }
  // The odd second, which the field cannot hold: two-second resolution means the
  // low bit is lost, and rounding *down* is what every writer does - an mtime
  // that moved forward would make a freshly written archive look newer than the
  // file it came from.
  if (seconds & 1) {
    seconds -= 1;
    exact = 0;
  }

  const int64_t days = seconds / 86400;
  const int64_t rest = seconds % 86400;
  int64_t year = 0;
  unsigned month = 0;
  unsigned day = 0;
  civil_from_days(days, &year, &month, &day);

  *out_date = (uint16_t)((((unsigned)(year - 1980)) << 9) | (month << 5) | day);
  *out_time = (uint16_t)((((unsigned)(rest / 3600)) << 11)
      | (((unsigned)((rest / 60) % 60)) << 5)
      | ((unsigned)(rest % 60) / 2u));
  return exact;
}

/** Seconds between 1601-01-01 and 1970-01-01, which is what a FILETIME counts
 *  from. 134,774 days. */
#define GARC_ZIP_FILETIME_EPOCH_DELTA ((uint64_t)11644473600u)

GARC_Result garc_zip_filetime_to_epoch(uint64_t filetime,
    int64_t * out_seconds, uint32_t * out_nanoseconds) {
  const uint64_t whole = filetime / 10000000u;
  const uint64_t fraction = filetime % 10000000u;

  // The fraction always counts *forward* from `whole`, so the pair
  // (seconds, nanoseconds) is exact on both sides of the epoch with no
  // adjustment: seconds is whichever signed value `whole` is, and nanoseconds is
  // the fraction. That is the same reading the pax `mtime=` parser settled on -
  // GARC_Member has one signed seconds field and one unsigned nanoseconds field,
  // and the two parsers have to agree about which way a negative value rounds.
  //
  // Both branches are exact rather than one being a wrap: `whole` is unsigned, so
  // the subtraction has to be done on the side that cannot go below zero.
  if (whole < GARC_ZIP_FILETIME_EPOCH_DELTA) {
    *out_seconds = -(int64_t)(GARC_ZIP_FILETIME_EPOCH_DELTA - whole);
  }
  else {
    *out_seconds = (int64_t)(whole - GARC_ZIP_FILETIME_EPOCH_DELTA);
  }
  *out_nanoseconds = (uint32_t)(fraction * 100u);
  return GARC_OK;
}
