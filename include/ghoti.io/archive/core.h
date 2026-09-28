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
 * Result codes and limits for the Ghoti.io Archive library.
 */

#ifndef GHOTI_IO_GARC_CORE_H
#define GHOTI_IO_GARC_CORE_H

#include <ghoti.io/archive/allocator.h>
#include <ghoti.io/archive/macros.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Result code for archive library operations.
 *
 * Two departures from CONVENTIONS.md section 5, both deliberate and both
 * recorded in that document's departures table.
 *
 * **::GARC_END is neither success nor failure.** Walking an archive ends, and
 * the end of a well-formed archive is not an error - so a caller that treats
 * everything but ::GARC_OK as a failure would report one on every complete
 * read. Use ::garc_result_is_error() rather than comparing against
 * ::GARC_OK, which is why that predicate exists.
 *
 * **There is no bare `GARC_ERR_LIMIT`.** Each cap has a status of its own.
 * A single code for every cap cannot distinguish an absent cap from a
 * defeated one, and cannot tell a test which cap fired - which makes the
 * limits untestable in exactly the way `notes/compress` records under
 * "absent cap and defeated cap return the same code". The cost is six
 * constants where the convention has one; the benefit is that a test can
 * assert *which*. Five of the six are ::GARC_Limits fields and the sixth,
 * ::GARC_ERR_LIMIT_CODEC_BYTES, is a cap held by `compress` - which is exactly
 * the case a shared code would have made indistinguishable, since raising a
 * cap in the wrong library changes nothing.
 *
 * A status is added by the phase that can return it. Phase A returns only
 * what is listed here, so every value below is reachable and every row of
 * ::garc_result_string() is exercised.
 */
typedef enum {
  GARC_OK = 0,          ///< Operation succeeded.
  GARC_END,             ///< Iteration finished. Not an error; see above.
  GARC_ERR_IO,          ///< The source reported a read or seek failure.
  GARC_ERR_FORMAT,      ///< Well formed, but not an archive format we read.
  GARC_ERR_UNSUPPORTED, ///< This format, but a feature we do not implement.
  GARC_ERR_CORRUPT,     ///< This format, but the bytes are wrong.
  GARC_ERR_OOM,         ///< The allocator returned NULL.
  GARC_ERR_INVALID,     ///< A caller-supplied argument is wrong.
  GARC_ERR_INTERNAL,    ///< The library's own invariant failed; a bug.
  /**
   * The source cannot seek, and what was asked for needs to.
   *
   * ::garc_find() and nothing else, today. Not ::GARC_ERR_UNSUPPORTED, which
   * says *this library* does not implement something: finding a member is
   * implemented, and this stream cannot be rewound to do it. The difference is
   * the caller's next move - a feature this library lacks is a wait, and a
   * stream that cannot seek is a different stream or a different approach.
   *
   * Every compressed archive is in this case and cannot leave it: a codec stream
   * has no seek, so a `tar.gz` is walked with ::garc_next() or not at all.
   */
  GARC_ERR_NOT_SEEKABLE,

  GARC_ERR_LIMIT_MEMBERS,      ///< ::GARC_Limits.max_members exceeded.
  GARC_ERR_LIMIT_MEMBER_BYTES, ///< ::GARC_Limits.max_member_bytes exceeded.
  GARC_ERR_LIMIT_TOTAL_BYTES,  ///< ::GARC_Limits.max_total_bytes exceeded.
  GARC_ERR_LIMIT_NAME_BYTES,   ///< ::GARC_Limits.max_name_bytes exceeded.
  GARC_ERR_LIMIT_EXTRA_BYTES,  ///< ::GARC_Limits.max_extra_bytes exceeded.
  /**
   * A cap in the *codec's* options stopped a decompressing stream.
   *
   * The only one of these that is not a ::GARC_Limits field, because the cap is
   * not this library's: `compress`'s decoder options carry a maximum output size
   * (512 MiB by default, so a decompression bomb is refused whether or not the
   * caller thought about it), and this is what that refusal arrives as. Kept
   * distinct from ::GARC_ERR_LIMIT_TOTAL_BYTES because the two name different
   * caps in different libraries, and a caller raising the wrong one would get
   * the same failure again.
   */
  GARC_ERR_LIMIT_CODEC_BYTES,

  /**
   * The member is encrypted and no password was given.
   *
   * The one unambiguous answer of the three below it. A zip's metadata is in
   * the clear whatever the password, so this arrives from
   * ::garc_read_member() and never from ::garc_next(): the member's name, size,
   * time and mode are readable and only its bytes are not.
   *
   * See ::garc_zip_set_password().
   */
  GARC_ERR_PASSWORD_REQUIRED,
  /**
   * The password was rejected before any data was read.
   *
   * ZipCrypto ends its 12-byte encryption header with one check byte, and this
   * is that byte disagreeing. **It is one byte of evidence**, which is worth
   * being precise about in both directions: a wrong password is caught here 255
   * times in 256, and the only other thing that produces this answer is a
   * corrupt encryption header - so the status names the password, because that
   * is overwhelmingly what it is and what the caller can act on.
   *
   * The 256th wrong password gets through and arrives as
   * ::GARC_ERR_PASSWORD_OR_CORRUPT at the end of the member instead.
   */
  GARC_ERR_PASSWORD_REJECTED,
  /**
   * An encrypted member's CRC-32 disagreed after its check byte agreed.
   *
   * **A status that names two causes, because nothing can separate them.**
   * ZipCrypto has no authentication tag: a wrong key and a corrupted ciphertext
   * produce the same observation, which is a member whose bytes are not the ones
   * the archive's CRC describes. Reporting ::GARC_ERR_CORRUPT would claim the
   * data is at fault and reporting ::GARC_ERR_PASSWORD_REJECTED would claim the
   * password is; both would be a guess dressed as a finding.
   *
   * This is the case WinZip AES fixed by adding an HMAC, and phase H is where
   * this status stops being the only answer available for an encrypted member
   * that does not come out right.
   */
  GARC_ERR_PASSWORD_OR_CORRUPT,

  GARC_RESULT_COUNT
} GARC_Result;

/**
 * @brief Convert a result code to a human-readable string.
 *
 * The returned string is statically allocated and must not be freed.
 *
 * @param result The result code.
 * @return A description of the result code, never NULL.
 */
GARC_API const char * garc_result_string(GARC_Result result);

/**
 * @brief Whether a result reports a failure.
 *
 * ::GARC_OK and ::GARC_END are not failures; everything else is. Callers use
 * this rather than `result != GARC_OK`, which would make the end of a
 * well-formed archive look like an error.
 *
 * @param result The result code.
 * @return Non-zero when @p result is a failure.
 */
GARC_API int garc_result_is_error(GARC_Result result);

/**
 * @brief Whether a result names one of the ::GARC_Limits caps.
 *
 * True for the six `GARC_ERR_LIMIT_*` codes and false for everything else.
 * Five of them name a ::GARC_Limits field and ::GARC_ERR_LIMIT_CODEC_BYTES
 * names one in the codec's options, which is the same question to a caller
 * asking "was I stopped by a cap I could raise" and a different one to a caller
 * asking *which* - so this is for the first, and tests name the constant.
 * A caller that wants to raise a cap and retry needs to know that a cap is
 * what stopped it without enumerating them, and a test that asserts "some
 * limit fired" is weaker than one that asserts which.
 *
 * @param result The result code.
 * @return Non-zero when @p result reports an exceeded limit.
 */
GARC_API int garc_result_is_limit(GARC_Result result);

/**
 * @name Default limits
 *
 * Named rather than written into the initialiser, so that a caller reading
 * the header and a test asserting the default cannot disagree.
 *
 * **Every one of these is non-zero, where model's and image's limits are
 * mostly open.** The difference is where the number comes from: a member's
 * size is *declared in the container* and read before a single byte of its
 * contents is, so "no limit" means the first thing a caller does with a
 * hostile archive is ask for a petabyte. 42.zip is 42 KB on disk. The size
 * of the input bounds nothing here, which is the assumption that lets a
 * record parser leave its caps open.
 *
 * These five numbers are **provisional**. They are chosen to stop a bomb, not
 * to bless a size, and what settles them is the corpus: no legitimate archive
 * in `tests/data/` may hit a default, and the phase that adds a format adds
 * that assertion with it. A default a real archive hits is a defect in the
 * default.
 * @{
 */

/** Default ::GARC_Limits.max_members: 2^20 members. */
#define GARC_DEFAULT_MAX_MEMBERS ((uint64_t)1048576u)

/**
 * Default ::GARC_Limits.max_member_bytes: 64 GiB.
 *
 * One member's declared uncompressed size. Above a zip64 archive's 4 GiB
 * ceiling by a wide margin, so a legitimate zip cannot reach it at all, and
 * a tar member this large is a disk image rather than a file.
 */
#define GARC_DEFAULT_MAX_MEMBER_BYTES ((uint64_t)64u << 30)

/**
 * Default ::GARC_Limits.max_total_bytes: 256 GiB.
 *
 * The sum across members, which is the cap that actually stops a bomb - no
 * codec can see it, because each member decodes within its own ratio limit
 * and it is the *count* of members that multiplies. 42.zip expands to some
 * 4.5 PB and is stopped here four orders of magnitude early.
 */
#define GARC_DEFAULT_MAX_TOTAL_BYTES ((uint64_t)256u << 30)

/**
 * Default ::GARC_Limits.max_name_bytes: 64 KiB.
 *
 * A pax `path=` record and a GNU `L` member are both unbounded in the format,
 * so this is the library's number rather than the format's. 64 KiB is far
 * past every filesystem's own path ceiling, so a name that hits it was not
 * going to be written to disk anyway.
 */
#define GARC_DEFAULT_MAX_NAME_BYTES ((size_t)65536u)

/**
 * Default ::GARC_Limits.max_extra_bytes: 64 KiB per member.
 *
 * A single zip extra field is length-prefixed with 16 bits, so 65535 is the
 * format's ceiling for one field and not for their sum - a member may carry
 * as many as fit. This caps the sum.
 *
 * tar reaches it through pax's extended records, which are unbounded in the
 * format: an `x` member's records and the `g` members' still in force are both
 * held in memory for the member being read, and both are chains a writer can make
 * as long as it likes.
 */
#define GARC_DEFAULT_MAX_EXTRA_BYTES ((size_t)65536u)

/** @} */

/**
 * @brief Caps applied while reading, so that a hostile or corrupt archive
 *   cannot make the library, or its caller, allocate without bound.
 *
 * Zero means "no limit" for every field. Pass NULL wherever a
 * ::GARC_Limits is accepted to use ::garc_limits_default().
 *
 * Each cap has a status of its own; see ::GARC_Result.
 *
 * There is deliberately no `max_nesting`. Descending into an archive inside
 * an archive is something this library does not do - a member is bytes, and
 * whether those bytes are themselves an archive is the caller's question -
 * so a field for it would be one nothing reads, which is worse than absent
 * because it reads as a promise.
 */
typedef struct GARC_Limits {
  /** Cap on the number of members walked. 42.zip is five nested layers; a
   *  flat archive of a million empty members is cheaper to build than that. */
  uint64_t max_members;
  /** Cap on one member's declared uncompressed size, in bytes. */
  uint64_t max_member_bytes;
  /** Cap on the sum of every member's declared uncompressed size, in bytes.
   *  The one no codec can enforce for us. */
  uint64_t max_total_bytes;
  /** Cap on one member's name, in bytes. */
  size_t max_name_bytes;
  /**
   * Cap on the container-specific extra fields held for one member, in bytes.
   *
   * The *sum*, not one field: zip lets a member carry as many extra fields as
   * fit, and pax lets an archive put any number of `x` and `g` members in front
   * of one. A cap on each would leave a hundred of them unbounded, which is the
   * same argument @ref max_total_bytes makes against @ref max_member_bytes.
   */
  size_t max_extra_bytes;
} GARC_Limits;

/**
 * @brief Fill in the default limits.
 *
 * @param limits Structure to populate. NULL is ignored.
 */
GARC_API void garc_limits_default(GARC_Limits * limits);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GARC_CORE_H
