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
 * The archive object, shared by the generic reader and each format's reader.
 */

#ifndef GHOTI_IO_GARC_SRC_READER_READER_INTERNAL_H
#define GHOTI_IO_GARC_SRC_READER_READER_INTERNAL_H

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/reader.h>
#include <ghoti.io/archive/tar.h>
#include <ghoti.io/archive/zip.h>
#include <ghoti.io/compress/options.h>
#include <stddef.h>
#include <stdint.h>

#include "core/buffer_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Storage for a ustar member's name.
 *
 * 155 bytes of prefix, a separator, 100 bytes of name, and a NUL. Fixed,
 * because no name a v7 or ustar *header* can express is longer - and an
 * ordinary archive is then walked with no allocation per member at all, which
 * is what makes ::GARC_Member's borrowing worth having.
 *
 * A name GNU's `L` member or pax's `path=` record carries is unbounded in the
 * format and cannot live here. Those go in ::GARC_Buffer instead, so the
 * allocation happens for the archives that need one and not for every archive.
 */
#define GARC_TAR_NAME_STORAGE 257u

/** Storage for a link target: 100 bytes and a NUL, for the same reason. */
#define GARC_TAR_LINK_STORAGE 101u

/** Storage for a user or group name: ustar's 32 bytes and a NUL. */
#define GARC_TAR_OWNER_STORAGE 33u

/**
 * The pax record keys this reader acts on.
 *
 * pax is an open vocabulary - real writers emit `SCHILY.*`, `LIBARCHIVE.*` and
 * GNU's own `GNU.*` keys - so an unknown key is *ignored* rather than refused:
 * refusing would refuse most of what they produce. The one exception is
 * `GNU.sparse.*`, refused by name, because there the member's data is a sparse
 * map rather than its contents and ignoring the records hands a caller the map
 * as the file.
 */
typedef enum {
  GARC_PAX_PATH = 0,   ///< `path=`, replacing the header's name.
  GARC_PAX_LINKPATH,   ///< `linkpath=`, replacing the link target.
  GARC_PAX_UNAME,      ///< `uname=`.
  GARC_PAX_GNAME,      ///< `gname=`.
  GARC_PAX_SIZE,       ///< `size=`, decimal, for what the octal field cannot hold.
  GARC_PAX_MTIME,      ///< `mtime=`, decimal, with a fraction.
  GARC_PAX_UID,        ///< `uid=`, decimal.
  GARC_PAX_GID,        ///< `gid=`, decimal.
  GARC_PAX_HDRCHARSET, ///< `hdrcharset=`, saying what the records' bytes are.
  GARC_PAX_SPARSE_SIZE,      ///< `GNU.sparse.size=`, the real size (0.0, 0.1).
  GARC_PAX_SPARSE_NUMBLOCKS, ///< `GNU.sparse.numblocks=`, the map's length (0.x).
  GARC_PAX_SPARSE_MAP,       ///< `GNU.sparse.map=`, comma-separated pairs (0.1).
  GARC_PAX_SPARSE_MAJOR,     ///< `GNU.sparse.major=` (1.0).
  GARC_PAX_SPARSE_MINOR,     ///< `GNU.sparse.minor=` (1.0).
  GARC_PAX_SPARSE_NAME,      ///< `GNU.sparse.name=`, the real name (0.1, 1.0).
  GARC_PAX_SPARSE_REALSIZE,  ///< `GNU.sparse.realsize=`, the real size (1.0).
  GARC_PAX_KEY_COUNT
} GARC_Pax_Key;

/**
 * One set of pax records: an `x` member's, or the accumulated `g` ones.
 *
 * The values stay in @ref records as the writer spelled them, and the table holds
 * **offsets rather than pointers** so that appending a second header's records -
 * which can move the allocation - does not invalidate what an earlier one said.
 * That is what makes POSIX's rule for global records implementable: a later `g`
 * overrides each key individually rather than replacing the set.
 *
 * `have[k]` with a @ref length of zero is not the same as `!have[k]`. A record
 * with an empty value *deletes* the key, which is how an `x` header suppresses a
 * global one, so the two states have to be distinguishable.
 */
typedef struct {
  /** The raw record bytes, appended to and never rewound within a set. */
  GARC_Buffer records;
  /** Where each key's value starts in @ref records. */
  size_t offset[GARC_PAX_KEY_COUNT];
  /** How long each key's value is; zero means the key was deleted. */
  size_t length[GARC_PAX_KEY_COUNT];
  /** Whether the key appeared at all. */
  int have[GARC_PAX_KEY_COUNT];
  /**
   * pax sparse 0.0's map: `GNU.sparse.offset=` and `GNU.sparse.numbytes=`
   * records, one pair per region, repeated in order.
   *
   * The table above keeps the last value of a key, which is pax's rule and the
   * wrong one here, so these are collected as they are parsed: two uint64_t per
   * pair, offset then length.
   */
  GARC_Buffer sparse_pairs;
  /** How many pairs @ref sparse_pairs holds. */
  size_t sparse_pair_count;
  /** Non-zero after an offset record whose numbytes has not arrived yet. */
  int sparse_offset_pending;
} GARC_Tar_Pax;

/**
 * Everything in an archive that only the tar reader looks at.
 *
 * **Named rather than inlined, and not a union with zip's.** Inlined, the archive
 * would hold two formats' worth of fields with nothing but a prefix saying which
 * reader owns which - and a prefix is a convention, where a member is a type. A
 * union would save the few hundred bytes the unused format costs and buy a way to
 * lose: nothing in C stops a reader writing one arm and another reading the other,
 * and the compiler cannot tell that apart from the intended use. So both formats
 * have a member each, the cost is under a kilobyte per open archive, and a
 * mis-dispatch reads its own zeroes rather than the other format's live state.
 */
typedef struct {
  /** Which of tar's formats the current member's header was. */
  GARC_Tar_Variant variant;
  /** Non-zero when the signed reading of the header checksum was the match. */
  int checksum_was_signed;
  /** Non-zero once a zero block has been seen, which is the end marker. */
  int saw_end_marker;

  /**
   * @name Where a member's strings live between calls
   *
   * A member's name is lent to the caller until the next ::garc_next(), so it
   * has to outlive the header block it was read from. These are sized to the
   * longest a ustar header can express - 100 plus a `/` plus 155 for a split
   * name - so the common case allocates nothing; a longer one goes to the heap
   * buffer below.
   * @{
   */
  char name_storage[GARC_TAR_NAME_STORAGE];   ///< Name, plus its terminator.
  char link_storage[GARC_TAR_LINK_STORAGE];   ///< Link target, plus terminator.
  char uname_storage[GARC_TAR_OWNER_STORAGE]; ///< Owner name, plus terminator.
  char gname_storage[GARC_TAR_OWNER_STORAGE]; ///< Group name, plus terminator.
  /** @} */

  /**
   * A name carried in front of the header rather than in it.
   *
   * GNU writes an `L` member whose data is the next member's name; pax writes a
   * `path=` record. Both are unbounded in the format, so this is where a name
   * too long for @ref name_storage goes. Allocated on first use and **kept
   * across members**, because an archive of long names would otherwise allocate
   * and free once per member; freed by garc_tar_release().
   */
  GARC_Buffer long_name;
  /** The same for a link target: GNU's `K` member, pax's `linkpath=`. */
  GARC_Buffer long_link;
  /**
   * Non-zero when @ref long_name holds a name for the header being read.
   *
   * Cleared at the start of every garc_tar_next(), so a carrier member whose
   * read failed cannot leave a name to be applied to some later header. The
   * *storage* is not cleared with it; only the claim on it is.
   */
  int have_long_name;
  /** The same for @ref long_link. */
  int have_long_link;

  /**
   * Records from an `x` member, which apply to the next member only.
   *
   * Reset at the start of every garc_tar_next(), for the same reason
   * @ref have_long_name is: a set left behind by a failed step would otherwise be
   * applied to whatever header a caller reached next.
   */
  GARC_Tar_Pax pax_next;
  /**
   * Records from `g` members, which apply until a later record replaces them.
   *
   * Not reset per member, and appended to rather than replaced, because POSIX
   * overrides a global record **per key**: a second `g` naming `mtime` does not
   * clear a first one's `path`.
   */
  GARC_Tar_Pax pax_global;

  /**
   * @name The current member's sparse map, when it is a GNU sparse file
   *
   * The data in the archive is the map's regions, back to back. A read hands
   * out the file instead: zeros up to each region, the region's stored bytes,
   * and zeros after the last up to the real size. Kept across members like the
   * long-name buffer, and claimed by @ref sparse.
   * @{
   */
  GARC_Buffer sparse_map;   ///< Pairs of uint64_t: offset, then length.
  size_t sparse_count;      ///< How many pairs.
  int sparse;               ///< Non-zero when the current member is sparse.
  uint64_t sparse_pos;      ///< Bytes of the real file handed out so far.
  size_t sparse_index;      ///< The first region not wholly behind sparse_pos.
  /** @} */
} GARC_Tar_State;

/**
 * Everything in an archive that only the zip reader looks at.
 *
 * Split into what was found once at open and what moves as the walk moves,
 * because ::garc_find() has to reset the second and must not touch the first -
 * the same split the tar reader's rewind settled, inherited here as that
 * function's comment says it would be.
 */
typedef struct {
  /**
   * @name Found once, at open
   * @{
   */
  /**
   * Where the archive's own offsets count from, as an absolute stream offset.
   *
   * Not the same as ::GARC_Archive.start_offset: an archive behind a
   * self-extracting stub has its offsets counted from after the stub, and this
   * is *discovered* by comparing where the central directory claims to be with
   * where it turned out to be. ::garc_zip_base_offset() reports the difference.
   */
  uint64_t origin;
  /** Absolute stream offset of the first central directory entry. */
  uint64_t central_offset;
  /** How many bytes of central directory the end record declared. */
  uint64_t central_size;
  /**
   * Absolute stream offset of the end record itself.
   *
   * Set by identification when it had to scan for one - which is how a zip
   * behind a self-extracting stub is found at all - and read back by
   * ::garc_zip_open() so that the scan happens once. @ref eocd_found says
   * whether it has been set, because zero is a legitimate offset: it is where
   * the record of a 22-byte empty archive sits.
   */
  uint64_t eocd_offset;
  /** Whether @ref eocd_offset has been found yet. */
  int eocd_found;
  /** How many entries the end record declared. */
  uint64_t declared_members;
  /** Non-zero when a zip64 end record supplied the counts. */
  int is_zip64;
  /** The archive comment, as bytes. Empty when there is none. */
  GARC_Buffer comment;
  /**
   * The three ZipCrypto key words, with the password already mixed in.
   *
   * Derived at ::garc_zip_set_password() and wiped on release. ZipCrypto still
   * needs nothing else. WinZip AES cannot be derived at that call: each member
   * has its own salt, so the password is kept in @ref password until release.
   *
   * Set by ::garc_zip_set_password() and deliberately untouched by
   * ::garc_zip_rewind(): a password is a property of the archive, not of where
   * the walk is. An empty password is @ref have_password with
   * @ref password_length 0, which is not the same as never having called it.
   */
  uint32_t crypt_keys[3];
  /** Whether ::garc_zip_set_password() has been called. */
  int have_password;
  /**
   * The password bytes, copied at ::garc_zip_set_password() and wiped on release.
   *
   * NULL when @ref password_length is 0. Untouched by ::garc_zip_rewind().
   */
  uint8_t * password;
  /** Length of @ref password. Zero with @ref have_password set is empty. */
  size_t password_length;
  /**
   * WinZip AES version from the 0x9901 field. 1 is AE-1, 2 is AE-2, 0 is not
   * an AES member.
   */
  uint16_t aes_version;
  /** WinZip AES strength byte: 1, 2 or 3. Zero when this member is not AES. */
  uint8_t aes_strength;
  /** The real compression method from 0x9901. The header method stays 99. */
  uint16_t aes_method;
  /**
   * Whether this member's HMAC matched.
   *
   * Stays 0 until the authentication code has been checked and agreed. A 16-bit
   * verifier can pass for a wrong password, so a failure here is reported as
   * ::GARC_ERR_PASSWORD_OR_CORRUPT when the member is over.
   */
  int aes_auth_ok;
  /** @} */

  /**
   * @name Where the walk is
   * @{
   */
  /** Absolute stream offset of the next central directory entry to read. */
  uint64_t cursor;
  /** How many entries have been read, which bounds the walk. */
  uint64_t entries_seen;
  /** @} */

  /**
   * @name The current member, as the central directory described it
   *
   * Each of these is a field of the entry rather than a conclusion about it, and
   * each has an accessor in zip.h, because a caller that has to re-derive one
   * from ::GARC_Member has to know the format to do it.
   * @{
   */
  /** The name, which is up to 65,535 bytes and so cannot be a fixed array. */
  GARC_Buffer name;
  /** Scratch for the entry's extra field, reused across members. */
  GARC_Buffer extra;
  /** A symlink's target, which in zip is the member's *data*. */
  GARC_Buffer link;
  /**
   * The decoder over this member's compressed range, or NULL.
   *
   * NULL for a stored member, which is read straight from the archive's stream,
   * and for one whose method has no codec here. Created by ::garc_zip_next() and
   * destroyed by the next call to it, so a walk that never reads a member's data
   * costs one allocation per compressed member and no I/O.
   */
  struct GARC_Member_Codec * codec;
  /**
   * The decrypting view of this member's data, or NULL.
   *
   * Non-NULL only for a ZipCrypto member whose check byte agreed. It sits
   * *under* @ref codec when the member is also compressed, because ZipCrypto
   * encrypts the compressed bytes - so the layering is decrypt then inflate, and
   * getting it the other way round reads a stored member correctly and a deflated
   * one not at all. Destroyed after @ref codec, which holds a slice of it.
   */
  GARC_Stream * crypt;
  /**
   * CRC-32 of the bytes handed to the caller so far, unfinalized.
   *
   * zip declares a CRC-32 per member, which tar has nothing like, so this reader
   * can tell a member whose bytes are wrong from one whose bytes are right - and
   * does, at the end of the member. @ref crc_active says whether a verdict is
   * still owed: a caller that stops reading half way gets none, because half a
   * member has no checksum to compare against.
   */
  uint32_t running_crc;
  int crc_active;                ///< Whether a CRC verdict is still owed.
  uint16_t method;               ///< The compression method number.
  uint16_t flags;                ///< The general purpose bit flags.
  uint16_t version_made_by;      ///< Host system in the high byte.
  uint32_t external_attributes;  ///< DOS bits low, Unix st_mode high.
  uint32_t crc32;                ///< The declared CRC-32.
  uint64_t compressed_size;      ///< Bytes the member occupies in the archive.
  uint64_t local_offset;         ///< Local header offset *as declared*.
  size_t extra_length;           ///< Length of the entry's extra field.
  int used_zip64;                ///< Whether a 0x0001 field supplied a value.
  GARC_Zip_Encryption encryption; ///< Which scheme, where there is one.
  /**
   * @name Kept for a raw copy, which writes the entry back as it was
   * @{
   */
  uint16_t version_needed;       ///< The entry's version needed to extract.
  uint16_t dos_time;             ///< The entry's MS-DOS time, as stored.
  uint16_t dos_date;             ///< The entry's MS-DOS date, as stored.
  uint16_t internal_attributes;  ///< The entry's internal attributes.
  uint64_t comment_offset;       ///< Absolute offset of the member's comment.
  uint16_t comment_length;       ///< Its length; read only when a copy asks.
  /** @} */

  /**
   * @name Reading from a stream that cannot seek
   *
   * The members are walked by their local headers, in order, and the central
   * directory is read last and checked against what the walk saw. zip_read.c's
   * "Streaming" section says why each piece is the way it is.
   * @{
   */
  int streaming;                 ///< Whether this zip is being read this way.
  /** Reads @ref pushback, then the archive's stream; counts @ref position. */
  GARC_Stream * seq;
  GARC_Buffer pushback;          ///< Bytes read ahead and given back.
  size_t pushback_offset;        ///< How many of them have been read again.
  uint64_t position;             ///< Bytes of the archive consumed so far.
  GARC_Buffer records;           ///< What each member was, for the directory.
  size_t record_count;           ///< How many records.
  GARC_Buffer s_names;           ///< Every record's name, end to end.
  GARC_Stream * s_slice;         ///< The current member's stored bytes.
  GARC_Stream * s_decoder;       ///< Its decoder when it has a descriptor.
  gcomp_options_t * s_options;   ///< That decoder's options.
  uint64_t s_data_start;         ///< Where its data began.
  uint64_t s_produced;           ///< Bytes of it handed out.
  uint64_t s_local_offset;       ///< Where its local header began.
  int s_descriptor;              ///< Whether it has a data descriptor.
  int s_zip64;                   ///< Whether its local header had zip64.
  int s_open;                    ///< Whether a member is current and unfinished.
  int s_data_done;               ///< Whether its data has all been read.
  GARC_Result s_stuck;           ///< Why the walk cannot pass this member.
  int s_dir_descriptor;          ///< A stored directory whose descriptor follows its header.
  /** @} */
  /** @} */
} GARC_Zip_State;

/** What only the ar reader looks at. */
typedef struct {
  /** The current member's name, resolved from whichever convention carried it. */
  GARC_Buffer name;
  /** GNU's `//` member: the names too long for a header, separated by `/\n`. */
  GARC_Buffer table;
  int have_table;     ///< Whether a `//` member has been read.
  int seen_member;    ///< Whether a real member has been reported yet.
} GARC_Ar_State;

/** What only the cpio reader looks at. */
typedef struct {
  GARC_Buffer name;   ///< The current member's name.
  GARC_Buffer link;   ///< A symlink's target, which in cpio is the data.
  int variant;        ///< 0 newc, 1 crc, 2 odc.
  uint32_t check;     ///< The crc variant's declared sum for this member.
  uint32_t running;   ///< The sum of the bytes handed over so far.
  int check_active;   ///< Whether a verdict is owed at the end of this member.
} GARC_Cpio_State;

/**
 * An archive being read.
 *
 * Opaque to callers: ::garc_open() hands back a pointer and every accessor is a
 * function, so the layout here is free to change without a consumer rebuild.
 */
struct GARC_Archive {
  /** The stream, borrowed. The caller destroys it; garc_close() does not. */
  GARC_Stream * stream;
  /**
   * Streams this archive owns, outermost first, or NULL.
   *
   * Only ::garc_fs_open() sets them: it opened the file and perhaps a
   * decompressing stream over it, so nobody else holds them. garc_close()
   * destroys both after the format reader is released, the outer one first,
   * because it reads from the inner one.
   */
  GARC_Stream * owned_stream;
  GARC_Stream * owned_inner; ///< See @ref owned_stream.
  /** Allocator for this object. */
  const GARC_Allocator * allocator;
  /** The caps, resolved at open so that NULL means the defaults exactly once. */
  GARC_Limits limits;
  /** Which container. */
  GARC_Format format;
  /**
   * Where in the stream this archive begins.
   *
   * Not assumed to be zero. ::garc_open() takes a stream *positioned at* the
   * start of an archive, which is not the same as the start of the stream - an
   * archive inside another one, or after a header the caller read itself. It is
   * what ::garc_find() seeks back to, and taking it at open is the only moment
   * it can be known.
   */
  uint64_t start_offset;

  /** The member garc_next() last handed out. */
  GARC_Member member;
  /** Non-zero when @ref member is meaningful. */
  int have_member;
  /**
   * Non-zero once ::garc_read_member() has been asked for the current member's
   * bytes, whatever it answered.
   *
   * ::garc_writer_copy_member() copies a member from its start, and a reader
   * cannot go back to it, so a member already read from is refused there rather
   * than copied short.
   */
  int member_touched;
  /** Non-zero once the end of the archive has been reached. */
  int at_end;

  /** Members handed out, which max_members is compared against. */
  uint64_t member_count;
  /** Sum of declared sizes, which max_total_bytes is compared against. */
  uint64_t total_declared_bytes;

  /** Bytes of the current member's data not yet read. */
  uint64_t data_remaining;
  /** Bytes of padding after the current member's data. */
  uint64_t data_padding;

  /**
   * Bytes read by identification and not yet consumed by the format reader.
   *
   * Identifying a container means looking at its first bytes, and putting them
   * back is the part a non-seekable stream cannot do. Seeking back to zero
   * would work on a file and fail on a pipe - which would make "tar can be read
   * from a pipe", the reason this library has a callback stream at all, false.
   * So the bytes are kept here and the format reader drains them before it
   * reads anything.
   *
   * The window is one block, and a format reader consumes a whole block before it
   * reports a member - so by the time garc_read_member() or garc_skip_member()
   * can be called there is nothing left in it. That is why those two may go to
   * the stream directly while everything inside the tar reader goes through
   * garc_tar_read() and garc_tar_skip().
   */
  uint8_t peek[GARC_TAR_BLOCK];
  /** How many of @ref peek are still to be consumed. */
  size_t peek_length;
  /** How many of @ref peek have been consumed. */
  size_t peek_consumed;

  /**
   * Whether the current member's data can be handed to a caller, and why not.
   *
   * ::GARC_OK for a member ::garc_read_member() may read. Otherwise the status it
   * returns - ::GARC_ERR_UNSUPPORTED for a zip member compressed with a method
   * this library has no codec for, or encrypted.
   *
   * It exists because in zip a member's *metadata* being readable and its *data*
   * not is an ordinary state rather than a failure: an archive with one PPMd
   * member is still an archive to walk. Without this, such a member would either
   * have to make ::garc_next() fail - losing the other members - or hand back
   * zero bytes and ::GARC_OK, which is an empty file where there is a compressed
   * one.
   */
  GARC_Result data_refusal;

  /** What only the tar reader looks at. Meaningless for any other format. */
  GARC_Tar_State tar;
  /** What only the zip reader looks at. Meaningless for any other format. */
  GARC_Zip_State zip;
  /** What only the 7z reader looks at: NULL for every other format. */
  struct GARC_SevenZ * sevenz;
  /** What only the ar reader looks at. */
  GARC_Ar_State ar;
  /** What only the cpio reader looks at. */
  GARC_Cpio_State cpio;
};

/**
 * Account for one member against the caps, and add it to the running totals.
 *
 * Called by a format reader once it has filled in the member, and before the
 * member is handed to the caller. Each cap has its own status, so this returns
 * the one that fired rather than a shared code.
 *
 * @param archive The archive.
 * @return GARC_OK, or the specific GARC_ERR_LIMIT_* that fired.
 */
GARC_Result garc_reader_account(GARC_Archive * archive);

/**
 * Throw away @p count bytes of the stream, draining the identification window
 * first.
 *
 * The tar reader never needs the window drained here because a header is a
 * whole block. ar and cpio headers are shorter, so the window still holds the
 * start of the first member's data when the header has been read, and a skip or
 * a read that went straight to the stream would lose it.
 *
 * @param archive The archive.
 * @param count How many bytes.
 * @return ::GARC_OK, or the stream's failure.
 */
GARC_Result garc_reader_discard(GARC_Archive * archive, uint64_t count);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GARC_SRC_READER_READER_INTERNAL_H
