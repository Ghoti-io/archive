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
 * Result strings, the two result predicates, and the default limits.
 */

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/core.h>

const char * garc_result_string(GARC_Result result) {
  switch (result) {
    case GARC_OK:
      return "No error";
    case GARC_END:
      return "End of archive";
    case GARC_ERR_IO:
      return "I/O error";
    case GARC_ERR_FORMAT:
      return "Not an archive format this library reads";
    case GARC_ERR_UNSUPPORTED:
      return "Unsupported feature";
    case GARC_ERR_CORRUPT:
      return "Corrupt archive";
    case GARC_ERR_OOM:
      return "Out of memory";
    case GARC_ERR_INVALID:
      return "Invalid argument";
    case GARC_ERR_INTERNAL:
      return "Internal error";
    case GARC_ERR_NOT_SEEKABLE:
      return "The source cannot seek, and this needs to";
    // Each cap says which cap. A shared string would undo half of what six
    // separate constants buy, since a message is what a caller prints.
    case GARC_ERR_LIMIT_MEMBERS:
      return "Limit exceeded: too many members";
    case GARC_ERR_LIMIT_MEMBER_BYTES:
      return "Limit exceeded: member too large";
    case GARC_ERR_LIMIT_TOTAL_BYTES:
      return "Limit exceeded: members total too large";
    case GARC_ERR_LIMIT_NAME_BYTES:
      return "Limit exceeded: member name too long";
    case GARC_ERR_LIMIT_EXTRA_BYTES:
      return "Limit exceeded: member extra fields too large";
    // Says whose cap, not just which, because this is the one that is not ours:
    // a caller who reads "limit exceeded" and goes looking through GARC_Limits
    // for the field to raise will not find it.
    case GARC_ERR_LIMIT_CODEC_BYTES:
      return "Limit exceeded: the codec's output cap, in its own options";
    // Three statuses where a lesser reader has one, and the third one names two
    // causes on purpose. See the enum: at the encryption header a wrong password
    // and a corrupt header are the same observation with one byte of evidence,
    // and at the CRC they are the same observation with no way at all to
    // separate them, because ZipCrypto carries no authentication tag.
    case GARC_ERR_PASSWORD_REQUIRED:
      return "The member is encrypted and no password was given";
    case GARC_ERR_PASSWORD_REJECTED:
      return "Password rejected by the encryption header's check byte";
    case GARC_ERR_PASSWORD_OR_CORRUPT:
      return "Wrong password or corrupt member; this cipher cannot tell them "
             "apart";
    case GARC_ERR_REFUSED:
      return "Refused by the filesystem layer";
    case GARC_RESULT_COUNT:
    default:
      return "Unknown error";
  }
}

int garc_result_is_error(GARC_Result result) {
  return !(result == GARC_OK || result == GARC_END);
}

int garc_result_is_limit(GARC_Result result) {
  switch (result) {
    case GARC_ERR_LIMIT_MEMBERS:
    case GARC_ERR_LIMIT_MEMBER_BYTES:
    case GARC_ERR_LIMIT_TOTAL_BYTES:
    case GARC_ERR_LIMIT_NAME_BYTES:
    case GARC_ERR_LIMIT_EXTRA_BYTES:
    case GARC_ERR_LIMIT_CODEC_BYTES:
      return 1;
    default:
      return 0;
  }
}

void garc_limits_default(GARC_Limits * limits) {
  if (!limits) {
    return;
  }

  // Every field gets a value, unlike model's and image's mostly-open caps.
  // See the header: a member's size is read from the container before any of
  // its bytes are, so the size of the input bounds nothing here, and "no
  // limit" would mean a hostile archive's first act is a petabyte request.
  *limits = (GARC_Limits) {
    .max_members = GARC_DEFAULT_MAX_MEMBERS,
    .max_member_bytes = GARC_DEFAULT_MAX_MEMBER_BYTES,
    .max_total_bytes = GARC_DEFAULT_MAX_TOTAL_BYTES,
    .max_name_bytes = GARC_DEFAULT_MAX_NAME_BYTES,
    .max_extra_bytes = GARC_DEFAULT_MAX_EXTRA_BYTES,
  };
}
