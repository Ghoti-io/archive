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
 * The writer object, shared by the generic writer and each format's writer.
 */

#ifndef GHOTI_IO_GARC_SRC_WRITER_WRITER_INTERNAL_H
#define GHOTI_IO_GARC_SRC_WRITER_WRITER_INTERNAL_H

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/writer.h>
#include <stddef.h>
#include <stdint.h>

#include "reader/reader_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

struct GARC_Writer {
  /** The sink, borrowed. The caller destroys it; garc_writer_destroy() does
   *  not. */
  GARC_Sink * sink;
  /** Allocator for this object and its buffer. */
  const GARC_Allocator * allocator;
  /** Which container. */
  GARC_Format format;
  /** The options, resolved at create so that NULL means the defaults once. */
  GARC_Writer_Options options;

  /** Members begun, which garc_writer_member_count() reports. */
  uint64_t member_count;
  /** Bytes of the current member's data still owed by the caller. */
  uint64_t data_remaining;
  /**
   * Bytes of padding owed once the data is complete.
   *
   * Computed when the member is added rather than when it is closed, because the
   * declared size is what decides it and the declaration is what the header
   * already carries. Written by the next garc_writer_add() or by
   * garc_writer_finish(), so that a caller never pads.
   */
  uint64_t data_padding;
  /** Non-zero while a member is open. */
  int have_member;
  /** Non-zero once the end-of-archive marker has been written. */
  int finished;

  /**
   * The extended records for the member being added.
   *
   * One buffer reused across members rather than one per member: an archive of
   * long names would otherwise allocate and free once each. Its length is reset
   * at the start of every member, so nothing a previous member needed can leak
   * into the next one's header - the same reason the reader resets its `x` set.
   */
  GARC_Tar_Buffer records;
};

/**
 * Write one member's metadata: its extended records, if it needs any, then its
 * header block.
 *
 * Leaves the sink positioned at the member's data and fills in
 * @ref GARC_Writer.data_remaining and @ref GARC_Writer.data_padding.
 *
 * @param writer The writer.
 * @param member What to write.
 * @return GARC_OK, or the failure garc_writer_add() reports.
 */
GARC_Result garc_tar_write_member(
    GARC_Writer * writer, const GARC_Member * member);

/**
 * Write the end-of-archive marker and whatever padding the options ask for.
 *
 * @param writer The writer.
 * @return GARC_OK, or GARC_ERR_IO.
 */
GARC_Result garc_tar_write_end(GARC_Writer * writer);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GARC_SRC_WRITER_WRITER_INTERNAL_H
