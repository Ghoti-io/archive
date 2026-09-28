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
 * One growable byte buffer, for a string no header field can bound.
 *
 * A leaf header: it knows about an allocator and nothing else - not the archive,
 * not the writer, not a format. Every part of this library that has to hold a
 * name, a link target or a record set of unbounded length uses this one, which is
 * what stops there being three of them with three different growth rules.
 *
 * It was tar's, declared in `tar_internal.h` and implemented in
 * `tar_extended.c`, and the writer already reached across for it. zip needs the
 * same thing for a name of up to 65,535 bytes, and a zip reader including tar's
 * header to get a buffer would be the wrong dependency written down.
 */

#ifndef GHOTI_IO_GARC_SRC_CORE_BUFFER_INTERNAL_H
#define GHOTI_IO_GARC_SRC_CORE_BUFFER_INTERNAL_H

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/allocator.h>
#include <ghoti.io/archive/core.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * A growable byte buffer for a string the header fields cannot bound.
 *
 * Bytes, a length and a capacity, rather than a C string: what it holds is a
 * member name, and a member name is attacker-controlled bytes that may contain
 * anything. A NUL is written one past @ref length as a convenience for a
 * debugger, and nothing reads it.
 */
typedef struct {
  /** The bytes, or NULL before the first use. */
  char * bytes;
  /** How many of them are in use. */
  size_t length;
  /** How many were allocated, which is at least @ref length + 1. */
  size_t capacity;
} GARC_Buffer;

/**
 * Make sure a buffer can hold @p wanted bytes and a terminator, keeping what it
 * already holds.
 *
 * Used by the tar reader for a record set, which is *appended* to - a second `x`
 * header for one member adds to it, and a second `g` overrides individual keys -
 * by the tar writer for the record set it builds, and by the zip reader for a
 * name or an extra field the central directory sizes at run time. It takes an
 * allocator rather than an archive because the writer has no archive; that is
 * also what makes it the one growable buffer in this library rather than three.
 *
 * @param allocator The allocator.
 * @param buffer The buffer.
 * @param wanted How many bytes have to fit.
 * @return ::GARC_OK, or ::GARC_ERR_OOM with the old contents intact.
 */
GARC_Result garc_buffer_grow(const GARC_Allocator * allocator,
    GARC_Buffer * buffer, size_t wanted);

/**
 * Free a buffer and leave it in its unused state.
 *
 * @param allocator The allocator it was grown through.
 * @param buffer The buffer.
 */
void garc_buffer_free(const GARC_Allocator * allocator, GARC_Buffer * buffer);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GARC_SRC_CORE_BUFFER_INTERNAL_H
