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
 * @file namespace.h
 *
 * Maps every public name of this library into its version namespace.
 *
 * Kept in one file rather than beside each declaration: a type rename has to
 * be in effect before any struct tag that uses the name, and an internal
 * header may define such a tag without including the public header that
 * declares the typedef.
 *
 * `make check-symbols` fails if an exported symbol is missing from this list.
 *
 * See CONVENTIONS.md section 4.
 */

#ifndef GHOTI_IO_GARC_NAMESPACE_H
#define GHOTI_IO_GARC_NAMESPACE_H

#include <ghoti.io/archive/libver.h>

/// @cond HIDDEN_SYMBOLS

// Public types. Renamed as well as the functions, so that two versions whose
// structs differ in layout cannot be confused for one another - which is the
// whole point of the scheme, and which renaming only the functions leaves
// undone. GCU_* names are deliberately absent: they are cutil's, and cutil
// has already renamed them.
#define GARC_Allocator GHOTIIO_ARCHIVE(GARC_Allocator)
#define GARC_Limits GHOTIIO_ARCHIVE(GARC_Limits)
#define GARC_Result GHOTIIO_ARCHIVE(GARC_Result)
#define GARC_Stream GHOTIIO_ARCHIVE(GARC_Stream)
#define GARC_Stream_Callbacks GHOTIIO_ARCHIVE(GARC_Stream_Callbacks)

// Public functions.
#define garc_allocator_default GHOTIIO_ARCHIVE(garc_allocator_default)
#define garc_limits_default GHOTIIO_ARCHIVE(garc_limits_default)
#define garc_result_is_error GHOTIIO_ARCHIVE(garc_result_is_error)
#define garc_result_is_limit GHOTIIO_ARCHIVE(garc_result_is_limit)
#define garc_result_string GHOTIIO_ARCHIVE(garc_result_string)
#define garc_stream_create_callback GHOTIIO_ARCHIVE(garc_stream_create_callback)
#define garc_stream_create_callback_with_allocator                             \
  GHOTIIO_ARCHIVE(garc_stream_create_callback_with_allocator)
#define garc_stream_create_memory GHOTIIO_ARCHIVE(garc_stream_create_memory)
#define garc_stream_create_memory_with_allocator                               \
  GHOTIIO_ARCHIVE(garc_stream_create_memory_with_allocator)
#define garc_stream_destroy GHOTIIO_ARCHIVE(garc_stream_destroy)
#define garc_stream_is_seekable GHOTIIO_ARCHIVE(garc_stream_is_seekable)
#define garc_stream_read GHOTIIO_ARCHIVE(garc_stream_read)
#define garc_stream_read_exact GHOTIIO_ARCHIVE(garc_stream_read_exact)
#define garc_stream_seek GHOTIIO_ARCHIVE(garc_stream_seek)
#define garc_stream_size GHOTIIO_ARCHIVE(garc_stream_size)
#define garc_stream_skip GHOTIIO_ARCHIVE(garc_stream_skip)
#define garc_stream_tell GHOTIIO_ARCHIVE(garc_stream_tell)
#define garc_version_number GHOTIIO_ARCHIVE(garc_version_number)
#define garc_version_string GHOTIIO_ARCHIVE(garc_version_string)

/// @endcond

#endif // GHOTI_IO_GARC_NAMESPACE_H
