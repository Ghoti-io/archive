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
#define GARC_Archive GHOTIIO_ARCHIVE(GARC_Archive)
#define GARC_Format GHOTIIO_ARCHIVE(GARC_Format)
#define GARC_Limits GHOTIIO_ARCHIVE(GARC_Limits)
#define GARC_Member GHOTIIO_ARCHIVE(GARC_Member)
#define GARC_Member_Type GHOTIIO_ARCHIVE(GARC_Member_Type)
#define GARC_Name_Encoding GHOTIIO_ARCHIVE(GARC_Name_Encoding)
#define GARC_Name_Finding GHOTIIO_ARCHIVE(GARC_Name_Finding)
#define GARC_Result GHOTIIO_ARCHIVE(GARC_Result)
#define GARC_Sink GHOTIIO_ARCHIVE(GARC_Sink)
#define GARC_Sink_Callbacks GHOTIIO_ARCHIVE(GARC_Sink_Callbacks)
#define GARC_Stream GHOTIIO_ARCHIVE(GARC_Stream)
#define GARC_Stream_Callbacks GHOTIIO_ARCHIVE(GARC_Stream_Callbacks)
#define GARC_Tar_Variant GHOTIIO_ARCHIVE(GARC_Tar_Variant)
#define GARC_Time_Source GHOTIIO_ARCHIVE(GARC_Time_Source)
#define GARC_Writer GHOTIIO_ARCHIVE(GARC_Writer)
#define GARC_Writer_Options GHOTIIO_ARCHIVE(GARC_Writer_Options)

// Public functions.
#define garc_allocator_default GHOTIIO_ARCHIVE(garc_allocator_default)
#define garc_archive_dump GHOTIIO_ARCHIVE(garc_archive_dump)
#define garc_close GHOTIIO_ARCHIVE(garc_close)
#define garc_format GHOTIIO_ARCHIVE(garc_format)
#define garc_format_string GHOTIIO_ARCHIVE(garc_format_string)
#define garc_limits_default GHOTIIO_ARCHIVE(garc_limits_default)
#define garc_member_count GHOTIIO_ARCHIVE(garc_member_count)
#define garc_member_dump GHOTIIO_ARCHIVE(garc_member_dump)
#define garc_member_type_string GHOTIIO_ARCHIVE(garc_member_type_string)
#define garc_name_check GHOTIIO_ARCHIVE(garc_name_check)
#define garc_name_encoding_string GHOTIIO_ARCHIVE(garc_name_encoding_string)
#define garc_name_finding_string GHOTIIO_ARCHIVE(garc_name_finding_string)
#define garc_name_findings_dump GHOTIIO_ARCHIVE(garc_name_findings_dump)
#define garc_next GHOTIIO_ARCHIVE(garc_next)
#define garc_open GHOTIIO_ARCHIVE(garc_open)
#define garc_open_with_allocator GHOTIIO_ARCHIVE(garc_open_with_allocator)
#define garc_read_member GHOTIIO_ARCHIVE(garc_read_member)
#define garc_skip_member GHOTIIO_ARCHIVE(garc_skip_member)
#define garc_tar_member_checksum_was_signed                                    \
  GHOTIIO_ARCHIVE(garc_tar_member_checksum_was_signed)
#define garc_tar_member_variant GHOTIIO_ARCHIVE(garc_tar_member_variant)
#define garc_tar_variant_string GHOTIIO_ARCHIVE(garc_tar_variant_string)
#define garc_time_source_string GHOTIIO_ARCHIVE(garc_time_source_string)
#define garc_total_declared_bytes GHOTIIO_ARCHIVE(garc_total_declared_bytes)
#define garc_result_is_error GHOTIIO_ARCHIVE(garc_result_is_error)
#define garc_result_is_limit GHOTIIO_ARCHIVE(garc_result_is_limit)
#define garc_result_string GHOTIIO_ARCHIVE(garc_result_string)
#define garc_sink_create_callback GHOTIIO_ARCHIVE(garc_sink_create_callback)
#define garc_sink_create_compress GHOTIIO_ARCHIVE(garc_sink_create_compress)
#define garc_sink_create_compress_with_allocator                              \
  GHOTIIO_ARCHIVE(garc_sink_create_compress_with_allocator)
#define garc_sink_create_callback_with_allocator                               \
  GHOTIIO_ARCHIVE(garc_sink_create_callback_with_allocator)
#define garc_sink_create_memory GHOTIIO_ARCHIVE(garc_sink_create_memory)
#define garc_sink_create_memory_with_allocator                                 \
  GHOTIIO_ARCHIVE(garc_sink_create_memory_with_allocator)
#define garc_sink_data GHOTIIO_ARCHIVE(garc_sink_data)
#define garc_sink_destroy GHOTIIO_ARCHIVE(garc_sink_destroy)
#define garc_sink_finish GHOTIIO_ARCHIVE(garc_sink_finish)
#define garc_sink_fill GHOTIIO_ARCHIVE(garc_sink_fill)
#define garc_sink_tell GHOTIIO_ARCHIVE(garc_sink_tell)
#define garc_sink_write GHOTIIO_ARCHIVE(garc_sink_write)
#define garc_stream_create_callback GHOTIIO_ARCHIVE(garc_stream_create_callback)
#define garc_stream_create_callback_with_allocator                             \
  GHOTIIO_ARCHIVE(garc_stream_create_callback_with_allocator)
#define garc_stream_create_decompress                                         \
  GHOTIIO_ARCHIVE(garc_stream_create_decompress)
#define garc_stream_create_decompress_with_allocator                          \
  GHOTIIO_ARCHIVE(garc_stream_create_decompress_with_allocator)
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
#define garc_writer_add GHOTIIO_ARCHIVE(garc_writer_add)
#define garc_writer_create GHOTIIO_ARCHIVE(garc_writer_create)
#define garc_writer_create_with_allocator                                      \
  GHOTIIO_ARCHIVE(garc_writer_create_with_allocator)
#define garc_writer_data_remaining GHOTIIO_ARCHIVE(garc_writer_data_remaining)
#define garc_writer_destroy GHOTIIO_ARCHIVE(garc_writer_destroy)
#define garc_writer_dump GHOTIIO_ARCHIVE(garc_writer_dump)
#define garc_writer_finish GHOTIIO_ARCHIVE(garc_writer_finish)
#define garc_writer_member_count GHOTIIO_ARCHIVE(garc_writer_member_count)
#define garc_writer_options_default GHOTIIO_ARCHIVE(garc_writer_options_default)
#define garc_writer_write GHOTIIO_ARCHIVE(garc_writer_write)
#define garc_version_string GHOTIIO_ARCHIVE(garc_version_string)

// Internal names. Hidden by -fvisibility=hidden and so unable to collide, but
// renamed anyway so that there is one rule rather than two.
#define garc_reader_account GHOTIIO_ARCHIVE(garc_reader_account)
#define garc_tar_block_is_header GHOTIIO_ARCHIVE(garc_tar_block_is_header)
#define garc_tar_buffer_free GHOTIIO_ARCHIVE(garc_tar_buffer_free)
#define garc_tar_buffer_grow GHOTIIO_ARCHIVE(garc_tar_buffer_grow)
#define garc_tar_format_int GHOTIIO_ARCHIVE(garc_tar_format_int)
#define garc_tar_format_uint GHOTIIO_ARCHIVE(garc_tar_format_uint)
#define garc_tar_identify GHOTIIO_ARCHIVE(garc_tar_identify)
#define garc_tar_next GHOTIIO_ARCHIVE(garc_tar_next)
#define garc_tar_parse_int GHOTIIO_ARCHIVE(garc_tar_parse_int)
#define garc_tar_pax_key_name GHOTIIO_ARCHIVE(garc_tar_pax_key_name)
#define garc_tar_parse_uint GHOTIIO_ARCHIVE(garc_tar_parse_uint)
#define garc_tar_write_end GHOTIIO_ARCHIVE(garc_tar_write_end)
#define garc_tar_write_member GHOTIIO_ARCHIVE(garc_tar_write_member)

/// @endcond

#endif // GHOTI_IO_GARC_NAMESPACE_H
