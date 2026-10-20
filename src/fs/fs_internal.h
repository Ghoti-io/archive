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
 * What the two files of the filesystem layer share.
 */

#ifndef GHOTI_IO_GARC_SRC_FS_FS_INTERNAL_H
#define GHOTI_IO_GARC_SRC_FS_FS_INTERNAL_H

#include <ghoti.io/archive/core.h>
#include <ghoti.io/archive/macros.h>
#include <ghoti.io/archive/fs.h>
#include <ghoti.io/cutil/file.h>

/**
 * Turn a cutil file status into this library's.
 *
 * A missing path and a refused one keep their own statuses, because a caller
 * does something different about each. Everything else that is not OOM or a
 * bad argument is an I/O failure.
 *
 * @param result The cutil status.
 * @return The archive status.
 */
GARC_Result garc_fs_from_file(GCU_File_Result result);

/**
 * ::garc_fs_open() past its argument checks, saying which codec it removed.
 *
 * @param path The file.
 * @param limits Caps, or NULL.
 * @param options `compress` options for a decoder, or NULL.
 * @param flags As ::garc_fs_open().
 * @param allocator The allocator. Not NULL.
 * @param out_archive Receives the archive.
 * @param out_method Receives the codec's name, or NULL when there was none.
 * @return As ::garc_fs_open().
 */
GARC_Result garc_fs_open_detecting(const char * path,
    const GARC_Limits * limits, gcomp_options_t * options, uint32_t flags,
    const GARC_Allocator * allocator, GARC_Archive ** out_archive,
    const char ** out_method);

#endif // GHOTI_IO_GARC_SRC_FS_FS_INTERNAL_H
