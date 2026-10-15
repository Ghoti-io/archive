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
 * What the shar writer shares with the writer.
 */

#ifndef GHOTI_IO_GARC_SRC_SHAR_SHAR_INTERNAL_H
#define GHOTI_IO_GARC_SRC_SHAR_SHAR_INTERNAL_H

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/core.h>

#include "writer/writer_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

GARC_Result garc_shar_write_member(
    GARC_Writer * writer, const GARC_Member * member);

GARC_Result garc_shar_write_data(
    GARC_Writer * writer, const void * data, size_t size);

GARC_Result garc_shar_write_close_member(GARC_Writer * writer);

GARC_Result garc_shar_write_end(GARC_Writer * writer);

void garc_shar_write_release(GARC_Writer * writer);

#ifdef __cplusplus
}
#endif

#endif
