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
 * @file allocator.h
 *
 * Allocator abstraction for the Ghoti.io Archive library.
 *
 * This is cutil's @ref GCU_Allocator under a local name, the same arrangement
 * the compress and image libraries use. One definition across the suite means
 * an allocator written for any of them works with all of them, rather than
 * needing a near-identical copy per library.
 */

#ifndef GHOTI_IO_GARC_ALLOCATOR_H
#define GHOTI_IO_GARC_ALLOCATOR_H

#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/archive/macros.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Allocator interface used by the library.
 *
 * All function pointers must be non-NULL. Each receives the `ctx` pointer from
 * the struct as its first argument.
 *
 * Two requirements beyond the C library equivalents: `calloc_fn` must treat
 * overflow of `nitems * size` as an allocation failure and return NULL rather
 * than allocating a truncated block, and a zero-size request should return a
 * usable non-NULL pointer, so that NULL always means failure.
 */
typedef GCU_Allocator GARC_Allocator;

/**
 * @brief Get the default allocator (stdlib-backed).
 *
 * @return Pointer to a process-global allocator instance.
 */
GARC_API const GARC_Allocator * garc_allocator_default(void);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GARC_ALLOCATOR_H
