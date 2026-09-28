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
 * The one growable byte buffer. Two functions, and both of them are about what
 * happens when the allocation fails.
 */

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/cutil/allocator.h>

#include "core/buffer_internal.h"

GARC_Result garc_buffer_grow(const GARC_Allocator * allocator,
    GARC_Buffer * buffer, size_t wanted) {
  if (buffer->capacity >= wanted + 1u) {
    return GARC_OK;
  }
  // realloc rather than malloc-and-copy: it returns NULL without freeing the old
  // block, so a failure here leaves what was already parsed readable.
  char * bytes
      = (char *)gcu_allocator_realloc(allocator, buffer->bytes, wanted + 1u);
  if (!bytes) {
    return GARC_ERR_OOM;
  }
  buffer->bytes = bytes;
  buffer->capacity = wanted + 1u;
  return GARC_OK;
}

void garc_buffer_free(const GARC_Allocator * allocator, GARC_Buffer * buffer) {
  gcu_allocator_free(allocator, buffer->bytes);
  buffer->bytes = NULL;
  buffer->capacity = 0;
  buffer->length = 0;
}
