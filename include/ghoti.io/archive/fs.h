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
 * Extracting an archive into a directory, and packing a directory into an
 * archive.
 *
 * **Opt-in, and not part of the reader or the writer.** Those still never
 * open a file. This header is not included by archive.h. A caller who does
 * not extract does not link a use of the filesystem into the question of
 * whether a name was safe.
 *
 * **A clean name is not permission to write.** ::garc_name_check() classifies
 * bytes. Containment is the canonical path of each parent after the links
 * this call has created, and the final component is created only once that
 * parent is still inside the root. `gcu_path_canonicalize()` cannot be asked
 * about a path that does not exist yet, which is why the check is the parent.
 *
 * ::GARC_NAME_ESCAPES, a NUL, and an empty name are refused with no flag.
 * ::GARC_NAME_PORTABILITY is refused unless ::GARC_FS_ALLOW_PORTABLE_NAMES
 * is set, and a `..` that leaves the root is still an escape when it is.
 * Symbolic links and hard links are refused unless ::GARC_FS_ALLOW_LINKS is
 * set, and a link target must still resolve inside the root. A hard link may
 * only name a path this extract has already claimed.
 *
 * The first refusal stops the call. Members already written stay, later
 * members are not written, and the root is not deleted. A path that already
 * exists is a refusal, and whatever is there is left unchanged. Two members
 * whose canonical paths are one path are a refusal of the second. Modes are
 * the archive mode with setuid, setgid and sticky cleared; there is no flag
 * that keeps those bits. On Windows the mode is not applied.
 *
 * Packing stores a symlink as a symlink and does not follow it. A hard link
 * whose other name is inside the tree is a hard link member; one whose other
 * name is outside is a refusal. If the writer cannot store a hard link, that
 * status is the result of the pack.
 */

#ifndef GHOTI_IO_GARC_FS_H
#define GHOTI_IO_GARC_FS_H

#include <ghoti.io/archive/core.h>
#include <ghoti.io/archive/macros.h>
#include <ghoti.io/archive/name.h>
#include <ghoti.io/archive/reader.h>
#include <ghoti.io/archive/writer.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Create symbolic links and hard links.
 *
 * Without it, either member is ::GARC_ERR_REFUSED and not created. With it,
 * the target must still stay inside the root, and a hard link must name a
 * path this extract already claimed.
 */
#define GARC_FS_ALLOW_LINKS ((uint32_t)1u << 0)

/**
 * @brief Allow names ::garc_name_check() reports as ::GARC_NAME_PORTABILITY.
 *
 * That set includes a parent component, so `a/..` is refused unless this is
 * set. A `..` that leaves the root is ::GARC_NAME_ESCAPES and is still
 * refused. The flag does not make an absolute path, a drive, or a UNC path
 * legal.
 */
#define GARC_FS_ALLOW_PORTABLE_NAMES ((uint32_t)1u << 1)

/**
 * @brief Extract the archive's remaining members into @p root.
 *
 * @p root must already exist and be a directory. The walk starts at the
 * archive's current member, so a caller who has already stepped has already
 * chosen where extraction begins; the usual call is on an archive just
 * opened.
 *
 * @param archive The archive to read. Not NULL.
 * @param root The directory to write into. Not NULL.
 * @param flags Zero, or a combination of ::GARC_FS_ALLOW_LINKS and
 *   ::GARC_FS_ALLOW_PORTABLE_NAMES. Any other bit is ::GARC_ERR_INVALID.
 * @return ::GARC_OK, ::GARC_ERR_REFUSED, ::GARC_ERR_INVALID, ::GARC_ERR_OOM,
 *   ::GARC_ERR_IO, or whatever failure ::garc_next() or ::garc_read_member()
 *   stopped on.
 */
GARC_API GARC_Result garc_fs_extract(GARC_Archive * archive, const char * root,
    uint32_t flags);

/**
 * @brief Pack the tree at @p root into an open writer.
 *
 * Does not finish the writer. A symlink is stored as a symlink, including
 * one whose target is outside the tree, and the outside file's bytes are not
 * read. A hard link to a path inside the tree is a hard link member. A hard
 * link to a path outside it is ::GARC_ERR_REFUSED. A fifo, a device, or any
 * other type is ::GARC_ERR_REFUSED. If the writer cannot store a hard link,
 * that status is returned and the pack stops.
 *
 * @param writer The writer to add members to. Not NULL.
 * @param root The directory to read. Not NULL. It must already exist.
 * @param flags As ::garc_fs_extract(). The link and portability flags do not
 *   change what a pack stores: a symlink is always a symlink. Unknown bits
 *   are still ::GARC_ERR_INVALID.
 * @return ::GARC_OK, ::GARC_ERR_REFUSED, ::GARC_ERR_INVALID, ::GARC_ERR_OOM,
 *   ::GARC_ERR_IO, or the writer's own status when it cannot store a member.
 */
GARC_API GARC_Result garc_fs_pack(GARC_Writer * writer, const char * root,
    uint32_t flags);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GARC_FS_H
