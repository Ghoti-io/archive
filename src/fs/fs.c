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
 * The filesystem layer. The policy is in fs.h; this file is how a path is
 * kept inside the root while members are created, and how a tree is walked
 * without following a symlink.
 */

#include <ghoti.io/archive/fs.h>
#include <ghoti.io/archive/name.h>

#include <ghoti.io/cutil/allocator.h>
#include <ghoti.io/cutil/dir.h>
#include <ghoti.io/cutil/file.h>
#include <ghoti.io/cutil/path.h>

#include <stdbool.h>
#include <string.h>

/** Setuid, setgid and sticky. Cleared before any mode is applied. */
#define GARC_FS_MODE_CLEAR ((uint32_t)(04000u | 02000u | 01000u))

#define GARC_FS_FLAGS_KNOWN                                                \
  (GARC_FS_ALLOW_LINKS | GARC_FS_ALLOW_PORTABLE_NAMES)

typedef struct FsPaths {
  char ** items;
  size_t count;
  size_t capacity;
} FsPaths;

typedef struct FsExtract {
  char * root;
  uint32_t flags;
  FsPaths claimed;
  FsPaths made;
} FsExtract;

static void fs_free(char * path) {
  gcu_path_free(NULL, path);
}

static char * fs_dup_n(const char * bytes, size_t length) {
  char * copy = (char *)gcu_allocator_malloc(NULL, length + 1u);
  if (!copy) {
    return NULL;
  }
  if (length) {
    memcpy(copy, bytes, length);
  }
  copy[length] = '\0';
  return copy;
}

static char * fs_dup(const char * text) {
  return text ? fs_dup_n(text, strlen(text)) : NULL;
}

static GARC_Result fs_from_file(GCU_File_Result result) {
  switch (result) {
    case GCU_FILE_OK:
      return GARC_OK;
    case GCU_FILE_ERR_OOM:
      return GARC_ERR_OOM;
    case GCU_FILE_ERR_INVALID:
      return GARC_ERR_INVALID;
    default:
      return GARC_ERR_IO;
  }
}

static GARC_Result fs_from_path(GCU_Path_Result result) {
  switch (result) {
    case GCU_PATH_OK:
      return GARC_OK;
    case GCU_PATH_ERR_OOM:
      return GARC_ERR_OOM;
    case GCU_PATH_ERR_INVALID:
      return GARC_ERR_INVALID;
    default:
      return GARC_ERR_IO;
  }
}

static int fs_sep(char byte) {
  if (byte == '/') {
    return 1;
  }
#ifdef _WIN32
  if (byte == '\\') {
    return 1;
  }
#endif
  return 0;
}

static int fs_under(const char * root, const char * path) {
  size_t length = strlen(root);
  if (strncmp(path, root, length) != 0) {
    return 0;
  }
  if (path[length] == '\0') {
    return 1;
  }
  if (length > 0 && fs_sep(root[length - 1u])) {
    return 1;
  }
  return fs_sep(path[length]);
}

static int fs_paths_has(const FsPaths * set, const char * path) {
  size_t i;
  for (i = 0; i < set->count; ++i) {
    if (strcmp(set->items[i], path) == 0) {
      return 1;
    }
  }
  return 0;
}

static GARC_Result fs_paths_add(FsPaths * set, const char * path) {
  char * copy;
  char ** grown;
  if (fs_paths_has(set, path)) {
    return GARC_OK;
  }
  copy = fs_dup(path);
  if (!copy) {
    return GARC_ERR_OOM;
  }
  if (set->count == set->capacity) {
    size_t next = set->capacity ? set->capacity * 2u : 8u;
    grown = (char **)gcu_allocator_realloc(NULL, set->items,
        next * sizeof(*grown));
    if (!grown) {
      fs_free(copy);
      return GARC_ERR_OOM;
    }
    set->items = grown;
    set->capacity = next;
  }
  set->items[set->count++] = copy;
  return GARC_OK;
}

static void fs_paths_clear(FsPaths * set) {
  size_t i;
  for (i = 0; i < set->count; ++i) {
    fs_free(set->items[i]);
  }
  gcu_allocator_free(NULL, set->items);
  set->items = NULL;
  set->count = 0;
  set->capacity = 0;
}

static GARC_Result fs_join(const char * base, const char * rel, char ** out) {
  size_t need = 0;
  char * joined;
  GCU_Path_Result result
      = gcu_path_join(GCU_PATH_NATIVE, base, rel, NULL, 0, &need);
  if (result != GCU_PATH_OK) {
    return fs_from_path(result);
  }
  joined = (char *)gcu_allocator_malloc(NULL, need + 1u);
  if (!joined) {
    return GARC_ERR_OOM;
  }
  result = gcu_path_join(GCU_PATH_NATIVE, base, rel, joined, need + 1u, NULL);
  if (result != GCU_PATH_OK) {
    fs_free(joined);
    return fs_from_path(result);
  }
  *out = joined;
  return GARC_OK;
}

static GARC_Result fs_canon(const char * path, char ** out) {
  return fs_from_path(gcu_path_canonicalize(path, NULL, out));
}

static GARC_Result fs_normalize(const char * path, char ** out) {
  size_t need = 0;
  char * text;
  GCU_Path_Result result
      = gcu_path_normalize(GCU_PATH_NATIVE, path, NULL, 0, &need);
  if (result != GCU_PATH_OK) {
    return fs_from_path(result);
  }
  text = (char *)gcu_allocator_malloc(NULL, need + 1u);
  if (!text) {
    return GARC_ERR_OOM;
  }
  result = gcu_path_normalize(
      GCU_PATH_NATIVE, path, text, need + 1u, NULL);
  if (result != GCU_PATH_OK) {
    fs_free(text);
    return fs_from_path(result);
  }
  *out = text;
  return GARC_OK;
}

/**
 * Portability applies to member names. A link target is judged by where it
 * resolves, so a `./` in a target is not a reason to refuse the link.
 */
static int fs_name_refused(const char * name, size_t length, uint32_t flags,
    int portability) {
  uint32_t blocked
      = GARC_NAME_ESCAPES | GARC_NAME_NUL_BYTE | GARC_NAME_EMPTY;
  uint32_t findings = garc_name_check(name, length);
  if (portability && (flags & GARC_FS_ALLOW_PORTABLE_NAMES) == 0) {
    blocked |= GARC_NAME_PORTABILITY;
  }
  return (findings & blocked) != 0;
}

static GARC_Result fs_split(char * name, char *** out_parts, size_t * out_count) {
  size_t capacity = 8;
  size_t count = 0;
  char ** parts;
  char * cursor = name;
  parts = (char **)gcu_allocator_malloc(NULL, capacity * sizeof(*parts));
  if (!parts) {
    return GARC_ERR_OOM;
  }
  while (*cursor) {
    char * start;
    while (*cursor && fs_sep(*cursor)) {
      ++cursor;
    }
    if (!*cursor) {
      break;
    }
    start = cursor;
    while (*cursor && !fs_sep(*cursor)) {
      ++cursor;
    }
    if (*cursor) {
      *cursor = '\0';
      ++cursor;
    }
    if (count == capacity) {
      char ** grown;
      capacity *= 2u;
      grown = (char **)gcu_allocator_realloc(
          NULL, parts, capacity * sizeof(*parts));
      if (!grown) {
        gcu_allocator_free(NULL, parts);
        return GARC_ERR_OOM;
      }
      parts = grown;
    }
    parts[count++] = start;
  }
  *out_parts = parts;
  *out_count = count;
  return GARC_OK;
}

static void fs_replace(char ** slot, char * next) {
  fs_free(*slot);
  *slot = next;
}

/** Step into one existing or newly created directory, and stay inside. */
static GARC_Result fs_enter(FsExtract * state, char ** current,
    const char * component) {
  char * joined = NULL;
  char * canon = NULL;
  GARC_Result result;
  GCU_File_Info info;
  GCU_File_Result looked;

  if (strcmp(component, ".") == 0) {
    return GARC_OK;
  }
  result = fs_join(*current, component, &joined);
  if (result != GARC_OK) {
    return result;
  }
  if (strcmp(component, "..") == 0) {
    result = fs_canon(joined, &canon);
    fs_free(joined);
    if (result != GARC_OK) {
      return result;
    }
    if (!fs_under(state->root, canon)) {
      fs_free(canon);
      return GARC_ERR_REFUSED;
    }
    fs_replace(current, canon);
    return GARC_OK;
  }

  looked = gcu_file_stat_link(joined, &info);
  if (looked == GCU_FILE_ERR_NOT_FOUND) {
    looked = gcu_dir_create(joined);
    if (looked != GCU_FILE_OK) {
      fs_free(joined);
      return fs_from_file(looked);
    }
    result = fs_canon(joined, &canon);
    fs_free(joined);
    if (result != GARC_OK) {
      return result;
    }
    if (!fs_under(state->root, canon)) {
      fs_free(canon);
      return GARC_ERR_REFUSED;
    }
    result = fs_paths_add(&state->made, canon);
    if (result != GARC_OK) {
      fs_free(canon);
      return result;
    }
    fs_replace(current, canon);
    return GARC_OK;
  }
  if (looked != GCU_FILE_OK) {
    fs_free(joined);
    return fs_from_file(looked);
  }

  result = fs_canon(joined, &canon);
  if (result != GARC_OK) {
    fs_free(joined);
    return result;
  }
  if (!fs_under(state->root, canon)) {
    fs_free(joined);
    fs_free(canon);
    return GARC_ERR_REFUSED;
  }
  if (info.type == GCU_FILE_TYPE_SYMLINK) {
    /* Follow only a link this extract created, and only into a directory
     * this extract created. A link aimed at a directory that was already
     * in the root is the same write the direct name is refused. */
    if (!fs_paths_has(&state->claimed, joined)
        || (!fs_paths_has(&state->made, canon)
            && strcmp(canon, state->root) != 0)) {
      fs_free(joined);
      fs_free(canon);
      return GARC_ERR_REFUSED;
    }
  }
  else if (info.type == GCU_FILE_TYPE_DIRECTORY) {
    if (!fs_paths_has(&state->made, canon)
        && strcmp(canon, state->root) != 0) {
      fs_free(joined);
      fs_free(canon);
      return GARC_ERR_REFUSED;
    }
  }
  else {
    fs_free(joined);
    fs_free(canon);
    return GARC_ERR_REFUSED;
  }
  fs_free(joined);
  fs_replace(current, canon);
  return GARC_OK;
}

/**
 * A symlink target is relative to the link's directory. Walk what exists and
 * follow it; the remainder is only lexical, and it still has to stay inside.
 */
static GARC_Result fs_target_inside(const char * root, const char * parent,
    const char * target) {
  char * copy;
  char ** parts = NULL;
  size_t count = 0;
  size_t index;
  char * current;
  GARC_Result result = GARC_OK;

  copy = fs_dup(target);
  current = fs_dup(parent);
  if (!copy || !current) {
    fs_free(copy);
    fs_free(current);
    return GARC_ERR_OOM;
  }
  result = fs_split(copy, &parts, &count);
  if (result != GARC_OK) {
    fs_free(copy);
    fs_free(current);
    return result;
  }
  for (index = 0; index < count; ++index) {
    char * joined = NULL;
    char * canon = NULL;
    GCU_File_Info info;
    GCU_File_Result looked;
    if (strcmp(parts[index], ".") == 0) {
      continue;
    }
    result = fs_join(current, parts[index], &joined);
    if (result != GARC_OK) {
      break;
    }
    looked = gcu_file_stat_link(joined, &info);
    if (looked == GCU_FILE_ERR_NOT_FOUND) {
      char * lexical = NULL;
      size_t rest;
      fs_free(joined);
      joined = fs_dup(current);
      if (!joined) {
        result = GARC_ERR_OOM;
        break;
      }
      for (rest = index; rest < count; ++rest) {
        char * step = NULL;
        result = fs_join(joined, parts[rest], &step);
        fs_free(joined);
        joined = step;
        if (result != GARC_OK) {
          break;
        }
      }
      if (result != GARC_OK) {
        fs_free(joined);
        break;
      }
      result = fs_normalize(joined, &lexical);
      fs_free(joined);
      joined = NULL;
      if (result != GARC_OK) {
        break;
      }
      if (!fs_under(root, lexical)) {
        result = GARC_ERR_REFUSED;
      }
      fs_free(lexical);
      break;
    }
    if (looked != GCU_FILE_OK) {
      fs_free(joined);
      result = fs_from_file(looked);
      break;
    }
    result = fs_canon(joined, &canon);
    fs_free(joined);
    if (result != GARC_OK) {
      break;
    }
    if (!fs_under(root, canon)) {
      fs_free(canon);
      result = GARC_ERR_REFUSED;
      break;
    }
    fs_replace(&current, canon);
  }
  gcu_allocator_free(NULL, parts);
  fs_free(copy);
  fs_free(current);
  return result;
}

static GARC_Result fs_resolve_claimed(FsExtract * state, const char * target,
    char ** out) {
  char * copy;
  char ** parts = NULL;
  size_t count = 0;
  size_t index;
  char * current;
  GARC_Result result;

  copy = fs_dup(target);
  current = fs_dup(state->root);
  if (!copy || !current) {
    fs_free(copy);
    fs_free(current);
    return GARC_ERR_OOM;
  }
  result = fs_split(copy, &parts, &count);
  if (result != GARC_OK) {
    fs_free(copy);
    fs_free(current);
    return result;
  }
  for (index = 0; index < count; ++index) {
    char * joined = NULL;
    char * canon = NULL;
    GCU_File_Result looked;
    GCU_File_Info info;
    if (strcmp(parts[index], ".") == 0) {
      continue;
    }
    result = fs_join(current, parts[index], &joined);
    if (result != GARC_OK) {
      break;
    }
    looked = gcu_file_stat_link(joined, &info);
    if (looked != GCU_FILE_OK) {
      fs_free(joined);
      result = looked == GCU_FILE_ERR_NOT_FOUND
          ? GARC_ERR_REFUSED : fs_from_file(looked);
      break;
    }
    result = fs_canon(joined, &canon);
    fs_free(joined);
    if (result != GARC_OK) {
      break;
    }
    if (!fs_under(state->root, canon)) {
      fs_free(canon);
      result = GARC_ERR_REFUSED;
      break;
    }
    fs_replace(&current, canon);
  }
  gcu_allocator_free(NULL, parts);
  fs_free(copy);
  if (result != GARC_OK) {
    fs_free(current);
    return result;
  }
  if (!fs_paths_has(&state->claimed, current)) {
    fs_free(current);
    return GARC_ERR_REFUSED;
  }
  *out = current;
  return GARC_OK;
}

static GARC_Result fs_apply_mode(const char * path, const GARC_Member * member) {
  uint32_t mode;
  GCU_File_Result result;
  if (!member->mode_valid) {
    return GARC_OK;
  }
  if (member->type == GARC_MEMBER_SYMLINK
      || member->type == GARC_MEMBER_HARDLINK) {
    return GARC_OK;
  }
  mode = (member->mode & 07777u) & ~GARC_FS_MODE_CLEAR;
  result = gcu_file_set_mode(path, mode);
  if (result == GCU_FILE_OK) {
    return GARC_OK;
  }
#ifdef _WIN32
  /* A Unix mode does not apply. The member is already there; stopping would
   * report a refusal for a platform that has no such bits. */
  if (result == GCU_FILE_ERR_ACCESS) {
    return GARC_OK;
  }
#endif
  return fs_from_file(result);
}

static GARC_Result fs_write_file(GARC_Archive * archive,
    const GARC_Member * member, const char * path) {
  GCU_File_Handle handle;
  uint64_t left = member->size;
  uint8_t buffer[8192];
  GARC_Result result = GARC_OK;
  memset(&handle, 0, sizeof(handle));
  result = fs_from_file(gcu_file_open(&handle, path, GCU_FILE_OPEN_WRITE,
      GCU_FILE_PERMS_PRIVATE, NULL));
  if (result != GARC_OK) {
    return result;
  }
  while (left) {
    size_t want = left > sizeof(buffer) ? sizeof(buffer) : (size_t)left;
    size_t got = 0;
    result = garc_read_member(archive, buffer, want, &got);
    if (result != GARC_OK) {
      break;
    }
    if (got == 0) {
      result = GARC_ERR_CORRUPT;
      break;
    }
    result = fs_from_file(gcu_file_write_bytes(&handle, buffer, got));
    if (result != GARC_OK) {
      break;
    }
    left -= got;
  }
  if (result == GARC_OK) {
    result = fs_from_file(gcu_file_close(&handle));
  }
  else {
    gcu_file_close(&handle);
  }
  return result;
}

static int fs_type_refused(GARC_Member_Type type, uint32_t flags) {
  switch (type) {
    case GARC_MEMBER_FILE:
    case GARC_MEMBER_DIRECTORY:
      return 0;
    case GARC_MEMBER_SYMLINK:
    case GARC_MEMBER_HARDLINK:
      return (flags & GARC_FS_ALLOW_LINKS) == 0;
    default:
      return 1;
  }
}

static GARC_Result fs_create_final(GARC_Archive * archive,
    const GARC_Member * member, FsExtract * state, const char * parent,
    const char * final, const char * link_text) {
  char * dest = NULL;
  char * canon = NULL;
  char * claimed_target = NULL;
  GCU_File_Info info;
  GCU_File_Result looked;
  GARC_Result result;
  int exists = 0;

  if (strcmp(final, ".") == 0 || strcmp(final, "..") == 0) {
    result = fs_join(parent, final, &dest);
    if (result != GARC_OK) {
      return result;
    }
    result = fs_canon(dest, &canon);
    fs_free(dest);
    dest = NULL;
    if (result != GARC_OK) {
      return result;
    }
    if (!fs_under(state->root, canon)) {
      fs_free(canon);
      return GARC_ERR_REFUSED;
    }
    dest = canon;
    canon = NULL;
    exists = 1;
  }
  else {
    result = fs_join(parent, final, &dest);
    if (result != GARC_OK) {
      return result;
    }
    looked = gcu_file_stat_link(dest, &info);
    if (looked == GCU_FILE_OK) {
      exists = 1;
    }
    else if (looked != GCU_FILE_ERR_NOT_FOUND) {
      fs_free(dest);
      return fs_from_file(looked);
    }
  }

  if (exists) {
    if (!canon) {
      result = fs_canon(dest, &canon);
      if (result != GARC_OK) {
        fs_free(dest);
        return result;
      }
    }
    if (member->type == GARC_MEMBER_DIRECTORY
        && fs_paths_has(&state->made, canon)
        && !fs_paths_has(&state->claimed, canon)) {
      result = fs_apply_mode(dest, member);
      if (result == GARC_OK) {
        result = fs_paths_add(&state->claimed, canon);
      }
      fs_free(dest);
      fs_free(canon);
      return result;
    }
    fs_free(dest);
    fs_free(canon);
    return GARC_ERR_REFUSED;
  }

  if (fs_paths_has(&state->claimed, dest)) {
    fs_free(dest);
    return GARC_ERR_REFUSED;
  }

  if (member->type == GARC_MEMBER_SYMLINK) {
    result = fs_target_inside(state->root, parent, link_text);
    if (result != GARC_OK) {
      fs_free(dest);
      return result;
    }
    looked = gcu_file_symlink(link_text, dest);
    if (looked != GCU_FILE_OK) {
      fs_free(dest);
#ifdef _WIN32
      if (looked == GCU_FILE_ERR_ACCESS) {
        return GARC_ERR_REFUSED;
      }
#endif
      return fs_from_file(looked);
    }
    result = fs_paths_add(&state->claimed, dest);
    fs_free(dest);
    return result;
  }

  if (member->type == GARC_MEMBER_HARDLINK) {
    result = fs_resolve_claimed(state, link_text, &claimed_target);
    if (result != GARC_OK) {
      fs_free(dest);
      return result;
    }
    looked = gcu_file_hardlink(claimed_target, dest);
    fs_free(claimed_target);
    if (looked != GCU_FILE_OK) {
      fs_free(dest);
      return fs_from_file(looked);
    }
    result = fs_canon(dest, &canon);
    if (result != GARC_OK) {
      fs_free(dest);
      return result;
    }
    /* The inode is the one already claimed. Claim the new name as well, so
     * a later member with this path is a second claim. */
    result = fs_paths_add(&state->claimed, dest);
    if (result == GARC_OK) {
      result = fs_paths_add(&state->claimed, canon);
    }
    fs_free(dest);
    fs_free(canon);
    return result;
  }

  if (member->type == GARC_MEMBER_DIRECTORY) {
    looked = gcu_dir_create(dest);
    if (looked != GCU_FILE_OK) {
      fs_free(dest);
      return fs_from_file(looked);
    }
  }
  else {
    result = fs_write_file(archive, member, dest);
    if (result != GARC_OK) {
      gcu_file_remove(dest);
      fs_free(dest);
      return result;
    }
  }
  result = fs_apply_mode(dest, member);
  if (result != GARC_OK) {
    if (member->type == GARC_MEMBER_DIRECTORY) {
      gcu_dir_remove(dest);
    }
    else {
      gcu_file_remove(dest);
    }
    fs_free(dest);
    return result;
  }
  result = fs_canon(dest, &canon);
  if (result != GARC_OK) {
    fs_free(dest);
    return result;
  }
  if (!fs_under(state->root, canon)) {
    if (member->type == GARC_MEMBER_DIRECTORY) {
      gcu_dir_remove(dest);
    }
    else {
      gcu_file_remove(dest);
    }
    fs_free(dest);
    fs_free(canon);
    return GARC_ERR_REFUSED;
  }
  result = fs_paths_add(&state->claimed, canon);
  if (result == GARC_OK && member->type == GARC_MEMBER_DIRECTORY) {
    result = fs_paths_add(&state->made, canon);
  }
  if (result == GARC_OK && strcmp(dest, canon) != 0) {
    result = fs_paths_add(&state->claimed, dest);
  }
  fs_free(dest);
  fs_free(canon);
  return result;
}

static GARC_Result fs_extract_member(GARC_Archive * archive,
    const GARC_Member * member, FsExtract * state) {
  char * name = NULL;
  char * link_text = NULL;
  char ** parts = NULL;
  size_t count = 0;
  size_t index;
  char * current = NULL;
  GARC_Result result;

  if (fs_type_refused(member->type, state->flags)) {
    return GARC_ERR_REFUSED;
  }
  if (fs_name_refused(member->name, member->name_length, state->flags, 1)) {
    return GARC_ERR_REFUSED;
  }
  if (member->type == GARC_MEMBER_SYMLINK
      || member->type == GARC_MEMBER_HARDLINK) {
    if (!member->link_target || member->link_target_length == 0) {
      return GARC_ERR_REFUSED;
    }
    if (fs_name_refused(member->link_target, member->link_target_length,
            state->flags, 0)) {
      return GARC_ERR_REFUSED;
    }
    link_text = fs_dup_n(member->link_target, member->link_target_length);
    if (!link_text) {
      return GARC_ERR_OOM;
    }
  }

  name = fs_dup_n(member->name, member->name_length);
  if (!name) {
    fs_free(link_text);
    return GARC_ERR_OOM;
  }
  result = fs_split(name, &parts, &count);
  if (result != GARC_OK) {
    fs_free(name);
    fs_free(link_text);
    return result;
  }
  if (count == 0) {
    gcu_allocator_free(NULL, parts);
    fs_free(name);
    fs_free(link_text);
    return GARC_ERR_REFUSED;
  }
  current = fs_dup(state->root);
  if (!current) {
    gcu_allocator_free(NULL, parts);
    fs_free(name);
    fs_free(link_text);
    return GARC_ERR_OOM;
  }
  for (index = 0; index + 1u < count; ++index) {
    result = fs_enter(state, &current, parts[index]);
    if (result != GARC_OK) {
      gcu_allocator_free(NULL, parts);
      fs_free(name);
      fs_free(link_text);
      fs_free(current);
      return result;
    }
  }
  result = fs_create_final(
      archive, member, state, current, parts[count - 1u], link_text);
  gcu_allocator_free(NULL, parts);
  fs_free(name);
  fs_free(link_text);
  fs_free(current);
  return result;
}

GARC_Result garc_fs_extract(GARC_Archive * archive, const char * root,
    uint32_t flags) {
  FsExtract state;
  GCU_File_Info info;
  GCU_File_Result looked;
  GARC_Result result;

  if (!archive || !root || !root[0] || (flags & ~GARC_FS_FLAGS_KNOWN) != 0) {
    return GARC_ERR_INVALID;
  }
  memset(&state, 0, sizeof(state));
  state.flags = flags;
  looked = gcu_file_stat(root, &info);
  if (looked != GCU_FILE_OK) {
    return fs_from_file(looked);
  }
  if (info.type != GCU_FILE_TYPE_DIRECTORY) {
    return GARC_ERR_INVALID;
  }
  result = fs_canon(root, &state.root);
  if (result != GARC_OK) {
    return result;
  }

  for (;;) {
    const GARC_Member * member = NULL;
    result = garc_next(archive, &member);
    if (result == GARC_END) {
      result = GARC_OK;
      break;
    }
    if (result != GARC_OK) {
      break;
    }
    result = fs_extract_member(archive, member, &state);
    if (result != GARC_OK) {
      break;
    }
  }
  fs_paths_clear(&state.claimed);
  fs_paths_clear(&state.made);
  fs_free(state.root);
  return result;
}

typedef struct FsEntry {
  char * rel;
  char * full;
  char * link;
  GARC_Member_Type type;
  uint32_t mode;
  uint64_t size;
  uint64_t device;
  uint64_t inode;
  uint64_t links;
  size_t first;
} FsEntry;

typedef struct FsList {
  FsEntry * items;
  size_t count;
  size_t capacity;
} FsList;

static void fs_entry_clear(FsEntry * entry) {
  fs_free(entry->rel);
  fs_free(entry->full);
  fs_free(entry->link);
  memset(entry, 0, sizeof(*entry));
}

static void fs_list_clear(FsList * list) {
  size_t i;
  for (i = 0; i < list->count; ++i) {
    fs_entry_clear(&list->items[i]);
  }
  gcu_allocator_free(NULL, list->items);
  list->items = NULL;
  list->count = 0;
  list->capacity = 0;
}

static GARC_Result fs_list_push(FsList * list, FsEntry * entry) {
  if (list->count == list->capacity) {
    size_t next = list->capacity ? list->capacity * 2u : 8u;
    FsEntry * grown = (FsEntry *)gcu_allocator_realloc(
        NULL, list->items, next * sizeof(*grown));
    if (!grown) {
      return GARC_ERR_OOM;
    }
    list->items = grown;
    list->capacity = next;
  }
  list->items[list->count++] = *entry;
  memset(entry, 0, sizeof(*entry));
  return GARC_OK;
}

static GARC_Result fs_rel_join(const char * parent, const char * name,
    char ** out) {
  size_t length;
  char * joined;
  if (!parent || !parent[0]) {
    *out = fs_dup(name);
    return *out ? GARC_OK : GARC_ERR_OOM;
  }
  length = strlen(parent) + 1u + strlen(name);
  joined = (char *)gcu_allocator_malloc(NULL, length + 1u);
  if (!joined) {
    return GARC_ERR_OOM;
  }
  memcpy(joined, parent, strlen(parent));
  joined[strlen(parent)] = '/';
  memcpy(joined + strlen(parent) + 1u, name, strlen(name) + 1u);
  *out = joined;
  return GARC_OK;
}

typedef struct FsSeen {
  uint64_t device;
  uint64_t inode;
  struct FsSeen * next;
} FsSeen;

static int fs_seen_has(const FsSeen * seen, uint64_t device, uint64_t inode) {
  for (; seen; seen = seen->next) {
    if (seen->device == device && seen->inode == inode) {
      return 1;
    }
  }
  return 0;
}

static GARC_Result fs_pack_dir(const char * dir, const char * rel, FsList * list,
    FsSeen ** seen, int depth) {
  GCU_Dir handle;
  GARC_Result result = GARC_OK;
  memset(&handle, 0, sizeof(handle));
  result = fs_from_file(gcu_dir_open(&handle, dir, NULL));
  if (result != GARC_OK) {
    return result;
  }
  for (;;) {
    const char * name = NULL;
    bool done = 0;
    GCU_File_Info info;
    GCU_File_Identity id;
    FsEntry entry;
    char * full = NULL;
    char * child_rel = NULL;
    GCU_File_Result looked;
    looked = gcu_dir_read(&handle, &name, NULL, &done);
    if (looked != GCU_FILE_OK) {
      result = fs_from_file(looked);
      break;
    }
    if (done) {
      break;
    }
    memset(&entry, 0, sizeof(entry));
    result = fs_join(dir, name, &full);
    if (result != GARC_OK) {
      break;
    }
    result = fs_rel_join(rel, name, &child_rel);
    if (result != GARC_OK) {
      fs_free(full);
      break;
    }
    looked = gcu_file_stat_link(full, &info);
    if (looked != GCU_FILE_OK) {
      fs_free(full);
      fs_free(child_rel);
      result = fs_from_file(looked);
      break;
    }
    entry.full = full;
    entry.rel = child_rel;
    entry.size = info.size;
    if (info.type == GCU_FILE_TYPE_DIRECTORY) {
      entry.type = GARC_MEMBER_DIRECTORY;
      entry.size = 0;
      looked = gcu_file_identity(full, &id);
      if (looked != GCU_FILE_OK) {
        fs_entry_clear(&entry);
        result = fs_from_file(looked);
        break;
      }
      entry.mode = id.mode;
      if (depth >= 64 || fs_seen_has(*seen, id.device, id.inode)) {
        fs_entry_clear(&entry);
        result = GARC_ERR_REFUSED;
        break;
      }
      result = fs_list_push(list, &entry);
      if (result != GARC_OK) {
        fs_entry_clear(&entry);
        break;
      }
      {
        FsSeen node;
        node.device = id.device;
        node.inode = id.inode;
        node.next = *seen;
        *seen = &node;
        result = fs_pack_dir(full, child_rel, list, seen, depth + 1);
        *seen = node.next;
      }
      if (result != GARC_OK) {
        break;
      }
      /* full and child_rel were moved into the list. */
      continue;
    }
    if (info.type == GCU_FILE_TYPE_SYMLINK) {
      char * text = NULL;
      size_t length = 0;
      entry.type = GARC_MEMBER_SYMLINK;
      entry.size = 0;
      looked = gcu_file_read_link(full, NULL, &text, &length);
      if (looked != GCU_FILE_OK) {
        fs_entry_clear(&entry);
        result = fs_from_file(looked);
        break;
      }
      entry.link = text;
      looked = gcu_file_identity(full, &id);
      entry.mode = looked == GCU_FILE_OK ? id.mode : 0777u;
      result = fs_list_push(list, &entry);
      if (result != GARC_OK) {
        fs_entry_clear(&entry);
        break;
      }
      continue;
    }
    if (info.type != GCU_FILE_TYPE_REGULAR) {
      fs_entry_clear(&entry);
      result = GARC_ERR_REFUSED;
      break;
    }
    looked = gcu_file_identity(full, &id);
    if (looked != GCU_FILE_OK) {
      fs_entry_clear(&entry);
      result = fs_from_file(looked);
      break;
    }
    entry.type = GARC_MEMBER_FILE;
    entry.mode = id.mode;
    entry.device = id.device;
    entry.inode = id.inode;
    entry.links = id.links;
    result = fs_list_push(list, &entry);
    if (result != GARC_OK) {
      fs_entry_clear(&entry);
      break;
    }
  }
  gcu_dir_close(&handle);
  return result;
}

static int fs_same_file(const FsEntry * left, const FsEntry * right) {
  return left->type == GARC_MEMBER_FILE && right->type == GARC_MEMBER_FILE
      && left->device == right->device && left->inode == right->inode;
}

static GARC_Result fs_mark_links(FsList * list) {
  size_t i;
  for (i = 0; i < list->count; ++i) {
    size_t count;
    size_t j;
    list->items[i].first = i;
    if (list->items[i].type != GARC_MEMBER_FILE) {
      continue;
    }
    count = 0;
    for (j = 0; j < list->count; ++j) {
      if (fs_same_file(&list->items[i], &list->items[j])) {
        ++count;
      }
    }
    if (list->items[i].links > count) {
      return GARC_ERR_REFUSED;
    }
    for (j = 0; j < i; ++j) {
      if (fs_same_file(&list->items[i], &list->items[j])) {
        list->items[i].first = j;
        break;
      }
    }
  }
  return GARC_OK;
}

static GARC_Result fs_emit(GARC_Writer * writer, const FsList * list) {
  size_t i;
  for (i = 0; i < list->count; ++i) {
    const FsEntry * entry = &list->items[i];
    GARC_Member member;
    GARC_Result result;
    void * data = NULL;
    size_t length = 0;
    memset(&member, 0, sizeof(member));
    member.name = entry->rel;
    member.name_length = strlen(entry->rel);
    member.mode = entry->mode;
    member.mode_valid = 1;
    if (entry->type == GARC_MEMBER_FILE && entry->first != i) {
      member.type = GARC_MEMBER_HARDLINK;
      member.link_target = list->items[entry->first].rel;
      member.link_target_length = strlen(member.link_target);
      member.size = 0;
      result = garc_writer_add(writer, &member);
      if (result != GARC_OK) {
        return result;
      }
      continue;
    }
    member.type = entry->type;
    if (entry->type == GARC_MEMBER_SYMLINK) {
      member.link_target = entry->link;
      member.link_target_length = strlen(entry->link);
      member.size = 0;
      result = garc_writer_add(writer, &member);
      if (result != GARC_OK) {
        return result;
      }
      continue;
    }
    if (entry->type == GARC_MEMBER_FILE) {
      GCU_File_Info again;
      GCU_File_Result looked = gcu_file_stat_link(entry->full, &again);
      if (looked != GCU_FILE_OK) {
        return fs_from_file(looked);
      }
      if (again.type != GCU_FILE_TYPE_REGULAR) {
        return GARC_ERR_REFUSED;
      }
      looked = gcu_file_read(entry->full, GCU_FILE_UNLIMITED,
          NULL, &data, &length);
      if (looked != GCU_FILE_OK) {
        return fs_from_file(looked);
      }
      member.size = length;
    }
    result = garc_writer_add(writer, &member);
    if (result != GARC_OK) {
      gcu_file_free(NULL, data);
      return result;
    }
    if (length) {
      result = garc_writer_write(writer, data, length);
      gcu_file_free(NULL, data);
      if (result != GARC_OK) {
        return result;
      }
    }
    else {
      gcu_file_free(NULL, data);
    }
  }
  return GARC_OK;
}

GARC_Result garc_fs_pack(GARC_Writer * writer, const char * root,
    uint32_t flags) {
  FsList list;
  GCU_File_Info info;
  GCU_File_Result looked;
  char * canon = NULL;
  GARC_Result result;

  if (!writer || !root || !root[0] || (flags & ~GARC_FS_FLAGS_KNOWN) != 0) {
    return GARC_ERR_INVALID;
  }
  looked = gcu_file_stat(root, &info);
  if (looked != GCU_FILE_OK) {
    return fs_from_file(looked);
  }
  if (info.type != GCU_FILE_TYPE_DIRECTORY) {
    return GARC_ERR_INVALID;
  }
  result = fs_canon(root, &canon);
  if (result != GARC_OK) {
    return result;
  }
  memset(&list, 0, sizeof(list));
  {
    GCU_File_Identity root_id;
    FsSeen * seen = NULL;
    FsSeen root_seen;
    looked = gcu_file_identity(canon, &root_id);
    if (looked != GCU_FILE_OK) {
      fs_free(canon);
      return fs_from_file(looked);
    }
    root_seen.device = root_id.device;
    root_seen.inode = root_id.inode;
    root_seen.next = NULL;
    seen = &root_seen;
    result = fs_pack_dir(canon, "", &list, &seen, 0);
  }
  fs_free(canon);
  if (result == GARC_OK) {
    result = fs_mark_links(&list);
  }
  if (result == GARC_OK) {
    result = fs_emit(writer, &list);
  }
  fs_list_clear(&list);
  return result;
}
