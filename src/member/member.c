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
 * Member names for the enums, and the member dump.
 */

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/member.h>
#include <ghoti.io/archive/tar.h>
#include <stdint.h>

const char * garc_member_type_string(GARC_Member_Type type) {
  switch (type) {
    case GARC_MEMBER_FILE:
      return "file";
    case GARC_MEMBER_DIRECTORY:
      return "directory";
    case GARC_MEMBER_SYMLINK:
      return "symlink";
    case GARC_MEMBER_HARDLINK:
      return "hardlink";
    case GARC_MEMBER_FIFO:
      return "fifo";
    case GARC_MEMBER_CHAR_DEVICE:
      return "character device";
    case GARC_MEMBER_BLOCK_DEVICE:
      return "block device";
    case GARC_MEMBER_OTHER:
      return "other";
    case GARC_MEMBER_TYPE_COUNT:
    default:
      return "invalid";
  }
}

const char * garc_name_encoding_string(GARC_Name_Encoding encoding) {
  switch (encoding) {
    case GARC_NAME_UNDECLARED:
      return "undeclared";
    case GARC_NAME_UTF8:
      return "utf-8";
    case GARC_NAME_ENCODING_COUNT:
    default:
      return "invalid";
  }
}

const char * garc_time_source_string(GARC_Time_Source source) {
  switch (source) {
    case GARC_TIME_NONE:
      return "none";
    case GARC_TIME_TAR_OCTAL:
      return "tar octal";
    case GARC_TIME_PAX_DECIMAL:
      return "pax decimal";
    case GARC_TIME_SOURCE_COUNT:
    default:
      return "invalid";
  }
}

const char * garc_tar_variant_string(GARC_Tar_Variant variant) {
  switch (variant) {
    case GARC_TAR_NONE:
      return "none";
    case GARC_TAR_V7:
      return "v7";
    case GARC_TAR_USTAR:
      return "ustar";
    case GARC_TAR_GNU:
      return "gnu";
    case GARC_TAR_PAX:
      return "pax";
    case GARC_TAR_VARIANT_COUNT:
    default:
      return "invalid";
  }
}

/**
 * Write bytes with everything but printable ASCII escaped.
 *
 * **A member name is attacker-controlled and a dump is something a person
 * looks at.** Writing the bytes through unescaped lets an archive put an ANSI
 * escape in a filename and move the cursor, clear the screen, or overwrite the
 * line above - so the output of a listing tool says whatever the archive wants
 * it to. A NUL or a newline is the cheaper version of the same trick: it ends
 * the line early and hides everything the dump was going to say next.
 *
 * Escaped as `\xHH`, and the backslash itself too, so that the escaping is
 * reversible and two different names cannot produce one line of output.
 */
static void member_write_escaped(
    const char * bytes, size_t length, FILE * out) {
  if (!bytes) {
    fputs("(null)", out);
    return;
  }
  for (size_t i = 0; i < length; ++i) {
    const unsigned char byte = (unsigned char)bytes[i];
    if (byte == '\\') {
      fputs("\\\\", out);
    } else if (byte >= 0x20u && byte < 0x7Fu) {
      fputc((int)byte, out);
    } else {
      fprintf(out, "\\x%02X", (unsigned)byte);
    }
  }
}

void garc_member_dump(const GARC_Member * member, FILE * out) {
  if (!out) {
    return;
  }
  if (!member) {
    fprintf(out, "member: (null)\n");
    return;
  }

  fputs("member: name=\"", out);
  member_write_escaped(member->name, member->name_length, out);
  fprintf(out, "\" (%zu bytes, %s)\n", member->name_length,
      garc_name_encoding_string(member->name_encoding));

  fprintf(out, "  type: %s\n", garc_member_type_string(member->type));
  fprintf(out, "  declared size: %llu\n", (unsigned long long)member->size);

  if (member->link_target) {
    fputs("  link target: \"", out);
    member_write_escaped(
        member->link_target, member->link_target_length, out);
    fprintf(out, "\" (%zu bytes)\n", member->link_target_length);
  }

  fprintf(out, "  mtime: ");
  if (member->mtime_source == GARC_TIME_NONE) {
    fprintf(out, "none\n");
  } else {
    fprintf(out, "%lld.%09lu from %s\n", (long long)member->mtime_seconds,
        (unsigned long)member->mtime_nanoseconds,
        garc_time_source_string(member->mtime_source));
  }

  if (member->mode_valid) {
    fprintf(out, "  mode: 0%o\n", (unsigned)member->mode);
  } else {
    fprintf(out, "  mode: absent\n");
  }

  if (member->ids_valid) {
    fprintf(out, "  uid/gid: %lld/%lld\n", (long long)member->uid,
        (long long)member->gid);
  } else {
    fprintf(out, "  uid/gid: absent\n");
  }

  if (member->uname) {
    fputs("  uname: \"", out);
    member_write_escaped(member->uname, member->uname_length, out);
    fputs("\"\n", out);
  }
  if (member->gname) {
    fputs("  gname: \"", out);
    member_write_escaped(member->gname, member->gname_length, out);
    fputs("\"\n", out);
  }

  if (member->device_valid) {
    fprintf(out, "  device: %lu/%lu\n", (unsigned long)member->device_major,
        (unsigned long)member->device_minor);
  }

  fprintf(out, "  offsets: header=%llu data=%llu\n",
      (unsigned long long)member->header_offset,
      (unsigned long long)member->data_offset);
}
