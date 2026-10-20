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
 * The shar writer: a shell script that recreates the archive when it is run.
 *
 * **Written, and never read.** A shell archive is a program, and reading one
 * means deciding what a shell would do with it - which is exactly the question a
 * library that hands back names and byte ranges must not answer. This library
 * writes them for the tools that still ask for one; extracting is `sh`'s job, and
 * running a script from a source is a decision for the person running it.
 *
 * **Two bodies.** The default writes a file's data as lines each prefixed with
 * `X`, recovered by `sed 's/^X//'`, between a here-document's delimiters. The
 * prefix is what makes the delimiter safe: no data line can *be* `SHAR_END`,
 * because every line begins with `X`. It is readable, and it is **text only**: a
 * NUL cannot sit in a shell here-document, and a last line with no newline would
 * gain one when `sed` wrote it. Both are ::GARC_ERR_UNSUPPORTED at the byte or
 * the close where they are met. A stream cannot know either in advance, and
 * part of the member is already in the sink by then, so the refusal fails the
 * writer: it never writes the `exit 0` that ends a whole script, and a file
 * sink never renames the partial one into place.
 * `shar_uuencode` writes any bytes, as uuencode, and extracting needs
 * `uudecode`.
 *
 * **Every name is single-quoted** for the shell, with an embedded quote written
 * `'\''`, so a name cannot carry a command into the script. A name that holds a
 * newline cannot be quoted onto one line and is ::GARC_ERR_INVALID. Nothing here
 * judges whether a name is *safe to extract*: `../x` is written as asked, and the
 * script that creates it is the caller's to read before running.
 *
 * Times are not recorded: no portable shell command sets one.
 */

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/writer.h>
#include <stdio.h>
#include <string.h>

#include "../core/buffer_internal.h"
#include "shar_internal.h"

static GARC_Result put(GARC_Writer * writer, const char * text) {
  return garc_sink_write(writer->sink, text, strlen(text));
}

/** The single-quoted spelling of a name, written to the sink. */
static GARC_Result put_quoted(
    GARC_Writer * writer, const char * text, size_t length) {
  GARC_Result result = put(writer, "'");
  size_t start = 0;
  for (size_t i = 0; result == GARC_OK && i <= length; ++i) {
    if (i == length || text[i] == '\'') {
      if (i > start) {
        result = garc_sink_write(writer->sink, text + start, i - start);
      }
      if (result == GARC_OK && i < length) {
        result = put(writer, "'\\''");
      }
      start = i + 1u;
    }
  }
  if (result == GARC_OK) {
    result = put(writer, "'");
  }
  return result;
}

/** A command, a quoted name, and a newline. */
static GARC_Result put_line(GARC_Writer * writer, const char * command,
    const char * name, size_t name_length) {
  GARC_Result result = put(writer, command);
  if (result == GARC_OK) {
    result = put_quoted(writer, name, name_length);
  }
  if (result == GARC_OK) {
    result = put(writer, "\n");
  }
  return result;
}

static GARC_Result begin(GARC_Writer * writer) {
  if (writer->shar.started) {
    return GARC_OK;
  }
  writer->shar.started = 1;
  writer->shar.uu = writer->options.shar_uuencode;
  return put(writer,
      "#!/bin/sh\n"
      "# This is a shell archive, written by Ghoti.io Archive.\n"
      "# Read it before running it: it creates exactly the files it names.\n");
}

static GARC_Result put_chmod(GARC_Writer * writer, const GARC_Member * member) {
  if (!member->mode_valid) {
    return GARC_OK;
  }
  char text[32];
  snprintf(text, sizeof(text), "chmod %03o ", (unsigned)(member->mode & 07777u));
  return put_line(writer, text, member->name, member->name_length);
}

GARC_Result garc_shar_write_member(
    GARC_Writer * writer, const GARC_Member * member) {
  if (!member->name || !member->name_length
      || memchr(member->name, '\0', member->name_length)
      || memchr(member->name, '\n', member->name_length)) {
    return GARC_ERR_INVALID;
  }
  const char * link = NULL;
  switch (member->type) {
    case GARC_MEMBER_FILE:
      break;
    case GARC_MEMBER_DIRECTORY:
      if (member->size) {
        return GARC_ERR_INVALID;
      }
      break;
    case GARC_MEMBER_SYMLINK:
      if (!member->link_target || !member->link_target_length || member->size
          || memchr(member->link_target, '\0', member->link_target_length)
          || memchr(member->link_target, '\n', member->link_target_length)) {
        return GARC_ERR_INVALID;
      }
      link = member->link_target;
      break;
    default:
      return GARC_ERR_UNSUPPORTED;
  }

  GARC_Result result = begin(writer);
  if (result == GARC_OK) {
    result = put_line(writer, "echo x ", member->name, member->name_length);
  }
  if (result != GARC_OK) {
    return result;
  }

  writer->shar.written = 0;
  writer->shar.in_data = 0;
  writer->shar.at_line_start = 1;
  writer->shar.last_newline = 1;
  writer->shar.pending_length = 0;
  writer->data_remaining = member->size;
  writer->data_padding = 0;

  if (member->type == GARC_MEMBER_DIRECTORY) {
    result = put_line(writer, "mkdir -p ", member->name, member->name_length);
    return result == GARC_OK ? put_chmod(writer, member) : result;
  }
  if (link) {
    result = put(writer, "ln -fs ");
    if (result == GARC_OK) {
      result = put_quoted(writer, link, member->link_target_length);
    }
    if (result == GARC_OK) {
      result = put(writer, " ");
    }
    if (result == GARC_OK) {
      result = put_line(writer, "", member->name, member->name_length);
    }
    return result;
  }
  if (!member->size) {
    result = put_line(writer, ": > ", member->name, member->name_length);
    return result == GARC_OK ? put_chmod(writer, member) : result;
  }

  writer->shar.in_data = 1;
  writer->shar.chmod_valid = 0;
  if (!writer->shar.uu && member->mode_valid) {
    // sed leaves the file with the umask's mode, so the script must say it.
    result = garc_buffer_grow(
        writer->allocator, &writer->shar.name, member->name_length);
    if (result != GARC_OK) {
      return result;
    }
    memcpy(writer->shar.name.bytes, member->name, member->name_length);
    writer->shar.name.length = member->name_length;
    writer->shar.chmod_valid = 1;
    writer->shar.chmod_mode = member->mode & 07777u;
  }
  if (writer->shar.uu) {
    char text[48];
    snprintf(text, sizeof(text), "uudecode << 'SHAR_END'\nbegin %03o ",
        member->mode_valid ? (unsigned)(member->mode & 0777u) : 0644u);
    result = put(writer, text);
    if (result == GARC_OK) {
      result = garc_sink_write(writer->sink, member->name, member->name_length);
    }
    if (result == GARC_OK) {
      result = put(writer, "\n");
    }
    return result;
  }
  result = put(writer, "sed 's/^X//' > ");
  if (result == GARC_OK) {
    result = put_quoted(writer, member->name, member->name_length);
  }
  if (result == GARC_OK) {
    result = put(writer, " << 'SHAR_END'\n");
  }
  return result;
}

/** One uuencoded line of up to 45 bytes. */
static GARC_Result uu_line(GARC_Writer * writer, const uint8_t * bytes, size_t n) {
  char line[64];
  size_t at = 0;
  line[at++] = n ? (char)(32u + n) : '`';
  for (size_t i = 0; i < n; i += 3u) {
    const unsigned a = bytes[i];
    const unsigned b = i + 1u < n ? bytes[i + 1u] : 0u;
    const unsigned c = i + 2u < n ? bytes[i + 2u] : 0u;
    const unsigned v[4] = {a >> 2, ((a & 3u) << 4) | (b >> 4),
        ((b & 15u) << 2) | (c >> 6), c & 63u};
    for (unsigned k = 0; k < 4u; ++k) {
      line[at++] = v[k] ? (char)(32u + v[k]) : '`';
    }
  }
  line[at++] = '\n';
  return garc_sink_write(writer->sink, line, at);
}

GARC_Result garc_shar_write_data(
    GARC_Writer * writer, const void * data, size_t size) {
  GARC_Shar_Write_State * shar = &writer->shar;
  const uint8_t * bytes = (const uint8_t *)data;
  shar->written += size;
  if (shar->uu) {
    size_t at = 0;
    while (at < size) {
      const size_t room = 45u - shar->pending_length;
      const size_t take = size - at < room ? size - at : room;
      memcpy(shar->pending + shar->pending_length, bytes + at, take);
      shar->pending_length += take;
      at += take;
      if (shar->pending_length == 45u) {
        GARC_Result result = uu_line(writer, shar->pending, 45u);
        shar->pending_length = 0;
        if (result != GARC_OK) {
          return result;
        }
      }
    }
    return GARC_OK;
  }

  // Text: the data in lines, each behind an X. A run up to and including a
  // newline goes out in one write.
  size_t at = 0;
  while (at < size) {
    if (shar->at_line_start) {
      GARC_Result result = garc_sink_write(writer->sink, "X", 1u);
      if (result != GARC_OK) {
        return result;
      }
      shar->at_line_start = 0;
    }
    size_t end = at;
    while (end < size && bytes[end] != '\n') {
      if (bytes[end] == '\0') {
        return GARC_ERR_UNSUPPORTED;
      }
      ++end;
    }
    const int ends_line = end < size;
    if (ends_line) {
      ++end;
    }
    GARC_Result result = garc_sink_write(writer->sink, bytes + at, end - at);
    if (result != GARC_OK) {
      return result;
    }
    shar->last_newline = ends_line;
    shar->at_line_start = ends_line;
    at = end;
  }
  return GARC_OK;
}

GARC_Result garc_shar_write_close_member(GARC_Writer * writer) {
  GARC_Shar_Write_State * shar = &writer->shar;
  if (!shar->in_data) {
    return GARC_OK;
  }
  shar->in_data = 0;
  GARC_Result result = GARC_OK;
  if (shar->uu) {
    if (shar->pending_length) {
      result = uu_line(writer, shar->pending, shar->pending_length);
      shar->pending_length = 0;
    }
    if (result == GARC_OK) {
      result = put(writer, "`\nend\nSHAR_END\n");
    }
    return result;
  }
  if (!shar->last_newline) {
    // sed would add the newline the data lacks, and the file would be a byte
    // longer than the member said.
    return GARC_ERR_UNSUPPORTED;
  }
  result = put(writer, "SHAR_END\n");
  if (result == GARC_OK && shar->chmod_valid) {
    char text[32];
    snprintf(text, sizeof(text), "chmod %03o ", (unsigned)shar->chmod_mode);
    shar->chmod_valid = 0;
    result = put_line(writer, text, shar->name.bytes, shar->name.length);
  }
  return result;
}

GARC_Result garc_shar_write_end(GARC_Writer * writer) {
  GARC_Result result = begin(writer);
  return result == GARC_OK ? put(writer, "exit 0\n") : result;
}

void garc_shar_write_release(GARC_Writer * writer) {
  garc_buffer_free(writer->allocator, &writer->shar.name);
}
