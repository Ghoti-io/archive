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
 * Classifying a member name. What each finding means, and which of them has an
 * outside reference, is in name.h; this file is how each one is decided.
 *
 * Nothing here allocates, reads any state, or looks at a filesystem. That is
 * deliberate beyond tidiness: it makes every answer a function of the bytes
 * alone, so a test can put any byte string in and a fuzzer can put any byte
 * string in, and neither needs an archive.
 */

#include <ghoti.io/archive/macros.h>

#include <ghoti.io/archive/name.h>
#include <stdint.h>
#include <stddef.h>

/** Reserved device names on Windows, which are reserved in every directory. */
static const char * const name_windows_reserved[] = {
  "CON", "PRN", "AUX", "NUL",
  "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
  "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
};

/** ASCII upper-casing, with no locale in it. A Turkish `i` is not involved. */
static char name_upper(char byte) {
  return (byte >= 'a' && byte <= 'z') ? (char)(byte - 'a' + 'A') : byte;
}

/**
 * Whether a component is a reserved Windows device name.
 *
 * The comparison stops at the first `.`, because `aux.txt` is reserved too - the
 * reservation is on the *stem*, which is the part that gets missed by a check
 * comparing whole names. A trailing space is stripped for the same reason
 * Windows strips it.
 *
 * @param component The component's bytes.
 * @param length Its length.
 * @return Non-zero when Windows would resolve this to a device.
 */
static int name_is_windows_reserved(const char * component, size_t length) {
  size_t stem = 0;
  while (stem < length && component[stem] != '.') {
    stem++;
  }
  while (stem > 0 && component[stem - 1u] == ' ') {
    stem--;
  }
  if (!stem) {
    return 0;
  }
  for (size_t i = 0;
      i < sizeof(name_windows_reserved) / sizeof(name_windows_reserved[0]);
      ++i) {
    const char * reserved = name_windows_reserved[i];
    size_t j = 0;
    while (j < stem && reserved[j] != '\0'
        && name_upper(component[j]) == reserved[j]) {
      j++;
    }
    if (j == stem && reserved[j] == '\0') {
      return 1;
    }
  }
  return 0;
}

/**
 * Walk the components, reporting what they are and whether they leave the root.
 *
 * @param name The bytes.
 * @param length How many.
 * @param backslash_too Treat `\` as a separator as well as `/`, which is what
 *   Windows does and what decides ::GARC_NAME_WINDOWS_TRAVERSAL.
 * @param out_findings Receives the per-component findings. NULL to skip them,
 *   which is how the second walk asks only about the escape.
 * @return Non-zero when resolving the components leaves the root.
 */
static int name_walk(const char * name, size_t length, int backslash_too,
    uint32_t * out_findings) {
  // A single trailing separator is how every archive spells a directory, so it
  // is dropped before splitting rather than counted as an empty component. Only
  // one: `a//` really does have an empty component in it.
  if (length && (name[length - 1u] == '/'
          || (backslash_too && name[length - 1u] == '\\'))) {
    length--;
  }

  // A leading separator means the name is rooted, so its first component is
  // empty by construction and is not the empty component this reports.
  size_t start = 0;
  if (length && (name[0] == '/' || (backslash_too && name[0] == '\\'))) {
    start = 1;
  }

  // The running depth. `a/..` returns to zero without escaping; `..` at depth
  // zero has nowhere to go but out. A count of `..` components would call the
  // first of those an escape, which is where the two references disagree.
  size_t depth = 0;
  int escapes = 0;
  size_t at = start;

  while (at <= length) {
    size_t end = at;
    while (end < length && name[end] != '/'
        && !(backslash_too && name[end] == '\\')) {
      end++;
    }
    const char * component = name + at;
    const size_t span = end - at;

    if (!span) {
      if (out_findings) {
        *out_findings |= GARC_NAME_EMPTY_COMPONENT;
      }
    } else if (span == 1u && component[0] == '.') {
      if (out_findings) {
        *out_findings |= GARC_NAME_CURRENT_COMPONENT;
      }
    } else if (span == 2u && component[0] == '.' && component[1] == '.') {
      if (out_findings) {
        *out_findings |= GARC_NAME_PARENT_COMPONENT;
      }
      if (!depth) {
        escapes = 1;
      } else {
        depth--;
      }
    } else {
      depth++;
      if (out_findings) {
        if (name_is_windows_reserved(component, span)) {
          *out_findings |= GARC_NAME_WINDOWS_RESERVED;
        }
        // `.` and `..` end in a dot and are not this: they are components with a
        // meaning, and they are handled above. What this is for is `x.` and `x `,
        // which Windows silently turns into `x`.
        const char last = component[span - 1u];
        if (last == '.' || last == ' ') {
          *out_findings |= GARC_NAME_TRAILING_DOT_OR_SPACE;
        }
      }
    }

    if (end == length) {
      break;
    }
    at = end + 1u;
  }
  return escapes;
}

/**
 * Whether the bytes are well-formed UTF-8.
 *
 * Strict: the ranges below refuse an overlong form, a surrogate, and anything
 * above U+10FFFF, because those are exactly the shapes a lenient decoder turns
 * into a *different* string. `0xC0 0xAF` is an overlong `/`, and a decoder that
 * accepts it has produced a separator that was not in the name anyone checked.
 *
 * A NUL is well-formed UTF-8 and is not reported here; it has a finding of its
 * own, because what is wrong with it is not its encoding.
 *
 * @param name The bytes.
 * @param length How many.
 * @return Non-zero when every sequence is well-formed.
 */
static int name_is_utf8(const char * name, size_t length) {
  size_t at = 0;
  while (at < length) {
    const uint8_t lead = (uint8_t)name[at];
    size_t extra = 0;
    uint8_t low = 0x80u;
    uint8_t high = 0xBFu;

    if (lead < 0x80u) {
      at++;
      continue;
    }
    if (lead >= 0xC2u && lead <= 0xDFu) {
      extra = 1u;
    } else if (lead == 0xE0u) {
      extra = 2u;
      low = 0xA0u; // Below this is an overlong two-byte form.
    } else if (lead >= 0xE1u && lead <= 0xECu) {
      extra = 2u;
    } else if (lead == 0xEDu) {
      extra = 2u;
      high = 0x9Fu; // Above this is a surrogate, which UTF-8 cannot encode.
    } else if (lead >= 0xEEu && lead <= 0xEFu) {
      extra = 2u;
    } else if (lead == 0xF0u) {
      extra = 3u;
      low = 0x90u; // Below this is an overlong three-byte form.
    } else if (lead >= 0xF1u && lead <= 0xF3u) {
      extra = 3u;
    } else if (lead == 0xF4u) {
      extra = 3u;
      high = 0x8Fu; // Above this is past U+10FFFF.
    } else {
      // 0x80-0xBF is a continuation with nothing to continue; 0xC0 and 0xC1 lead
      // only overlong forms; 0xF5 and up are past the end of the encoding.
      return 0;
    }

    if (length - at <= extra) {
      return 0;
    }
    for (size_t i = 1; i <= extra; ++i) {
      const uint8_t byte = (uint8_t)name[at + i];
      const uint8_t floor_byte = (i == 1u) ? low : 0x80u;
      const uint8_t ceiling = (i == 1u) ? high : 0xBFu;
      if (byte < floor_byte || byte > ceiling) {
        return 0;
      }
    }
    at += extra + 1u;
  }
  return 1;
}

uint32_t garc_name_check(const char * name, size_t length) {
  if (!name || !length) {
    // A NULL pointer with a length is as nameless as a zero length: there is
    // nothing there to classify, and answering 0 would say it was fine.
    return GARC_NAME_EMPTY;
  }

  uint32_t findings = 0;

  for (size_t i = 0; i < length; ++i) {
    const uint8_t byte = (uint8_t)name[i];
    if (byte == 0u) {
      // Its own finding rather than a control byte, because what is wrong with a
      // NUL is not that it is unprintable: a caller reaching for the pointer and
      // not the length sees a shorter name than the archive holds.
      findings |= GARC_NAME_NUL_BYTE;
    } else if (byte < 0x20u || byte == 0x7Fu) {
      findings |= GARC_NAME_CONTROL_BYTE;
    }
    if (byte == (uint8_t)'\\') {
      findings |= GARC_NAME_BACKSLASH;
    }
  }

  if (!name_is_utf8(name, length)) {
    findings |= GARC_NAME_NOT_UTF8;
  }

  // Rooted, and the three ways a name can say so. A drive letter and a UNC
  // prefix are checked before the separator, because `C:/x` is absolute on
  // Windows without a leading separator and `//x` is two separators rather than
  // one.
  if (length >= 2u && name[1] == ':'
      && ((name[0] >= 'A' && name[0] <= 'Z')
          || (name[0] >= 'a' && name[0] <= 'z'))) {
    findings |= GARC_NAME_DRIVE_LETTER;
  }
  if (length >= 2u && (name[0] == '/' || name[0] == '\\')
      && (name[1] == '/' || name[1] == '\\')) {
    findings |= GARC_NAME_UNC;
  }
  if (name[0] == '/') {
    findings |= GARC_NAME_ABSOLUTE;
  }

  if (name_walk(name, length, 0, &findings)) {
    findings |= GARC_NAME_TRAVERSAL;
  } else if (findings & GARC_NAME_BACKSLASH) {
    // Asked only of a name that has a backslash in it, and only when the POSIX
    // reading does *not* escape. A name that escapes either way is already
    // reported as a traversal, and saying it twice would tell a caller nothing.
    if (name_walk(name, length, 1, NULL)) {
      findings |= GARC_NAME_WINDOWS_TRAVERSAL;
    }
  }

  return findings;
}

const char * garc_name_finding_string(GARC_Name_Finding finding) {
  switch (finding) {
    case GARC_NAME_ABSOLUTE:
      return "absolute path";
    case GARC_NAME_TRAVERSAL:
      return "resolves outside the root";
    case GARC_NAME_PARENT_COMPONENT:
      return "has a parent component";
    case GARC_NAME_CURRENT_COMPONENT:
      return "has a current-directory component";
    case GARC_NAME_EMPTY_COMPONENT:
      return "has an empty component";
    case GARC_NAME_EMPTY:
      return "empty name";
    case GARC_NAME_NUL_BYTE:
      return "contains a NUL byte";
    case GARC_NAME_CONTROL_BYTE:
      return "contains a control byte";
    case GARC_NAME_BACKSLASH:
      return "contains a backslash";
    case GARC_NAME_WINDOWS_TRAVERSAL:
      return "resolves outside the root where a backslash separates";
    case GARC_NAME_DRIVE_LETTER:
      return "begins with a drive letter";
    case GARC_NAME_UNC:
      return "begins with two separators";
    case GARC_NAME_WINDOWS_RESERVED:
      return "reserved device name on Windows";
    case GARC_NAME_TRAILING_DOT_OR_SPACE:
      return "a component ends in a dot or a space";
    case GARC_NAME_NOT_UTF8:
      return "not well-formed UTF-8";
    default:
      // Not an internal error: a caller passing a mask rather than one bit is
      // making a category mistake this can name, and picking the lowest set bit
      // would answer a question nobody asked.
      return "not a single finding";
  }
}

void garc_name_findings_dump(uint32_t findings, FILE * out) {
  if (!out) {
    return;
  }
  if (!findings) {
    fprintf(out, "name: no findings\n");
    return;
  }
  // Every bit, driven by the mask rather than by a literal bound, so that a
  // finding added to the enum and not to this loop is impossible rather than
  // merely unlikely.
  for (uint32_t bit = 1u; bit <= GARC_NAME_FINDING_ALL; bit <<= 1) {
    if (findings & bit) {
      fprintf(out, "name: %s\n",
          garc_name_finding_string((GARC_Name_Finding)bit));
    }
  }
  const uint32_t unknown = findings & ~GARC_NAME_FINDING_ALL;
  if (unknown) {
    // A bit this build does not know about, which means a caller passed a mask
    // from somewhere else. Reported rather than ignored.
    fprintf(out, "name: %u unrecognised finding bits\n", (unsigned)unknown);
  }
}
