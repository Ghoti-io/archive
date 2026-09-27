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
 * What is wrong with a member's name, named one finding at a time.
 *
 * **This is a classifier, not a permission.** ::garc_name_check() answers "what
 * is dangerous about these bytes"; it does not answer "is it safe to extract
 * this". Those are different questions and the second one cannot be answered
 * from a name at all:
 *
 *   - A member named `docs/readme` has no findings and escapes any root you like
 *     if an earlier member made `docs` a symlink to `/`. **Neither member is
 *     suspicious alone.** That is why extraction has to check the *resolved*
 *     path, as it resolves, with the links it has actually created - and why a
 *     check on the declared name is the bug rather than the fix.
 *   - Two names with no findings between them can still collide: `A.txt` and
 *     `a.txt` on a case-insensitive filesystem, or two spellings that normalise
 *     to one. A collision is a property of a *pair*, so no function taking one
 *     name can see it, and deciding it needs case-folding and normalisation
 *     tables this library deliberately does not carry - they are `unicode`'s.
 *
 * So what is this for? Three things. Refusing an archive early and cheaply,
 * before any of it is read. Telling a person *why* a listing looks wrong, which
 * is what the strings are for. And giving the filesystem layer a vocabulary it
 * can report in, rather than one boolean for every way a path can be hostile.
 *
 * **The findings are a bitmask because a name has as many problems as it has.**
 * `../../CON.` is a traversal *and* a Windows reserved name *and* a name Windows
 * will strip a dot from, and a function returning the first of those would make
 * the other two unreportable.
 *
 * ### Where the answers come from
 *
 * Every finding below is either checked against an outside reference or marked as
 * having none, because a safety predicate whose expectations were written by the
 * same session that wrote the predicate measures nothing. The references are
 * Python's `tarfile.data_filter` (PEP 706) and libarchive's `bsdtar -x`, both
 * pinned, and `tests/data/tar/verdicts.tsv` records what each one *does* with
 * every name in the corpus.
 *
 * They do not agree with each other, and the disagreement is why two of these
 * findings are separate bits rather than one:
 *
 * | name | `data_filter` | `bsdtar -x` |
 * | --- | --- | --- |
 * | `../../x` | refuses | refuses |
 * | `/tmp/x` | **rewrites** to `tmp/x` | **rewrites** |
 * | `a/..` | **accepts** | **refuses** |
 * | `C:\\x` | **accepts** | **rewrites**, dropping `C:` |
 * | `./x`, `a//b` | accepts | accepts |
 *
 * `a/..` has a parent component and resolves *inside* the root. Python resolves
 * and accepts it; libarchive refuses any `..` at all. A single safe/unsafe bit
 * would have to pick one of them, so ::GARC_NAME_PARENT_COMPONENT and
 * ::GARC_NAME_TRAVERSAL are separate: this library agrees with libarchive about
 * the first and with Python about the second, and a caller can hold either
 * policy.
 */

#ifndef GHOTI_IO_GARC_NAME_H
#define GHOTI_IO_GARC_NAME_H

#include <ghoti.io/archive/core.h>
#include <ghoti.io/archive/macros.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief One thing that is wrong with a name.
 *
 * A bitmask rather than an enumeration of states: see the file comment.
 */
typedef enum {
  /**
   * The name begins with `/`, so it names a place rather than a place *within*
   * something. Both references act on this and neither refuses it: they strip the
   * slash and carry on, which is worth knowing before writing a reader that
   * expects a refusal.
   */
  GARC_NAME_ABSOLUTE = 1u << 0,

  /**
   * Resolving the name's components leaves the root.
   *
   * A running depth, not a count: `a/..` ends where it started and does not
   * escape, while `a/b/../../../c` climbs one further than it descended and does.
   * This is the finding Python's `data_filter` refuses on, exactly.
   */
  GARC_NAME_TRAVERSAL = 1u << 1,

  /**
   * A `..` component is present, whether or not it escapes.
   *
   * Separate from ::GARC_NAME_TRAVERSAL because libarchive refuses on this and
   * Python does not - see the table in the file comment. A caller wanting
   * libarchive's policy asks for this bit; one wanting Python's asks for the
   * other.
   */
  GARC_NAME_PARENT_COMPONENT = 1u << 2,

  /**
   * A `.` component is present.
   *
   * Both references accept these, so this is hygiene rather than danger: it is
   * here because `./x` and `x` are the same file under two names, which matters
   * to anything keeping an index.
   */
  GARC_NAME_CURRENT_COMPONENT = 1u << 3,

  /**
   * Two separators in a row, or a trailing separator on a name that already
   * ended in one.
   *
   * A single trailing `/` is how every archive there is spells a directory and is
   * **not** a finding.
   */
  GARC_NAME_EMPTY_COMPONENT = 1u << 4,

  /** The name has no bytes at all. A member that is not called anything. */
  GARC_NAME_EMPTY = 1u << 5,

  /**
   * A NUL byte inside the name.
   *
   * The one finding that is about this library's callers rather than about a
   * filesystem: a C caller that reaches for the pointer and not the length sees a
   * *shorter name* than the archive holds, so the name it checks and the name it
   * uses can differ. No filesystem can store one either.
   */
  GARC_NAME_NUL_BYTE = 1u << 6,

  /**
   * A C0 control byte or DEL.
   *
   * A newline makes one member look like two in a listing; an ESC makes a
   * terminal print whatever the archive wants. Neither reference objects, because
   * neither is printing to your terminal.
   */
  GARC_NAME_CONTROL_BYTE = 1u << 7,

  /**
   * A backslash appears somewhere in the name.
   *
   * On Windows it is a separator, so this name has components that this library
   * cannot see - and ::GARC_NAME_WINDOWS_TRAVERSAL says whether they escape.
   * Reported separately because on a POSIX host a backslash is an ordinary
   * character in an ordinary filename, and both references treat it as one.
   */
  GARC_NAME_BACKSLASH = 1u << 8,

  /**
   * Resolving the name with `\\` *also* treated as a separator leaves the root,
   * where resolving it with `/` alone does not.
   *
   * `a\\..\\..\\b` is one component on POSIX and an escape on Windows. This is
   * **not** in ::GARC_NAME_ESCAPES, because putting it there would make this
   * library stricter than both references about names they are right to accept on
   * the host they run on. A caller extracting on Windows, or refusing to guess,
   * adds it.
   */
  GARC_NAME_WINDOWS_TRAVERSAL = 1u << 9,

  /**
   * The name begins with a drive letter, as in `C:\\x` or `C:x`.
   *
   * libarchive strips this even on POSIX; Python leaves it alone. So it has one
   * reference rather than none, and they disagree.
   */
  GARC_NAME_DRIVE_LETTER = 1u << 10,

  /**
   * The name begins with two separators, as in `\\\\server\\share\\x` or `//x`.
   *
   * A UNC path on Windows, and on POSIX a path whose leading `//` is
   * implementation-defined. Neither reference objects on a POSIX host.
   */
  GARC_NAME_UNC = 1u << 11,

  /**
   * A component is a reserved device name on Windows: `CON`, `PRN`, `AUX`,
   * `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9`.
   *
   * Matched without regard to case, and **with an extension too**: `aux.txt` is
   * reserved, which is the form that gets missed. No reference can answer this -
   * both of them run on POSIX, where these are ordinary names.
   */
  GARC_NAME_WINDOWS_RESERVED = 1u << 12,

  /**
   * A component ends in a dot or a space.
   *
   * Windows strips both, so `x.` and `x ` are two names for the file `x` - a
   * collision that only appears on extraction.
   */
  GARC_NAME_TRAILING_DOT_OR_SPACE = 1u << 13,

  /**
   * The bytes are not well-formed UTF-8.
   *
   * Overlong forms, surrogates and out-of-range values all count, because those
   * are the shapes a lenient decoder turns into something else - an overlong
   * `0xC0 0xAF` becomes `/` in a decoder that accepts it, which is a separator
   * that was not in the name this library checked.
   *
   * This is a fact about the *bytes* and is not ::GARC_Member.name_encoding,
   * which is what the container *claimed*. A container claiming UTF-8 over bytes
   * that are not is two facts in contradiction, and a caller comparing them is
   * the only thing that can see it.
   */
  GARC_NAME_NOT_UTF8 = 1u << 14,
} GARC_Name_Finding;

/**
 * @brief Every finding this library can report, for iterating the set.
 *
 * Spelled as a mask rather than a count because ::GARC_Name_Finding is a bitmask:
 * a sweep that walked `0` to some literal bound would silently stop covering a
 * finding added after it was written.
 */
#define GARC_NAME_FINDING_ALL ((uint32_t)0x7FFFu)

/**
 * @brief The findings that mean the name does not stay inside a root.
 *
 * This library's policy, and a starting point rather than an answer: see the file
 * comment for what passing it does *not* establish.
 *
 * ::GARC_NAME_WINDOWS_TRAVERSAL is deliberately absent - it is a hazard only
 * where `\\` separates, and including it would make this stricter than both
 * references about names they correctly accept.
 */
#define GARC_NAME_ESCAPES                                                      \
  ((uint32_t)(GARC_NAME_ABSOLUTE | GARC_NAME_TRAVERSAL                         \
      | GARC_NAME_DRIVE_LETTER | GARC_NAME_UNC))

/**
 * @brief The findings that are about where a name is used rather than where it
 *   points.
 *
 * A POSIX extractor may reasonably ignore all of these; one writing to a
 * Windows filesystem, or printing to a terminal, may not.
 */
#define GARC_NAME_PORTABILITY                                                  \
  ((uint32_t)(GARC_NAME_PARENT_COMPONENT | GARC_NAME_CURRENT_COMPONENT         \
      | GARC_NAME_EMPTY_COMPONENT | GARC_NAME_CONTROL_BYTE                     \
      | GARC_NAME_BACKSLASH | GARC_NAME_WINDOWS_TRAVERSAL                      \
      | GARC_NAME_WINDOWS_RESERVED | GARC_NAME_TRAILING_DOT_OR_SPACE           \
      | GARC_NAME_NOT_UTF8))

/**
 * @brief Classify a name, or a link target.
 *
 * Takes bytes and a length rather than a string, because that is what a member
 * name is: ::GARC_Member.name is not NUL-terminated and may contain any byte.
 * Pass `member->name` with `member->name_length`, or `member->link_target` with
 * `member->link_target_length` - **a symlink's target needs checking as much as
 * its name does**, and it is the same question about different bytes.
 *
 * A pure function of the bytes. It reads no state, allocates nothing, and can be
 * called on a name from anywhere, which is what makes it testable without an
 * archive.
 *
 * @param name The bytes. NULL with a non-zero @p length returns
 *   ::GARC_NAME_EMPTY, since there is no name there either.
 * @param length How many bytes.
 * @return A bitmask of ::GARC_Name_Finding, or 0 when nothing is wrong. Zero is
 *   not a promise; see the file comment.
 */
GARC_API uint32_t garc_name_check(const char * name, size_t length);

/**
 * @brief Name for one finding, for messages and dumps.
 *
 * @param finding A single finding. A mask with more than one bit set, or none,
 *   returns a string saying so rather than picking one.
 * @return A static string, never NULL.
 */
GARC_API const char * garc_name_finding_string(GARC_Name_Finding finding);

/**
 * @brief Write every finding in a mask, one per line.
 *
 * @param findings A mask as ::garc_name_check() returned it.
 * @param out Destination. NULL is ignored.
 */
GARC_API void garc_name_findings_dump(uint32_t findings, FILE * out);

#ifdef __cplusplus
}
#endif

#endif // GHOTI_IO_GARC_NAME_H
