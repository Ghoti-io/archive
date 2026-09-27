/**
 * @file
 *
 * Classifying member names, against what two extractors actually do.
 *
 * **The point of this file is that its expectations are not its own.** A safety
 * predicate whose test table was written by whoever wrote the predicate measures
 * the author twice. So the load-bearing tests here walk
 * `tests/data/tar/verdicts.tsv` - what Python's `tarfile.data_filter` and
 * libarchive's `bsdtar -x` did with every name in the corpus, recorded in the
 * pinned container - and assert a two-sided relation against each of them.
 *
 * The two references **disagree with each other**, which is why there are two
 * relations and two masks rather than one:
 *
 *   - Python resolves `a/..` and accepts it; libarchive refuses any `..`.
 *   - libarchive strips a drive letter from `C:\x`; Python leaves it alone.
 *
 * Each reference therefore gets the mask it actually answers for, and the masks
 * differ. Writing one mask and one relation would have meant picking a reference
 * and calling the other one wrong.
 *
 * The hand-built cases below are the complement: bytes no writer can put in a
 * name (a NUL, an empty name), and boundaries the corpus does not happen to hit.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstdint>
#include <set>
#include <utility>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "tar_manifest.h"
#include "test_helpers.h"

using garctest::VerdictRow;
using garctest::names_load;
using garctest::verdicts_load;

namespace {

std::string data_path(const std::string & name) {
  return std::string(GARC_TEST_DATA) + "/tar/" + name;
}

const std::vector<VerdictRow> & verdicts() {
  static const std::vector<VerdictRow> rows
      = verdicts_load(data_path("verdicts.tsv"));
  return rows;
}

/**
 * Link targets by (archive, member index), from the metadata manifest.
 *
 * **The verdict and the target come from different files on purpose.**
 * `verdicts.tsv` says what a reference would *do* with a member; `manifest.tsv`
 * says what the bytes of its link target are. Copying the target into the verdict
 * file would be the same fact in two places, which is the shape that drifts.
 */
const std::map<std::pair<std::string, size_t>, std::string> & link_targets() {
  static const std::map<std::pair<std::string, size_t>, std::string> targets = [] {
    std::map<std::pair<std::string, size_t>, std::string> built;
    for (const auto & entry : garctest::manifest_load(data_path("manifest.tsv"))) {
      for (const garctest::ManifestRow & row : entry.second) {
        built[{row.archive, row.index}] = row.link;
      }
    }
    return built;
  }();
  return targets;
}

/** Which part of a member the reference objected to. */
enum class Axis { None, Name, Link, Type };

/**
 * Map one of `tarfile`'s exception names onto the part of the member it is about.
 *
 * Read off the reference's own vocabulary rather than guessed: PEP 706 names an
 * exception per problem, and the names say which field each one is about. This is
 * what restricts the relation at both ends - the verdict is about a *member*, and
 * garc_name_check() is about *bytes*, so relating them without saying which bytes
 * would score a link-target refusal against the member's name.
 */
Axis axis_of(const std::string & verdict) {
  if (verdict == "same") {
    return Axis::None;
  }
  // A rewrite is always a rewrite of the name: data_filter strips a leading '/'
  // and changes nothing else that this library has an opinion about.
  if (verdict == "rewrite" || verdict == "AbsolutePathError"
      || verdict == "OutsideDestinationError") {
    return Axis::Name;
  }
  if (verdict == "AbsoluteLinkError" || verdict == "LinkOutsideDestinationError") {
    return Axis::Link;
  }
  if (verdict == "SpecialFileError") {
    return Axis::Type;
  }
  return Axis::Type; // Anything new is not a name or a link until read.
}

/** Shorthand so a test reads as a claim about a name rather than about a call. */
uint32_t check(const std::string & name) {
  return garc_name_check(name.data(), name.size());
}

/**
 * The findings Python's `data_filter` is answering about.
 *
 * It refuses a name that resolves out of the root and *rewrites* an absolute one,
 * so both count as "it would not leave this alone". It says nothing about a drive
 * letter, a UNC prefix, or a `..` that does not escape - so none of those is in
 * here, and a test that put them in would be asserting that Python agrees with a
 * policy it does not have.
 */
constexpr uint32_t kPythonAnswers = GARC_NAME_TRAVERSAL | GARC_NAME_ABSOLUTE;

/**
 * The findings libarchive's extractor is answering about.
 *
 * It refuses any member whose name has a `..` component in it, escaping or not,
 * and it rewrites an absolute name and a drive letter. It does *not* object to a
 * UNC prefix on a POSIX host - it wrote `server\share\ghoti` as one filename - so
 * GARC_NAME_UNC is absent here too.
 */
constexpr uint32_t kLibarchiveAnswers = GARC_NAME_TRAVERSAL
    | GARC_NAME_PARENT_COMPONENT | GARC_NAME_ABSOLUTE | GARC_NAME_DRIVE_LETTER;

} // namespace

//-----------------------------------------------------------------------------
// The reference cross-check
//-----------------------------------------------------------------------------

TEST(NameOracle, AgreesWithPythonsDataFilterInBothDirections) {
  // The relation, stated so that each direction can fail on its own:
  //
  //   we report an escape Python answers for  =>  Python did not leave it alone
  //   Python left the name alone              =>  we report none of those
  //
  // One direction alone is satisfiable by a checker that reports nothing, or by
  // one that reports everything. Both together are not.
  const auto & rows = verdicts();
  ASSERT_FALSE(rows.empty()) << "tests/data/tar/verdicts.tsv is missing";

  size_t on_the_name = 0;
  size_t on_the_link = 0;
  size_t on_the_type = 0;
  size_t left_alone = 0;
  for (const VerdictRow & row : rows) {
    SCOPED_TRACE(row.archive + " member " + std::to_string(row.index) + " "
        + row.name + " [" + row.python_data + "]");
    const auto found = link_targets().find({row.archive, row.index});
    const std::string target
        = (found == link_targets().end()) ? std::string() : found->second;

    const uint32_t name_findings = check(row.name) & kPythonAnswers;
    const uint32_t link_findings
        = target.empty() ? 0u : (check(target) & kPythonAnswers);

    switch (axis_of(row.python_data)) {
      case Axis::Name:
        ++on_the_name;
        EXPECT_NE(name_findings, 0u)
            << "the reference " << row.python_data
            << " over this member's NAME and we report nothing about it";
        break;
      case Axis::Link:
        ++on_the_link;
        ASSERT_FALSE(target.empty())
            << "the reference objected to a link target and the manifest has "
               "none for this member, so the two files have come apart";
        EXPECT_NE(link_findings, 0u)
            << "the reference " << row.python_data
            << " over this member's TARGET (" << target
            << ") and we report nothing about it";
        break;
      case Axis::Type:
        // Nothing in the corpus is a device or a fifo, so this arm is not
        // exercised - and the count below is what says so, rather than the arm
        // silently absorbing a member the relation does not cover.
        ++on_the_type;
        break;
      case Axis::None:
        ++left_alone;
        EXPECT_EQ(name_findings, 0u)
            << "the reference left this member alone and we call its name an "
               "escape";
        EXPECT_EQ(link_findings, 0u)
            << "the reference left this member alone and we call its target ("
            << target << ") an escape";
        break;
    }
  }
  EXPECT_GT(on_the_name, 4u)
      << "almost no name made the reference act, so that direction of this "
         "relation is asserting nothing";
  EXPECT_GT(on_the_link, 1u)
      << "no link target made the reference act, so the target half of this "
         "relation is asserting nothing";
  EXPECT_GT(left_alone, 50u)
      << "almost nothing was left alone, so the reverse direction is asserting "
         "nothing";
  EXPECT_EQ(on_the_type, 0u)
      << "the corpus has grown a member the reference objects to for a reason "
         "that is neither its name nor its target - extend the relation rather "
         "than letting this arm absorb it";
}

TEST(NameOracle, AgreesWithLibarchivesExtractorOnItsOwnPolicy) {
  // The same shape against a different policy, and the *reason* there are two:
  // libarchive refuses `a/..` where Python accepts it. A single mask would make
  // one of these tests fail however it was drawn.
  const auto & rows = verdicts();
  ASSERT_FALSE(rows.empty());

  size_t refused = 0;
  for (const VerdictRow & row : rows) {
    SCOPED_TRACE(row.archive + " member " + std::to_string(row.index) + " "
        + row.name);
    const uint32_t findings = check(row.name) & kLibarchiveAnswers;
    if (row.libarchive_refused()) {
      ++refused;
      EXPECT_NE(findings, 0u)
          << "libarchive refused this member and we report nothing about it";
    }
  }
  EXPECT_GT(refused, 4u)
      << "libarchive refused almost nothing, so this asserts nothing";
}

TEST(NameOracle, TheTwoReferencesDisagreeAndBothAreAnswered) {
  // The disagreement, asserted rather than described. If a reference release
  // changes its mind about `a/..` this fails here, in a test whose name says what
  // it is about - rather than in whichever of the two relations above happens to
  // break first.
  const auto & rows = verdicts();
  bool seen = false;
  for (const VerdictRow & row : rows) {
    if (row.name != "a/..") {
      continue;
    }
    seen = true;
    EXPECT_FALSE(row.python_acts())
        << "Python used to resolve this and accept it";
    EXPECT_TRUE(row.libarchive_refused())
        << "libarchive used to refuse any '..' at all";

    const uint32_t findings = check(row.name);
    // Ours answers both: the parent component libarchive objects to, and no
    // traversal, because it resolves back to where it started.
    EXPECT_TRUE(findings & GARC_NAME_PARENT_COMPONENT);
    EXPECT_FALSE(findings & GARC_NAME_TRAVERSAL);
  }
  EXPECT_TRUE(seen)
      << "the corpus no longer contains `a/..`, which is the one name that "
         "separates the two references' policies";
}

TEST(NameOracle, TheDriveLetterHasOneReferenceAndTheyDisagree) {
  // The mirror of the case above: libarchive acts on a drive letter and Python
  // does not. Asserted because it is the whole justification for
  // GARC_NAME_DRIVE_LETTER being in GARC_NAME_ESCAPES while
  // GARC_NAME_WINDOWS_TRAVERSAL is not.
  const auto & rows = verdicts();
  bool seen = false;
  for (const VerdictRow & row : rows) {
    if (row.name != "C:\\Windows\\ghoti") {
      continue;
    }
    seen = true;
    EXPECT_FALSE(row.python_acts()) << "Python used to accept a drive letter";
    // libarchive rewrote rather than refused, so it is not in the refused column;
    // the evidence is the tree it created, which is a comment in verdicts.tsv.
    EXPECT_FALSE(row.libarchive_refused());
    EXPECT_TRUE(check(row.name) & GARC_NAME_DRIVE_LETTER);
  }
  EXPECT_TRUE(seen) << "the corpus no longer contains a drive-letter name";
}

TEST(NameOracle, EveryOrdinaryNameInTheCorpusIsClean) {
  // The control: a checker that flagged every name would pass the first direction
  // of both relations above, and only something like this can tell.
  //
  // **These are tarfile's names, which means directory names arrive without their
  // trailing slash** - that is the one thing tarfile normalises, and it is why
  // bsdtar is the names reference elsewhere. So this test does *not* cover
  // `sizes/`; the equivalent walk over the reader's own bytes, in test_tar.cpp's
  // TarCorpus.EveryOrdinaryNameTheReaderReportsIsClean, is what does. Said here
  // because a reader could otherwise take this for the whole control - and a
  // mutation that made a trailing slash an empty component was caught only by the
  // hand-written test, which is how the gap was found.
  const auto & rows = verdicts();
  ASSERT_FALSE(rows.empty());

  size_t ordinary = 0;
  for (const VerdictRow & row : rows) {
    if (row.archive.compare(0, 4, "mal-") == 0) {
      continue;
    }
    SCOPED_TRACE(row.archive + " " + row.name);
    ++ordinary;
    const uint32_t findings = check(row.name);
    EXPECT_EQ(findings, 0u) << "an ordinary name reported findings";
    // And the reference agrees it is ordinary, which is what makes this a control
    // rather than a restatement of what this library thinks.
    EXPECT_FALSE(row.python_acts());
    EXPECT_FALSE(row.libarchive_refused());
  }
  EXPECT_GT(ordinary, 50u)
      << "too few ordinary names to be a control over the reader's whole corpus";
}

TEST(NameOracle, EveryMaliciousFixtureHasSomethingToSayAboutIt) {
  // A guard on the instrument. If the malicious fixtures were regenerated into
  // something harmless - which happened once already, when two names meant to
  // hold raw bytes were encoded into valid UTF-8 on the way to tar - every test
  // above would still pass by checking nothing.
  const auto & rows = verdicts();
  std::map<std::string, size_t> clean;
  std::map<std::string, size_t> total;
  for (const VerdictRow & row : rows) {
    if (row.archive.compare(0, 4, "mal-") != 0) {
      continue;
    }
    total[row.archive]++;
    if (!check(row.name)) {
      clean[row.archive]++;
    }
  }
  ASSERT_FALSE(total.empty()) << "there are no malicious fixtures";
  for (const auto & entry : total) {
    SCOPED_TRACE(entry.first);
    // mal-collisions.tar is the deliberate exception: a collision is a property
    // of a *pair* of names, so every name in it is individually clean and has to
    // be. It is in the corpus for phase F, not for this check.
    // Two fixtures are deliberate exceptions, and for different reasons.
    //
    // mal-collisions.tar: a collision is a property of a *pair* of names, so
    // every name in it is individually clean and has to be.
    //
    // mal-links.tar: the hostile part is each member's link *target*, not its
    // name - `abs-target` is an ordinary name pointing somewhere it should not.
    // That distinction is the one that made the reference relation above wrong on
    // its first run: Python raised AbsoluteLinkError for a member whose name is
    // fine, and a relation stated over names scored it against the name.
    if (entry.first == "mal-collisions.tar" || entry.first == "mal-links.tar") {
      EXPECT_EQ(clean[entry.first], entry.second)
          << "the names in this fixture are meant to be individually clean; it "
             "is the pairs, or the targets, that are hostile";
      continue;
    }
    EXPECT_LT(clean[entry.first], entry.second)
        << "every name in this hostile fixture came back clean, so the fixture "
           "is no longer hostile";
  }
}

TEST(NameOracle, ACollisionIsInvisibleToAPerNameCheck) {
  // Said out loud rather than left implied, because the corpus contains the pairs
  // and a reader could otherwise assume they are covered. `A.txt` and `a.txt`
  // collide on a case-insensitive filesystem; `café` spelled composed and
  // decomposed collide after normalisation. Both pairs are clean name by name,
  // and no function taking one name can be otherwise.
  //
  // **If this test ever starts failing, it is because someone taught the checker
  // to fold case or normalise** - which needs tables this library does not carry.
  // The right response is to move the claim, not to relax the test.
  const auto & rows = verdicts();
  size_t pairs = 0;
  for (const VerdictRow & row : rows) {
    if (row.archive != "mal-collisions.tar") {
      continue;
    }
    ++pairs;
    SCOPED_TRACE(row.name);
    EXPECT_EQ(check(row.name), 0u);
  }
  EXPECT_EQ(pairs, 4u) << "the collision fixture no longer has two pairs in it";
}

TEST(NameOracle, ALinkTargetIsCheckedTheSameWay) {
  // The other half of the problem, and the reason garc_name_check() takes bytes
  // rather than a member: a symlink's *target* is as dangerous as its name, and
  // it is the same question about different bytes.
  //
  // The targets come from names.tsv rather than being written here, so they are
  // the bytes GNU tar put in the linkname field.
  const auto & rows = names_load(data_path("names.tsv"));
  ASSERT_NE(rows.find("mal-links.tar"), rows.end())
      << "the hostile-link fixture is missing";

  // The names in that fixture are ordinary; it is the targets that are not, and
  // the targets are read from the archive by the test below in test_tar.cpp.
  // What this asserts is the classification of the target *strings*.
  const uint32_t absolute = garc_name_check("/tmp/ghoti-escaped", 18);
  EXPECT_TRUE(absolute & GARC_NAME_ABSOLUTE);
  const uint32_t up = garc_name_check("../../..", 8);
  EXPECT_TRUE(up & GARC_NAME_TRAVERSAL);
  const uint32_t fine = garc_name_check("./sibling", 9);
  EXPECT_FALSE(fine & GARC_NAME_ESCAPES);
  EXPECT_TRUE(fine & GARC_NAME_CURRENT_COMPONENT);
}

//-----------------------------------------------------------------------------
// Boundaries the corpus does not reach
//-----------------------------------------------------------------------------

TEST(NameCheck, DepthIsARunningCountRatherThanATallyOfParents) {
  // The arithmetic that makes `a/..` different from `..`, from both sides and at
  // the boundary. A checker counting `..` components calls the first three of
  // these an escape; one that only looks at the first component misses the last
  // two.
  struct Row { const char * name; bool escapes; };
  const std::vector<Row> rows = {
    {"a/..", false},
    {"a/b/../..", false},
    {"a/b/../../..", true},
    {"..", true},
    {"../a", true},
    {"a/../b/../c", false},
    {"a/../../b", true},
    {"./a/..", false},
    {"a/./../b", false},
  };
  for (const Row & row : rows) {
    SCOPED_TRACE(row.name);
    const uint32_t findings = check(row.name);
    EXPECT_EQ((findings & GARC_NAME_TRAVERSAL) != 0u, row.escapes);
    // Every one of them has a parent component, which is the bit libarchive
    // objects to - so this also shows the two bits moving independently.
    EXPECT_TRUE(findings & GARC_NAME_PARENT_COMPONENT);
  }
}

TEST(NameCheck, ATrailingSlashIsADirectoryAndNotAnEmptyComponent) {
  // Every directory member in every archive ends in a slash, so flagging one
  // would put a finding on a large fraction of every real archive - and a
  // checker whose findings are that common is one a caller learns to ignore.
  EXPECT_EQ(check("dir/"), 0u);
  EXPECT_EQ(check("a/b/"), 0u);
  // Two is not one. `a//` has a component with nothing in it.
  EXPECT_TRUE(check("a//") & GARC_NAME_EMPTY_COMPONENT);
  EXPECT_TRUE(check("a//b") & GARC_NAME_EMPTY_COMPONENT);
}

TEST(NameCheck, AnEmptyNameIsItsOwnFinding) {
  EXPECT_EQ(check(""), (uint32_t)GARC_NAME_EMPTY);
  // A NULL pointer is as nameless as a zero length, and answering 0 for it would
  // call a missing name safe.
  EXPECT_EQ(garc_name_check(nullptr, 0), (uint32_t)GARC_NAME_EMPTY);
  EXPECT_EQ(garc_name_check(nullptr, 10), (uint32_t)GARC_NAME_EMPTY);
}

TEST(NameCheck, ANulByteIsNotMerelyAControlByte) {
  // The finding that is about this library's callers: a C caller reaching for the
  // pointer and not the length sees `safe`, where the archive says
  // `safe\0../../etc`. The name that gets checked and the name that gets used are
  // then different strings, which is the whole failure.
  // Three parent components, not two: the first component is `safe\0..`, which
  // *descends* - so `safe\0../../etc` resolves back to `etc` and does not escape.
  // Getting that wrong here was worth keeping, because it is the same arithmetic
  // the `a/..` case turns on and a test asserting the wrong answer would have
  // been evidence for the wrong rule.
  const std::string hostile = std::string("safe") + '\0' + "../../../etc";
  const uint32_t findings = garc_name_check(hostile.data(), hostile.size());
  EXPECT_TRUE(findings & GARC_NAME_NUL_BYTE);
  // And the rest of the bytes are classified too, rather than the scan stopping
  // at the NUL the way a string function would.
  EXPECT_TRUE(findings & GARC_NAME_TRAVERSAL);
  // Which is the whole point: a caller that reached for the pointer and not the
  // length would check `safe`, and `safe` has nothing wrong with it at all.
  EXPECT_EQ(check("safe"), 0u);
  // Not also reported as a control byte: one finding per fact.
  EXPECT_FALSE(findings & GARC_NAME_CONTROL_BYTE);
  // Whereas an ordinary control byte is.
  const std::string tab = std::string("a\tb");
  EXPECT_TRUE(garc_name_check(tab.data(), tab.size()) & GARC_NAME_CONTROL_BYTE);
  EXPECT_FALSE(garc_name_check(tab.data(), tab.size()) & GARC_NAME_NUL_BYTE);
}

TEST(NameCheck, WindowsReservedNamesAreMatchedOnTheStem) {
  // `aux.txt` is reserved and `auxiliary.txt` is not, which is the pair that
  // separates a stem comparison from a prefix one. Case is ignored, and a
  // trailing space is stripped the way Windows strips it.
  const std::vector<const char *> reserved = {
    "CON", "con", "Con", "NUL", "PRN", "AUX", "aux.txt", "COM1", "com9.dat",
    "LPT1", "lpt9", "CON ", "dir/CON", "dir/aux.txt",
    // The stem is what is reserved, so a second extension changes nothing:
    // `nul.txt.gz` is the NUL device with two extensions after it. This was in
    // the ordinary list on the first run, and the library was right.
    "nul.txt.gz",
  };
  for (const char * name : reserved) {
    SCOPED_TRACE(name);
    EXPECT_TRUE(check(name) & GARC_NAME_WINDOWS_RESERVED);
  }
  const std::vector<const char *> ordinary = {
    "CONS", "console.txt", "auxiliary.txt", "COM", "COM0", "COM10", "LPT",
    "NULL", "acon", "prnt",
    // A component whose stem is empty once the dot is reached: there is no name
    // before the extension, so there is nothing that could be a device. `.` and
    // `..` never get here - they are components with a meaning and are handled
    // before the device table - so a dotfile is the only way in.
    ".bashrc", ".config/x",
    // And a component that is nothing but spaces, which strips to empty the same
    // way.
    "   ", "a/   /b",
  };
  for (const char * name : ordinary) {
    SCOPED_TRACE(name);
    EXPECT_FALSE(check(name) & GARC_NAME_WINDOWS_RESERVED);
  }
}

TEST(NameCheck, ATrailingDotOrSpaceIsFlaggedButNotOnDotComponents) {
  EXPECT_TRUE(check("file.") & GARC_NAME_TRAILING_DOT_OR_SPACE);
  EXPECT_TRUE(check("file ") & GARC_NAME_TRAILING_DOT_OR_SPACE);
  EXPECT_TRUE(check("dir./file") & GARC_NAME_TRAILING_DOT_OR_SPACE);
  // `.` and `..` end in a dot and are components with a meaning, not names
  // Windows would strip a dot from. Flagging them would put this finding on
  // every name that has a `..` in it and tell a caller nothing.
  EXPECT_FALSE(check(".") & GARC_NAME_TRAILING_DOT_OR_SPACE);
  EXPECT_FALSE(check("..") & GARC_NAME_TRAILING_DOT_OR_SPACE);
  EXPECT_FALSE(check("a/../b") & GARC_NAME_TRAILING_DOT_OR_SPACE);
  EXPECT_FALSE(check("file.txt") & GARC_NAME_TRAILING_DOT_OR_SPACE);
}

TEST(NameCheck, TheRootedFormsAreToldApart) {
  // Three different ways a name can refer to a place rather than to a place
  // within something, and they are not the same finding because they are not the
  // same hazard and the references do not treat them alike.
  EXPECT_EQ(check("/etc/x") & GARC_NAME_ESCAPES, (uint32_t)GARC_NAME_ABSOLUTE);

  const uint32_t drive = check("C:\\x");
  EXPECT_TRUE(drive & GARC_NAME_DRIVE_LETTER);
  EXPECT_FALSE(drive & GARC_NAME_ABSOLUTE);
  // `C:x` is drive-relative on Windows and has no separator at all.
  EXPECT_TRUE(check("C:x") & GARC_NAME_DRIVE_LETTER);
  // A colon that is not a drive letter is not one.
  EXPECT_FALSE(check("ab:x") & GARC_NAME_DRIVE_LETTER);
  EXPECT_FALSE(check("1:x") & GARC_NAME_DRIVE_LETTER);

  const uint32_t unc = check("\\\\server\\share");
  EXPECT_TRUE(unc & GARC_NAME_UNC);
  // `//x` is two separators as well, and is absolute into the bargain.
  const uint32_t slashes = check("//x");
  EXPECT_TRUE(slashes & GARC_NAME_UNC);
  EXPECT_TRUE(slashes & GARC_NAME_ABSOLUTE);
  // One separator is not two.
  EXPECT_FALSE(check("/x") & GARC_NAME_UNC);
}

TEST(NameCheck, BackslashTraversalIsSeparateFromTheRealThing) {
  // `a\..\..\b` is one component on POSIX and an escape on Windows. Reporting it
  // as GARC_NAME_TRAVERSAL would make this library stricter than *both*
  // references about a name they are right to accept on the host they run on -
  // and the cross-check above would fail on it. So it has a finding of its own,
  // and that finding is not in GARC_NAME_ESCAPES.
  const uint32_t mixed = check("a\\..\\..\\b");
  EXPECT_TRUE(mixed & GARC_NAME_BACKSLASH);
  EXPECT_TRUE(mixed & GARC_NAME_WINDOWS_TRAVERSAL);
  EXPECT_FALSE(mixed & GARC_NAME_TRAVERSAL);
  EXPECT_EQ(mixed & GARC_NAME_ESCAPES, 0u);
  EXPECT_NE(mixed & GARC_NAME_PORTABILITY, 0u);

  // A backslash that goes nowhere is only a backslash.
  const uint32_t plain = check("a\\b");
  EXPECT_TRUE(plain & GARC_NAME_BACKSLASH);
  EXPECT_FALSE(plain & GARC_NAME_WINDOWS_TRAVERSAL);

  // And a name that escapes under *either* reading is reported once, as the real
  // thing, rather than twice.
  const uint32_t both = check("../a\\..\\..\\b");
  EXPECT_TRUE(both & GARC_NAME_TRAVERSAL);
  EXPECT_FALSE(both & GARC_NAME_WINDOWS_TRAVERSAL);
}

TEST(NameCheck, Utf8IsValidatedStrictly) {
  // The shapes a lenient decoder turns into a *different* string, which is the
  // reason to care: an overlong 0xC0 0xAF becomes `/` in a decoder that accepts
  // it, and that is a separator nobody checked for.
  struct Row { std::string bytes; bool valid; const char * why; };
  const std::vector<Row> rows = {
    // One row per arm of the lead-byte table, so that every arm is exercised by
    // something rather than by whichever example happened to be picked. A range
    // in a table is the shape where one value gets tested and the rest are
    // assumed.
    {"plain.txt", true, "ASCII, the one-byte arm"},
    {std::string("na\xC3\xAFve"), true, "0xC2-0xDF: two bytes, U+00EF"},
    {std::string("\xE0\xA0\x80"), true, "0xE0: three bytes at its floor, U+0800"},
    {std::string("\xE2\x82\xAC"), true, "0xE1-0xEC: three bytes, U+20AC"},
    {std::string("\xED\x9F\xBF"), true, "0xED: three bytes below the surrogates"},
    {std::string("\xEF\xBF\xBD"), true, "0xEE-0xEF: three bytes, U+FFFD"},
    {std::string("\xF0\x9F\x90\x9F"), true, "0xF0: four bytes, U+1F41F"},
    {std::string("\xF1\x80\x80\x80"), true, "0xF1-0xF3: four bytes, U+40000"},
    {std::string("\xF4\x8F\xBF\xBF"), true, "0xF4: four bytes at U+10FFFF"},
    {std::string("\x80"), false, "a continuation with nothing to continue"},
    {std::string("\xC0\xAF"), false, "an overlong '/'"},
    {std::string("\xC1\xBF"), false, "an overlong 0x7F"},
    {std::string("\xE0\x80\xAF"), false, "a three-byte overlong"},
    {std::string("\xF0\x80\x80\xAF"), false, "a four-byte overlong"},
    {std::string("\xED\xA0\x80"), false, "a surrogate, U+D800"},
    {std::string("\xF4\x90\x80\x80"), false, "past U+10FFFF"},
    {std::string("\xF5\x80\x80\x80"), false, "a lead byte past the encoding"},
    {std::string("\xC3"), false, "truncated: a lead byte at the end"},
    {std::string("\xE2\x82"), false, "truncated: two of three"},
    {std::string("\xC3\x28"), false, "a lead byte followed by a non-continuation"},
    // A NUL is well-formed UTF-8 and is reported by a different finding, which is
    // what keeps "what the bytes are" apart from "what they will do to a caller".
    {std::string("a\0b", 3), true, "a NUL is well-formed"},
  };
  for (const Row & row : rows) {
    SCOPED_TRACE(row.why);
    const uint32_t findings
        = garc_name_check(row.bytes.data(), row.bytes.size());
    EXPECT_EQ((findings & GARC_NAME_NOT_UTF8) == 0u, row.valid);
  }
}

TEST(NameCheck, FindingsAccumulateRatherThanRacing) {
  // A name has as many problems as it has, and a function returning the first
  // would make the rest unreportable. `../CON.` is four of them at once.
  const uint32_t findings = check("../CON.");
  EXPECT_TRUE(findings & GARC_NAME_TRAVERSAL);
  EXPECT_TRUE(findings & GARC_NAME_PARENT_COMPONENT);
  EXPECT_TRUE(findings & GARC_NAME_WINDOWS_RESERVED);
  EXPECT_TRUE(findings & GARC_NAME_TRAILING_DOT_OR_SPACE);
}

TEST(NameCheck, TheMasksPartitionTheFindingsWithNothingLeftOver) {
  // Every finding is in exactly one of the two published masks, and the union is
  // every finding there is. A finding added to the enum and to neither mask would
  // be invisible to a caller using them, which is how a new hazard gets shipped
  // switched off.
  EXPECT_EQ(GARC_NAME_ESCAPES & GARC_NAME_PORTABILITY, 0u)
      << "a finding is in both masks";
  const uint32_t together = GARC_NAME_ESCAPES | GARC_NAME_PORTABILITY;
  // GARC_NAME_EMPTY and GARC_NAME_NUL_BYTE are deliberately in neither: an empty
  // or NUL-bearing name is not a path question at all, it is a name that cannot
  // be used, and a caller must refuse it whatever its extraction policy is.
  const uint32_t unclassified = GARC_NAME_FINDING_ALL & ~together;
  EXPECT_EQ(unclassified,
      (uint32_t)(GARC_NAME_EMPTY | GARC_NAME_NUL_BYTE))
      << "a finding belongs to neither mask and is not one of the two that "
         "deliberately do not";
}

//-----------------------------------------------------------------------------
// Strings and dumps
//-----------------------------------------------------------------------------

TEST(NameStrings, EveryFindingHasAStringAndNoneShareOne) {
  // Driven by the mask rather than by a literal bound, so a finding added to the
  // enum and not to the string function fails here instead of printing whatever
  // the default arm says.
  std::set<std::string> seen;
  size_t bits = 0;
  for (uint32_t bit = 1u; bit <= GARC_NAME_FINDING_ALL; bit <<= 1) {
    if (!(GARC_NAME_FINDING_ALL & bit)) {
      continue;
    }
    ++bits;
    const char * text
        = garc_name_finding_string(static_cast<GARC_Name_Finding>(bit));
    ASSERT_NE(text, nullptr);
    SCOPED_TRACE(text);
    EXPECT_STRNE(text, "not a single finding")
        << "this bit is in GARC_NAME_FINDING_ALL and has no string";
    EXPECT_TRUE(seen.insert(text).second) << "two findings share a string";
  }
  EXPECT_EQ(bits, 15u) << "the finding set changed size; check the masks too";

  // A mask rather than a single bit is a category mistake this names, instead of
  // picking one of the bits and answering a question nobody asked.
  EXPECT_STREQ(garc_name_finding_string(
                   static_cast<GARC_Name_Finding>(
                       GARC_NAME_ABSOLUTE | GARC_NAME_TRAVERSAL)),
      "not a single finding");
  EXPECT_STREQ(garc_name_finding_string(static_cast<GARC_Name_Finding>(0)),
      "not a single finding");
}

TEST(NameStrings, TheDumpPrintsEveryFindingAndSaysSoWhenThereAreNone) {
  char buffer[4096];
  FILE * out = fmemopen(buffer, sizeof(buffer), "w");
  ASSERT_NE(out, nullptr);
  garc_name_findings_dump(check("../CON."), out);
  fflush(out);
  fclose(out);
  const std::string text(buffer);
  EXPECT_NE(text.find("resolves outside the root"), std::string::npos) << text;
  EXPECT_NE(text.find("reserved device name"), std::string::npos) << text;
  EXPECT_NE(text.find("ends in a dot"), std::string::npos) << text;

  std::memset(buffer, 0, sizeof(buffer));
  out = fmemopen(buffer, sizeof(buffer), "w");
  ASSERT_NE(out, nullptr);
  garc_name_findings_dump(0, out);
  fflush(out);
  fclose(out);
  EXPECT_NE(std::string(buffer).find("no findings"), std::string::npos);

  // A bit from outside this build's vocabulary is reported rather than dropped.
  std::memset(buffer, 0, sizeof(buffer));
  out = fmemopen(buffer, sizeof(buffer), "w");
  ASSERT_NE(out, nullptr);
  garc_name_findings_dump(1u << 20, out);
  fflush(out);
  fclose(out);
  EXPECT_NE(std::string(buffer).find("unrecognised"), std::string::npos)
      << buffer;

  // NULL is ignored rather than crashing.
  garc_name_findings_dump(GARC_NAME_ABSOLUTE, nullptr);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
