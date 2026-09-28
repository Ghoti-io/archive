/**
 * @file
 *
 * Classifying a zip member's name, against what three extractors actually do.
 *
 * **The expectations here are not this library's.** A safety predicate whose test
 * table was written by whoever wrote the predicate measures its author twice, so
 * the load-bearing tests walk `tests/data/zip/verdicts.tsv` - what Python's
 * `zipfile`, unzip 6.00 and libarchive's `bsdtar -x` did with every member of the
 * corpus, recorded in the pinned container - and assert a two-sided relation
 * against each of them.
 *
 * **zip has no reference that states a policy, which is the first difference from
 * tar.** PEP 706 gave `tarfile` a `data_filter` whose verdict is a documented
 * decision; `zipfile` has no equivalent and never did. So every column in that
 * file is an *action* - what got created - and a Python exception in it is the
 * filesystem answering rather than a check refusing. A test that read one of those
 * as a policy verdict would credit Python with a check it does not perform.
 *
 * **Three references, three different masks**, and each difference is a measured
 * row rather than a guess:
 *
 *   - unzip rewrites `..` to `__`, drops a `./` and an empty component, and
 *     strips a control byte out of a name. It leaves a backslash, a drive letter
 *     and a UNC prefix exactly as they are.
 *   - libarchive translates a zip member's backslashes to slashes and then refuses
 *     the result for containing `..`, and it splits a drive letter and a UNC
 *     prefix into directories. It leaves `./`, an empty component, a reserved
 *     device name and a control byte alone.
 *   - Python's `zipfile` normalises the path - `./` and empty components go - and
 *     re-encodes a name that is not UTF-8, so the bytes it writes are not the bytes
 *     the archive holds. It leaves backslashes, drive letters and UNC prefixes
 *     alone.
 *
 * **And libarchive answers differently for zip than it does for tar**, which is
 * the same library at the same version and is worth stating out loud. For a tar
 * member it created `Windows\ghoti` and `server\share\ghoti` - one filename each,
 * backslashes intact - where for a zip member it created `Windows/ghoti` and
 * `server/share/ghoti`. And for a tar it created both halves of the
 * composed/decomposed pair, where for a zip it created one. A mask written once
 * for "libarchive" would be wrong for one of the two formats.
 *
 * The hand-built cases below are the complement: what the corpus cannot carry
 * because a reference refuses to open the archive at all.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstdint>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "test_helpers.h"
#include "zip_manifest.h"

using garctest::BufferSource;
using garctest::ZipNameRow;
using garctest::ZipVerdictRow;
using garctest::read_fixture;
using garctest::zip_names_load;
using garctest::zip_verdicts_load;

namespace {

std::string data_path(const std::string & name) {
  return std::string(GARC_TEST_DATA) + "/zip/" + name;
}

const std::vector<ZipVerdictRow> & verdicts() {
  static const std::vector<ZipVerdictRow> rows
      = zip_verdicts_load(data_path("verdicts.tsv"));
  return rows;
}

const std::map<std::string, std::vector<ZipNameRow>> & names() {
  static const std::map<std::string, std::vector<ZipNameRow>> rows
      = zip_names_load(data_path("names.tsv"));
  return rows;
}

/** Shorthand so a test reads as a claim about a name rather than about a call. */
uint32_t check(const std::string & name) {
  return garc_name_check(name.data(), name.size());
}

/**
 * The findings Python's `zipfile` extractor acts on.
 *
 * It resolves the path, so a traversal, a parent component, a leading separator, a
 * `./` and an empty component all change what it creates - and it re-encodes a
 * name that is not UTF-8, which changes the bytes. It says nothing about a
 * backslash, a drive letter, a UNC prefix, a reserved device name, a trailing dot
 * or a control byte, so none of those is in here.
 */
constexpr uint32_t kPythonAnswers = GARC_NAME_TRAVERSAL
    | GARC_NAME_PARENT_COMPONENT | GARC_NAME_ABSOLUTE
    | GARC_NAME_CURRENT_COMPONENT | GARC_NAME_EMPTY_COMPONENT
    | GARC_NAME_NOT_UTF8;

/**
 * The findings unzip 6.00 acts on.
 *
 * The path ones, plus a control byte, which it strips out of the name it creates.
 * Not a backslash: it wrote `..\..\..\tmp\ghoti-esc-bs` as one ordinary filename,
 * which is the row that separates it from libarchive.
 */
constexpr uint32_t kUnzipAnswers = GARC_NAME_TRAVERSAL
    | GARC_NAME_PARENT_COMPONENT | GARC_NAME_ABSOLUTE
    | GARC_NAME_CURRENT_COMPONENT | GARC_NAME_EMPTY_COMPONENT
    | GARC_NAME_CONTROL_BYTE;

/**
 * The findings libarchive's extractor acts on, **for a zip**.
 *
 * A `..` component escaping or not, a leading separator, a drive letter, a UNC
 * prefix, and a traversal spelled with backslashes - which it sees because it
 * translates them into separators first. Not `./`, not an empty component, not a
 * reserved name, not a control byte. Its tar mask is not this: see the file
 * comment.
 */
constexpr uint32_t kLibarchiveAnswers = GARC_NAME_TRAVERSAL
    | GARC_NAME_PARENT_COMPONENT | GARC_NAME_ABSOLUTE | GARC_NAME_DRIVE_LETTER
    | GARC_NAME_UNC | GARC_NAME_WINDOWS_TRAVERSAL;

/** One reference's column, its mask, and a name for failure messages. */
struct Reference {
  const char * who;
  uint32_t mask;
  const std::string & (*column)(const ZipVerdictRow &);
};

const std::string & python_of(const ZipVerdictRow & row) { return row.python; }
const std::string & unzip_of(const ZipVerdictRow & row) { return row.unzip; }
const std::string & libarchive_of(const ZipVerdictRow & row) {
  return row.libarchive;
}

const std::vector<Reference> & references() {
  static const std::vector<Reference> all = {
    {"Python's zipfile", kPythonAnswers, &python_of},
    {"unzip", kUnzipAnswers, &unzip_of},
    {"libarchive", kLibarchiveAnswers, &libarchive_of},
  };
  return all;
}

/** What a reference's verdict is a statement about. */
enum class About {
  Nothing,  ///< It created the member's own name.
  TheName,  ///< It rewrote the name, refused it for the path, or died on it.
  TheData,  ///< It refused the member for a reason the name has no part in.
};

/**
 * Classify one verdict, from the reference's own vocabulary.
 *
 * **Not every refusal is about the name**, and this is where that is decided
 * rather than assumed. Python raises `RuntimeError` for an encrypted member with
 * no password and `NotImplementedError` for a method it does not implement, and
 * neither says anything about the name - the first run of this file scored seven
 * such rows as "it acted on this name and we report nothing about it", which was
 * the test being wrong and not the checker.
 *
 * An exception name this list does not know is ::About::TheName, so a reference
 * release that raises something new fails loudly here rather than being absorbed
 * into a silent exclusion.
 */
About about(const std::string & verdict) {
  if (verdict == "same") {
    return About::Nothing;
  }
  if (verdict.rfind("rewrite=", 0) == 0) {
    return About::TheName;
  }
  if (verdict.rfind("refused=", 0) == 0) {
    // libarchive and unzip say why. Only the path reasons are about the name; a
    // method with no codec and an encrypted member are not.
    return verdict.find("Path contains") != std::string::npos
        ? About::TheName : About::TheData;
  }
  // Python, which raises rather than reporting. These two are about the member's
  // bytes; everything else it raises here is the filesystem answering about the
  // path it built from the name.
  if (verdict == "RuntimeError" || verdict == "NotImplementedError") {
    return About::TheData;
  }
  return About::TheName;
}

/**
 * Whether a row is one the per-name relation cannot cover.
 *
 * `mal-collisions.zip` is the exception, and it is the same exception the tar
 * suite makes: a collision is a property of a *pair* of names, so every name in it
 * is individually clean and has to be. libarchive acts on one of them - it creates
 * the composed form for the decomposed name, silently losing the other half - and
 * no function taking one name can predict that.
 */
bool beyond_a_per_name_check(const ZipVerdictRow & row) {
  return row.archive == "mal-collisions.zip";
}

} // namespace

//-----------------------------------------------------------------------------
// The reference cross-check
//-----------------------------------------------------------------------------

TEST(ZipNameOracle, TheVerdictsAreNotEmpty) {
  // The denominator. Every test below iterates this file, so an unreadable one
  // would make all of them pass while asking nothing.
  const auto & rows = verdicts();
  ASSERT_FALSE(rows.empty()) << "no verdicts at " << data_path("verdicts.tsv");
  EXPECT_EQ(rows.size(), 75u);

  size_t hostile = 0;
  for (const ZipVerdictRow & row : rows) {
    if (row.archive.compare(0, 4, "mal-") == 0) {
      ++hostile;
    }
  }
  EXPECT_GE(hostile, 24u) << "the hostile fixtures have left the verdict file";
}

TEST(ZipNameOracle, AgreesWithEachExtractorInBothDirections) {
  // The relation, stated so that each direction can fail on its own:
  //
  //   we report something the reference answers for  =>  it did not leave the
  //                                                      name alone
  //   the reference left the name alone              =>  we report none of those
  //
  // One direction alone is satisfiable by a checker that reports nothing, or by
  // one that reports everything. Both together are not - and here they are
  // asserted three times over, against three references whose masks differ.
  for (const Reference & reference : references()) {
    size_t acted = 0;
    size_t left_alone = 0;
    size_t skipped = 0;
    for (const ZipVerdictRow & row : verdicts()) {
      const std::string & verdict = reference.column(row);
      if (verdict == "-") {
        // The reference could not open the archive, which openings.tsv records
        // and which is not a verdict about this member's name.
        continue;
      }
      if (beyond_a_per_name_check(row)) {
        ++skipped;
        continue;
      }
      const std::string where = std::string(reference.who) + " on "
          + row.archive + " member " + std::to_string(row.index) + " "
          + row.name + " [" + verdict + "]";
      const uint32_t findings = check(row.name) & reference.mask;
      switch (about(verdict)) {
        case About::Nothing:
          ++left_alone;
          EXPECT_EQ(findings, 0u) << where
              << ": it created this name unchanged and we call it a hazard";
          break;
        case About::TheName:
          ++acted;
          EXPECT_NE(findings, 0u) << where
              << ": it acted on this name and we report nothing about it";
          break;
        case About::TheData:
          // A refusal the name has no part in - a method with no codec, an
          // encrypted member with no password. Counted rather than ignored, so
          // this arm cannot silently absorb a row that *is* about the name.
          ++skipped;
          break;
      }
    }
    EXPECT_GE(acted, 6u) << reference.who
        << " acted on almost nothing, so that direction asserts nothing";
    EXPECT_GE(left_alone, 40u) << reference.who
        << " left almost nothing alone, so the reverse direction asserts nothing";
    EXPECT_GT(skipped, 0u) << reference.who
        << ": nothing was skipped, so the exclusions are not being exercised and "
           "one of them may have stopped matching";
  }
}

TEST(ZipNameOracle, TheThreeReferencesDisagreeAboutABackslashTraversal) {
  // **The discriminating case, and it is zip's own.** libarchive translates a zip
  // member's backslashes to slashes and refuses the result; unzip and Python
  // create one ordinary file with backslashes in its name. Asserted here, in a
  // test whose name says what it is about, rather than left to break whichever of
  // the three relations above happens to fail first.
  //
  // It is also the whole justification for GARC_NAME_BACKSLASH and
  // GARC_NAME_WINDOWS_TRAVERSAL being two findings: one reference in three treats
  // the separator as a separator, so a single bit would have to pick a side.
  bool seen = false;
  for (const ZipVerdictRow & row : verdicts()) {
    if (row.name != "..\\..\\..\\tmp\\ghoti-esc-bs") {
      continue;
    }
    seen = true;
    EXPECT_TRUE(ZipVerdictRow::unchanged(row.python))
        << "Python used to write this name as it stands";
    EXPECT_TRUE(ZipVerdictRow::unchanged(row.unzip))
        << "unzip used to write this name as it stands";
    EXPECT_TRUE(ZipVerdictRow::refused_for_path(row.libarchive))
        << "libarchive used to refuse this for containing '..'";

    const uint32_t findings = check(row.name);
    EXPECT_TRUE(findings & GARC_NAME_BACKSLASH);
    EXPECT_TRUE(findings & GARC_NAME_WINDOWS_TRAVERSAL);
    // And *not* a POSIX traversal, because with `/` as the separator this is one
    // component and goes nowhere. That is the difference the two findings carry.
    EXPECT_FALSE(findings & GARC_NAME_TRAVERSAL);
  }
  EXPECT_TRUE(seen)
      << "the corpus no longer contains a backslash traversal, which is the name "
         "that separates the three references";
}

TEST(ZipNameOracle, TheDriveLetterAndUncPrefixAreLibarchivesAlone) {
  // The mirror: libarchive splits both into directories and the other two write
  // them verbatim. This is the justification for GARC_NAME_DRIVE_LETTER and
  // GARC_NAME_UNC being in GARC_NAME_ESCAPES at all - one reference in three
  // treats them as paths, and it is the one that writes to a filesystem for a
  // living.
  size_t seen = 0;
  for (const ZipVerdictRow & row : verdicts()) {
    const bool drive = row.name == "C:\\Windows\\ghoti";
    const bool unc = row.name == "\\\\server\\share\\ghoti";
    if (!drive && !unc) {
      continue;
    }
    ++seen;
    EXPECT_TRUE(ZipVerdictRow::unchanged(row.python)) << row.name;
    EXPECT_TRUE(ZipVerdictRow::unchanged(row.unzip)) << row.name;
    EXPECT_EQ(row.libarchive,
        drive ? "rewrite=Windows/ghoti" : "rewrite=server/share/ghoti")
        << row.name << ": libarchive used to split this one";
    EXPECT_TRUE(check(row.name)
        & (drive ? GARC_NAME_DRIVE_LETTER : GARC_NAME_UNC));
  }
  EXPECT_EQ(seen, 2u) << "the corpus no longer holds both shapes";
}

TEST(ZipNameOracle, EveryOrdinaryNameInTheCorpusIsClean) {
  // The control: a checker that flagged every name would pass the first direction
  // of all three relations above, and only something like this can tell. These
  // are the names of 25 archives written by four real tools, so "ordinary" here
  // means "what a writer produces when nobody is trying".
  size_t ordinary = 0;
  for (const ZipVerdictRow & row : verdicts()) {
    if (row.archive.compare(0, 4, "mal-") == 0) {
      continue;
    }
    SCOPED_TRACE(row.archive + " " + row.name);
    ++ordinary;
    EXPECT_EQ(check(row.name), 0u) << "an ordinary name reported findings";
    // And every reference agrees it is ordinary, which is what makes this a
    // control rather than a restatement of what this library thinks. Python's
    // column is the one checked, because it is the only in-process one and so the
    // only one with no output parsing between the reference and the row.
    EXPECT_NE(about(row.python), About::TheName)
        << "Python acted on a name from a fixture nothing hostile was put in";
  }
  EXPECT_GT(ordinary, 40u)
      << "too few ordinary names to be a control over the corpus";
}

TEST(ZipNameOracle, EveryMaliciousFixtureHasSomethingToSayAboutIt) {
  // A guard on the instrument. If the hostile fixtures were regenerated into
  // something harmless - which happened once already in the tar corpus, when two
  // names meant to hold raw bytes were encoded into valid UTF-8 on the way to
  // tar - every test above would still pass by checking nothing.
  std::map<std::string, size_t> clean;
  std::map<std::string, size_t> total;
  for (const ZipVerdictRow & row : verdicts()) {
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
    // Two fixtures are deliberate exceptions, for different reasons.
    //
    // mal-collisions.zip: a collision is a property of a *pair* of names, so
    // every name in it is individually clean and has to be.
    //
    // mal-links.zip: the hostile part is each member's *data*, which in a zip is
    // its link target - `abs-target` is an ordinary name pointing somewhere it
    // should not.
    if (entry.first == "mal-collisions.zip" || entry.first == "mal-links.zip") {
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

TEST(ZipNameOracle, ACollisionIsInvisibleToAPerNameCheckAndLibarchiveRealisesIt) {
  // Said out loud rather than left implied. `A.txt` and `a.txt` collide on a
  // case-insensitive filesystem; `café` composed and decomposed collide after
  // normalisation. Both pairs are clean name by name, and no function taking one
  // name can be otherwise - folding case or normalising needs tables this library
  // deliberately does not carry, which are `unicode`'s.
  //
  // **And one reference makes the collision real.** libarchive extracts three
  // files from this four-member archive, with exit 0 and not a word about it: it
  // reports the decomposed name in composed form, so the second member lands on
  // the first one's path. unzip creates both. That is recorded in verdicts.tsv as
  // a rewrite, and it is the reason this test names libarchive.
  //
  // **If the first half of this ever starts failing, it is because someone taught
  // the checker to normalise.** The right response is to move the claim, not to
  // relax the test.
  size_t pairs = 0;
  size_t collapsed = 0;
  for (const ZipVerdictRow & row : verdicts()) {
    if (row.archive != "mal-collisions.zip") {
      continue;
    }
    ++pairs;
    SCOPED_TRACE(row.name);
    EXPECT_EQ(check(row.name), 0u);
    EXPECT_TRUE(ZipVerdictRow::unchanged(row.unzip))
        << "unzip used to create both halves of both pairs";
    if (!ZipVerdictRow::unchanged(row.libarchive)) {
      ++collapsed;
      // The verdict columns keep the generator's escaping - only the name column
      // is unescaped by the loader - so this is the literal text of the row, and
      // `caf\xC3\xA9` is the composed spelling of the decomposed name above it.
      EXPECT_EQ(row.libarchive, "rewrite=caf\\xC3\\xA9");
    }
  }
  EXPECT_EQ(pairs, 4u) << "the collision fixture no longer has two pairs in it";
  EXPECT_EQ(collapsed, 1u)
      << "libarchive used to collapse exactly one of these four onto another";
}

TEST(ZipNameOracle, ALinkTargetIsCheckedTheSameWayAndNoReferenceObjects) {
  // The other half of the problem, and the reason garc_name_check() takes bytes
  // rather than a member: a symlink's *target* is as dangerous as its name, and it
  // is the same question about different bytes.
  //
  // **In a zip the target is the member's data**, not a header field, so it cannot
  // be asked about until the member has been read - a different order of
  // operations from tar, where the target is in the header beside the name.
  //
  // And the finding that makes this fixture worth having: **neither unzip nor
  // libarchive objects to any of these targets.** Both create
  // `abs-target -> /tmp/ghoti-escaped` and `up-target -> ../../..` without a
  // word. So for a link target there is no reference to disagree with, and the
  // whole of the answer is this library's - which is the case where writing the
  // corpus first mattered most, because it is the case where agreement would have
  // been no evidence at all.
  const auto found = names().find("mal-links.zip");
  ASSERT_NE(found, names().end()) << "the hostile-link fixture is missing";

  size_t hostile = 0;
  size_t harmless = 0;
  for (const ZipNameRow & row : found->second) {
    if (row.link.empty()) {
      continue;
    }
    SCOPED_TRACE(row.name + " -> " + row.link);
    // The name is ordinary in every case; the target is the question.
    EXPECT_EQ(check(row.name), 0u);
    if (row.link == "./sibling") {
      ++harmless;
      // The control. A target that does not escape must not be an escape, or the
      // check would be reporting "symlink" rather than "hazard".
      EXPECT_EQ(check(row.link) & GARC_NAME_ESCAPES, 0u);
      EXPECT_TRUE(check(row.link) & GARC_NAME_CURRENT_COMPONENT);
      continue;
    }
    ++hostile;
    EXPECT_NE(check(row.link) & GARC_NAME_ESCAPES, 0u)
        << "a target that leaves any root is not reported as one";
  }
  EXPECT_EQ(hostile, 2u);
  EXPECT_EQ(harmless, 1u) << "the control target has gone, so this test can no "
                             "longer tell a hazard from a symlink";

  // And the references' silence, asserted rather than described: every one of
  // these members is `same` for all three.
  size_t quiet = 0;
  for (const ZipVerdictRow & row : verdicts()) {
    if (row.archive != "mal-links.zip") {
      continue;
    }
    ++quiet;
    EXPECT_TRUE(ZipVerdictRow::unchanged(row.python)) << row.name;
    EXPECT_TRUE(ZipVerdictRow::unchanged(row.unzip)) << row.name;
    EXPECT_TRUE(ZipVerdictRow::unchanged(row.libarchive)) << row.name;
  }
  EXPECT_EQ(quiet, 4u);
}

//-----------------------------------------------------------------------------
// What the corpus cannot carry, because a reference refuses the archive
//-----------------------------------------------------------------------------

TEST(ZipNameOracle, ANameThatIsNotUtf8IsReportedWhateverTheFlagClaims) {
  // **Two fixtures, one axis: general purpose flag bit 11.** The same eight bytes
  // in both, and they are not well-formed UTF-8 either way. With the flag clear
  // the archive says nothing about the encoding, which is the case for most names
  // in the world; with it set the archive *claims* UTF-8 about bytes that are not.
  //
  // The second is refused outright by Python and by libarchive - it has no
  // manifest rows and no names rows, and openings.tsv is where that is recorded -
  // so this is a claim the corpus-driven tests structurally cannot make, and it is
  // read here through this library's own walk.
  //
  // What is asserted is that the finding does not depend on the flag. A reader
  // that trusted bit 11 would report a well-formed name for the archive that lies,
  // which is exactly backwards: the flag is a claim and the bytes are the fact.
  for (const char * fixture : {"mal-encodings.zip", "mal-utf8-lie.zip"}) {
    SCOPED_TRACE(fixture);
    const std::vector<uint8_t> bytes = read_fixture(data_path(fixture));
    BufferSource source(bytes.data(), bytes.size(), true, true);
    GARC_Stream * stream = nullptr;
    ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK);
    GARC_Archive * archive = nullptr;
    ASSERT_EQ(garc_open(stream, nullptr, &archive), GARC_OK);

    const GARC_Member * member = nullptr;
    ASSERT_EQ(garc_next(archive, &member), GARC_OK);
    const std::string name(member->name, member->name_length);
    EXPECT_EQ(name, std::string("bad\x80utf\xC0", 8u))
        << "the bytes are the fact, whatever the flag says";
    EXPECT_TRUE(check(name) & GARC_NAME_NOT_UTF8);
    // The declaration is reported separately from the bytes, which is what lets a
    // caller see the contradiction rather than having it resolved for them.
    const bool lying = std::strcmp(fixture, "mal-utf8-lie.zip") == 0;
    EXPECT_EQ(member->name_encoding,
        lying ? GARC_NAME_UTF8 : GARC_NAME_UNDECLARED);

    // The control member, so the fixture is not simply unreadable.
    ASSERT_EQ(garc_next(archive, &member), GARC_OK);
    EXPECT_EQ(std::string(member->name, member->name_length), "ordinary.txt");
    EXPECT_EQ(check("ordinary.txt"), 0u);

    garc_close(archive);
    garc_stream_destroy(stream);
  }
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
