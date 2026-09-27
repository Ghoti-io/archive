/**
 * @file
 *
 * Reading tar, against what a third implementation says the fixtures contain.
 *
 * The fixtures are written by GNU tar 1.35 in the pinned container and the
 * expectations are Python 3.13.5's `tarfile` reading them back - so a passing
 * row here is two independent implementations agreeing, not this library
 * agreeing with itself. `tools/oracle/make_corpus.py` generates both and
 * `make check-corpus` proves the committed bytes are what it generates.
 *
 * **A missing corpus fails these tests rather than skipping them.** The fixtures
 * are committed, so their absence is a broken checkout; a skip would make a
 * clone with no `tests/data/` look exactly like a clone that passes.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstring>
#include <map>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "tar_manifest.h"
#include "test_helpers.h"

using garctest::BufferSource;
using garctest::ManifestRow;
using garctest::manifest_load;
using garctest::names_load;
using garctest::read_fixture;

namespace {

std::string data_path(const std::string & name) {
  return std::string(GARC_TEST_DATA) + "/tar/" + name;
}

/** The metadata manifest, from Python's tarfile, loaded once. */
const std::map<std::string, std::vector<ManifestRow>> & manifest() {
  static const std::map<std::string, std::vector<ManifestRow>> rows
      = manifest_load(data_path("manifest.tsv"));
  return rows;
}

/** The names, from bsdtar. See names_load() for why they are a second file. */
const std::map<std::string, std::vector<std::string>> & names() {
  static const std::map<std::string, std::vector<std::string>> rows
      = names_load(data_path("names.tsv"));
  return rows;
}

/** A member's name as a std::string, using the length rather than a NUL. */
std::string member_name(const GARC_Member * member) {
  return std::string(member->name, member->name_length);
}

/**
 * Whether `bsdtar -tf` would print these bytes unchanged.
 *
 * **It does not always, and finding that out cost a test run.** bsdtar is a
 * *listing* tool, so it escapes: a control byte comes out as `\033`, a high byte
 * as `\200`, and a backslash is doubled. That is the right thing for a program
 * writing attacker-controlled bytes to a terminal - it is what this library's own
 * example does - and it means bsdtar's listing is a **rendering rather than the
 * bytes**, so it cannot be the byte-level expectation for a hostile name.
 *
 * It is still the only reference that keeps a directory's trailing slash, which is
 * why it is not simply dropped. See expect_matches_manifest() for how the two
 * references are combined now: the bytes come from tarfile, the slash rule is
 * reconstructed, and bsdtar checks the reconstruction on every name it *can*
 * render verbatim - which is most of them.
 */
bool renders_verbatim(const std::string & name) {
  for (char byte : name) {
    const unsigned char value = static_cast<unsigned char>(byte);
    if (value < 0x20u || value > 0x7Eu || value == static_cast<unsigned char>('\\')) {
      return false;
    }
  }
  return true;
}

/**
 * Walk one fixture and compare every member against the manifest.
 *
 * `shape` chooses the stream: a memory stream, or a callback stream that cannot
 * seek and does not know its length. Both must give the same answers, which is
 * the assertion that makes "tar can be read from a pipe" true rather than
 * claimed - and it is checked on every fixture rather than on one.
 */
/**
 * How many names the bsdtar cross-check covered, and how many it could not.
 *
 * A clause that quietly stops applying is a gate that vanishes from a green
 * suite, so the two counts are totalled across every fixture and asserted once
 * at the end - see TarCorpus::TheNameReferencesAreBothStillBeingAsked.
 */
size_t g_rendered_verbatim = 0;
size_t g_rendered_escaped = 0;

void expect_matches_manifest(const std::string & fixture, bool as_pipe) {
  const auto & rows = manifest();
  ASSERT_FALSE(rows.empty())
      << "tests/data/tar/manifest.tsv is missing or empty. The corpus is "
         "committed; run `make corpus` only if you mean to regenerate it.";
  const auto found = rows.find(fixture);
  ASSERT_NE(found, rows.end()) << "no manifest rows for " << fixture;

  const auto & name_rows = names();
  const auto found_names = name_rows.find(fixture);
  ASSERT_NE(found_names, name_rows.end()) << "no name rows for " << fixture;
  // The two references must agree about how many members there are, even where
  // they disagree about what one is called. A mismatch means bsdtar's
  // one-name-per-line listing broke - a name containing a newline would do it -
  // and every comparison below would then be against a shifted row.
  ASSERT_EQ(found->second.size(), found_names->second.size())
      << fixture << ": tarfile and bsdtar disagree about the member count";

  std::vector<uint8_t> bytes = read_fixture(data_path(fixture));
  ASSERT_FALSE(bytes.empty()) << "cannot read " << fixture;

  GARC_Stream * stream = nullptr;
  BufferSource source(bytes.data(), bytes.size(), false, false);
  if (as_pipe) {
    ASSERT_EQ(garc_stream_create_callback(source.callbacks(), &stream), GARC_OK);
  } else {
    ASSERT_EQ(
        garc_stream_create_memory(bytes.data(), bytes.size(), &stream), GARC_OK);
  }

  GARC_Archive * archive = nullptr;
  ASSERT_EQ(garc_open(stream, nullptr, &archive), GARC_OK) << fixture;
  EXPECT_EQ(garc_format(archive), GARC_FORMAT_TAR);

  size_t index = 0;
  const GARC_Member * member = nullptr;
  GARC_Result result;
  while ((result = garc_next(archive, &member)) == GARC_OK) {
    ASSERT_LT(index, found->second.size())
        << fixture << ": more members than the reference found";
    const ManifestRow & want = found->second[index];

    // **The name, from both references, each used for what it can express.**
    //
    // tarfile's `.name` is the bytes - it round-trips any byte through
    // surrogateescape - and is wrong about exactly one thing: it strips a
    // directory member's trailing slash. bsdtar keeps the slash and is wrong
    // about any byte it has to escape, because its listing is a rendering.
    //
    // So the expectation is tarfile's bytes with the slash put back, and bsdtar
    // checks *that rule* wherever it renders verbatim - which is every name in the
    // ordinary corpus and most of the hostile ones. The rule is therefore not
    // assumed; it is asserted against a second reference 85-odd times.
    std::string want_name = want.name;
    if (want.type == "directory") {
      want_name += '/';
    }
    EXPECT_EQ(member_name(member), want_name)
        << fixture << " member " << index;
    if (renders_verbatim(want_name)) {
      ++g_rendered_verbatim;
      EXPECT_EQ(found_names->second[index], want_name)
          << fixture << " member " << index
          << ": the two references disagree about a name neither of them has to "
             "escape, so the slash rule above is wrong";
    } else {
      ++g_rendered_escaped;
    }
    EXPECT_STREQ(garc_member_type_string(member->type), want.type.c_str())
        << fixture << " member " << index << " " << want.name;
    // uname and gname are bytes plus a length, and absent rather than empty when
    // the archive carried none - so the comparison is against what the reference
    // read, empty string included.
    const std::string uname = member->uname
        ? std::string(member->uname, member->uname_length)
        : std::string();
    const std::string gname = member->gname
        ? std::string(member->gname, member->gname_length)
        : std::string();
    EXPECT_EQ(uname, want.uname) << fixture << " member " << index;
    EXPECT_EQ(gname, want.gname) << fixture << " member " << index;
    EXPECT_EQ(member->size, want.size)
        << fixture << " member " << index << " " << want.name;
    EXPECT_EQ(member->mtime_seconds, want.mtime)
        << fixture << " member " << index << " " << want.name;
    // The sub-second part, which only a pax `mtime=` record carries. Compared
    // against a column of its own because the reference's own mtime is a float
    // and cannot hold a nanosecond - so a test comparing against that would
    // agree with a reader that dropped the last two digits.
    EXPECT_EQ(member->mtime_nanoseconds, want.mtime_nanoseconds)
        << fixture << " member " << index << " " << want.name;
    EXPECT_EQ(member->mode, want.mode)
        << fixture << " member " << index << " " << want.name;
    EXPECT_EQ(member->uid, want.uid) << fixture << " member " << index;
    EXPECT_EQ(member->gid, want.gid) << fixture << " member " << index;

    const std::string link = member->link_target
        ? std::string(member->link_target, member->link_target_length)
        : std::string();
    EXPECT_EQ(link, want.link) << fixture << " member " << index;

    ++index;
  }

  EXPECT_EQ(result, GARC_END)
      << fixture << ": " << garc_result_string(result) << " after " << index
      << " members";
  EXPECT_EQ(index, found->second.size())
      << fixture << ": fewer members than the reference found";
  EXPECT_EQ(garc_member_count(archive), index);

  garc_close(archive);
  garc_stream_destroy(stream);
}

/** The fixtures this reader is expected to read in full. */
const char * const readable[] = {
  "v7-basic.tar",
  "ustar-basic.tar",
  "ustar-sizes.tar",
  "ustar-modes.tar",
  "ustar-owners.tar",
  "ustar-prefix.tar",
  "ustar-nonascii.tar",
  // pax uses ustar's magic, so a pax archive whose names all fit the ustar
  // fields carries no extended records and reads as ustar - which it should,
  // rather than being refused for the format it declares.
  "pax-basic.tar",
  "pax-longname.tar",
  "pax-longlink.tar",
  "pax-times.tar",
  "pax-global.tar",
  // GNU's carriers. These were refused until the commit that read them, so they
  // are here as well as in the tests below: the reference comparison is what says
  // the name a carrier produced is the name the archive holds, rather than only
  // that something was produced.
  "gnu-longname.tar",
  "gnu-longname-blocks.tar",
  "gnu-longlink.tar",
  // The hostile-name fixtures are read like any others, and they are here for
  // that reason rather than despite it: **this library must not sanitise.** A
  // reader that quietly cleaned `../../../tmp/x` into `tmp/x` would hand a caller
  // a name the archive does not contain, and the caller could then never find out
  // that the archive lied. The names in the manifest are the bytes GNU tar wrote,
  // so comparing against it is what says nothing was cleaned.
  "mal-paths.tar",
  "mal-links.tar",
  "mal-collisions.tar",
  "mal-gnu-longpath.tar",
  "mal-pax-longpath.tar",
};

} // namespace

//-----------------------------------------------------------------------------
// The reference comparison
//-----------------------------------------------------------------------------

TEST(TarCorpus, EveryFixtureMatchesTheReferenceFromMemory) {
  for (const char * fixture : readable) {
    SCOPED_TRACE(fixture);
    expect_matches_manifest(fixture, false);
  }
}

TEST(TarCorpus, EveryFixtureMatchesTheReferenceFromAPipe) {
  // The same answers from a stream that cannot seek and does not know its
  // length. tar is a cursor over a stream and this is what says so; a reader
  // that quietly needed to seek would pass every test above and fail on the
  // first real pipe.
  for (const char * fixture : readable) {
    SCOPED_TRACE(fixture);
    expect_matches_manifest(fixture, true);
  }
}

TEST(TarCorpus, TheNameReferencesAreBothStillBeingAsked) {
  // The guard on the split above. If `renders_verbatim` ever returned false for
  // everything - a stricter predicate, a corpus of binary names - the bsdtar
  // cross-check would stop running and nothing would say so, because a clause
  // that never fires and a clause that always passes look identical in a green
  // suite. And if it returned true for everything, the escaped names would be
  // being compared against a rendering.
  //
  // This runs after the two walks above, which is why it reads globals rather
  // than measuring anything itself: gtest runs tests in declaration order within
  // a suite, and these three are in one.
  EXPECT_GT(g_rendered_verbatim, 100u)
      << "the bsdtar cross-check covered almost nothing";
  EXPECT_GT(g_rendered_escaped, 5u)
      << "no name needed escaping, so the hostile fixtures are no longer hostile "
         "or the predicate has stopped distinguishing";
}

TEST(TarCorpus, TheManifestIsNotEmpty) {
  // A guard on the instrument rather than on the subject. Every comparison above
  // loops over manifest rows, so an empty manifest would pass all of them by
  // checking nothing - which is the shape that reads as a green suite.
  const auto & rows = manifest();
  ASSERT_FALSE(rows.empty()) << "tests/data/tar/manifest.tsv is missing";
  size_t total = 0;
  for (const auto & entry : rows) {
    total += entry.second.size();
  }
  EXPECT_GT(total, 30u) << "the manifest has suspiciously few rows";
  for (const char * fixture : readable) {
    EXPECT_NE(rows.find(fixture), rows.end())
        << fixture << " has no manifest rows, so its test asserts nothing";
    EXPECT_NE(names().find(fixture), names().end())
        << fixture << " has no name rows, so its names assert nothing";
  }
}

//-----------------------------------------------------------------------------
// Variants
//-----------------------------------------------------------------------------

TEST(TarVariant, V7IsRecognisedWithNoMagicAtAll) {
  // v7 has no magic field, so the checksum is the only evidence the block is a
  // header. A reader that requires magic rejects the whole variant.
  std::vector<uint8_t> bytes = read_fixture(data_path("v7-basic.tar"));
  ASSERT_FALSE(bytes.empty());

  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
      GARC_OK);
  GARC_Archive * archive = nullptr;
  ASSERT_EQ(garc_open(stream, nullptr, &archive), GARC_OK);

  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(archive, &member), GARC_OK);
  EXPECT_EQ(garc_tar_member_variant(archive), GARC_TAR_V7);
  // v7 carries no owner names. Reporting an empty string rather than absent
  // would make a caller print "" where the archive said nothing.
  EXPECT_EQ(member->uname, nullptr);
  EXPECT_EQ(member->gname, nullptr);

  garc_close(archive);
  garc_stream_destroy(stream);
}

TEST(TarVariant, UstarIsRecognisedFromItsMagic) {
  std::vector<uint8_t> bytes = read_fixture(data_path("ustar-owners.tar"));
  ASSERT_FALSE(bytes.empty());

  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
      GARC_OK);
  GARC_Archive * archive = nullptr;
  ASSERT_EQ(garc_open(stream, nullptr, &archive), GARC_OK);

  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(archive, &member), GARC_OK);
  EXPECT_EQ(garc_tar_member_variant(archive), GARC_TAR_USTAR);
  // ustar carries owner names, and this is the one fixture written without
  // --numeric-owner so that they are not empty. Every other fixture here has
  // them blank, which is why a test asserting "ustar has a uname" against any of
  // those would have been asserting the writer's flags rather than the format.
  ASSERT_NE(member->uname, nullptr);
  EXPECT_EQ(std::string(member->uname, member->uname_length), "ghoti");
  ASSERT_NE(member->gname, nullptr);
  EXPECT_EQ(std::string(member->gname, member->gname_length), "ghotigroup");

  garc_close(archive);
  garc_stream_destroy(stream);
}

TEST(TarVariant, APrefixedNameIsJoinedWithASlash) {
  // The one shape that exercises ustar's 155-byte prefix. A reader that ignores
  // the prefix reports the tail of the path as the whole name, which is a
  // plausible answer rather than an error - so this asserts the *length* as well,
  // since a truncated name is still a name.
  std::vector<uint8_t> bytes = read_fixture(data_path("ustar-prefix.tar"));
  ASSERT_FALSE(bytes.empty());

  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
      GARC_OK);
  GARC_Archive * archive = nullptr;
  ASSERT_EQ(garc_open(stream, nullptr, &archive), GARC_OK);

  bool saw_long = false;
  const GARC_Member * member = nullptr;
  while (garc_next(archive, &member) == GARC_OK) {
    if (member->name_length > 100u) {
      saw_long = true;
      EXPECT_NE(member_name(member).find('/'), std::string::npos);
    }
  }
  EXPECT_TRUE(saw_long)
      << "no member longer than ustar's 100-byte name field, so the prefix "
         "join was never exercised";

  garc_close(archive);
  garc_stream_destroy(stream);
}

TEST(TarVariant, AGnuLongNameReplacesTheHeadersTruncatedCopy) {
  // GNU writes an 'L' member whose data is the next member's name, and then a
  // header holding a *truncated* copy of that name in its own field. So there are
  // two wrong answers a reader can give and both look like a name: reporting the
  // carrier itself as a file called "././@LongLink", and reporting the truncated
  // copy. This asserts against neither happening.
  std::vector<uint8_t> bytes = read_fixture(data_path("gnu-longname.tar"));
  ASSERT_FALSE(bytes.empty());

  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
      GARC_OK);
  GARC_Archive * archive = nullptr;
  ASSERT_EQ(garc_open(stream, nullptr, &archive), GARC_OK);

  size_t over_the_field = 0;
  const GARC_Member * member = nullptr;
  GARC_Result result;
  while ((result = garc_next(archive, &member)) == GARC_OK) {
    const std::string name = member_name(member);
    EXPECT_EQ(name.find("@LongLink"), std::string::npos)
        << "the carrier was reported as a member";
    if (name.size() > 100u) {
      ++over_the_field;
      // The variant is GNU even though the carrier is what said so, because a
      // member read through one was not read as a ustar member.
      EXPECT_EQ(garc_tar_member_variant(archive), GARC_TAR_GNU);
    }
  }
  EXPECT_EQ(result, GARC_END) << garc_result_string(result);
  EXPECT_GT(over_the_field, 0u)
      << "no name longer than the 100-byte field, so nothing here needed a "
         "carrier and the test asserts nothing";

  garc_close(archive);
  garc_stream_destroy(stream);
}

TEST(TarVariant, AGnuLongNamePayloadSpanningBlocksIsReadWhole) {
  // The payload is a member's data: padded to a block, and longer than one when
  // the name is. A reader that read it with a single 512-byte read would pass on
  // every name in gnu-longname.tar - the longest is 108 bytes - and truncate here
  // at exactly 512, which is a name rather than an error.
  std::vector<uint8_t> bytes = read_fixture(data_path("gnu-longname-blocks.tar"));
  ASSERT_FALSE(bytes.empty());

  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
      GARC_OK);
  GARC_Archive * archive = nullptr;
  ASSERT_EQ(garc_open(stream, nullptr, &archive), GARC_OK);

  size_t longest = 0;
  const GARC_Member * member = nullptr;
  GARC_Result result;
  while ((result = garc_next(archive, &member)) == GARC_OK) {
    longest = member->name_length > longest ? member->name_length : longest;
    EXPECT_NE(member->name_length, 512u)
        << "a name of exactly one block is what a single-block read produces";
  }
  EXPECT_EQ(result, GARC_END) << garc_result_string(result);
  EXPECT_GT(longest, 512u)
      << "no name longer than one block, so the multi-block payload was never "
         "exercised - the fixture is what makes this test mean anything";

  garc_close(archive);
  garc_stream_destroy(stream);
}

TEST(TarVariant, AGnuLongLinkTargetIsNotTruncated) {
  // 'K' is the same mechanism for the link target, and a reader that implements
  // 'L' and not 'K' truncates this silently at 100 bytes. A truncated symlink
  // target is a path to somewhere else, so it is a wrong answer of the worst kind
  // - which is why the fixture also holds a symlink whose target *does* fit, so
  // that the field and the carrier are both exercised in one archive.
  std::vector<uint8_t> bytes = read_fixture(data_path("gnu-longlink.tar"));
  ASSERT_FALSE(bytes.empty());

  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
      GARC_OK);
  GARC_Archive * archive = nullptr;
  ASSERT_EQ(garc_open(stream, nullptr, &archive), GARC_OK);

  size_t from_the_field = 0;
  size_t from_a_carrier = 0;
  const GARC_Member * member = nullptr;
  GARC_Result result;
  while ((result = garc_next(archive, &member)) == GARC_OK) {
    ASSERT_EQ(member->type, GARC_MEMBER_SYMLINK) << member_name(member);
    ASSERT_NE(member->link_target, nullptr) << member_name(member);
    if (member->link_target_length > 100u) {
      ++from_a_carrier;
      EXPECT_EQ(garc_tar_member_variant(archive), GARC_TAR_GNU);
    } else {
      ++from_the_field;
    }
  }
  EXPECT_EQ(result, GARC_END) << garc_result_string(result);
  EXPECT_EQ(from_a_carrier, 1u) << "no target needed a 'K' member";
  EXPECT_EQ(from_the_field, 1u)
      << "no target came from the header field, so a reader that read every "
         "target from a carrier would pass this";

  garc_close(archive);
  garc_stream_destroy(stream);
}

//-----------------------------------------------------------------------------
// Hostile names, which are read rather than cleaned
//-----------------------------------------------------------------------------

TEST(TarCorpus, EveryOrdinaryNameTheReaderReportsIsClean) {
  // The control over the bytes the *reader* hands out, which is not the same set
  // as the names in verdicts.tsv: those come from tarfile, which strips a
  // directory member's trailing slash. So this is the only place `sizes/` and
  // `emptydir/` are classified at all, and a checker that read a trailing
  // separator as an empty component would put a finding on a large fraction of
  // every real archive.
  size_t checked = 0;
  size_t directories = 0;
  for (const char * fixture : readable) {
    if (std::string(fixture).compare(0, 4, "mal-") == 0) {
      continue;
    }
    SCOPED_TRACE(fixture);
    std::vector<uint8_t> bytes = read_fixture(data_path(fixture));
    ASSERT_FALSE(bytes.empty());

    GARC_Stream * stream = nullptr;
    ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
        GARC_OK);
    GARC_Archive * archive = nullptr;
    ASSERT_EQ(garc_open(stream, nullptr, &archive), GARC_OK);

    const GARC_Member * member = nullptr;
    GARC_Result result;
    while ((result = garc_next(archive, &member)) == GARC_OK) {
      SCOPED_TRACE(member_name(member));
      ++checked;
      if (member->type == GARC_MEMBER_DIRECTORY) {
        ++directories;
        // The reader keeps the slash, which is the byte this test exists for.
        ASSERT_EQ(member->name[member->name_length - 1u], '/');
      }
      EXPECT_EQ(garc_name_check(member->name, member->name_length), 0u)
          << "an ordinary name reported findings";
      if (member->link_target) {
        EXPECT_EQ(garc_name_check(
                      member->link_target, member->link_target_length),
            0u)
            << "an ordinary link target reported findings";
      }
    }
    EXPECT_EQ(result, GARC_END) << garc_result_string(result);

    garc_close(archive);
    garc_stream_destroy(stream);
  }
  EXPECT_GT(checked, 50u) << "too few names to be a control";
  EXPECT_GT(directories, 5u)
      << "no directory member was classified, so the trailing-slash case is not "
         "covered here either";
}

TEST(TarHostileNames, TheReaderReportsThemVerbatimAndSaysWhatIsWrong) {
  // Two claims in one walk, because they are the two halves of the same decision:
  // the *reader* hands over exactly what the header said, and the *classifier* is
  // what says it is dangerous. A library that did the first without offering the
  // second would be handing out hazards with no vocabulary to describe them; one
  // that did the second by rewriting the name would be lying about the archive.
  std::vector<uint8_t> bytes = read_fixture(data_path("mal-paths.tar"));
  ASSERT_FALSE(bytes.empty());

  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
      GARC_OK);
  GARC_Archive * archive = nullptr;
  ASSERT_EQ(garc_open(stream, nullptr, &archive), GARC_OK);

  size_t escaping = 0;
  size_t flagged = 0;
  size_t members = 0;
  const GARC_Member * member = nullptr;
  GARC_Result result;
  while ((result = garc_next(archive, &member)) == GARC_OK) {
    ++members;
    const std::string name = member_name(member);
    SCOPED_TRACE(name);
    const uint32_t findings = garc_name_check(member->name, member->name_length);
    if (findings) {
      ++flagged;
    }
    if (findings & GARC_NAME_ESCAPES) {
      ++escaping;
      // Nothing was stripped on the way through: a name this library calls an
      // escape still *looks* like one to the caller.
      EXPECT_TRUE(name.find("..") != std::string::npos || name[0] == '/'
          || name.find(':') != std::string::npos
          || name.compare(0, 2, "\\\\") == 0)
          << "a name reported as an escape has none of the syntax that makes it "
             "one, so something cleaned it";
    }
  }
  EXPECT_EQ(result, GARC_END) << garc_result_string(result);
  EXPECT_EQ(members, 18u) << "the hostile-name fixture changed size";
  EXPECT_EQ(flagged, members)
      << "a name in the hostile fixture came back with no findings";
  EXPECT_GT(escaping, 4u) << "too few escapes to be asserting anything";

  garc_close(archive);
  garc_stream_destroy(stream);
}

TEST(TarHostileNames, AHostileTargetSurvivesTheCarriersToo) {
  // A long hostile name arrives through a GNU `L` carrier in one fixture and a pax
  // `path=` record in the other, and the check has to see *that* name rather than
  // the truncated copy in the header behind it. This is the one place a reader
  // that got the carriers wrong would hand a safety check something harmless and
  // get a clean answer.
  for (const char * fixture : {"mal-gnu-longpath.tar", "mal-pax-longpath.tar"}) {
    SCOPED_TRACE(fixture);
    std::vector<uint8_t> bytes = read_fixture(data_path(fixture));
    ASSERT_FALSE(bytes.empty());

    GARC_Stream * stream = nullptr;
    ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
        GARC_OK);
    GARC_Archive * archive = nullptr;
    ASSERT_EQ(garc_open(stream, nullptr, &archive), GARC_OK);

    const GARC_Member * member = nullptr;
    ASSERT_EQ(garc_next(archive, &member), GARC_OK);
    // Longer than the header field, so it can only have come from the carrier.
    EXPECT_GT(member->name_length, 100u);
    const uint32_t findings = garc_name_check(member->name, member->name_length);
    EXPECT_TRUE(findings & GARC_NAME_TRAVERSAL)
        << "the long hostile name lost its traversal on the way through";

    garc_close(archive);
    garc_stream_destroy(stream);
  }
}

TEST(TarHostileNames, ALinkTargetIsHostileWhereTheNameIsNot) {
  // The half of the problem a name check cannot reach from the name. Every member
  // here has an ordinary name and two of them point somewhere they should not -
  // which is why garc_name_check() takes bytes, so the same function answers about
  // a target.
  std::vector<uint8_t> bytes = read_fixture(data_path("mal-links.tar"));
  ASSERT_FALSE(bytes.empty());

  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
      GARC_OK);
  GARC_Archive * archive = nullptr;
  ASSERT_EQ(garc_open(stream, nullptr, &archive), GARC_OK);

  size_t hostile_targets = 0;
  size_t members = 0;
  const GARC_Member * member = nullptr;
  GARC_Result result;
  while ((result = garc_next(archive, &member)) == GARC_OK) {
    ++members;
    SCOPED_TRACE(member_name(member));
    // Every name in this fixture is ordinary, which is the point.
    EXPECT_EQ(garc_name_check(member->name, member->name_length), 0u);
    if (!member->link_target) {
      continue;
    }
    const uint32_t findings
        = garc_name_check(member->link_target, member->link_target_length);
    if (findings & GARC_NAME_ESCAPES) {
      ++hostile_targets;
    }
  }
  EXPECT_EQ(result, GARC_END) << garc_result_string(result);
  EXPECT_EQ(members, 5u);
  EXPECT_EQ(hostile_targets, 2u)
      << "the fixture should hold one absolute target and one that climbs out, "
         "beside a target that does neither";

  garc_close(archive);
  garc_stream_destroy(stream);
}

//-----------------------------------------------------------------------------
// Offsets
//-----------------------------------------------------------------------------

TEST(TarOffsets, TheFirstMemberIsAtTheStartOfTheStream) {
  // Identification reads a block ahead and keeps it, so the stream's own position
  // is a block past the first header while that window is being drained. Reporting
  // it put every archive's first member at offset 512 and every member after it in
  // the right place - which is the shape that looks like a working field.
  for (const char * fixture : readable) {
    SCOPED_TRACE(fixture);
    std::vector<uint8_t> bytes = read_fixture(data_path(fixture));
    ASSERT_FALSE(bytes.empty());

    GARC_Stream * stream = nullptr;
    ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
        GARC_OK);
    GARC_Archive * archive = nullptr;
    ASSERT_EQ(garc_open(stream, nullptr, &archive), GARC_OK);

    const GARC_Member * member = nullptr;
    ASSERT_EQ(garc_next(archive, &member), GARC_OK);
    EXPECT_EQ(member->header_offset, 0u);

    garc_close(archive);
    garc_stream_destroy(stream);
  }
}

TEST(TarOffsets, EveryMemberStartsOnABlockAndItsDataFollowsItsHeader) {
  // Two invariants that together pin the pair of fields, rather than asserting
  // numbers read off this reader's own answers:
  //
  //   - both offsets are multiples of 512, because everything in a tar is;
  //   - the data begins at least one block after the header begins, and exactly
  //     one when nothing was carried in front of it.
  //
  // The second is what says header_offset points at the *carrier* for a member
  // that had one: gnu-longname-blocks.tar's members sit three blocks apart, one
  // carrier and two payload blocks, and a reader reporting the real header would
  // make the gap one everywhere.
  for (const char * fixture : readable) {
    SCOPED_TRACE(fixture);
    std::vector<uint8_t> bytes = read_fixture(data_path(fixture));
    ASSERT_FALSE(bytes.empty());

    GARC_Stream * stream = nullptr;
    ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
        GARC_OK);
    GARC_Archive * archive = nullptr;
    ASSERT_EQ(garc_open(stream, nullptr, &archive), GARC_OK);

    uint64_t previous_data_end = 0;
    const GARC_Member * member = nullptr;
    GARC_Result result;
    while ((result = garc_next(archive, &member)) == GARC_OK) {
      SCOPED_TRACE(member_name(member));
      EXPECT_EQ(member->header_offset % GARC_TAR_BLOCK, 0u);
      EXPECT_EQ(member->data_offset % GARC_TAR_BLOCK, 0u);
      EXPECT_GE(member->data_offset, member->header_offset + GARC_TAR_BLOCK);
      // Nothing between the end of one member's data and the start of the next
      // member's first block: a gap would mean a block this reader consumed and
      // reported to nobody.
      EXPECT_EQ(member->header_offset, previous_data_end);
      const uint64_t remainder = member->size % GARC_TAR_BLOCK;
      previous_data_end = member->data_offset + member->size
          + (remainder ? GARC_TAR_BLOCK - remainder : 0u);
    }
    EXPECT_EQ(result, GARC_END) << garc_result_string(result);

    garc_close(archive);
    garc_stream_destroy(stream);
  }
}

TEST(TarVariant, APaxArchiveWithNoExtendedRecordsReadsAsUstar) {
  // pax's magic *is* ustar's, so an archive in pax format whose names all fit
  // the ustar fields has no extended records in it at all and is a ustar archive
  // in every way a reader can see. Refusing it for the format GNU tar was asked
  // for would refuse most of what `tar --format=pax` writes.
  std::vector<uint8_t> bytes = read_fixture(data_path("pax-basic.tar"));
  ASSERT_FALSE(bytes.empty());

  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
      GARC_OK);
  GARC_Archive * archive = nullptr;
  ASSERT_EQ(garc_open(stream, nullptr, &archive), GARC_OK);

  const GARC_Member * member = nullptr;
  ASSERT_EQ(garc_next(archive, &member), GARC_OK);
  EXPECT_EQ(garc_tar_member_variant(archive), GARC_TAR_USTAR);

  garc_close(archive);
  garc_stream_destroy(stream);
}

TEST(TarVariant, APaxPathRecordReplacesTheHeadersName) {
  // An `x` member carrying a path= record, forced by a name too long for the
  // ustar fields. As with GNU's carrier the two wrong answers are both names: the
  // `x` member reported as a file called `./PaxHeaders/...`, and the real member
  // under the truncated copy in its own header.
  //
  // The four short-named directories in front of it need no record and are read
  // from their headers, so this also pins *which* member the record applied to -
  // an earlier version of this test asserted the refusal would come first, on the
  // theory that pax puts its `x` before the member it describes. It does; the
  // directories ahead of it simply have no `x` at all.
  std::vector<uint8_t> bytes = read_fixture(data_path("pax-longname.tar"));
  ASSERT_FALSE(bytes.empty());

  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
      GARC_OK);
  GARC_Archive * archive = nullptr;
  ASSERT_EQ(garc_open(stream, nullptr, &archive), GARC_OK);

  size_t from_a_record = 0;
  size_t from_the_header = 0;
  const GARC_Member * member = nullptr;
  GARC_Result result;
  while ((result = garc_next(archive, &member)) == GARC_OK) {
    EXPECT_EQ(member_name(member).find("PaxHeaders"), std::string::npos)
        << "the record member was reported as a member";
    if (garc_tar_member_variant(archive) == GARC_TAR_PAX) {
      ++from_a_record;
      EXPECT_GT(member->name_length, 100u);
      // **A name that came from a record carries a declaration.** POSIX says the
      // records are UTF-8, and this archive has no hdrcharset= saying otherwise,
      // so the container did assert an encoding for this name - unlike every name
      // read from a header field, which asserts nothing.
      EXPECT_EQ(member->name_encoding, GARC_NAME_UTF8);
    } else {
      ++from_the_header;
      EXPECT_EQ(member->name_encoding, GARC_NAME_UNDECLARED);
    }
  }
  EXPECT_EQ(result, GARC_END) << garc_result_string(result);
  EXPECT_EQ(from_a_record, 1u);
  EXPECT_EQ(from_the_header, 4u)
      << "every member came through a record, so nothing here shows that one "
         "applies to the member behind it and not to the archive";

  garc_close(archive);
  garc_stream_destroy(stream);
}

TEST(TarVariant, APaxLinkpathRecordIsNotTruncated) {
  // The pax half of the pair gnu-longlink.tar covers for GNU: one target that
  // needs a record and one that fits the header field, in one archive.
  std::vector<uint8_t> bytes = read_fixture(data_path("pax-longlink.tar"));
  ASSERT_FALSE(bytes.empty());

  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
      GARC_OK);
  GARC_Archive * archive = nullptr;
  ASSERT_EQ(garc_open(stream, nullptr, &archive), GARC_OK);

  size_t from_a_record = 0;
  size_t from_the_field = 0;
  const GARC_Member * member = nullptr;
  GARC_Result result;
  while ((result = garc_next(archive, &member)) == GARC_OK) {
    ASSERT_NE(member->link_target, nullptr) << member_name(member);
    if (member->link_target_length > 100u) {
      ++from_a_record;
      EXPECT_EQ(garc_tar_member_variant(archive), GARC_TAR_PAX);
    } else {
      ++from_the_field;
    }
  }
  EXPECT_EQ(result, GARC_END) << garc_result_string(result);
  EXPECT_EQ(from_a_record, 1u);
  EXPECT_EQ(from_the_field, 1u);

  garc_close(archive);
  garc_stream_destroy(stream);
}

TEST(TarVariant, APaxMtimeRecordCarriesAFraction) {
  // The only fixture with a sub-second time, and the only way to get one out of a
  // real writer: with a whole second GNU tar writes no `mtime=` record at all,
  // because the header's octal field already says it. So this is what makes
  // GARC_TIME_PAX_DECIMAL and a non-zero nanoseconds field reachable from
  // something other than a hand-built header.
  std::vector<uint8_t> bytes = read_fixture(data_path("pax-times.tar"));
  ASSERT_FALSE(bytes.empty());

  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
      GARC_OK);
  GARC_Archive * archive = nullptr;
  ASSERT_EQ(garc_open(stream, nullptr, &archive), GARC_OK);

  size_t members = 0;
  const GARC_Member * member = nullptr;
  GARC_Result result;
  while ((result = garc_next(archive, &member)) == GARC_OK) {
    SCOPED_TRACE(member_name(member));
    ++members;
    EXPECT_EQ(member->mtime_seconds, 1000000000);
    EXPECT_EQ(member->mtime_nanoseconds, 123456789u);
    // Which field answered, not only what it said. The same time is in the
    // header's octal field to the second, so a reader that ignored the record
    // would report the right seconds and a zero fraction - and the source is what
    // separates those two answers.
    EXPECT_EQ(member->mtime_source, GARC_TIME_PAX_DECIMAL);
    EXPECT_EQ(garc_tar_member_variant(archive), GARC_TAR_PAX);
  }
  EXPECT_EQ(result, GARC_END) << garc_result_string(result);
  EXPECT_EQ(members, 7u);

  garc_close(archive);
  garc_stream_destroy(stream);
}

TEST(TarVariant, AGlobalHeaderAppliesToEveryMemberAfterIt) {
  // The `g` member, which is the hard one to get a writer to produce: GNU tar
  // writes one only when it has something global to say, and `hdrcharset` is it.
  // What comes out is a global asserting that the record bytes are **not** UTF-8,
  // and an `x` path= record for the non-ASCII name that only exists because of it.
  //
  // So this fixture and pax-longname.tar are a minimal pair on the one axis that
  // matters: both carry a name in a path= record, and they differ only in whether
  // a global says what its bytes are. A reader that took GARC_NAME_UTF8 from the
  // presence of a record rather than from the declaration passes the other test
  // and fails this one.
  std::vector<uint8_t> bytes = read_fixture(data_path("pax-global.tar"));
  ASSERT_FALSE(bytes.empty());

  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
      GARC_OK);
  GARC_Archive * archive = nullptr;
  ASSERT_EQ(garc_open(stream, nullptr, &archive), GARC_OK);

  size_t members = 0;
  const GARC_Member * member = nullptr;
  GARC_Result result;
  while ((result = garc_next(archive, &member)) == GARC_OK) {
    SCOPED_TRACE(member_name(member));
    ++members;
    EXPECT_EQ(member_name(member).find("GlobalHead"), std::string::npos)
        << "the global header was reported as a member";
    // Every member is pax, including the one with no `x` of its own: a global in
    // force is a statement about how this member is read.
    EXPECT_EQ(garc_tar_member_variant(archive), GARC_TAR_PAX);
    EXPECT_EQ(member->name_encoding, GARC_NAME_UNDECLARED)
        << "hdrcharset=BINARY says the bytes are bytes, so nothing is declared";
  }
  EXPECT_EQ(result, GARC_END) << garc_result_string(result);
  EXPECT_EQ(members, 2u);

  garc_close(archive);
  garc_stream_destroy(stream);
}

TEST(TarVariant, AnEmptyArchiveIsAnArchive) {
  // Two zero blocks and nothing else. It identifies as a tar even though no
  // header in it validates, and the first garc_next() is the end - not an error,
  // and not a member.
  std::vector<uint8_t> bytes = read_fixture(data_path("ustar-empty.tar"));
  ASSERT_FALSE(bytes.empty());

  GARC_Stream * stream = nullptr;
  ASSERT_EQ(garc_stream_create_memory(bytes.data(), bytes.size(), &stream),
      GARC_OK);
  GARC_Archive * archive = nullptr;
  ASSERT_EQ(garc_open(stream, nullptr, &archive), GARC_OK);
  EXPECT_EQ(garc_format(archive), GARC_FORMAT_TAR);

  const GARC_Member * member = nullptr;
  EXPECT_EQ(garc_next(archive, &member), GARC_END);
  EXPECT_FALSE(garc_result_is_error(GARC_END));
  EXPECT_EQ(garc_member_count(archive), 0u);

  garc_close(archive);
  garc_stream_destroy(stream);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
