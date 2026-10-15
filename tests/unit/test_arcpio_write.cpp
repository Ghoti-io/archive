/**
 * @file
 *
 * Writing ar, cpio and shar.
 *
 * What these tests can say is bounded: ar and cpio are read back by this
 * library's reader, which agrees with the writer by construction, so the strong
 * half is `make check-arcpio-writer`, which hands the same archives to libarchive
 * and compares what it says with what was meant. Here: the exact bytes of small
 * cases, the refusals, and the shell script, which is checked as text and then
 * run by `sh`.
 *
 * Copyright 2026 by Corey Pennycuff
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <ghoti.io/cutil/dir.h>
#include <ghoti.io/cutil/file.h>

#include "failing_allocator.h"
#include "sevenz_builder.h"
#include "test_helpers.h"

using garctest::BufferSource;

namespace {

struct Spec {
  std::string name;
  GARC_Member_Type type = GARC_MEMBER_FILE;
  std::string data;
  std::string link;
  uint32_t mode = 0644;
  int64_t mtime = 1000000000;
  int64_t uid = 0;
  int64_t gid = 0;
  uint32_t major = 0;
  uint32_t minor = 0;
};

GARC_Member member_of(const Spec & spec) {
  GARC_Member member;
  std::memset(&member, 0, sizeof(member));
  member.name = spec.name.data();
  member.name_length = spec.name.size();
  member.type = spec.type;
  member.size = spec.type == GARC_MEMBER_FILE ? spec.data.size() : 0;
  member.mode = spec.mode;
  member.mode_valid = 1;
  member.mtime_seconds = spec.mtime;
  member.mtime_source = GARC_TIME_UNIX;
  member.uid = spec.uid;
  member.gid = spec.gid;
  member.ids_valid = 1;
  member.device_major = spec.major;
  member.device_minor = spec.minor;
  if (!spec.link.empty()) {
    member.link_target = spec.link.data();
    member.link_target_length = spec.link.size();
  }
  return member;
}

class Built {
public:
  explicit Built(GARC_Format format, GARC_Cpio_Variant variant = GARC_CPIO_NEWC,
      bool uu = false) {
    if (garc_sink_create_memory(&sink_) != GARC_OK) {
      return;
    }
    GARC_Writer_Options options;
    garc_writer_options_default(&options);
    options.cpio_variant = variant;
    options.shar_uuencode = uu ? 1 : 0;
    create_result_ = garc_writer_create(sink_, format, &options, &writer_);
  }
  ~Built() {
    garc_writer_destroy(writer_);
    garc_sink_destroy(sink_);
  }
  Built(const Built &) = delete;
  Built & operator=(const Built &) = delete;

  GARC_Result create_result() const { return create_result_; }
  GARC_Writer * writer() const { return writer_; }

  GARC_Result add(const Spec & spec) {
    const GARC_Member member = member_of(spec);
    GARC_Result result = garc_writer_add(writer_, &member);
    if (result != GARC_OK || spec.type != GARC_MEMBER_FILE
        || spec.data.empty()) {
      return result;
    }
    return garc_writer_write(writer_, spec.data.data(), spec.data.size());
  }
  GARC_Result finish() { return garc_writer_finish(writer_); }

  std::string text() const {
    const void * data = nullptr;
    size_t size = 0;
    if (garc_sink_data(sink_, &data, &size) != GARC_OK) {
      return "";
    }
    return std::string(static_cast<const char *>(data), size);
  }

private:
  GARC_Sink * sink_ = nullptr;
  GARC_Writer * writer_ = nullptr;
  GARC_Result create_result_ = GARC_ERR_INTERNAL;
};

struct Read {
  GARC_Member_Type type;
  uint32_t mode;
  int64_t mtime;
  int64_t uid;
  int64_t gid;
  uint32_t major;
  uint32_t minor;
  std::string data;
  std::string link;
  GARC_Result status;
};

GARC_Result read_back(const std::string & text, std::map<std::string, Read> * out,
    std::vector<std::string> * order = nullptr, bool can_seek = true) {
  BufferSource source(text.data(), text.size(), can_seek, can_seek);
  GARC_Stream * stream = nullptr;
  if (garc_stream_create_callback(source.callbacks(), &stream) != GARC_OK) {
    return GARC_ERR_INTERNAL;
  }
  GARC_Archive * archive = nullptr;
  GARC_Result result = garc_open(stream, nullptr, &archive);
  if (result == GARC_OK) {
    const GARC_Member * member = nullptr;
    while ((result = garc_next(archive, &member)) == GARC_OK) {
      Read read{};
      read.type = member->type;
      read.mode = member->mode;
      read.mtime = member->mtime_seconds;
      read.uid = member->uid;
      read.gid = member->gid;
      read.major = member->device_major;
      read.minor = member->device_minor;
      if (member->link_target) {
        read.link.assign(member->link_target, member->link_target_length);
      }
      char buffer[257];
      size_t got = 0;
      while ((read.status = garc_read_member(archive, buffer, sizeof(buffer),
                  &got)) == GARC_OK
          && got) {
        read.data.append(buffer, got);
      }
      const std::string name(member->name, member->name_length);
      (*out)[name] = read;
      if (order) {
        order->push_back(name);
      }
    }
  }
  garc_close(archive);
  garc_stream_destroy(stream);
  return result;
}

Spec file(const std::string & name, const std::string & data) {
  Spec s;
  s.name = name;
  s.data = data;
  return s;
}

}  // namespace

//-----------------------------------------------------------------------------
// ar
//-----------------------------------------------------------------------------

TEST(ArWrite, AShortNameIsWrittenTheSystemVWayAndPaddedToEven) {
  Built built(GARC_FORMAT_AR);
  ASSERT_EQ(built.create_result(), GARC_OK);
  ASSERT_EQ(built.add(file("a.txt", "hello")), GARC_OK);
  ASSERT_EQ(built.finish(), GARC_OK);
  const std::string want = std::string("!<arch>\n")
      + "a.txt/          1000000000  0     0     100644  5         `\n"
      + "hello\n";
  EXPECT_EQ(built.text(), want);
}

TEST(ArWrite, NamesThatCannotBeSystemVAreWrittenTheBsdWay) {
  const std::vector<std::string> names = {
      "exactly15chars!", "sixteen-chars-xy", "has/slash", "trailing ", "/lead",
      "#1/looks-like-one", "a-name-that-is-much-longer-than-sixteen-bytes.txt",
      "x"};
  Built built(GARC_FORMAT_AR);
  ASSERT_EQ(built.create_result(), GARC_OK);
  for (size_t i = 0; i < names.size(); ++i) {
    ASSERT_EQ(built.add(file(names[i], std::string(i + 1, 'd'))), GARC_OK)
        << names[i];
  }
  ASSERT_EQ(built.finish(), GARC_OK);
  for (bool can_seek : {true, false}) {
    std::map<std::string, Read> got;
    std::vector<std::string> order;
    ASSERT_EQ(read_back(built.text(), &got, &order, can_seek), GARC_END);
    ASSERT_EQ(order, names);
    for (size_t i = 0; i < names.size(); ++i) {
      EXPECT_EQ(got[names[i]].data, std::string(i + 1, 'd')) << names[i];
      EXPECT_EQ(got[names[i]].status, GARC_OK);
    }
  }
  // The 15-byte name fits the field with its slash and stays System V.
  EXPECT_NE(built.text().find("exactly15chars!/"), std::string::npos);
  EXPECT_NE(built.text().find("#1/16"), std::string::npos);
}

TEST(ArWrite, MetadataSurvivesAndAnEmptyArchiveIsTheMagic) {
  {
    Built built(GARC_FORMAT_AR);
    Spec s = file("m", "x");
    s.mode = 0755;
    s.uid = 1000;
    s.gid = 2000;
    s.mtime = 1700000000;
    ASSERT_EQ(built.add(s), GARC_OK);
    ASSERT_EQ(built.finish(), GARC_OK);
    std::map<std::string, Read> got;
    ASSERT_EQ(read_back(built.text(), &got), GARC_END);
    EXPECT_EQ(got["m"].mode, 0755u);
    EXPECT_EQ(got["m"].uid, 1000);
    EXPECT_EQ(got["m"].gid, 2000);
    EXPECT_EQ(got["m"].mtime, 1700000000);
  }
  {
    Built built(GARC_FORMAT_AR);
    ASSERT_EQ(built.finish(), GARC_OK);
    EXPECT_EQ(built.text(), "!<arch>\n");
  }
}

TEST(ArWrite, RefusalsWriteNothing) {
  struct Case {
    const char * what;
    Spec spec;
    GARC_Result expect;
  };
  std::vector<Case> cases;
  {
    Spec s;
    s.name = "d";
    s.type = GARC_MEMBER_DIRECTORY;
    cases.push_back({"a directory", s, GARC_ERR_UNSUPPORTED});
  }
  {
    Spec s;
    s.name = "l";
    s.type = GARC_MEMBER_SYMLINK;
    s.link = "t";
    cases.push_back({"a symlink", s, GARC_ERR_UNSUPPORTED});
  }
  {
    Spec s = file("", "x");
    cases.push_back({"an empty name", s, GARC_ERR_INVALID});
  }
  {
    Spec s = file(std::string("a\0b", 3), "x");
    cases.push_back({"a NUL in the name", s, GARC_ERR_INVALID});
  }
  {
    Spec s = file("u", "x");
    s.uid = 1000000;
    cases.push_back({"an owner id that does not fit six digits", s,
        GARC_ERR_INVALID});
  }
  {
    Spec s = file("t", "x");
    s.mtime = -1;
    cases.push_back({"a time before the epoch", s, GARC_ERR_INVALID});
  }
  for (const Case & one : cases) {
    SCOPED_TRACE(one.what);
    Built built(GARC_FORMAT_AR);
    EXPECT_EQ(built.add(one.spec), one.expect);
    EXPECT_EQ(built.add(file("fine", "ok")), GARC_OK);
    EXPECT_EQ(built.finish(), GARC_OK);
    std::map<std::string, Read> got;
    EXPECT_EQ(read_back(built.text(), &got), GARC_END);
    EXPECT_EQ(got.size(), 1u);
  }
}

//-----------------------------------------------------------------------------
// cpio
//-----------------------------------------------------------------------------

namespace {

std::vector<Spec> cpio_corpus() {
  std::vector<Spec> specs;
  specs.push_back(file("a.txt", "alpha\n"));
  Spec dir;
  dir.name = "dir";
  dir.type = GARC_MEMBER_DIRECTORY;
  dir.mode = 0755;
  specs.push_back(dir);
  Spec link;
  link.name = "dir/link";
  link.type = GARC_MEMBER_SYMLINK;
  link.link = "../a.txt";
  link.mode = 0777;
  specs.push_back(link);
  specs.push_back(file("empty", ""));
  for (size_t n : {1u, 2u, 3u, 4u, 5u}) {
    specs.push_back(file("s" + std::to_string(n), std::string(n, 'p')));
  }
  Spec fifo;
  fifo.name = "fifo";
  fifo.type = GARC_MEMBER_FIFO;
  specs.push_back(fifo);
  Spec chr;
  chr.name = "chr";
  chr.type = GARC_MEMBER_CHAR_DEVICE;
  chr.major = 4;
  chr.minor = 64;
  specs.push_back(chr);
  Spec blk;
  blk.name = "blk";
  blk.type = GARC_MEMBER_BLOCK_DEVICE;
  blk.major = 8;
  blk.minor = 1;
  specs.push_back(blk);
  Spec owned = file("owned", "mine");
  owned.uid = 1234;
  owned.gid = 4321;
  owned.mtime = 1700000000;
  specs.push_back(owned);
  Spec big = file("big", "");
  for (size_t i = 0; i < 100000; ++i) {
    big.data.push_back(static_cast<char>('a' + i % 23));
  }
  specs.push_back(big);
  specs.push_back(file(std::string(300, 'n'), "long name"));
  return specs;
}

}  // namespace

TEST(CpioWrite, BothDialectsRoundTripEveryKindOfMember) {
  for (GARC_Cpio_Variant variant : {GARC_CPIO_NEWC, GARC_CPIO_ODC}) {
    SCOPED_TRACE(static_cast<int>(variant));
    Built built(GARC_FORMAT_CPIO, variant);
    ASSERT_EQ(built.create_result(), GARC_OK);
    const std::vector<Spec> specs = cpio_corpus();
    for (const Spec & spec : specs) {
      ASSERT_EQ(built.add(spec), GARC_OK) << spec.name.substr(0, 20);
    }
    ASSERT_EQ(built.finish(), GARC_OK);
    EXPECT_EQ(built.text().size() % 512u, 0u);
    for (bool can_seek : {true, false}) {
      std::map<std::string, Read> got;
      std::vector<std::string> order;
      ASSERT_EQ(read_back(built.text(), &got, &order, can_seek), GARC_END);
      ASSERT_EQ(order.size(), specs.size());
      for (size_t i = 0; i < specs.size(); ++i) {
        const Spec & spec = specs[i];
        SCOPED_TRACE(spec.name.substr(0, 20));
        EXPECT_EQ(order[i], spec.name);
        const Read & read = got[spec.name];
        EXPECT_EQ(read.type, spec.type);
        EXPECT_EQ(read.mode & 07777u, spec.mode);
        EXPECT_EQ(read.mtime, spec.mtime);
        EXPECT_EQ(read.uid, spec.uid);
        EXPECT_EQ(read.gid, spec.gid);
        EXPECT_EQ(read.status, GARC_OK);
        if (spec.type == GARC_MEMBER_FILE) {
          EXPECT_EQ(read.data, spec.data);
        }
        if (spec.type == GARC_MEMBER_SYMLINK) {
          EXPECT_EQ(read.link, spec.link);
        }
        if (spec.type == GARC_MEMBER_CHAR_DEVICE
            || spec.type == GARC_MEMBER_BLOCK_DEVICE) {
          EXPECT_EQ(read.major, spec.major);
          EXPECT_EQ(read.minor, spec.minor);
        }
      }
    }
  }
}

TEST(CpioWrite, ANewcHeaderIsExactlyWhatTheFormatSays) {
  Built built(GARC_FORMAT_CPIO);
  ASSERT_EQ(built.add(file("ab", "xyz")), GARC_OK);
  ASSERT_EQ(built.finish(), GARC_OK);
  const std::string text = built.text();
  // 070701, inode 1, mode 100644, ids 0, nlink 1, mtime 1e9, size 3, devices 0,
  // rdev 0, namesize 3, check 0; then "ab\0" and one pad byte; then "xyz\0".
  const std::string want = "070701" "00000001" "000081a4" "00000000" "00000000"
      "00000001" "3b9aca00" "00000003" "00000000" "00000000" "00000000"
      "00000000" "00000003" "00000000" + std::string("ab\0\0\0\0", 6)
      + std::string("xyz\0", 4);
  EXPECT_EQ(text.substr(0, want.size()), want);
  EXPECT_NE(text.find("TRAILER!!!"), std::string::npos);
}

TEST(CpioWrite, AnOdcHeaderIsExactlyWhatTheFormatSays) {
  Built built(GARC_FORMAT_CPIO, GARC_CPIO_ODC);
  ASSERT_EQ(built.add(file("ab", "xyz")), GARC_OK);
  ASSERT_EQ(built.finish(), GARC_OK);
  const std::string want = "070707" "000000" "000001" "100644" "000000" "000000"
      "000001" "000000" "07346545000" "000003" "00000000003" + std::string("ab\0", 3)
      + "xyz";
  EXPECT_EQ(built.text().substr(0, want.size()), want);
}

TEST(CpioWrite, RefusalsWriteNothing) {
  struct Case {
    const char * what;
    Spec spec;
    GARC_Result expect;
    GARC_Cpio_Variant variant;
  };
  std::vector<Case> cases;
  {
    Spec s;
    s.name = "h";
    s.type = GARC_MEMBER_HARDLINK;
    s.link = "t";
    cases.push_back({"a hard link", s, GARC_ERR_UNSUPPORTED, GARC_CPIO_NEWC});
  }
  {
    Spec s;
    s.name = "o";
    s.type = GARC_MEMBER_OTHER;
    cases.push_back({"another type", s, GARC_ERR_UNSUPPORTED, GARC_CPIO_NEWC});
  }
  cases.push_back({"the trailer's own name", file("TRAILER!!!", "x"),
      GARC_ERR_INVALID, GARC_CPIO_NEWC});
  cases.push_back({"an empty name", file("", "x"), GARC_ERR_INVALID,
      GARC_CPIO_NEWC});
  {
    Spec s = file("u", "x");
    s.uid = 0777777 + 1;
    cases.push_back({"an odc owner id over six octal digits", s,
        GARC_ERR_INVALID, GARC_CPIO_ODC});
  }
  {
    Spec s = file("t", "x");
    s.mtime = -5;
    cases.push_back({"a time before the epoch", s, GARC_ERR_INVALID,
        GARC_CPIO_NEWC});
  }
  {
    Spec s;
    s.name = "c";
    s.type = GARC_MEMBER_CHAR_DEVICE;
    s.major = 300;
    cases.push_back({"an odc device number over a byte", s, GARC_ERR_INVALID,
        GARC_CPIO_ODC});
  }
  {
    Spec s;
    s.name = "d";
    s.type = GARC_MEMBER_DIRECTORY;
    s.data = "x";
    GARC_Member probe = member_of(s);
    (void)probe;
    cases.push_back({"a symlink with no target", [] {
      Spec l;
      l.name = "l";
      l.type = GARC_MEMBER_SYMLINK;
      return l;
    }(), GARC_ERR_INVALID, GARC_CPIO_NEWC});
  }
  for (const Case & one : cases) {
    SCOPED_TRACE(one.what);
    Built built(GARC_FORMAT_CPIO, one.variant);
    EXPECT_EQ(built.add(one.spec), one.expect);
    EXPECT_EQ(built.add(file("fine", "ok")), GARC_OK);
    EXPECT_EQ(built.finish(), GARC_OK);
    std::map<std::string, Read> got;
    EXPECT_EQ(read_back(built.text(), &got), GARC_END);
    EXPECT_EQ(got.size(), 1u);
  }
}

TEST(CpioWrite, AnUnknownVariantIsInvalid) {
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  GARC_Writer_Options options;
  garc_writer_options_default(&options);
  options.cpio_variant = static_cast<GARC_Cpio_Variant>(7);
  GARC_Writer * writer = nullptr;
  EXPECT_EQ(garc_writer_create(sink, GARC_FORMAT_CPIO, &options, &writer),
      GARC_ERR_INVALID);
  garc_sink_destroy(sink);
}

//-----------------------------------------------------------------------------
// shar
//-----------------------------------------------------------------------------

TEST(SharWrite, ATextScriptIsExactlyWhatItShouldBe) {
  Built built(GARC_FORMAT_SHAR);
  Spec dir;
  dir.name = "d";
  dir.type = GARC_MEMBER_DIRECTORY;
  dir.mode = 0755;
  ASSERT_EQ(built.add(dir), GARC_OK);
  ASSERT_EQ(built.add(file("d/it's", "one\ntwo\n")), GARC_OK);
  ASSERT_EQ(built.add(file("empty", "")), GARC_OK);
  Spec link;
  link.name = "l";
  link.type = GARC_MEMBER_SYMLINK;
  link.link = "d/it's";
  ASSERT_EQ(built.add(link), GARC_OK);
  ASSERT_EQ(built.finish(), GARC_OK);
  const std::string want =
      "#!/bin/sh\n"
      "# This is a shell archive, written by Ghoti.io Archive.\n"
      "# Read it before running it: it creates exactly the files it names.\n"
      "echo x 'd'\n"
      "mkdir -p 'd'\n"
      "chmod 755 'd'\n"
      "echo x 'd/it'\\''s'\n"
      "sed 's/^X//' > 'd/it'\\''s' << 'SHAR_END'\n"
      "Xone\n"
      "Xtwo\n"
      "SHAR_END\n"
      "chmod 644 'd/it'\\''s'\n"
      "echo x 'empty'\n"
      ": > 'empty'\n"
      "chmod 644 'empty'\n"
      "echo x 'l'\n"
      "ln -fs 'd/it'\\''s' 'l'\n"
      "exit 0\n";
  EXPECT_EQ(built.text(), want);
}

TEST(SharWrite, AUuencodedScriptCarriesAnyBytes) {
  Built built(GARC_FORMAT_SHAR, GARC_CPIO_NEWC, true);
  Spec s = file("b", std::string("abc"));
  s.mode = 0600;
  ASSERT_EQ(built.add(s), GARC_OK);
  ASSERT_EQ(built.add(file("z", std::string("\0\xFF\0", 3))), GARC_OK);
  ASSERT_EQ(built.finish(), GARC_OK);
  const std::string text = built.text();
  EXPECT_NE(text.find("uudecode << 'SHAR_END'\nbegin 600 b\n#86)C\n`\nend\nSHAR_END\n"),
      std::string::npos);
  EXPECT_NE(text.find("begin 644 z\n#`/\\`\n`\nend"), std::string::npos)
      << text;
}

TEST(SharWrite, TextModeRefusesWhatItCannotCarry) {
  {
    Built built(GARC_FORMAT_SHAR);
    EXPECT_EQ(built.add(file("n", std::string("a\0b\n", 4))),
        GARC_ERR_UNSUPPORTED);
  }
  {
    Built built(GARC_FORMAT_SHAR);
    ASSERT_EQ(built.add(file("m", "no newline")), GARC_OK);
    EXPECT_EQ(built.finish(), GARC_ERR_UNSUPPORTED);
  }
  {
    Built built(GARC_FORMAT_SHAR);
    EXPECT_EQ(built.add(file("a\nb", "x\n")), GARC_ERR_INVALID);
    Spec o;
    o.name = "o";
    o.type = GARC_MEMBER_FIFO;
    EXPECT_EQ(built.add(o), GARC_ERR_UNSUPPORTED);
  }
}

TEST(SharWrite, TheScriptWhenRunRecreatesTheTree) {
  char * made = nullptr;
  ASSERT_EQ(GCU_FILE_OK, gcu_dir_temp_create(nullptr, "garc-shar", nullptr, &made));
  const std::string root = made;
  gcu_dir_free_path(nullptr, made);

  Built built(GARC_FORMAT_SHAR);
  Spec dir;
  dir.name = "sub";
  dir.type = GARC_MEMBER_DIRECTORY;
  dir.mode = 0755; // A directory without x would refuse its own contents.
  ASSERT_EQ(built.add(dir), GARC_OK);
  std::string body;
  for (int i = 0; i < 2000; ++i) {
    body += "line " + std::to_string(i) + " X and $HOME `date` 'quoted'\n";
  }
  ASSERT_EQ(built.add(file("sub/it's a file", body)), GARC_OK);
  ASSERT_EQ(built.add(file("plain", "p\n")), GARC_OK);
  ASSERT_EQ(built.finish(), GARC_OK);

  const std::string script = root + "/script.sh";
  FILE * out = fopen(script.c_str(), "wb");
  ASSERT_NE(out, nullptr);
  const std::string text = built.text();
  fwrite(text.data(), 1, text.size(), out);
  fclose(out);

  const std::string command = "cd '" + root + "' && sh script.sh > /dev/null";
  ASSERT_EQ(std::system(command.c_str()), 0);

  auto slurp = [](const std::string & path) {
    std::string s;
    FILE * f = fopen(path.c_str(), "rb");
    if (!f) {
      return s;
    }
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
      s.append(buf, n);
    }
    fclose(f);
    return s;
  };
  EXPECT_EQ(slurp(root + "/sub/it's a file"), body);
  EXPECT_EQ(slurp(root + "/plain"), "p\n");
  const std::string cleanup = "rm -rf '" + root + "'";
  EXPECT_EQ(std::system(cleanup.c_str()), 0);
}

//-----------------------------------------------------------------------------
// All three: allocation failure, and a writer left half way
//-----------------------------------------------------------------------------

TEST(ArCpioWrite, AWriterDestroyedMidArchiveFreesEverything) {
  for (GARC_Format format :
      {GARC_FORMAT_AR, GARC_FORMAT_CPIO, GARC_FORMAT_SHAR}) {
    garctest::FailingAllocator allocator(static_cast<size_t>(-1));
    {
      GARC_Sink * sink = nullptr;
      ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
      GARC_Writer * writer = nullptr;
      ASSERT_EQ(garc_writer_create_with_allocator(sink, format, nullptr,
                    allocator.get(), &writer),
          GARC_OK);
      const Spec spec = file("a", "data\n");
      const GARC_Member member = member_of(spec);
      ASSERT_EQ(garc_writer_add(writer, &member), GARC_OK);
      garc_writer_destroy(writer);
      garc_sink_destroy(sink);
    }
    EXPECT_EQ(allocator.live(), 0u);
  }
}

TEST(ArCpioWrite, ARefusedFormatCombinationIsStillRefused) {
  GARC_Sink * sink = nullptr;
  ASSERT_EQ(garc_sink_create_memory(&sink), GARC_OK);
  GARC_Writer * writer = nullptr;
  EXPECT_EQ(garc_writer_create(sink, GARC_FORMAT_COUNT, nullptr, &writer),
      GARC_ERR_UNSUPPORTED);
  garc_sink_destroy(sink);
}

int main(int argc, char ** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
