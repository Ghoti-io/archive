# Ghoti.io Archive

Archive containers — tar and zip — read and written **without touching the
filesystem**. This library walks the members of an archive and hands you each
one's name, size, time and bytes; it never opens, creates or writes a file. The
one part that does is opt-in, arrives later, and lives in a header of its own.

That is not squeamishness. Every well-known archive vulnerability is a *path*
vulnerability — a member named `../../etc/cron.d/x`, a symlink whose target
escapes the extraction root, a hardlink doing the same with no target string to
inspect — and a library that hands you a name and a byte range cannot commit
one. It also makes a corpus of malicious archives something that runs on every
commit rather than something a fuzzer has to find its way to.

What this library *does* offer is a vocabulary for saying what is wrong with a
name, checked against what two pinned extractors actually do with it. What it
does not offer is a verdict on whether extracting one is safe, because that
cannot be answered from a name: a member called `docs/readme` has nothing wrong
with it and escapes any root you like if an earlier member made `docs` a symlink
to `/`.

Codecs are [Ghoti.io Compress](https://github.com/Ghoti-io/compress)'s job: a
zip member stored with method 8 *is* RFC 1951, and `tar.zst` is a tar stream
through a compress decoder. This library is the container, not the compression.

## Status

**Reads tar - all four of them.** v7, ustar, GNU's `L`/`K` members and pax's
`x`/`g` records, from a file or a pipe. What is refused, by name and with
`GARC_ERR_UNSUPPORTED`, is a *sparse* member: there the data is a map of holes and
extents rather than the file's contents, so reading it as contents would be a
wrong answer rather than a missing feature.

The fixtures are written by GNU tar 1.35 in a pinned container and the
expectations come from Python 3.13.5's `tarfile` and libarchive 3.7.4's bsdtar,
so a passing test is three implementations agreeing rather than this library
agreeing with itself.

**Names are classified, not cleaned.** `garc_name_check()` reports what is
dangerous about a member name or a link target - traversal, absolute, drive
letter, a NUL, a Windows device name, malformed UTF-8 - one finding at a time,
and the reader hands over the bytes the archive actually holds. It is a
classifier and not a permission: see `examples/name_findings.c`, which prints why.

**Writes pax** — a ustar header with every field filled in, and an extended
record only for what ustar cannot say, so a reader that knows only POSIX.1-1988
gets a correct answer wherever one exists in its vocabulary. `GARC_TAR_USTAR`
writes the same headers and *refuses*, by name, anything that would need a record:
a caller who needs an archive a 1988 reader can read wants to be told rather than
handed one with records in it. No zip writer yet, and no filesystem layer.

**Reads zip, backwards, from the central directory.** The end record is found by
scanning back from the end of the stream - at most 65,557 bytes, with every
candidate validated rather than the last signature taken - and every value
reported about a member comes from the **central directory**. The local header is
read for exactly one thing: where the member's data starts, which only it can say,
because its name and extra fields are sized independently of the directory's.

That is not a preference. libarchive writes a data descriptor for every member
with data, even into a seekable file, so its local headers say a size of zero
where its central directory says fifteen - and a reader that believed them would
report every member of an ordinary archive as empty. Where the two disagree
deliberately, following the directory is what every real tool does, which makes
trusting the local header the root of the whole class of zip confusion bugs. This
reader also **refuses a local header whose name is not the directory's**: an
archive saying two different things about which member this is has nothing else to
be.

zip64 is read as the format defines it - a value is in a 0x0001 extra field only
for the fields that hold the `0xFFFFFFFF` marker, which is why `zip -fz` produces
an eight-byte field where a reader consuming the values positionally expects
sixteen. Method 0 is read; 8, 9, 12, 14, 93 and 98 are refused with a status and
an accessor that **name the method number**, so the refusal is a to-do list.
ZipCrypto and WinZip AES are named separately from each other and from
"unsupported", because a caller needs to know whether a password could ever help.
Reading a zip needs a seekable stream, and a zip on a pipe is
`GARC_ERR_NOT_SEEKABLE` rather than "not an archive".

The zip fixtures are 23 archives from four writers - Info-ZIP's `zip`,
libarchive's `bsdtar`, 7-Zip and Python's `zipfile` - with what `zipfile` and
`bsdtar` read out of them and what all four references *do* when handed one,
because zip has no GNU tar to take one idea of the format from. They disagree
already: an archive comment holding the bytes `PK\x05\x06` is read correctly by
three of them and refused by Python, and a zip behind a self-extracting stub is
read by bsdtar and Python and refused by unzip and 7-Zip. Where no writer produces
the input a refusal needs - a header that contradicts its directory, a member count
that is wrong, a zip64 field one value short - the archive is built byte by byte in
the test, from a control archive this library reads.

**Reads and writes `tar.gz`, `tar.zst` and `tar.lz4`, with no format code for
any of them.** A codec wraps the stream or the sink, the tar reader and writer
see the same interface they always saw, and the codec is named by a **string**
rather than an enum — an enum here would be a second copy of compress's list of
methods, and the copy goes stale. What a compressed archive gives up is
random access: it has no seek and no size, which is the same shape as a pipe, so
`garc_find()` on one is `GARC_ERR_NOT_SEEKABLE` permanently rather than quietly
linear.

**`garc_find()` is a scan and says so.** tar has no index and cannot gain one, so
finding a name means reading every header until it appears; the function exists so
that the walk back to the start is written once — resetting an inherited pax global
record set on the way is easy to forget — rather than in every caller. A format
with a central directory overrides it later with a real lookup.

The three reference writers disagree about nearly every spelling in a pax header —
the digits in a numeric field, whether to use the ustar name split, what the
extended header is called — so each was measured and each choice is argued in
`documentation/design.md` rather than copied.

Build clean under GCC 14 with `-Werror`; 481 tests; 99.4% line coverage of 2,677
lines, with the zip reader at 100%; the seventeen uncovered lines are four
`default:` arms no input can reach - kept so that a third format added to an enum
and not to a switch is a named internal error rather than a silent fall-through -
seven arms only a codec that broke its own contract reaches, and the six this
library has always had, three of which are live only where `size_t` is 32 bits and
one of which needs a pax record set larger than `INT64_MAX`. Clean under Valgrind
and under ASan+UBSan; `check-symbols`, `check-aliasing`, `check-corpus-hashes`,
`check-fixtures` and `check-docs` green, the last at zero Doxygen warnings; five
fuzz harnesses.

## A minimal complete program

```c
#include <stdio.h>
#include <ghoti.io/archive/archive.h>

static GARC_Result read_cb(
    void * ctx, void * buffer, size_t size, size_t * out_read) {
  FILE * file = (FILE *)ctx;
  size_t got = fread(buffer, 1, size, file);
  if (got < size && ferror(file)) {
    return GARC_ERR_IO;
  }
  *out_read = got;   // A short read is the end of the stream, not a failure.
  return GARC_OK;
}

int main(void) {
  FILE * file = fopen("archive.tar", "rb");
  if (!file) {
    return 1;
  }

  // The fopen is yours. The library sees one function pointer; seek and size are
  // optional, and tar does not need them.
  GARC_Stream_Callbacks callbacks = {.read = read_cb, .ctx = file};
  GARC_Stream * stream = NULL;
  if (garc_stream_create_callback(&callbacks, &stream) != GARC_OK) {
    fclose(file);
    return 1;
  }

  GARC_Archive * archive = NULL;
  // NULL limits means garc_limits_default(), which is bounded on every field.
  if (garc_open(stream, NULL, &archive) != GARC_OK) {
    garc_stream_destroy(stream);
    fclose(file);
    return 1;
  }

  const GARC_Member * member = NULL;
  GARC_Result result;
  while ((result = garc_next(archive, &member)) == GARC_OK) {
    // A name is bytes and a length, not a string: a hostile archive puts a NUL
    // in the middle of one so that a C caller sees a shorter name than this did.
    printf("%-9s %8llu %.*s\n", garc_member_type_string(member->type),
        (unsigned long long)member->size, (int)member->name_length,
        member->name);
  }
  // GARC_END is the end of a well-formed archive and is not a failure, which is
  // why this asks the predicate rather than comparing against GARC_OK.
  if (garc_result_is_error(result)) {
    fprintf(stderr, "%s\n", garc_result_string(result));
  }

  garc_close(archive);
  garc_stream_destroy(stream);
  fclose(file);
  return 0;
}
```

`examples/tar_list.c` is that with the member data read as well, and the names
escaped - which a listing tool has to do, because a name is attacker-controlled
bytes and an ANSI escape in one makes the output say whatever the archive wants.
`examples/stream_from_file.c` is the stream on its own, with `seek` and `size`
filled in as a zip reader will need. `examples/name_findings.c` judges an archive
without reading a byte of member data: it classifies every name and every link
target, prints what is wrong with each, and exits non-zero if anything names a
place outside a root — which works on a pipe, since that is when you most want to
refuse.

## Building

Depends on [Ghoti.io CUtil](https://github.com/Ghoti-io/cutil), found through
pkg-config. Nothing else.

```bash
make            # the shared and static libraries
make test       # build and run the tests, and the gates
make help       # every target
```

Building against a prefix rather than the system:

```bash
export PKG_CONFIG_PATH=/path/to/prefix/share/pkgconfig
make test PREFIX=/path/to/prefix
```

## The API

**Walking an archive.** `garc_open()` identifies the container, `garc_next()`
steps through the members, `garc_read_member()` reads the bytes of one into your
buffer. Three things about that loop:

- **`garc_next()` is a cursor, not an index.** A cursor is the only thing tar can
  offer, and one API both formats satisfy is worth more than two that fit each
  perfectly. Random access will be an *addition* for zip, not a second mode.
- **Unread data is skipped for you.** Stepping past a member you do not want is
  normal and cheap - seeking when the stream can, discarding when it cannot.
- **A member is borrowed**, valid until the next `garc_next()`, and its name is
  bytes plus a length rather than a NUL-terminated string.
- **Some members are not members.** tar puts anything that will not fit a header -
  a long name, a long link target, a sub-second time - in a block of its own in
  front of the real one. Those never reach you: a listing that showed a file called
  `././@LongLink` or `./PaxHeaders/x` would be reporting an artefact of the format,
  and the member behind it under a truncated name.

Every field of a member is **what the container declared**, not what this library
believes. A member's `size` is the size the header gave; whether that many bytes
were there is a separate answer, reported when the data is read. That distinction
is what lets a reader say *the archive lied* rather than quietly agreeing.

The stream is **borrowed** too: `garc_close()` does not destroy it, because this
library never frees what it did not allocate.

**Results.** Every call that can fail returns a `GARC_Result`. `GARC_OK` is
zero. Two things about the vocabulary are worth knowing before you write a
loop:

- **`GARC_END` is neither success nor failure.** Walking an archive ends, and
  the end of a well-formed archive is not an error. Use
  `garc_result_is_error()`; `result != GARC_OK` would report a failure on every
  complete read.
- **Each limit has a status of its own.** There is no bare `GARC_ERR_LIMIT`.
  One code for every cap cannot tell an absent cap from a defeated one, nor
  tell you which cap you need to raise. `garc_result_is_limit()` answers "was
  it a cap" without enumerating them.

`garc_result_string()` maps any result to a static string, and every limit's
string names which limit.

**Limits.** `GARC_Limits` caps the members walked, one member's declared size,
their sum, a name's length, and the extra fields held for one member - in tar,
pax's extended records, which are unbounded in the format.
`garc_limits_default()` fills it in, and unlike its siblings elsewhere in the
suite **every default is non-zero**: a member's size is declared in the
container and read before a single byte of its contents is, so "no limit" would
mean the first thing you do with a hostile archive is ask for a petabyte. Zero
in any field means unlimited, which is yours to choose deliberately. The sum is
the cap that actually stops a bomb — no codec can see it, because each member
decodes within its own ratio limit and it is the *count* of members that
multiplies.

**The stream.** `GARC_Stream` is how bytes get in: over a buffer you own, or
through `read`/`seek`/`size` callbacks. `seek` and `size` are optional, and
their absence is a property rather than a failure — a stream with no `seek` is
a pipe, and one with no `size` does not know its length.
`garc_stream_is_seekable()` and `garc_stream_size()` report both, and a format
that needs what is missing refuses rather than guessing. `garc_stream_size()`
answers `GARC_ERR_UNSUPPORTED` rather than zero for an unknown length, because
a stream of no bytes and a stream of unknown length are different facts.

Offsets and sizes are `uint64_t` throughout. A zip64 archive can exceed 4 GiB
and `size_t` is 32 bits on a 32-bit host, so `size_t` would make exactly those
archives unreadable on exactly the platforms where it matters.

**The sink.** `GARC_Sink` is how bytes get out, and it is a separate type rather
than `GARC_Stream` with a `write` added — four of that type's five operations
mean nothing on the way out, and its `read` is *required*, so one struct would
have had to stop requiring it. Either a buffer the sink owns and grows
(`garc_sink_data()` lends it back) or a `write` callback, which is how an archive
reaches a file, a socket, or a compressor.

Three asymmetries with the read side, each of them the format's answer rather
than a preference. **A short write is a failure**, where a short read is just the
end of the stream — so `write` is all-or-nothing and reports no count. **A memory
sink owns its buffer**, where a memory stream borrows one, because the bytes a
writer produces do not exist yet and their number is not known until the archive
is finished. And **there is no `seek` yet**: tar is append-only, zip is not, so
that callback arrives with the writer that reads it.

**Building one.** `garc_writer_create()` takes a sink and a format,
`garc_writer_add()` begins a member, `garc_writer_write()` writes its bytes, and
`garc_writer_finish()` writes the end-of-archive marker. Four things about that:

- **A member is a `GARC_Member`** — the same struct the reader hands out, so
  copying an archive needs no translation step. `header_offset` and `data_offset`
  are where a member *was*; a writer decides where it goes, and ignores them.
- **A size is declared before its bytes**, because tar puts it in the header and
  the header goes first. Writing a different number of bytes is an error rather
  than something padded over: `garc_writer_data_remaining()` is how many are owed.
- **There are no limits here.** `GARC_Limits` caps a *reader*, which allocates on
  a declaration it did not make. A writer allocates on its caller's own request,
  so a cap would be this library second-guessing the program that called it.
- **Nothing is normalised.** A directory's trailing slash is yours to include, the
  typeflag is what says it is a directory either way, and a name
  `garc_name_check()` has findings about is written as given. Deciding what is
  safe to *create* is the filesystem layer's job, and that is phase F.

`garc_writer_finish()` is not called by `garc_writer_destroy()`, on purpose:
finishing can fail, a destructor cannot report it, and a destructor that finished
silently would turn an abandoned archive into a complete-looking one.

**Names.** `garc_name_check()` takes bytes and a length — a member's name, or a
symlink's target, since they are equally dangerous and it is the same question —
and returns a bitmask of `GARC_Name_Finding`: traversal, absolute, drive letter,
UNC, a parent or empty component, a NUL or control byte, a Windows device name, a
trailing dot, malformed UTF-8. A bitmask because a name has as many problems as it
has; `../../CON.` has four.

Two masks group them. `GARC_NAME_ESCAPES` is "this names somewhere a root does not
contain"; `GARC_NAME_PORTABILITY` is "this matters where it is used, not where it
points". Which to refuse on is yours: a POSIX extractor may ignore every finding in
the second, and one writing to a Windows filesystem may not.

**Two findings look redundant and are not.** `GARC_NAME_TRAVERSAL` means resolving
the components leaves the root; `GARC_NAME_PARENT_COMPONENT` means there is a `..`
in it. `a/..` has the second and not the first, and that is exactly where the two
reference extractors disagree — Python's `tarfile.data_filter` resolves it and
accepts, libarchive's `bsdtar` refuses any `..` at all. One bit would have to pick
a side.

**A clean answer is not permission to extract.** No function taking one name can
see a symlink an earlier member created, or a collision between two names, and this
one does not pretend to. Resolve as you create.

**Allocation.** Everything goes through a `GARC_Allocator`, which is cutil's
vtable under a local name. `NULL` means `garc_allocator_default()`. The
`_with_allocator` variant of each constructor takes one, and whatever it
allocated is freed through the same one.

## License

LGPL-3.0-only. `COPYING` and `COPYING.LESSER` are both here because LGPLv3 is
written as a set of additional permissions on top of GPLv3.

Patches are not being accepted at this time; see `CONTRIBUTING.md`, which says
why and what would change that. Bug reports and reproducers are welcome.
