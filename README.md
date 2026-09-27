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
wrong answer rather than a missing feature. No zip yet, and no filesystem layer.

The fixtures are written by GNU tar 1.35 in a pinned container and the
expectations come from Python 3.13.5's `tarfile` and libarchive 3.7.4's bsdtar,
so a passing test is three implementations agreeing rather than this library
agreeing with itself.

**Names are classified, not cleaned.** `garc_name_check()` reports what is
dangerous about a member name or a link target - traversal, absolute, drive
letter, a NUL, a Windows device name, malformed UTF-8 - one finding at a time,
and the reader hands over the bytes the archive actually holds. It is a
classifier and not a permission: see `examples/name_findings.c`, which prints why.

**Nothing is written yet.** `GARC_Sink` is here - the byte sink a writer will
write through - and the writer that fills it is not. A header with no consumer is
usually a promise nobody keeps, so it is worth saying which this is: the sink is
the half of tar-write that needs no format, committed on its own for the same
reason the stream was committed before any reader.

Build clean under GCC 14 with `-Werror`; 253 tests; 99.6% line coverage, the
five remaining lines being a defensive arm no input can reach and three guards
that are live only where `size_t` is 32 bits; clean under Valgrind and under
ASan+UBSan; `check-symbols`, `check-aliasing`, `check-corpus-hashes` and
`check-fixtures` green; three fuzz harnesses.

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
