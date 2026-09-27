# Ghoti.io Archive

Archive containers — tar and zip — read and written **without touching the
filesystem**. This library walks the members of an archive and hands you each
one's name, size, time and bytes; it never opens, creates or writes a file. The
one part that does is opt-in, arrives later, and lives in a header of its own.

That is not squeamishness. Every well-known archive vulnerability is a *path*
vulnerability — a member named `../../etc/cron.d/x`, a symlink whose target
escapes the extraction root, a hardlink doing the same with no target string to
inspect — and a library that hands you a name and a byte range cannot commit
one. It also makes a corpus of several hundred malicious archives something
that runs on every commit rather than something a fuzzer has to find its way
to.

Codecs are [Ghoti.io Compress](https://github.com/Ghoti-io/compress)'s job: a
zip member stored with method 8 *is* RFC 1951, and `tar.zst` is a tar stream
through a compress decoder. This library is the container, not the compression.

## Status

**Phase A.** The skeleton: the result vocabulary, the limits, and the byte
stream every reader will read through. **There is no format reader yet** — no
tar, no zip — so there is nothing here that will open an archive. What is here
is the surface every phase after it is an instance of, which is the part worth
arguing about before two formats are built on it.

Build clean under GCC 14 with `-Werror`; 48 tests; clean under Valgrind and
under ASan+UBSan; `make check-symbols` and `make check-aliasing` green; one
fuzz harness over the stream.

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

  // The fopen is yours. The library sees three function pointers.
  GARC_Stream_Callbacks callbacks = {.read = read_cb, .ctx = file};
  GARC_Stream * stream = NULL;
  if (garc_stream_create_callback(&callbacks, &stream) != GARC_OK) {
    fclose(file);
    return 1;
  }

  unsigned char header[512];
  GARC_Result result = garc_stream_read_exact(stream, header, sizeof(header));
  printf("%s\n", garc_result_string(result));

  garc_stream_destroy(stream);
  fclose(file);
  return 0;
}
```

`examples/stream_from_file.c` is that program with `seek` and `size` filled in
as well, which is what a zip reader will need.

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
their sum, a name's length, and a member's extra fields.
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

**Allocation.** Everything goes through a `GARC_Allocator`, which is cutil's
vtable under a local name. `NULL` means `garc_allocator_default()`. The
`_with_allocator` variant of each constructor takes one, and whatever it
allocated is freed through the same one.

## License

LGPL-3.0-only. `COPYING` and `COPYING.LESSER` are both here because LGPLv3 is
written as a set of additional permissions on top of GPLv3.

Patches are not being accepted at this time; see `CONTRIBUTING.md`, which says
why and what would change that. Bug reports and reproducers are welcome.
