# Design

**Status:** phase A shipped; phases B onwards are design. What is below
describes what exists unless a heading says otherwise.

This page records the decisions a reader of the headers would otherwise have to
reconstruct, and — where the decision could reasonably have gone the other way
— what the alternative was and why it lost.

The phase plan itself is a working note rather than a published document, and
lives outside this repository.

---

## 1. Why this is not part of `compress`

A codec is bytes to bytes; `gcomp_encode_buffer()` is the whole of its shape.
An archive is a sequence of *members*, each with a name, a size, a modification
time, a type, permissions, and possibly its own codec. Two things follow:

1. **The API shape is iteration and metadata, not transformation.** A caller
   opens an archive, walks its members, and reads the bytes of the ones it
   wants. Nothing in `gcomp_method_t` describes that, and bending it to would
   make it worse at the seven things it does describe.
2. **This consumes compress rather than extending it.** ZIP's method 8 *is*
   RFC 1951. `tar.zst` is a tar stream through a compress decoder. The
   dependency is clean and one-way, exactly as `image` depends on `compress`
   today.

## 2. The filesystem is not this library's

**Nothing here opens, creates, or writes a file.** A caller reading an archive
from disk does the `fopen` and supplies a `GARC_Stream_Callbacks`, which is the
three functions `examples/stream_from_file.c` shows.

The security property is the reason. Every well-known archive vulnerability is
a path vulnerability:

- **Zip-slip / tar traversal**: a member named `../../etc/cron.d/x`, or with an
  absolute path, or on Windows `C:\...` or `\\?\UNC\...`.
- **Symlink escape**: a member that is a symlink to `/`, followed by a member
  whose path goes through it. Neither member is suspicious alone.
- **Hardlink escape**: the same, harder to spot because there is no target
  string to inspect on the second member.
- **Case and Unicode collisions**: `A.txt` and `a.txt` on a case-insensitive
  filesystem; two names that normalise to one.

A library that hands the caller a name and a byte range cannot commit any of
them. It is also testable entirely in memory, which is what makes a corpus of
several hundred malicious archives cheap enough to run on every commit.

Extraction to a directory, and creation from one, arrive later as a separate
opt-in layer, with the corpus already written. That layer then has exactly one
job, done once, in one place.

## 3. What this library refuses to know

Two refusals keep the dependency list at `cutil` and `compress`. Both will be
proposed again by somebody writing a test that has to build a CP437 name, so
they are written down rather than implied.

**Names are bytes plus a declaration, never transcoded.** ZIP stores member
names as bytes, with bit 11 of the general purpose flag meaning "these are
UTF-8" and no declaration at all meaning, historically, CP437. tar's are bytes
with no declaration ever. A member will report its name as bytes plus an enum
saying what the container *declared*, and transcoding is the caller's, or a
later optional helper's. This is the same refusal compress makes about text: a
codec does not know what its bytes mean. Transcoding here would mean depending
on `unicode`.

**Times are epoch seconds plus provenance, never normalised.** ZIP has an
MS-DOS date/time field with two-second resolution, plus extra fields carrying
better ones. tar has an octal Unix time, and pax a decimal one with sub-second
digits. A member will report seconds since the epoch, plus nanoseconds where
the container carried them, plus which field they came from. Normalising would
mean depending on `chron`.

## 4. Limits, and why every default is bounded

`model` and `image` leave most of their caps open, because the size of the
input already bounds them — every record costs at least a couple of bytes.
**That argument does not hold here.** A member's uncompressed size is *declared
in the container* and read before a single byte of its contents is, so an open
cap means the first thing a caller does with a hostile archive is ask for a
petabyte. 42.zip is 42 KB on disk.

So `garc_limits_default()` fills in all five, zero still means unlimited, and
the numbers are **provisional**: chosen to stop a bomb, not to bless a size.
What settles them is the corpus — no legitimate archive in `tests/data/` may hit
a default, and the phase that adds a format adds that assertion with it. A
default a real archive hits is a defect in the default.

`max_total_bytes` is the one that actually matters, and the one no codec can
enforce: each member decodes within its own expansion-ratio limit, and it is
the *count* of members that multiplies. compress's `limits.max_memory_bytes`
and ratio refusal compose underneath it and cover the per-member half already.

There is deliberately no `max_nesting`. Descending into an archive inside an
archive is something this library does not do — a member is bytes, and whether
those bytes are themselves an archive is the caller's question — so a field for
it would be one nothing reads, which is worse than absent because it reads as a
promise.

## 5. The result vocabulary, and its two departures

CONVENTIONS.md section 5 fixes the result vocabulary. This library departs
twice, and both departures are in that document's table.

**`GARC_END` is neither success nor failure.** Walking an archive ends, and the
end of a well-formed archive is not an error, so a caller writing
`result != GARC_OK` would report a failure on every complete read.
`garc_result_is_error()` exists so that nobody has to hand-roll the comparison,
and it is what the tests assert in both directions.

**There is no bare `GARC_ERR_LIMIT`.** Each cap has a status of its own. One
code for every cap cannot distinguish an absent cap from a defeated one, and
cannot tell a test which cap fired — which is the failure the compress notes
record as "absent cap and defeated cap return the same code". The cost is five
constants where the convention has one. Each of their strings names which
limit, because a shared message would undo half of what the separate constants
buy: a message is what a caller prints.

A status is added by the phase that can return it. Phase A defines only what
phase A can return, so every value is reachable and every row of
`garc_result_string()` is exercised — a string table with unreachable rows is a
table nobody can test.

## 6. The stream

**Offsets and sizes are `uint64_t`, not `size_t`.** A zip64 archive may exceed
4 GiB and declare a member that does, and `size_t` is 32 bits on a 32-bit host:
using it would make those archives unreadable on exactly the platforms where
the check matters, and it would do it with an overflow rather than a refusal.
Buffer lengths stay `size_t`, because a buffer is a real object in this process
and an offset is a number in a file.

**Seekability and known-size are properties, not error conditions.** tar is a
cursor over a stream and can be read from a pipe; zip is read backwards from
its end and cannot. `seek` and `size` are therefore optional callbacks, and
their absence is reported — `garc_stream_is_seekable()`, and
`GARC_ERR_UNSUPPORTED` from `garc_stream_size()`. A format that needs what is
missing refuses before it starts rather than discovering it from a failed seek
halfway in.

`garc_stream_size()` answers `GARC_ERR_UNSUPPORTED` rather than zero, because a
stream of no bytes and a stream of unknown length are different facts and one
integer cannot carry both.

**A memory stream is implemented as a callback stream** over the borrowed
buffer, rather than as a second path. Every test in this library reads from
memory, so two paths would mean the one the tests exercise and the one a caller
uses are different code.

### What `garc_stream_skip()` can and cannot promise

A skip is always driven by a length the container declared, so running off the
end means the container lied, and it is reported as `GARC_ERR_CORRUPT` rather
than left to be noticed later. That promise holds in three of the four stream
shapes, and the fourth is written into the header rather than glossed:

| shape | how the end is found | on a lying length |
| --- | --- | --- |
| sized, seekable | the `size` callback, checked first | `GARC_ERR_CORRUPT` |
| sized, not seekable | the `size` callback | `GARC_ERR_CORRUPT` |
| unsized, not seekable | the discard loop runs out | `GARC_ERR_CORRUPT` |
| **unsized, seekable** | nothing to check against | whatever `seek` says |

The size check exists *because* a seek past the end of an ordinary file
succeeds. Without it, a lying length would be reported at the next read instead
of at the skip that was driven by it — a long way from the cause. Supplying a
`size` callback is what closes the fourth row.

**Where a failed skip leaves the offset depends on the shape, and cannot not.**
A seekable stream is restored, so a caller may retry. A non-seekable one cannot
be: the discard loop has consumed the bytes and they are gone, so
`garc_stream_tell()` reports how far it got — which is the useful number, being
where the archive ran out. The fuzz harness found this on its first run by
asserting one rule for both paths; two paths meant to be interchangeable have
to say where they are not.

## 7. Testing

**Four stream shapes, not one.** Seekability and known-size are two independent
properties, so there are four combinations and a memory stream is one of them.
`tests/test_helpers.h`'s `BufferSource` takes both as constructor parameters
and every property test sweeps all four, because two features tested alone
leave their product untested.

**A short read and a read failure are asserted separately.** The first is the
end of the stream and the second is a failure to reach it. A stream that folded
them together would make a truncated archive and a broken disk look alike, and
`read_exact` turning a short read into `GARC_ERR_CORRUPT` is what gives a
parser the distinction for free.

**The fuzz harness's first byte is an options byte** that chooses the stream
shape and the operation programme, so one harness covers the seekable and
non-seekable paths rather than whichever one a constructor happened to pick. It
also drives the failing allocator, so the out-of-memory arms are walked by the
same corpus rather than by a separate campaign.

Phase A has no oracle, because it has no format: there is nothing an external
tool could be asked that this library can answer. The container-pinned oracle
harness — `tar`, `bsdtar`, `zip`, `unzip`, Python's `tarfile` and `zipfile`,
`7z` — lands with the first format reader, where it has something to check and
can be seen to fail. Landing it now would mean a gate with nothing behind it.
