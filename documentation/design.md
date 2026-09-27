# Design

**Status:** phases A and B shipped, except GNU's and pax's extended members,
which are refused by name. What is below describes what exists unless a heading
says otherwise.

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

### Naming the danger without deciding about it

`garc_name_check()` classifies a name - or a link target, which is the same
question about different bytes - into a bitmask of `GARC_Name_Finding`. A bitmask
because a name has as many problems as it has: `../../CON.` is a traversal *and* a
Windows device *and* a name Windows will strip a dot from, and a function
returning the first of those makes the other two unreportable.

**It is a classifier, not a permission, and that distinction is the whole design.**
Two things cannot be answered from one name, ever:

- A member called `docs/readme` has no findings and escapes any root you like if
  an earlier member made `docs` a symlink to `/`. Neither member is suspicious
  alone, which is why extraction has to check the **resolved** path as it
  resolves, against the links it has actually created. A check on the declared
  name is the bug, not the fix.
- A collision is a property of a *pair*: `A.txt` and `a.txt`, or `café` composed
  and decomposed. No function taking one name can see it, and deciding it needs
  case-folding and normalisation tables this library deliberately does not carry.

So the corpus contains both shapes and the tests say out loud that the check does
not claim them. `mal-links.tar` holds an absolute link target and one that climbs
out of any root, and every *name* in it is ordinary. `mal-collisions.tar` holds
both collision pairs, and every name in it is individually clean - asserted, so
that if someone ever teaches the checker to fold case the claim gets moved rather
than the test relaxed.

What it is for: refusing an archive early and cheaply, before any of it is read;
telling a person *why* a listing looks wrong; and giving the filesystem layer a
vocabulary to report in. `examples/name_findings.c` is the refuse-early shape, and
it prints the "no findings is not permission" sentence because that is the thing a
reader of it is most likely to get wrong.

#### Two references, and the disagreement that shaped the API

Every finding is either checked against an outside reference or marked as having
none, because a safety predicate whose expectations were written by whoever wrote
the predicate measures the author twice. `tests/data/tar/verdicts.tsv` records
what each pinned reference *does* with all 91 names in the corpus - which is a
decision rather than a reading, and the only part of the corpus that is.

They do not agree with each other:

| name | `tarfile.data_filter` | `bsdtar -x` |
| --- | --- | --- |
| `../../../tmp/x` | refuses | refuses |
| `/tmp/x` | **rewrites** to `tmp/x` | **rewrites** |
| `a/..` | **accepts** | **refuses** |
| `C:\Windows\x` | **accepts** | **rewrites**, dropping `C:` |
| `./x`, `a//b` | accepts | accepts |

`a/..` has a parent component and resolves *inside* the root. Python resolves and
accepts; libarchive refuses any `..` at all. **A single safe/unsafe bit would have
to pick one of them**, so `GARC_NAME_TRAVERSAL` (resolving leaves the root) and
`GARC_NAME_PARENT_COMPONENT` (there is a `..`) are separate bits, and a caller can
hold either policy. The depth is a running count for the same reason: `a/..` ends
where it started, and `a/b/../../../c` climbs one further than it descended.

Each reference then gets the mask it actually answers for, and the two masks
differ - which is what makes the cross-check a relation rather than a restatement.
The relation is two-sided in both cases, because one direction alone is satisfied
by a checker that reports nothing and the other by one that reports everything.

Two limits of the references are written down rather than worked around:

- **Both run on POSIX**, so neither can answer about a Windows reserved name, a
  trailing dot, or a backslash as a separator. Those findings are justified from
  documented platform behaviour, not from a tool's verdict, and
  `GARC_NAME_WINDOWS_TRAVERSAL` is deliberately **not** in `GARC_NAME_ESCAPES`:
  including it would make this library stricter than both references about names
  they are right to accept on the host they run on.
- **The verdict is about a member and the check is about bytes.** Python raises
  `AbsoluteLinkError` for a member whose *name* is perfectly ordinary and whose
  *target* is not. The relation has to be restricted at both ends, so the test maps
  each of `tarfile`'s exception names onto the field it is about - which is reading
  the reference's own vocabulary rather than inventing an expectation. Getting
  that wrong was the first failure of the cross-check.

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

## 5. Walking an archive

Three decisions in the reader loop, each of which could have gone the other way.

**`garc_next()` is a cursor, not an index**, even for a format that has one. A
cursor is the only thing tar can offer - it has no directory and can be read
from a pipe - and one API both formats satisfy is worth more than two that fit
each perfectly. Random access becomes an *addition* for the formats that can
support it rather than a second mode.

**Unread data is skipped for the caller.** Stepping to the next member without
having read the current one is normal and cheap: the reader seeks when the stream
can and discards when it cannot. A caller is never required to read bytes it does
not want in order to reach the next member, and the two paths are asserted to
land in the same place rather than merely each succeeding.

**`garc_read_member()` fills a caller buffer.** No allocate-and-return in this
cut. compress added `gcomp_decode_alloc()` after the bounded form existed and the
order mattered: the bounded form is the one a caller with a size limit can use,
and the allocating one is a convenience built on it rather than the reverse.

A member is **borrowed, valid until the next `garc_next()`**, and its name is
bytes plus a length rather than a NUL-terminated string. A hostile archive puts a
NUL in the middle of a name precisely so that a C caller sees a shorter name than
the library did.

## 6. tar, which is four formats

There is no such thing as "tar". There are four formats sharing a 512-byte
header, and a reader that handles one and calls it done mis-reports the others
without ever erroring:

| variant | names | sizes | how it says so |
| --- | --- | --- | --- |
| v7 | 100 bytes | octal | nothing at all; the checksum is the only evidence |
| ustar (POSIX.1-1988) | 100 bytes + a 155-byte prefix | octal, 11 digits, so 8 GB | `magic` is `ustar\0`, `version` `00` |
| GNU | an `L` member carrying the next member's name | base-256 when the high bit is set | `magic` is `ustar  \0` |
| pax (POSIX.1-2001) | an `x`/`g` member of `len key=value\n` records | a `size=` record, decimal | an `x` member before the one it describes |

**All four are read.** What is refused, by name and with
`GARC_ERR_UNSUPPORTED`, is a *sparse* member - GNU's `S` typeflag and pax's
`GNU.sparse.*` records - because there the member's data is a map of holes and
extents rather than its contents, and a reader that ignored that would hand a
caller the map as the file. The members around a refused one are read normally, so
it is a refusal of one construct rather than of the archive.

Note that a pax archive whose names all fit the ustar fields contains no extended
records at all - pax's magic *is* ustar's - so `tar --format=pax` output is
usually readable here. Refusing it for the format it was asked for would refuse
most of what that flag writes.

The variant is reported **per member, not per archive**, because it changes within
one: GNU tar writes pax records in front of ustar headers. `garc_tar_member_variant()`
answers for the member `garc_next()` last handed out, and it lives in `tar.h`
rather than on `GARC_Member` because a member field whose meaning depends on which
format filled it in is the shape that goes wrong when the second format arrives.

### Metadata in front of the header, not in it

GNU cannot put a name longer than 100 bytes, or a link target longer than 100
bytes, in a header - so it writes one of its own in front: a member with typeflag
`L` or `K`, named `././@LongLink`, whose *data* is the string, followed by the
real header with a truncated copy of it in the ordinary field. pax does the same
job with `len key=value\n` records in an `x` or `g` member.

The wrong answers here are all names, which is what makes them worth naming:

- **Reporting the carrier as a member** hands a caller a file called
  `././@LongLink` whose contents are somebody's path, *and* reports the real
  member under the truncated name in the header behind it. Two wrong members from
  one construct, neither of them an error.
- **Reading the payload with a single block read** truncates every name longer
  than 512 bytes at exactly 512 and reports the rest correctly. A corpus whose
  longest long name is 108 bytes cannot tell; `gnu-longname-blocks.tar` exists
  because of this, with names of 201, 402, 603 and 611 bytes.
- **Implementing `L` and not `K`** truncates a symlink's target at 100 bytes, and
  a truncated path is a path to somewhere else rather than a damaged one.
- **Leaving the carried name in place for the next member** gives two members one
  name and still round-trips. A carrier describes the member immediately behind
  it and nothing after it.

Three things a payload can be that no writer writes, each refused:

- **A payload with content behind its terminator.** GNU writes `strlen + 1`, so
  there is one NUL at the end; a writer that omitted it writes `strlen` and there
  is none. Both are read, because each has exactly one reading. A NUL with more
  bytes behind it has two - this reader would report the bytes before it and a
  reader using the declared length would report all of them - and a member whose
  name depends on which reader is asked is how a checked name and an extracted
  name come apart. `GARC_ERR_CORRUPT` rather than either answer.
- **An empty payload**, by a declared size of zero or by bytes that are all NUL.
  The tempting reading is "no name here, use the header's", which silently
  produces the truncated name the carrier existed to replace.
- **Two carriers of the same kind for one member.** Each allocates its declared
  size, so a chain of them turns a few hundred bytes of archive into one
  allocation of the cap per link; libarchive refuses the same shape for the same
  reason. The alternative reading, last-one-wins, would make a member's name
  depend on how far a reader got.

Two consequences in the API worth knowing:

- **`max_name_bytes` is checked against the *declared* size, before the payload
  is allocated.** This is the only place in the tar reader where a length arrives
  in one block and the bytes in the next, so it is the only place a cap has to
  fire on a declaration. The cap is on the name and the payload is the name plus
  its terminator, so a cap of *N* accepts a payload of *N* + 1 and
  `garc_reader_account()` remains the authority on the name itself.
- **`header_offset` is the offset of the carrier**, not of the header behind it,
  because that is the offset a member can be re-read from. Re-reading from the
  real header would produce the truncated name. A carrier is not counted in
  `garc_member_count()` and its size is not added to
  `garc_total_declared_bytes()`: it is metadata, bounded by `max_name_bytes` and
  by nothing else.

And the variant a member read through a carrier reports is `GARC_TAR_GNU` even
when the header's own magic says `ustar`, because the construct is GNU's and the
member was not read as a ustar member.

### pax's records, which are the same job with different rules

An `x` or `g` member's data is a run of `len SP key = value LF` records, where
`len` is the decimal length of the whole record *including itself* - the one
self-referential field in any of these formats, and what lets a record be found
without scanning for a delimiter a value might contain. The keys this reader acts
on are `path`, `linkpath`, `uname`, `gname`, `size`, `mtime`, `uid`, `gid` and
`hdrcharset`.

Four rules, each of which has a wrong reading that still round-trips:

- **`x` applies to the next member; `g` applies until replaced.** Backwards, this
  mis-attributes every name in an archive and reports a complete one.
- **A later record overrides an earlier one key by key**, so a second `g` naming
  `mtime` does not clear the first one's `path`. This is why the global record
  bytes are appended to rather than replaced, and why the record table holds
  offsets into them rather than pointers.
- **An empty value deletes the key**, which is how an `x` header suppresses a
  global one. "The key appeared" and "the key has a value" are therefore two
  states, and a reader that conflated them would report the very thing an archive
  asked it to forget.
- **An unknown key is ignored, not refused.** pax is an open vocabulary and real
  writers use it - `SCHILY.*`, `LIBARCHIVE.*`, `GNU.*` - so refusing would refuse
  most of what `bsdtar --format=pax` writes. `GNU.sparse.*` is the one exception,
  and it is an exception because ignoring it changes what the member's *data* is
  rather than what its metadata says.

Three consequences worth knowing:

- **`hdrcharset` is the only thing in tar that declares an encoding**, and it
  declares it for the *records* - so it decides `name_encoding` for a name that
  came from a `path=` record and says nothing about one read from a header field,
  which stays `GARC_NAME_UNDECLARED` whatever the records claim. Absent is a
  declaration too: POSIX says the records are UTF-8, so a `path=` record with no
  `hdrcharset=` beside it is `GARC_NAME_UTF8`. `BINARY` is the opposite, and a
  charset this library cannot vouch for reaches the same answer for a different
  reason.
- **`mtime` is where `GARC_TIME_PAX_DECIMAL` and a non-zero
  `mtime_nanoseconds` come from**, and the fraction *floors* for a time before
  the epoch: the nanoseconds a member reports are unsigned, so `-1.5` is -2
  seconds and 500000000 nanoseconds. Truncating towards zero would put it half a
  second after the epoch where the archive said half a second before it. Digits
  past the ninth are dropped rather than rounded, because rounding can carry into
  the second.
- **`max_extra_bytes` is reachable for the first time.** No tar construct read
  before pax had an "extra field" for it to bound, so it was a status with no path
  to it - worth saying plainly rather than leaving the cap looking live. What it
  bounds is what the reader is *holding* for the current member: the `x` records
  plus the globals still in force, because either can be made into a chain and a
  cap on one header at a time would leave a hundred of them unbounded.

**`x` and `g` differ at the end of an archive**, and it is not an oversight. An
`x` with nothing behind it describes a member the archive does not contain, so it
is `GARC_ERR_CORRUPT`; a `g` with nothing behind it describes every member after
it and "none" is a number of members, which is what `tar --concatenate` leaves at
a join. So the reader tracks "this block joins the member's group" and "this block
leaves a member owed" as two questions - a `g` answers yes to the first, because
`header_offset` has to point at the start of the whole run of metadata blocks for
a re-read to produce the same member, and no to the second.

Where a GNU carrier and a pax record both describe one member - which no writer
produces - **the record wins**. That is an order rather than a refusal because pax
*has* an override rule and this is an instance of it, unlike two GNU carriers of
the same kind, where the format defines no order and the reader refuses.

### What a header field can do to a reader

Each of these produces a plausible *wrong answer* rather than an error, which is
why each has a test naming it:

- **The checksum is computed with the checksum field read as spaces**, and
  historically some writers summed the bytes as signed chars and some as
  unsigned. Both are accepted, because refusing either rejects real archives, and
  which one matched is reported - so a corpus can show it has one of each rather
  than assuming it does. The two differ only when a header holds a byte above
  0x7F.
- **Identification is the checksum, not the magic.** v7 has no magic field, so a
  reader that requires one rejects the whole variant.
- **A numeric field's terminator may be a NUL, a space, both, or absent** when
  the digits fill the field exactly, and leading padding may be spaces or NULs. A
  reader that stops at the first space reads 0 from `" 0000644"`.
- **A blank field is zero, not corrupt.** The device numbers are blank in almost
  every archive there is.
- **Base-256 is a two's-complement integer over the whole field**, with bit 7 of
  the first byte as the flag and bit 6 as the *sign* - so `0x80` and `0xFF` are
  the two commonest leading bytes and not the whole scheme. Reading it as "0x80
  means positive and the rest is the magnitude" discards six value bits of the
  first byte.
- **A directory, symlink, fifo or device declares no data and its size field may
  not be zero.** A reader that seeks by the field walks into the next header and
  reports that header's bytes as this member's contents.
- **v7 has no prefix field**, so those bytes are whatever the writer left there.
  A reader that always joins the prefix turns padding into a directory component.
- **Two zero blocks end the archive, one does not necessarily.** Writers pad the
  end to a record boundary and some strip the padding, so an archive ending after
  a single zero block is a trimmed tail; but GNU tar concatenates archives, which
  leaves markers in the middle, so a reader that stops at the first truncates a
  valid archive and reports success. An archive with no marker at all is
  `GARC_ERR_CORRUPT`, which is what `tar cf - x | head -c 4096` produces.
- **An unrecognised typeflag is `GARC_MEMBER_OTHER`, not a file.** Extracting an
  unknown type as a regular file is how a reader invents data.

## 7. The result vocabulary, and its two departures

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

## 8. The stream

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

## 9. Testing

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

### The oracle, and why two references answer two questions

Three implementations, pinned in one image
(`tools/oracle/containers/tars/Containerfile`): **GNU tar 1.35** writes the
fixtures in each of its four formats, **Python 3.13.5's `tarfile`** reads the
metadata back, and **bsdtar / libarchive 3.7.4** reads the names. One image
rather than three, because these are not three tools each answering about its own
format - they are three implementations asked the same question, and in three
images a disagreement would first have to be shown not to be the images' fault.

**The fixtures are generated, not hand-built.** A corpus written by hand contains
the shapes whoever wrote it thought of; `notes/` records a library that scored
395/395 against its own corpus with eleven divergences outstanding. What is
committed is what GNU tar writes. The complement - headers no current writer
emits, which is damage, a spelling decades out of use, and fields at their limits
- is built in `tests/tar_builder.h` and labelled as hand-built wherever it is
used, because that is the difference between an assertion about the format and an
assertion about what a test file constructs.

**Names come from bsdtar and everything else from tarfile**, and that split is a
finding rather than a convenience. Python's `tarfile` strips the trailing slash
from a directory member's name: the header says `sizes/` and it reports `sizes`.
GNU tar's `-t` and bsdtar's both print `sizes/`, which is what the archive
contains. So two of three references agree with each other and with the bytes,
and the third normalises - and this library reports what the container said.
Comparing names against the one that normalises would have needed either a wrong
expectation or a tolerance wide enough to hide a real truncation. Naming the
reference per question is the answer instead.

### The malicious corpus, and where its names come from

Every hostile name in `tests/data/tar/mal-*.tar` is written by **GNU tar**, through
`--transform` with `-P`. That is the point rather than a convenience: a corpus of
hostile names invented by whoever wrote the checker measures that person's
imagination, which is the argument that kept this out of phase A until there was an
oracle to build it against.

`-P` is what makes it work and is worth knowing about on its own: GNU tar's
*default* is to sanitise, stripping a leading `/` or `../` with a warning. A corpus
generated without it would contain nothing hostile at all and every test over it
would pass.

Three of these fixtures cost a regeneration each to get right, and each failure is
the same shape - a fixture that looked hostile and was not:

- **Two names meant to hold raw bytes arrived well-formed.** `"\x80"` in a Python
  `str` is U+0080, which `subprocess` encodes to the valid pair `C2 80` on the way
  to `tar`. The surrogate spelling `"\udc80"` is what `surrogateescape` maps back to
  a single raw byte, and the generator now asserts that a name's encoding is what
  its table entry says.
- **A global pax header's own mtime is a wall-clock reading**, because `--mtime`
  sets the *members'* times and a global header is not a member.
- **GNU tar's sparse members embed its pid** in the member name
  (`./GNUSparseFile.6/...`), which cannot be pinned at all - so the sparse refusal
  is tested hand-built and there is no sparse fixture.

The complement is hand-built, as everywhere else in this library: an empty name and
a NUL inside one cannot be produced by any writer, because no filesystem can hold
them.

### Four gates, and what each cannot see

| gate | needs a container | catches |
| --- | --- | --- |
| `check-corpus-hashes` | no, and so it is in `TEST_GATES` | a fixture edited, truncated, or half-committed |
| `check-corpus` | yes | the references no longer *writing* these bytes |
| `check-oracle` | yes | the references no longer *reading* them the same way, or no longer *deciding* the same way about them |

The split matters in both directions. Hashing needs only sha256, so it runs on
every machine; regenerating needs the image, so it fails closed rather than
skipping - a gate that skipped would make a machine with no engine look exactly
like one where the references still agree. And `check-corpus` and `check-oracle`
are not the same question: a tar release can change how a field is parsed without
changing any output, and a suite that only regenerated would call that a pass.
`check-oracle` is also the only thing that catches a manifest edited *and*
rehashed to make a failing test pass.

The fourth question is `verdicts.tsv`, which `check-oracle` re-derives along with
the other two. It is the only file in the corpus recording a **decision** rather
than a reading - what `tarfile.data_filter` and `bsdtar -x` would *do* with each
name - and it is what `garc_name_check()` is measured against. Its archive-level
comment lines, which record the tree libarchive actually created, are not
re-derived there on purpose: they are part of the file `check-corpus` regenerates
and hashes, so a change in them already fails that gate, and asking twice would be
the same question twice. Those lines are the only evidence that libarchive strips a
drive letter, because it reports at most one archive-level rewrite per archive and
an absolute name in the same fixture uses up the message.

`make check-corpus` earned its keep on its first run, by finding that GNU tar's
pax output is not reproducible: it writes `atime` and `ctime` records that are
wall-clock readings. `--pax-option=delete=atime,delete=ctime` fixes it, and that
leaves an archive with no extended records for short names - which is why there
are two pax fixtures rather than one.
