# Design

**Status:** tar is read in all four of its formats and written as pax; `tar.gz`,
`tar.zst` and `tar.lz4` work in both directions; zip is **read** and not yet
written. The filesystem layer does not exist. What is below describes what exists
unless a heading says otherwise.

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

## 7. zip, which is read backwards

A tar is a sequence of headers from the front. A zip is an index at the **end**:
the end-of-central-directory record says where the central directory is, and the
directory's entries say where each member's local header is. Everything below
follows from that one fact.

**Every value reported about a member comes from the central directory**, and the
local header is read for exactly one thing - where the member's data starts, which
only it can say, because its name and extra field are sized independently of the
directory's copies.

That is not a preference between two equal sources. libarchive writes a data
descriptor for every member with data, *even into a seekable file*, which means
the local header's sizes are zero and the real values are behind the data and in
the directory; a reader that believed the local header would report every member
of an ordinary bsdtar-made zip as empty and would still pass every test written
against archives from any other tool. And where the two disagree deliberately,
following the directory is what every real tool does - which is what makes
trusting the local header the root of the whole class of zip confusion bugs, where
one member is displayed and another extracted.

The corollary is a refusal: **a local header whose name is not the directory's is
`GARC_ERR_CORRUPT`**. An archive saying two different things about which member
this is has nothing else to be, and no writer in the corpus disagrees with itself,
so the refusal costs nothing real.

### Finding the end record, which is the part that must not be lazy

The scan starts at the end of the stream and goes back at most 65,557 bytes - 22
of record plus the largest comment its 16-bit length field can describe - and
**every candidate is validated**: the comment length has to account for exactly
the bytes after it. Two things force that:

- The signature can appear *inside the archive comment*, and does. Python's
  `zipfile` does an `rfind` for it and gives up when the arithmetic fails, so it
  cannot open `python-comments.zip` at all - while unzip, bsdtar and 7-Zip read it
  correctly. Add 22 more bytes behind the decoy, so that a whole record fits where
  it sits, and unzip refuses it too while the other two still read it. The pair of
  fixtures is one byte count apart and **no two of the four references answer both
  the same way**.
- A scan that looked further than the bound would find a signature inside a
  *member's data*, which is a thing an attacker can put there for free.
  `python-data-decoy.zip` has a whole plausible directory header and end record
  inside one member, and every reference reads that archive - so a reader it breaks
  is broken by its own scan.

Where two records are both valid, **the one nearer the end wins**, which is what
unzip and libarchive do. The format cannot distinguish them, so the choice is
written down rather than left to whichever way a loop happened to run.

**A zip must end where the stream ends.** Bytes *before* the archive are ordinary -
a self-extracting stub is exactly that - but bytes after the record that its
comment length does not cover make the archive unfindable by any conforming
reader, and this one answers `GARC_ERR_CORRUPT` rather than scanning the whole
file.

### The base offset is discovered, not declared

The directory says where it is; the scan finds where it actually is; the difference
is how many bytes sit in front of the archive without being counted, and every
offset in the file is short by that much. `garc_zip_base_offset()` reports it
rather than applying it silently, because it is the one number here this library
worked out rather than read.

**One consequence is worth knowing rather than fixing:** an archive whose declared
directory *size* is wrong is indistinguishable from one with a stub, because both
show up as the same subtraction. The reader concludes there is a stub, shifts every
offset, and lands somewhere that is not a local header - so it fails closed, with a
signature mismatch rather than a size complaint. The bound that *is* a size check
catches the other shape: an entry whose own name or extra length runs it past the
end of the directory.

### Seeking, which is required, and the refusal that says so

Reading a zip needs a seekable stream: the answer to "what is in this" is at the
far end of the file. A stream whose first bytes are a zip signature and which
cannot seek is **`GARC_ERR_NOT_SEEKABLE`**, not `GARC_ERR_FORMAT` - a caller told
"not an archive" about a file every other tool opens would go looking for the
wrong thing, and the fix is only discoverable from the status. There is no
streaming mode, and adding one would mean trusting the local headers.

### zip64, which is per field and not per archive

A size, a compressed size or an offset that does not fit its 32-bit field holds
`0xFFFFFFFF`, and the real value is in a 0x0001 extra field - **only for the
fields that hold the marker, in the specification's order**. `zip -fz` writes an
eight-byte field for an archive where only the uncompressed size was marked, so a
reader that consumed the values positionally, or that assumed sixteen bytes, gets
this member's size out of the wrong eight. A marker with no field to supply it is
refused rather than read as 4 GiB minus one.

The archive-level records are a separate question from the member-level fields, and
`garc_zip_has_zip64_end_record()` is separate from
`garc_zip_member_used_zip64()`: Python's `force_zip64` writes the member's fields
into the **local header only**, leaving a directory that needs none and no zip64
end record at all.

The locator is looked for whenever there is room for one, not only when a field
holds a marker - because `zip -fz` writes the zip64 records for an archive whose
32-bit counts would all have fitted, and those counts are right, so a reader that
waited for a marker would pass on that archive until the one where they are not.

### Methods, which are numbers, and the two that have codecs

**Methods 0, 8 and 93 are read.** A compressed member is a *bounded view* of the
file with a decoder over it: the view ends where the member's compressed size ends,
which is what stops a deflate stream from reading the next member's local header as
more input, and the decoder is `compress`'s. So method 8 is RFC 1951 raw -
`compress`'s `"deflate"`, not its `"zlib"`, and reading one as the other fails on
the first two bytes - and method 93 is a zstd frame, which came almost free.

**Method 9 is refused on purpose, and it is the interesting one.** "Enhanced
deflate" is not RFC 1951: it allows a 64 KB window and a different length code. A
reader that pointed it at the deflate decoder would decode the members that used
neither extension correctly and the ones that used either into plausible wrong
bytes, which is the worst of the three available outcomes. 12, 14, 95 and 98 are
refused for the ordinary reason - no codec - and `garc_zip_member_method()` with
`garc_zip_method_string()` name the number in every case, so a refusal is a to-do
list rather than a dead end. unzip 6.00 refuses 14 and 99 itself, with "need PK
compat. v6.3", so refusing them here is the format's age rather than conservatism.

The mapping from a method number to a codec name is **one switch in one file**,
which is the whole reason the codec layer takes a string: a second enum would be a
copy of `compress`'s list of methods, and the copy goes stale.

### The CRC, which tar has nothing like

Every member declares a CRC-32 of its uncompressed bytes, and this reader checks
it. Reading a member to its end and getting ::GARC_OK therefore means something
stronger than "the bytes were there": it means this reader and whatever wrote the
archive agree about every one of them.

Two decisions about *when*:

- **The verdict arrives on the call that returns zero bytes**, not on the call that
  hands over the last of the data. A checksum covers a whole member, so it cannot
  be reported until the member is over - and reporting it on the last data call
  would make the caller lose those bytes to an error return.
- **A partial read gets no verdict**, and neither does a skipped member. Half a
  member has no checksum to compare against, so a caller that stops early is told
  nothing rather than told something false.

The decoder's output cap is the member's **declared uncompressed size**, which is
available before any of its bytes are read. That moves the bound in both
directions: tighter than `compress`'s 512 MiB default for the small members a bomb
hides among, and *looser* for the legitimate member that is bigger than 512 MiB,
which the default would refuse. A member's data is also required to fit between its
local header and the central directory, so a stored member that declares more bytes
than are there cannot be handed the directory's own bytes as its contents - the CRC
would catch that afterwards, and afterwards is after a caller who ignored the
status has already been given them.

### Encryption, which is two answers rather than one

Encryption is **two schemes and not a bit**: ZipCrypto is broken and is read and
never written. WinZip AES is read and written, and `security` is a dependency of
this library for that, with no feature gate. "Unsupported" alone cannot tell a
caller which they are looking at, nor whether a password could ever help. A
member's metadata is in the clear in both schemes, at every password strength -
zip cannot hide which files exist, and 7z's encrypted header can. AES wraps the
compressed bytes. `compress` is unchanged.

That a member's *metadata* is readable and its *data* is not is an **ordinary
state** in zip rather than a failure: an archive with one bzip2 member is still an
archive to walk. So the refusal lives on the read rather than on the walk, and
`garc_read_member()` answers it before the size check - a zero-length member of an
unreadable kind must not read as a successful end of data.

#### ZipCrypto, and why a wrong password needs three statuses

`garc_zip_set_password()` decrypts the traditional PKWARE cipher. **The whole
cipher is CRC-32**, which is why it needed no cryptography library and landed with
the rest of zip rather than behind `security`: three 32-bit words are mixed with
each plaintext byte, and two of the three steps are one table lookup of the CRC-32
polynomial - `gcomp_crc32_update()` over a single byte, exactly, because that
function operates on the unfinalized running value and the cipher's step has no
inversion in it either.

It is broken - Biham and Kocher's 1994 attack recovers the keys from about a dozen
known plaintext bytes, and a zip is full of known bytes - and that is not a reason
to refuse reading what exists in the world. **Writing it is refused permanently**,
because no option name makes shipping a cipher we know is broken honest.

Three decisions worth arguing about:

**ZipCrypto's keys are derived at `garc_zip_set_password()`, and the password is
kept beside them.** Every ZipCrypto member starts from the same three words, so
those are stored at the call. An AES member has its own salt, which is not known
until the member is reached, so the password bytes are copied and wiped on
release. An empty password is a call with length 0, which is distinct from never
having called it.

**Decryption is a stream, not a transform.** ZipCrypto encrypts the *compressed*
bytes, so for a deflated member the layering is decrypt-then-inflate: the decrypting
view sits under the bounded slice the decoder reads. Getting that the other way
round reads a stored member correctly and a deflated one not at all, which is why
the corpus has `infozip-crypto-deflate.zip` as well as `infozip-crypto.zip`.

**A wrong password gets three statuses and not one**, because the cipher makes it
distinguishable to three different degrees. The failure to avoid is
`limit-bounds-not-status` in a new costume: one code for all three cannot tell a
wrong password from a damaged member.

| status | when | evidence |
| --- | --- | --- |
| `GARC_ERR_PASSWORD_REQUIRED` | encrypted, none supplied | unambiguous |
| `GARC_ERR_PASSWORD_REJECTED` | the encryption header's check byte disagreed | one byte; catches 255 wrong passwords in 256, and the only other cause is a corrupt header |
| `GARC_ERR_PASSWORD_OR_CORRUPT` | the member decrypted and its CRC-32 disagreed | **none that separates the two causes** |

The third names two causes on purpose. ZipCrypto has no authentication tag, so a
key that got past the check byte and a corrupted ciphertext produce the same
observation; reporting `GARC_ERR_CORRUPT` would claim the data is at fault and
`GARC_ERR_PASSWORD_REJECTED` would claim the password is, and both would be a guess
dressed as a finding. WinZip AES authenticates the ciphertext with an HMAC-SHA1,
and the member stores the first 10 bytes of the digest. The verifier in front of
the ciphertext is 16 bits, so a wrong password can pass it and then fail the
HMAC. That failure is `GARC_ERR_PASSWORD_OR_CORRUPT` for the same reason the CRC
disagreement is: the caller cannot tell a wrong password from a damaged member.
AE-2 stores a CRC of 0 and does not check it. AE-1 still checks the CRC, and a
mismatch is the same status.

**The check byte has two conventions and the corpus decided which to implement.**
APPNOTE says the twelfth header byte is the high byte of the member's CRC-32.
Info-ZIP sets general purpose flag bit 3 on every encrypted member it writes - the
sizes and the CRC go in a data descriptor *after* the data, so there is no CRC to
derive it from - and uses the high byte of the DOS time instead. In
`infozip-crypto.zip` the check byte is `0x0D` and the CRC's high byte is `0x51`: a
reader that knew only APPNOTE's convention would reject the correct password for
every encrypted archive `zip` has ever produced. Both are accepted, the time's only
when bit 3 is set, which is what unzip does - and the test that pins it is a pair of
built archives differing in that bit alone, because no writer here produces the
APPNOTE convention at all.

**The real method is answered before the password**, which is a choice rather than
an accident. A member whose method has no codec here can only be refused, so
asking for a password first would send a caller to a prompt and refuse them
anyway. For WinZip AES the header method stays 99, which is what
`garc_zip_member_method()` reports, and the real method is the last two bytes of
the 0x9901 field. That real method is what selects the codec. An unsupported one
is `GARC_ERR_UNSUPPORTED` with no password prompt. A compressed size shorter than
the salt, the verifier and the authentication code is `GARC_ERR_CORRUPT`, and
that check does not depend on a password either.

### Times, modes and types, each from the field that is allowed to say

**Three fields can carry an mtime** and the most precise wins: the 0x000a NTFS
field (100-nanosecond intervals since 1601, which 7-Zip writes in the directory
only), then the 0x5455 extended timestamp (epoch seconds), then the MS-DOS field.
`GARC_Member.mtime_source` says which answered, because they can disagree.

The DOS field **carries no time zone and never has**, so converting it is a
decision: this library reads it as UTC and `GARC_TIME_ZIP_DOS` is how a caller
knows that is what happened. Reading the host's zone instead would make one
archive answer two ways. An out-of-range field - a date of zero has month 0 and
day 0 - is reported as *no* time rather than as the date the arithmetic would
invent.

A **mode** is only meaningful when `version made by`'s high byte says Unix. On a
DOS or Windows archive that half of `external_file_attributes` is zero rather than
absent, so a reader that read it unconditionally would report a mode of 0000 for
every member of a perfectly ordinary zip.

A **type** has three sources in order: a name ending in `/`, which is the
convention every tool follows and the only one a DOS archive has; the DOS
directory attribute bit; and then the Unix mode's `S_IFMT`, which is the only
place a symlink is distinguishable at all, since zip has no type field. There are
no hard links in zip.

A **symlink's target is the member's data**, so reporting one means reading data
during the walk. This library does that eagerly where it is cheap and certain -
stored, unencrypted, and no longer than a name is allowed to be - and leaves
`link_target` NULL otherwise. The alternative was reporting no target for any zip
symlink, which would leave the filesystem layer of phase F unable to ask the
question it exists to ask.

### Duplicate names are reported, not resolved

Two members may declare the same name, and every reference accepts such an archive
and reports both. So does this: silently picking one would be deciding which of
two answers a caller wanted, and the two have different contents.
`garc_find()` returns the first, which is the same rule the tar reader follows.

## 8. The result vocabulary, and its two departures

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

## 9. The stream

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

## 10. The sink, which is not the stream with a `write` added

Bytes leave through `GARC_Sink`, a separate type. The alternative - one
`GARC_Stream` with a `write` callback beside `read` - was refused for a reason
worth writing down, because it is the obvious economy: four of the stream's five
operations mean nothing on the way out. There is nothing to read, nothing to
skip, and a sink's length is what it has been given rather than something to ask
about. One struct would have been one required callback and four optional ones
whose absence meant four different things, and `GARC_Stream.read` - required
today, which is what makes every stream usable without a capability check -
would have had to stop being required.

Three differences from the read side, each of them the format's answer rather
than a preference:

- **A short write is a failure, where a short read is not.** Reading fewer bytes
  than asked for is the end of the stream, which is ordinary and is reported as a
  count. There is no corresponding end of a sink: a callback that can take only
  some of the bytes has failed. So `write` is all-or-nothing and reports no
  count, which also keeps the retry loop out of every call site - one of them
  would have got it wrong.
- **A memory sink owns its buffer, where a memory stream borrows one.** The bytes
  a reader reads already exist. The bytes a writer writes do not, and their
  number is not known until the archive is finished, because a name decides
  whether a pax record joins the header that carries it. `garc_sink_data()` lends
  the result back, valid until the next write, and answers
  `GARC_ERR_UNSUPPORTED` for a callback sink - which is the same refusal
  `garc_stream_size()` makes about an unknown length, for the same reason: a sink
  holding no bytes and a sink that never holds any are different facts.
- **There is no `seek`, and that is this cut rather than the design.** tar is
  append-only: every byte is written once, in order, and nothing is patched
  afterwards. zip is not - a streamed local header carries zeros where the sizes
  go, and the writer either follows the data with a descriptor or seeks back to
  fill them in - so a `seek` callback and a `garc_sink_is_seekable()` arrive with
  the writer that reads them. This is the same discipline the manifest line gets:
  three edits rather than one, each true when it is made.

**Growth is geometric with an exact-size retry**, and the retry is not only a
guard against a doubling that would overflow. An overflow-only fallback needs a
host holding `SIZE_MAX` bytes, so it is a line no test can put in a position to
fail; asking for the exact size when the geometric request is refused is
reachable from the failing allocator, *and* it is what lets a sink finish an
archive on a host that cannot spare twice the room it already holds. cutil's
growable array does the same thing for the same reason, which is why
`FailingAllocator`'s `run = 2` exists - one logical append costs two requests, so
refusing one request cannot fail it.

**A failed write does not move `garc_sink_tell()`.** That offset is what a writer
computes padding from, so counting a refused write would pad the next member to
the wrong boundary - and every reader would then report the damage at a header
some distance after the cause.

## 11. Writing tar, which is one header and a record for the rest

The writer emits **pax**: a ustar header with every field filled in, and an
extended record only for what ustar cannot say. A reader that knows only
POSIX.1-1988 therefore gets a correct answer wherever one exists in its
vocabulary, and a reader that knows pax gets the exact one. The alternative -
records for everything with the fields left blank, which is legal - produces an
archive half the world reads as empty.

`GARC_TAR_USTAR` is the same code with the records turned into a status: anything
that would need one, or a base-256 field, is `GARC_ERR_UNSUPPORTED` naming the
member. That is not a second writer. It is what makes every threshold in the
table below *testable as a threshold* rather than as "a record appeared", and it
is what a caller who needs an archive a 1988 reader can read actually wants -
to be told, rather than handed one with records in it.

### What the three references disagree about

Measured rather than assumed, with `tools/oracle/`. Each row is a decision this
writer had to make and each reference makes it differently, so none of them could
simply be copied:

| | GNU tar 1.35 | libarchive 3.7.4 | Python 3.13 `tarfile` | this writer |
| --- | --- | --- | --- | --- |
| numeric field | 7 digits + NUL | 6 digits + space + NUL | 7 digits + NUL | **7 digits + NUL** |
| the ustar name split | never | always | never | **when it is exact** |
| fields behind a `path=` record | truncated | split, dropping components | truncated | **truncated** |
| the extended header's name | `<dir>/PaxHeaders/<base>` | `PaxHeader/<base>` | `././@PaxHeader` | **`././@PaxHeader`** |
| device fields on a non-device | blank | `000000 \0` | blank | **blank** |
| end padding | to 20 blocks | two zero blocks | to 20 blocks | **two zero blocks**, or a blocking factor |

And the reasons, because each is a judgement rather than a coin toss:

- **The widest octal run.** Seven digits rather than six holds one more octal
  digit, which is three more bits before an extended record becomes necessary.
  libarchive's space is equally legal and expresses less.
- **The split when it is exact.** A name too long for the 100-byte field can
  often be cut at a `/` into a 155-byte prefix and a 100-byte name, which between
  them hold 255 bytes with no record at all. Only libarchive does this. It is not
  a compromise: it is the ustar format doing the job it has a prefix field for,
  and it means a ustar-only reader gets the *whole* name rather than its first
  hundred bytes. The last usable slash is chosen, so the name field holds the
  basename.
- **Truncation when it is not.** Here libarchive splits anyway, at a slash that
  leaves the middle of the path out: a 300-byte `f…/g…/h…` goes out with `f…` in
  the prefix and `h…` in the name, so a ustar-only reader sees a path with a
  directory silently missing. Two of three references truncate, and the argument
  agrees with them - every answer here is wrong, and a *recognisably* wrong one
  beats a *plausibly* wrong one. A truncated name puts a file with a mangled name
  in the right place; a name with a component dropped puts it somewhere else.
- **A constant for the carrier's name.** Nothing reads it - it names a carrier,
  and a carrier is not a member - so the choice falls to what costs least. A
  constant cannot be truncated, needs no basename arithmetic, cannot collide with
  a real path because `././` is not something a filesystem produces, and is
  already in this library's vocabulary from GNU's `././@LongLink`. The carrier's
  mode, owner and time are **zero rather than the member's**: it is not a file,
  and a reader that extracted it anyway should not be handed the member's mode to
  apply to it.
- **Blank device fields.** Every header in the wild leaves them blank on a
  non-device, the reader reads blank as zero and reports no device at all, and
  writing `0000000` there would be putting a number where the archive has none.
- **Two zero blocks.** 10240 bytes was a tape record. Every reader accepts
  either, and this library's archives are built in memory and handed to a caller
  far more often than written to tape - so the padding is an option, defaulting
  to none.

### What makes an extended record necessary

One table, and every row has a test at the last value that fits and the first
that does not, because a cap tested from one side cannot tell a cap that is off
by one from a cap that is right:

| field | fits | beyond it |
| --- | --- | --- |
| name | 100 bytes, or 255 with a usable `/` | `path=`, field truncated to 100 |
| link target | 100 bytes | `linkpath=`, field truncated to 100 |
| owner, group name | 32 bytes | `uname=`, `gname=` |
| size | 8589934591 (11 octal digits) | base-256 **and** `size=` |
| mtime | 0 … 8589934591 | base-256 **and** `mtime=` |
| uid, gid | 2097151 (7 octal digits) | base-256 **and** `uid=`, `gid=` |
| mode, device numbers | 2097151 | base-256, and no record: pax has no key for them |

**Both statements say the same number**, which is the opposite of the reader's
"one payload, two readings" refusal and is why writing base-256 beside a record is
safe rather than ambiguous. A reader that does base-256 gets the right answer from
the field alone; a reader that does not gets an error rather than a wrong number,
because a high bit is not an octal digit. The third option - zeroing the field, as
`tarfile` does - is the one that gives every reader a wrong answer: a ustar reader
then skips no data and reads the member's contents as headers.

`hdrcharset=BINARY` is written, first in the set, when any value in it is not
well-formed UTF-8. POSIX says a record's bytes are UTF-8, so writing bytes that
are not without saying so would put a claim in the archive that this library's own
reader reports back as `GARC_NAME_UTF8` - a declaration made by the writer rather
than by the data. Whether the bytes are UTF-8 is asked of `garc_name_check()`,
because a second validator is a second answer.

### What the writer refuses

Each of these is the caller's argument being wrong rather than the format falling
short, so each is `GARC_ERR_INVALID`:

- **An empty name**, which is how an archive says the name is elsewhere.
- **A NUL in the name, the link target, or either owner name.** A NUL ends a
  header field and does not end a record, so the value would be two different
  values depending on which a reader believed. Written as a sweep over all four
  strings rather than a check per field, because the first version checked two of
  them and the fuzz harness found an owner name of raw bytes coming back empty
  within four thousand executions - four near-identical checks is the shape where
  the fourth gets forgotten.
- **`GARC_MEMBER_OTHER`**, which is a *reading* of an unnamed typeflag rather
  than a thing to write. There is no byte to put in the field.
- **A size on a member that carries no data.** The reader ignores a stale size
  there because real archives have one; a writer cannot, because it would accept
  the declaration and then refuse every byte written against it.
- **A symlink or hard link with no target**, and a device with no numbers. Both
  are the member's defining field.
- **A sub-second time that did not come from a pax record**, which says two
  things at once, and a nanosecond count of a whole second or more.

And two things it deliberately does *not* refuse, because the reader produces
both and a library that cannot write back what it reads is one that disagrees with
itself: a **link target on a member that is not a link** - the linkname field is
read whatever the typeflag says, because a hostile archive can carry one - and a
name `garc_name_check()` has findings about. Nothing is normalised either: a
directory's trailing slash is the caller's to include, and the typeflag is what
says it is a directory.

### What a round trip can and cannot promise

Two fields cannot survive one, and both are facts about tar rather than defects.
Both are asserted rather than absorbed into a tolerance:

- **`mode_valid` and `ids_valid` come back set.** Every tar header *has* a mode
  field, so a writer cannot un-have one; a member written with `mode_valid` clear
  reads back with mode 0 and the flag set.
- **`GARC_TIME_NONE` comes back as `GARC_TIME_TAR_OCTAL` with a time of zero**,
  for the same reason: the header has an `mtime` field whether or not the caller
  had a time, and zero is what goes in it.
- **`mtime_source` cannot always be kept.** `GARC_TIME_PAX_DECIMAL` is honoured
  as a request - a record is written even for a whole second, so a member read out
  of a pax archive and written back still says a record answered - but a time the
  octal field cannot hold can *only* be a record, so it reads back as
  `GARC_TIME_PAX_DECIMAL` whatever was asked. The writer's fuzz harness found that
  on its first run, by asserting that it could not happen.

## 12. Writing zip, which is a directory written last

The reader trusts the central directory, so the writer's job is to produce one
worth trusting: every offset in it is a position recorded on the way past, and
nothing re-reads what it wrote. Three problems the format sets, and each shaped an
interface rather than a function.

### A local header carries two values the writer does not have yet

A member's CRC-32 and compressed size are not known until its data has been
written, and the local header goes in front of the data. There are exactly two
lawful answers: leave zeros and put the real values in a **data descriptor** after
the data with general purpose flag bit 3 set, or **go back and fill the header
in**.

Both are here, chosen by ::GARC_Zip_Sizes, and it is an option rather than an
internal route because it is a property of the archive: a consumer reading a zip
as a stream needs the descriptors and some old tools refuse them.
`GARC_ZIP_SIZES_AUTO` asks the sink, `DESCRIPTOR` always streams, and `LOCAL`
refuses a sink that cannot be patched - `GARC_ERR_NOT_SEEKABLE`, by name, before a
byte is written, because failing later would leave a truncated archive behind a
refusal.

**The central directory always carries the real values**, in every discipline. A
descriptor is for the local header's benefit; the directory has never had an
excuse, and it is what a reader believes.

### So the sink gained a patch, and deliberately not a seek

`sink.h` had promised this would arrive "with the writer that reads them", and what
arrived is narrower than a seek on purpose:

- **A patch cannot extend the archive.** The range is checked against
  `garc_sink_tell()` before the callback is reached, so that figure keeps meaning
  "how long this archive is" at every moment - and every padding calculation in
  the writer reads it. A `seek` would make it a *position*.
- **A caller implementing `seek` would have to remember to come back.** One
  `patch` that saves and restores its own position is a contract they satisfy once;
  two calls they must pair correctly is one they can get wrong per member.

`garc_sink_is_seekable()` is the question, and **a compressing sink answers no at
any time**: a codec's output for a byte depends on every byte before it, so there
is no offset in the compressed stream that corresponds to a field in the
uncompressed one. A zip written through one therefore has descriptors, which is
the same answer a pipe gets and for a deeper reason.

### zip64 is per field and per record

A value that does not fit is `0xFFFFFFFF` in its slot and real in a 0x0001 extra
carrying **only the marked fields**, in the specification's order. That makes the
two records disagree about how many fields are in the extra, and the disagreement
is correct: in the local header the compressed size is unknown when the header is
written, so it is marked whenever zip64 is in play; in the directory it is known
and fits. `zip -fz` produces exactly that asymmetry - 16 bytes of payload in the
local header against 8 in the directory - and `infozip-zip64.zip` in the corpus is
the evidence, so `GARC_Writer_Options.zip_force_zip64` reproduces a real writer's
output rather than a plausible one.

The threshold is otherwise the rule the format wants: **not before it is needed**,
because an archive carrying zip64 fields unnecessarily is refused by some old
readers. The forced flag exists because the upper side of that threshold is a 4 GiB
member and a test needs both sides.

### Deflate, and what decides a member's method

`GARC_Writer_Options.zip_method` takes `GARC_ZIP_METHOD_STORED` or
`GARC_ZIP_METHOD_DEFLATE` and refuses every other value at
`garc_writer_create()` - including the ones this library can *read*. Reading a
method means owning a decoder; writing one means choosing to produce it, and a
zstd member is refused by enough readers that a caller should have to name it.

**Stored is the default, and the reason is the zero.** Every field in
`GARC_Writer_Options` is written so that a zero-filled struct either behaves like
the defaults or is refused outright, and `GARC_ZIP_METHOD_STORED` is 0 - so a
default of deflate would make this the one field where `memset` and NULL disagree.
Compression is one assignment away, and the assignment is visible in the caller's
code.

Two members are stored whatever the option says:

- **One with no data.** Deflating nothing produces a two-byte empty final block,
  so the choice is between a member occupying 0 bytes and one occupying 2, and
  every reference writes the first. A directory reaches it without ever having had
  the option.
- **A symlink.** Its target is its data, and a target is a path: short enough that
  deflate rarely helps, and wanted by every reader that cares where the link
  points. **This was a finding rather than a preference.** The first version
  deflated targets along with everything else - consistently, since the target
  *is* the data - and they then came back empty from this library's own reader,
  which reads a target eagerly only when it is stored. Checking the corpus settled
  which side to fix: every symlink in it is stored, Info-ZIP's included.

**A member whose data does not compress is still deflated.** The method is in a
local header written before the first byte of data arrives, so there is no point
at which it could be changed back. `zip` stores such a member instead, which it
can because it has the whole file on disk before it writes anything; a streaming
writer does not. The cost is deflate's stored-block overhead, and the example
program shows it: five tiny members come out six bytes *larger* deflated than
stored.

One encoder per archive, reset between members, because each member is an
independent deflate stream and an archive of ten thousand small files should not
allocate ten thousand windows. The CRC-32 is of the **uncompressed** bytes in both
methods - it is what an extractor checks after inflating - which is the one field a
writer that checksummed its own output would get wrong, and every reader would then
reject the deflated member while accepting the stored one.

### The zip64 threshold moved, because deflate can expand a member

A member's zip64 fields are decided before its data exists, so the compressed size
is not available to decide on. What stands in for it is not the declared size but
the **largest the compressed size can be**: `garc_zip_deflate_bound()`, which is
`gcomp_encode_bound()` for deflate with its failure modes collapsed into "assume
the worst".

The alternative was to decide on the declared size and refuse when the compressed
size turned out to cross 4 GiB after all - a refusal arm reachable only by a member
of very nearly 4 GiB that deflate expands, which is a line nothing could put in a
position to fail. Deciding on the bound has no such arm: a member whose bound fits
a 32-bit field cannot produce a compressed size that does not. The cost is that a
member inside the bound's slack gets zip64 fields it would probably have done
without - about the top ten megabytes of the 4 GiB range - and being wrong in that
direction costs an archive a few readers from 1993 where being wrong in the other
costs it a size field it cannot write.

**The bound is asked for rather than derived, and that was a finding too.** The
first version spelled RFC 1951's own worst case - five bytes of stored-block header
per 65535 bytes of payload - and compress's encoder reserves rather more, so the
constant sat *below* the implementation's real bound for every size over 65534. The
test comparing the two caught it on its first run, which is the whole argument for
writing that test before trusting the constant.

### Three decisions about a member

**The type bits come from the type and the permissions from the mode.** A zip has
no typeflag: what makes a member a symlink is `S_IFLNK` in the high half of its
external attributes. A caller copying a member out of a *tar* has permissions in
`GARC_Member.mode` and nothing else, because tar's mode field carries no type - so
taking `mode` whole turns every symlink copied from a tar into a regular file,
which is what the first run of this writer did. A caller copying out of a zip has
the type bits in `mode` as well, and composing from `member->type` reproduces them
exactly, so there is no need to ask which kind of caller it is.

**A symlink's target is written for the caller.** In zip the target *is* the
member's data, so the caller sets `link_target` and writes nothing, exactly as for
a tar - which is what lets an archive be copied from tar to zip without the caller
knowing which it is writing. It is the one place this writer puts bytes in a member
the caller did not hand it.

**One extra field, and it is conditional.** 0x5455 carries the mtime as an epoch
second, written only when the MS-DOS pair cannot hold the time exactly - which is
what keeps "write the minimum" true: an archive whose every time is an even second
in range has no extra fields in it at all. The condition has three parts and the
third was a defect a test found: the extra field holds a **signed 32-bit** second,
so it stops in 2038 where the DOS date runs to 2107, and a time past that was
being truncated into it - 2108 came back as 1971, which is worse than the clamp it
existed to avoid. Above `INT32_MAX` the DOS pair is the better of the two.

No Ux, no Unix uid/gid, no NTFS timestamp. **A zip cannot carry an owner**, and
that is the format rather than this cut.

### What it refuses, and why each is a refusal

A fifo, a device, a hard link and `GARC_MEMBER_OTHER`: zip's attributes could carry
the mode bits, but there is no convention for what such a member's *data* is and no
reference here writes one, so it is refused by name rather than invented. A name
the 16-bit length field cannot hold, because zip has no carrier record to put a
longer one in. And the tar writer's own refusals - an empty name, a NUL in a name
or a target, a size on a member that carries no data.

### The UTF-8 flag is a claim, and the gate caught it being made falsely

Bit 11 says a name is UTF-8. The first version of this writer set it whenever a
name had a byte above 0x7F, which is a different question - so a name carrying raw
bytes got the flag, and an archive that *claims* UTF-8 about bytes that are not is
refused outright by Python's `zipfile` and has the member skipped by libarchive.
That is `mal-utf8-lie.zip` in the corpus, built on purpose to be hostile, produced
by accident from an ordinary name.

The flag is now set only when the name is not ASCII **and** is well-formed UTF-8,
using `garc_name_check()`'s validator rather than a second one. With it clear such
a name is cp437 by specification, which every reference accepts.

**Nothing that ran inside this process could have found that.** The round-trip
tests passed, because this library reads back what it writes either way; it took
handing the bytes to four other programs. That is what `check-zip-writer` is for.

## 13. Testing

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

**The zip harness walks each archive twice and compares.** Once with a password
and once without, asserting that every member's name, size, method, CRC, encryption
and data offset match - because a zip's metadata is in the clear at every password
strength, so the walk must not depend on the caller's secret. It earned that
invariant within its first two minutes, and not with a crash: an encrypted member
shorter than its own 12-byte encryption header was refused when a password was set
and walked past when one was not, because the length check lived inside the
decryption setup. The same archive was corrupt to a caller who had the password and
readable to one who did not, and a refusal that arrives only for some callers is
worse than either answer. Both of that member's structural checks now happen before
the password is looked at.

The harness also has no stream-shape axis, which is the difference from the tar
one: a zip on a pipe is `GARC_ERR_NOT_SEEKABLE` before a byte is parsed, so half the
inputs would have been spent on one branch.

**The writer harness can check the answer, not only the survival.** The others
check invariants that hold *by construction* - that `tell` advances by exactly what
`read` reported, that a traversal implies a parent component, that prefixing
`safe/` cannot turn a contained name into an escape - which is real and is not the
same thing as an expected value. `fuzz_writer` has an expected value for free,
because an archive it writes is an archive the reader reads: the member that comes
back either is the member that went in or it is not. It also checks that a *refused* member left the sink's offset exactly where it
was - not merely lower - that two writes of one member produce identical bytes, and
that `GARC_TAR_USTAR` refuses a superset of what `GARC_TAR_PAX` refuses.

It earned that twice within its first four thousand executions, and neither finding
was a crash. The first was an over-strong invariant of its own: a negative time can
only be written as a record, and a record *is* `GARC_TIME_PAX_DECIMAL`, so
`mtime_source` cannot always survive a round trip - which is now said in
`writer.h`. The second was a real gap in the writer's own validation: a NUL was
refused in a member's name and in its link target and not in its owner names, so an
owner name of raw bytes came back empty. Four near-identical checks is the shape
where the fourth gets forgotten, and the fix is a sweep over all four rather than a
fourth check.

What it cannot find is a field with the wrong *meaning*: a writer and a reader that
share a misunderstanding agree perfectly. That is what `make check-oracle` is for.

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

### The malicious zip corpus, and the three references that disagree

The hostile zip fixtures are written by **Python's `zipfile`**, not by the tool
that wrote most of the corpus. `zip` has no `--transform`: it resolves a path
against the filesystem before storing it, so there is no way to ask it for
`../../../tmp/x`. Python's module is the only one of the four that stores the name
it is handed, which makes it the writer here - and means that for these fixtures
**the writer is not one of the references that read them back**.

The verdict file has three reference columns where tar's has two, and the first
thing to say about it is what it is *not*:

**zip has no reference that states a policy.** PEP 706 gave `tarfile` a
`data_filter` whose verdict is a documented decision; `zipfile` has no equivalent
and never did. So every column in `tests/data/zip/verdicts.tsv` is an *action* -
`same`, `rewrite=<name>`, `refused=<reason>` - and a Python exception in it is the
*filesystem* answering, not a check refusing. `a/..` raises `IsADirectoryError`
because the name sanitises to `a`, which the previous member already made a
directory; reading that as a safety verdict would credit Python with a check it
does not perform. The rewrite *target* is recorded rather than a bit, because the
targets are the finding and none is derivable from another.

Three references, three different masks, each row measured:

| | unzip 6.00 | libarchive 3.7.4 | Python 3.13.5 |
| --- | --- | --- | --- |
| `..` component | rewrites to `__` | refuses | resolves away |
| `./` and `//` | drops | keeps | drops |
| `..\..\..\x` | one filename | **translates, then refuses** | one filename |
| `C:\x`, `\\s\h\x` | one filename | splits into directories | one filename |
| a control byte | strips | keeps | keeps |
| a name that is not UTF-8 | writes the bytes | writes the bytes | **re-encodes** |

**libarchive answers differently for zip than for tar, at the same version.** For
a tar member it created `Windows\ghoti` and `server\share\ghoti` - one filename
each, backslashes intact - where for a zip member it created `Windows/ghoti` and
`server/share/ghoti`. And for a tar it created both halves of the
composed/decomposed `café` pair; for a zip it created one, silently, with exit 0:
four members in, three files out. A mask written once for "libarchive" would be
wrong for one of the two formats, which is why `test_zip_names.cpp` carries its own
and says so.

That last one is worth stating as a property of the corpus rather than of the
library: `mal-collisions.zip` is in it because a collision is a property of a
*pair* of names and no per-name check can see one - and one reference makes the
collision real.

Two fixtures differ only in general purpose flag bit 11, which is the whole of what
a zip ever says about a name's encoding. With it clear the name is cp437 by
specification and all four references read the archive; with it set the archive
claims UTF-8 about bytes that are not, and Python and libarchive both refuse the
whole file. So the second one contributes no rows to any per-member reading, and
the claim it exists to support - that the finding comes from the bytes and not from
the flag - is made by this library's own walk instead.

One consequence for `manifest.tsv`: a member with bit 11 clear has its name
re-encoded from cp437 rather than from UTF-8 before it is written to that file,
because `zipfile` decodes such a name as cp437 and re-encoding it as UTF-8 would put
a name in the manifest that is in no record of the archive. Every name in the corpus
that is ASCII is unaffected, which is why this only had to be got right once there
was a fixture that was not.

A link target is the other half, and in zip it is the member's **data** rather than
a header field - so it cannot be asked about until the member has been read, which
is a different order of operations from tar. `mal-links.zip` holds an absolute
target and one that climbs out of any root, and the finding is that **neither unzip
nor libarchive objects to either of them**: both create the links without a word.
For a zip link target there is no reference to agree with, which is the case where
writing the corpus first mattered most - because it is the case where agreement
would have been no evidence at all.

### Four gates, and what each cannot see

| gate | needs a container | catches |
| --- | --- | --- |
| `check-corpus-hashes` | no, and so it is in `TEST_GATES` | a fixture edited, truncated, or half-committed |
| `check-corpus` | yes | the references no longer *writing* these bytes |
| `check-oracle` | yes | the references no longer *reading* them the same way, or no longer *deciding* the same way about them |
| `check-writer` | yes | **this library's tar** no longer producing something the references understand |
| `check-zip-writer` | yes | **this library's zip** likewise, against four references rather than three |

The split matters in both directions. Hashing needs only sha256, so it runs on
every machine; regenerating needs the image, so it fails closed rather than
skipping - a gate that skipped would make a machine with no engine look exactly
like one where the references still agree. And `check-corpus` and `check-oracle`
are not the same question: a tar release can change how a field is parsed without
changing any output, and a suite that only regenerated would call that a pass.
`check-oracle` is also the only thing that catches a manifest edited *and*
rehashed to make a failing test pass.

`check-zip-writer` is the zip half of `check-writer`, and it earned its place on
its first run: the writer was setting the UTF-8 flag on a name that is not UTF-8,
which no test inside this process could see because this library reads back what it
writes either way. Python refused the whole archive and libarchive skipped the
member. Four planted regressions were then caught as well - a flipped CRC bit in a
directory entry, a name length one byte short, a symlink written as a file, and an
end record claiming one member too few.

It grew two archives when the writer learned to deflate, one with the compressed
size patched into each local header and one with it in a data descriptor, because
those are the two places that number goes and a *stored* archive cannot tell them
apart - its two sizes are the same number, so a writer putting the wrong one in the
local header passes every stored archive. Three more regressions were planted and
caught: the CRC taken over the compressed bytes instead of the uncompressed ones
(Python refused the archive outright), the uncompressed size written into both the
local header and the descriptor (unzip refused it), and symlink targets deflated
again - which no reference minded, and which our own reading caught, because the
target came back empty.

One comparison got sharper rather than wider. libarchive deflates whatever it
re-writes, so the method column used to be skipped for its whole round trip; now it
is a predicate on the intent row, and libarchive *agrees* about every member we
deflated. The skip applies only to the members we stored, which is a statement about
libarchive rather than a hole in the gate.

What it compares, and what it deliberately does not: four archives, the same member
list encoded four ways, are accepted by unzip, bsdtar, 7-Zip and Python, with
`unzip -t`, `7z t` and `zipfile.testzip()` each recomputing every member's CRC.
`unzip -Z1` is the byte-faithful **name** reference for zip - it prints a high byte
and a literal backslash as they are, where GNU tar needs `--quoting-style=literal`
to do the same for tar. libarchive answers **type, mode and link target**, which
Python's module does not decide, and its name is compared only where the intended
name has neither a backslash nor a high byte, because libarchive treats the first
as a separator and renders the second as octal. Then both bsdtar and Python
**re-write** every archive and this library reads what they produced: `bsdtar
--format zip` deflates as it does so, so the method column is skipped and the size
and CRC are not - libarchive deflated our bytes and we inflated them back to the
same bytes with the same checksum.

The two columns that are skipped as *findings* rather than as unasked questions are
named in `ROUNDTRIP_SKIP` with the reason beside each, and the count of skipped
fields is printed separately from the count of unasked ones - a figure dominated by
"this reference has no such column" is one nobody can act on.

The zip corpus has the same three gates under their own names -
`check-corpus-hashes` covers both corpora, `check-zip-corpus` regenerates and
`check-zip-oracle` re-reads - and five readings rather than three:
`manifest.tsv`, `names.tsv`, `openings.tsv`, `verdicts.tsv` and `decrypted.tsv`.
The last is the plaintext of every encrypted member as Python, unzip and 7-Zip
decrypt it, and it is what makes a ZipCrypto reader measurable instead of
self-consistent. `check-zip-oracle` is also the only gate that covers the four zip
fixtures with no digest in `CORPUS-ZIP`: two random encryption headers, a random
AES salt and an unsettable `st_ctime` mean their bytes move between runs, and what
is compared instead is what the references read - and, for the encrypted two, what
they decrypt, which is a function of the member and not of the random header.

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
