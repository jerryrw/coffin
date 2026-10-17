# coffin

Inspect executable files from the command line on Linux and macOS. coffin
(Common Object File Format Inspector) reports headers, hashes, sections, and
permissions for PE, ELF, and Mach-O files. All formats include whole-file and
section entropy. PE reports include imports, exports, decoded resource previews,
and raw resource extraction. ELF32 and ELF64 are supported in either byte order,
along with thin and universal Mach-O files. Reports include complete tables, and resource extraction can reconstruct
standalone icon and cursor files. ELF and Mach-O also report declared library
dependencies and symbols.

The project grew out of learning PE internals and malware analysis, with the aim
of making executable structure easier to explore from a Linux terminal. It is
under active development; supported formats and current limits are listed below.

## Quick start

Requires a C11 compiler, Make, the system math library, and iconv headers/library
(provided by the macOS SDK and common Linux C libraries).
From the repository directory:

```sh
make
bin/coffin hello-pe64.exe
```

The compiled Hello World samples live in the project root. Try an ELF32 file or
a universal Mach-O containing both arm64 and x86-64 executables:

```sh
bin/coffin hello-elf32
bin/coffin hello-mach-universal
bin/coffin /path/to/executable
```

The original `testexecutable.exe`, `testelf`, and `testmach` fixtures are also
available in the root. For example, `testexecutable.exe` includes a manifest
resource that coffin can preview and extract.

## Example output

A summary report for the root-level PE64 Hello World sample:

```sh
bin/coffin --summary hello-pe64.exe
```

```text
PE File Analysis Report
File: hello-pe64.exe
Size: 2048 bytes
SHA-256: 0b88e431d310c42b9102a2c6ac9dba7cff8b5a338187089328cd4eeeae6a4b2c
MD5: 1079c08fd9b0cf9f53d78ca85dbb4147
Whole-file entropy:  2.0791 bits/byte across 2048 file bytes
Entropy uses on-disk byte frequencies, including padding; virtual zero-fill is excluded from section measurements.
High entropy alone does not establish randomness, compression, encryption, or maliciousness.
Summary: PE32+ / x86-64 / 64-bit / little-endian
Entry point: RVA 0x00001000 | Image base: VA 0x0000000140000000
Counts: 2 sections | 3 imports | 0 delay-load imports | 0 exports | 0 resources

Structural observations:
  No findings from the implemented structural checks.
  These observations describe file structure; they are not malware verdicts.
```

## Usage

```sh
bin/coffin [options] <filepath>
bin/coffin --help
```

Reports are plain text on stdout. The default starts with file identity, hashes,
whole-file entropy, format/CPU/bitness/byte order, entry point, and table counts,
followed by
structural observations and compact tables. Numeric type names appear beside
their raw values; flags retain their hexadecimal representation.

| Option | Report behavior |
| --- | --- |
| `--summary` | Identity, hashes, whole-file entropy, summary, counts, and structural observations; omit detail tables |
| `--headers` | Format-specific header values |
| `--sections` | PE, ELF, or Mach-O section tables |
| `--imports`, `--exports`, `--resources` | Select PE tables; imports include ordinary and delay-load symbols |
| `--dependencies`, `--symbols` | Select ELF/Mach-O library and symbol tables |
| `--program-headers` | Select ELF program headers |
| `--load-commands` | Select Mach-O load commands and segment ranges |
| `--observations` | Select structural observations |
| `--entropy-window BYTES` | Add non-overlapping whole-file entropy windows, up to 4096 windows |
| `--no-preview` | Suppress decoded resource payload previews; retain metadata and extraction |
| `--verbose` | Add full field details after the compact report and progress on stderr |
| `--code-page N` | Fallback code page for resource text without a declared code page |
| `--extract-resources NEW_DIRECTORY` | Extract PE resource payloads and reconstruct supported icons/cursors |
| `--version` | Show the version embedded at build time |
| `--help` | Show command-line help |

Detail selectors can be combined. When any is supplied, only those detail groups
are shown after the summary. Unsupported selector/format pairs return an error.
`--summary` cannot be combined with detail selectors. With selectors, `--verbose`
adds available fields within the selected groups instead of printing unrelated
tables.

```sh
bin/coffin --imports --exports hello-pe64.exe
bin/coffin --resources --no-preview testexecutable.exe
bin/coffin --program-headers hello-linux-arm64
bin/coffin --load-commands hello-mach-universal
bin/coffin --dependencies --symbols hello-mach-universal
bin/coffin --verbose testexecutable.exe
```

Address labels distinguish file offsets, image-relative PE RVAs, and virtual
addresses (VA). Virtual addresses use 8 hexadecimal digits for 32-bit images and
16 for 64-bit images; file/container offsets use 16 digits. Universal Mach-O
section tables include both slice-relative and container file offsets.
Mach-O entry points are decoded from LC_MAIN; images that specify an entry
through thread-state commands instead are marked unavailable.

Structural observations identify declared writable-and-executable regions,
nonzero entry points outside declared executable regions, and PE sections with
entropy at least 7.5 bits/byte across at least 256 raw bytes. Relocatable ELF
objects are excluded from process-entry checks. These are explicit structural
checks; neither an observation nor its absence establishes whether a file is
malicious.

Errors go to stderr and return exit status 1; successful analysis returns 0.
Use `--` before a filename beginning with a dash, for example
`bin/coffin -- -sample.exe`.

## Supported formats

| Format | Supported input | Report |
| --- | --- | --- |
| PE | PE32 and PE32+ images, little-endian | COFF and optional headers, sections, permissions, UTC timestamp, entropy, imports, exports, resource tree and decoded previews; raw extraction |
| ELF | ELF32 and ELF64, either byte order, including extended numbering | Program and section headers, section names, flags, permissions, entropy, dependencies and static/dynamic symbols |
| Mach-O | Thin 32/64-bit images in either byte order; universal FAT32/FAT64 containers | Header, load commands, segments, individual sections, names, permission flags, entropy, linked libraries and nlist symbols |

### Linux ARM

The ELF inspector handles Linux ARM32 and AArch64 headers, program headers, and
sections. ARM reports include EABI version and declared floating-point ABI flags.
The Hello World fixtures use Linux syscalls and are statically linked, so no ARM
libc or target sysroot is needed to rebuild them with Clang and LLD:

```sh
make samples
bin/coffin hello-linux-arm32
bin/coffin hello-linux-arm64
```

These are Linux executables; macOS can inspect them but cannot run them directly.
To build and run coffin itself on a Linux ARM machine, use the normal `make` and
`make test` commands with a native C compiler and iconv development headers.

## Current limitations

Universal Mach-O reports every contained architecture (up to 64),
with separate section and command reports for each slice. FAT32 and FAT64 tables
are accepted in either byte order. Slice ranges, alignment, CPU identifiers, and
overlap are validated; nested universal containers are rejected. Slice file
offsets are relative to the slice; the report also gives its container offset.
Hashes in a universal report identify the complete container. Numeric fields are
decoded explicitly from bytes; parsing does not depend on host endianness or C
structure packing.

Default and verbose reports include every parsed PE section, import, export, and resource; every ELF
program and section header; and every Mach-O load command and section. Storage
grows with the input instead of truncating tables at 16 or 128 entries. Parser table arrays share a 64 MiB allocation-growth budget per input, including
all universal slices; each array accepts at most 100,000 entries. Metadata reads
share a separate 64 MiB byte budget and 1,000,000-read limit. Repeated ELF address
and extended-index lookups share 16,777,216 record visits. Exceeding these limits
returns an error with a `Parser resource limit exceeded` diagnostic and no report;
entries are never silently omitted. Universal containers accept at most 64 slices.
These fixed policies are defined in `include/common.h`.

The table budget is not a cap on total process memory: bounded decoding buffers,
entropy caches, and icon reconstruction have separate limits. Streaming hashes
still read the whole file, so these budgets impose neither a file-size limit nor
a wall-clock timeout on arbitrary inputs.

ELF32/ELF64 use the file's declared byte order. Extended section counts, section
name-table indices, and program-header counts are resolved through section zero.
ELF section names are limited to 255 display bytes, with an ellipsis for long
names. Name scans are bounded to 4,096 bytes per name and 16 MiB in total.
Filename fields in the legacy verbose details are limited to 255 bytes; the
report identity uses the supplied path. Permission labels describe header flags,
not runtime permissions; Mach-O sections show their containing segment's
initial permission flags.

## Inspection features

### PE directory details

- Imports list DLL names and named or ordinal symbols, with hints where present.
  Delay-load imports are marked in the compact table and listed separately in
  full verbose details. They support PE32/PE32+ RVA descriptors
  and legacy VA-based descriptors that can be represented by their 32-bit fields.
  Both 32-bit and 64-bit lookup tables are supported, including the FirstThunk
  fallback when OriginalFirstThunk is absent.
- Exports list names, ordinal-only entries, RVAs, aliases, and forwarder targets.
- Resources list type/name/language paths, sizes, code pages, RVAs, and payload
  file offsets. Numeric types such as MANIFEST and VERSION receive readable
  labels; named entries are decoded from UTF-16.

Compact resource tables place bounded payload previews below their rows: manifest text (UTF-8 or
BOM-marked UTF-16), version numbers and version-string fields, UTF-16 string
tables, DIB/PNG dimensions, and image-group counts. Additional decoders cover
standard and extended menus, accelerator keys and command IDs, standard
and extended dialog templates, message tables, and HTML text. Dialog previews
include font metadata, control IDs/classes/titles, signed coordinates, styles,
extended styles, help IDs, and creation-data sizes with a hex preview. Control
creation data remains application-specific bytes; it is not executed or used to
instantiate a dialog. Dialogs are limited to 4,096 controls. Other types receive a hex preview. Image support reports
metadata rather than rendering pixels. Text and
control characters are escaped for terminal display. Previews are limited to
2,047 bytes and payload decoding to 1 MiB per resource, with a 16 MiB aggregate
decode budget; larger payloads can still be extracted. Menu decoding is bounded
to 16 nested levels and 4,096 items, and message tables to 4,096 entries. Malformed
or unsupported payload encodings are labeled
in the report and remain available for raw extraction. Recovery of import names
from a bound IAT when no lookup table is available remains unsupported.
Directory ranges must fit within one file-backed section or the headers;
ambiguous overlapping RVA mappings are rejected. Directory strings must
terminate within 4,096 bytes; displayed strings are shortened with an ellipsis
when needed, and control bytes in import/export names are escaped. Resource
names accept up to 4,096 UTF-16 code units. Parsing is bounded by 100,000 RVA
lookups, 4,096 resource reads, a resource depth of 16, and a resource display path
of 767 bytes. Malformed directory structures and inputs exceeding these work
limits fail with an error rather than producing a partial report.

### ELF and Mach-O linkage

`--dependencies` lists ELF `DT_NEEDED` names and Mach-O load/weak/re-export/lazy/
upward library commands. Mach-O image-ID commands are labeled `image-id`, not
runtime dependencies; declared current/compatible versions and raw command IDs
are retained. Nothing resolves these paths against the inspection host or loads
libraries. Universal Mach-O reports each slice's declarations separately.

`--symbols` shows ELF static/dynamic symbol tables with names, values, sizes,
section indices, binding/type/visibility numbers, table identity, and whether a
symbol is defined. Mach-O `LC_SYMTAB` entries retain values, section indices,
raw type/description bits, external/local roles, and indirect-symbol target names.
These are table entries, not demangled names or an enumeration of all runtime
bindings. ELF symbol-version tables are not decoded. Mach-O bind bytecode, chained fixups, and export tries are not decoded.

ELF section tables provide exact symbol counts. Without sections, `PT_DYNAMIC`
still supplies dependencies; SysV or GNU hash metadata can recover the dynamic
symbol count. If that count cannot be recovered, the report explicitly says
symbols are unavailable. Mach-O without `LC_SYMTAB` is labeled similarly.
ELF extended symbol section indices use `SHT_SYMTAB_SHNDX` companions.
Linkage work is bounded to 100000 ELF table entries or Mach-O symbols/library
records (each category); strings must terminate within 4096 bytes and share a
16 MiB string-read/extended-index-scan work allowance per image. Limits fail
explicitly instead of silently truncating tables; display strings remain bounded.

### Terminal-safe output

Untrusted filenames, section/segment names, dependency names, and symbol names
escape control bytes, backslashes, and non-ASCII bytes as `\xNN`. This makes
ANSI escape sequences and invalid byte encodings visible in compact and verbose
reports and path diagnostics. These display escapes do not change input bytes,
hashes, decoded offsets, or extracted resource payloads. Resource Unicode names
and previews retain readable text while escaping control and direction marks.
Bounded display fields use an ellipsis when shortened.

### Legacy text encodings

Non-Unicode message tables, manifests, and HTML previews use the resource's
code-page field. Unicode flags and Unicode byte-order marks take precedence.
Supported mappings include Windows-1250 through Windows-1258, common OEM pages
437/850/866/874, Shift-JIS (932), GBK (936), Korean (949), Big5 (950), GB18030,
ASCII, ISO-8859 pages, and UTF-8/UTF-16. Conversion uses the platform's iconv
implementation; unavailable converters are labeled explicitly.

If the resource code-page field is zero, supply a fallback:

```sh
bin/coffin --code-page 1252 testexecutable.exe
```

The fallback does not override a declared code page or a Unicode marker.
Without a declared/fallback code page, message-table bytes are escaped and
labeled as unspecified; manifest and HTML previews default to UTF-8. XML/HTML
encoding declarations are not used to guess a different encoding. Invalid byte
sequences are labeled and preserved as escaped bytes. Extraction always retains
the original payload bytes regardless of the preview conversion.

### Extract resource payloads

```sh
bin/coffin --extract-resources ./sample-resources testexecutable.exe
```

The destination must not already exist and its parent must exist. Extraction
writes every resource entry using generated filenames. `index.tsv` maps each
filename to its resource path,
type, RVA, size, and code page. Files contain the original payload bytes;
manifest files retain their original encoding, bitmap files contain raw DIB data,
and raw icon/cursor payloads are preserved. For valid image resources,
coffin also writes standalone `.ico` and `.cur` files. Group resources produce
multi-image files; individual RT_ICON/RT_CURSOR resources produce single-image
files. Cursor hotspots move into the CUR directory entries, and PNG/DIB image
bytes are preserved. `index.tsv` includes a `reconstructed_file` column.

Image references are matched by resource ID and language, then a neutral-language
or unique-image fallback. Missing, ambiguous, or malformed image data leaves the
raw file available and marks reconstruction unavailable in the index. Each
reconstructed file is limited to 16 MiB and groups to 1,024 images. Files use mode
0600 and the directory uses mode 0700.

Extraction is limited to 256 MiB of total output, including reconstructed files
and repeated payload references. Existing destinations and symlinks are rejected.
A write failure
returns a nonzero status and may leave partial results in the new directory.
This option requires a PE input.

### Declared permissions

Reports label permissions as declared by the file. They describe PE section
characteristics, ELF header flags, or Mach-O segment initial protection flags.
Actual runtime permissions vary with loading, relocations, page layout, and
later changes by the process; coffin inspects files without executing them.

Mach-O sections report addresses, sizes, file offsets, alignment, raw flags, and
relocation counts. Zero-fill sections are identified as having no file bytes.

### File hashes

Every report includes the complete file's MD5 (32 hexadecimal characters) and
SHA-256 (64 hexadecimal characters), including when detail selectors are used.
For universal Mach-O inputs, both hashes cover the entire container.

The input is opened once. MD5 and SHA-256 are calculated together in one pass,
and parsers and entropy calculation reuse that stream. Keep the file unchanged
while analysis runs; an open stream is not a snapshot of concurrent in-place
writes. MD5 is included for sample identification.

The bundled C implementations use streaming contexts and constant memory.
SHA-256 processes complete 64-byte input blocks directly, buffers partial blocks,
and uses a `uint64_t` bit counter. The streaming contracts are documented in
[`include/md5.h`](include/md5.h) and [`include/sha256.h`](include/sha256.h):
initialize before updates, allow NULL input only for zero-length updates, finalize
once into a 16-byte MD5 or 32-byte SHA-256 output buffer, and reinitialize before
reusing a finalized context. Zero-length updates are explicit no-ops.

### Entropy measurements

All reports include whole-file Shannon entropy in bits per byte (0–8); section
tables include entropy for PE, ELF, and Mach-O file-backed sections. Universal
Mach-O whole-file entropy covers the entire container; section measurements use
the correct container offsets for each slice. Measurements count actual on-disk
bytes, including PE raw-section alignment padding, and exclude virtual zero-fill.
Empty PE sections, ELF NULL/NOBITS sections, and Mach-O zero-fill sections show
`N/A`, rather than a measured zero. File byte counts accompany the measurements;
ELF NOBITS and Mach-O zero-fill size fields describe memory, not measured bytes.

Section entropy is computed only when the selected report needs it. PE summary/
observation reports need it for their high-entropy check; focused headers/imports/
exports/resources reports skip it. ELF/Mach-O summaries and non-section selections
skip section measurements. Whole-file entropy remains in every report, and
`--entropy-window` always performs its explicitly requested windows. With
`--verbose`, the `Entropy work` line shows actual bytes read and cached ranges.

Use windows to inspect regions that a section average might hide:

```sh
bin/coffin --sections --entropy-window 4096 hello-pe64.exe
bin/coffin --summary --entropy-window 16384 hello-mach-universal
```

Windows start at container file offset zero, do not overlap, and include a shorter
final window when necessary. `BYTES` must be a positive decimal integer. Reports
are limited to 4096 windows; choose a larger window for larger inputs. Window
output is available with summaries and all detail selectors.

Entropy describes byte frequencies, not byte order. A predictable repeating
sequence of bytes 0–255 has entropy 8, just like a perfectly uniform histogram.
High entropy alone does not establish randomness, compression, encryption, or
maliciousness. Small samples and padding can substantially affect the result;
the PE observation threshold of 7.5 across at least 256 bytes is a heuristic.

Identical offset/length ranges share cached results, including sections that
alias the same bytes. Partially overlapping ranges are measured separately.
Each analysis permits at most 1 GiB of cumulative entropy reads and 131072
distinct nonempty ranges, counting whole-file, section, and optional window
measurements together. Exceeding either limit fails explicitly instead of
printing incomplete measurements. These limits bound entropy work, not the
separate hashing and parser passes. Entropy uses an 8 KiB read buffer and a
bounded cache; it never allocates a buffer the size of a section.

## Install and release preparation

```sh
bin/coffin --version
make install PREFIX="$HOME/.local"
make uninstall PREFIX="$HOME/.local"
make package
```

The version comes from [VERSION](VERSION). Installation supports `PREFIX`,
`BINDIR`, `DOCDIR`, and `DESTDIR`; the default prefix is `/usr/local`. Install
copies the executable and documentation; uninstall removes just those files.
`make package` creates an OS/CPU-specific archive and checksum in `dist/`.
See the [changelog](CHANGELOG.md) and [release checklist](docs/RELEASING.md),
including Linux/macOS verification and the tag-gated release-candidate workflow.
Preparing these files does not publish a release.

## Development

New to C or this codebase? Start with the [source reading guide](docs/SOURCE_GUIDE.md).
It explains the program flow, pointer ownership, binary decoding, cleanup, tests,
and build rules. Source and header comments explain individual functions and
the format-specific checks beside the code.

Python 3 is required for the regression tests and coverage-guided fuzz runner.

### Hello World test samples

Nine executable fixtures are compiled from the shared
[Hello World source](tests/samples/hello.c). **All compiled samples are in the
project root**; source, build notes, and the hash manifest stay in `tests/samples/`.

| Root-level executable | Format / architecture |
| --- | --- |
| [hello-elf32](hello-elf32) | ELF32, Linux i386 |
| [hello-elf64](hello-elf64) | ELF64, Linux x86-64 |
| [hello-linux-arm32](hello-linux-arm32) | ELF32, Linux ARMv7 / EABI5 |
| [hello-linux-arm64](hello-linux-arm64) | ELF64, Linux AArch64 |
| [hello-pe32.exe](hello-pe32.exe) | PE32, Windows x86 |
| [hello-pe64.exe](hello-pe64.exe) | PE32+, Windows x64 |
| [hello-mach-arm64](hello-mach-arm64) | Thin Mach-O, macOS arm64 |
| [hello-mach-x86_64](hello-mach-x86_64) | Thin Mach-O, macOS x86-64 |
| [hello-mach-universal](hello-mach-universal) | Universal Mach-O, macOS arm64 + x86-64 |

`make test` inspects every sample, verifies its size and SHA-256 against the
[manifest](tests/samples/manifest.json), and checks that the source hash matches.
It also executes the compatible native sample on macOS or Linux and verifies
`Hello from coffin!` and exit status 0. On Linux, ARM samples run natively on
matching ARM hosts or through `qemu-arm`/`qemu-aarch64` when those tools are installed. Samples for other platforms are
inspected without being executed. Mutation tests and libFuzzer use all nine
executables as seeds.

To rebuild on macOS:

```sh
brew install llvm lld
make samples
make test
```

See [sample build instructions](tests/samples/README.md) for prerequisites,
custom compiler paths, Linux builds, and the sample hash manifest. Cross-compilers
are only needed when rebuilding samples; normal tests use the included binaries.

### Build configuration

The build honors `CC`, `CPPFLAGS`, `CFLAGS`, `LDFLAGS`, and `LDLIBS`, and tracks
header dependencies automatically. For example:

```sh
make CC=clang CFLAGS='-O0 -g -std=c11 -Wall -Wextra -Wpedantic'
```

Run `make clean` before changing compiler options on an existing build.
Sanitizer builds use separate `obj/sanitize` and `bin/sanitize` directories.
`make clean` removes the selected build's objects, dependency files, executable,
and unit-test binaries; use `make BUILD_DIR=obj/sanitize BIN_DIR=bin/sanitize clean` for that build.

### Debian and Homebrew packages

`make deb` builds a native `.deb` on Debian/Ubuntu with `build-essential`,
`debhelper`, `dpkg-dev`, and `python3` installed. `make homebrew` creates a source
archive and a Homebrew formula with its SHA-256 checksum. Both write to `dist/`.
These commands prepare packages; they do not install or publish them.

CI tests Debian installation/removal in a clean container and Homebrew source
installation, formula tests, reinstallation, and removal in a temporary macOS
tap. Package artifacts are downloadable from successful workflows. The
[packaging guide](packaging/README.md) covers local commands, supported baselines,
and the steps to publish a reviewed release and Homebrew tap.

### Memory leak checks

On Linux, install Valgrind (`sudo apt-get install valgrind` on Debian/Ubuntu),
then run `make valgrind`. On macOS, run `make leaks` to use Apple's `leaks`
command. `make memory-check` selects the host's target. These optional targets
use separate debug builds and first run the normal functional tests.

Each target checks the hash, entropy, and display unit programs, all root sample
executables, synthetic format/resource fixtures, and truncated inputs. A deliberate
leak verifies that the checker actually detects leaks before checking Coffin.
Logs are saved in `bin/valgrind/memory-logs/` or `bin/leaks/memory-logs/`;
any detected leak or checker failure fails the target. Valgrind also checks invalid
accesses and uninitialized values. Apple's `leaks` checks unreachable allocations;
continue using `make sanitize` for invalid accesses and undefined behavior.
These runs cover exercised paths and complement fuzzing rather than proving
all possible inputs leak-free.

For interactive macOS investigation, Instruments provides Leaks and Allocations
instruments. Process-inspection restrictions may require running the command
outside a sandbox. The target fails if its deliberate-leak check cannot run.
Valgrind itself does not support Apple Silicon macOS.

### Regression tests and sanitizers

```sh
make test
make sanitize
make differential
make fuzz-smoke
```

`make test` also runs dedicated MD5/SHA-256 and entropy unit tests. Hash tests
use fixed reference digests for standard strings, one million `a` bytes, and
binary inputs around padding, block, and 8 KiB read boundaries. They exercise
unaligned buffers, one-shot and fragmented updates, deterministic varying chunk
sizes, zero-length NULL updates, and context reinitialization. The same tests run
under ASan/UBSan with `make sanitize`.

Distribution tests also verify version output, install/uninstall inside a
temporary staging directory, archive membership, executable bytes, and checksums.
`make differential` compares the included samples against available GNU readelf,
LLVM readelf/readobj, and macOS otool: section locations/sizes, architecture,
permissions, entry points, imports, symbols, and linked-library declarations.
It also checks frozen ELF width/byte-order/extended-numbering cases, literal
versioned static symbols, PE directory samples, and rejection of unambiguously
truncated headers. Missing optional tools are reported; CI explicitly requires
platform tools. GNU and LLVM readelf text-format differences have dedicated tests.
When older LLVM omits extended-count program headers, that table is compared
against GNU readelf on the original file, with an explicit note. If GNU readelf
is unavailable, the check fails with upgrade/install instructions.

The [permanent regression corpus](tests/corpus/README.md) contains checked-in
inputs with SHA-256 checksums, expected status, and an explanation per case.
`make test` and `make sanitize` run it with timeouts. Budget unit tests cover
exact boundaries and shared counters; a generated universal Mach-O verifies
that valid individual slices cannot each reset the allocation allowance.

To measure focused versus section reporting on a large input:

```sh
python3 tests/benchmark_reports.py bin/coffin /path/to/large-executable --runs 5
```

The benchmark reports median elapsed times and entropy read counters. Timing
results depend on the input and filesystem cache; they are not pass/fail tests.

Regression tests cover bundled samples and hashes, malformed headers and file
ranges, reporting limits, PE optional-header padding, known entropy values,
chunk boundaries, range-cache reuse and work limits, whole-file/window entropy,
empty-section reporting, 32/64-bit PE, ELF, and Mach-O, universal containers,
ELF section names, PE
imports/exports/resources, Mach-O sections, unsupported variants, and CLI status.
`sanitize` enables AddressSanitizer and UndefinedBehaviorSanitizer and treats
compiler warnings as errors.

`fuzz-smoke` runs 1,000 deterministic truncations and mutations per original
fixture, root-level Hello World sample, and synthetic fixture under sanitizers.
It works with toolchains that lack libFuzzer, including some Apple Clang installations. Its log is `bin/fuzz/smoke.log`.

### Coverage-guided fuzzing

For coverage-guided fuzzing, use a Clang installation with the libFuzzer runtime:

```sh
make FUZZ_CC=clang fuzz
python3 tests/run_fuzz.py bin/fuzz/coffin-fuzz --runs 10000
```

On Linux, libFuzzer links C++ runtime libraries. If the build fails with
`cannot find -lstdc++`, install your distro's GNU C++ development package first
(`g++` on Debian/Ubuntu, `gcc-c++` on Fedora/RHEL), then rerun `make fuzz`.

#### macOS LLVM setup

On macOS, Apple Clang may lack that runtime. If Homebrew is installed, install
[Homebrew LLVM](https://formulae.brew.sh/formula/llvm) first:

```sh
brew install llvm
make fuzz
python3 tests/run_fuzz.py bin/fuzz/coffin-fuzz --runs 10000
```

The Makefile automatically selects Homebrew's LLVM Clang from
`/opt/homebrew/opt/llvm/bin/clang` (Apple Silicon) or
`/usr/local/opt/llvm/bin/clang` (Intel). Normal builds keep using `CC`; no global
PATH change is needed. Without either installation, fuzz builds fall back to
`clang`. For a custom Homebrew prefix or another LLVM installation, set `FUZZ_CC`
explicitly:

```sh
make FUZZ_CC="$(brew --prefix llvm)/bin/clang" fuzz
```

If a macOS fuzz build fails because the runtime is missing, the Makefile prints
these installation instructions. LLVM is only required for coverage-guided
fuzzing; regular builds and `fuzz-smoke` can use Apple Clang. See the
[LLVM libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html) for details.

#### Corpus and failures

The runner seeds a persistent corpus from the bundled samples, the compiled
root-level Hello World samples, and synthetic fixtures covering directories,
payloads, sections, and universal containers, plus the checksummed permanent
regression corpus. It stores its log and crash
artifacts under `bin/fuzz/`. Increase `--runs` for a longer run. Inputs are capped at 1 MiB for fuzzing only.
Reproduce a libFuzzer crash with `bin/fuzz/coffin-fuzz path/to/crash-artifact`,
then preserve the minimized bytes and expected behavior in `tests/corpus/`
and add a focused assertion for the original failure. The
[release/fuzzing guide](docs/RELEASING.md#longer-fuzzing-and-failure-follow-up)
explains minimization and the separate 30-minute daily fuzz workflow, retained
corpus, and diagnostic artifacts. For a timed local run, use `--seconds 1800`
instead of `--runs`; both limits may be supplied to stop at the first one reached.

### Continuous integration

GitHub Actions runs builds, regression tests, sanitizers, and mutation checks on
Linux and macOS, independent-tool comparisons, and coverage-guided fuzzing on
Linux. Extended daily fuzzing runs separately to keep push/PR checks short. CI rebuilds the ELF and
PE samples on Linux and the thin/universal Mach-O samples on macOS before
running the tests. Linux CI installs QEMU user-mode emulators and checks that both
ARM Hello World binaries print the expected message and exit successfully. Failure diagnostics are uploaded as workflow artifacts.

## Project status

Complete table reports, icon/cursor reconstruction, big-endian parsing, ELF
extended numbering, dialog control decoding, delay-load imports, and legacy
text-code-page conversion are implemented. Whole-file and section entropy cover
all supported formats, with optional file windows. Dedicated hash and entropy
unit tests run alongside the parser regressions. Reports retain bounded previews for
resource payloads; the limits and unsupported cases above describe the current
behavior.

## License

Licensed under the [MIT License](License).

## Format references

- [Microsoft PE/COFF specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Apple Mach-O structure definitions](https://github.com/apple-oss-distributions/cctools/blob/main/include/mach-o/loader.h)

Additional linkage references:

- [ELF dynamic linking](https://gabi.xinuos.com/v42/elf/08-dynamic.html)
- [ELF symbol tables](https://gabi.xinuos.com/v42/elf/05-symtab.html)
- [Apple nlist definitions](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/nlist.h)
