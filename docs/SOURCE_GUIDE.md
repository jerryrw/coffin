# Reading coffin as a C beginner

Start with a successful report, then follow the same input through the code:

```sh
make
bin/coffin --sections hello-pe64.exe
make test
```

The inspector reads executable bytes as data. It does not execute the file being
inspected. The tests separately run selected known-source Hello World fixtures
when the host or an installed emulator supports them.

The command-line reference is [coffin(1)](coffin.1), also available after
installation with `man coffin`.

## Suggested reading order

| Read | What to look for |
| --- | --- |
| [src/main.c](../src/main.c) | Argument parsing, opening the input, format dispatch, and cleanup |
| [include/common.h](../include/common.h), [src/common.c](../src/common.c) | Shared file state, checked reads, byte decoding, and growing arrays |
| [include/peparser.h](../include/peparser.h), [src/peparser.c](../src/peparser.c) | A concrete header/section parser and its result structure |
| [src/entropy.c](../src/entropy.c) | Counting bytes, floating-point probabilities, streaming, and caching |
| [src/report.c](../src/report.c) | Turning stored results into tables and selecting report groups |
| [src/elfparser.c](../src/elfparser.c) | Two integer widths, two byte orders, and string-table references |
| [src/machparser.c](../src/machparser.c) | Variable-length commands and universal-file slices |
| [src/elf_details.c](../src/elf_details.c), [src/mach_details.c](../src/mach_details.c) | Bounded dependency/symbol tables and sectionless dynamic metadata |
| [src/pe_details.c](../src/pe_details.c) | Address mapping, terminated tables, and resource-tree recursion |
| [src/resource_payload.c](../src/resource_payload.c) | Text conversion, variable records, and bounded previews |
| [src/resource_image.c](../src/resource_image.c), [src/resource_extract.c](../src/resource_extract.c) | Constructing new binary files and managing output handles |
| [src/md5.c](../src/md5.c), [src/sha256.c](../src/sha256.c) | Streaming hash state, bit operations, and block padding |
| [tests](../tests), [Makefile](../Makefile) | Independent checks, generated test inputs, and build rules |

Each C module starts with its purpose. Function comments explain inputs, results,
ownership, and the less obvious rules. Local comments explain algorithms and
binary-format constraints at the point where they matter. You can read the
expanded verbose renderers later; their repeated `printf` calls format fields
that have already been parsed.

## What happens to one input

```mermaid
flowchart TD
    A[Parse command-line options] --> B[Open one binary stream]
    B --> C[Measure size and calculate both hashes]
    C --> D[Choose PE, ELF, or Mach-O parser]
    D --> E[Validate headers and collect metadata]
    E --> F[Measure whole-file entropy and optional file windows]
    F --> G[Measure section entropy when the report needs it]
    G --> H[Extract PE resources if requested]
    H --> I[Print selected report groups]
    I --> J[Free arrays and close stream]
```

`entropy_file` computes the whole-file result and any requested windows before
format-specific section measurements. `report_needs_section_entropy` decides
whether those extra reads are necessary. Header/linkage-only reports skip them;
PE summaries and observations can still need section entropy for their findings.
Report selection controls presentation and optional entropy work; it does not
mean the parser validates only the selected tables.

Some stages return early on error, but allocated resources still need cleanup.
`main` returns `EXIT_SUCCESS` only when all requested work completes. Low-level
helpers usually return `STATUS_SUCCESS` (zero) or `STATUS_ERROR` (-1). Use explicit
comparisons: `if (status == STATUS_SUCCESS)`, rather than assuming a nonzero
value means success.

## The C syntax used most often

### Structures and pointers

A `struct` groups fields; `typedef` gives that type a short name. `InputFile input`
is a structure object, while `InputFile *p` is a pointer to one.

```c
InputFile input = {0};   /* Initialize fields, including pointers, to zero. */
InputFile *p = &input;   /* & takes an object's address. */
input.verbose = 1;      /* . accesses a field on an object. */
p->verbose = 1;         /* -> accesses a field through a pointer. */
```

`const InputFile *p` means a function should not change fields through `p`.
The stream referred to by `p->file` can still move when read: `const` does not
make the underlying file or stream state immutable.

A pointer argument can let a function return an additional value:

```c
size_t size;
if (file_size_checked(file, &size) == STATUS_SUCCESS) {
    /* The function wrote the measured length into size. */
}
```

The array-growth helper goes a step further: it receives the address of an array
pointer, so it can replace that pointer if `realloc` moves the allocation.
The existing calls cast that address to the helper's generic `void **` parameter.
Callers must use the updated array pointer afterward.

### Declarations and the preprocessor

A function declaration in a header describes its name, return type, and
parameters. Its definition in a `.c` file contains the body. Compilation checks
each source file; linking connects calls to definitions in other object files.
A file-level `static` function is private to that source file. A file-level
`static` array has storage for the program's lifetime and is private to the file.
`extern` declares a name whose definition is supplied elsewhere.

`#include` brings in declarations. Include guards prevent a header from declaring
its types twice in one compilation unit. `#define` creates a macro expanded
before C compilation; the hash round macros substitute expressions, while the
report constants substitute bit values. `#if`/`#elif` choose code at compile time,
which is why the Hello World source can contain several OS/CPU implementations.

### Arrays, counts, and allocation

A local array such as `unsigned char buffer[8192]` contains storage directly.
A pointer such as `PESection *sections` refers to storage elsewhere, allocated
with `malloc`, `calloc`, or `realloc`.

- `malloc` allocates uninitialized storage.
- `calloc` allocates zeroed storage.
- `realloc` may move existing storage. On failure, its original allocation still
  exists, so the helper first stores the result in a temporary pointer.
- `free` releases heap storage; it must not receive a pointer to a local array.
  `free(NULL)` is permitted.

A result's **count** is the number of populated entries. Its **capacity** is the
number of allocated slots. Iterate to count, not capacity. The parser result
owns its arrays; a `free_*_info` function releases them. The caller owns the
result object itself, often on the stack. Borrowing a pointer does not transfer
ownership.

`sizeof(array) / sizeof(array[0])` counts elements of an actual array. It does
not count elements behind a pointer. In a function parameter, `buffer[]` is
adjusted to a pointer, so the function also needs an explicit length.

### Byte buffers and strings

C strings end at a zero byte, written `'\0'`. Binary buffers have explicit lengths
and may contain zeros anywhere. Use `memcmp` for fixed-length binary comparisons;
`strcmp` requires terminated strings.

A PE section name occupies eight disk bytes. It may have no terminator, so the
normalized result reserves up to four ASCII display characters per raw byte
plus a terminator. The parser escapes control, backslash, and non-ASCII bytes.
SHA-256's 32 raw digest bytes need 64 hexadecimal characters plus one terminating
zero when displayed. MD5's 16 raw bytes need 33 display-buffer bytes.

### Integer widths and bit operations

`uint16_t`, `uint32_t`, and `uint64_t` have exact unsigned widths. `size_t` is the
unsigned type used for object sizes; it is not necessarily the same width on all
hosts. Unsigned addition wraps when it exceeds the type's maximum. Hash algorithms
use that wraparound deliberately; file offsets and allocation sizes must avoid
accidental wraparound.

Hexadecimal constants start with `0x`. A mask selects particular bits:

```c
flags & mask       /* Keep bits present in both. */
flags | mask       /* Combine bits. */
flags ^ mask       /* Toggle selected bits. */
~mask              /* Flip every bit. */
value << 8         /* Shift toward higher bit positions. */
```

Bitwise `&` and `|` differ from logical `&&` and `||`. Logical operators test
true/false conditions and short-circuit evaluation; bitwise operators manipulate
individual bits. Report selectors combine independent powers of two with `|`.

Cast byte values to an unsigned type of sufficient width **before** shifting.
A high byte promoted to signed `int` and shifted into its sign bit could produce
undefined behavior. A shift count must also be smaller than the operand width.

## Reading a binary format safely

### File layout is not C object layout

A compiler can add padding between struct fields and choose a native byte order.
Consequently the parsers read byte arrays and decode fields at documented disk
offsets, rather than casting file bytes to struct pointers.

Little-endian stores the lowest-value byte first. Big-endian stores it last.
For example, the two little-endian bytes `34 12` represent the number `0x1234`.
The decoding helpers work from bytes, so alignment and the host's byte order do
not change the result.

### Address spaces are different

| Term | Meaning in this project |
| --- | --- |
| File offset | Byte position from the beginning of the input file |
| VA | Virtual address in the image's declared memory layout |
| PE RVA | Address relative to the preferred image base |
| Slice offset | Position relative to one thin Mach-O image |
| Container offset | Position relative to the complete universal Mach-O file |

For a file-backed PE section, mapping uses:

```text
file offset = section raw offset + (RVA - section RVA)
```

The RVA must belong to an unambiguous mapped range. A virtual zero-filled tail
has no bytes to read. Likewise ELF NOBITS and Mach-O zero-fill sections can have
memory sizes without file payloads.

For a universal Mach-O section:

```text
container offset = slice base + section offset
```

Both the range inside the slice and the range inside the complete file matter.
A file-wide check alone could allow one slice to read another slice's bytes.

### Check before adding, multiplying, or reading

`file_range_valid` first checks `offset <= size`, then `length <= size - offset`.
It avoids computing `offset + length`, which could wrap. Table counts are widened
before multiplication, and allocation helpers bound the number of bytes before
allocating them. Every `read_at` requires an exact read; short reads are errors.

PE resource traversal tracks offsets only along the current ancestor path.
A shared subtree reached from another branch is permitted; reaching an ancestor
is a cycle and is rejected. Every visit, including a revisit, consumes a resource
read. The root is level one, so sixteen directory levels fit the recursion budget.
`tests/test_stress.py` checks both PE widths, exact boundary failures, and that
resource parsing errors occur before extraction creates a directory. Shared
payloads still produce distinct path records and extracted files.

Valid byte ranges alone do not bound computation. A resource tree could cycle,
and many sections could repeatedly reference the same bytes. Work/depth limits
and entropy caching prevent these structures from requesting unlimited work.
`input_prepare` initializes a `ParserBudget` owned by the input. Its pointer lets
helpers update accounting even when they borrow a `const InputFile *`, just as
reading a borrowed `FILE *` changes stream state. Do not copy a prepared
`InputFile`: its budget pointer refers to its own storage. Parser reads use
`parser_read`; streaming hash and entropy reads have separate policies.
`reserve_array` charges allocation growth across all tables and universal slices.
The budget is not refunded during an analysis. `parser_lookup_work` charges
repeated ELF table scans before entering their loops. These helpers reject work
before it would exceed the allowance.

The constants in `include/common.h` currently allow 64 MiB of table allocation
growth, 64 MiB of metadata reads, 1,000,000 metadata read operations, and
16,777,216 repeated ELF lookup steps per input. Each table accepts at most
100,000 entries. All slices of a universal Mach-O share those counters. Budget
failures return an error before a report is printed. These are separate work
budgets, not a total-process memory or wall-clock limit; hashing still reads the
whole input. Entropy, resource previews, and extraction have their own limits,
listed in the main README.

## Cleanup and error handling

`goto` is used for forward jumps to shared cleanup labels. This avoids copying
many `free` and `close` calls into each error branch. A label's position reflects
which resources have been acquired: image construction's `invalid_parts` also
falls through to `invalid_directory`.

Zero-initialized result pointers make cleanup possible after partial parsing.
Cleanup functions clear their pointers after `free`, so a caller can safely clean
up a result whose parser already cleaned up on failure. This does not mean that
arbitrary uninitialized results can be freed safely.

Output uses both integer file descriptors and `FILE *` streams. After successful
`fdopen`, the stream owns closing the descriptor through `fclose`. If `fdopen`
fails, the descriptor must be closed explicitly. A buffered write may fail only
at `fclose`, so extraction checks that result too.

## Understanding the numerical modules

Entropy counts each byte value and evaluates `-sum(p * log2(p))`. A conversion
to `double` is essential before division. One histogram combines all chunks;
averaging chunk entropies would compute a different quantity. `NAN` means there
were no measured bytes, while numeric zero means the bytes were constant.

The hash modules follow `init -> update -> final`. Splitting the same input across
updates must not change its digest. Full 64-byte blocks update a running state;
a partial block stays in the context. Finalization adds padding and the original
message length. MD5 writes little-endian digest words, while SHA-256 writes
big-endian words. Their constants and round schedules are algorithm data, not
values to simplify or change when learning the code.

## Learning from the tests and tools

| Tool/file | Purpose |
| --- | --- |
| [tests/test_display.c](../tests/test_display.c) | Escape untrusted names and paths for terminal output |
| [tests/test_hashes.c](../tests/test_hashes.c) | Fixed expected digests, padding boundaries, unaligned input, and update partitioning |
| [tests/test_entropy.c](../tests/test_entropy.c) | Known distributions, cache reuse, work limits, and windows |
| [tests/test_malformed.py](../tests/test_malformed.py) | Run the CLI, inspect reports, and verify rejection/extraction behavior |
| [tests/fixtures.py](../tests/fixtures.py) | Build small binary images with known field locations |
| [tests/fuzz_parser.c](../tests/fuzz_parser.c) | Send generated/mutated byte buffers through real parsing paths |
| [tests/test_limits.c](../tests/test_limits.c) | Allocation, metadata I/O, and lookup budget boundaries |
| [tests/test_corpus.py](../tests/test_corpus.py) | Frozen checksummed inputs, expected status, timeouts |
| [tests/test_stress.py](../tests/test_stress.py), [tests/stress_fixtures.py](../tests/stress_fixtures.py) | Generate hostile inputs and check stable rejection, table boundaries, and entropy-cache work |
| [tests/test_parser_limits.py](../tests/test_parser_limits.py) | Shared allocation budget across universal slices |
| [tests/test_differential.py](../tests/test_differential.py) | Compare metadata and malformed-header rejection against independent binary tools |
| [tests/test_differential_parser.py](../tests/test_differential_parser.py) | GNU/LLVM output differences and the extended-numbering fallback |
| [tests/regression_corpus.py](../tests/regression_corpus.py), [tests/corpus/README.md](../tests/corpus/README.md) | Load frozen inputs and verify checksums and recorded expectations |
| [tests/run_memory_checks.py](../tests/run_memory_checks.py) | Valgrind or Apple leaks checks, including a deliberate-leak self-test |
| [tests/memory_probe.c](../tests/memory_probe.c) | Intentionally leak memory so a broken checker cannot silently pass |
| [tests/benchmark_reports.py](../tests/benchmark_reports.py) | Compare entropy work and timing for focused versus section reports |
| [tests/test_distribution.py](../tests/test_distribution.py) | Verify staging, archives, and version output without system writes |
| [tests/run_fuzz.py](../tests/run_fuzz.py) | Preserve fuzz corpus, logs, and reproducible crash inputs |
| [tests/build_samples.py](../tests/build_samples.py) | Optional cross-compilation of known-source executable samples |
| [tests/linkage_fixtures.py](../tests/linkage_fixtures.py) | Construct ELF/Mach-O dependencies and symbol tables |
| [.github/workflows/ci.yml](../.github/workflows/ci.yml) | Verify parsers and package installation on Linux and macOS |
| [.github/workflows/fuzz-nightly.yml](../.github/workflows/fuzz-nightly.yml) | Longer scheduled fuzzing with cached coverage inputs and saved diagnostics |

Python's `struct.pack` creates serialized fields; `pack_into` edits a field at an
explicit offset in a mutable `bytearray`. `<`, `>`, `H`, `I`, and `Q` describe byte
order and integer widths. Mutating one field while leaving the rest intact helps
identify which parser rule a test exercises.

A malformed input returning an error is normal during fuzzing. Crashes, hangs,
and sanitizer diagnostics are failures. Deterministic smoke mutations are
repeatable; coverage-guided fuzzing retains inputs that explore new paths.
Neither technique replaces fixed regression cases with known expected results.

The C unit tests use `assert`, so keep `NDEBUG` undefined when running them.
Expected negative entropy and parser-budget tests print work-limit/range errors
before reporting that the test executable passed. `make test` runs the C unit
programs, CLI regressions, distribution/packaging checks, the permanent corpus,
and generated hostile-input stress tests. `make stress` runs the hostile-input
suites alone, including the universal-file allocation test. `make sanitize` repeats those
checks in separate ASan/UBSan build directories.

`make valgrind` on Linux and `make leaks` on macOS build ordinary debug binaries,
run functional tests, then check cleanup on the unit programs and parser inputs.
Apple's `leaks` returns its own exit status rather than the inspected program's,
so functional status checks are separate. The deliberate-leak probe must be
detected before clean memory-check results are accepted. These targets remain
optional for ordinary local builds; Linux CI also runs Valgrind.

In the Makefile, compilation produces `.o` files and linking joins them into an
executable. Generated `.d` files track header dependencies. The comments explain
`$@`, `$<`, `$^`, pattern rules, library flags, and separate sanitizer outputs.
`oldmakefile` and `git.txt` are historical reference notes, not required setup.

The Hello World source also contains platform-specific inline assembly. Read it
after the portable C modules: register constraints and syscall conventions are
more specialized than ordinary C functions. Its manifest hashes source text as
well as sample bytes, so even a comment-only source edit changes the recorded
source checksum. JSON manifests and executable fixtures cannot contain ordinary
C/Python comments; their explanations belong here and in the sample README.

The VERSION file feeds the CLI's version macro. Install/uninstall use a staging
prefix, and `scripts/package_release.py` creates host binary archives. Shared
release and distribution instructions are in
[packaging/README.md](../packaging/README.md).

## Distribution packaging

`make deb` exports source into a disposable directory and runs Debian's
`dpkg-buildpackage`. Debhelper's rules run tests, stage `/usr/bin/coffin`, and
compute runtime library dependencies. `make source-package` creates a normalized
source archive. `make homebrew` also renders a formula using the archive checksum.
The source export is handled by `scripts/package_source.py`. It includes current
source bytes and a `.coffin-source-files` manifest containing filenames and the
source timestamp, so an extracted release can rebuild without `.git`.
`scripts/package_deb.py` drives Debian builds; `scripts/package_homebrew.py`
renders `packaging/homebrew/coffin.rb.in` with the archive's real checksum.

`tests/test_packaging.py` verifies source contents, checksums, and Git-free
re-exporting without installing software. `tests/test_deb.py` exercises Debian
install/remove/reinstall/purge in a disposable container; `tests/test_homebrew.py`
checks source installation, formula tests, reinstallation, and removal using a
temporary tap. Both refuse to replace an existing Coffin installation.
Debian and Homebrew installation tests run in dedicated CI jobs and can also
run manually. Both remove only packages and temporary taps they created. See
[packaging/README.md](../packaging/README.md) for commands and release boundaries.

## CI and release artifacts

The main workflow tests on Ubuntu 24.04 and `macos-latest`. Its actions use the
Node.js 24 runtime; this runtime belongs to GitHub Actions and is not a dependency
of the C executable. Linux rebuilds ELF/PE fixtures and macOS rebuilds Mach-O
fixtures. Independent tools, sanitizers, and deterministic mutation checks run
on both platforms; Linux also runs Valgrind and a coverage-guided fuzz smoke run.
Older LLVM versions can omit extended-count ELF program headers. The differential
suite prints a note and uses GNU readelf for that table on the original input;
other LLVM comparisons remain active.

After the parser matrix passes, the package job exercises a Debian amd64 package
in a Debian bookworm container and saves downloadable candidate artifacts.
The Homebrew job then downloads that same source archive, verifies its checksum,
generates a matching formula, and tests installation/reinstallation/removal on
macOS. A tag matching
`v` plus VERSION also builds host binary archives and enables the
`release-candidates` job. That job waits for the parser matrix and both package
jobs before collecting verified artifacts. Ordinary branch/PR runs skip that
final collection job. Creating tags and publishing a GitHub Release remain
separate maintainer actions.
