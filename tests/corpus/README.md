# Permanent regression corpus

These are synthetic parser inputs, not applications to execute. They are kept
in Git so changes to fixture builders cannot silently change old regression
cases. No collected malware or third-party executable is included here.

`manifest.json` records each file's SHA-256, expected CLI exit status, reason,
and independent tools approved for comparing it. Optional `stdout_contains` and
`stderr_contains` lists preserve case-specific findings and diagnostics.
Successful cases must produce
a report with the correct hash; rejected cases must exit 1 without a report.
The CLI runner enforces a ten-second timeout and rejects sanitizer diagnostics.
`make test` and `make sanitize` run all cases. Valgrind/macOS leaks checks and
both fuzz runners also consume these files. Differential tests use only the
manifest's approved comparisons: a header reader is not expected to detect a
resource-directory cycle or enforce Coffin's own limits.

Coverage includes PE resources, delay imports, icon/cursor groups, legacy text,
ELF linkage and extended numbering in both widths/orders, literal versioned
static symbols, thin/universal Mach-O, truncated inputs, a resource cycle, and
overlapping universal slices, including one-byte overlap and adjacent valid
slices. PE raw-range aliases and ambiguous PE/ELF address maps have separate
acceptance/rejection controls. PE32/PE32+ depth-16 controls, depth-17 rejections,
non-root cycles, shared subtrees, and reference-amplification inputs preserve
explicit expectations for resource traversal. The readelf text-format regressions (plain-zero
alignment and static/dynamic version suffixes) are in `test_differential_parser.py`.
Generated large-input resource-limit tests live in `test_parser_limits.py` and
`test_stress.py` so
large files do not need to be stored in Git.

## Add a discovered failure

1. Minimize the input and verify that the failure reproduces. Use synthetic or
   redistributable data; remove credentials and personal information.
2. Give the `.bin` file a descriptive, unique name. Add its SHA-256, intended
   exit status, and explanation to the manifest. Add output-specific assertions
   to a Python regression test when status alone would miss the original bug.
3. Leave `differential` empty unless the independent tool actually exercises
   the relevant structure and its comparison is meaningful.
4. Run `make test`, `make sanitize`, and `make differential`; commit the input,
   manifest, assertion, and fix together.

`python3 tests/corpus/build.py` explicitly regenerates the initial synthetic
cases. It is never called by tests. Review every resulting byte/hash/expectation
change; it is a bootstrap script, not a way to refresh expectations automatically.
Keep subsequently added cases when updating the synthetic set.
