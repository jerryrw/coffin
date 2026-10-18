# Changelog

## 0.1.1 — Unreleased

Release preparation for the first Debian and Homebrew distribution packages.
The existing `v0.1.0` tag predates those packages and remains unchanged.

- Add native Debian packages and a source-based Homebrew formula, with
  installation, reinstallation, and removal checked in CI.
- Export checksummed source archives that rebuild without Git metadata.
- Update GitHub Actions to Node.js 24 and pin Linux runners to Ubuntu 24.04.

## 0.1.0

Initial executable inspector and verification infrastructure.

- Inspect PE32/PE32+, ELF32/ELF64, and thin/universal Mach-O files.
- Report full-file MD5/SHA-256, declared permissions, structural observations,
  whole-file/section entropy, and optional entropy windows.
- Decode PE imports, delay imports, exports, and resource previews; extract raw
  payloads and reconstruct supported ICO/CUR resources.
- Report ELF dependencies and static/dynamic symbols, including sectionless
  dynamic tables with recoverable SysV/GNU hash counts.
- Report Mach-O library declarations and nlist symbols for each architecture.
- Escape untrusted report names and paths; skip unused section entropy work.
- Add independent-tool comparisons, longer scheduled fuzz runs with corpus
  retention, installation targets, version output, and release packaging.
- Expand independent-tool comparisons to frozen width/order/numbering and
  symbol-version regressions, plus malformed-header rejection checks.
- Keep a permanent checksummed regression corpus in normal, sanitizer, memory,
  and fuzz tests.
- Share table-allocation, metadata-read, and ELF lookup budgets across an input,
  including universal slices; reject excess work explicitly.
