# Changelog

## 0.1.0 — Unreleased

Initial release preparation. No release tag has been created by these changes.

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
- Prepare native Debian packages and a checksummed source-based Homebrew formula;
  test installation, malformed-input handling, reinstallation, and removal in CI.
- Export source archives that can rebuild and test without Git metadata.
