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
