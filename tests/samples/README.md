# Hello World executable fixtures

The compiled executables live in the project root, alongside the original test
samples. Their source, build notes, and hash manifest remain in `tests/samples/`.

These samples are compiled from [hello.c](hello.c), a small program that prints
`Hello from coffin!` and exits. The source is part of coffin and uses its MIT
license. No downloaded executable or third-party runtime is bundled.

| Fixture in the project root | Target | Implementation |
| --- | --- | --- |
| `hello-elf32` | Linux i386 ELF32 | Freestanding C with Linux write/exit syscalls |
| `hello-elf64` | Linux x86-64 ELF64 | Freestanding C with Linux write/exit syscalls |
| `hello-linux-arm32` | Linux ARMv7 ELF32, EABI5 | Freestanding C with ARM EABI write/exit syscalls |
| `hello-linux-arm64` | Linux AArch64 ELF64 | Freestanding C with AArch64 write/exit syscalls |
| `hello-pe32.exe` | Windows x86 PE32 | Kernel32 GetStdHandle/WriteFile/ExitProcess imports |
| `hello-pe64.exe` | Windows x64 PE32+ | Same Windows console program |
| `hello-mach-arm64` | macOS arm64 Mach-O | C main calling puts |
| `hello-mach-x86_64` | macOS x86-64 Mach-O | C main calling puts |
| `hello-mach-universal` | macOS arm64 + x86-64 universal Mach-O | Both thin Mach-O executables combined with lipo |

## Rebuild

Ordinary `make test` uses the checked-in binaries and requires no cross-compilers.
To rebuild all samples on macOS, install Homebrew LLVM and LLD, and have Xcode's
command-line tools installed:

```sh
brew install llvm lld
make samples
```

The builder uses Clang and LLD to cross-compile the Linux x86, ARMv7, AArch64,
and Windows samples
without libc or a Windows SDK. It generates temporary Kernel32 import libraries
with llvm-dlltool. The macOS samples use Apple Clang, the macOS SDK, and lipo.
Nothing is installed or executed by the builder.

For Intel Macs or custom installations, specify the tool directories:

```sh
make samples SAMPLE_ARGS="--llvm-bin $(brew --prefix llvm)/bin --lld-bin $(brew --prefix lld)/bin"
```

On Linux, install Clang, LLVM tools, and LLD with your package manager, then:

```sh
make samples SAMPLE_ARGS='--llvm-bin /usr/bin --lld-bin /usr/bin --formats elf pe'
```

Rebuild just the macOS fixtures with:

```sh
make samples SAMPLE_ARGS='--formats mach'
```

[manifest.json](manifest.json) records SHA-256 and size for each executable and
is updated by the builder. Commit the binaries, source, and manifest together
when intentionally rebuilding. Toolchain and SDK changes may alter the output;
the manifest verifies the checked-in artifacts rather than promising identical
binaries across compiler versions.

## Test integration

Regression tests check every sample's size and hash, expected format and
architecture, readable reports, and Windows imports. They also execute the
known-source native sample on macOS or Linux and check the message and exit
status. Linux ARM samples run natively on matching ARM hosts or, when installed,
through `qemu-arm` and `qemu-aarch64` on Linux. The Linux CI job installs both
emulators via `qemu-user`, so both ARM syscall implementations are exercised.
macOS inspects these ELF files without executing them. Windows binaries are
inspected without being executed on incompatible hosts.

Both mutation testing and libFuzzer include these samples in their input sets.
CI rebuilds ELF/PE samples on Linux and Mach-O samples on macOS before running the
regression suite. Synthetic fixtures separately cover malformed offsets and
sizes, swapped universal tables, FAT64 containers, big-endian images, ELF extended numbering, and icon/cursor reconstruction.

## Reading the sample source

`hello.c` includes comments explaining OS selection, entry points, Windows
imports, Linux syscall registers, and inline-assembly constraints. The
[project source guide](../../docs/SOURCE_GUIDE.md) introduces the portable C
concepts first. The manifest hashes the source text, including comments; update
`source_sha256` after a comment-only edit. Rebuild the samples when executable
code changes so binary contents and manifest entries reflect the new program.
