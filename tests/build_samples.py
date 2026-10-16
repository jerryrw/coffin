# Optional fixture builder, not a prerequisite for normal parsing or tests.
# Cross-compilation chooses a target CPU/OS; linking turns its object file into
# an executable. Temporary object/import-library files are removed automatically.
# The root-level binaries and manifest are the intended persistent outputs.

"""Rebuild known-source executable fixtures with Clang, LLD, and macOS tools."""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT
SOURCE = ROOT / 'tests/samples/hello.c'


# Prefer an explicit tool-directory path, then search the system PATH.
# Fail clearly when unavailable so a different compiler is not silently assumed.
def tool(name, prefix=None):
    if prefix and (Path(prefix) / name).is_file():
        return str(Path(prefix) / name)
    found = shutil.which(name)
    if not found:
        raise SystemExit(f'Missing {name}; see tests/samples/README.md for build prerequisites')
    return found


# Pass a list of arguments directly to the subprocess, without a shell.
# check=True stops the build at the first failed compiler/linker command.
def run(args):
    print(' '.join(map(str, args)), flush=True)
    subprocess.run(list(map(str, args)), check=True)


# Choose requested formats, compile known source, link fixtures, and regenerate
# their hash manifest. Include existing binaries when rebuilding only some formats.
# ELF uses syscalls without libc; PE synthesizes its small Windows import library;
# Mach-O uses macOS tools and lipo combines the two architecture slices.
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--llvm-bin', default='/opt/homebrew/opt/llvm/bin')
    parser.add_argument('--lld-bin', default='/opt/homebrew/opt/lld/bin')
    parser.add_argument('--formats', nargs='+', choices=['elf', 'pe', 'mach'],
                        default=['elf', 'pe', 'mach'] if platform.system() == 'Darwin' else ['elf', 'pe'])
    args = parser.parse_args()
    clang = tool('clang', args.llvm_bin)
    DEST.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary)
        # -target selects cross-compilation; -ffreestanding avoids assuming a
        # hosted C runtime. _start is supplied by hello.c instead of libc startup.
        if 'elf' in args.formats:
            linker = tool('ld.lld', args.lld_bin)
            for name, target, emulation in (
                    ('hello-elf32', 'i386-linux-gnu', 'elf_i386'),
                    ('hello-elf64', 'x86_64-linux-gnu', 'elf_x86_64'),
                    ('hello-linux-arm32', 'armv7-linux-gnueabihf', 'armelf_linux_eabi'),
                    ('hello-linux-arm64', 'aarch64-linux-gnu', 'aarch64linux')):
                obj = work / f'{name}.o'
                run([clang, '-target', target, '-O1', '-ffreestanding', '-fomit-frame-pointer', '-fno-pic', '-fno-stack-protector', '-fno-asynchronous-unwind-tables', '-c', SOURCE, '-o', obj])
                run([linker, '-m', emulation, '--build-id=none', '-e', '_start', obj, '-o', DEST / name])
        # A .def export list plus llvm-dlltool creates an import library describing
        # Windows APIs; it does not bundle their implementation or a Windows SDK.
        if 'pe' in args.formats:
            linker, dlltool = tool('lld-link', args.lld_bin), tool('llvm-dlltool', args.llvm_bin)
            for bits, target, machine in ((32, 'i686-pc-windows-msvc', 'i386'), (64, 'x86_64-pc-windows-msvc', 'i386:x86-64')):
                definition = work / 'kernel32.def'
                names = ['GetStdHandle', 'WriteFile', 'ExitProcess'] if bits == 64 else ['GetStdHandle@4', 'WriteFile@20', 'ExitProcess@4']
                definition.write_text('LIBRARY KERNEL32.dll\nEXPORTS\n' + '\n'.join(names) + '\n')
                library, obj = work / f'kernel{bits}.lib', work / f'pe{bits}.obj'
                run([dlltool, '-m', machine, '-k', '-d', definition, '-l', library])
                run([clang, '-target', target, '-O1', '-ffreestanding', '-fno-stack-protector', '-c', SOURCE, '-o', obj])
                run([linker, '/entry:mainCRTStartup', '/subsystem:console', '/nodefaultlib', '/timestamp:0', '/Brepro', f'/out:{DEST / f"hello-pe{bits}.exe"}', obj, library])
        if 'mach' in args.formats:
            if platform.system() != 'Darwin':
                raise SystemExit('Mach-O samples require macOS and Xcode command-line tools')
            cc, lipo = tool('clang'), tool('lipo')
            for architecture in ('arm64', 'x86_64'):
                run([cc, '-arch', architecture, '-mmacosx-version-min=11.0', SOURCE, '-o', DEST / f'hello-mach-{architecture}'])
            run([lipo, '-create', DEST / 'hello-mach-arm64', DEST / 'hello-mach-x86_64', '-output', DEST / 'hello-mach-universal'])
    # Include existing fixtures when rebuilding only a subset of formats.
    # This manifest checks the source text as well as each binary's bytes.
    # Comment-only source edits require refreshing source_sha256 too.
    entries = []
    for path in sorted(DEST.glob('hello-*')):
        data = path.read_bytes()
        entries.append({'file': path.name, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
    (ROOT / 'tests/samples/manifest.json').write_text(json.dumps({'source': 'hello.c', 'source_sha256': hashlib.sha256(SOURCE.read_bytes()).hexdigest(), 'samples': entries}, indent=2) + '\n')


if __name__ == '__main__':
    main()
