"""Check parser cleanup with Memcheck (Linux) or Apple's leaks (macOS).

Functional tests run first in Make: leaks reports its own result rather than
preserving the child's exit status. Every invocation keeps a diagnostic log.
A deliberately leaking probe must fail before a clean result can be trusted.
"""
import argparse
from pathlib import Path
import platform
import shutil
import subprocess
import sys

from fixtures import fuzz_seeds


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('tool', choices=('valgrind', 'leaks'))
    parser.add_argument('binary_dir', type=Path)
    parser.add_argument('--checker')
    args = parser.parse_args()
    required = 'Linux' if args.tool == 'valgrind' else 'Darwin'
    if platform.system() != required:
        parser.error(f'{args.tool} target requires {required}')
    checker = shutil.which(args.checker or args.tool)
    if not checker:
        parser.error(f'{args.tool} is missing; install valgrind on Linux or Apple developer tools on macOS')
    directory = args.binary_dir.resolve()
    logs = directory / 'memory-logs'
    logs.mkdir(parents=True, exist_ok=True)
    inputs = logs / 'inputs'
    inputs.mkdir(exist_ok=True)

    def check(name, command, expected=None, probe=False):
        if args.tool == 'valgrind':
            prefix = [checker, '--tool=memcheck', '--leak-check=full',
                      '--show-leak-kinds=all', '--errors-for-leak-kinds=all',
                      '--track-origins=yes', '--error-exitcode=99']
            wanted = 99 if probe else expected
        else:
            prefix = [checker, '--quiet', '--atExit', '--']
            wanted = 1 if probe else 0
        result = subprocess.run(prefix + list(map(str, command)),
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=120)
        log = logs / f'{name}.log'
        log.write_bytes(result.stdout)
        # A missing scan must never count as a successful macOS leak check.
        scanned = args.tool != 'leaks' or b'total leaked bytes' in result.stdout
        if result.returncode != wanted or not scanned:
            raise RuntimeError(f'{name}: checker exited {result.returncode}, expected {wanted}; see {log}')

    check('checker-self-test', [directory / 'memory-probe'], probe=True)
    for unit in ('test-entropy', 'test-hashes', 'test-display'):
        check(unit, [directory / unit], expected=0)

    cases = fuzz_seeds()
    cases.update({'empty': b'', 'truncated-pe': b'MZ' + bytes(14),
                  'truncated-elf': b'\x7fELF' + bytes(12),
                  'truncated-mach': b'\xcf\xfa\xed\xfe' + bytes(12)})
    root = Path(__file__).resolve().parent.parent
    for sample in sorted(root.glob('hello-*')):
        if sample.is_file():
            cases[sample.name] = sample.read_bytes()
    for sample in ('testelf', 'testmach', 'testexecutable.exe'):
        cases[sample] = (root / sample).read_bytes()
    for name, data in cases.items():
        path = inputs / name
        path.write_bytes(data)
        command = [directory / 'coffin', path]
        # Capture the expected status separately: malformed input exits 1.
        baseline = subprocess.run(list(map(str, command)), stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL, timeout=30)
        if baseline.returncode not in (0, 1):
            raise RuntimeError(f'{name}: unexpected application exit {baseline.returncode}')
        check(name, command, expected=baseline.returncode)
    print(f'{args.tool}: {len(cases)} parser cases and 3 unit programs passed; logs: {logs}')


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, subprocess.TimeoutExpired) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
