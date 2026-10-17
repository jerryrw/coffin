"""Install/reinstall/remove a newly built .deb in a disposable root CI container.

Do not use a development workstation with an existing Coffin package. This test
refuses to replace one and checks every installed non-directory package path.
"""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run(*command):
    return subprocess.check_output(list(map(str, command)), text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('package', type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run in a disposable Debian/Ubuntu container as root')
    package = args.package.resolve()
    assert run('dpkg-deb', '-f', package, 'Package') == 'coffin'
    assert run('dpkg-deb', '-f', package, 'Architecture') == run('dpkg', '--print-architecture')
    assert 'libc6' in run('dpkg-deb', '-f', package, 'Depends')
    existing = subprocess.run(['dpkg-query', '-W', 'coffin'], capture_output=True)
    if existing.returncode == 0:
        parser.error('An existing Coffin package is registered; refusing to replace it')
    binary = Path('/usr/bin/coffin')
    if binary.exists() or binary.is_symlink() or Path('/usr/share/doc/coffin').exists():
        parser.error('Existing Coffin files would be replaced')
    installed = False
    owned = []
    try:
        for attempt in range(2):
            # Mark ownership before installation so a partial failure gets purged.
            installed = True
            subprocess.run(['dpkg', '--install', str(package)], check=True)
            assert run(binary, '--version') == 'coffin ' + (ROOT / 'VERSION').read_text().strip()
            owned = [Path(name) for name in run('dpkg-query', '-L', 'coffin').splitlines()
                     if Path(name).is_file() or Path(name).is_symlink()]
            assert binary in owned and any('/usr/share/doc/coffin/' in str(p) for p in owned)
            for name, kind in (('hello-elf64', 'ELF'), ('hello-pe64.exe', 'PE'), ('hello-mach-arm64', 'Mach-O')):
                source = ROOT / name
                output = run(binary, '--headers', '--sections', source)
                assert kind + ' File Analysis Report' in output
                assert hashlib.sha256(source.read_bytes()).hexdigest() in output
            with tempfile.TemporaryDirectory() as temporary:
                malformed = Path(temporary) / 'truncated'
                malformed.write_bytes(b'\x7fELF')
                result = subprocess.run([str(binary), str(malformed)], capture_output=True)
                assert result.returncode == 1 and b'Analysis Report' not in result.stdout
            # First check ordinary removal, then verify a clean reinstall/purge.
            subprocess.run(['dpkg', '--remove' if attempt == 0 else '--purge', 'coffin'], check=True)
            installed = False
            assert all(not path.exists() and not path.is_symlink() for path in owned), owned
            assert not binary.exists()
        print('Debian package passed: install, analyze three formats, reject malformed input, remove, reinstall, purge')
    finally:
        if installed:
            subprocess.run(['dpkg', '--purge', 'coffin'], check=False)


if __name__ == '__main__':
    main()
