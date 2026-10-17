"""Export current source bytes for package builds; omit local build/private files.

Git supplies tracked and nonignored filenames, not their contents: a developer's
uncommitted source fixes are included in the package being tested. Only known
source directories and project root files are eligible. No Git history is shipped.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIRS = {'src', 'include', 'tests', 'scripts', 'packaging', 'docs', '.github'}
ROOT_FILES = {'Makefile', 'VERSION', 'README.md', 'License', 'CHANGELOG.md',
              '.gitignore', 'testelf', 'testmach', 'testexecutable.exe',
              'hello-elf32', 'hello-elf64', 'hello-linux-arm32', 'hello-linux-arm64',
              'hello-pe32.exe', 'hello-pe64.exe', 'hello-mach-arm64',
              'hello-mach-x86_64', 'hello-mach-universal'}


def version():
    value = (ROOT / 'VERSION').read_text().strip()
    if not re.fullmatch(r'\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?', value):
        raise ValueError('VERSION must contain a semantic version')
    return value


def source_files():
    manifest = ROOT / '.coffin-source-files'
    if manifest.exists():
        # Release archives deliberately omit .git. The frozen list lets their
        # package tests/rebuilds export source without discovering build outputs.
        names = json.loads(manifest.read_text())['files']
    else:
        output = subprocess.check_output(['git', 'ls-files', '-z', '--cached',
                                          '--others', '--exclude-standard'], cwd=ROOT)
        names = output.decode().strip('\0').split('\0')
    for name in sorted(set(names)):
        path = Path(name)
        if path.is_absolute() or '..' in path.parts:
            raise ValueError(f'Invalid source path: {name}')
        if path.parts and (name in ROOT_FILES or path.parts[0] in SOURCE_DIRS):
            full = ROOT / path
            if full.is_symlink() or not full.is_file():
                raise ValueError(f'Source entry must be a regular file: {name}')
            yield path, full


def export_tree(destination):
    files = list(source_files())
    for name, full in files:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(full.read_bytes())
        target.chmod(0o755 if full.stat().st_mode & 0o111 else 0o644)
    (destination / '.coffin-source-files').write_bytes(source_manifest(files))


def source_epoch():
    if 'SOURCE_DATE_EPOCH' in os.environ:
        return int(os.environ['SOURCE_DATE_EPOCH'])
    manifest = ROOT / '.coffin-source-files'
    if manifest.exists():
        return int(json.loads(manifest.read_text())['source_date_epoch'])
    return int(subprocess.check_output(['git', 'show', '-s', '--format=%ct', 'HEAD'], cwd=ROOT, text=True).strip())


def source_manifest(files):
    metadata = {'source_date_epoch': source_epoch(),
                'files': [name.as_posix() for name, _ in files]}
    return (json.dumps(metadata, indent=2) + '\n').encode()


def source_archive(output):
    output.mkdir(parents=True, exist_ok=True)
    archive = output / f'coffin-{version()}-source.tar.gz'
    # Normalize container metadata. This makes identical source bytes stable;
    # it does not claim that compiler-produced binaries are reproducible.
    with archive.open('wb') as raw, gzip.GzipFile(filename='', fileobj=raw, mode='wb', mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode='w') as bundle:
            files = list(source_files())
            for name, full in files:
                data = full.read_bytes()
                member = tarfile.TarInfo(f'coffin-{version()}/{name.as_posix()}')
                member.size = len(data)
                member.mode = 0o755 if full.stat().st_mode & 0o111 else 0o644
                bundle.addfile(member, io.BytesIO(data))
            data = source_manifest(files)
            member = tarfile.TarInfo(f'coffin-{version()}/.coffin-source-files')
            member.size = len(data)
            member.mode = 0o644
            bundle.addfile(member, io.BytesIO(data))
    checksum(archive)
    return archive


def checksum(path):
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    path.with_name(path.name + '.sha256').write_text(f'{digest}  {path.name}\n')
    return digest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'dist')
    args = parser.parse_args()
    print(source_archive(args.output_dir.resolve()))
