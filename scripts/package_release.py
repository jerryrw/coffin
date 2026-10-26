"""Create a host-specific release archive and checksum; never tag or publish it."""
import argparse
import hashlib
from pathlib import Path
import platform
import re
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'dist')
    args = parser.parse_args()
    version = (ROOT / 'VERSION').read_text().strip()
    if not re.fullmatch(r'\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?', version):
        parser.error('VERSION must contain a semantic version')
    name = f'coffin-{version}-{platform.system().lower()}-{platform.machine().lower()}'
    args.output_dir.mkdir(parents=True, exist_ok=True)
    archive = args.output_dir / (name + '.tar.gz')
    # Use deliberate member names: no absolute paths, fixtures, corpora, or secrets.
    with tarfile.open(archive, 'w:gz') as bundle:
        bundle.add(args.binary, arcname=name + '/bin/coffin', recursive=False)
        bundle.add(ROOT / 'docs/coffin.1', arcname=name + '/share/man/man1/coffin.1', recursive=False)
        for filename in ('README.md', 'License', 'CHANGELOG.md', 'VERSION'):
            bundle.add(ROOT / filename, arcname=name + '/' + filename, recursive=False)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix(archive.suffix + '.sha256').write_text(f'{digest}  {archive.name}\n')
    print(archive)


if __name__ == '__main__':
    main()
