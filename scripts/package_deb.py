"""Build a native Debian package in a disposable source tree, without installing it."""
import argparse
from datetime import datetime, timezone
from email.utils import format_datetime
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
from package_source import ROOT, checksum, export_tree, source_epoch, version


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'dist')
    args = parser.parse_args()
    if platform.system() != 'Linux' or not shutil.which('dpkg-buildpackage') or not shutil.which('dh'):
        parser.error('Build on Debian/Ubuntu with build-essential, debhelper, dpkg-dev, and python3 installed')
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    # Debian orders prereleases before their final release with a tilde.
    deb_version = version().replace('-', '~', 1) + '-1'
    epoch = str(source_epoch())
    date = format_datetime(datetime.fromtimestamp(int(epoch), timezone.utc))
    with tempfile.TemporaryDirectory(prefix='coffin-deb-') as temporary:
        source = Path(temporary) / ('coffin-' + version())
        export_tree(source)
        shutil.copytree(source / 'packaging/debian', source / 'debian')
        (source / 'debian/rules').chmod(0o755)
        (source / 'debian/changelog').write_text(
            f'coffin ({deb_version}) unstable; urgency=medium\n\n'
            '  * Package the upstream executable inspector.\n\n'
            f' -- Coffin contributors <jerryrw@users.noreply.github.com>  {date}\n')
        env = {**os.environ, 'SOURCE_DATE_EPOCH': epoch}
        # Binary-only build: debhelper runs normal tests and determines shared
        # library dependencies. No root privileges or source upload are required.
        subprocess.run(['dpkg-buildpackage', '-b', '-us', '-uc'], cwd=source, env=env, check=True)
        packages = sorted(Path(temporary).glob('*.deb'))
        if not packages:
            raise RuntimeError('Debian build did not produce a package')
        for package in packages:
            target = output / package.name
            shutil.copyfile(package, target)
            checksum(target)
            print(target)


if __name__ == '__main__':
    main()
