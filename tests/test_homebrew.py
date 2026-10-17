"""Test a generated source formula in a temporary local tap, then remove it.

Refuse to replace an existing Coffin installation. The release formula remains
unchanged: only the disposable test tap uses a file:// source archive URL.
"""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from package_homebrew import formula


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    args = parser.parse_args()
    if sys.platform != 'darwin' or not shutil.which('brew'):
        parser.error('Homebrew installation checks require macOS with brew installed')
    env = {**os.environ, 'HOMEBREW_NO_AUTO_UPDATE': '1', 'HOMEBREW_NO_ANALYTICS': '1',
           'HOMEBREW_DEVELOPER': '1', 'HOMEBREW_NO_INSTALL_CLEANUP': '1'}
    existing = subprocess.run(['brew', 'list', '--formula', '--versions'], env=env,
                              capture_output=True, text=True, check=True, timeout=60)
    if any(line.split()[0] == 'coffin' for line in existing.stdout.splitlines() if line.split()):
        parser.error('Coffin is already installed through Homebrew; refusing to replace it')
    brew_prefix = Path(subprocess.check_output(['brew', '--prefix'], env=env, text=True, timeout=60).strip())
    linked = brew_prefix / 'bin/coffin'
    if linked.exists() or linked.is_symlink():
        parser.error(f'{linked} already exists; refusing to replace it')
    tap = f'coffin-ci/test-{os.getpid()}'
    full_name = tap + '/coffin'
    created = False
    installed = False

    def brew(*arguments):
        subprocess.run(['brew', *map(str, arguments)], env=env, check=True, timeout=600)

    try:
        brew('tap-new', '--no-git', tap)
        created = True
        repository = Path(subprocess.check_output(['brew', '--repository', tap], env=env, text=True, timeout=60).strip())
        target = repository / 'Formula/coffin.rb'
        target.parent.mkdir(exist_ok=True)
        archive = args.archive.resolve()
        target.write_text(formula(archive, archive.as_uri()))
        installed = True
        brew('install', '--build-from-source', full_name)
        prefix = Path(subprocess.check_output(['brew', '--prefix', full_name], env=env, text=True, timeout=60).strip())
        assert (prefix / 'bin/coffin').is_file() and linked.is_file()
        actual_prefix = prefix.resolve()
        brew('test', full_name)
        brew('reinstall', '--build-from-source', full_name)
        brew('test', full_name)
        brew('uninstall', full_name)
        installed = False
        assert not actual_prefix.exists() and not prefix.exists() and not linked.exists() and not linked.is_symlink()
        print('Homebrew package passed: source install, formula tests, reinstall, uninstall')
    finally:
        if installed:
            subprocess.run(['brew', 'uninstall', full_name], env=env, check=False)
        if created:
            subprocess.run(['brew', 'untap', tap], env=env, check=True)


if __name__ == '__main__':
    main()
