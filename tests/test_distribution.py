"""Exercise version output, staging/uninstall, and archives without system writes."""
import hashlib
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
binary = Path(sys.argv[1]).resolve()
version = (ROOT / 'VERSION').read_text().strip()
assert subprocess.check_output([str(binary), '--version'], text=True).strip() == 'coffin ' + version
with tempfile.TemporaryDirectory() as temporary:
    work = Path(temporary)
    # TARGET picks the already tested normal/sanitized binary. DESTDIR confines
    # all writes/removals to this disposable staging tree, even for PREFIX=/usr.
    arguments = ['make', f'TARGET={binary}', f'DESTDIR={work}', 'PREFIX=/usr']
    subprocess.run([*arguments, 'install'], cwd=ROOT, check=True, capture_output=True)
    installed = work / 'usr/bin/coffin'
    assert installed.read_bytes() == binary.read_bytes()
    assert installed.stat().st_mode & 0o777 == 0o755
    sentinel = installed.parent / 'other-program'
    sentinel.write_text('unrelated file')
    subprocess.run([*arguments, 'uninstall'], cwd=ROOT, check=True, capture_output=True)
    assert not installed.exists() and sentinel.read_text() == 'unrelated file'
    assert not (work / 'usr/share/doc/coffin/README.md').exists()
    subprocess.run([sys.executable, str(ROOT / 'scripts/package_release.py'), str(binary),
                    '--output-dir', str(work)], check=True, capture_output=True)
    archive, = work.glob('*.tar.gz')
    checksum = archive.with_suffix(archive.suffix + '.sha256').read_text().split()[0]
    assert checksum == hashlib.sha256(archive.read_bytes()).hexdigest()
    with tarfile.open(archive) as bundle:
        names = bundle.getnames()
        assert len(names) == 5 and all(not n.startswith('/') and '..' not in Path(n).parts for n in names)
        member, = [n for n in names if n.endswith('/bin/coffin')]
        assert bundle.extractfile(member).read() == binary.read_bytes()
        assert bundle.getmember(member).mode & 0o111
print('Distribution checks passed: version, staged install/uninstall, archive, checksum')
