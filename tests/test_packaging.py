"""Check source export boundaries and formula checksums without installing software."""
import hashlib
from pathlib import Path
import sys
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from package_source import source_archive, version, export_tree
from package_homebrew import formula


class PackagingTests(unittest.TestCase):
    def test_source_archive_and_formula(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = source_archive(root / 'first')
            again = source_archive(root / 'second')
            self.assertEqual(archive.read_bytes(), again.read_bytes())
            snapshot = root / 'snapshot'
            export_tree(snapshot)
            subprocess.run([sys.executable, 'scripts/package_source.py', '--output-dir', str(root / 'exported')],
                           cwd=snapshot, check=True, capture_output=True)
            self.assertEqual(archive.read_bytes(), (root / 'exported' / archive.name).read_bytes())
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            self.assertEqual(archive.with_name(archive.name + '.sha256').read_text().split()[0], digest)
            with tarfile.open(archive) as bundle:
                prefix = 'coffin-' + version() + '/'
                members = {member.name.removeprefix(prefix): member for member in bundle.getmembers()}
                self.assertTrue({'Makefile', 'src/main.c', 'VERSION', 'License',
                                 'packaging/debian/rules', 'tests/corpus/manifest.json',
                                 'hello-pe64.exe'} <= members.keys())
                self.assertFalse(any(name.startswith(('bin/', 'obj/', 'dist/', '.git/')) for name in members))
                self.assertTrue(all(member.isfile() and member.name.startswith(prefix) and
                                    '..' not in Path(member.name).parts for member in members.values()))
                self.assertEqual(bundle.extractfile(members['src/main.c']).read(), (ROOT / 'src/main.c').read_bytes())
                self.assertEqual(members['packaging/debian/rules'].mode, 0o755)
            text = formula(archive, 'https://example.invalid/coffin-source.tar.gz')
            self.assertIn(f'sha256 "{digest}"', text)
            self.assertIn(f'version "{version()}"', text)
            self.assertNotIn('@SOURCE_URL@', text)
            self.assertIn(archive.as_uri(), formula(archive, archive.as_uri()))
            with self.assertRaises(ValueError):
                formula(archive, 'https://example.invalid/#{execute_me}')


if __name__ == '__main__':
    unittest.main()
