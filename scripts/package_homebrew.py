"""Render a formula with the actual source archive's checksum, never a placeholder."""
import argparse
import hashlib
import json
from pathlib import Path
from urllib.parse import urlparse
from package_source import ROOT, version


def formula(archive, url):
    # JSON strings are compatible Ruby literals after escaping interpolation.
    # Reject interpolation rather than allowing an untrusted URL to become Ruby.
    if '#{' in url or '\n' in url or '\r' in url or urlparse(url).scheme not in ('https', 'file'):
        raise ValueError('Source URL must be a literal https:// or file:// URL')
    text = (ROOT / 'packaging/homebrew/coffin.rb.in').read_text()
    for token, value in {'SOURCE_URL': url, 'VERSION': version(),
                         'SHA256': hashlib.sha256(archive.read_bytes()).hexdigest()}.items():
        text = text.replace('@' + token + '@', json.dumps(value))
    return text


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('archive', type=Path)
    parser.add_argument('--source-url', help='default: versioned GitHub release asset URL')
    parser.add_argument('--output', type=Path, default=ROOT / 'dist/coffin.rb')
    args = parser.parse_args()
    url = args.source_url or f'https://github.com/jerryrw/coffin/releases/download/v{version()}/{args.archive.name}'
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(formula(args.archive.resolve(), url))
    print(args.output)
