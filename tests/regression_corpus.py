"""Load frozen, checksummed regression inputs for tests and fuzz seeding."""
import hashlib
import json
from pathlib import Path

DIRECTORY = Path(__file__).resolve().parent / 'corpus'


def corpus_cases():
    cases = json.loads((DIRECTORY / 'manifest.json').read_text())
    listed = {case['file'] for case in cases}
    present = {path.name for path in DIRECTORY.glob('*.bin')}
    if listed != present:
        raise ValueError(f'Corpus files differ from manifest: {listed ^ present}')
    names = set()
    for case in cases:
        name = case['file']
        if Path(name).name != name or name in names:
            raise ValueError(f'Invalid or duplicate corpus filename: {name}')
        names.add(name)
        data = (DIRECTORY / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != case['sha256']:
            raise ValueError(f'Corpus checksum mismatch: {name}')
        if case['exit'] not in (0, 1) or not case['reason']:
            raise ValueError(f'Missing corpus expectation: {name}')
        yield case, DIRECTORY / name, data
