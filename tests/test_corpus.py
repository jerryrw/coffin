"""Run the frozen corpus through the CLI; timeouts and sanitizer errors fail."""
import hashlib
from pathlib import Path
import subprocess
import sys
from regression_corpus import corpus_cases

binary = str(Path(sys.argv[1]).resolve())
count = 0
for case, path, data in corpus_cases():
    result = subprocess.run([binary, str(path)], capture_output=True, text=True,
                            timeout=10)
    assert result.returncode == case['exit'], (path, result.returncode, result.stderr)
    assert ('Analysis Report' in result.stdout) == (case['exit'] == 0), path
    assert not any(word in result.stderr for word in
                   ('Sanitizer', 'runtime error:', 'LeakSanitizer')), (path, result.stderr)
    if case['exit'] == 0:
        assert hashlib.sha256(data).hexdigest() in result.stdout, path
    for text in case.get('stdout_contains', []):
        assert text in result.stdout, (path, text, result.stdout)
    for text in case.get('stderr_contains', []):
        assert text in result.stderr, (path, text, result.stderr)
    count += 1
print(f'Permanent regression corpus passed: {count} cases')
