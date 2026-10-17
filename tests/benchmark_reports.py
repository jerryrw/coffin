"""Compare focused versus section-report cost on a caller-supplied large file.

Elapsed times are observations, never pass/fail thresholds. Verbose entropy-read
counters explain work independently of filesystem caches or noisy wall clocks.
"""
import argparse
from pathlib import Path
import re
import statistics
import subprocess
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('binary', type=Path)
parser.add_argument('input', type=Path)
parser.add_argument('--runs', type=int, default=5)
args = parser.parse_args()
if args.runs < 1:
    parser.error('--runs must be positive')
for selector in ('--headers', '--sections'):
    elapsed = []
    for _ in range(args.runs):
        start = time.perf_counter()
        result = subprocess.run([str(args.binary.resolve()), '--verbose', selector, str(args.input)],
                                capture_output=True, text=True, check=True)
        elapsed.append(time.perf_counter() - start)
    work = re.search(r'^Entropy work: .+$', result.stdout, re.M)
    print(f'{selector}: median {statistics.median(elapsed):.6f}s; {work.group() if work else "no counter"}')
