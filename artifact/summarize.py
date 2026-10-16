#!/usr/bin/env python3
"""Summarize raw accepted timing rows, including median per-sample total time."""
import csv
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

root = Path(sys.argv[1])
groups = defaultdict(list)
for path in sorted(root.rglob('*.csv')):
    with path.open() as stream:
        reader = csv.DictReader(stream)
        if not {'accepted', 'commit_ms', 'prove_ms', 'verify_ms'}.issubset(reader.fieldnames or []):
            continue
        for row in reader:
            if row['accepted'] != 'true':
                raise SystemExit(f'Failed proof: {path}')
            group = (str(path.relative_to(root).parent), row.get('code', row['protocol']),
                     row['message_log'], row['eta'], row['threads'])
            groups[group].append(row)
result = []
for (campaign, protocol, log, eta, threads), rows in groups.items():
    lengths = {int(r['proof_bytes']) for r in rows}
    assert len(lengths) == 1, (campaign, protocol)
    summary = dict(campaign=campaign, protocol=protocol, message_log=int(log),
                   eta=int(eta), threads=int(threads), samples=len(rows), proof_bytes=lengths.pop())
    for field in ['setup_ms', 'commit_ms', 'prove_ms', 'verify_ms']:
        summary[field] = statistics.median(float(r[field]) for r in rows)
    summary['total_prover_ms'] = statistics.median(float(r['commit_ms']) + float(r['prove_ms']) for r in rows)
    result.append(summary)
assert result, f'No timing CSVs in {root}'
print(json.dumps(result, indent=2))
