#!/usr/bin/env python3
"""Summarize measured CSV files; refuse failed or mixed-size proof runs."""
import csv
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

groups = defaultdict(list)
for name in sys.argv[1:]:
    with Path(name).open(newline='') as stream:
        for row in csv.DictReader(stream):
            if row['accepted'] != 'true':
                raise SystemExit(f'Failed verification in {name}: {row}')
            identity = tuple(row.get(k, '') for k in (
                'protocol', 'code', 'message_log', 'eta', 'output_log',
                'output_log_rate', 'terminal_log', 'threads', 'seed', 'queries'))
            groups[identity].append(row)
summary = []
for identity, rows in groups.items():
    if len({r['proof_bytes'] for r in rows}) != 1:
        raise SystemExit(f'Non-deterministic proof size: {identity}')
    item = {k: rows[0][k] for k in rows[0] if k not in (
        'sample', 'setup_ms', 'commit_ms', 'prove_ms', 'verify_ms')}
    item['samples'] = len(rows)
    for stage in ('setup_ms', 'commit_ms', 'prove_ms', 'verify_ms'):
        values = [float(row[stage]) for row in rows]
        item[stage] = {'median': statistics.median(values), 'min': min(values),
                       'max': max(values)}
    summary.append(item)
print(json.dumps(summary, indent=2))
