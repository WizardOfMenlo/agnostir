#!/usr/bin/env python3
"""Summarize commitment measurements without implying a measured Bolt proof."""
import csv
import json
import statistics
import sys
from collections import defaultdict

groups = defaultdict(list)
for name in sys.argv[1:]:
    with open(name, newline="") as stream:
        for row in csv.DictReader(stream):
            if row["scope"] != "commitment-only" or any(
                row[k] != "true" for k in ("encoder_checked", "merkle_checked")
            ):
                raise SystemExit(f"Failed commitment check in {name}")
            identity = tuple(row[k] for k in (
                "code", "scope", "field", "hash", "message_log", "eta", "seed", "threads"
            ))
            groups[identity].append(row)
summary = []
for rows in groups.values():
    if len({r["root_hex"] for r in rows}) != 1:
        raise SystemExit("Non-deterministic commitment roots")
    stages = ("setup_ms", "buffer_ms", "expander_ms", "rs_ms", "merkle_ms", "commit_ms")
    item = {k: v for k, v in rows[0].items() if k not in (*stages, "sample")}
    item["samples"] = len(rows)
    for key in stages:
        values = [float(r[key]) for r in rows]
        item[key] = {"median": statistics.median(values), "min": min(values), "max": max(values)}
    # Null means unavailable, never zero cost or an estimated serialized length.
    item.update(prove_ms=None, verify_ms=None, proof_bytes=None, queries=None)
    summary.append(item)
print(json.dumps(summary, indent=2))
