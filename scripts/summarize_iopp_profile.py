#!/usr/bin/env python3
"""Validate and summarize compare_iopps timing/stage CSVs (stdlib only)."""
import argparse
import csv
import json
import statistics
from collections import defaultdict
from pathlib import Path


def summarize(directory):
    results = []
    identities = {}
    for timing_file in sorted(directory.glob("timings-t*.csv")):
        suffix = timing_file.name.removeprefix("timings-")
        with (directory / f"stages-{suffix}").open() as file:
            stage_rows = list(csv.DictReader(file))
        spans = defaultdict(list)
        for row in stage_rows:
            spans[row["protocol"], row["sample"]].append(row)
        groups = defaultdict(list)
        with timing_file.open() as file:
            for row in csv.DictReader(file):
                assert row["accepted"] == "true", row
                identity = (int(row["proof_bytes"]), row["proof_blake3"])
                assert identities.setdefault(row["protocol"], identity) == identity
                measurements = spans.pop((row["protocol"], row["sample"]))
                assert sum(int(m["exclusive_bytes"]) for m in measurements) == identity[0]
                root, = [m for m in measurements if m["path"] == "prove"]
                assert int(root["inclusive_bytes"]) == identity[0]
                assert abs(sum(float(m["exclusive_ms"]) for m in measurements)
                           - float(root["inclusive_ms"])) < 0.01
                row["total_prover_ms"] = float(row["commit_ms"]) + float(row["prove_ms"])
                groups[row["protocol"]].append((row, measurements))
        assert not spans, "orphan stage measurements"
        for protocol, runs in groups.items():
            paths = defaultdict(list)
            for row, measurements in runs:
                per_run = defaultdict(lambda: dict(calls=0, inclusive_ms=0., exclusive_ms=0.,
                                                  inclusive_bytes=0, exclusive_bytes=0))
                for m in measurements:
                    aggregate = per_run[m["path"]]
                    aggregate["calls"] += 1
                    for key in ("inclusive_ms", "exclusive_ms"):
                        aggregate[key] += float(m[key])
                    for key in ("inclusive_bytes", "exclusive_bytes"):
                        aggregate[key] += int(m[key])
                for path, aggregate in per_run.items():
                    paths[path].append(aggregate)
            metrics = {}
            for key in ("setup_ms", "commit_ms", "prove_ms", "verify_ms", "total_prover_ms"):
                values = [float(r[key]) for r, _ in runs]
                metrics[key] = dict(median=statistics.median(values),
                                    mean=statistics.mean(values), min=min(values), max=max(values))
            stages = {}
            for path, measurements in sorted(paths.items()):
                assert len(measurements) == len(runs)
                for key in ("calls", "inclusive_bytes", "exclusive_bytes"):
                    assert len({m[key] for m in measurements}) == 1
                stages[path] = {
                    **{key: measurements[0][key]
                       for key in ("calls", "inclusive_bytes", "exclusive_bytes")},
                    **{key: {"median": statistics.median(m[key] for m in measurements),
                             "mean": statistics.mean(m[key] for m in measurements)}
                       for key in ("inclusive_ms", "exclusive_ms")},
                }
            first = runs[0][0]
            results.append(dict(protocol=protocol, threads=int(first["threads"]),
                                samples=len(runs), proof_bytes=int(first["proof_bytes"]),
                                proof_blake3=first["proof_blake3"], metrics=metrics, stages=stages))
    assert results, "no timing/stage pairs found"
    controls = []
    for path in sorted(directory.glob("control-t*.csv")):
        with path.open() as file:
            for row in csv.DictReader(file):
                assert row["accepted"] == "true"
                assert identities[row["protocol"]] == (int(row["proof_bytes"]), row["proof_blake3"])
                controls.append(row)
    return dict(status="all proofs verified; byte accounting and cross-run identities agree",
                results=results, unprofiled_controls=controls)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(summarize(args.directory), indent=2))
