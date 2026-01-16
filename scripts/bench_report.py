#!/usr/bin/env -S uv run --python 3.12
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


def run_benchmarks(bench: str) -> None:
    subprocess.run(["cargo", "bench", "--bench", bench], check=True)


def load_results(criterion_dir: Path, groups: list[str]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for group in groups:
        group_dir = criterion_dir / group / "size"
        if not group_dir.exists():
            continue
        for entry in group_dir.iterdir():
            if not entry.is_dir() or entry.name == "report":
                continue
            estimates_path = entry / "new" / "estimates.json"
            bench_path = entry / "new" / "benchmark.json"
            if not estimates_path.exists() or not bench_path.exists():
                continue
            with estimates_path.open("r", encoding="utf-8") as handle:
                estimates = json.load(handle)
            with bench_path.open("r", encoding="utf-8") as handle:
                bench_info = json.load(handle)
            median_ns = estimates["median"]["point_estimate"]
            throughput = bench_info.get("throughput", {}).get("Elements")
            value_str = bench_info.get("value_str", entry.name)
            log_size = parse_log_size(value_str, entry.name)
            rows.append(
                {
                    "group": group,
                    "size": value_str,
                    "log_size": log_size,
                    "median_ns": median_ns,
                    "throughput": throughput,
                }
            )
    return rows


def parse_log_size(value_str: str, fallback: str) -> int:
    match = re.search(r"\^(\d+)", value_str)
    if match:
        return int(match.group(1))
    match = re.search(r"(\d+)$", fallback)
    if match:
        return int(match.group(1))
    return 0


def format_markdown(rows: list[dict[str, object]]) -> str:
    header = "| Benchmark | Size | Median (ms) | Throughput (Melem/s) |\n"
    header += "| --- | --- | --- | --- |\n"
    lines = [header]
    for row in rows:
        median_ms = row["median_ns"] / 1_000_000
        throughput = row["throughput"]
        if throughput:
            melems = throughput / (row["median_ns"] * 1e-9) / 1e6
            throughput_str = f"{melems:.2f}"
        else:
            throughput_str = "-"
        lines.append(
            f"| {row['group']} | {row['size']} | {median_ms:.3f} | {throughput_str} |\n"
        )
    return "".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run Criterion benchmarks and emit a Markdown summary table."
    )
    parser.add_argument("--no-run", action="store_true", help="Skip running cargo bench.")
    parser.add_argument(
        "--bench", default="era_encode", help="Criterion bench target to run."
    )
    parser.add_argument(
        "--criterion-dir",
        default="target/criterion",
        help="Path to Criterion output directory.",
    )
    parser.add_argument(
        "--out",
        default="",
        help="Write the Markdown table to this path instead of stdout.",
    )
    args = parser.parse_args()

    if not args.no_run:
        run_benchmarks(args.bench)

    criterion_dir = Path(args.criterion_dir)
    rows = load_results(criterion_dir, ["encode_naive", "encode_packed"])
    rows.sort(key=lambda row: (row["group"], row["log_size"]))

    if not rows:
        print("No Criterion results found.", file=sys.stderr)
        return 1

    table = format_markdown(rows)
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(table, encoding="utf-8")
    else:
        sys.stdout.write(table)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
