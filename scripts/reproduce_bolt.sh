#!/usr/bin/env bash
# CPU-only upstream Bolt-min commitment comparison, kept separate from IOPP CSVs.
set -euo pipefail
repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_dir"
output_dir="${1:-results/bolt/$(date -u +%Y%m%dT%H%M%SZ)}"
if [[ -e "$output_dir" ]]; then echo "Choose a new output directory: $output_dir" >&2; exit 2; fi
mkdir -p "$output_dir"
output_dir=$(cd "$output_dir" && pwd)
threads="${RAYON_NUM_THREADS:-32}"
samples="${SAMPLES:-5}"
warmups="${WARMUPS:-1}"
message_log="${MESSAGE_LOG:-22}"
eta="${ETA:-6}"
seed="${SEED:-2025}"
manifest="comparisons/bolt-min/Cargo.toml"
{
  date -u '+started_utc=%Y-%m-%dT%H:%M:%SZ'
  git rev-parse HEAD
  rustc -vV
  cargo -V
  uname -a
  command -v lscpu >/dev/null && lscpu || true
  if [[ "$(uname -s)" == Darwin ]]; then
    sysctl machdep.cpu.brand_string hw.physicalcpu hw.logicalcpu hw.memsize || true
  fi
  printf 'scope=commitment-only\nfield=GF(2^32)\nupstream=3832e47b24e7b3e10525c9c5bcfc1cfe66d525f2\n'
  printf 'threads=%s\nsamples=%s\nwarmups=%s\nmessage_log=%s\neta=%s\nseed=%s\nRUSTFLAGS=%s\n' \
    "$threads" "$samples" "$warmups" "$message_log" "$eta" "$seed" "${RUSTFLAGS-}"
} > "$output_dir/metadata.txt" 2>&1
tar -czf "$output_dir/adapter-source.tar.gz" \
  comparisons/bolt-min/Cargo.toml comparisons/bolt-min/Cargo.lock \
  comparisons/bolt-min/src scripts/reproduce_bolt.sh scripts/summarize_bolt.py
cargo test --locked --manifest-path "$manifest" > "$output_dir/tests.log" 2>&1
cargo build --release --locked --manifest-path "$manifest" > "$output_dir/build.log" 2>&1
# The dependency's .cargo/config.toml is not inherited. Record explicit host flags.
for hash in sha256 blake3; do
  comparisons/bolt-min/target/release/agnostir-bolt-min-comparison \
    --hash "$hash" --message-log "$message_log" --eta "$eta" \
    --threads "$threads" --samples "$samples" --warmups "$warmups" --seed "$seed" \
    > "$output_dir/$hash.csv" 2> "$output_dir/$hash.log"
done
python3 scripts/summarize_bolt.py "$output_dir"/sha256.csv "$output_dir"/blake3.csv > "$output_dir/summary.json"
date -u '+completed_utc=%Y-%m-%dT%H:%M:%SZ' >> "$output_dir/metadata.txt"
printf 'Bolt commitment results: %s\n' "$output_dir"
