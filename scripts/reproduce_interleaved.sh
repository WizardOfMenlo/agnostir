#!/usr/bin/env bash
set -euo pipefail

# Run the two reported instance sizes with the current shared configuration.
# --test executes each benchmark once; omit it to collect Criterion timings.
repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_dir"

output_dir="results/interleaved/$(date -u +%Y%m%dT%H%M%SZ)"
smoke=false
for arg in "$@"; do
  if [[ "$arg" == "--test" ]]; then
    smoke=true
  elif [[ "$arg" == --* ]]; then
    echo "Usage: bash scripts/reproduce_interleaved.sh [output-directory] [--test]" >&2
    exit 2
  else
    output_dir="$arg"
  fi
done
shopt -s nullglob dotglob
existing_entries=("$output_dir"/*)
if (( ${#existing_entries[@]} > 0 )); then
  echo "Choose a fresh output directory; $output_dir is not empty." >&2
  exit 2
fi
mkdir -p "$output_dir"
output_dir=$(cd "$output_dir" && pwd)

export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-8}"
export AGNOSTIR_CHUNK_LEN="${AGNOSTIR_CHUNK_LEN:-8192}"
export IOPP_SEED="${IOPP_SEED:-2025}"
export IOPP_INCLUDE_CONJECTURED_ERA=1
export IOPP_ONLY_CONJECTURED_ERA=0
export IOPP_SKIP_EA=0

# Keep Criterion outputs for each instance under this run directory, rather than
# overwriting a previous benchmark in target/criterion.
export CRITERION_HOME="$output_dir/criterion"
{
  date -u '+started_utc=%Y-%m-%dT%H:%M:%SZ'
  printf 'mode=%s\n' "$([[ "$smoke" == true ]] && echo smoke || echo benchmark)"
  printf 'rust_repo=%s\n' "$repo_dir"
  git rev-parse HEAD
  git status --short
  rustc -vV
  cargo --version
  uname -a
  if command -v sw_vers >/dev/null; then sw_vers; fi
  if command -v lscpu >/dev/null; then lscpu; fi
  if [[ "$(uname -s)" == Darwin ]]; then
    sysctl -n machdep.cpu.brand_string hw.memsize || true
  fi
  for name in RAYON_NUM_THREADS AGNOSTIR_CHUNK_LEN IOPP_SEED RUSTFLAGS CARGO_BUILD_TARGET; do
    printf '%s=%s\n' "$name" "${!name-}"
  done
} > "$output_dir/metadata.txt" 2>&1

# Preserve the exact code and lockfile even when benchmarking a dirty checkout.
git diff --no-ext-diff --binary HEAD > "$output_dir/source.patch"
git ls-files --cached --others --exclude-standard --deduplicate -z -- Cargo.toml Cargo.lock src benches scripts |
  while IFS= read -r -d '' source_file; do
    if [[ -f "$source_file" ]]; then printf '%s\0' "$source_file"; fi
  done | tar -czf "$output_dir/source.tar.gz" --null -T - 2> "$output_dir/source-archive.log"

for instance in '18 4' '22 6'; do
  read -r IOPP_MESSAGE_LOG IOPP_ETA <<< "$instance"
  export IOPP_MESSAGE_LOG IOPP_ETA
  label="k${IOPP_MESSAGE_LOG}_eta${IOPP_ETA}"
  if [[ "$smoke" == true ]]; then
    cargo bench --locked --bench iopp_bench -- --test 2>&1 | tee "$output_dir/$label.log"
  else
    cargo bench --locked --bench iopp_bench -- --save-baseline "$label" 2>&1 | tee "$output_dir/$label.log"
  fi
done
date -u '+completed_utc=%Y-%m-%dT%H:%M:%SZ' >> "$output_dir/metadata.txt"
printf 'Saved run to %s\n' "$output_dir"
