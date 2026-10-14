#!/usr/bin/env bash
set -euo pipefail
repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_dir"
output_dir="${1:-results/artifact/$(date -u +%Y%m%dT%H%M%SZ)}"
mode="${2:-full}"
if [[ "$mode" != full && "$mode" != smoke ]]; then echo 'Mode must be full or smoke.' >&2; exit 2; fi
if [[ -e "$output_dir" ]]; then echo "Choose a new output directory: $output_dir" >&2; exit 2; fi
mkdir -p "$output_dir"
output_dir=$(cd "$output_dir" && pwd)
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-32}"
export AGNOSTIR_CHUNK_LEN="${AGNOSTIR_CHUNK_LEN:-8192}"
samples="${SAMPLES:-5}"
{
  date -u '+started_utc=%Y-%m-%dT%H:%M:%SZ'
  git rev-parse HEAD || true
  git status --short || true
  rustc -vV
  cargo -V
  uname -a
  command -v lscpu >/dev/null && lscpu || true
  if [[ "$(uname -s)" == Darwin ]]; then
    sysctl machdep.cpu.brand_string hw.physicalcpu hw.logicalcpu hw.memsize || true
  fi
  printf 'mode=%s\nthreads=%s\nsamples=%s\nwarmups=1\nRUSTFLAGS=%s\nchunk_len=%s\n' "$mode" "$RAYON_NUM_THREADS" "$samples" "${RUSTFLAGS-}" "$AGNOSTIR_CHUNK_LEN"
} > "$output_dir/metadata.txt" 2>&1
# Include dirty and untracked implementation files; exclude caches and outputs.
git diff --binary HEAD > "$output_dir/source.patch" 2>/dev/null || true
python3 - "$output_dir/source.tar.gz" <<'PY'
import sys,tarfile
from pathlib import Path
with tarfile.open(sys.argv[1], 'w:gz') as archive:
    for name in ('Cargo.toml','Cargo.lock','AGENTS.md','README.md','LICENSE','AI_DISCLOSURE.md',
                 'Dockerfile','requirements-analysis.txt','src','benches','scripts','docs',
                 'proof-size-estimate.py','distance-analysis','comparisons'):
        path=Path(name)
        if not path.exists(): continue
        files=sorted(path.rglob('*')) if path.is_dir() else [path]
        for file in files:
            if file.is_file() and not file.is_symlink() and not {'__pycache__','target'}.intersection(file.parts) and file.suffix != '.pyc' and file.name != '.DS_Store':
                archive.add(file,recursive=False)
PY
cargo build --locked --release --bins > "$output_dir/build.log" 2>&1
cargo test --locked --lib > "$output_dir/tests.log" 2>&1
cargo test --locked --lib --no-default-features > "$output_dir/tests-serial.log" 2>&1
if [[ "$mode" == smoke ]]; then
  target/release/compare_iopps --smoke --threads "$RAYON_NUM_THREADS" --samples 1 > "$output_dir/comparison.csv" 2> "$output_dir/comparison.log"
  target/release/interleaved_iopp --message-log 14 --eta 2 --queries 32 --threads "$RAYON_NUM_THREADS" --samples 1 --csv > "$output_dir/interleaved-era.csv" 2> "$output_dir/interleaved-era.log"
else
  for code in brakedown ea basefold era; do
    target/release/interleaved_iopp --code "$code" --message-log 22 --eta 6 --threads "$RAYON_NUM_THREADS" --samples "$samples" --csv > "$output_dir/interleaved-$code.csv" 2> "$output_dir/interleaved-$code.log"
  done
  target/release/compare_iopps --threads "$RAYON_NUM_THREADS" --samples "$samples" > "$output_dir/comparison.csv" 2> "$output_dir/comparison.log"
fi
python3 scripts/summarize_artifact.py "$output_dir"/*.csv > "$output_dir/summary.json"
if [[ "${INCLUDE_BOLT:-1}" == 1 ]]; then
  if [[ "$mode" == smoke ]]; then
    MESSAGE_LOG=14 ETA=2 SAMPLES=1 bash scripts/reproduce_bolt.sh "$output_dir/bolt-min"
  else
    bash scripts/reproduce_bolt.sh "$output_dir/bolt-min"
  fi
fi
date -u '+completed_utc=%Y-%m-%dT%H:%M:%SZ' >> "$output_dir/metadata.txt"
printf 'Results: %s\n' "$output_dir"
