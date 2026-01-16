#!/usr/bin/env bash
set -euo pipefail

BENCH_NAME="optimized_era_repetition_6"
SIZES=(
  4096
  8192
  16384
  32768
  65536
  131072
  262144
  524288
  1048576
)

best_size=""
best_time=""

for size in "${SIZES[@]}"; do
  echo "==> chunk_len=${size}"
  output=$(
    AGNOSTIR_CHUNK_LEN="${size}" \
      cargo bench --bench compare_codes "${BENCH_NAME}" 2>/dev/null
  )
  line=$(printf "%s\n" "${output}" | rg -m 1 "time:\\s+\\[")
  if [[ -z "${line}" ]]; then
    echo "No timing line found for ${size}"
    continue
  fi
  median=$(printf "%s\n" "${line}" | sed -E 's/.*\[[^0-9]*[0-9.]+ (ns|us|ms|s) ([0-9.]+) (ns|us|ms|s) [0-9.]+ (ns|us|ms|s)\].*/\2/')
  unit=$(printf "%s\n" "${line}" | sed -E 's/.*\[[^0-9]*[0-9.]+ (ns|us|ms|s) ([0-9.]+) (ns|us|ms|s) [0-9.]+ (ns|us|ms|s)\].*/\3/')
  echo "time: ${median} ${unit}"

  if [[ -z "${best_time}" ]]; then
    best_time="${median}"
    best_size="${size}"
  else
    better=$(awk -v a="${median}" -v b="${best_time}" 'BEGIN {print (a+0 < b+0) ? 1 : 0}')
    if [[ "${better}" == "1" ]]; then
      best_time="${median}"
      best_size="${size}"
    fi
  fi
done

echo "Best chunk_len=${best_size} with median ${best_time}"
