#!/usr/bin/env bash
# Reviewer entry point. Full-size cases always run sequentially at 2^28.
set -euo pipefail
cd "$(dirname "$0")/.."
mode=${1:-smoke}
output=${2:-results/artifact-$mode}
threads=${THREADS:-8}
samples=${SAMPLES:-1}
if [[ "$mode" == evidence ]]; then
    python3 -B artifact/validate.py evidence .
    python3 -B artifact/summarize.py evidence
    exit 0
fi
case "$mode" in check|smoke|paper22|full28|codeswitch28|interleaved28) ;; *)
    echo 'Modes: evidence, check, smoke, paper22, full28, codeswitch28, interleaved28' >&2; exit 2;; esac
if [[ -e "$output" ]]; then echo "Output already exists: $output" >&2; exit 2; fi
if [[ "$mode" == full28 || "$mode" == codeswitch28 || "$mode" == interleaved28 ]]; then
    experiment=both
    [[ "$mode" != codeswitch28 ]] || experiment=codeswitching
    [[ "$mode" != interleaved28 ]] || experiment=interleaved
    python3 -B scripts/run_large_iopp_plan.py artifact/evaluation-plan.json "$output" \
        --logs 28 --threads 16 --samples 1 --warmups 1 --memory-budget-gib 112 \
        --experiment "$experiment" --instance-type "${INSTANCE_TYPE:-unspecified}" --profile
    python3 -B artifact/validate.py run "$output"
    python3 -B artifact/summarize.py "$output"
    python3 -B artifact/validate.py manifest "$output"
    exit 0
fi
mkdir -p "$output"
output=$(cd "$output" && pwd)
python3 -B artifact/snapshot.py "$output"
{
    date -u +%FT%TZ
    uname -a
    rustc -Vv
    cargo -V
    python3 --version
    python3 -m pip freeze
    printf 'mode=%s\nthreads=%s\nwarmups=1\nsamples=%s\nRUSTFLAGS=%s\n' "$mode" "$threads" "$samples" "${RUSTFLAGS-}"
    command -v lscpu >/dev/null && lscpu || true
} > "$output/environment.txt" 2>&1
if [[ "$mode" == check || "$mode" == smoke ]]; then
    cargo test --release --locked --lib > "$output/tests.log" 2>&1
    cargo test --release --locked --lib --no-default-features > "$output/tests-serial.log" 2>&1
    python3 -B -m unittest discover -s distance-analysis -v > "$output/distance-tests.log" 2>&1
    python3 -B -m unittest discover -s scripts -p test_large_iopp_plan.py -v > "$output/model-tests.log" 2>&1
    python3 -B scripts/calibrate_interleaved.py > "$output/calibration.json"
fi
if [[ "$mode" != check ]]; then
    for code in era basefold brakedown ea; do
        args=(--message-log 22 --eta 6)
        [[ "$mode" != smoke ]] || args=(--message-log 18 --eta 2 --queries 32)
        target/release/interleaved_iopp --code "$code" "${args[@]}" --threads "$threads" \
            --samples "$samples" --warmups 1 --proof-out "$output/$code.proof" --csv \
            > "$output/interleaved-$code.csv" 2> "$output/interleaved-$code.log"
    done
    if [[ "$mode" == smoke ]]; then
        target/release/compare_iopps --smoke --threads "$threads" --samples 1 --warmups 1 \
            --proof-dir "$output/proofs" > "$output/iopps.csv" 2> "$output/iopps.log"
    fi
    python3 -B artifact/validate.py run "$output"
    python3 -B artifact/summarize.py "$output"
fi
python3 -B artifact/validate.py manifest "$output"
printf 'Completed: %s\n' "$output"
