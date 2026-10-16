#!/usr/bin/env bash
set -euo pipefail
cd /home/ubuntu/agnostir-aws-r7a4x-n28-20261015
exec 9>campaign.lock
flock -n 9 || exit 75
trap 'result=$?; printf "%s\n" "$result" > campaign.exit; date -u +%FT%TZ > ended-at.txt' EXIT
phase() {
    printf '%s\n' "$1" > phase.txt
    printf '%s %s\n' "$(date -u +%FT%TZ)" "$1" >> events.log
}
date -u +%FT%TZ > started-at.txt
python3 -B control/instance.py > instance.json
phase install
sudo -n apt-get update > install.log 2>&1
sudo -n env DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential git curl python3-venv pkg-config >> install.log 2>&1
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o rustup-init.sh
sh rustup-init.sh -y --profile minimal --default-toolchain 1.92.0 >> install.log 2>&1
source "$HOME/.cargo/env"
export RUSTFLAGS='-C target-cpu=native'
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-analysis.txt > python-install.log 2>&1
phase build
cargo build --release --locked --bin interleaved_iopp --bin compare_iopps > build.log 2>&1
sha256sum target/release/interleaved_iopp target/release/compare_iopps > binaries.sha256
rustc -Vv > compiler.txt
lscpu > cpu.txt
uname -a > system.txt
phase tests
cargo test --locked --lib > tests.log 2>&1
.venv/bin/python -B -m unittest discover -s scripts -p test_large_iopp_plan.py -v > model-tests.log 2>&1
mkdir -p results/default-identity
target/release/compare_iopps --threads 16 --samples 1 --warmups 0 \
    --proof-dir results/default-identity/proofs > results/default-identity/timings.csv 2> results/default-identity/run.log
.venv/bin/python -B control/validate.py identity
phase full
.venv/bin/python -B scripts/run_large_iopp_plan.py \
    artifact_results/2026-10-15-aws-r7a4x-n28/plan.json results/full-n28 \
    --logs 28 --threads 16 --samples 1 --warmups 1 --memory-budget-gib 112 \
    --instance-type r7a.4xlarge > full-summary.log 2> full-run.log
.venv/bin/python -B control/validate.py full
phase complete
