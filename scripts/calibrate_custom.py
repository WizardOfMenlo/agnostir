#!/usr/bin/env python3
"""Reproduce the *numerical* finite-size calibration, not a soundness certificate.
Requires numpy/scipy; no dependency is required to run the Rust benchmarks.
"""
import contextlib
import importlib.util
import io
import json
import math
from pathlib import Path
root = Path(__file__).resolve().parents[1]
def load(name):
    spec = importlib.util.spec_from_file_location(name, root/'distance-analysis'/f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
era, basefold = load('era'), load('basefold')
# At inner k=256 the corrected Brakedown encoder terminates at systematic RS.
inner_k, inner_n, repetition = 256, 281, 4
n = repetition * inner_n**2
base_delta = ((inner_n-inner_k+1)/inner_n)**2
setup_bits, query_bits, field_log = 102, 104, 255.999
with contextlib.redirect_stdout(io.StringIO()):
    c = era.compute_c_from_q_bound(repetition, setup_bits, base_delta, math.log2(n), field_log)
    gamma = era.compute_gamma_from_n_bound(repetition, c, setup_bits, math.log2(n))
    delta = era.solve_system(c, repetition, gamma, base_delta)
assert c is not None and 1 < c < repetition/2*(1-1/math.sqrt(5))
assert delta is not None and 0 < delta < 1
entries = []
for label, distance in (
    ('era', delta),
    ('terminal-basefold', basefold.compute_formula(field_log, 8, 15, setup_bits)),
    ('baseline-basefold', basefold.compute_formula(field_log, 2, 17, setup_bits)),
):
    rounded = math.floor(distance*1_000_000)/1_000_000
    entries.append({'code': label, 'raw_distance': distance, 'rounded_down_distance': rounded,
        'queries': math.ceil(-3*query_bits/math.log2(1-rounded))})
print(json.dumps({'status': 'numerical; independent proof/bound review pending',
    'inner_code': {'n': inner_n, 'k': inner_k, 'type': 'systematic RS base case'},
    'era_length': n, 'tensor_base_distance': base_delta, 'independent_multipliers': 2,
    'setup_bits': setup_bits, 'query_bits': query_bits, 'c': c, 'gamma': gamma,
    'entries': entries}, indent=2))
