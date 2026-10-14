#!/usr/bin/env python3
"""Exact kernel-ensemble certificate plus conditional outer-code calibration.

The certificate concerns ideal uniform setup, not a fixed seeded instance.
See docs/bolt-adaptation.md for the union bound and monotonicity proof.
The inherited BaseFold formula is evaluated numerically, not certified here.
"""
import importlib.util
import json
import math
from fractions import Fraction
from pathlib import Path

repo = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("basefold_distance", repo / "distance-analysis/basefold.py")
basefold = importlib.util.module_from_spec(spec)
spec.loader.exec_module(basefold)

# The smallest supported power of two is the worst case, as proved in the note.
m = 4096
t = m // 8
cutoff = m // 16
certificates = []
for weight in (1, cutoff):
    # B(w)^8, with h=9w/8, is rational even for non-integral h.
    base = (Fraction(3 * m, weight) ** 8
            * Fraction(24 * t, 9 * weight) ** 9
            * Fraction(9 * weight, 8 * t) ** 128)
    numerator = base.numerator ** weight
    denominator = base.denominator ** weight
    # cutoff * B(w) <= 2^-102, tested using only integer arithmetic.
    passed = cutoff ** 8 * numerator * 2 ** (8 * 102) <= denominator
    if not passed:
        raise SystemExit("Kernel graph bound failed")
    certificates.append({
        "weight": weight,
        "exact_integer_comparison_passed": passed,
        "approx_log2_union_bound": math.log2(cutoff) + (math.log2(numerator) - math.log2(denominator)) / 8,
    })

rows = []
for message_log in range(12, 23):
    outer_log = message_log - 3
    estimate = basefold.compute_formula(255, 2, outer_log, 102)
    outer_delta = math.floor(estimate * 1000) / 1000
    delta = min(1 / 20, outer_delta / 5)
    rows.append({
        "row_message_log": message_log,
        "outer_message_log": outer_log,
        "outer_conditional_distance_formula": estimate,
        "outer_conditional_distance_rounded_down": outer_delta,
        "adapted_conditional_distance": delta,
        "conditional_100_bit_queries": math.ceil(-300 / math.log2(1 - delta)),
    })
print(json.dumps({
    "scope": "Bolt-min ideal-ensemble kernel bound; conditional BaseFold distances; not a full IOPP security certificate",
    "minimum_message_size": m,
    "supported_row_message_logs": [12, 22],
    "kernel_weight_cutoff": "m/16",
    "kernel_graph_failure_bound": "2^-102",
    "kernel_coefficient_failure_bound": "<2^-263 (for log2(m)<=22 and |F|-1>2^255)",
    "kernel_certificates": certificates,
    "outer_formula_field_bits": 255,
    "outer_formula_setup_bits": 102,
    "rows": rows,
    "bolt_max": {
        "scope": "conditional experiment only; binary LDPC analysis does not certify prime-field distance",
        "degree": 8,
        "coefficients": "all-one (prime-field additions, not XOR)",
        "assumed_kernel_relative_distance": 0.013,
        "inverse_rate": 1.25,
        "assumed_complete_code_relative_distance": 0.013 / 1.25,
        "conditional_100_bit_queries": math.ceil(-300 / math.log2(1 - 0.013 / 1.25)),
        "prime_field_kernel_distance_certified": False,
        "setup_failure_certified": False,
    },
}, indent=2))
