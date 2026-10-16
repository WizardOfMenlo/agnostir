#!/usr/bin/env python3
"""Reproduce the distance audit; prints JSON without changing benchmark presets.

Run with requirements-analysis.txt installed. All outputs are numerical bounds
for ideal ensembles, not security certificates for deterministic seeded codes.
"""
import importlib.util
import json
import math
from pathlib import Path

import numpy as np
from scipy.optimize import minimize_scalar

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT/'distance-analysis'/f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def query_count(delta):
    return math.ceil(-300/math.log2(1-delta))


def bolt_exponent(field_log2, delta=.0941):
    """Numerically minimize Bolt Theorem 8's exponent, in NATURAL logs.

    q is a float here; this is a diagnostic, not rigorous interval arithmetic.
    A nonnegative result does not refute the distance, it fails to certify it.
    """
    logq = field_log2*math.log(2)
    inverse_q = math.exp(-logq)
    logqm1 = logq+math.log1p(-inverse_q)
    entropy = -delta*math.log(delta)-(1-delta)*math.log1p(-delta)+delta*logqm1
    def omega(x):
        divergence = delta*math.log(delta/x)+(1-delta)*math.log((1-delta)/(1-x))
        z = 1-x/(1-inverse_q)
        log_power = -math.inf if z == 0 else 128*math.log(abs(z))
        rho = np.logaddexp(0, logqm1+log_power)
        return entropy+(16/128)*(128*divergence+rho-logq)
    optimum = minimize_scalar(omega, bounds=(1e-10, 1-1e-10), method='bounded',
                              options={'xatol': 1e-15})
    if not optimum.success:
        raise RuntimeError('Bolt exponent minimization failed')
    return {'field_log2': field_log2, 'kernel_distance': delta,
            'candidate_xhat': float(optimum.x), 'numerical_minimum_omega': float(optimum.fun)}


def main():
    bf, bd, era = (load(name) for name in ('basefold', 'brakedown', 'era'))
    field_log = 255.999  # Conservative lower bound for the secp256k1 scalar field.
    basefold_delta = bf.distance_for_setup_bits(field_log, 2, 16, 100)
    base_delta = .0009
    era_n = 4*int(65536*1.05)
    c = era.compute_c_from_q_bound(4, 102, base_delta, math.log2(era_n), field_log)
    if c is None:
        raise RuntimeError('no valid ERA field parameter')
    gamma = era.compute_gamma_from_n_bound(4, c, 102, math.log2(era_n))
    era_result = era.solve_details(c, 4, gamma, base_delta)
    if era_result is None:
        raise RuntimeError('ERA root calculation failed')
    outer = bf.distance_for_setup_bits(field_log, 2, 13, 102)
    # The previously derived finite-length prime-field kernel bound excludes
    # weights through m/16. Increasing this to the paper's .0941 would not help
    # the current outer-code bottleneck even if that transfer were justified.
    bolt_min = min(1/16/1.25, outer/5)
    result = {
        'scope': 'numerical paper-to-script audit, not a fixed-setup or complete IOPP certificate',
        'implemented_field': 'secp256k1 scalar field; these are the pre-migration parameters',
        'field_log2_lower_bound': field_log,
        'row_message_length': 65536,
        'basefold': {'setup_bits': 100, 'per_level_lambda': 104,
                     'distance': basefold_delta, 'conditional_queries': query_count(basefold_delta),
                     'legacy_per_level_100_distance': bf.compute_formula(field_log, 2, 16, 100)},
        'brakedown_current': bd.check_recursive(65536, .3, 2, .1, 10, 20),
        'brakedown_candidate': bd.check_recursive(65536, .3, 2, .1, 14, 28),
        'era': {'base_distance_used': base_delta,
                'base_check': bd.check_recursive(65536, .04, 1.05, base_delta, 5, 42, security=102),
                'block_length': era_n, 'calcdist_bits': 102, 'c': c, 'gamma': gamma,
                **era_result, 'conditional_queries': query_count(era_result['delta'])},
        'bolt': {
            'paper_kernel_distances': {'min': .0941, 'max': .013},
            'paper_RS_complete_distances': {'min': .0941/1.25, 'max': .013/1.25},
            'weighted_exponent_diagnostics': [bolt_exponent(32), bolt_exponent(field_log)],
            'adapted_min_with_existing_finite_kernel_bound': {
                'outer_setup_bits': 102, 'outer_per_level_lambda': 106,
                'outer_distance': outer, 'complete_distance': bolt_min,
                'conditional_queries': query_count(bolt_min)},
            'max_status': 'prime-characteristic and configuration-vs-Gallager ensemble transfer unproved',
            'proposed_binary_extension': {
                'field': 'GF(2^256)',
                'implemented': False,
                'kernel_distance_transfer': 'exact for a fixed matrix over a subfield',
                'max_matrix_coefficients': 'GF(2)',
                'min_matrix_coefficients': 'GF(2^32), embedded into GF(2^256)',
                'max_ensemble_required': 'Gallager strips, as in Bolt Section 6.1',
                'max_unexpurgated_setup_failure_log2_lower_bound':
                    7*math.log2(63/(65536-1)),
                'lower_bound_reason':
                    'one fixed pair in the first strip collides in all seven remaining strips',
                'basefold_status':
                    'general framework supports binary fields; current symmetric RFC needs adaptation',
            },
        },
        'benchmark_presets_changed': False,
    }
    print(json.dumps(result, indent=2, allow_nan=False))


if __name__ == '__main__':
    main()
