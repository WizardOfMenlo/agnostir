#!/usr/bin/env python3
"""Optimize interleaving for expected serialized size, with a conservative RAM model.

Distances use the existing numerical bounds, not a new soundness certificate.
Only eta changes: encoder parameters, codeswitch output_log=15/rate=1/8,
terminal_log=12, and the two query-budget conventions stay fixed.
"""
import argparse
import importlib.util
import json
import math
import sys
from functools import lru_cache
from pathlib import Path

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
GIB = 1 << 30
SETUP_BITS = 102
FIELD_LOG = 255.999


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'distance-analysis' / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


BD, BF, ERA = (load(name) for name in ('brakedown', 'basefold', 'era'))


def ceildiv(n, d):
    return (n + d - 1) // d


def power_ceiling(n):
    return 1 << (n - 1).bit_length()


def distinct(n, q):
    return n if n == 1 else -n * math.expm1(q * math.log1p(-1 / n))


def empty_probability(count, n, q):
    if count == 0:
        return 1.0
    if count == n:
        return 0.0
    return math.exp(q * math.log1p(-count / n))


def authentication_hashes(n, q):
    """Exact expectation for uniform draws, including non-power-of-two padding.

    A sibling hash is sent iff exactly one of its two subtrees is occupied.
    The implementation transmits missing siblings even in the padded tail.
    """
    hashes, size = 0.0, 1
    while size < power_ceiling(max(2, n)):
        full, tail = divmod(n, 2 * size)
        if full:
            hashes += full * 2 * (empty_probability(size, n, q)
                                  - empty_probability(2 * size, n, q))
        if tail:
            a, b = min(size, tail), max(0, tail - size)
            hashes += (empty_probability(a, n, q) + empty_probability(b, n, q)
                       - 2 * empty_probability(tail, n, q))
        size *= 2
    return hashes


def opening_bytes(length, queries, height):
    return 32 * (height * distinct(length, queries) + authentication_hashes(length, queries))


def basefold_proof_bytes(row_log, rate_log, terminal_log, queries, heights):
    rounds = row_log - terminal_log
    size = 32 * (3 * rounds + rounds - 1 + (1 << terminal_log))
    for r in range(rounds):
        pairs = 1 << (row_log + rate_log - r - 1)
        # Both children of each queried pair are opened, so the first level
        # sends no sibling hashes. Subsequent pair indices remain uniform.
        sources = heights if r == 0 else [1]
        size += 32 * (2 * distinct(pairs, queries) * sum(sources)
                      + len(sources) * authentication_hashes(pairs, queries))
    return size


@lru_cache(maxsize=None)
def brakedown_storage(k, alpha, inverse_rate, cn, dn, base_case='rs'):
    n, child = int(k * inverse_rate), math.ceil(alpha * k)
    child_n = int(child * inverse_rate)
    parity = n - k - child_n
    if child < cn or parity < dn or k <= 32:
        return 32 * k * (n - k) if base_case == 'rs' else 0
    return (40 * (k * cn + child_n * dn) + 8 * (child + parity + 2)
            + brakedown_storage(child, alpha, inverse_rate, cn, dn, base_case))


@lru_cache(maxsize=None)
def checked_bd(k, alpha, inverse_rate, delta, cn, dn):
    return BD.check_recursive(k, alpha, inverse_rate, delta, cn, dn, security=SETUP_BITS)


def query_count(distance, bits):
    return math.ceil(-3 * bits / math.log2(1 - distance))


def era_distance(length, base_delta):
    c = ERA.compute_c_from_q_bound(4, SETUP_BITS, base_delta, math.log2(length), FIELD_LOG)
    if c is None:
        raise ValueError('ERA field-size inequality has no feasible c')
    gamma = ERA.compute_gamma_from_n_bound(4, c, SETUP_BITS, math.log2(length))
    if not 0 < gamma < base_delta:
        raise ValueError('ERA gamma is not below the base distance')
    solution = ERA.solve_details(c, 4, gamma, base_delta)
    if solution is None:
        raise ValueError('ERA numerical root search failed')
    return solution['delta'], dict(base_distance=base_delta, c=c, gamma=gamma, **solution)


@lru_cache(maxsize=None)
def row_parameters(kind, row_log):
    k = 1 << row_log
    details = {}
    if kind == 'basefold':
        length = 2 * k
        delta = BF.distance_for_setup_bits(FIELD_LOG, 2, row_log, SETUP_BITS)
        storage = 32 * 2 * (k - 1)
    elif kind == 'ea':
        length = 2 * k
        delta = .1
        storage = 48 * length * ((row_log + 1) * 18 // 2)
        details['scope'] = 'EA distance 0.1 is the inherited conjecture'
    elif kind == 'brakedown':
        length = 2 * k
        delta = .1
        check = checked_bd(k, .3, 2., delta, 14, 28)
        if not check['bound_passes']:
            raise ValueError('Brakedown recursive finite-size bound fails at distance 0.1')
        storage = brakedown_storage(k, .3, 2., 14, 28)
        details['base_rs_dimensions'] = check['base_rs_dimensions']
    elif kind == 'era':
        length = 4 * int(k * 1.05)
        check = checked_bd(k, .04, 1.05, .0009, 5, 42)
        if not check['bound_passes']:
            raise ValueError('ERA base-code bound fails at distance 0.0009')
        delta, details = era_distance(length, .0009)
        storage = brakedown_storage(k, .04, 1.05, 5, 42) + 80 * length
    else:
        assert kind == 'era-codeswitch' and row_log % 2 == 0
        inner_k = 1 << (row_log // 2)
        inner_n = int(inner_k * 1.1)
        check = checked_bd(inner_k, .05, 1.1, .01, 6, 40)
        if check['events'] == 0:
            inner_delta = (inner_n - inner_k + 1) / inner_n
        else:
            # Keep the paper's 0.01 target when its finite-size check passes.
            # Otherwise try a documented descending grid, never assume it.
            inner_delta = None
            for candidate in [.01, .009, .008, .007, .006, .005, .004, .003, .002, .001]:
                if checked_bd(inner_k, .05, 1.1, candidate, 6, 40)['bound_passes']:
                    inner_delta = candidate
                    break
            if inner_delta is None:
                raise ValueError('no checked inner distance on the candidate grid')
        length = 4 * inner_n * inner_n
        delta, details = era_distance(length, inner_delta * inner_delta)
        details.update(inner_k=inner_k, inner_n=inner_n, inner_distance=inner_delta)
        storage = brakedown_storage(inner_k, .05, 1.1, 6, 40) + 80 * length
    rounded = math.floor(delta * 1_000_000) / 1_000_000
    if not 0 < rounded < 1:
        raise ValueError('distance is not positive after rounding')
    return dict(block_length=length, distance=rounded, numerical_distance=delta,
                code_storage_bytes=storage, distance_details=details)


def interleaved_candidate(kind, log, row_log, threads):
    p = row_parameters(kind, row_log)
    k, n, h = 1 << row_log, 1 << log, 1 << (log - row_log)
    length = p['block_length']
    q = query_count(p['distance'], 100)
    proof = 40 + 32 * (3 * log + k) + opening_bytes(length, q, h)
    resident = 32 * (n + h * length) + p['code_storage_bytes'] + 64 * power_ceiling(length)
    # Worst-case row temporaries for up to one active encoding per worker.
    scratch = min(h, threads) * 32 * (2 * length + k)
    peak = max(resident + max(64 * n, scratch), 3 * p['code_storage_bytes'])
    return dict(protocol='interleaved-' + kind, message_log=log, eta=log-row_log,
                row_log=row_log, queries=q, estimated_proof_bytes=proof,
                estimated_live_bytes=peak, **p)


def codeswitch_candidate(log, row_log, threads):
    p = row_parameters('era-codeswitch', row_log)
    return codeswitch_candidate_from_parameters(log, row_log, threads, p)


@lru_cache(maxsize=None)
def output_distance(output_log, rate_log):
    return math.floor(BF.distance_for_setup_bits(
        FIELD_LOG, 1 << rate_log, output_log, SETUP_BITS) * 1_000_000) / 1_000_000


def codeswitch_candidate_from_parameters(log, row_log, threads, p,
                                        output_log=15, output_log_rate=3, terminal_log=12,
                                        consume_commitment=False):
    """Same proof/memory model with explicitly calibrated row-code parameters."""
    k, n, h = 1 << row_log, 1 << log, 1 << (log-row_log)
    inner_k, inner_n = p['distance_details']['inner_k'], p['distance_details']['inner_n']
    base, length, generator = inner_n**2, p['block_length'], inner_n*inner_k
    if not 0 <= terminal_log < output_log < row_log or not 0 <= output_log_rate <= 5:
        raise ValueError('invalid output or terminal dimensions')
    rate = 1 << output_log_rate
    width = 1 << output_log
    g, m, b, ell = [ceildiv(x, width) for x in (generator, k, base, length)]
    index, online = g + 4*ell, m + b + 2*ell
    rows = index + online
    claims = 2*m + online + 2*b + 2*g + 6*ell
    d = (length-1).bit_length()
    q = query_count(p['distance'], 104)
    terminal_distance = output_distance(output_log, output_log_rate)
    qb = query_count(terminal_distance, 104)
    fields = (3*log + m + online + 1 + b + 4*row_log + 3 + 2*g + m
              + 8 + 16*d + 2*d*(d-1) + 6 + b + 6*ell + 4*output_log + rows)
    proof = (40 + 32 + 32*fields + opening_bytes(length, q, h)
             + basefold_proof_bytes(output_log, output_log_rate, terminal_log, qb, [index, online]))
    setup = (p['code_storage_bytes'] + 32*index*width*(rate+1)
             + 64*rate*width + 64*power_ceiling(rate*width))
    resident = 32*(n + h*length) + 64*power_ceiling(length) + setup
    scratch = min(h, threads)*32*(2*length+k)
    online_live = 32*(online*width*(rate+1) + rows*width + k + base + 3*length)
    # Sum of all fraction-tree layers plus largest GKR's 17 input tables.
    gkr = 32*(16*power_ceiling(length) + 17*power_ceiling(length)//2 + claims*width)
    # Conservative bound: original weights, grouped weights, copied weights,
    # and the copied witness rows coexist during final claim reduction.
    reduction = 32*((3*claims + rows)*width + 3*rate*width)
    peak = resident + max(64*n, scratch, online_live + max(gkr, reduction))
    phases = None
    if consume_commitment:
        # The consumed original commitment is dropped immediately after its
        # column openings, before tensor/GKR checks or final claim reduction.
        original_commitment = 32*h*length + 64*power_ceiling(length)
        # Before those openings, only the initial message IP and online OOD
        # weight tables exist. Include split()'s extra original weight vector,
        # one OOD table, a virtual encoding and a Merkle construction buffer.
        early_scratch = 32*(k + width + 2*rate*width)
        phases = dict(
            commitment=resident+scratch,
            starting_sumcheck=resident+64*n,
            before_original_openings=resident+online_live+32*(m+online)*width+early_scratch,
            after_original_openings=resident-original_commitment+online_live+max(gkr,reduction))
        peak = max(phases.values())
    return dict(protocol='era-codeswitch', message_log=log, eta=log-row_log,
                row_log=row_log, output_log=output_log, output_log_rate=output_log_rate,
                terminal_log=terminal_log, queries=q, terminal_queries=qb,
                terminal_distance=terminal_distance, index_rows=index, online_rows=online,
                estimated_proof_bytes=proof, estimated_live_bytes=peak,
                consume_commitment=consume_commitment, memory_phases_bytes=phases, **p)


def basefold_candidate(log, row_log, threads):
    p = row_parameters('basefold', row_log)
    n, k, h = 1 << log, 1 << row_log, 1 << (log-row_log)
    q = query_count(p['distance'], 104)
    proof = 40 + 96*log + basefold_proof_bytes(row_log, 1, 12, q, [h])
    # Original rows, message, StartingIOR's copy+weights; retain the recursive
    # trees, both code tables, and fold temporaries conservatively as 24*K.
    peak = 32*(5*n + 24*k)
    return dict(protocol='basefold-local', message_log=log, eta=log-row_log,
                row_log=row_log, terminal_log=12, queries=q,
                estimated_proof_bytes=proof, estimated_live_bytes=peak, **p)


def optimize(log, kind, threads, headroom):
    best, candidates, rejected = None, [], []
    lower = 16 if kind == 'era-codeswitch' else 13 if kind == 'basefold-local' else 6
    # Visit likely minima first, allowing a rigorous folded-message lower
    # bound to skip costly checks for unnecessarily large interleaved rows.
    center = round((log + 10) / 2)
    for row_log in sorted(range(lower, log+1), key=lambda r: abs(r-center)):
        if kind == 'era-codeswitch' and row_log % 2:
            continue
        if kind.startswith('interleaved-') and best and 32*(1 << row_log) >= best['estimated_proof_bytes']:
            continue
        try:
            if kind == 'era-codeswitch':
                c = codeswitch_candidate(log, row_log, threads)
            elif kind == 'basefold-local':
                c = basefold_candidate(log, row_log, threads)
            else:
                c = interleaved_candidate(kind.removeprefix('interleaved-'), log, row_log, threads)
        except (ValueError, OverflowError) as error:
            rejected.append(dict(row_log=row_log, reason=str(error)))
            continue
        c['estimated_peak_with_margin_bytes'] = math.ceil(c['estimated_live_bytes']*(1+headroom))
        candidates.append(c)
        if best is None or c['estimated_proof_bytes'] < best['estimated_proof_bytes']:
            best = c
    return dict(best=best, candidates=candidates, rejected=rejected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--logs', nargs='+', type=int, default=[28])
    parser.add_argument('--ram-gib', type=float, default=128)
    parser.add_argument('--headroom', type=float, default=.15)
    parser.add_argument('--threads', type=int, default=16)
    args = parser.parse_args()
    assert args.threads > 0 and 0 <= args.headroom < 1
    assert all(16 <= log <= 31 for log in args.logs)
    groups = dict(interleaved=['interleaved-'+k for k in ['era','basefold','brakedown','ea']],
                  codeswitching=['era-codeswitch','basefold-local'])
    results = {}
    for log in sorted(set(args.logs)):
        results[log] = {}
        for group, kinds in groups.items():
            cases = {}
            for kind in kinds:
                print(f'Optimizing log={log} protocol={kind}', file=sys.stderr, flush=True)
                cases[kind] = optimize(log, kind, args.threads, args.headroom)
            fits = all(c['best'] and c['best']['estimated_peak_with_margin_bytes'] <= args.ram_gib*GIB
                       for c in cases.values())
            results[log][group] = dict(fits=bool(fits), protocols=cases)
    maximum = {group: max((log for log in results if results[log][group]['fits']), default=None)
               for group in groups}
    print(json.dumps(dict(ram_gib=args.ram_gib, threads=args.threads, headroom=args.headroom,
                          scope='Numerical distance assumptions and allocation model; confirm peak RSS on target. '
                                'Optimize eta only, with fixed encoder/output/termination parameters; '
                                'EA retains conjectured distance 0.1. No complete FS soundness certification.',
                          maximum_fitting_log=maximum, results=results), indent=2, allow_nan=False))


if __name__ == '__main__':
    main()
