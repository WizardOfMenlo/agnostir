#!/usr/bin/env python3
"""Check the selected sparse base, including exact integer Brakedown bounds.

Graph probabilities use Habock (4); coefficient bounds use his nonzero-entry
variant (Section 5.1). ERA's separate scalar maximization remains numerical.
"""
import argparse
from fractions import Fraction
import json
import math
from pathlib import Path

import numpy as np
from scipy.optimize import minimize_scalar
import plan_large_iopp as P


def check(summary):
    chosen = summary['chosen']
    case = chosen['case']
    base = case['base_parameters']
    details = case['distance_details']
    delta = Fraction(str(details['inner_distance']))
    report = chosen['recursive_bound']
    assert base['base_case'] == 'zero-pad' and report['bound_passes']
    assert Fraction(1, chosen['terminal_dimensions'][1]) > delta
    q = P.BD.SECP256K1_SCALAR
    rows = []
    for level in report['levels']:
        length = level['block_length']
        child_n = level['B_dimensions'][0]
        for kind, degree, first, last, target in [
            ('A', base['cn'], 1, math.floor(delta*length), Fraction(0)),
            ('B', base['dn'], math.floor(delta*child_n)+1,
             math.floor(delta*length), delta*(length-child_n)),
        ]:
            n, m = level[kind+'_dimensions']
            count = last-first+1
            bits = report['per_event_bits']+(count-1).bit_length()
            for k in range(first, last+1):
                # Use the same conservative expansion threshold as the search,
                # then check both probability inequalities with exact integers.
                required = (float(target)+(k*math.log2(q)+bits+1e-6
                            +math.log2(math.comb(n,k))+(m if target else 0))
                            /math.log2(q-1))
                b = math.ceil(required)-1
                assert b < m
                graph = Fraction(math.comb(n,k)*math.comb(m,b)*math.comb(b,degree)**k,
                                 math.comb(m,degree)**k)
                exponent = b+1-math.floor(target)
                assert exponent > 0
                coefficients = Fraction(math.comb(n,k)*q**k*(2**m if target else 1),
                                        (q-1)**exponent)
                assert graph <= Fraction(1,2**bits)
                assert coefficients <= Fraction(1,2**bits)
                rows.append(dict(matrix=kind, input=n, output=m, degree=degree,
                                 weight=k, expansion_threshold=b, bits=bits,
                                 graph_passes_exact=True, coefficients_pass_exact=True))
    # Reduce the two-dimensional exponent maximization to one dimension using
    # strict concavity in d1. Sample logarithmically and refine every grid peak.
    model = P.ERA.Exponent(details['c'],4)
    bound = case['distance']
    low, high = details['base_distance'], bound/model.A**2*(1-1e-9)
    def value(d0):
        d1 = model.maximizing_d1(d0,bound)
        return model.value(d0,d1,bound)
    grid = np.geomspace(low,high,2000)
    values = [value(float(x)) for x in grid]
    maxima = [(values[0],float(grid[0])),(values[-1],float(grid[-1]))]
    for i in range(1,len(grid)-1):
        if values[i] >= max(values[i-1],values[i+1]):
            result = minimize_scalar(lambda x:-value(x), bounds=(grid[i-1],grid[i+1]),
                                     method='bounded',options=dict(xatol=1e-14))
            maxima.append((-result.fun,float(result.x)))
    maximum, at = max(maxima)
    assert maximum < -details['gamma']
    assert bound > .2
    return dict(brakedown_exact_checks=rows,setup_bits=report['setup_bits'],
                base_distance=str(delta), terminal_distance='1/'+str(chosen['terminal_dimensions'][1]),
                era_distance=bound, tensor_distance=details['base_distance'],
                exponent_maximum_found=maximum, exponent_maximizer_d0=at,
                required_exponent_upper_bound=-details['gamma'],
                scope='Brakedown rational probability inequalities for the ideal sampler. '
                      'ERA numerical falsification check, not an interval or all-roots certificate.')


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('summary',type=Path)
    parser.add_argument('--eta',type=int,help='validate this fastest-by-row alternative')
    args=parser.parse_args()
    summary=json.loads(args.summary.read_text())
    if args.eta is not None:
        summary['chosen']=next(c for c in summary['fastest_by_row'] if c['case']['eta']==args.eta)
    print(json.dumps(check(summary),indent=2))
