"""Numerical implementation of the ERA draft's CalcDist figure.

This checks equations and feasibility; it is NOT an interval-arithmetic proof
that all solutions of the Hessian system have been found. n and q arguments
are log2(block length) and log2(field size), respectively.
"""

import argparse
import math
from functools import lru_cache

import numpy as np
from scipy.optimize import brentq, root
from scipy.special import expit, logit, xlogy


def entropy(x):
    if not np.isfinite(x) or not 0 <= x <= 1:
        raise ValueError("entropy argument outside [0, 1]")
    return -(xlogy(x, x) + xlogy(1-x, 1-x)) / math.log(2)


def entropy_prime(x):
    if not 0 < x < 1:
        raise ValueError("entropy derivative requires 0 < x < 1")
    return (math.log1p(-x) - math.log(x)) / math.log(2)


def entropy_second(x):
    if not 0 < x < 1:
        raise ValueError("entropy second derivative requires 0 < x < 1")
    return -1 / (x * (1-x) * math.log(2))


class Exponent:
    """E_perm/n in eq:event-4-exp-term, with its analytic gradient/Hessian."""

    def __init__(self, c, r):
        if not (isinstance(r, (int, np.integer)) and r >= 4 and
                math.isfinite(c) and 1 < c < r/2*(1-1/math.sqrt(5))):
            raise ValueError("CalcDist requires integer r>=4 and 1<c<r/2*(1-1/sqrt(5))")
        self.r, self.A, self.B = r, 1-c/r, c/r
        self.constant = self.A * entropy(self.B/self.A)

    def arguments(self, d0, d1, delta):
        A, B = self.A, self.B
        if not (0 < d0 < 1 and d0*A < d1 < 1 and d1*A < delta < A*A):
            raise ValueError("weights outside the interior feasible domain")
        args = (d0*A/d1, d0*B/(1-d1), d1*A/delta, d1*B/(1-delta))
        if not all(0 < x < 1 for x in args):
            raise ValueError("infeasible entropy ratio")
        return args

    def value(self, d0, d1, delta):
        x, y, u, v = self.arguments(d0, d1, delta)
        return ((1/self.r-1)*entropy(d0) + (d0+d1)*self.constant
                + d1*entropy(x) + (1-d1)*entropy(y)
                + delta*entropy(u) + (1-delta)*entropy(v) - entropy(d1))

    def derivatives(self, d0, d1, delta):
        x, y, u, v = self.arguments(d0, d1, delta)
        A, B = self.A, self.B
        p, pp = entropy_prime, entropy_second
        e0 = (1/self.r-1)*p(d0) + self.constant + A*p(x) + B*p(y)
        e1 = (-math.log1p(-x)+math.log1p(-y))/math.log(2) + self.constant + A*p(u)+B*p(v)-p(d1)
        e00 = (1/self.r-1)*pp(d0)+A*A/d1*pp(x)+B*B/(1-d1)*pp(y)
        e11 = x*x/d1*pp(x)+y*y/(1-d1)*pp(y)+A*A/delta*pp(u)+B*B/(1-delta)*pp(v)-pp(d1)
        e01 = (-x*x*pp(x)+y*y*pp(y))/d0
        return np.array([e0, e1]), np.array([[e00, e01], [e01, e11]])

    def maximizing_d1(self, d0, delta):
        # E is strictly concave in d1. Its derivative has opposite infinite
        # limits at d0*A and delta/A; bracket the unique interior maximum.
        lo, hi = d0*self.A, delta/self.A
        gap = hi-lo
        if gap <= 0:
            raise ValueError("empty d1 interval")
        margin = max(gap*1e-11, 8*math.ulp(hi))
        a, b = lo+margin, hi-margin
        if a >= b:
            raise ValueError("d1 interval is too narrow for float64")
        return brentq(lambda d1: self.derivatives(d0, d1, delta)[0][1], a, b,
                      xtol=1e-14, rtol=1e-14)


def _validate_inputs(r, secparam, db, n_log, q_log=None):
    if not isinstance(r, (int, np.integer)) or r < 4:
        raise ValueError("r must be an integer >=4")
    if not math.isfinite(secparam) or secparam <= 0 or not 0 < db < 1:
        raise ValueError("positive security and 0<base distance<1 required")
    if not math.isfinite(n_log) or not 0 <= n_log <= 1000:
        raise ValueError("invalid log2 block length")
    if q_log is not None and (not math.isfinite(q_log) or q_log <= 1):
        raise ValueError("log2 field size must exceed one")


def field_bound_log2(c, r, secparam, db, n_log):
    """Log2 of the right side of CalcDist step 1 (a bound on q-1)."""
    alpha = 1 - (c/(math.e*r))**(c/r)
    return (-math.log2(db) + (r-r*alpha+1+c*alpha)*math.log2(math.e)
            + c*alpha*math.log2(r/c) - (r-r*alpha)*math.log2(1-alpha)
            + r*(2*secparam+4+4*n_log)/(db*2**n_log)) / (c-1)


def compute_c_from_q_bound(r, secparam, db, n_lower_bound, q_lower_bound):
    _validate_inputs(r, secparam, db, n_lower_bound, q_lower_bound)
    # Figure 1 equates q_min - 1, NOT q_min, to its RHS.
    target = q_lower_bound + math.log1p(-2.0**(-q_lower_bound))/math.log(2)
    lower = math.nextafter(1.0, math.inf)
    upper = math.nextafter(r/2*(1-1/math.sqrt(5)), 1.0)
    fun = lambda c: field_bound_log2(c, r, secparam, db, n_lower_bound)-target
    if fun(upper) >= 0:
        return None
    c = brentq(fun, lower, upper, xtol=5e-15, rtol=1e-14)
    if abs(fun(c)) > 1e-8 * max(1, abs(target)):
        return None
    # Round toward the feasible (larger c) side, then check the inequality.
    c = math.nextafter(c, upper)
    for _ in range(128):
        if fun(c) <= 0:
            return c
        c = math.nextafter(c, upper)
    return None


def compute_gamma_from_n_bound(r, c, secparam, n_lower_bound):
    _validate_inputs(r, secparam, 0.5, n_lower_bound)
    Exponent(c, r)
    n = 2**n_lower_bound
    return (secparam+1+math.log2(c*c*(r-c)**3/r**5)+7*math.log2(n+1))/n


@lru_cache(maxsize=256)
def critical_delta(c, r):
    """Step 4: smallest admissible root FOUND, not an all-roots certificate."""
    exponent = Exponent(c, r)
    A = exponent.A

    def unpack(z):
        # Interior parameterization prevents evaluating fictitious clipped
        # entropy values outside the weight polytope.
        s0, s1, s2 = expit(z)
        delta = A*A*s2
        d1 = delta/A*s1
        d0 = d1/A*s0
        return d0, d1, delta

    def equations(z):
        try:
            with np.errstate(over='raise', invalid='raise', divide='raise'):
                d0, d1, delta = unpack(z)
                grad, hessian = exponent.derivatives(d0, d1, delta)
                # det(H)=0 iff H11-H01^2/H00=0; scaling avoids huge determinants.
                schur = hessian[1, 1]-hessian[0, 1]**2/hessian[0, 0]
                return [grad[0], grad[1], schur*d1]
        except (ValueError, ZeroDivisionError, FloatingPointError):
            return [1e6, 1e6, 1e6]

    candidates = []
    for s0 in (0.03, 0.15, 0.5):
        for s1 in (0.08, 0.3, 0.7):
            for s2 in (0.15, 0.4, 0.7, 0.9):
                result = root(equations, logit([s0, s1, s2]), method='hybr', tol=1e-10)
                if not result.success or not np.all(np.isfinite(result.x)):
                    continue
                point = unpack(result.x)
                try:
                    with np.errstate(over='raise', invalid='raise', divide='raise'):
                        grad, hessian = exponent.derivatives(*point)
                except (ValueError, FloatingPointError, ZeroDivisionError):
                    continue
                if not np.all(np.isfinite(grad)) or not np.all(np.isfinite(hessian)):
                    continue
                det = np.linalg.det(hessian)
                scale = max(1, abs(hessian[0, 0]*hessian[1, 1]), hessian[0, 1]**2)
                if np.max(np.abs(grad)) < 1e-8 and abs(det)/scale < 1e-9:
                    candidates.append(point)
    if not candidates:
        return None
    return min(candidates, key=lambda point: point[2])


def solve_details(c, r, gamma, db):
    exponent = Exponent(c, r)
    if not (0 < gamma < db < 1):
        raise ValueError("the ERA theorem requires 0<gamma<base distance<1")
    A = exponent.A

    def boundary_value(delta):
        d1 = exponent.maximizing_d1(db, delta)
        return gamma+exponent.value(db, d1, delta)

    lower, upper = db*A*A*(1+1e-5), A*A*(1-1e-8)
    try:
        delta1 = brentq(boundary_value, lower, upper, xtol=1e-13, rtol=1e-13)
    except ValueError:
        return None
    d1 = exponent.maximizing_d1(db, delta1)
    if abs(boundary_value(delta1)) > 1e-9:
        return None
    critical = critical_delta(c, r)
    if critical is None:
        return None
    return {"delta": min(delta1, critical[2]), "delta1": delta1,
            "d1_at_delta1": d1, "delta2": critical[2],
            "critical_point": list(critical),
            "scope": "numerical CalcDist candidate; no certified all-roots isolation"}


def solve_system(c, r, gamma, db):
    """Compatibility API; return None if either root computation fails."""
    result = solve_details(c, r, gamma, db)
    return None if result is None else result['delta']


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-n', type=float, default=20, help='log2 of minimum ERA block length')
    parser.add_argument('-q', type=float, default=192, help='lower bound on log2 field size')
    parser.add_argument('-secparam', type=int, default=100)
    parser.add_argument('-r', type=int, required=True)
    parser.add_argument('-db', type=float, required=True, help='separately justified base-code distance')
    args = parser.parse_args()
    try:
        c = compute_c_from_q_bound(args.r, args.secparam, args.db, args.n, args.q)
        if c is None:
            raise ValueError('no feasible c satisfies the field-size bound')
        gamma = compute_gamma_from_n_bound(args.r, c, args.secparam, args.n)
        result = solve_details(c, args.r, gamma, args.db)
        if result is None:
            raise ValueError('failed to find and validate both CalcDist roots')
    except (ValueError, OverflowError) as error:
        parser.error(str(error))
    import json
    print(json.dumps({'c': c, 'gamma': gamma, **result}, indent=2))
