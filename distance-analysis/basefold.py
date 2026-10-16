"""BaseFold RFC distance bound, CRYPTO 2024 §1.3 and Theorem 2.

q is log2(|F|), c is inverse rate, d is the number of doublings, k0=1.
The theorem's lambda is PER LEVEL: setup failure is at most d*2**(-lambda).
This is the symmetric RFC construction (t, -t), requiring odd characteristic;
field size alone does not make this bound applicable to a binary variant.
These are ideal-ensemble bounds, not certificates for a fixed seeded code.
"""

import argparse
import math


def compute_formula(q, c, d, lam):
    """Return the published §1.3 bound with per-level failure 2**(-lam).

    The recurrence is t_i = 2*t_(i-1) +
      (2*log2(n_(i-1)) + lam + 2.002*t_(i-1) + 0.6*n_i)/(q-1.001).
    Normalizing by n_i gives exactly the closed form formerly used here.
    The printed Theorem 2 has an indexing/logarithm typo; §1.3 and the
    n_(d-1)^2 factor in the full proof (Eq. 26) give this recurrence.
    """
    if not math.isfinite(q) or q < 10:
        raise ValueError("Theorem 2 requires log2(|F|) >= 10")
    if not math.isfinite(c) or c < 1 or not float(c).is_integer():
        raise ValueError("with k0=1, inverse rate c must be a positive integer")
    if not isinstance(d, int) or d < 0:
        raise ValueError("d must be a nonnegative integer")
    if not math.isfinite(lam) or lam <= 0:
        raise ValueError("per-level lambda must be positive and finite")
    zero_fraction = 1 / c
    n = c
    for _ in range(d):
        zero_fraction = (q * zero_fraction + 0.6 + (2 * math.log2(n) + lam) / (2 * n)) / (q - 1.001)
        n *= 2
    return max(0.0, 1 - zero_fraction)


def distance_for_setup_bits(q, c, d, setup_bits):
    """Allocate the union bound over all d random levels explicitly."""
    if not isinstance(d, int) or d < 0:
        raise ValueError("d must be a nonnegative integer")
    if not math.isfinite(setup_bits) or setup_bits <= 0:
        raise ValueError("setup_bits must be positive and finite")
    lam = math.ceil(setup_bits + math.log2(max(1, d)))
    return compute_formula(q, c, d, lam)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("q", type=float, help="lower bound on log2(|F|)")
    parser.add_argument("c", type=int, help="inverse rate, with base message length k0=1")
    parser.add_argument("d", type=int, help="log2(message length)")
    budget = parser.add_mutually_exclusive_group()
    budget.add_argument("--lam", type=float, help="per-level lambda (legacy semantics)")
    budget.add_argument("--setup-bits", type=float, help="total setup budget (default: 100)")
    args = parser.parse_args()
    try:
        lam = args.lam
        if lam is None:
            bits = args.setup_bits if args.setup_bits is not None else 100
            result = distance_for_setup_bits(args.q, args.c, args.d, bits)
            lam = math.ceil(bits + math.log2(max(1, args.d)))
        else:
            result = compute_formula(args.q, args.c, args.d, lam)
    except (ValueError, OverflowError) as error:
        parser.error(str(error))
    print(f"Numerical ideal-ensemble distance bound: {result:.15g}")
    print(f"Per-level lambda: {lam}; setup failure <= {args.d} * 2^(-{lam})")
