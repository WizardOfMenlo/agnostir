# Distance-script audit — 14 October 2026

> The current four-encoder benchmark applies the audit corrections; see the
> [README](../README.md) and [current calibration](prime-experiment.md).

The three distance scripts have been checked against their source analyses and
repaired. Their output evaluates sufficient bounds for ideal random ensembles;
it does not measure the minimum distance of a sampled code. ERA's nonlinear
calculation remains numerical, without certified isolation of every root.

This report records the audit before applying its corrections to the benchmark.
Its historical calculations use the secp256k1 scalar field. The current
benchmark applies the corrected presets and retains that field; the binary-field
proposal below is not part of the comparison.

## Sources and correspondence

| Script | Primary reference | Calculation checked |
| --- | --- | --- |
| [basefold.py](../distance-analysis/basefold.py) | [BaseFold, CRYPTO 2024](https://link.springer.com/content/pdf/10.1007/978-3-031-68403-6_5.pdf), §1.3, Definitions 5–6, Theorem 2; [full version](https://eprint.iacr.org/2023/1705) | RFC distance recurrence and union over recursive levels. |
| [brakedown.py](../distance-analysis/brakedown.py) | [Ulrich Haböck, *Brakedown's expander code*](https://eprint.iacr.org/2023/769), §§4–5 | Graph bound (4), coefficient bounds (10), (15), convexity argument, and §5.1's nonzero-coefficient correction. |
| [era.py](../distance-analysis/era.py) | ERA draft, `figures/era-compute-delta.tex`, `sections/era-analysis/era-perms.tex`, `era-main.tex`, `era-calc-delta.tex` | `CalcDist`, exponent `eq:event-4-exp-term`, its derivatives, and the admissible domain. |

The ERA files are in the sibling paper checkout. The Brakedown
reference here is Haböck's analysis, as requested, rather than the original
Brakedown paper.

## What was correct and what changed

### BaseFold

The original closed-form arithmetic matches the paper's §1.3 expression for
`k0=1`. Rewriting it as a recurrence does not change that formula. The security
interpretation needed correction: Theorem 2 bounds setup failure by
`d * 2^-lambda`, where `d` is the number of levels. A per-level `lambda=100`
therefore gives only 96 bits for `d=16`.

The CLI now defaults to a total setup budget and allocates
`lambda = ceil(setup_bits + log2(d))`. The compatibility function
`compute_formula` and explicit `--lam` retain their per-level meaning.
Domain checks reject invalid parameters; vacuous distance bounds return zero.

The printed Theorem 2 has an apparent indexing/logarithm typo in its `ell_i`
display. The implemented recurrence follows §1.3 and the `n_(d-1)^2` factor in
equation (26) of the full proof, rather than that inconsistent display.

### Brakedown

The core graph and entropy formulas were substantially correct. The surrounding
search and parameter handling could produce unjustified answers:

- The CLI and helper defaults used different field sizes. They now consistently
  use the actual secp256k1 scalar modulus, with an explicit field-order override.
- The small-weight search skipped the degree-one singleton case. It now checks it.
- Impossible graph degrees and unsuccessful searches could be treated like a
  zero-probability event or a zero-degree requirement. They now raise errors.
- The recursion budget used a fractional depth estimate, and an inclusive B
  support interval was undercounted. Integer recursion and support counts are
  now explicit, with allocation across `4*K` events: A/B, graph/coefficients,
  at each of `K` random levels.
- Nonzero coefficients require Haböck §5.1's `q-1` correction. Both coefficient
  counting and the nonzero sampling denominator are now distinguished.

`--cn/--dn` now checks **every integer support weight at every recursive level**,
including the actual rounded dimensions and RS stopping rule in the Rust code.
The standalone degree search still describes the root level only. The
`alpha_range` helper is explicitly labeled a §4 uniform-coefficient diagnostic;
it is not itself a certificate for the nonzero-coefficient ensemble.

For the existing `(alpha, inverse_rate, cn, dn)=(0.3,2,10,20)` preset at message
length 65,536, the sufficient bound passes the top four levels but fails at
message lengths 531 and 160. **This does not prove that the sampled code has
bad distance.** It means the displayed target is not justified by this check.
Degrees `(14,28)` pass the same numerical check for distance 0.1 and a 100-bit
setup budget. Those degrees have not been installed or benchmarked. Earlier
RS termination or degrees selected per level are other possible repairs.

### ERA

The exponent, gradient, and Hessian were correctly transcribed. The original
solver nevertheless clipped invalid entropy arguments, did not adequately
validate the field-equation root, used `q` where the figure says `q-1`, and
could mishandle a missing second root. Its search did not establish that the
first solution found had the smallest admissible distance.

The replacement brackets the field equation and the first distance root,
enforces `0 < gamma < base_distance`, parameterizes the second system inside
its feasible domain, uses multiple initial points, and checks residuals and
the Hessian determinant. Either missing root makes the calculation fail.
It returns the smallest admissible second root **found**, without claiming
an exhaustive root certificate. Valid historical roots agree to at least
10 decimal places; finite differences independently check the derivatives.

For the implemented ERA base preset `(0.04,1.05,5,42)`, the recursive Brakedown
check justifies base distance 0.0009 at a 102-bit setup allocation. This is a
sufficient choice, not a maximum: the current induction discards some extra
distance available from its RS child. At ERA block length 275,248 and repetition
4, it gives `c=1.08900711573781`, `gamma=0.000815131100964`,
`delta1=0.247181414361224`, and `delta2=0.220370450206257`.
The previous distance 0.228 is not certified by this calculation; this audit
does not prove it false.

Two apparent draft transcription errors were also identified in
`era-calc-delta.tex`: the first displayed domain has `ell0/A` where the
subsequent domain uses `ell0*A`, and a later display has `E <= gamma*n`
instead of `E <= -gamma*n`. The paper source has not been edited.

## Recalibrations for the existing prime-field experiment

These are analytical inputs, **not newly measured proof sizes or timings**.
Query counts use the existing conditional model
`ceil(-300/log2(1-delta))`; the setup allocations alone do not establish a
complete 100-bit IOPP bound.

| Code | Audited numerical result | Conditional queries | Qualification |
| --- | ---: | ---: | --- |
| BaseFold | 0.205204645670459 | 906 | Total setup budget 100; 16 levels, per-level lambda 104. Legacy lambda 100 gives 0.213490066324848. |
| Brakedown | Target 0.1 | 1,974 | Current degrees fail the sufficient check; candidate degrees 14/28 pass. |
| ERA | Candidate 0.220370450206257 | 836 | Base distance 0.0009; 102-bit base and CalcDist allocations; numerical root search. |
| Adapted Bolt-min | 0.0434858481753831 | 4,678 | Existing finite kernel bound, with outer BaseFold recalibrated to total setup budget 102. |
| Adapted Bolt-max | No established prime-field transfer | — | Its previous 0.0104 remains an assumption for the saved prime-field measurements. |

Exact inputs, recursive results, and numerical outputs are in
[audit-results.json](../distance-analysis/audit-results.json). Existing
calibration scripts using `compute_formula(..., lambda)` retain its legacy
per-level semantics and should not be interpreted as a total setup allocation.

## Bolt and the proposed GF(2^256) field

The primary source is [*Bolt: Faster SNARKs from Sketched Codes*, §§6–8](https://link.springer.com/content/pdf/10.1007/978-3-032-35424-2_14.pdf).
Its kernel-distance targets are 0.013 for Bolt-max's binary matrix and 0.0941
for Bolt-min's GF(2^32) weighted matrix. These are kernel distances, not the
complete sketched-code distances.

**Field extension preserves the minimum distance of a fixed linear code
exactly.** To see this, expand an extension-field kernel vector in a basis over
the original field. Each coefficient vector lies in the original kernel, and
at least one is nonzero with support contained in the extension-field vector's
support. The reverse inequality follows by embedding original codewords.

Consequently, the kernel guarantees transfer to GF(2^256) if:

- Bolt-max keeps its binary matrix and the ensemble covered by the analysis.
- Bolt-min keeps its GF(2^32) coefficients, embedded into the subfield of
  GF(2^256). Uniformly resampling coefficients from the larger field is a
  different ensemble and is not justified by this extension argument.

With compression 1/8 and a rate-1/2 outer RS code, normalization gives full-code
bounds 0.0104 for max and 0.07528 for min. More generally, the bound is
`min(kernel_distance/1.25, outer_distance/5)`. Our current BaseFold outer code
limits Bolt-min, so its full RS-based distance cannot simply replace the old
table entry.

Two issues remain independent of field extension:

1. Bolt §6.1 analyzes Gallager's strip ensemble. Our current max sampler uses
   configuration-model socket matching. The construction must match the
   analyzed ensemble before that theorem is applied.
2. The paper's asymptotic high-probability statement is not a 100-bit setup
   guarantee at our row length. In the unexpurgated Gallager ensemble, fix two
   columns sharing a check in the first strip. They collide in all seven other
   strips with probability `(63/65535)^7`, approximately `2^-70.16`. This alone
   creates a weight-two kernel word, below the target distance. Thus even this
   one event rules out a 100-bit bad-setup guarantee for that unconditioned
   sampler. The paper's Remark 4 proposes expurgating weight-two words; a full
   finite-length analysis is still required after doing so.

The audit also evaluates Bolt's weighted-ensemble exponent at the published
target 0.0941. Its numerical minimum is negative at `log2(q)=32`, but positive
at `log2(q)=255.999`. This is a failure to certify the target by that calculation,
not evidence that every larger-field code has worse distance. Retaining the
GF(2^32) matrix and extending scalars avoids this issue.

### BaseFold compatibility

BaseFold's general foldable-code definition supports arbitrary finite fields:
the two interpolation points must be distinct. Its concrete symmetric RFC
construction, also used here, chooses `t` and `-t`. They coincide in
characteristic 2. The current distance script therefore cannot certify a
binary replacement merely by setting `q=256`.

A characteristic-2 BaseFold adaptation exists in
[Diamond–Posen, *Polylogarithmic Proofs for Multilinears over Binary Towers*](https://eprint.iacr.org/2024/504).
The framework is not the obstacle; the encoder and applicable distance analysis
must be chosen consistently. The shared harness also needs binary-field
serialization/challenge sampling, distinct RS evaluation points, and sumcheck
interpolation without division by 2 or 6. No field migration or new timings
are claimed by this audit.

## Reproduction and checks

From the repository root, with `requirements-analysis.txt` installed:

```bash
python3 -B -m unittest discover -s distance-analysis -v
python3 -B scripts/audit_distances.py > /tmp/era-codes-distance-audit.json
diff -u distance-analysis/audit-results.json /tmp/era-codes-distance-audit.json
python3 -B distance-analysis/basefold.py 255.999 2 16 --setup-bits 100
python3 -B distance-analysis/brakedown.py .3 .2 2 -n 16 --cn 14 --dn 28
```

Using `--cn 10 --dn 20` in the last command deliberately exits nonzero and
reports the failing recursive levels. Float64 output can vary in its final
digits across SciPy/platform versions. The saved run used Python 3.14,
NumPy 2.4.1, and SciPy 1.17.0.

The 16 tests cover independent high-precision BaseFold evaluation, a tiny
exhaustively enumerated graph, recursion and budget accounting, search failure
paths, analytic derivative checks, and an independent numerical ERA domain
search. These tests catch implementation errors; they do not replace the
remaining global-root, finite-length, sampling-distribution, or protocol
soundness proofs.
