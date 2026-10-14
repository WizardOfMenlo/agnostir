# Paper and implementation consistency audit

Audit date: 2026-10-05. The paper source reviewed was the sibling repository
`../AgnosSTIR`, branch `main`, commit `215312d` (`fix links`). Its tracked files
were clean; `table.txt` was untracked. The Rust baseline was commit `f50d2d3`,
followed by the current uncommitted experiment cleanup. No paper or estimator
source was changed for this audit.

The paper's main file is `AgnosSTIR/agnostir.tex`. It selects the short LLNCS
version (`\fullfalse`, line 6) and includes `sections/iopp.tex`,
`sections/codeswitching.tex`, and `sections/evaluation.tex` at lines 264–266.
Paper paths below refer to that optional sibling checkout. Implementation links
refer to this repository.

## What the experiments establish

The paper explicitly separates the measured interleaved experiment
(`sections/evaluation.tex:25–29,38–118`) from estimates for the custom IOPP
(`sections/evaluation.tex:167–251`). This distinction agrees with the repository:
the [interleaved protocol](../src/interleaved_iopp.rs) has prover and verifier
functions, while [custom codeswitching](../src/codeswitching/codeswitch_claims.rs)
contains witness/oracle and claim-generation scaffolding. The
[Python estimator](../proof-size-estimate.py) models the optimized custom
protocol's proof size; it does not run its prover or verifier.

The interleaved experiment proves a random multilinear evaluation interactively.
It supplies verifier randomness externally and has no Fiat–Shamir transcript.
Distance values used to choose query counts are assumed parameters, not a
certificate of the sampled code's distance or setup failure probability.

## Interleaved experiment discrepancies

| Issue | Paper evidence | Implementation evidence and interpretation |
|---|---|---|
| Final evaluation is written over the encoded word. | `sections/evaluation.tex:60` checks the multilinear extension of the encoded folded word at the remaining message coordinates. | The final check must evaluate the **folded message**, as implemented by `verify` in [interleaved_iopp.rs](../src/interleaved_iopp.rs). The paper's encoded-word expression is inconsistent with the stated evaluation claim and dimensions. |
| BaseFold prose and table use different distances. | `sections/evaluation.tex:74` states distance 0.224; its row at line 112 uses 869 queries for message exponent 22 and interleaving exponent 6. | The segment exponent is 16. The old `benches/iopp_params.rs` at `f50d2d3`, and current `CodeKind::assumed_distance` in [iopp_experiment.rs](../src/iopp_experiment.rs), use distance 0.213 there, yielding 869 queries. Distance 0.224 yields 820. The table agrees with the segment-16 parameter; the prose does not. |
| ERA prose and table describe different parameter choices. | `sections/evaluation.tex:76–77` states base inverse rate 1.1, total inverse rate 4.4, and distance 0.226; line 113 uses 804 queries. | The baseline benchmark and current shared setup use Brakedown parameters `(alpha=0.04, inverse_rate=1.05, cn=5, dn=42)`, repetition 4, and assumed distance 0.228 at segment exponent 16. The nominal total inverse rate is about 4.2, with exact lengths determined by the encoder. Distance 0.228 yields 804 queries; 0.226 yields 812. |
| Reported proof size uses an analytical Merkle compression model. | The ERA row at `sections/evaluation.tex:113` reports 3894.3 KiB. | The baseline size function used a shared-path estimate with fractional depth `log2(block_length)`, while the actual proof sends independent full authentication paths. The paper number should be described as an estimate, not serialized or transmitted bytes. |
| Timing table combines runs. | `sections/evaluation.tex:110–114` contains the same rows as `bench_logs/iopp_noea_joined_with_prev_ea.tex:24–28`. | The saved table's caption at line 31 explicitly says the EA row was reused from the latest full run. These timings have provenance, but they are not all from one uniform rerun. The logs do not establish every detail of the historical environment. |

The query model is consistent across the paper and code:

```text
q(delta) = ceil(-3 * 100 / log2(1 - delta)).
```

For the current ERA setup at message exponent 22, interleaving exponent 6,
804 queries, and a padded Merkle depth of 19, the proof contains:

```text
field elements = 1 + 2^16 + 804 * 2^6 = 116993
hashes         = 804 * 19              = 15276
payload        = (116993 + 15276) * 32 / 1024
               = 4133.40625 KiB
```

This counts the claimed evaluation, folded message, opened columns, and all
independent paths at 32 bytes per field element/hash. It excludes the public
root, evaluation point, verifier indices, and serialization framing. It is an
in-memory proof-component count, not a wire-format measurement. The current
[demo](../src/bin/interleaved_iopp.rs) and [benchmark](../benches/iopp_bench.rs)
report this count separately from the shared-path estimate.

The cleanup also changes the analytical comparison model: the shared-path
estimate now uses the padded integer Merkle depth. At the same dimensions it
gives approximately **3915.986 KiB**. This deliberate rounding change should not
be mistaken for reproduction of the paper's historical **3894.3 KiB**. Applying
the old fractional-depth model to the current inverse-rate-1.05 setup gives
approximately **3892.6 KiB**, so the exact historical table value also does not
follow from the current setup alone. Merkle path compression remains
unimplemented.

The paper specifies eight Rayon threads (`sections/evaluation.tex:33`), but the
baseline benchmark did not pin the pool size itself. The cleanup's
[reproduction script](../scripts/reproduce_interleaved.sh) defaults to eight
threads, chunk length 8192, and seed 2025. It runs all five encoder choices at
`(message_log, eta)=(18,4)` and `(22,6)`, and preserves configuration metadata,
logs, and Criterion outputs. The benchmark prints the active thread count,
seed, message/interleaving exponents, and chunk length. Fresh runs remain
necessary for fresh timing claims.

The initial `f50d2d3` benchmark had lost its BaseFold cases even though the paper
and historical logs included them. The cleanup restores BaseFold and shares
encoder setup and distance/query parameters between the CLI and benchmark in
[iopp_experiment.rs](../src/iopp_experiment.rs). This restores experiment
coverage; it does not retrospectively certify the saved timings.

## Custom analytical estimate: matching formulas and a different search space

The current estimator agrees with the paper's optimized communication formula
(`sections/codeswitching.tex:350–360`), its two oracle stack heights
(`sections/codeswitching.tex:315–318`), and the query formula. In particular:

- Indexer stack height: `ell_g + 3 * ell_ERA`.
- Online stack height: `ell_msg + ell_CodeB + 2 * ell_ERA`.
- Non-oracle field elements:
  `(2*ceil(log2(n_ERA))+1)*ceil(log2(n_ERA)) + 5*ell_msg + 4*ell_g + 4*ell_CodeB + 20*ell_ERA + 8 + 3*log2(k0) + 4*log2(k_prime)`.

The constants `ERA_DB=0.0001`, inner inverse-rate factor `1.21`, and repetition 4
agree with the paper's tensor base code made from an inner code of distance 0.01
and inverse rate 1.1 (`sections/evaluation.tex:175`). Squaring these inner-code
parameters gives distance 0.0001 and inverse rate 1.21.

There are two concrete search-scope differences:

1. `sections/iopp.tex:52–53` requires strictly decreasing ERA message lengths and
   a strictly smaller final-code message length. The estimator's
   `generate_k_exponent_sequences` uses combinations with replacement and
   permits equality. Its saved best result at total message length `2^32`
   therefore selects ERA `k0=2^26` and BaseFold `k_prime=2^26`, whereas the paper
   selects `k_prime=2^25` (`sections/evaluation.tex:199`). The equal-length
   candidate lies outside the paper's stated composition constraints; this
   audit does not conclude whether the theorem can be generalized to it.
2. `sections/evaluation.tex:180–181,234` says the search optimizes the terminating
   message length. The estimator takes one configurable `--final-message-exp`
   value (default 12) and does not automatically search over it. Saved results
   thus establish the best candidate within a fixed termination-size search.

A direct calculation using the current cached distances and closed-form cost
functions, without rerunning the optimizer or distance solvers, gives:

| Configuration at total message length `2^32` | Field elements | Hashes | Size, decimal KB | Total evaluation oracle elements |
|---|---:|---:|---:|---:|
| Paper custom parameters: `eta=64`, ERA `k0=2^26`, `r=4`, BaseFold `k_prime=2^25`, inverse rate 8, termination `2^12` | 72,418 | 53,011 | 4,013.728 | 16,106,061,824 |
| Current saved optimizer candidate: same parameters except `k_prime=2^26` | 68,366 | 56,911 | 4,008.864 | 17,179,803,648 |
| Optimized BaseFold baseline: `eta=32`, message `2^27`, inverse rate 2, termination `2^12` | 82,233 | 225,472 | 9,846.560 | 536,854,528 |

The first row reproduces the paper's custom totals **exactly**
(`sections/evaluation.tex:207–222`), and the third reproduces its baseline
(`sections/evaluation.tex:236`). The paper's approximately 4.014 MB custom result
is correct for its stated parameters. Its difference from the saved 4.008864 MB
result is explained by the optimizer's non-strict size constraint, not by stale
paper arithmetic. These are decimal KB/MB; the interleaved runtime tables use
binary KiB.

The local sweep Markdown/CSV/TeX and k32 TeX report retain older estimator
numbers than the latest result text and detailed k32 Markdown. Those local
artifact versions should not be mixed. The current BaseFold cost uses two
queried field elements per round, agreeing with
`sections/evaluation.tex:219–220`.

## Custom implementation gaps relative to the optimized paper

These differences describe unfinished protocol work, separate from the
analytical estimator's matching cost formulas:

- The paper's basic permutation argument uses inverse witnesses
  `1/(alpha^2 + alpha*pi + word)` (`figures/CodeswitchClaims.tex:58–60`). Its
  optimized argument uses batched logUp-GKR fractional sumchecks without
  additional permutation witness oracles (`sections/codeswitching.tex:243–271`).
  Rust instead constructs affine factors `alpha-(word+beta*pi)` and placeholder
  prefix products in `build_first_permute_witness_vectors`, with an explicit
  replacement TODO ([codeswitch_claims.rs](../src/codeswitching/codeswitch_claims.rs)).
  Its [transition sumcheck](../src/codeswitching/sumcheck/permutation.rs) processes
  these witnesses; it is not the paper's complete permutation argument. Passing
  helper tests does not validate the paper's soundness or optimized costs.
- Rust's [oracle builder](../src/codeswitching/oracles.rs) emits generator,
  identity, two permutation, and two multiplier families. The optimized paper
  emits generator, two permutations, and one multiplier family
  (`figures/CodeswitchOracles.tex:4–13`). The current API therefore materializes
  more families than the estimator's optimized indexer stack.
- The paper emulates repeat and accumulation oracles and retains only the
  base-code and two permutation words online
  (`sections/codeswitching.tex:151–198`). Rust materializes and split-encodes ERA,
  multiplication, accumulation, and permutation-witness intermediates. Avoid
  treating its returned vectors as the paper's optimized transmitted proof.
- Rust requires exact chunk divisibility and power-of-two intermediate lengths;
  the estimate uses rounded stack counts for rate-derived lengths. Padding and
  general shapes still need an implementation contract.
- The paper composes `StartingIOR`, `Reduce`, and a terminal IOPP
  (`sections/iopp.tex:79–84`). The Rust helpers do not yet provide that complete
  composition, an independent custom verifier, or the optimized final proof
  transport. The BaseFold encoder used in the interleaved benchmark is not a
  recursive implementation of BaseFold's terminal IOPP.

The sibling paper was read only. None of these findings were automatically
applied to its TeX, result tables, or figure files.
