# Parameter and memory planning for the retained experiments

The authoritative plan is [artifact/evaluation-plan.json](../artifact/evaluation-plan.json):
2^28 input elements, 16 Rayon workers, a 112 GiB estimated-memory allowance,
and one warmup plus one measured sample. It targets a 128 GiB Linux host.
The six cases run sequentially. No 2^29 benchmark is part of this artifact.
See [parameters](../artifact/parameters.md) for the selected row dimensions,
code rates, distances, query counts and termination choices.

Inspect all six commands without allocating input vectors:

```sh
python3 -B scripts/run_large_iopp_plan.py artifact/evaluation-plan.json \
  results/planned-run --logs 28 --threads 16 --samples 1 --warmups 1 \
  --memory-budget-gib 112 --profile --dry-run
```

The common-interleaved choices minimize expected wire size over the recorded
row-size range while holding each encoder preset fixed. The ERA codeswitching
choice comes from the subsequent joint search: 64 rows, output length 2^21,
output rate 1/8, and terminal size 2^11. Its sparse Brakedown base avoids RS.
These are finite search results, not a claim of a global optimum.

The memory model takes the maximum over live allocations in each phase.
The consumed ERA commitment is released after its last authenticated opening,
so it need not overlap the whole GKR and terminal BaseFold computation.
Predictions include a 15% margin; measured whole-process peaks are retained
with each timing record. A preflight estimate is not an OS memory limit.

The reusable model is `scripts/plan_large_iopp.py`; its standalone search uses
the earlier fixed-output codeswitch dimensions and is not a replacement for
the final joint-search plan. For the final ERA search methodology and exact
base-distance checks, use [the joint parameter report](era-joint-parameters.md),
`scripts/search_era_base.py`, `scripts/search_era_joint.py`, and
`scripts/check_era_sparse_base.py`. The distance calculations retain their
[numerical qualifications](distance-audit.md).

Earlier 32-worker Spot plans, continuation scripts and 2^29 projections are
archived outside the active experiment tree; see [retention](repository-layout.md).
