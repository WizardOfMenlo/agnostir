# Paper-to-artifact map

Paper: `paper/paper.pdf`, 77 pages, supplied PDF generated October 14, 2026.
It retains anonymous review formatting; author metadata is recorded separately
from the paper's TeX source in submission.json. Its scientific text was not
silently rewritten during artifact packaging.

| Paper location | Artifact component / command | Scope |
| --- | --- | --- |
| Appendix D.1, Table 3, p.63 | `paper22`; `evidence/paper22/` | Same four encoders, field, hash, query counts, row dimensions and serializer. Historical M2 medians of three samples retained; new runs default to one sample. |
| ERA construction/analysis and CalcDist | `distance-analysis/era.py`; `scripts/calibrate_interleaved.py` | Numerical analysis, not interval-certified all-roots verification. |
| BaseFold distance and Brakedown preset choices in D.1 | `distance-analysis/basefold.py`, `brakedown.py` | Brakedown uses Ulrich Habock's sufficient-bound analysis, including recursive levels. |
| Appendix B IOPP and Appendix C codeswitching | `src/era_iopp.rs`, `src/proof/fractional.rs`; `codeswitch28` | Implemented corrected transcript, two independent multipliers, batched GKR, then recursive BaseFold. See changes.md. |
| Appendix D.2, Table 4, Figure 7, pp.63-65 | `proof-size-estimate.py`; `evidence/proof-size-audit/` | Historical analytical estimates with documented omissions/parameter differences. Not measured proof sizes and not claimed as reproduced by the current implementation. |
| Additional 2^28 common-interleaved experiment | `interleaved28`; `evidence/interleaved28/` | ERA, BaseFold-code, Brakedown, EA; each uses its saved size-selected interleaving. |
| Additional 2^28 full IOPP comparison | `codeswitch28`; `evidence/codeswitch28/` | Latest ERA versus local recursive BaseFold; exact proof lengths and online timings. |

The artifact does not implement a complete zero-knowledge SNARK. It evaluates
encoders and evaluation arguments. It does not measure BrakingBase, Bolt, or
an upstream BaseFold PCS. The full-size additional measurements are not a
replacement for an author-reviewed revision of the paper's old estimates.
