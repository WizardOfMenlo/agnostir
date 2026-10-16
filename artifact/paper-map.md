# Paper-to-artifact map

Paper: `paper/paper.pdf`, the 84-page LLNCS version generated October 16, 2026.
It contains the named authors, main text through page 30, bibliography,
appendices, current repository links, and the updated AWS evaluation.

| Paper location | Artifact component / command | Scope |
| --- | --- | --- |
| Appendix D.1, Table 3, p.65 | `paper22`; `evidence/container-validation/validation/paper22/` | Four encoders at 2^22, AWS Docker, eight workers, one measured sample after one warmup. Exact proof lengths match historical reference proofs. |
| Appendix D.1, Table 4, p.65 | `interleaved28`; `evidence/interleaved28/` | ERA, BaseFold-code, Brakedown, EA at 2^28; sixteen workers, one warmup/sample, saved size-selected interleaving. |
| Appendix D.3, Table 6, p.69 | `codeswitch28`; `evidence/codeswitch28/` | Final ERA versus local recursive BaseFold at 2^28; exact serialized proof lengths and online timings. |
| ERA construction/analysis and CalcDist | `distance-analysis/era.py`; `scripts/calibrate_interleaved.py` | Numerical analysis, not interval-certified all-roots verification. |
| Remark 2, p.30 (second candidate distance) | `distance-analysis/exponent-behavior.ipynb`; instructions in `distance-analysis/README.md` | Original interactive visualization of the permutation exponent; optional Python/Jupyter dependencies. |
| BaseFold distance and Brakedown presets in D.1 | `distance-analysis/basefold.py`, `brakedown.py` | Brakedown uses Ulrich Habock's sufficient-bound analysis, including recursive levels. |
| Appendix B IOPP and Appendix C codeswitching | `src/era_iopp.rs`, `src/proof/fractional.rs`; `codeswitch28` | Implemented transcript, two independent multipliers, batched GKR, then recursive BaseFold. See changes.md. |
| Appendix D.2, Table 5 / Figure 7, pp.67-68 | `proof-size-estimate.py`; `evidence/proof-size-audit/` | Retained analytical estimates with documented omissions/parameter differences. They are distinct from the measured wire format. |

`evidence/paper22/` retains the earlier Apple M2 three-sample measurements for
historical provenance; those timings are not the updated Table 3. The later
Docker full-size IOPP validation under `evidence/container-validation/` is
also separate from the native measurements in Table 6. The measurement groups
are not pooled, and the 2^22 and 2^28 runs use different worker counts.

The artifact evaluates encoders and evaluation arguments, not a complete
zero-knowledge SNARK. It does not measure BrakingBase, Bolt, or an upstream
BaseFold PCS. The analytical estimates remain as presented in the paper;
Appendix D.3 discusses their relationship to the implemented protocol.
