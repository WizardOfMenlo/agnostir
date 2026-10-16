# Current four-code calibration

The interleaved comparison uses ERA, BaseFold, Brakedown, and EA over the
secp256k1 scalar field, with 65,536 message symbols per row. The GF(2^256)
experiment was reverted at the user's request. Both Bolt variants are omitted from
the comparison. The shared argument retains canonical prime-field proof
transport and BLAKE3 Fiat–Shamir.

`scripts/calibrate_interleaved.py` imports the three audited distance scripts.
Its output is saved in `distance-analysis/current-results.json`. The original
[audit](distance-audit.md) explains the paper-to-script correspondence and
errors found; its benchmark configurations are historical.

EA retains its earlier inverse rate 2, multiplier 18, and distance assumption
0.1 (1,974 queries). This update supplies no new finite-length EA setup
certificate; the 102-bit numerical setup calculations below cover the other
three encoders.

| Encoder | Current change | Result |
| --- | --- | --- |
| BaseFold | Allocate a total 102-bit setup budget across 16 levels, rather than treating a per-level budget as the whole construction's budget. | Per-level lambda 106; numerical distance 0.20106193534326489, rounded down to 0.20106; 927 queries. |
| Brakedown | Check Haböck's sufficient bound at every recursive level and the RS base; use `(cn,dn)=(14,28)` instead of `(10,20)`. | Numerical bound passes for distance 0.1 and a 102-bit total setup budget; 1,974 queries. |
| ERA | Check base distance 0.0009 with the complete Brakedown recursion; use actual row length and a 102-bit CalcDist parameter. | Numerical distance candidate 0.22037045020625684, rounded down to 0.22037; 836 queries. |

The extra two setup bits provide margin relative to the experiment's nominal
100-bit query model. They do not constitute a complete allocation of all
protocol failure events. BaseFold's distance is the symmetric random
foldable-code bound from [BaseFold](https://eprint.iacr.org/2023/1705), rather
than the MDS distance of an additive RS encoder. Brakedown uses
[Ulrich Haböck's analysis](https://eprint.iacr.org/2023/769), as requested.
ERA's calculation follows the local paper's `CalcDist` statement and the
corrected admissible-domain/root handling described in the audit.

Field size is conservatively bounded below by `2^255.999`; Brakedown's
coefficient calculation uses the exact prime modulus. The numerical
Brakedown check is not interval certified, and ERA's root search does not
certify isolation of all critical roots. The setup bounds concern ideal
independent randomness. The fixed public `SmallRng` seed is used only to
reproduce benchmark instances; no statistical or cryptographic setup
guarantee is asserted for that deterministic stream.

The query rule is `ceil(-300/log2(1-delta))`. Its use remains conditional on
the distance/agreement analysis and does not establish the full Fiat–Shamir
security claim. Every measured proof is verified, and proof sizes are actual
serialized bytes. All online stages include their transcript and transport
work. Graph construction and interpolation-table setup are timed separately.

The field-independent batch-inversion optimization in Brakedown's RS base
is retained: it replaces many individual inversions with prefix products and
one inverse per batch, preserving the same interpolation matrix. The setup
ID version changes to bind the stronger Brakedown preset. Default dimensions
are `message-log=22, eta=6`; other row lengths require explicit distance/query
overrides, supplied by the final full-size plan.
The CLI, Criterion list, reproduction loop, README, and paper table all use
the same four encoders.
