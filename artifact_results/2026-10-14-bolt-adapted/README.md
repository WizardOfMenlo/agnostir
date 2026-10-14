# Bolt-min adapted: local results, 14 October 2026

Same-field sketched code inside the common serialized Fiat–Shamir interleaved argument.
Field: secp256k1 scalar. Hash: BLAKE3-256. N=2^22, eta=6, seed=2025.
Degree 16, compression 8, rate-1/2 BaseFold syndrome code. Conditional delta=0.0448; 4537 queries.
Apple M2, 16 GiB, Rust 1.92, no explicit CPU flags. Three samples after one warmup.

Eight-worker median times: commit 695.659209 ms, prove 902.238167 ms, verify 85.947750 ms.
Actual serialized proof: 11,621,288 bytes. Public initial root: 32 bytes, excluded.

- `interleaved-bolt-min.csv`: 8-worker measured samples.
- `interleaved-bolt-min-1.csv`: 1-worker measured samples.
- `summary.json`: medians and ranges for these two runs.
- `bolt-min.proof`: actual verified byte string.
- `thread-32/`: full-size functional check on the same 8-core host; not an AWS scaling run.
- `calibration.json` and `adaptation-notes.md`: ideal-kernel certificate and conditional outer-code analysis.
- `source.tar.gz`: source captured before measurement.
- `source-final.tar.gz`: final reporting/reproduction changes; Rust and dependency sources are identical to measured sources.
- `paper-evaluation.patch` and `paper-table.png`: cumulative evaluation-section patch and checked table rendering.
- `validation.txt`, logs, and `SHA256SUMS`: validation and provenance.

Every measured proof verified. The 32-worker proof matched the 8-worker proof byte for byte.
This is not the native Bolt code-switching PCS or a certified complete 100-bit security claim.
