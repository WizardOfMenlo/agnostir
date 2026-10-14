# Bolt-max adapted: local results, 14 October 2026

Same-field all-one sketched code inside the common serialized Fiat-Shamir
interleaved argument. secp256k1 scalar field, BLAKE3-256, N=2^22, eta=6, seed=2025.
Degree 8, compression 8, rate-1/2 BaseFold syndrome code. Unproved assumed kernel
delta=0.013; normalized complete-code delta=0.0104; 19,891 queries.
Apple M2, 16 GiB, Rust 1.92, no explicit CPU flags. Three samples after one warmup.

Eight-worker median times: commit 182.287459 ms, prove 927.058792 ms, verify 255.221709 ms.
Actual proof: 39,119,368 bytes. Public initial root: 32 bytes, excluded.

- `interleaved-bolt-max.csv`: final 8-worker measured samples.
- `interleaved-bolt-max-1.csv`: 1-worker measured samples.
- `summary.json`: medians and ranges for these runs.
- `bolt-max.proof`: verified proof, identical before and after a style-only refactor.
- `thread-32/`: full-size functional run on the same 8-core host, not AWS scaling.
- `bolt-min-regression.csv`: full-size proof matched the prior Bolt-min proof exactly.
- `calibration.json`: separate explicit Bolt-max assumptions and Bolt-min certificate.
- `adaptation-notes.md`: construction, assumptions, measurements, reproduction.
- `source.tar.gz`: source captured before final measurements.
- `source-final.tar.gz`: final documentation updates; same Rust and dependencies.
- `pre-style/`: preliminary samples/source before replacing an if-let with map_or_else;
  these samples are excluded from the paper and final summary.
- `paper-evaluation.tex`, `paper-evaluation.patch`: evaluation source and cumulative patch.
- `paper.pdf`, `paper-table.png`, `paper-parameters.png`: compiled paper and checked revised pages.
- `integration-smoke/`: raw 32-worker artifact-script smoke output.
- `validation.txt`, logs, and `SHA256SUMS`: checks and provenance.

Every proof verified. Full-size 1-, 8-, and 32-worker proof bytes match.
The main artifact script also passes its 32-worker smoke run including both Bolt variants.
This is not the native Bolt PCS, a prime-field distance proof, or a complete
100-bit security certificate. The query budget is explicitly conditional.
