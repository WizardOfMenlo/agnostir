# Container validation

The native Docker configuration was tested on the same on-demand AWS
r7a.4xlarge used for the additional reference measurements, on October 16,
2026. It used the digest-pinned Rust 1.92.0 / Debian bookworm base,
`RUSTFLAGS=-C target-cpu=native`, the vendored locked Cargo dependencies,
and Linux CPython 3.11 NumPy/SciPy wheels. Runtime networking was disabled.
The portable default compiler configuration is supplied, but the timed
container validation used the explicit native build command in the README.

The smoke and paper-sized modes used 8 CPU capacity and an 8 GiB memory cap.
The full-size pair used 16 CPU capacity, 16 Rayon workers, and a 120 GiB cap.
Every benchmark used one warmup and one measured sample.

Checks performed:

- 204 Rust library tests with default features; 203 without default features.
- 18 numerical distance tests and two planning-model tests.
- Calibration and six reduced-size smoke proofs, all accepted.
- Four 2^22 common-interleaved proofs, all accepted and byte-identical by
  SHA-256 to their historical reference files.
- The two 2^28 IOPP proofs, both accepted and SHA-256-identical to their
  previous full-size references.

This validates the packaged commands and proof identity. The original four
2^28 common-interleaved measurements were retained from native AWS runs;
they were not rerun at full size inside Docker. Their paper-sized
configurations were rerun in the container. The main reference table keeps
the earlier measurements separate from this container validation.

## Full-size container results

| IOPP | Commit s | Evaluation s | Total prover s | Verify ms | Proof bytes | Peak GiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| era-corrected | 26.187 | 57.627 | 83.814 | 38.381 | 3,622,568 | 87.129 |
| basefold-local | 18.820 | 18.660 | 37.480 | 56.416 | 6,004,040 | 44.277 |

Raw validation CSVs, profiles, test/build logs, environment data, and proof
hashes are in `evidence/container-validation/`. All 70 files of the complete
container validation record were downloaded and hash-verified before the
instance was released to the user. The separate local backup also preserves
the four completed AWS campaigns, their proofs, original source snapshots,
and measured binaries (280 files verified).

At initial packaging, all 50 Rust source files matched the previously
measured optimized implementation; see the naming update below for later edits. Packaging adds the MIT license and Cargo
license metadata, the Docker workflow, reviewer scripts, and documentation.
The timed container binaries used this MIT Cargo metadata. Documentation and
license inventories finalized after validation do not change the binaries.

## Repository cleanup follow-up

The later cleanup leaves scientific Rust source and final parameters unchanged.
It removes superseded launchers and duplicate payloads, aligns the generic
runner defaults with 16 workers and 112 GiB, and makes the proof-size audit's
input local to its script. Small reruns also retain source snapshots, including
uncommitted files, and final manifests cover all generated validation records. The refreshed source package is validated separately
by checksum, dry-run command inspection and the audit reproduction. The AWS
Docker measurements above are preserved rather than rerun for these file and
Python tooling changes.

Local follow-up passed the same 204/203 Rust and 18+2 Python tests, all six
smoke proofs, a 480-file source-snapshot check, the six-case dry run, and exact
reproduction of the saved proof-size audit from the package. The check receipt
is `artifact/cleanup-validation.json`.

## Naming update

The active Cargo package, Rust imports, tuning-variable names, documentation,
image tags and release filenames now use ERA terminology. Historical domain
labels and raw evidence are retained to preserve proof compatibility and
provenance. Thus source-file hashes after this naming update differ from the
measured snapshot where imports or tuning-variable names changed; the protocol,
parameters and serializer are unchanged. The original AWS timings continue to
refer to their retained measured snapshots, not a new AWS run.

Renaming validation passed 204 default-feature and 203 serial library tests,
18 distance tests, two model tests, six smoke proofs, direct byte comparison
of the two IOPP smoke proofs before/after renaming, and SHA-256 identity for
all four paper-sized 2^22 proofs. Each benchmark used one warmup and one
sample. See `artifact/naming-validation.json` for the receipt.

## AI disclosure update

The subsequent disclosure release identifies GPT-6 Astra through OpenAI Codex
and its role in nearly all final original artifact code and content, based on
the paper's human-written algorithm descriptions. Prominent README notices,
submission metadata, and the supplementary scope/prompt/revision account were
updated. This update changes documentation and a packaging link rewrite only;
scientific sources, dependencies, parameters, measured evidence, and expected
proof hashes are unchanged from the naming release. It introduces no new
benchmark or test-result claims.

## Final README consistency pass

The final README revision describes both maintained experiments, distinguishes
the paper-sized and full-size results, labels superseded campaign measurements,
and lists the main and optional submission contents. Repository and distribution
paths are distinguished explicitly. The documented full-size plan, timing and
proof-size tables, README links, and packaged evidence commands are checked
against the retained records. This is a documentation update; scientific
sources, parameters, expected proof hashes and measured CSVs remain unchanged.
