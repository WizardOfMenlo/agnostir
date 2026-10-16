# Prepared ASIACRYPT artifact, October 16, 2026

## Current source distribution

The prepared main submission is
`results/submission-20261016/era-codes-artifact-20261016-final.tar.gz`
(1,406,955 bytes; SHA-256
`7ee84ca8693a5a687e4311e5037073df523eaff276358894502f22f1d9cf165a`). All 625 manifest-listed files were verified directly from the
archive. This release is prepared locally and has not been uploaded.

The archive's root `README.md` is generated from `artifact/README.md`; the
repository root README describes the checkout and both final comparisons.
They identify the paper-sized interleaved comparison, the additional 2^28
interleaved results, and the final sparse-base ERA codeswitching comparison
with local recursive BaseFold. They distinguish repository and distribution
paths and prominently link the [AI disclosure](../AI_DISCLOSURE.md).

## Submission contents

The main archive includes source, tests, fixed parameters, compact raw
measurements and provenance, Dockerfile, reproduction commands, MIT license,
dependency notices, AI disclosure, and the supplied paper PDF. The prepared
submission text and metadata are `artifact/submission-form.txt` and
`artifact/submission.json`. The PDF is `artifact/paper.pdf` in the repository
and `paper/paper.pdf` in the distribution; it can also be attached separately
in the submission form. The published artifact deadline was October 15 with
no timezone stated on the requirements page; portal availability has not been
verified. No public submission or committee badge is claimed.

The optional companion archives remain local under `results/submission-20261016/`:

- `era-codes-dependencies-20261016.tar.gz`: pinned Cargo sources, Linux Python
  wheels and license notices; all 12,474 payload files were verified.
- `era-codes-evidence-20261016.tar.gz`: ten full reference proofs, original
  source snapshots and measured binaries; all 18 payload files were verified.

They are conveniences for dependency acquisition and inspection. The main
source package can regenerate the proofs without them. Building requires the
official Rust/Debian base and OS packages even with the dependency archive.

Private `aws-backup.tar.gz` and `container-validation.tar.gz` retain the complete
campaign and container records locally; 280 and 70 payload files, respectively,
were verified. Build caches, private backups, old releases and superseded
experiment payloads are not included in the main source submission.
See [the retention index](repository-layout.md) for their locations and scope.

## Validation and measurement provenance

The native Docker build was validated on the on-demand r7a.4xlarge with runtime
network access disabled. The recorded checks passed 204 parallel and 203 serial
Rust library tests, 18 distance tests, two model tests, and six smoke proofs.
The four paper-sized proofs and two full-size IOPP proofs matched reference
SHA-256 values. These container runs used one warmup and one measured sample.
The four full-size common-interleaved reference rows retain their earlier
native AWS measurements; their paper-sized configurations were rerun in Docker.
See [validation details](../artifact/validation.md).

The original measured source snapshots remain authoritative for timings.
The subsequent ERA naming edit changed crate/import and tuning-variable names
and comments; its tests and proof-identity checks are recorded separately.
Current sources therefore are not claimed to be byte-identical to every
historical measured source. Protocol domain labels and raw records retain
their original identifiers for proof compatibility and provenance.

The final README pass changed documentation, release metadata and packaging
link rewrites only. Scientific sources, dependencies, final parameters,
expected proof hashes and measured evidence are unchanged from the preceding
disclosure release. Validation checked both READMEs' numerical tables against
the saved measurements, local links, shell-command syntax, the 625-file
packaged manifest, saved-evidence summarization, and a dry run selecting exactly
six 2^28 cases with 16 workers, one warmup and one sample. No benchmark was
rerun for this documentation edit. The local receipt is
`results/submission-20261016/final-readme-validation.json`.

The supplied paper is unchanged. Table 3's original configuration is supported;
the older Table 4/Figure 7 analytical estimates are not claimed as reproduced
by current proof bytes. The complete-IOPP baseline is the local recursive
BaseFold implementation. Numerical distance, soundness, and verifier-complexity
qualifications remain in [the scientific limits](../artifact/changes.md).

## Historical source releases

These previous local archives remain immutable; the current submission is the
`-final` archive above. All filenames below are relative to
`results/submission-20261016/`.

| Archive | Bytes | SHA-256 |
| --- | ---: | --- |
| `era-codes-artifact-20261016-original.tar.gz` | 1,390,044 | `c46751503bce0b528814aa15e24621e319c0632abc4c06fbfbeeaf3adea3dfc9` |
| `era-codes-artifact-20261016-cleanup.tar.gz` | 1,398,223 | `7ec6ed54d5c53923ebb3ddcddf8841edc7f070ba66c39599d78ebcf0cfa3475b` |
| `era-codes-artifact-20261016.tar.gz` | 1,398,882 | `8bfb25fee309c593e630cd8080fa42d60d40489e0d0e45ac84db5923e593ce25` |
| `era-codes-artifact-20261016-disclosure.tar.gz` | 1,404,884 | `456fa7eb8a26b2ce3e6fd66a48d9ddb520c442de9475b6d0459d81b811325b12` |

`results/submission-20261016/SHA256SUMS` records all retained release-archive
checksums. Historical filenames were renamed to ERA terminology without
changing their contents. All required AWS results, proofs and source snapshots
are local; reproduction and packaging require no running AWS instance. No
instance termination was issued by the assistant.
