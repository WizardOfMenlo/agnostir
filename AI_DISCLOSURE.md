# AI assistance disclosure

**GPT-6 Astra, accessed through OpenAI Codex, generated or substantially revised
nearly all final project-specific code and original repository content in this
artifact.** This was extensive implementation and content generation, including
this disclosure. The implementation was developed from the **human-written
algorithm descriptions and details in the paper**, together with human-provided
instructions, parameter choices, corrections, and experimental goals.

This document is the artifact's supplementary account of AI use. It is linked
prominently from both reviewer entry points and the submission metadata.
The recorded model designation is **GPT-6 Astra**; a more specific dated model
snapshot is not recorded. The work described here took place in October 2026.

## Scope of assistance

- **Implementation:** encoding routines; interleaved and codeswitching IOPPs;
  the local recursive BaseFold baseline; Fiat-Shamir transcripts; proof
  serialization and parsing; Merkle proofs; sumcheck; GKR; and public-weight
  evaluations. This includes substantial generation and revision of the final
  Rust library, binaries, and benchmarks.
- **Audit and optimization:** comparison of implementations and distance
  calculations with the cited papers; identification and proposed repair of
  implementation and protocol gaps; parameter searches; profiling; memory and
  parallelism changes; and proof-identity checks. AI also suggested corrections
  and parameter choices; its role was not limited to transcribing pseudocode.
  The resulting changes and remaining scientific qualifications are recorded
  in [artifact/changes.md](artifact/changes.md).
- **Validation and experiments:** generation and revision of tests, numerical
  distance scripts, proof-size models, benchmarking and reproduction scripts;
  operation of local and AWS experiments; analysis of logs; and preparation of
  result summaries, tables, and experimental text. The retained benchmark
  numbers are outputs of program executions, not measurements invented by the
  model. Source snapshots, logs, proof hashes, and validation records document
  those executions.
- **Repository and submission materials:** nearly all final original README
  and documentation content, Docker and packaging workflows, dependency and
  provenance records, cleanup, and prepared submission text were generated or
  substantially revised with the same assistance.

This scope statement covers original project material, not authorship of
third-party dependencies or the human-written algorithm descriptions in the
paper. Inherited material and third-party code retain their provenance and
licenses. AI-assisted updates to experimental tables and accompanying text
are included in the scope above; this statement does not attribute the paper's
underlying algorithmic descriptions to the model.

## Prompts and subsequent editing

Inputs included the paper's descriptions and details, the existing repository,
the cited literature, and iterative human instructions. The following are
verbatim substantive prompt excerpts from that workflow, selected to document
the types and extent of assistance. They are not a complete conversation export;
operational credentials and infrastructure identifiers are not reproduced.
Misspellings in the quoted prompts are retained.

> Ascertain that the current interleaved IOPP experiment is correct. I also want to change the proof sizes to be the exact serialized proof sizes from doing fs and everything. Same for prover time and verifier time.

> Implement our new IOPP for ERA codes as described in the paper: feel free to delete the current impl in the repo. Use the current parameters described in the paper and compute its prover times for 2^22 elements and compare it against optimized basefold (implement the optimized basefold by modfiying basefold's plonky3 impl). Make sure that the current IOPP is sound first, if there are any missing steps or mistakes please report them to me, fix them, and implement the fixed IOPP.

> we have 3 scripts for computing distances of basefold, era, and brakedown: can you go through them and validate that they are correctly implementing the computation wrt to the statements in the respective papers? For brakedown use the paper by Ulrich Habock, not the original braekdown paper.

> I believe the 0.1 distance for ea is conjectured in their paper, and it's already bad so we dont need to do anything about it. I think we can now move on to the codeswithcing iopp experiment and comparison with basefold iopp. Can you profile the prover time and the proof size for our codeswitching iopp and find out what the bottlenecks are

> implement the optimizations that would provide the best bang for our buck, and check if the resulting proof is exactly identical to the proof before doing any of these opts. Then rebenchmark the iopp against basefold

> oh i see gkr isnt even the bottleneck itself anymore, go back to uncheckpointed code. What was the profile for the whole iopp when not checkpointed?

> for the interleaved iopp experiment pick an interleaving param that minimizes the estimated proof size, and then run the experiemnet for that size. For codeswitching based iopp do the same

> so we are using the quadratic time encoding for rs codes and that's why it's taking so long right, i think we should use a different parameterization of brakedown which does not require rs invocation: might require you to increase the degree to get a similar distance. I would like to maintain the distance of the final era code to be > 0.2 (you can reverse engineer the required tensor code distance from that and then in turn the required base code distance for brakedown)

> yeah remember that we can codeswitch to basefold and then just basefold's iopp from there on out

> implement the compact weight evaluations for the verifier, make sure the proof is byte-identical. Then also try to optimize the current prover with the new parameterization (probably can optimize gkr in some way) and then rebench and run on aws for size 2^28

> ok can you add the interleaved iopp experiment, what the setup is, what the numbers are, how to reproduce etc to the readme? Dont add anything for the new codeswitching based iopp just yet

> great now are we ready to prepare the final artifact for submission? If so do it and I will termiante the aws instance

> ok can you make another pass of the repo? Feel free to cleanup and potentially delete older experiments and data that are not important for obtaining reproducability

> Great, also make sure we are compliant of the ai tool policy: clarify that GPT6 Astra was used for pretty much all the final code and contents of the repo which implemented the algorithms based on the human-written descriptions and details in the paper

These prompts describe requests, not evidence that every requested property was
achieved. In particular, the final baseline is the local recursive BaseFold
implementation, and the artifact does not claim a complete soundness proof;
see [the recorded qualifications](artifact/changes.md).

Work proceeded through repeated generation, execution, feedback, and revision.
Human feedback changed the field and comparison scope, selected parameters,
rejected checkpointing, requested compact verifier computations and proof
identity checks, and specified the final experiment size and sampling policy.
The AI then revised the code, tests, result summaries, and documentation in
response to that feedback and to compilation, test, and profiling results.
Subsequent editing therefore also involved substantial AI use, rather than
only manual polishing of one initial generated version. Retained snapshots
and validation records identify the tested implementations; this disclosure
does not assert that every final line has received independent human review.

## Responsibility and policy

The human authors retain responsibility for the scientific contributions,
correctness and appropriateness of the code and text, accuracy of reported
results, attribution, remaining limitations, and final submission. AI-generated
audits and passing tests do not establish cryptographic soundness. No AI tool
is listed as an author.

The [ASIACRYPT 2026 artifact requirements](https://asiacrypt.iacr.org/2026/artifacts.php)
require prominent disclosure proportionate to generated content. The linked
[AI Tool Policy](https://asiacrypt.iacr.org/2026/aipolicy.php) calls for a detailed
supplementary account of extensive assistance, including tool identity, prompts,
and subsequent editing, and places responsibility on the authors. These pages
were checked on October 16, 2026. This document describes the artifact's use of
AI; it does not claim committee approval or establish compliance for any
separate manuscript submission.
