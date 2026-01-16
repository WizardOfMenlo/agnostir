# Repository Guidelines

## Project Structure & Module Organization

- `src/lib.rs` contains the core error-correcting code implementations and unit tests.
- `src/bin/main.rs` is a standalone binary used for timing/experiments.
- `benches/era_encode.rs` holds Criterion benchmarks.
- `target/` is build output and should not be edited manually.

## Build, Test, and Development Commands

- `cargo build` compiles the library and default binary.
- `cargo run --bin main` runs the experimental encoder binary.
- `cargo test` runs unit tests in `src/lib.rs`.
- `cargo bench` runs Criterion benchmarks in `benches/`.
- `cargo clippy` runs linting; this crate enables strict Rust + Clippy lints in `Cargo.toml`.

## Coding Style & Naming Conventions

- Follow standard Rust formatting; use `cargo fmt` before committing.
- Prefer clear, descriptive names for algorithmic steps (see `encode_naive`).
- Keep public APIs in `src/lib.rs` and keep binaries small and purpose-specific.
- Rust edition is 2024; toolchain should support `rust-version = "1.91"`.

## Testing Guidelines

- Unit tests live in `src/lib.rs` under `#[cfg(test)]` modules.
- Use `#[test]` for deterministic checks; keep tests fast and focused.
- For property tests, `proptest` is available in dev-dependencies.

## Commit & Pull Request Guidelines

- Commit messages in history are short and terse (e.g., `add benches`, `ckpt`); keep them brief and action-oriented.
- Pull requests should include a clear summary, test commands run, and any benchmark notes if performance changes are expected.

## Configuration Notes

- Default features include `parallel` and `cli`; disable with `--no-default-features` if needed.
- Several dependencies are pinned to a specific Plonky3 git revision; update carefully and note in PRs.
