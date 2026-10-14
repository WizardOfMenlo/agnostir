FROM rust:1.92-bookworm
WORKDIR /artifact
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY benches ./benches
COPY scripts ./scripts
COPY docs ./docs
COPY distance-analysis/basefold.py ./distance-analysis/basefold.py
COPY README.md AI_DISCLOSURE.md ./
RUN cargo build --locked --release --bins
CMD ["bash", "scripts/reproduce_artifact.sh", "/results/run", "smoke"]
