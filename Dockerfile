# Immutable official Rust 1.92.0/bookworm image.
FROM rust:1.92.0-bookworm@sha256:e90e846de4124376164ddfbaab4b0774c7bdeef5e738866295e5a90a34a307a2
ARG RUSTFLAGS=""
ENV RUSTFLAGS=${RUSTFLAGS} PYTHONDONTWRITEBYTECODE=1
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv \
    && rm -rf /var/lib/apt/lists/* && python3 -m venv /opt/analysis
ENV PATH="/opt/analysis/bin:${PATH}"
WORKDIR /artifact
COPY . .
# Optional dependency archive: extract at the artifact root before building.
RUN if [ -d dependencies/wheels ]; then \
      python -m pip install --no-index --find-links dependencies/wheels -r requirements-analysis.txt; \
    else python -m pip install --no-cache-dir -r requirements-analysis.txt; fi
RUN if [ -d dependencies/vendor ]; then \
      mkdir -p .cargo && cp dependencies/cargo-config.toml .cargo/config.toml; \
    fi \
    && cargo build --locked --release --bin interleaved_iopp --bin compare_iopps \
    && cargo test --release --locked --lib --no-run \
    && cargo test --release --locked --lib --no-default-features --no-run \
    && rustc -Vv > artifact/container-compiler.txt \
    && python -m pip freeze > artifact/container-python.txt \
    && dpkg-query -W > artifact/container-system-packages.txt
ENTRYPOINT ["bash", "artifact/run.sh"]
CMD ["smoke", "/results/smoke"]
