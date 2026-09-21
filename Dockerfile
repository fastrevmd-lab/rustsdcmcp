# Security Director Cloud MCP server container image
#
# Multi-stage build producing a distroless image with no shell and no external
# binaries. The runtime has no package manager, no shell, and no GNU userland —
# only libc and the statically-linked server binary.
#
# Builder glibc generation must be ≤ runtime generation: Debian 13 (trixie) on
# both sides satisfies this. Building on a newer base (Debian 14+) would link
# against a newer glibc that the Debian 13 runtime does not carry.

# Builder stage: Debian 13 slim with Rust 1.98
# Pinned to the amd64 digest resolved on 2026-08-25.
FROM rust:1.98-slim-trixie@sha256:bce1476d4be4d78b83705bc5f428b86d640eeeea33e9dadafbc037b5703a53bf AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        pkg-config \
        libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Copy workspace manifests first for better layer caching
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/rustsdcmcp/Cargo.toml crates/rustsdcmcp/
COPY crates/rustsdcmcp-core/Cargo.toml crates/rustsdcmcp-core/

# Create stub main.rs files to cache dependencies
RUN mkdir -p crates/rustsdcmcp/src crates/rustsdcmcp-core/src && \
    echo 'fn main() {}' > crates/rustsdcmcp/src/main.rs && \
    echo '' > crates/rustsdcmcp-core/src/lib.rs && \
    cargo build --release && \
    rm -rf crates/rustsdcmcp/src crates/rustsdcmcp-core/src

# Copy source and build the real binary
COPY crates/ crates/
RUN touch crates/rustsdcmcp/src/main.rs crates/rustsdcmcp-core/src/lib.rs && \
    cargo build --release --locked

# Runtime stage: Distroless Debian 13 with nonroot user
# Pinned to the amd64 digest resolved on 2026-08-24.
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:54df941ed0d06a1bd95ef5e0ce391fd8d9f94b64782dc9a60062727849ee3f97

# Run as nonroot user (UID 65532)
USER 65532:65532

# No HEALTHCHECK: distroless has no shell and no utilities, so there is nothing
# for a healthcheck command to run. Orchestrators supervise the process via the
# container runtime. Suppressed explicitly in .trivyignore.yaml (AVD-DS-0026)
# rather than silently, so the decision is reviewable.

# Copy the server binary
COPY --from=builder /build/target/release/rustsdcmcp /usr/local/bin/rustsdcmcp

# Metadata
LABEL org.opencontainers.image.title="rustsdcmcp"
LABEL org.opencontainers.image.description="Security Director Cloud MCP server"
LABEL org.opencontainers.image.source="https://github.com/fastrevmd-lab/rustsdcmcp"
LABEL org.opencontainers.image.licenses="MIT OR Apache-2.0"

# ENTRYPOINT carries what must always hold: config paths and anything security-
# relevant. CMD carries only what an operator is expected to replace: bind
# address, port, and mode flags. Docker replaces CMD when the caller supplies
# arguments, so security-relevant defaults must stay in ENTRYPOINT.
ENTRYPOINT ["/usr/local/bin/rustsdcmcp", \
    "--device-mapping", "/etc/rustsdcmcp/sdc.json", \
    "--tokens-file", "/var/lib/rustsdcmcp/tokens.json"]
CMD ["--transport", "streamable-http", \
    "--host", "127.0.0.1", \
    "--port", "30032"]
