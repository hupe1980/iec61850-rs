# csp0924's iec61850-* 0.4.0 crates as an interop peer: a probe built against the exact versions
# Cargo.lock records (`--locked`), so a different crate cannot slip in between runs.
FROM rust:1.90-bookworm AS build
WORKDIR /probe
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
COPY --from=build /probe/target/release/csp0924-probe /usr/local/bin/probe
RUN useradd --create-home --uid 10001 peer
USER peer
WORKDIR /home/peer
ENTRYPOINT ["probe"]
CMD ["server", "10102", "/home/peer/model.icd", "IED1"]
