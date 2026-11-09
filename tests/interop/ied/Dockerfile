# This crate's own side of the process-bus interop: a Linux toolchain that builds `ied` from the
# repository, which the test mounts read-only, into a cached target volume, and runs it on the
# test's Docker network. It runs as root inside the container because it owns raw sockets and
# writes the build cache; the container is unprivileged (NET_RAW and NET_ADMIN only) and never
# sees the host network or the Docker socket.
FROM rust:1.90-bookworm
ENV CARGO_TARGET_DIR=/target
WORKDIR /src/iec61850-rs
CMD ["sleep", "infinity"]
