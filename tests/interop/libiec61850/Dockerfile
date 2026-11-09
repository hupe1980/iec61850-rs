# libiec61850, the interop peer for both buses: its MMS clients and servers, its log and file
# clients, and its GOOSE and SV publishers and subscribers. Pinned to a release and checked by
# SHA-256 before a byte of it is compiled; built for whichever architecture Docker runs on.
FROM debian:bookworm-slim AS build
ARG LIBIEC61850_VERSION=1.6.2.1
ARG LIBIEC61850_SHA256=a0c970b00ccd8dd1145c2a7f5369a58ea0916cc2dbcbcbfe9ba0975e72afb514
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential ca-certificates curl libsqlite3-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN curl -fsSL -o libiec61850.tar.gz \
      "https://codeload.github.com/mz-automation/libiec61850/tar.gz/refs/tags/v${LIBIEC61850_VERSION}" \
 && echo "${LIBIEC61850_SHA256}  libiec61850.tar.gz" | sha256sum -c - \
 && tar -xzf libiec61850.tar.gz \
 && mv "libiec61850-${LIBIEC61850_VERSION}" libiec61850
# `make examples` walks the example list only; the log client, the file tool and the logging
# server (which needs SQLite) are built by name, and any one that fails fails the build.
RUN make -C libiec61850 -j"$(nproc)" examples \
 && for d in server_example_logging iec61850_client_example_log iec61850_client_example_files server_example_goose; do \
      make -C "libiec61850/examples/$d" || exit 1; \
    done

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends libcap2-bin libsqlite3-0 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/libiec61850/examples /opt/libiec61850/examples
COPY --from=build /src/libiec61850/tools/model_generator_dotnet/Tools/ICDFiles /opt/libiec61850/tools/model_generator_dotnet/Tools/ICDFiles
# The process-bus tools need a raw socket. They get it as a file capability, so they run as the
# unprivileged user like everything else; the container is never privileged. The capabilities
# are set after `chown`, which would clear them.
RUN useradd --create-home --uid 10001 peer \
 && chown -R peer /opt/libiec61850/examples \
 && for b in goose_publisher/goose_publisher_example goose_subscriber/goose_subscriber_example \
             sv_publisher/sv_publisher sv_subscriber/sv_subscriber \
             server_example_goose/server_example_goose; do \
      setcap cap_net_raw,cap_net_admin+ep "/opt/libiec61850/examples/$b" || exit 1; \
    done
USER peer
WORKDIR /opt/libiec61850
CMD ["sleep", "infinity"]
