#!/usr/bin/env bash
# The process bus on a real kernel: GOOSE and SV over a veth pair, on the ring and on the plain
# receive path, and the live CLI (`ied mu --iface` into `ied sv monitor --iface`).
#
#   scripts/linux-test.sh            # Linux: builds as you, runs the binaries with sudo
#   scripts/linux-test.sh --docker   # anywhere with Docker: the same inside a Linux container
#
# rawether is a path dependency at ../rawether; the container mounts it there too.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ "${1:-}" == "--docker" ]]; then
    rawether=$(cd ../rawether && pwd -P)
    exec docker run --rm --cap-add NET_ADMIN --cap-add NET_RAW \
        -v "$PWD":/src/iec61850-rs -v "$rawether":/src/rawether -w /src/iec61850-rs \
        -v iec61850-cargo:/usr/local/cargo/registry -v iec61850-target:/target -e CARGO_TARGET_DIR=/target \
        rust:latest bash -c 'command -v ip >/dev/null || { apt-get -qq update && apt-get -qq install -y iproute2 >/dev/null; }; scripts/linux-test.sh --inside'
fi

mode="${1:-}"
run() { if [[ "$mode" == "--inside" ]]; then "$@"; else sudo -E "$@"; fi; }

run ip link add iec0 type veth peer name iec1 2>/dev/null || true
run ip link set iec0 up
run ip link set iec1 up
trap 'run ip link del iec0 2>/dev/null || true' EXIT

json=$(cargo test --features net,goose,sv --test net_link --no-run --message-format=json 2>/dev/null)
bin=$(sed -n 's/.*"executable":"\([^"]*net_link[^"]*\)".*/\1/p' <<<"$json" | tail -1)
[[ -n "$bin" ]] || { echo "could not build tests/net_link.rs" >&2; exit 1; }
cargo build --features cli --bin ied
ied="${CARGO_TARGET_DIR:-target}/debug/ied"

export IEC61850_IFACE=iec0 IEC61850_PEER_IFACE=iec1 IEC61850_IED="$ied"
for rx in ring plain; do
    echo "==> net_link, receive path: $rx"
    run env IEC61850_IFACE=iec0 IEC61850_PEER_IFACE=iec1 IEC61850_IED="$ied" RAWETHER_RX="$rx" "$bin" --test-threads=1
    run env IEC61850_IFACE=iec0 IEC61850_PEER_IFACE=iec1 RAWETHER_RX="$rx" IEC61850_ALLOC_ALONE=1 \
        "$bin" --exact the_live_steady_state_does_not_allocate
done

echo "==> live CLI: ied mu --iface iec0 → ied sv monitor --iface iec1"
out=$(mktemp)
run "$ied" sv monitor --iface iec1 --duration 3 >"$out" 2>&1 &
monitor=$!
sleep 0.5
run "$ied" mu --iface iec0 --profile le80-60 --frames 4800
wait "$monitor"
cat "$out"
grep -q 'frames=4800' "$out" || { echo "the monitor did not see all 4800 frames" >&2; exit 1; }
grep -q 'gaps=0' "$out" || { echo "the monitor saw a gap" >&2; exit 1; }
echo "==> all live tests passed"
