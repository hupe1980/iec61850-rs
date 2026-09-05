#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

//! The MMS association state machine, fed arbitrary bytes in the place of a peer.
//!
//! This is the surface a client actually exposes to a network: everything a server sends
//! arrives here before anything else has looked at it. Both roles are driven, and the bytes
//! are delivered in small chunks so the TPKT reader's partial-header path and the COTP
//! reassembler are exercised on every input rather than only when the fuzzer happens to
//! produce a clean packet boundary.
//!
//! The property is not "it decodes" — most of this input never will. It is that nothing
//! panics, that the machine always either stays usable or reaches `Closed`, and that a
//! closed association never asks to be woken again.

use iec61850_rs::common::Instant;
use iec61850_rs::proto::mms::association::{Association, AssociationConfig, AssociationEvent, State};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    for role in 0..2 {
        let cfg = AssociationConfig { max_tsdu: 64 * 1024, ..AssociationConfig::default() };
        let mut a = if role == 0 { Association::client(cfg) } else { Association::server(cfg) };
        let mut now = Instant::ZERO;
        if role == 0 {
            a.start(now).unwrap();
        }
        while a.poll_transmit().is_some() {}

        // Small chunks: a peer's bytes do not arrive on PDU boundaries, and the reader has
        // to be a state machine over a growing buffer rather than a function over a packet.
        for chunk in data.chunks(7) {
            a.on_bytes(now, chunk);
            now = now.plus_millis(1);
            a.on_timeout(now);
            while a.poll_transmit().is_some() {}
            while let Some(event) = a.poll_event() {
                if let AssociationEvent::Response { pdu, .. } | AssociationEvent::Request { pdu, .. } | AssociationEvent::Unconfirmed { pdu } = event {
                    // Every PDU handed up must decode — the association promised so by
                    // parsing it before it emitted the event.
                    assert!(!pdu.is_empty());
                }
            }
            if a.state() == State::Closed {
                assert_eq!(a.next_timeout(), None, "a closed association must not ask to be woken");
                assert_eq!(a.outstanding(), 0);
                break;
            }
        }
        // Whatever happened, aborting is always safe and always terminal.
        a.abort();
        assert_eq!(a.state(), State::Closed);
        a.on_bytes(now, data);
        a.on_timeout(now);
    }
});
