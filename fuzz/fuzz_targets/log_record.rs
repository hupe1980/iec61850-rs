#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use iec61850_rs::server::decode_record;
use libfuzzer_sys::fuzz_target;

// A log file may be corrupted or crafted, so decoding a stored record must never panic or
// allocate by a length the record merely claims.
fuzz_target!(|data: &[u8]| {
    let _ = decode_record(1, data);
});
