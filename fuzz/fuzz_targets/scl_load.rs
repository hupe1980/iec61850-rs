#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use iec61850_rs::model::IedModel;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(xml) = std::str::from_utf8(data) {
        let _ = iec61850_rs::scl::ied_names(xml);
        let _ = IedModel::from_scl(xml, None);
    }
});
