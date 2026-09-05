#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use iec61850_rs::ber::Cursor;
use iec61850_rs::common::Limits;
use iec61850_rs::proto::data::{decode_all, Value};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut c = Cursor::new(data);
    while let Some(Ok(t)) = c.next() {
        let _ = (t.integer_i64(), t.unsigned_u64(), t.boolean(), t.bit_string(), t.visible_string(), t.floating_point(), t.utc_time());
    }
    if let Ok(values) = decode_all(data, &Limits::DEFAULT) {
        let bytes = Value::encode_all(&values).unwrap();
        let again = decode_all(&bytes, &Limits::DEFAULT).unwrap();
        assert_eq!(again.len(), values.len());
    }
});
