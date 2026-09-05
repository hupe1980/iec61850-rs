#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use iec61850_rs::common::{Instant, Limits};
use iec61850_rs::proto::ethernet::{Frame, MacAddr};
use iec61850_rs::proto::goose::{GoosePdu, GoosePduView, Subscriber, SubscriberConfig, SubscriptionKey};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(fr) = Frame::parse(data) {
        if let Ok(v) = GoosePduView::parse(fr.apdu) {
            let _ = v.member_count_matches();
            if let Ok(owned) = GoosePdu::from_view(&v, &Limits::DEFAULT) {
                // Decoded → encoded → decoded must agree.
                let bytes = owned.encode().unwrap();
                let again = GoosePduView::parse(&bytes).unwrap();
                assert_eq!(again.st_num, v.st_num);
                assert_eq!(GoosePdu::from_view(&again, &Limits::DEFAULT).unwrap(), owned);
            }
        }
    }
    let mut sub = Subscriber::new(SubscriberConfig::new(SubscriptionKey { dst: MacAddr::GOOSE_BASE, appid: 0, gocb_ref: String::new() }));
    let _ = sub.feed(Instant::ZERO, data);
    sub.on_timeout(Instant::ZERO.plus_millis(1_000_000));
});
