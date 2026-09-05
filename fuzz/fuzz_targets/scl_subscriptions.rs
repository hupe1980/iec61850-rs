#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use iec61850_rs::scl;
use libfuzzer_sys::fuzz_target;

// Resolving one IED's `Inputs/ExtRef` against the publishers in the same file walks between
// IEDs, so a malformed SCD reaches parts of the loader `scl_load` never touches. Whatever
// comes back must be self-consistent: every subscription must build a usable configuration.
fuzz_target!(|data: &[u8]| {
    let Ok(xml) = core::str::from_utf8(data) else { return };
    let Ok(names) = scl::ied_names(xml) else { return };
    for name in names.iter().take(4) {
        let Ok(subs) = scl::subscriptions(xml, name, 50) else { continue };
        for s in &subs.goose {
            let cfg = s.goose_config();
            assert_eq!(cfg.key.gocb_ref, s.identifier);
            assert_eq!(cfg.expected_conf_rev, Some(s.conf_rev));
        }
        for s in &subs.sv {
            assert!(s.sv_config().samples_per_second > 0, "a stream must have a wrap value");
        }
    }
});
