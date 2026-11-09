#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use iec61850_rs::common::{Instant, Limits};
use iec61850_rs::proto::mms::Mms;
use iec61850_rs::proto::mms::file::FileNameBuf;
use iec61850_rs::server::{FileError, FileWriter, Obtains};
use libfuzzer_sys::fuzz_target;

/// A writer that keeps nothing but a bounded count, as a store with a limit would.
struct Counting(u64);

impl FileWriter for Counting {
    fn expect(&mut self, size: u32) -> Result<(), FileError> {
        if size > 1 << 20 { Err(FileError::TooLarge) } else { Ok(()) }
    }
    fn write(&mut self, chunk: &[u8]) -> Result<(), FileError> {
        self.0 += chunk.len() as u64;
        if self.0 > 1 << 20 { Err(FileError::TooLarge) } else { Ok(()) }
    }
    fn commit(self: Box<Self>) -> Result<(), FileError> {
        Ok(())
    }
}

// A client answering a server's FileOpen/FileRead/FileClose with whatever it likes: the transfer
// may fail, but the engine must never panic, never answer an ObtainFile twice, and always end.
fuzz_target!(|data: &[u8]| {
    let mut engine = Obtains::new(2, 1000);
    engine.start(1, FileNameBuf::from_path("source").unwrap(), Box::new(Counting(0)), Instant(0));
    engine.bind(1, 7);
    let mut answered = 0;
    let mut invoke = 0;
    let mut rest = data;
    while let Some((&len, tail)) = rest.split_first() {
        let (pdu, next) = tail.split_at(usize::from(len).min(tail.len()));
        rest = next;
        if engine.next_call(1).is_some() {
            invoke += 1;
            engine.issued(1, invoke);
        }
        let done = match Mms::parse(pdu, &Limits::DEFAULT) {
            Ok(mms) => engine.on_response(1, invoke, &mms),
            Err(_) => engine.failed(1, Some(invoke)),
        };
        if done.is_some() {
            answered += 1;
        }
    }
    answered += engine.on_timeout(Instant(0).plus_millis(1000)).len();
    assert!(answered <= 1, "an ObtainFile answered {answered} times");
    assert!(engine.is_empty(), "a transfer survived its deadline");
});
