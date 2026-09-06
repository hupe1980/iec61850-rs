//! Types every layer shares: time, quality, object references, MAC addresses, editions,
//! the IEC 61850-7-2 packed option types (`TrgOps`, `OptFlds`, `ReasonCode`), errors and
//! limits, the [`Clock`] trait the application supplies, and the [`EventQueue`] every core
//! hands its events through.

mod edition;
mod error;
mod flags;
mod limits;
mod mac;
mod machine;
mod quality;
mod reference;
mod time;

pub use edition::Edition;
pub use error::{DecodeReason, Error, Result};
pub use flags::{ControlModel, OptFlds, ReasonCode, TrgOps};
pub use limits::Limits;
pub use mac::MacAddr;
#[cfg(feature = "std")]
pub use machine::SystemClock;
pub use machine::{Clock, EventQueue, Instant, ManualClock, Now};
pub use quality::{Quality, Source, Validity};
pub use reference::{Fc, ObjectReference};
pub use time::{EntryTime, TimeQuality, UtcTime};
