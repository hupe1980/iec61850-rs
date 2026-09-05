//! GOOSE (IEC 61850-8-1): the APDU codec, the publisher with its retransmission
//! scheduler, and the subscriber with the IEC 62351-6 replay-protection state machine.
//!
//! Everything here is sans-IO: the publisher yields frames to send and asks to be called
//! back at a time; the subscriber consumes frames and timer ticks and yields events.

mod apdu;
mod publisher;
mod subscriber;

pub use apdu::{GooseHeader, GoosePdu, GoosePduView, TAG_GOOSE_PDU, encode_into};
pub use publisher::{Publisher, PublisherConfig, Retransmission};
pub use subscriber::{FrameDeltas, Invalid, SimulationMode, Subscriber, SubscriberConfig, SubscriberEvent, SubscriberStats, SubscriptionKey};
