//! An IEC 61850 server: the SCL file is the model, and the model is the namespace.
//!
//! There is no registry, no generated configuration file and no build step — [`Ied::from_scl`]
//! is the whole of it. What a client can browse, read and write is exactly what the
//! engineering file says the IED has, so the server cannot drift from its own SCD.
//!
//! Four layers, each testable without the one below it:
//!
//! | | |
//! |---|---|
//! | [`Variable`] / [`Domain`] | the MMS namespace the 8-1 mapping makes of the model — flattened, sorted, and the same tree browse, read and type discovery all walk |
//! | [`Ied`] | that namespace with values behind it, plus the data sets and control blocks |
//! | [`Acsi`] | a request in, an [`Answer`] out. Sans-IO: no socket, no clock, no association |
//! | [`Server`] | the accept loop and one thread per association, over the same [`Association`](crate::proto::mms::association::Association) the client drives in the other role |
//!
//! ```no_run
//! use iec61850_rs::server::{Ied, Server};
//!
//! # fn main() -> iec61850_rs::Result<()> {
//! let server = Server::bind("0.0.0.0:102", Ied::from_scl(&std::fs::read_to_string("relay.cid")?, None)?)?;
//! let updates = server.handle();
//! std::thread::spawn(move || {
//!     updates.txn().set("IED1LD0/PTRC1$ST$Tr$general", iec61850_rs::proto::data::Value::Boolean(true)).commit();
//! });
//! server.run()
//! # }
//! ```

mod acsi;
mod control;
mod files;
mod ied;
mod log;
mod net;
mod rcb;
mod sg;
mod supervision;
mod tracking;
mod tree;

pub use acsi::{Acsi, AcsiConfig, Answer, AssocId, error_class};
pub use control::{ControlEvent, ControlHook, Controls, DEFAULT_SBO_TIMEOUT_MS, Stage, Termination};
#[cfg(feature = "std")]
pub use files::DirectoryStore;
pub use files::{FileInfo, FileStore, NoFiles, is_safe_relative};
pub use ied::{
    Block, BlockKind, DATA_ACCESS_DENIED, DATA_ACCESS_NON_EXISTENT, DATA_ACCESS_TYPE_INCONSISTENT, DATA_ACCESS_VALUE_INVALID, DataSetMember, Ied,
    ServedDataSet, accepts, default_value,
};
pub use log::{DEFAULT_LOG_CAPACITY, Entry, LogBounds, LogStore, Logs, MemoryLog, NewEntry};
pub use net::{Server, ServerConfig, ServerHandle, Txn};
pub use rcb::{DEFAULT_BUFFER, Engine, Outgoing};
pub use sg::SettingGroups;
pub use supervision::SubscriptionStatus;
pub use tracking::Tracking;
pub use tree::{Domain, SEP, VarKind, Variable, split_item, type_of};
