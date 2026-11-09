//! GOOSE and Sampled Values on a live interface (feature `net`).
//!
//! A [`Link`] is a raw Ethernet socket on one interface with the process-bus presets: the
//! GOOSE (`0x88B8`) and SV (`0x88BA`) `EtherTypes`, VLAN-tagged or not, and either the multicast
//! groups a subscriber was configured with or the IEC 61850 multicast ranges
//! (01-0C-CD-01-xx for GOOSE, 01-0C-CD-04-xx for SV). Both are checked **in the kernel**, so a
//! frame the cores would ignore never reaches user space. The sockets themselves are
//! [`rawether`]'s: `AF_PACKET` with a `TPACKET_V3` ring on Linux, BPF devices on macOS and FreeBSD.
//!
//! The cores stay sans-IO: a link hands out frames with the monotonic [`Instant`] they were
//! received at, which is what the subscribers' timers run on, and takes frames the publishers
//! built. The kernel's (or the NIC's) receive timestamp travels beside it as [`WireTime`] for
//! latency measurement and never drives a state machine.
//!
//! ```no_run
//! # #[cfg(feature = "goose")]
//! # fn main() -> iec61850_rs::Result<()> {
//! use std::time::Duration;
//! use iec61850_rs::net::{Link, LinkOptions};
//! use iec61850_rs::proto::goose::{Subscriber, SubscriberConfig, SubscriptionKey};
//!
//! let key = SubscriptionKey { dst: iec61850_rs::MacAddr::parse("01-0C-CD-01-00-05")?, appid: 5, gocb_ref: "IED1LD0/LLN0$GO$gcbTrip".into() };
//! let mut link = Link::open("eth0", &LinkOptions::goose().join(key.dst))?;
//! iec61850_rs::net::drop_capabilities()?; // CAP_NET_RAW is not needed any more
//! let mut sub = Subscriber::new(SubscriberConfig::new(key));
//! loop {
//!     if let Some(rx) = link.recv(Some(Duration::from_millis(10)))? {
//!         sub.on_frame(rx.at, rx.frame);
//!     }
//!     sub.on_timeout(iec61850_rs::common::monotonic_now());
//!     while let Some(event) = sub.poll_event() {
//!         println!("{event:?}");
//!     }
//! }
//! # }
//! # #[cfg(not(feature = "goose"))] fn main() {}
//! ```
//!
//! Opening a link needs `CAP_NET_RAW` on Linux — grant it to the binary
//! (`setcap cap_net_raw+ep`) rather than running as root — or access to `/dev/bpf*` on macOS.

// "EtherType" is the IEEE term, not an identifier.
#![allow(clippy::doc_markdown)]

mod filter;

use alloc::string::String;
use alloc::vec::Vec;
use std::time::Duration;

pub use rawether::{RingConfig, RxMode as Receive, RxPath, TxErrors as LaunchErrors};

use crate::common::{Error, Instant, MacAddr, Result, monotonic_now};

/// The GOOSE EtherType.
pub const ETHERTYPE_GOOSE: u16 = 0x88B8;
/// The Sampled Values EtherType.
pub const ETHERTYPE_SV: u16 = 0x88BA;
/// The first four octets of every GOOSE multicast address (IEC 61850-8-1 Annex B).
pub const GOOSE_MULTICAST_PREFIX: [u8; 4] = [0x01, 0x0C, 0xCD, 0x01];
/// The first four octets of every SV multicast address (IEC 61850-9-2).
pub const SV_MULTICAST_PREFIX: [u8; 4] = [0x01, 0x0C, 0xCD, 0x04];
/// The default VLAN priority for GOOSE and SV (IEC 61850-8-1, IEC 61850-9-2): 4. Linux maps
/// `SO_PRIORITY` to the tag's PCP through the VLAN device's egress map.
pub const DEFAULT_PRIORITY: u32 = 4;

/// How a [`Link`] is opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkOptions {
    ethertypes: Vec<u16>,
    join: Vec<MacAddr>,
    prefixes: Vec<[u8; 4]>,
    promiscuous: bool,
    priority: Option<u32>,
    launch_time: bool,
    hardware_timestamps: bool,
    receive: Receive,
}

impl LinkOptions {
    fn with(ethertypes: &[u16], prefixes: &[[u8; 4]]) -> LinkOptions {
        LinkOptions {
            ethertypes: ethertypes.to_vec(),
            join: Vec::new(),
            prefixes: prefixes.to_vec(),
            promiscuous: false,
            priority: Some(DEFAULT_PRIORITY),
            launch_time: false,
            hardware_timestamps: false,
            receive: Receive::Auto,
        }
    }

    /// GOOSE: EtherType 0x88B8 to the GOOSE multicast range, unless groups are joined.
    pub fn goose() -> LinkOptions {
        LinkOptions::with(&[ETHERTYPE_GOOSE], &[GOOSE_MULTICAST_PREFIX])
    }

    /// SV: EtherType 0x88BA to the SV multicast range, unless groups are joined.
    pub fn sv() -> LinkOptions {
        LinkOptions::with(&[ETHERTYPE_SV], &[SV_MULTICAST_PREFIX])
    }

    /// GOOSE and SV together.
    pub fn process_bus() -> LinkOptions {
        LinkOptions::with(&[ETHERTYPE_GOOSE, ETHERTYPE_SV], &[GOOSE_MULTICAST_PREFIX, SV_MULTICAST_PREFIX])
    }

    /// Receive only frames to `group` (and any other group joined): the socket joins it, and the
    /// kernel filter admits exactly the joined groups instead of the whole range.
    #[must_use]
    pub fn join(mut self, group: MacAddr) -> LinkOptions {
        if !self.join.contains(&group) {
            self.join.push(group);
        }
        self
    }

    /// Put the interface into promiscuous mode — only for monitoring a port mirror; the kernel
    /// filter still applies. Off by default.
    #[must_use]
    pub fn promiscuous(mut self, on: bool) -> LinkOptions {
        self.promiscuous = on;
        self
    }

    /// `SO_PRIORITY` for frames sent (default [`DEFAULT_PRIORITY`]); `None` leaves the socket's.
    #[must_use]
    pub fn priority(mut self, priority: Option<u32>) -> LinkOptions {
        self.priority = priority;
        self
    }

    /// Send with launch times ([`Link::send_at`]): Linux `SO_TXTIME` on `CLOCK_TAI`, which needs
    /// an `etf` or `taprio` qdisc on the interface.
    #[must_use]
    pub fn launch_time(mut self, on: bool) -> LinkOptions {
        self.launch_time = on;
        self
    }

    /// Ask the NIC for receive timestamps (falls back to the kernel's, and says so).
    #[must_use]
    pub fn hardware_timestamps(mut self, on: bool) -> LinkOptions {
        self.hardware_timestamps = on;
        self
    }

    /// How frames reach user space; [`Receive::Plain`] has the lowest latency, the ring the
    /// fewest system calls.
    #[must_use]
    pub fn receive(mut self, receive: Receive) -> LinkOptions {
        self.receive = receive;
        self
    }
}

/// When the kernel or the NIC saw a received frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireTime {
    /// Seconds on the stamping clock (the Unix epoch for kernel stamps).
    pub secs: i64,
    /// Nanoseconds within the second.
    pub nanos: u32,
    /// Whether the NIC stamped it (on its own clock) rather than the kernel.
    pub hardware: bool,
}

/// One received frame.
#[derive(Debug)]
pub struct Received<'a> {
    /// The frame as it was on the wire, destination first (a VLAN tag the driver stripped is
    /// put back).
    pub frame: &'a [u8],
    /// When it was received, on the monotonic clock the cores run on.
    pub at: Instant,
    /// The kernel's or the NIC's timestamp, where there is one.
    pub wire_time: Option<WireTime>,
    /// Whether the frame was longer than what was captured. A truncated frame is not decodable
    /// and should be counted, not fed to a decoder.
    pub truncated: bool,
}

/// Frames a link has seen and lost.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkStats {
    /// Frames that passed the filter.
    pub received: u64,
    /// Frames that passed the filter and were dropped because the socket could not keep up.
    pub dropped: u64,
}

/// A raw Ethernet link for the process bus.
#[derive(Debug)]
pub struct Link {
    sock: rawether::Socket,
    mac: MacAddr,
    /// `CLOCK_TAI − monotonic`, in nanoseconds, for launch times.
    tai_offset: Option<i128>,
}

fn io(e: &std::io::Error) -> Error {
    Error::Io(alloc::format!("{e}"))
}

impl Link {
    /// Open a link on `iface`.
    pub fn open(iface: &str, options: &LinkOptions) -> Result<Link> {
        let destinations = if options.join.is_empty() {
            filter::Destinations::Prefixes(options.prefixes.clone())
        } else {
            filter::Destinations::Exactly(options.join.clone())
        };
        let program = filter::program(&options.ethertypes, &destinations)?;
        let mut cfg = rawether::Config::new(iface)
            .filter(rawether::Filter::Bpf(program))
            .rx_mode(options.receive)
            .promiscuous(options.promiscuous)
            .timestamping(if options.hardware_timestamps { rawether::Timestamping::Hardware } else { rawether::Timestamping::Software });
        if options.join.is_empty() {
            // The ranges are not joinable as groups; all-multicast admits them and the kernel
            // filter keeps everything else out.
            cfg = cfg.all_multicast(true);
        }
        for g in &options.join {
            cfg = cfg.join(rawether::MacAddr(g.0));
        }
        if let Some(p) = options.priority {
            cfg = cfg.priority(p);
        }
        if options.launch_time {
            cfg = cfg.tx_time(rawether::TxTime { clock: rawether::Clock::Tai, deadline: false, report_errors: true });
        }
        let sock = cfg.open().map_err(|e| io(&e))?;
        let mac = MacAddr(sock.mac_address().0);
        let tai_offset = if options.launch_time {
            let tai = rawether::clock_now(rawether::Clock::Tai).map_err(|e| io(&e))?;
            let mono = monotonic_now();
            Some(tai.as_nanos() as i128 - i128::from(mono.0))
        } else {
            None
        };
        Ok(Link { sock, mac, tai_offset })
    }

    /// Open a link on the interface named by environment variable `var`, or `Ok(None)` when it
    /// is unset — the seam tests and interop harnesses use.
    pub fn from_env(var: &str, options: &LinkOptions) -> Result<Option<Link>> {
        match std::env::var(var) {
            Ok(iface) if !iface.is_empty() => Link::open(&iface, options).map(Some),
            _ => Ok(None),
        }
    }

    /// The interface's hardware address: the source address for frames published on it.
    pub fn mac(&self) -> MacAddr {
        self.mac
    }

    /// The interface name.
    pub fn interface(&self) -> &str {
        self.sock.interface()
    }

    /// How received frames reach user space.
    pub fn receive_path(&self) -> RxPath {
        self.sock.rx_path()
    }

    /// Send one frame now.
    pub fn send(&self, frame: &[u8]) -> Result<()> {
        self.sock.send(frame).map_err(|e| io(&e))
    }

    /// Send one frame to leave at `due` (a monotonic instant, such as a publisher's
    /// `next_timeout`). Needs [`LinkOptions::launch_time`].
    pub fn send_at(&self, frame: &[u8], due: Instant) -> Result<()> {
        let offset = self.tai_offset.ok_or_else(|| Error::Io(String::from("send_at needs LinkOptions::launch_time")))?;
        let tai = (i128::from(due.0) + offset).max(0) as u64;
        self.sock.send_at(frame, tai).map_err(|e| io(&e))
    }

    /// Send several frames with as few system calls as the platform allows.
    pub fn send_batch(&mut self, frames: &[&[u8]]) -> Result<usize> {
        self.sock.send_batch(frames).map_err(|e| io(&e))
    }

    /// Wait up to `timeout` (`None`: indefinitely) for the next frame.
    pub fn recv(&mut self, timeout: Option<Duration>) -> Result<Option<Received<'_>>> {
        let Some(p) = self.sock.recv(timeout).map_err(|e| io(&e))? else { return Ok(None) };
        let at = monotonic_now();
        let wire_time = p.timestamp().map(|t| WireTime { secs: t.secs, nanos: t.nanos, hardware: t.source == rawether::TimestampSource::Hardware });
        Ok(Some(Received { frame: p.data(), at, wire_time, truncated: p.is_truncated() }))
    }

    /// Frames received and dropped since the link was opened.
    pub fn stats(&mut self) -> Result<LinkStats> {
        let s = self.sock.stats().map_err(|e| io(&e))?;
        Ok(LinkStats { received: s.received, dropped: s.dropped })
    }

    /// Launch-time frames the kernel dropped since the last call, by reason: the launch time
    /// had passed (`missed`), or the qdisc refused its parameters (`invalid`).
    pub fn launch_errors(&mut self) -> Result<LaunchErrors> {
        self.sock.tx_errors().map_err(|e| io(&e))
    }
}

#[cfg(unix)]
impl std::os::fd::AsFd for Link {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.sock.as_fd()
    }
}

/// Give up `CAP_NET_RAW` once every link is open; open links keep working. On Linux,
/// capabilities are per thread: call this before spawning threads. A no-op on macOS.
pub fn drop_capabilities() -> Result<()> {
    rawether::drop_capabilities().map_err(|e| io(&e))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SR-007: the presets never put an interface into promiscuous mode; without joined groups
    /// they admit the IEC multicast range through the kernel filter.
    #[test]
    fn the_presets_are_not_promiscuous() {
        for o in [LinkOptions::goose(), LinkOptions::sv(), LinkOptions::process_bus()] {
            assert!(!o.promiscuous && o.join.is_empty() && !o.prefixes.is_empty(), "{o:?}");
        }
        assert!(LinkOptions::goose().promiscuous(true).promiscuous);
        assert_eq!(LinkOptions::goose().prefixes, [GOOSE_MULTICAST_PREFIX]);
        assert_eq!(LinkOptions::sv().prefixes, [SV_MULTICAST_PREFIX]);
    }
}
