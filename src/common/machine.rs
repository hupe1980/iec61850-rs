use alloc::collections::VecDeque;

use super::UtcTime;

/// A monotonic point in time, in nanoseconds from an arbitrary origin.
///
/// The protocol cores never read a clock: every input carries the caller's `now`. A plain
/// integer keeps the type available in `no_std` and makes simulated time trivial.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Instant(pub u64);

impl Instant {
    /// The origin.
    pub const ZERO: Instant = Instant(0);

    /// This instant plus `ns` nanoseconds (saturating).
    #[must_use]
    pub const fn plus_nanos(self, ns: u64) -> Instant {
        Instant(self.0.saturating_add(ns))
    }

    /// This instant plus `ms` milliseconds (saturating).
    #[must_use]
    pub const fn plus_millis(self, ms: u64) -> Instant {
        Instant(self.0.saturating_add(ms.saturating_mul(1_000_000)))
    }

    /// Nanoseconds from `earlier` to `self`, or 0 if `earlier` is later.
    pub const fn nanos_since(self, earlier: Instant) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

/// The two clocks a server needs at once, carried together so they cannot be swapped.
///
/// There are exactly two kinds of time here and they answer different questions (D33):
/// [`Now::mono`] is a monotonic [`Instant`] and is what every deadline, window and duration is
/// measured on; [`Now::wall`] is an absolute [`UtcTime`] and is what every *published*
/// timestamp carries — a report's `TimeOfEntry`, a log entry, an `SGCB`'s `LActTm`, the status
/// timestamp an operate writes.
///
/// Neither may be derived from the other, and passing them as one value is what stops a
/// signature from letting a caller pass the wrong one: a monotonic instant reinterpreted as a
/// date reads as 1970-01-01 plus the process's uptime, which every test where both ends are
/// ours will happily agree on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Now {
    /// Monotonic, for deadlines and durations.
    pub mono: Instant,
    /// Absolute, for timestamps that leave the process.
    pub wall: UtcTime,
}

impl Now {
    /// Both readings, taken together.
    pub const fn new(mono: Instant, wall: UtcTime) -> Now {
        Now { mono, wall }
    }

    /// The wall reading as the six-octet `EntryTime` the report and log services publish.
    pub const fn entry(self) -> super::EntryTime {
        super::EntryTime::from_unix_millis(self.wall.to_unix_nanos() / 1_000_000)
    }
}

/// A source of wall-clock time with quality, as IEC 61850 needs it.
///
/// Implementations: a PTP-disciplined PHC, an SNTP client, or [`ManualClock`] in tests.
///
/// `Debug` is a supertrait for the same reason [`FileStore`](crate::server::FileStore) has
/// one: a clock is a field of a server that derives `Debug`, and a trait object that cannot
/// be printed forces every holder to hand-write the impl.
pub trait Clock: core::fmt::Debug {
    /// The current UTC time with its quality bits.
    fn now(&self) -> UtcTime;
}

/// The system's own wall clock, as [`std::time::SystemTime`] reports it.
///
/// This is the default clock of a server built on `std`. It reports
/// [`TimeQuality::SYNCHRONIZED`](super::TimeQuality::SYNCHRONIZED) with no leap-second or
/// accuracy claim, because a plain
/// system clock knows nothing about how it is disciplined; a deployment that runs
/// `ptp4l`/`phc2sys` replaces it with a clock that does.
#[cfg(feature = "std")]
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

#[cfg(feature = "std")]
impl Clock for SystemClock {
    fn now(&self) -> UtcTime {
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
        UtcTime::from_unix_nanos(nanos, super::TimeQuality::SYNCHRONIZED)
    }
}

/// A clock that returns whatever it was last told. For tests and simulation.
#[derive(Clone, Copy, Debug, Default)]
pub struct ManualClock {
    now: UtcTime,
}

impl ManualClock {
    /// A manual clock reading `now`.
    pub const fn new(now: UtcTime) -> Self {
        ManualClock { now }
    }

    /// Set the time that subsequent [`Clock::now`] calls return.
    pub fn set(&mut self, now: UtcTime) {
        self.now = now;
    }
}

impl Clock for ManualClock {
    fn now(&self) -> UtcTime {
        self.now
    }
}

/// A bounded FIFO of pending events.
///
/// Every core in this crate hands events to the application through one of these. The bound
/// matters: a 4.8 kHz sampled-value stream, or a publisher whose frames nobody collects,
/// would otherwise grow an unbounded queue in a process that has stopped draining it. When
/// the queue is full the **oldest** event is dropped — the newest state is the one that
/// matters for protection — and [`EventQueue::dropped`] counts what was lost so the
/// application can tell a quiet system from one it is not keeping up with.
#[derive(Debug)]
pub struct EventQueue<T> {
    items: VecDeque<T>,
    capacity: usize,
    dropped: u64,
}

impl<T> EventQueue<T> {
    /// A queue holding at most `capacity` events (at least one).
    pub fn new(capacity: usize) -> Self {
        EventQueue { items: VecDeque::new(), capacity: capacity.max(1), dropped: 0 }
    }

    /// Append an event, dropping the oldest if the queue is full.
    pub fn push(&mut self, item: T) {
        if self.items.len() >= self.capacity {
            self.items.pop_front();
            self.dropped = self.dropped.saturating_add(1);
        }
        self.items.push_back(item);
    }

    /// Take the oldest event.
    pub fn pop(&mut self) -> Option<T> {
        self.items.pop_front()
    }

    /// Number of events dropped because the application was not draining.
    pub const fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Events waiting.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// True when nothing is waiting.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_drops_oldest_and_counts() {
        let mut q = EventQueue::new(2);
        q.push(1);
        q.push(2);
        q.push(3);
        assert_eq!(q.dropped(), 1);
        assert_eq!(q.pop(), Some(2));
        assert_eq!(q.pop(), Some(3));
        assert_eq!(q.pop(), None);
        assert!(q.is_empty());
        // A zero capacity is clamped to one rather than dropping everything silently.
        let mut q0 = EventQueue::new(0);
        q0.push(7);
        assert_eq!(q0.pop(), Some(7));
    }

    #[test]
    fn instant_saturates() {
        assert_eq!(Instant(u64::MAX).plus_millis(1), Instant(u64::MAX));
        assert_eq!(Instant(5).nanos_since(Instant(9)), 0);
        assert_eq!(Instant(9).nanos_since(Instant(5)), 4);
    }
}
