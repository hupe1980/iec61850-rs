//! Operating a controllable object: select, operate, cancel, and what comes back.
//!
//! Every control service is a `Read` or a `Write` on a structured variable under the `CO`
//! functional constraint. What differs between the four control models of IEC 61850-7-2 is
//! *which* ones, in what order, and whether the answer is the write response or an
//! unsolicited `CommandTermination` that arrives later:
//!
//! | Model | Sequence |
//! |---|---|
//! | direct, normal security | write `Oper` — the response is the answer |
//! | SBO, normal security | read `SBO`, then write `Oper` |
//! | direct, enhanced security | write `Oper`, then wait for a `CommandTermination` |
//! | SBO, enhanced security | write `SBOw`, write `Oper`, then wait for a `CommandTermination` |
//!
//! [`Control::execute`] does whichever of those the model requires, so the caller states the
//! model once — from the SCD's `ctlModel`, which is where it is engineered — instead of
//! writing the sequence out.

use alloc::string::String;
use std::time::Duration;

use super::Client;
use crate::common::{Error, Fc, ObjectReference, Result, TimeQuality, UtcTime};
use crate::proto::data::{Typed, Value};
use crate::proto::mms::control::{AddCause, Check, CommandTermination, ControlModel, ControlRequest, Origin, OriginCategory};

/// A control operation being built.
///
/// ```no_run
/// # use std::time::Duration;
/// # use iec61850_rs::client::Client;
/// # use iec61850_rs::proto::data::{Dbpos, Value};
/// # use iec61850_rs::proto::mms::control::{Check, ControlModel, OriginCategory};
/// # fn main() -> iec61850_rs::Result<()> {
/// # let mut c = Client::connect("10.0.0.5")?;
/// c.control("IED1LD0/CSWI1.Pos")
///     .model(ControlModel::SboEnhanced)
///     .origin(OriginCategory::StationControl, "hmi-1")
///     .check(Check { synchro: true, interlock: true })
///     .execute(&Value::dbpos(Dbpos::On))?;
/// # Ok(()) }
/// ```
#[derive(Debug)]
pub struct Control<'c> {
    client: &'c mut Client,
    /// The controllable object, as `LD/LN$CO$DO`.
    base: String,
    /// The reference the caller wrote, kept for `ctlModel` discovery.
    object: String,
    /// The model the caller stated, or the one read off the server — `None` until either.
    model: Option<ControlModel>,
    origin: Origin,
    check: Check,
    test: bool,
    ctl_num: Option<u8>,
    oper_tm: Option<UtcTime>,
    issued_at: Option<UtcTime>,
    timeout: Duration,
}

impl Client {
    /// Start a control operation on a controllable object.
    ///
    /// `reference` names the data object, not one of its control attributes:
    /// `IED1LD0/CSWI1.Pos`, or `IED1LD0/CSWI1$CO$Pos`. The `$Oper`, `$SBO`, `$SBOw` and
    /// `$Cancel` below it are this module's business.
    pub fn control<'c>(&'c mut self, reference: &str) -> Control<'c> {
        let timeout = self.timeout();
        // A reference that does not parse is passed through untouched: the server's error
        // names the reference the caller wrote, which is more useful than one this rewrote.
        let base = ObjectReference::parse(reference).map_or_else(
            |_| String::from(reference),
            |r| {
                let (domain, item) = r.to_mms(Fc::CO);
                alloc::format!("{domain}/{item}")
            },
        );
        Control {
            client: self,
            base,
            object: String::from(reference),
            model: None,
            origin: Origin::new(OriginCategory::RemoteControl, "iec61850-rs"),
            check: Check::NONE,
            test: false,
            ctl_num: None,
            oper_tm: None,
            issued_at: None,
            timeout,
        }
    }
}

impl Control<'_> {
    /// The control model the object is engineered with (`ctlModel`).
    ///
    /// Getting this wrong is the most common reason a control silently does nothing: an
    /// object engineered for select-before-operate answers an unselected `Oper` with
    /// `AddCause::ObjectNotSelected` and no state change. **A caller that does not say is not
    /// guessed at**: the model is read off the server's own `CF$…$ctlModel` before the first
    /// command, which costs one round trip and is the only source that cannot be out of date.
    /// State it here when it is known — from the SCD, or from a previous read — and the round
    /// trip goes away.
    #[must_use]
    pub const fn model(mut self, model: ControlModel) -> Self {
        self.model = Some(model);
        self
    }

    /// Who is issuing the command.
    #[must_use]
    pub fn origin(mut self, category: OriginCategory, identifier: &str) -> Self {
        self.origin = Origin::new(category, identifier);
        self
    }

    /// Which conditions the server must verify before it operates.
    #[must_use]
    pub const fn check(mut self, check: Check) -> Self {
        self.check = check;
        self
    }

    /// Mark the command as a test. A server not in test mode must refuse it.
    #[must_use]
    pub const fn test(mut self, test: bool) -> Self {
        self.test = test;
        self
    }

    /// Use this `ctlNum` instead of the client's running counter.
    #[must_use]
    pub const fn ctl_num(mut self, ctl_num: u8) -> Self {
        self.ctl_num = Some(ctl_num);
        self
    }

    /// Operate at this time rather than now (`operTm`).
    ///
    /// Only for an object engineered for time-activated operate: the field's presence changes
    /// the structure, so a server that does not expect it rejects the write.
    #[must_use]
    pub const fn at(mut self, when: UtcTime) -> Self {
        self.oper_tm = Some(when);
        self
    }

    /// Stamp the request with this time instead of the host clock (`T`).
    #[must_use]
    pub const fn issued_at(mut self, t: UtcTime) -> Self {
        self.issued_at = Some(t);
        self
    }

    /// How long to wait for a `CommandTermination` under enhanced security.
    #[must_use]
    pub const fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Do whatever the control model requires, and report the outcome.
    ///
    /// Under normal security the write response is the answer. Under enhanced security the
    /// server answers the write immediately and sends the *real* answer later as a
    /// `CommandTermination`; a negative one becomes an [`Error::ControlRejected`] carrying
    /// the `AddCause`, because "the write succeeded" is not what the caller asked.
    pub fn execute(&mut self, value: &Value) -> Result<Option<CommandTermination>> {
        let model = self.resolved_model();
        if matches!(model, ControlModel::StatusOnly) {
            // A status-only object has no `Oper` to write to. Saying so here costs no round
            // trip and names the actual problem, where the server's answer would be a bare
            // "object does not exist" against a reference that plainly does.
            return Err(Error::ControlRejected { add_cause: AddCause::NotSupported.to_code() });
        }
        let ctl_num = self.take_ctl_num();
        if model.needs_select() {
            if model.select_carries_value() {
                self.write_control("SBOw", &self.request(value.clone(), ctl_num), false)?;
            } else if !self.select_inner()? {
                return Err(Error::ControlRejected { add_cause: AddCause::SelectFailed.to_code() });
            }
        }
        self.write_control("Oper", &self.request(value.clone(), ctl_num), false)?;
        if !model.enhanced_security() {
            return Ok(None);
        }
        let timeout = self.timeout;
        // Matched by `ctlNum`: a client with two commands in flight gets two terminations,
        // and handing the second command's answer to the first is how a tool reports that a
        // breaker closed when it was a different breaker.
        match self.client.next_termination_for(ctl_num, timeout)? {
            Some(CommandTermination::Negative { error, request }) => {
                let add_cause = error.add_cause.to_code();
                let _ = request;
                Err(Error::ControlRejected { add_cause })
            }
            Some(positive) => Ok(Some(positive)),
            None => Err(Error::Io(String::from("no command termination arrived"))),
        }
    }

    /// `Select` — read `SBO`, for a control model with normal security.
    ///
    /// Returns whether the server granted the reservation. A server grants it by answering
    /// with a non-empty string and refuses by answering with an empty one.
    pub fn select(&mut self) -> Result<bool> {
        self.select_inner()
    }

    /// `SelectWithValue` — write `SBOw`, for a control model with enhanced security.
    pub fn select_with_value(&mut self, value: &Value) -> Result<()> {
        let ctl_num = self.take_ctl_num();
        self.write_control("SBOw", &self.request(value.clone(), ctl_num), false)
    }

    /// `Operate` — write `Oper`, without doing anything the model might also require.
    pub fn operate(&mut self, value: &Value) -> Result<()> {
        let ctl_num = self.take_ctl_num();
        self.write_control("Oper", &self.request(value.clone(), ctl_num), false)
    }

    /// `Cancel` — release a selection, or abandon a time-activated operate.
    ///
    /// The structure is an `Oper` without its `Check`, and it must carry the **same**
    /// `ctlNum` as the command it cancels — so pass the one that was used, rather than
    /// letting the counter advance.
    pub fn cancel(&mut self, value: &Value) -> Result<()> {
        let ctl_num = self.take_ctl_num();
        self.write_control("Cancel", &self.request(value.clone(), ctl_num), true)
    }

    /// The `ctlNum` this operation is using, once one has been taken.
    pub const fn current_ctl_num(&self) -> Option<u8> {
        self.ctl_num
    }

    /// The control model to act on: what the caller stated, or what the server says.
    ///
    /// Read once and remembered, so a `select` followed by an `operate` costs one lookup and
    /// not two. A server that does not publish `ctlModel` at all — the attribute is optional
    /// under `CF` — leaves `DirectNormal`, which is what this did unconditionally before and
    /// is the only assumption left.
    fn resolved_model(&mut self) -> ControlModel {
        if let Some(m) = self.model {
            return m;
        }
        let m = self.client.read_control_model(&self.object).unwrap_or(ControlModel::DirectNormal);
        self.model = Some(m);
        m
    }

    fn select_inner(&mut self) -> Result<bool> {
        let reference = alloc::format!("{}$SBO", self.base);
        let granted = self.client.read(&reference, Fc::CO)?;
        Ok(match granted.as_str() {
            Some(s) => !s.is_empty(),
            // Some servers answer a select with a boolean rather than the object reference
            // the standard asks for. Both mean the same thing and neither is worth failing.
            None => granted.as_bool().unwrap_or(false),
        })
    }

    fn request(&self, ctl_val: Value, ctl_num: u8) -> ControlRequest {
        ControlRequest {
            ctl_val,
            oper_tm: self.oper_tm,
            origin: self.origin.clone(),
            ctl_num,
            t: self.issued_at.unwrap_or_else(host_time),
            test: self.test,
            check: self.check,
        }
    }

    fn write_control(&mut self, attribute: &str, request: &ControlRequest, cancel: bool) -> Result<()> {
        let reference = alloc::format!("{}${attribute}", self.base);
        let value = if cancel { request.to_cancel_value() } else { request.to_value() };
        let writes = alloc::vec![(reference, value)];
        match self.client.write_many(&writes)?.into_iter().next() {
            Some(Ok(())) => Ok(()),
            Some(Err(e)) => Err(self.reason_for(request.ctl_num, e)),
            None => Err(Error::InvalidValue("empty Write response")),
        }
    }

    /// Turn a refused control write into the reason it was refused.
    ///
    /// A server that refuses a **normal-security** command answers the write with a
    /// `DataAccessError` *and* sends a `LastApplError` alongside it — the access code says
    /// "denied", the `AddCause` says "blocked by interlocking", and only one of those is
    /// something an operator can act on. The wait is short because the error is already on
    /// the wire when the failed response arrives; if none comes, the access error stands.
    fn reason_for(&mut self, ctl_num: u8, fallback: Error) -> Error {
        let waited = self.client.next_termination_for(ctl_num, Duration::from_millis(500));
        match waited {
            Ok(Some(t)) => match t.add_cause() {
                Some(cause) => Error::ControlRejected { add_cause: cause.to_code() },
                None => fallback,
            },
            _ => fallback,
        }
    }

    fn take_ctl_num(&mut self) -> u8 {
        if let Some(n) = self.ctl_num {
            return n;
        }
        let n = self.client.next_ctl_num();
        self.ctl_num = Some(n);
        n
    }
}

/// The host clock, as an IEC 61850 timestamp.
///
/// This is an adapter, not a core: `T` is the time *the client issued the command*, which
/// only the host knows. A caller with a disciplined clock overrides it with
/// [`Control::issued_at`].
fn host_time() -> UtcTime {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => UtcTime::from_unix_nanos(u64::try_from(d.as_nanos()).unwrap_or(u64::MAX), TimeQuality::default()),
        Err(_) => UtcTime::default(),
    }
}

/// The control attributes of a controllable object, under the `CO` functional constraint.
pub const CONTROL_ATTRIBUTES: &[&str] = &["Oper", "SBO", "SBOw", "Cancel"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reference_becomes_the_control_object_under_co() {
        // Both spellings, and neither names an attribute: `$Oper` is this module's business.
        for r in ["IED1LD0/CSWI1.Pos", "IED1LD0/CSWI1$CO$Pos"] {
            let parsed = ObjectReference::parse(r).unwrap();
            let (domain, item) = parsed.to_mms(Fc::CO);
            assert_eq!((domain, item.as_str()), ("IED1LD0", "CSWI1$CO$Pos"));
        }
    }

    #[test]
    fn the_host_clock_produces_a_plausible_timestamp() {
        let t = host_time();
        assert!(t.seconds > 1_700_000_000, "the host clock is before 2023");
        assert!(CONTROL_ATTRIBUTES.contains(&"Oper"));
    }

    #[test]
    fn a_cancel_is_the_request_without_its_check() {
        let r = ControlRequest {
            ctl_val: Value::Boolean(true),
            oper_tm: None,
            origin: Origin::new(OriginCategory::BayControl, "x"),
            ctl_num: 3,
            t: UtcTime::default(),
            test: false,
            check: Check::BOTH,
        };
        let oper = r.to_value();
        let cancel = r.to_cancel_value();
        assert_eq!(oper.members().map(<[Value]>::len), Some(6));
        assert_eq!(cancel.members().map(<[Value]>::len), Some(5));
        assert_eq!(ControlRequest::from_value(&cancel).unwrap().ctl_num, 3, "the same sequence number as the command it cancels");
    }
}
