//! Controls, server side: the four models of IEC 61850-7-2 §20 as a state machine.
//!
//! Operating a breaker is a `Read` of `SBO` or a `Write` of `SBOw`/`Oper`/`Cancel` on a
//! structured variable under `CO`. What differs between the models is which of those are
//! legal, in what order, and whether the client's answer is the write response or an
//! unsolicited [`CommandTermination`](crate::proto::mms::control::CommandTermination) that arrives afterwards:
//!
//! | `ctlModel` | The sequence the server enforces |
//! |---|---|
//! | 1 direct, normal | `Oper` → the write response *is* the answer |
//! | 2 SBO, normal | read `SBO` (reserve), then `Oper` |
//! | 3 direct, enhanced | `Oper` → response, then a `CommandTermination` |
//! | 4 SBO, enhanced | `SBOw` (reserve *with* the value), then `Oper`, then a termination |
//!
//! Three rules carry most of the weight, and each is a way a real substation refuses a
//! command that a naive server would accept:
//!
//! - **A selection belongs to one client and one value.** An `Oper` from another association,
//!   or with a `ctlVal` the `SBOw` did not select, is `ObjectNotSelected` — not a silent
//!   operate.
//! - **A selection expires.** `sboTimeout` is what stops an abandoned select holding a
//!   breaker for ever, and the expiry is `AddCause::TimeLimitOver`.
//! - **A refusal is an `AddCause`, never a success.** For an enhanced-security control the
//!   write succeeds and the *command* fails later, which is precisely the case a thin server
//!   reports as "operated".

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::result::Result;

use super::acsi::AssocId;
use super::ied::{DATA_ACCESS_DENIED, DATA_ACCESS_VALUE_INVALID, Ied};
use crate::common::{Fc, Instant, Now, UtcTime};
use crate::proto::data::Value;
use crate::proto::mms::control::{AddCause, ControlError, ControlModel, ControlRequest, LastApplError};
use crate::proto::mms::{AccessResult, Mms, ObjectName, Unconfirmed, VariableAccess, VariableSpecification};

/// How long a selection is held before it expires, when the model does not say.
///
/// IEC 61850-7-3 puts `sboTimeout` on the controllable object; a file that leaves it out gets
/// this, which is libiec61850's default too 🌐. Zero would mean "never expires", which is a
/// breaker one client can hold for ever.
pub const DEFAULT_SBO_TIMEOUT_MS: u64 = 30_000;

/// What the application is asked before a control is applied.
#[derive(Clone, Debug, PartialEq)]
pub struct ControlEvent {
    /// The controllable object, as `IED1LD0/CSWI1$CO$Pos`.
    pub object: String,
    /// Which stage this is.
    pub stage: Stage,
    /// The request the client sent.
    pub request: ControlRequest,
    /// The control model the object is engineered with.
    pub model: ControlModel,
}

/// Where in a control sequence a hook is being called.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// A `Read` of `SBO` or a `Write` of `SBOw`: may this client reserve the object?
    Select,
    /// A `Write` of `Oper`: should the switchgear move?
    Operate,
    /// A `Write` of `Cancel`.
    Cancel,
}

/// The application's answer to a [`ControlEvent`].
///
/// `Ok(())` lets the sequence proceed; an `AddCause` refuses it and is what the client is
/// told, which is the difference between "the breaker did not close" and a diagnosis.
pub type ControlHook = Box<dyn Fn(&ControlEvent) -> Result<(), AddCause> + Send + Sync>;

/// One outstanding selection.
#[derive(Clone, Debug)]
struct Selection {
    assoc: AssocId,
    /// The value the client selected, for `SBOw`. A bare `SBO` reserves without one.
    value: Option<Value>,
    ctl_num: u8,
    expires: Instant,
}

/// What a control sequence produced besides its write response.
#[derive(Clone, Debug, PartialEq)]
pub struct Termination {
    /// Who to send it to.
    pub assoc: AssocId,
    /// The encoded `unconfirmed-PDU`.
    pub pdu: Vec<u8>,
}

/// A command accepted now and due later — IEC 61850-7-2's *time-activated operate*.
///
/// `operTm` is an **absolute** time and the deadline is a **monotonic** one, so the wait is
/// computed once, at acceptance, from the difference between `operTm` and the wall clock then
/// (D33: the two are different questions and neither may be derived from the other). The
/// command's own `wall` is kept so the status it eventually writes is stamped with the moment
/// it was *asked for*, which is what an operator reconstructing a sequence needs.
#[derive(Clone, Debug)]
struct Timed {
    assoc: AssocId,
    object: String,
    request: ControlRequest,
    model: ControlModel,
    due: Instant,
}

/// The control state machine over every controllable object of an [`Ied`].
pub struct Controls {
    selections: BTreeMap<String, Selection>,
    /// Commands accepted with an `operTm` in the future, in the order they fall due.
    timed: Vec<Timed>,
    hook: Option<ControlHook>,
    sbo_timeout_ms: u64,
    pending: Vec<Termination>,
}

/// Hand-written because a [`ControlHook`] is a closure and closures have no `Debug`; the
/// count of pending terminations is what a reader of a `{:?}` actually wants anyway.
impl core::fmt::Debug for Controls {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Controls")
            .field("selections", &self.selections.len())
            .field("timed", &self.timed.len())
            .field("hook", &self.hook.is_some())
            .field("sbo_timeout_ms", &self.sbo_timeout_ms)
            .field("pending", &self.pending.len())
            .finish()
    }
}

impl Default for Controls {
    fn default() -> Controls {
        Controls { selections: BTreeMap::new(), timed: Vec::new(), hook: None, sbo_timeout_ms: DEFAULT_SBO_TIMEOUT_MS, pending: Vec::new() }
    }
}

impl Controls {
    /// A control layer with no application hook: every command is accepted and applied to the
    /// object's `stVal`, which is what a simulator wants and what a device replaces.
    pub fn new() -> Controls {
        Controls::default()
    }

    /// Ask `hook` before every select, operate and cancel.
    pub fn on_control(&mut self, hook: ControlHook) {
        self.hook = Some(hook);
    }

    /// How long a selection is held.
    pub fn set_sbo_timeout_ms(&mut self, ms: u64) {
        self.sbo_timeout_ms = ms;
    }

    /// Terminations produced by the last request, to be sent after its response.
    pub fn take_pending(&mut self) -> Vec<Termination> {
        core::mem::take(&mut self.pending)
    }

    /// An association ended: drop the selections it held, so a client that disappears
    /// mid-sequence does not leave a breaker reserved.
    pub fn on_association_closed(&mut self, assoc: AssocId) {
        self.selections.retain(|_, s| s.assoc != assoc);
        // A command nobody is left to tell about is a command that must not run: an
        // association that disappears between an `Oper` and its `operTm` takes its
        // time-activated commands with it.
        self.timed.retain(|t| t.assoc != assoc);
    }

    /// Expire selections that were never operated, and run the commands whose `operTm` has
    /// arrived.
    pub fn on_timeout(&mut self, ied: &mut Ied, now: Instant) {
        self.selections.retain(|_, s| now < s.expires);
        if self.timed.iter().all(|t| now < t.due) {
            return;
        }
        let (due, waiting): (Vec<Timed>, Vec<Timed>) = core::mem::take(&mut self.timed).into_iter().partition(|t| now >= t.due);
        self.timed = waiting;
        for t in due {
            // The hook is asked **now**, not when the command was accepted: an interlock that
            // has closed in the meantime is exactly what a time-activated operate is for.
            if let Err(cause) = self.ask(&t.object, Stage::Operate, &t.request, t.model) {
                let error = LastApplError {
                    control_object: alloc::format!("{}$Oper", t.object),
                    error: ControlError::Unknown,
                    origin: t.request.origin.clone(),
                    ctl_num: t.request.ctl_num,
                    add_cause: cause,
                };
                self.pending.push(Termination { assoc: t.assoc, pdu: negative(&t.object, &t.request, &error) });
                continue;
            }
            apply(ied, &t.object, &t.request, t.request.t);
            if t.model.enhanced_security() {
                self.pending.push(Termination { assoc: t.assoc, pdu: positive(&t.object, &t.request) });
            }
        }
    }

    /// When this layer next needs [`Controls::on_timeout`]: the earliest selection expiry or
    /// time-activated command, whichever comes first.
    pub fn next_timeout(&self) -> Option<Instant> {
        self.selections.values().map(|s| s.expires).chain(self.timed.iter().map(|t| t.due)).min()
    }

    /// Whether `reference` is a control attribute this layer owns.
    ///
    /// `IED1LD0/CSWI1$CO$Pos$Oper` → the object and `Oper`. Anything under `CO` that is not
    /// one of the four service attributes is an ordinary variable.
    pub fn split(reference: &str) -> Option<(&str, &str)> {
        let (object, attribute) = reference.rsplit_once('$')?;
        matches!(attribute, "Oper" | "SBOw" | "SBO" | "Cancel").then_some((object, attribute))
    }

    /// A `Read` of `SBO`: the select of a normal-security select-before-operate object.
    ///
    /// The answer is the object's own reference when the selection is granted, and an **empty
    /// string** when it is refused — which is the whole of IEC 61850-8-1's mapping for it, and
    /// is why a client cannot tell *why* a bare `SBO` was refused.
    pub fn select(&mut self, assoc: AssocId, ied: &Ied, object: &str, now: Now) -> Value {
        let model = model_of(ied, object);
        if model != Some(ControlModel::SboNormal) {
            return Value::VisibleString(String::new());
        }
        if self.held_by_other(object, assoc, now.mono) {
            return Value::VisibleString(String::new());
        }
        let request = ControlRequest::new(Value::Boolean(false), 0, now.wall);
        if self.ask(object, Stage::Select, &request, ControlModel::SboNormal).is_err() {
            return Value::VisibleString(String::new());
        }
        self.selections.insert(String::from(object), Selection { assoc, value: None, ctl_num: 0, expires: now.mono.plus_millis(self.sbo_timeout_ms) });
        Value::VisibleString(String::from(object))
    }

    /// A `Write` of `SBOw`, `Oper` or `Cancel`.
    ///
    /// Returns the `DataAccessError` code when the write itself is refused. A command that is
    /// *accepted* and then fails is not an error here: the write succeeds and the failure
    /// arrives as a negative [`CommandTermination`](crate::proto::mms::control::CommandTermination), which is the whole point of enhanced
    /// security and the case a thin server reports as success.
    pub fn write(&mut self, assoc: AssocId, ied: &mut Ied, object: &str, attribute: &str, value: &Value, now: Now) -> Result<(), i64> {
        let Some(model) = model_of(ied, object) else { return Err(DATA_ACCESS_DENIED) };
        let Ok(request) = ControlRequest::from_value(value) else { return Err(DATA_ACCESS_VALUE_INVALID) };
        self.on_timeout(ied, now.mono);

        match attribute {
            "SBOw" => {
                if model != ControlModel::SboEnhanced {
                    return self.refuse(assoc, object, &request, model, Stage::Select, AddCause::NotSupported);
                }
                if self.held_by_other(object, assoc, now.mono) {
                    return self.refuse(assoc, object, &request, model, Stage::Select, AddCause::ObjectAlreadySelected);
                }
                if let Err(cause) = self.ask(object, Stage::Select, &request, model) {
                    return self.refuse(assoc, object, &request, model, Stage::Select, cause);
                }
                self.selections.insert(
                    String::from(object),
                    Selection { assoc, value: Some(request.ctl_val.clone()), ctl_num: request.ctl_num, expires: now.mono.plus_millis(self.sbo_timeout_ms) },
                );
                Ok(())
            }
            "Cancel" => {
                if let Err(cause) = self.ask(object, Stage::Cancel, &request, model) {
                    return self.refuse(assoc, object, &request, model, Stage::Cancel, cause);
                }
                // `Cancel` withdraws a *pending time-activated command* as well as a
                // selection — that is the only way to stop one, and a server that cannot is a
                // server that has armed something it cannot disarm.
                let had_timed = self.timed.iter().any(|t| t.object == object && t.assoc == assoc);
                self.timed.retain(|t| !(t.object == object && t.assoc == assoc));
                match self.selections.get(object) {
                    Some(s) if s.assoc == assoc => {
                        self.selections.remove(object);
                        Ok(())
                    }
                    _ if had_timed => Ok(()),
                    // Cancelling a selection somebody else holds, or one that does not exist,
                    // is refused rather than silently doing nothing.
                    _ => self.refuse(assoc, object, &request, model, Stage::Cancel, AddCause::ObjectNotSelected),
                }
            }
            "Oper" => self.operate(assoc, ied, object, &request, model, now),
            _ => Err(DATA_ACCESS_DENIED),
        }
    }

    fn operate(&mut self, assoc: AssocId, ied: &mut Ied, object: &str, request: &ControlRequest, model: ControlModel, now: Now) -> Result<(), i64> {
        if model == ControlModel::StatusOnly {
            return self.refuse(assoc, object, request, model, Stage::Operate, AddCause::NotSupported);
        }
        if model.needs_select() {
            match self.selections.get(object) {
                None => return self.refuse(assoc, object, request, model, Stage::Operate, AddCause::ObjectNotSelected),
                Some(s) if s.assoc != assoc => return self.refuse(assoc, object, request, model, Stage::Operate, AddCause::ObjectNotSelected),
                // An `SBOw` selects a *value*, and operating a different one is not the
                // command that was selected.
                Some(s) if s.value.as_ref().is_some_and(|v| *v != request.ctl_val) => {
                    return self.refuse(assoc, object, request, model, Stage::Operate, AddCause::InconsistentParameters);
                }
                Some(s) if s.ctl_num != 0 && s.ctl_num != request.ctl_num => {
                    return self.refuse(assoc, object, request, model, Stage::Operate, AddCause::InconsistentParameters);
                }
                Some(_) => {}
            }
        }
        if let Err(cause) = self.ask(object, Stage::Operate, request, model) {
            return self.refuse(assoc, object, request, model, Stage::Operate, cause);
        }
        self.selections.remove(object);
        // Time-activated operate (IEC 61850-7-2 §20): an `operTm` in the future arms the
        // command rather than running it. The write still succeeds — what the client is
        // waiting for is the termination, which arrives when the command actually runs.
        if let Some(at) = request.oper_tm {
            if let Some(wait) = at.to_unix_nanos().checked_sub(now.wall.to_unix_nanos()).filter(|w| *w > 0) {
                self.timed.retain(|t| !(t.object == object && t.assoc == assoc));
                self.timed.push(Timed {
                    assoc,
                    object: String::from(object),
                    request: ControlRequest { t: now.wall, ..request.clone() },
                    model,
                    due: now.mono.plus_nanos(wait),
                });
                return Ok(());
            }
        }
        apply(ied, object, request, now.wall);
        if model.enhanced_security() {
            // The write succeeded; the *command* is answered by the termination that follows.
            self.pending.push(Termination { assoc, pdu: positive(object, request) });
        }
        Ok(())
    }

    /// Refuse a command: a `LastApplError` to the client, and a write result that depends on
    /// *which* command it was.
    ///
    /// Only a refused **operate** on an enhanced-security object succeeds-and-then-fails —
    /// that is what a `CommandTermination` is for (IEC 61850-7-2 §20.4). A refused **select**
    /// is answered by its own response, whatever the security model, because
    /// `SelectWithValue` has no termination to carry the failure: a server that accepts the
    /// select and reports the refusal afterwards leaves the client believing it holds a
    /// breaker it does not.
    fn refuse(&mut self, assoc: AssocId, object: &str, request: &ControlRequest, model: ControlModel, stage: Stage, cause: AddCause) -> Result<(), i64> {
        let error = LastApplError {
            control_object: alloc::format!("{object}$Oper"),
            error: ControlError::Unknown,
            origin: request.origin.clone(),
            ctl_num: request.ctl_num,
            add_cause: cause,
        };
        self.pending.push(Termination { assoc, pdu: negative(object, request, &error) });
        if model.enhanced_security() && stage == Stage::Operate {
            // The write is accepted and the command fails afterwards; the client is told by
            // the `LastApplError` above, which it is already waiting for.
            Ok(())
        } else {
            Err(DATA_ACCESS_DENIED)
        }
    }

    fn held_by_other(&self, object: &str, assoc: AssocId, now: Instant) -> bool {
        self.selections.get(object).is_some_and(|s| s.assoc != assoc && now < s.expires)
    }

    fn ask(&self, object: &str, stage: Stage, request: &ControlRequest, model: ControlModel) -> Result<(), AddCause> {
        match &self.hook {
            Some(hook) => hook(&ControlEvent { object: String::from(object), stage, request: request.clone(), model }),
            None => Ok(()),
        }
    }
}

/// The `ctlModel` of a controllable object, read out of the model the server serves.
fn model_of(ied: &Ied, object: &str) -> Option<ControlModel> {
    // `IED1LD0/CSWI1$CO$Pos` → `IED1LD0/CSWI1$CF$Pos$ctlModel`.
    let (domain, item) = object.split_once('/')?;
    let (ln, rest) = item.split_once('$')?;
    let path = rest.strip_prefix("CO$")?;
    let value = ied.value(&alloc::format!("{domain}/{ln}$CF${path}$ctlModel"))?;
    let code = match value {
        Value::Integer(i) => *i,
        Value::Unsigned(u) => i64::try_from(*u).ok()?,
        _ => return None,
    };
    ControlModel::from_code(code)
}

/// Apply a command to the model: the value becomes the object's status, stamped now.
///
/// This is the default a simulator wants and a device replaces with a
/// [`ControlHook`] that drives the switchgear and lets the process report the position back.
/// Writing the status here rather than in the hook is what makes `ied sim` a working IED with
/// no code at all.
fn apply(ied: &mut Ied, object: &str, request: &ControlRequest, wall: UtcTime) {
    let Some((domain, item)) = object.split_once('/') else { return };
    let Some((ln, rest)) = item.split_once('$') else { return };
    let Some(path) = rest.strip_prefix("CO$") else { return };
    let status = alloc::format!("{domain}/{ln}$ST${path}$stVal");
    // The status attribute may be a different shape from `ctlVal` — a `DPC` selects a
    // `Dbpos` and reports one, an `SPC` a boolean — so the write goes through the same type
    // check every other write does and is simply dropped when it does not fit.
    let _ = ied.write_leaf(&status, request.ctl_val.clone());
    let _ = ied.write_leaf(&alloc::format!("{domain}/{ln}$ST${path}$t"), Value::UtcTime(wall));
    let _ = Fc::CO;
}

/// A positive `CommandTermination`: an `InformationReport` naming only the object's `Oper`,
/// carrying the `Oper` value the client sent (IEC 61850-8-1 §20.9).
fn positive(object: &str, request: &ControlRequest) -> Vec<u8> {
    let (domain, item) = object.split_once('/').unwrap_or(("", object));
    let oper = alloc::format!("{item}$Oper");
    report(&[(domain, oper.as_str())], &[request.to_value()])
}

/// A negative one: `LastApplError` first — VMD-specific, with no domain — then the `Oper`.
fn negative(object: &str, request: &ControlRequest, error: &LastApplError) -> Vec<u8> {
    let (domain, item) = object.split_once('/').unwrap_or(("", object));
    let oper = alloc::format!("{item}$Oper");
    let mut e = crate::ber::Encoder::new();
    let values = [error.to_value(), request.to_value()];
    let encoded: Vec<Vec<u8>> = values.iter().filter_map(|v| Value::encode_all(core::slice::from_ref(v)).ok()).collect();
    if encoded.len() != 2 {
        return Vec::new();
    }
    let mut results = Vec::with_capacity(2);
    for bytes in &encoded {
        match crate::ber::Cursor::new(bytes).next_required() {
            Ok(t) => results.push(AccessResult::Success(t)),
            Err(_) => return Vec::new(),
        }
    }
    let names = alloc::vec![
        VariableSpecification::Name(ObjectName::VmdSpecific("LastApplError")),
        VariableSpecification::Name(ObjectName::DomainSpecific { domain, item: &oper }),
    ];
    let pdu = Mms::Unconfirmed(Unconfirmed::InformationReport { access: VariableAccess::ListOfVariable(names), results });
    if pdu.write(&mut e).is_err() { Vec::new() } else { e.into_vec() }
}

/// An `InformationReport` naming a list of variables, carrying these values.
fn report(names: &[(&str, &str)], values: &[Value]) -> Vec<u8> {
    let encoded: Vec<Vec<u8>> = values.iter().filter_map(|v| Value::encode_all(core::slice::from_ref(v)).ok()).collect();
    if encoded.len() != values.len() {
        return Vec::new();
    }
    let mut results = Vec::with_capacity(encoded.len());
    for bytes in &encoded {
        match crate::ber::Cursor::new(bytes).next_required() {
            Ok(t) => results.push(AccessResult::Success(t)),
            Err(_) => return Vec::new(),
        }
    }
    let specs = names.iter().map(|(d, i)| VariableSpecification::Name(ObjectName::DomainSpecific { domain: d, item: i })).collect();
    let mut e = crate::ber::Encoder::new();
    let pdu = Mms::Unconfirmed(Unconfirmed::InformationReport { access: VariableAccess::ListOfVariable(specs), results });
    if pdu.write(&mut e).is_err() { Vec::new() } else { e.into_vec() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_four_service_attributes_are_controls() {
        assert_eq!(Controls::split("IED1LD0/CSWI1$CO$Pos$Oper"), Some(("IED1LD0/CSWI1$CO$Pos", "Oper")));
        assert_eq!(Controls::split("IED1LD0/CSWI1$CO$Pos$SBOw"), Some(("IED1LD0/CSWI1$CO$Pos", "SBOw")));
        assert_eq!(Controls::split("IED1LD0/CSWI1$CO$Pos$Cancel"), Some(("IED1LD0/CSWI1$CO$Pos", "Cancel")));
        // Anything else under `CO` is an ordinary variable — `ctlNum` inside an `Oper` most
        // of all, which is a component and not a service.
        assert_eq!(Controls::split("IED1LD0/CSWI1$CO$Pos$Oper$ctlNum"), None);
        assert_eq!(Controls::split("IED1LD0/CSWI1$ST$Pos$stVal"), None);
    }
}
