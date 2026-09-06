//! Service tracking, server side: IEC 61850-7-2 §14, §15.3.2 and §20.6.2.
//!
//! Reporting says what happened in the **process**. Tracking says what happened on the
//! **wire** — who enabled that control block, which client was refused and with what — which
//! no report can, because a report is about data and a service is not data.
//!
//! The mechanism is small (§14.1): one data object per kind of service in a logical device,
//! mirroring the parameters of the last such service. Because that object is an ordinary data
//! object, putting it in a data set makes an ordinary report control block carry it, with no
//! new service and no new PDU.
//!
//! Three rules keep the whole thing free of tables this crate has not read:
//!
//! - **The `cdc` finds the object.** IEC 61850-7-4 names each tracking data object; the file
//!   declares `cdc="BTS"` and the server looks for that, so the name never has to be known.
//! - **The specific attributes copy themselves.** Every tracking CDC's own half is the control
//!   block's attributes with a lower-case first letter — `rptID` for `RptID`, `actSG` for
//!   `ActSG` — so the engine copies, for each attribute the *file* declares on the tracker,
//!   the same-named attribute of the block in `objRef`. One rule instead of nine tables, and a
//!   file that declares half a tracker gets half a tracker (D41). The rule has exactly one
//!   exception, `gi` for `GI`, and [`block_attribute`] is where it lives.
//! - **The ordinals come from the file.** The `serviceType` and `errorCode` names are IEC
//!   61850-7-2's ✅ and their numbers IEC 61850-8-1's, behind the paywall (R2), so the server
//!   resolves a name against the file's own `EnumType` and falls back to the standard's list
//!   order only when there is none.
//!
//! §15.3.2 also says what is *not* tracked: a `GetBRCBValues`, a `Report` (it is already in the
//! report), a `SendGOOSEMessage`.

use alloc::string::String;
use alloc::vec::Vec;

use super::ied::Ied;
use crate::common::{Fc, Now, ServiceError, ServiceType, Tracked, TrackingCdc};
use crate::model::{BType, IedModel};
use crate::proto::data::Value;

/// Where one tracking data object lives, and what it is for.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Tracker {
    /// The logical device it tracks services in.
    domain: String,
    /// Its full MMS reference under `SR`: `IED1LD0/LLN0$SR$BrcbTrk`.
    reference: String,
    /// The class the file declared.
    cdc: TrackingCdc,
    /// For a `CTS`, the `bType` of its own `ctlVal` — which is what says *which* controllable
    /// object it tracks when a logical device declares several.
    ctl_val: Option<BType>,
}

/// The service tracking engine over every logical device of an [`Ied`].
#[derive(Debug, Default)]
pub struct Tracking {
    trackers: Vec<Tracker>,
}

impl Tracking {
    /// Find every tracking data object the model declares.
    ///
    /// A server whose file declares none does nothing at all here — which is the common case
    /// and costs one empty vector.
    pub fn new(ied: &Ied) -> Tracking {
        let mut trackers = Vec::new();
        collect(&ied.model, &mut trackers);
        Tracking { trackers }
    }

    /// Whether this model tracks anything.
    pub fn is_empty(&self) -> bool {
        self.trackers.is_empty()
    }

    /// The references of the tracking objects, for a caller that wants to see them.
    pub fn references(&self) -> Vec<String> {
        self.trackers.iter().map(|t| t.reference.clone()).collect()
    }

    /// Record one service.
    ///
    /// Writes go through [`Ied::write_leaf`], not `set_internal`, because a tracked service
    /// **is** a data change: that is the entire point — a report control block whose data set
    /// holds the tracker carries the service to the control room. A model that declares no
    /// tracker of that class, or none in that logical device, is left alone.
    pub fn record(&self, ied: &mut Ied, event: &Tracked, now: Now) {
        self.record_with(ied, event, &[], now);
    }

    /// Record one service, with values the mirror cannot find on a control block.
    ///
    /// `CTS` is the one class whose specific half does not live on the object it names: a
    /// control object's `ctlVal`, `origin`, `ctlNum`, `T`, `Test` and `Check` are components of
    /// the `Oper` structure the *client sent*, not attributes the server holds, and
    /// `respAddCause` exists nowhere but in the refusal. So the caller that has them passes
    /// them, and the mirror fills in the rest.
    pub fn record_with(&self, ied: &mut Ied, event: &Tracked, extra: &[(&str, Value)], now: Now) {
        let Some(reference) = self.select(ied, event) else { return };

        // The common half (Table 25), then the block-specific half, then `t` last — because `t`
        // is "the timestamp of the *completion* of the service" and writing it first would
        // stamp a report that had not finished being assembled.
        write(ied, &reference, "objRef", Value::VisibleString(event.obj_ref.clone()));
        write(
            ied,
            &reference,
            "serviceType",
            Value::Integer(enum_ordinal(ied, &reference, "serviceType", event.service.as_str(), event.service.table_ordinal())),
        );
        write(ied, &reference, "errorCode", Value::Integer(enum_ordinal(ied, &reference, "errorCode", event.error.as_str(), event.error.table_ordinal())));
        write(ied, &reference, "originatorID", Value::OctetString(event.originator.clone()));
        Tracking::mirror(ied, &reference, &event.obj_ref);
        for (attribute, value) in extra {
            write(ied, &reference, attribute, value.clone());
        }
        write(ied, &reference, "t", Value::UtcTime(now.wall));
    }

    /// The tracking object that records `event`, if the model has one.
    ///
    /// §14.1 puts **one** instance of each tracking class in a logical device, and for eight of
    /// the nine classes that is the whole of the lookup. `CTS` is the exception, and IEC
    /// 61850-7-4's `LTRK` is where it shows: the node carries `SpcTrk`, `DpcTrk`, `IncTrk`,
    /// `BscTrk` … — one control tracker per **kind of controlled object**, because a tracker
    /// has to declare a `ctlVal` and a `ctlVal` has a type 🌐 (libiec61850's
    /// `simpleIO_ltrk_tests.icd` declares exactly those four). Writing a double-point command
    /// into the single-point tracker would be a value of the wrong type in a data set a client
    /// reads positionally.
    ///
    /// The match is by `bType`, from the file on both sides — the tracker's `ctlVal` and the
    /// controlled object's — so no name table is needed here either. A logical device with one
    /// control tracker and no matching type still gets it: one tracker is unambiguous whatever
    /// it declares.
    fn select(&self, ied: &Ied, event: &Tracked) -> Option<String> {
        let (domain, _) = event.obj_ref.split_once('/')?;
        let mut candidates = self.trackers.iter().filter(|t| t.cdc == event.cdc && t.domain == domain);
        let first = candidates.next()?;
        if event.cdc != TrackingCdc::Cts || candidates.next().is_none() {
            return Some(first.reference.clone());
        }
        let wanted = ied.node_at(&alloc::format!("{}{}Oper{}ctlVal", event.obj_ref, tree_sep(), tree_sep())).and_then(|n| match &n.kind {
            crate::server::VarKind::Leaf(b) => Some(b.clone()),
            // A `ctlVal` is a leaf; a control object whose one is a structure or an array is
            // not one of the kinds `LTRK` distinguishes, so the first tracker stands.
            crate::server::VarKind::Structure | crate::server::VarKind::Array(_) => None,
        });
        let matched = wanted.and_then(|w| self.trackers.iter().find(|t| t.cdc == TrackingCdc::Cts && t.domain == domain && t.ctl_val.as_ref() == Some(&w)));
        Some(matched.unwrap_or(first).reference.clone())
    }

    /// Copy the block's own attributes into the tracker's same-named ones.
    ///
    /// The rule is one line of IEC 61850-7-2 read carefully: every tracking CDC's specific half
    /// is the control block's attribute set with a lower-case first letter, and §20.6.2's note 2
    /// says so out loud by pointing out the three that keep an upper-case one (`T`, `Test`,
    /// `Check`). Copying by name is therefore not a shortcut — it is the mapping. Its one
    /// exception is [`block_attribute`]'s.
    ///
    /// Only leaves the tracker actually declares are copied, and only when the block has one:
    /// a file whose `BTS` type omits `resvTms` gets a tracker without it rather than a server
    /// that answers `object-non-existent` for half of what it publishes (D41).
    fn mirror(ied: &mut Ied, tracker: &str, obj_ref: &str) {
        let names: Vec<String> = ied.leaves_of(tracker).iter().filter_map(|l| l.rsplit_once(tree_sep()).map(|(_, n)| String::from(n))).collect();
        for name in names {
            if COMMON.contains(&name.as_str()) {
                continue;
            }
            let Some(value) = block_attribute(ied, obj_ref, &name) else { continue };
            write(ied, tracker, &name, value);
        }
    }
}

/// The attributes of the common class (Table 25), which the engine writes itself and must not
/// try to copy off the control block.
const COMMON: [&str; 5] = ["objRef", "serviceType", "errorCode", "originatorID", "t"];

/// The MMS component separator, spelt once.
const fn tree_sep() -> char {
    super::tree::SEP
}

/// `rptID` → `RptID`. The one rule that maps a tracking attribute onto the control block's.
fn upper_first(name: &str) -> String {
    let mut chars = name.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// The control block attribute a tracking attribute mirrors, when the block has one.
///
/// The rule is [`upper_first`]; the fallback is the name in **full** upper case, and it exists
/// for exactly one attribute in the whole of IEC 61850-7-2. A report control block's general
/// interrogation is `GI` — two capitals — and its tracking attribute is `gi`, so `upper_first`
/// alone looks for a `Gi` that no model has and the busiest field of a `BTS` is silently left
/// empty. libiec61850's own `LTRK` model spells `gi` next to `rptID`, `entryID` and `goID`
/// (`simpleIO_ltrk_tests.icd`) 🌐, which is what says the rule is one rule with one exception
/// rather than a table.
///
/// The fallback is only consulted when the first form names nothing, so it can never shadow a
/// real attribute — and neither form invents one: a block without the attribute yields `None`
/// and the tracker keeps whatever it held.
fn block_attribute(ied: &Ied, obj_ref: &str, name: &str) -> Option<Value> {
    let read = |candidate: &str| ied.value(&alloc::format!("{obj_ref}{}{candidate}", tree_sep())).cloned();
    read(&upper_first(name)).or_else(|| {
        let shouted = name.to_uppercase();
        if shouted == upper_first(name) { None } else { read(&shouted) }
    })
}

/// Write one attribute of a tracker, if the model declares it.
fn write(ied: &mut Ied, tracker: &str, attribute: &str, value: Value) {
    let reference = alloc::format!("{tracker}{}{attribute}", tree_sep());
    if ied.value(&reference).is_some() {
        let _ = ied.write_leaf(&reference, value);
    }
}

/// The ordinal an enumeration name has **in this file**, or the standard's list position.
///
/// The names are IEC 61850-7-2's ✅ and the numbers are IEC 61850-8-1's, which is paywalled
/// (R2). A file that declares the `EnumType` has already answered the question, and answering
/// it a second way is how a server ends up disagreeing with its own engineering document.
fn enum_ordinal(ied: &Ied, tracker: &str, attribute: &str, name: &str, fallback: i64) -> i64 {
    let reference = alloc::format!("{tracker}{}{attribute}", tree_sep());
    ied.enum_ordinal(&reference, name).unwrap_or(fallback)
}

/// Every tracking data object of the model, as a flat list.
fn collect(model: &IedModel, out: &mut Vec<Tracker>) {
    for ld in &model.logical_devices {
        for ln in &ld.logical_nodes {
            for object in &ln.data_objects {
                let Some(cdc) = TrackingCdc::parse(&object.cdc) else { continue };
                // A tracking object's attributes are all `SR`; an object whose type says
                // otherwise is not the thing the standard describes, whatever its `cdc` says.
                if !object.attributes.iter().any(|a| a.fc == Fc::SR) {
                    continue;
                }
                out.push(Tracker {
                    domain: ld.name.clone(),
                    reference: alloc::format!("{}/{}{}{}{}{}", ld.name, ln.name, tree_sep(), Fc::SR.as_str(), tree_sep(), object.name),
                    cdc,
                    ctl_val: object.attributes.iter().find(|a| a.name == "ctlVal").map(|a| a.btype.clone()),
                });
            }
        }
    }
}

/// Build a [`Tracked`] for a control-block service, choosing the class from the block's own
/// functional constraint.
///
/// The mapping is the one IEC 61850-7-2 §15.3.2 draws: a buffered report control block is
/// tracked by `BTS`, an unbuffered one by `UTS`, and so on down to the setting group block.
/// Anything else is the common class, which exists precisely so that a service with no control
/// block behind it still has somewhere to go.
pub fn class_for(fc: Option<Fc>) -> TrackingCdc {
    match fc {
        Some(Fc::BR) => TrackingCdc::Bts,
        Some(Fc::RP) => TrackingCdc::Uts,
        Some(Fc::LG) => TrackingCdc::Lts,
        Some(Fc::GO) => TrackingCdc::Gts,
        Some(Fc::MS) => TrackingCdc::Mts,
        Some(Fc::US) => TrackingCdc::Nts,
        Some(Fc::SP) => TrackingCdc::Sts,
        Some(Fc::CO) => TrackingCdc::Cts,
        _ => TrackingCdc::Cst,
    }
}

/// The [`ServiceError`] a write result carries.
pub fn error_of(result: &Result<(), i64>) -> ServiceError {
    result.as_ref().map_or_else(|code| ServiceError::from_data_access(*code), |()| ServiceError::NoError)
}

/// The `SetXxxValues` service that writing an attribute of a control block under `fc` is.
pub const fn set_service(fc: Option<Fc>) -> ServiceType {
    match fc {
        Some(Fc::BR) => ServiceType::SetBRCBValues,
        Some(Fc::RP) => ServiceType::SetURCBValues,
        Some(Fc::LG) => ServiceType::SetLCBValues,
        Some(Fc::GO) => ServiceType::SetGoCBValues,
        Some(Fc::MS) => ServiceType::SetMSVCBValues,
        Some(Fc::US) => ServiceType::SetUSVCBValues,
        _ => ServiceType::SetDataValues,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_one_rule_that_maps_a_tracker_onto_a_control_block() {
        // Lower-case first letter, and nothing else changes — including the three IEC
        // 61850-7-2 §20.6.2 note 2 points out keep an upper-case one.
        assert_eq!(upper_first("rptID"), "RptID");
        assert_eq!(upper_first("goEna"), "GoEna");
        assert_eq!(upper_first("numOfSG"), "NumOfSG");
        assert_eq!(upper_first("T"), "T");
        assert_eq!(upper_first(""), "");
        // …and its one exception, which `upper_first` alone gets wrong: a report control
        // block's general interrogation is `GI`, not `Gi`, so the rule's fallback is the
        // shouted form and `block_attribute` is where the two are tried in order.
        assert_eq!(upper_first("gi"), "Gi");
        assert_ne!(upper_first("gi"), "GI");
    }

    #[test]
    fn the_class_follows_the_control_block_it_tracks() {
        assert_eq!(class_for(Some(Fc::BR)), TrackingCdc::Bts);
        assert_eq!(class_for(Some(Fc::RP)), TrackingCdc::Uts);
        assert_eq!(class_for(Some(Fc::US)), TrackingCdc::Nts);
        // A service with no control block behind it is what the common class is for.
        assert_eq!(class_for(Some(Fc::ST)), TrackingCdc::Cst);
        assert_eq!(class_for(None), TrackingCdc::Cst);
        assert_eq!(set_service(Some(Fc::BR)), ServiceType::SetBRCBValues);
        assert_eq!(set_service(None), ServiceType::SetDataValues);
    }
}
