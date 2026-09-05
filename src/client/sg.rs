//! Setting groups: switching the active one, and editing another without disturbing it.
//!
//! A setting group control block (`SGCB`) is a structured variable under the `SP` functional
//! constraint, so all six ACSI services are reads and writes — there is no MMS service for
//! any of them:
//!
//! | ACSI service | What it is |
//! |---|---|
//! | `GetSGCBValues` | read `LLN0$SP$SGCB` |
//! | `SelectActiveSG` | write `SGCB$ActSG` |
//! | `SelectEditSG` | write `SGCB$EditSG` |
//! | `SetEditSGValue` | write the setting itself, under `SE` |
//! | `GetEditSGValue` | read the setting, under `SE` |
//! | `ConfirmEditSGValues` | write `SGCB$CnfEdit` = true |
//!
//! The rule that catches everyone: **a setting under `SE` is the edit copy and a setting
//! under `SG` is the active one.** Writing to `SG` is refused; writing to `SE` changes
//! nothing until `CnfEdit`. [`Client::edit_setting_group`] does the whole sequence — select,
//! write, confirm — so the order cannot be got wrong, and refuses to confirm if any write was
//! rejected, because confirming a half-written group is how a protection setting ends up
//! half applied.

use alloc::string::String;
use alloc::vec::Vec;

use super::Client;
use crate::common::{Error, Fc, ObjectReference, Result};
use crate::proto::data::{Typed, Value};

/// A setting group control block, as the server currently has it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Sgcb {
    /// The reference this was read from, in MMS form (`IED1LD0/LLN0$SP$SGCB`).
    pub reference: String,
    /// `NumOfSG` — how many groups the device has.
    pub num_of_sg: Option<u32>,
    /// `ActSG` — which one is in force.
    pub act_sg: Option<u32>,
    /// `EditSG` — which one is being edited, or 0 for none.
    pub edit_sg: Option<u32>,
    /// `CnfEdit` — an edit is outstanding and not yet confirmed.
    pub cnf_edit: Option<bool>,
    /// `LActTm` — when the active group was last changed.
    pub last_activation: Option<crate::common::EntryTime>,
    /// `ResvTms` — how long the edit reservation lasts, in seconds (Edition 2).
    pub resv_tms: Option<i64>,
}

const SGCB_ATTRIBUTES: &[&str] = &["NumOfSG", "ActSG", "EditSG", "CnfEdit", "LActTm", "ResvTms"];

impl Client {
    /// `GetSGCBValues`: read the setting group control block of a logical device.
    ///
    /// `reference` is the block — `IED1LD0/LLN0$SP$SGCB`, or `IED1LD0/LLN0.SGCB`.
    pub fn read_sgcb(&mut self, reference: &str) -> Result<Sgcb> {
        let base = sgcb_base(reference)?;
        let names: Vec<String> = SGCB_ATTRIBUTES.iter().map(|a| alloc::format!("{base}${a}")).collect();
        let refs: Vec<(&str, Fc)> = names.iter().map(|n| (n.as_str(), Fc::SP)).collect();
        let values = self.read_many_results(&refs)?;
        let mut sgcb = Sgcb { reference: base, ..Sgcb::default() };
        for (attribute, value) in SGCB_ATTRIBUTES.iter().zip(values) {
            let Ok(v) = value else { continue };
            match *attribute {
                "NumOfSG" => sgcb.num_of_sg = unsigned(&v),
                "ActSG" => sgcb.act_sg = unsigned(&v),
                "EditSG" => sgcb.edit_sg = unsigned(&v),
                "CnfEdit" => sgcb.cnf_edit = v.as_bool(),
                "LActTm" => {
                    sgcb.last_activation = match &v {
                        Value::BinaryTime(b) => <[u8; 6]>::try_from(b.as_slice()).ok().map(crate::common::EntryTime::from_octets),
                        Value::UtcTime(t) => Some(crate::common::EntryTime::from_unix_millis(t.to_unix_nanos() / 1_000_000)),
                        _ => None,
                    }
                }
                "ResvTms" => sgcb.resv_tms = v.as_i64(),
                _ => {}
            }
        }
        if sgcb.num_of_sg.is_none() && sgcb.act_sg.is_none() {
            return Err(Error::NotFound("setting group control block"));
        }
        Ok(sgcb)
    }

    /// `SelectActiveSG`: put group `group` into force.
    ///
    /// This changes the settings the device is protecting with, immediately.
    pub fn select_active_setting_group(&mut self, reference: &str, group: u32) -> Result<()> {
        let base = sgcb_base(reference)?;
        self.write_sgcb(&base, "ActSG", Value::Unsigned(u64::from(group)))
    }

    /// `SelectEditSG`: reserve group `group` for editing. `0` releases the reservation.
    pub fn select_edit_setting_group(&mut self, reference: &str, group: u32) -> Result<()> {
        let base = sgcb_base(reference)?;
        self.write_sgcb(&base, "EditSG", Value::Unsigned(u64::from(group)))
    }

    /// `ConfirmEditSGValues`: apply everything written to the edit group.
    pub fn confirm_edit_setting_group(&mut self, reference: &str) -> Result<()> {
        let base = sgcb_base(reference)?;
        self.write_sgcb(&base, "CnfEdit", Value::Boolean(true))
    }

    /// `GetEditSGValue`: read a setting out of the **edit** copy (`SE`), not the active one.
    pub fn read_edit_setting(&mut self, setting: &str) -> Result<Value> {
        self.read(setting, Fc::SE)
    }

    /// `SetEditSGValue`: write one setting into the edit copy.
    ///
    /// Nothing changes until [`Client::confirm_edit_setting_group`].
    pub fn write_edit_setting(&mut self, setting: &str, value: &Value) -> Result<()> {
        self.write(setting, Fc::SE, value)
    }

    /// Select a group, write every setting into it, and confirm — the whole sequence.
    ///
    /// The settings go out in one `Write`, so a device sees them as one change. If any of
    /// them is refused the edit is **not** confirmed and the first refusal is returned: a
    /// half-written protection group that is then activated is the failure mode this exists
    /// to prevent. The reservation is released on the way out either way.
    pub fn edit_setting_group(&mut self, reference: &str, group: u32, settings: &[(&str, Value)]) -> Result<()> {
        let base = sgcb_base(reference)?;
        self.write_sgcb(&base, "EditSG", Value::Unsigned(u64::from(group)))?;
        let mut writes = Vec::with_capacity(settings.len());
        for (name, value) in settings {
            let parsed = ObjectReference::parse(name)?;
            let (domain, item) = parsed.to_mms(Fc::SE);
            writes.push((alloc::format!("{domain}/{item}"), value.clone()));
        }
        let outcome = if writes.is_empty() { Ok(()) } else { self.write_many(&writes).and_then(|r| r.into_iter().collect::<Result<Vec<()>>>().map(|_| ())) };
        match outcome {
            Ok(()) => {
                let confirmed = self.write_sgcb(&base, "CnfEdit", Value::Boolean(true));
                // Releasing the reservation is best-effort: the edit is already confirmed,
                // and a server that will not release it is not a reason to report failure.
                let _ = self.write_sgcb(&base, "EditSG", Value::Unsigned(0));
                confirmed
            }
            Err(e) => {
                // Give the group back rather than leaving it reserved by a client that has
                // stopped editing it.
                let _ = self.write_sgcb(&base, "EditSG", Value::Unsigned(0));
                Err(e)
            }
        }
    }

    fn write_sgcb(&mut self, base: &str, attribute: &str, value: Value) -> Result<()> {
        match self.write_many(&[(alloc::format!("{base}${attribute}"), value)])?.into_iter().next() {
            Some(r) => r,
            None => Err(Error::InvalidValue("empty Write response")),
        }
    }
}

/// Normalise a setting group control block reference to `LD/LN$SP$SGCB`.
fn sgcb_base(reference: &str) -> Result<String> {
    let parsed = ObjectReference::parse(reference)?;
    let fc = parsed.fc.unwrap_or(Fc::SP);
    if fc != Fc::SP {
        return Err(Error::InvalidReference("a setting group control block is under SP"));
    }
    let (domain, item) = parsed.to_mms(Fc::SP);
    let item = if parsed.path().count() == 0 { alloc::format!("{item}$SGCB") } else { item };
    Ok(alloc::format!("{domain}/{item}"))
}

fn unsigned(v: &Value) -> Option<u32> {
    match v {
        Value::Unsigned(n) => u32::try_from(*n).ok(),
        Value::Integer(i) => u32::try_from(*i).ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reference_normalises_to_the_control_block_under_sp() {
        assert_eq!(sgcb_base("IED1LD0/LLN0$SP$SGCB").unwrap(), "IED1LD0/LLN0$SP$SGCB");
        assert_eq!(sgcb_base("IED1LD0/LLN0.SGCB").unwrap(), "IED1LD0/LLN0$SP$SGCB");
        // The logical node alone is enough: there is exactly one SGCB per logical device and
        // it always lives in LLN0.
        assert_eq!(sgcb_base("IED1LD0/LLN0").unwrap(), "IED1LD0/LLN0$SP$SGCB");
        assert!(sgcb_base("IED1LD0/LLN0$ST$SGCB").is_err());
    }
}
