//! Setting groups, server side.
//!
//! A setting has one value **per group**, and two functional constraints reach it:
//!
//! - `SG` is the **active** group's value. It is read-only: what is in force changes only by
//!   activating a group, never by writing a setting.
//! - `SE` is the **edit** group's value. Writing it changes nothing until `CnfEdit`.
//!
//! Everything else is the `SGCB`: `ActSG` puts a group into force, `EditSG` reserves one for
//! editing, and `CnfEdit` applies the edit. The rules the server enforces are the ones that
//! stop a half-written protection group being activated:
//!
//! - **`SE` is unreadable and unwritable until a group is selected for editing.** IEC
//!   61850-7-2 §11: with `EditSG = 0` there is no edit copy, and a server that invents one
//!   lets a client write settings into nowhere.
//! - **The edit belongs to one client.** A second client that writes `EditSG` while another
//!   holds it is refused.
//! - **`CnfEdit` applies the whole group or none of it**, which is why the edit copy exists
//!   at all rather than writing `SG` directly.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::result::Result;

use super::acsi::AssocId;
use super::ied::{BlockKind, DATA_ACCESS_DENIED, DATA_ACCESS_VALUE_INVALID, Ied};
use crate::common::{Fc, Instant, Now};
use crate::proto::data::Value;

/// One logical device's setting groups.
#[derive(Debug)]
struct Groups {
    /// The setting group control block, `IED1LD0/LLN0$SP$SGCB`.
    block: String,
    /// The logical device the settings live in.
    domain: String,
    /// How many groups the device has.
    count: u32,
    /// Values per group: `group → (setting reference under SG → value)`. The reference is the
    /// **`SG`** form, which is the one the model publishes; the `SE` form differs only in its
    /// functional constraint.
    values: BTreeMap<u32, BTreeMap<String, Value>>,
    /// The association that holds the edit reservation.
    editor: Option<AssocId>,
    /// When that reservation lapses, from the `SGCB`'s `ResvTms`.
    ///
    /// A client that selects a group for editing and then goes quiet without closing its
    /// association would otherwise hold the whole logical device's settings for ever;
    /// `ResvTms` is the attribute that exists to stop it, and a server that publishes it and
    /// never acts on it is the case D40 is about.
    editor_until: Option<Instant>,
}

/// The setting-group engine over every logical device of an [`Ied`].
#[derive(Debug, Default)]
pub struct SettingGroups {
    devices: Vec<Groups>,
}

impl SettingGroups {
    /// Build the engine from the model, seeding every group from the engineered values.
    ///
    /// A setting whose `DAI` carries one `Val` per `sGroup` gets each group's own value; one
    /// with a single ungrouped `Val` gets that value in *every* group, which is what a file
    /// that engineers one setting set means.
    pub fn new(ied: &Ied) -> SettingGroups {
        let mut devices = Vec::new();
        for block in ied.blocks().iter().filter(|b| b.kind == BlockKind::SettingGroup) {
            let count = ied.value(&alloc::format!("{}$NumOfSG", block.reference)).and_then(unsigned_of).unwrap_or(1).max(1);
            let mut values: BTreeMap<u32, BTreeMap<String, Value>> = (1..=count).map(|g| (g, BTreeMap::new())).collect();
            for (reference, per_group, fallback) in settings_of(ied, &block.domain) {
                for group in 1..=count {
                    let value = per_group.iter().find(|(g, _)| *g == group).and_then(|(_, text)| ied.parse_text(&reference, text)).or_else(|| fallback.clone());
                    if let Some(v) = value {
                        if let Some(slot) = values.get_mut(&group) {
                            slot.insert(reference.clone(), v);
                        }
                    }
                }
            }
            devices.push(Groups { block: block.reference.clone(), domain: block.domain.clone(), count, values, editor: None, editor_until: None });
        }
        SettingGroups { devices }
    }

    /// The control block of the logical device a reference belongs to.
    fn device(&self, domain: &str) -> Option<&Groups> {
        self.devices.iter().find(|g| g.domain == domain)
    }

    fn device_mut(&mut self, domain: &str) -> Option<&mut Groups> {
        self.devices.iter_mut().find(|g| g.domain == domain)
    }

    /// Whether `reference` is a setting group control block attribute.
    pub fn is_block(&self, reference: &str) -> Option<(String, String)> {
        let (block, attribute) = reference.rsplit_once('$')?;
        self.devices.iter().find(|g| g.block == block).map(|_| (String::from(block), String::from(attribute)))
    }

    /// Put the engineered active group into force at start-up.
    pub fn activate_initial(&mut self, ied: &mut Ied) {
        let plan: Vec<(String, u32)> =
            self.devices.iter().map(|g| (g.domain.clone(), ied.value(&alloc::format!("{}$ActSG", g.block)).and_then(unsigned_of).unwrap_or(1))).collect();
        for (domain, group) in plan {
            self.apply_group(ied, &domain, group);
        }
    }

    /// A write to an `SGCB` attribute.
    pub fn on_block_write(&mut self, assoc: AssocId, ied: &mut Ied, block: &str, attribute: &str, value: &Value, now: Now) -> Result<(), i64> {
        let Some(domain) = self.devices.iter().find(|g| g.block == block).map(|g| g.domain.clone()) else { return Ok(()) };
        // An expired reservation is released before the write is judged, or a client would be
        // refused by a hold that has already run out.
        self.expire(now.mono);
        let wall = now.wall;
        match attribute {
            "ActSG" => {
                let Some(group) = unsigned_of(value) else { return Err(DATA_ACCESS_VALUE_INVALID) };
                if !self.device(&domain).is_some_and(|g| group >= 1 && group <= g.count) {
                    return Err(DATA_ACCESS_VALUE_INVALID);
                }
                self.apply_group(ied, &domain, group);
                let _ = ied.set_internal(&alloc::format!("{block}$LActTm"), Value::BinaryTime(wall.to_octets().to_vec()));
                Ok(())
            }
            "EditSG" => {
                let Some(group) = unsigned_of(value) else { return Err(DATA_ACCESS_VALUE_INVALID) };
                let Some(g) = self.device_mut(&domain) else { return Ok(()) };
                if group == 0 {
                    // Releasing: only the client that holds it may, and doing so abandons
                    // whatever it had written into the edit copy.
                    if g.editor.is_some_and(|e| e != assoc) {
                        return Err(DATA_ACCESS_DENIED);
                    }
                    g.editor = None;
                    g.editor_until = None;
                    return Ok(());
                }
                if group > g.count {
                    return Err(DATA_ACCESS_VALUE_INVALID);
                }
                if g.editor.is_some_and(|e| e != assoc) {
                    return Err(DATA_ACCESS_DENIED);
                }
                g.editor = Some(assoc);
                g.editor_until = reservation_deadline(ied, block, now.mono);
                let group_values = g.values.get(&group).cloned().unwrap_or_default();
                // Selecting a group for editing fills the edit copy with what that group
                // currently holds, so a client that changes one setting does not blank the
                // rest when it confirms. It is the *server* filling in a scratch copy, so it
                // goes in through `set_internal` and does not make a report claim the
                // settings changed — nothing in force has moved.
                for (reference, v) in group_values {
                    let _ = ied.set_internal(&edit_reference(&reference), v);
                }
                Ok(())
            }
            "CnfEdit" => {
                if !bool_of(value).unwrap_or(false) {
                    return Ok(());
                }
                let Some(g) = self.device_mut(&domain) else { return Ok(()) };
                if g.editor.is_some_and(|e| e != assoc) {
                    return Err(DATA_ACCESS_DENIED);
                }
                let group = ied.value(&alloc::format!("{block}$EditSG")).and_then(unsigned_of).unwrap_or(0);
                if group == 0 || group > g.count {
                    // Confirming with no group selected is the mistake this exists to catch.
                    return Err(DATA_ACCESS_DENIED);
                }
                let references: Vec<String> = g.values.get(&group).map(|m| m.keys().cloned().collect()).unwrap_or_default();
                let mut edited = BTreeMap::new();
                for reference in references {
                    if let Some(v) = ied.value(&edit_reference(&reference)) {
                        edited.insert(reference, v.clone());
                    }
                }
                if let Some(slot) = g.values.get_mut(&group) {
                    for (reference, v) in edited {
                        slot.insert(reference, v);
                    }
                }
                let active = ied.value(&alloc::format!("{block}$ActSG")).and_then(unsigned_of).unwrap_or(1);
                let domain = g.domain.clone();
                // Confirming the group that is *in force* changes the settings the device is
                // protecting with, immediately. That is the standard's behaviour and it is
                // why a half-written group must never get this far.
                if active == group {
                    self.apply_group(ied, &domain, group);
                }
                Ok(())
            }
            // `ResvTms` is how long the *client* wants the edit reservation held for, so it
            // is the client's to write — and writing it re-arms a reservation already held.
            "ResvTms" => {
                let Some(seconds) = unsigned_of(value) else { return Err(DATA_ACCESS_VALUE_INVALID) };
                let Some(g) = self.device_mut(&domain) else { return Ok(()) };
                if g.editor.is_some_and(|e| e != assoc) {
                    return Err(DATA_ACCESS_DENIED);
                }
                if g.editor == Some(assoc) {
                    g.editor_until = (seconds > 0).then(|| now.mono.plus_millis(u64::from(seconds) * 1000));
                }
                Ok(())
            }
            // `NumOfSG` and `LActTm` are the device's to say, not the client's.
            _ => Err(DATA_ACCESS_DENIED),
        }
    }

    /// A **read** of a setting under `SE`.
    ///
    /// `GetEditSGValue` is rejected while `EditSG = 0` (IEC 61850-7-2 §11): with no group
    /// selected there is no edit copy, and answering with the scratch the model was seeded
    /// with would tell a client it is looking at a setting group when it is not.
    ///
    /// The reservation itself is *not* checked. A second client may look at what the first is
    /// editing — that is an operator watching a change being made, and refusing it would hide
    /// the one thing an operator most wants to see.
    pub fn on_edit_read(&self, assoc: AssocId, ied: &Ied, reference: &str) -> Result<(), i64> {
        let _ = assoc;
        let Some((domain, _)) = reference.split_once('/') else { return Err(DATA_ACCESS_DENIED) };
        let Some(g) = self.device(domain) else { return Err(DATA_ACCESS_DENIED) };
        let group = ied.value(&alloc::format!("{}$EditSG", g.block)).and_then(unsigned_of).unwrap_or(0);
        if group == 0 { Err(DATA_ACCESS_DENIED) } else { Ok(()) }
    }

    /// A write to a setting under `SE`.
    pub fn on_edit_write(&mut self, assoc: AssocId, ied: &Ied, reference: &str) -> Result<(), i64> {
        let Some((domain, _)) = reference.split_once('/') else { return Err(DATA_ACCESS_DENIED) };
        let Some(g) = self.device(domain) else { return Err(DATA_ACCESS_DENIED) };
        let group = ied.value(&alloc::format!("{}$EditSG", g.block)).and_then(unsigned_of).unwrap_or(0);
        // With no group selected there is no edit copy, and a server that accepts the write
        // anyway lets a client believe it has changed a setting it has not.
        if group == 0 {
            return Err(DATA_ACCESS_DENIED);
        }
        if g.editor.is_some_and(|e| e != assoc) {
            return Err(DATA_ACCESS_DENIED);
        }
        Ok(())
    }

    /// A write to a setting under `SG` — always refused: what is in force changes by
    /// activating a group, never by writing a value into it.
    pub const fn on_active_write() -> Result<(), i64> {
        Err(DATA_ACCESS_DENIED)
    }

    /// An association ended: release the edit reservation it held.
    ///
    /// Unlike a report control block's `ResvTms`, this one does **not** outlive the
    /// association. A report reservation exists so a client can come back to a subscription;
    /// an edit reservation holds a half-written protection group, and leaving a device's
    /// settings locked by a client that is gone is the opposite of what `CnfEdit` is for.
    pub fn on_association_closed(&mut self, assoc: AssocId) {
        for g in &mut self.devices {
            if g.editor == Some(assoc) {
                g.editor = None;
                g.editor_until = None;
            }
        }
    }

    /// Release edit reservations whose `ResvTms` has run out.
    pub fn on_timeout(&mut self, ied: &mut Ied, now: Instant) {
        let lapsed: Vec<String> =
            self.devices.iter().filter(|g| g.editor.is_some() && g.editor_until.is_some_and(|u| now >= u)).map(|g| g.block.clone()).collect();
        self.expire(now);
        // `EditSG` back to zero, because "no group is selected" is what the release means and
        // a client reading the block has to see it.
        for block in lapsed {
            let _ = ied.set_internal(&alloc::format!("{block}$EditSG"), Value::Unsigned(0));
        }
    }

    /// When this layer next needs [`SettingGroups::on_timeout`].
    pub fn next_timeout(&self) -> Option<Instant> {
        self.devices.iter().filter(|g| g.editor.is_some()).filter_map(|g| g.editor_until).min()
    }

    fn expire(&mut self, now: Instant) {
        for g in &mut self.devices {
            if g.editor_until.is_some_and(|u| now >= u) {
                g.editor = None;
                g.editor_until = None;
            }
        }
    }

    /// `CnfEdit` is a **command**, not a state: it is written true to apply the edit and the
    /// server puts it back, exactly as `GI` and `PurgeBuf` work on a report control block. A
    /// server that leaves it true answers "is an edit being confirmed?" with yes for ever.
    pub fn after_block_write(&mut self, ied: &mut Ied, block: &str, attribute: &str) {
        if attribute == "CnfEdit" && self.devices.iter().any(|g| g.block == block) {
            let _ = ied.set_internal(&alloc::format!("{block}$CnfEdit"), Value::Boolean(false));
        }
    }

    /// Copy a group's values into the active (`SG`) settings.
    fn apply_group(&mut self, ied: &mut Ied, domain: &str, group: u32) {
        let Some(g) = self.devices.iter().find(|g| g.domain == domain) else { return };
        let block = g.block.clone();
        let Some(values) = g.values.get(&group).cloned() else { return };
        for (reference, v) in values {
            let _ = ied.write_leaf(&reference, v);
        }
        let _ = ied.write_leaf(&alloc::format!("{block}$ActSG"), Value::Unsigned(u64::from(group)));
    }
}

/// When an edit reservation taken now lapses, from the block's `ResvTms`.
///
/// Zero — the usual engineered value — means no deadline: the reservation then lives exactly
/// as long as the association does.
fn reservation_deadline(ied: &Ied, block: &str, now: Instant) -> Option<Instant> {
    let seconds = ied.value(&alloc::format!("{block}$ResvTms")).and_then(unsigned_of).unwrap_or(0);
    (seconds > 0).then(|| now.plus_millis(u64::from(seconds) * 1000))
}

/// The `SE` form of a setting whose `SG` reference is given.
fn edit_reference(sg: &str) -> String {
    sg.replacen("$SG$", "$SE$", 1)
}

/// One setting: its `SG` reference, its per-group engineered texts, and the value the type
/// template gave it when the file engineers no groups at all.
type Setting = (String, Vec<(u32, String)>, Option<Value>);

/// Every setting of a logical device, with its per-group and ungrouped engineered values.
fn settings_of(ied: &Ied, domain: &str) -> Vec<Setting> {
    let mut out = Vec::new();
    let Some(ld) = ied.model.logical_devices.iter().find(|ld| ld.name == domain) else { return out };
    for ln in &ld.logical_nodes {
        for object in &ln.data_objects {
            walk(ied, domain, &ln.name, &object.name, object, &mut out);
        }
    }
    out
}

fn walk(ied: &Ied, domain: &str, ln: &str, do_path: &str, object: &crate::model::DataObject, out: &mut Vec<Setting>) {
    fn attribute(ied: &Ied, prefix: &str, a: &crate::model::DataAttribute, out: &mut Vec<Setting>) {
        let path = alloc::format!("{prefix}${}", a.name);
        if a.fc == Fc::SG || a.fc == Fc::SE {
            let fallback = ied.value(&path).cloned();
            out.push((path.clone(), a.group_values.clone(), fallback));
        }
        for c in &a.children {
            attribute(ied, &path, c, out);
        }
    }
    for a in &object.attributes {
        // Only the settings: `SG` is what is in force and `SE` is the edit copy of it, and the
        // engine stores them under the `SG` name.
        if a.fc == Fc::SG {
            attribute(ied, &alloc::format!("{domain}/{ln}$SG${do_path}"), a, out);
        }
    }
    for s in &object.sub_objects {
        walk(ied, domain, ln, &alloc::format!("{do_path}${}", s.name), s, out);
    }
}

fn unsigned_of(v: &Value) -> Option<u32> {
    match v {
        Value::Unsigned(n) => u32::try_from(*n).ok(),
        Value::Integer(n) => u32::try_from(*n).ok(),
        _ => None,
    }
}

fn bool_of(v: &Value) -> Option<bool> {
    match v {
        Value::Boolean(b) => Some(*b),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_edit_copy_of_a_setting_is_the_same_name_under_a_different_constraint() {
        assert_eq!(edit_reference("IED1LD0/PTOC1$SG$StrVal$setMag$f"), "IED1LD0/PTOC1$SE$StrVal$setMag$f");
        // Only the constraint changes, and only the first occurrence of it: a data object
        // called `SG` further down the path is not a functional constraint.
        assert_eq!(edit_reference("IED1LD0/PTOC1$SG$SGx$SG$f"), "IED1LD0/PTOC1$SE$SGx$SG$f");
    }
}
