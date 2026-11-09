//! The in-kernel filter of a process-bus link: `EtherType` **and** destination.
//!
//! A frame passes when its EtherType — untagged, or behind one or two VLAN tags — is one of the
//! link's, and its destination is one of the joined groups, or (when no group is named) inside
//! the IEC 61850 multicast range for GOOSE or SV. Multicast membership alone does not do this:
//! an interface without a hardware filter (veth, a bridge port, a NIC in promiscuous mode)
//! delivers every group, so the destination is checked in the kernel too.

use alloc::string::String;
use alloc::vec::Vec;

use rawether::bpf::{ACCEPT, Insn, Program, op};

use crate::common::MacAddr;

/// What the destination must be.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Destinations {
    /// One of these addresses exactly.
    Exactly(Vec<MacAddr>),
    /// Any address starting with one of these four octets (01-0C-CD-01 is GOOSE, 01-0C-CD-04 SV).
    Prefixes(Vec<[u8; 4]>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Label {
    Types,
    Accept,
    Reject,
    Tagged,
    Double,
    /// The `n`-th exact-address candidate's second half.
    Low(usize),
    /// The candidate after the `n`-th.
    Next(usize),
}

/// A two-pass assembler: jumps name labels, resolved once every instruction is placed.
#[derive(Default)]
struct Asm {
    code: Vec<(Insn, Option<(Label, Label)>)>,
    labels: Vec<(Label, usize)>,
}

impl Asm {
    fn op(&mut self, code: u16, k: u32) {
        self.code.push((Insn::new(code, 0, 0, k), None));
    }
    /// `if A == k goto t else goto f`.
    fn jeq(&mut self, k: u32, t: Label, f: Label) {
        self.code.push((Insn::new(op::JMP | op::JEQ | op::K, 0, 0, k), Some((t, f))));
    }
    fn label(&mut self, l: Label) {
        self.labels.push((l, self.code.len()));
    }
    fn finish(self) -> Option<Vec<Insn>> {
        let at = |l: Label| self.labels.iter().find(|(x, _)| *x == l).map(|(_, pc)| *pc);
        self.code
            .iter()
            .enumerate()
            .map(|(pc, (insn, jumps))| {
                let mut insn = *insn;
                if let Some((t, f)) = jumps {
                    let rel = |l: Label| at(l).and_then(|target| target.checked_sub(pc + 1)).and_then(|d| u8::try_from(d).ok());
                    insn.jt = rel(*t)?;
                    insn.jf = rel(*f)?;
                }
                Some(insn)
            })
            .collect()
    }
}

/// The program for `types` and `destinations`. Errors when the sets are empty or too large to
/// encode as relative jumps (more than 16 types or 16 addresses).
pub(crate) fn program(types: &[u16], destinations: &Destinations) -> crate::Result<Program> {
    let too_many = |what: &'static str| crate::Error::Io(alloc::format!("a link filter takes at most 16 {what}"));
    if types.is_empty() || types.len() > 16 {
        return Err(too_many("EtherTypes (and at least one)"));
    }
    let mut a = Asm::default();
    // The destination.
    match destinations {
        Destinations::Prefixes(prefixes) => {
            if prefixes.is_empty() || prefixes.len() > 16 {
                return Err(too_many("address prefixes (and at least one)"));
            }
            a.op(op::LD | op::W | op::ABS, 0);
            for (i, p) in prefixes.iter().enumerate() {
                let next = if i + 1 == prefixes.len() { Label::Reject } else { Label::Next(i) };
                a.jeq(u32::from_be_bytes(*p), Label::Types, next);
                if i + 1 < prefixes.len() {
                    a.label(Label::Next(i));
                }
            }
        }
        Destinations::Exactly(macs) => {
            if macs.is_empty() || macs.len() > 16 {
                return Err(too_many("addresses (and at least one)"));
            }
            for (i, m) in macs.iter().enumerate() {
                let next = if i + 1 == macs.len() { Label::Reject } else { Label::Next(i) };
                let [b0, b1, b2, b3, b4, b5] = m.0;
                a.op(op::LD | op::W | op::ABS, 0);
                a.jeq(u32::from_be_bytes([b0, b1, b2, b3]), Label::Low(i), next);
                a.label(Label::Low(i));
                a.op(op::LD | op::H | op::ABS, 4);
                a.jeq(u32::from(u16::from_be_bytes([b4, b5])), Label::Types, next);
                if i + 1 < macs.len() {
                    a.label(Label::Next(i));
                }
            }
        }
    }
    // The EtherType: at 12, behind one tag at 16, behind two at 20.
    a.label(Label::Types);
    for (offset, here, then) in [(12, None, Label::Tagged), (16, Some(Label::Tagged), Label::Double), (20, Some(Label::Double), Label::Reject)] {
        if let Some(l) = here {
            a.label(l);
        }
        a.op(op::LD | op::H | op::ABS, offset);
        for (i, t) in types.iter().enumerate() {
            let _ = i;
            // Fall through to the next test: a jump of 0.
            a.code.push((Insn::new(op::JMP | op::JEQ | op::K, 0, 0, u32::from(*t)), Some((Label::Accept, FALL))));
        }
        if then == Label::Reject {
            a.code.push((Insn::new(op::JMP | op::JA, 0, 0, 0), None));
            // `ja 0` falls into the reject below.
        } else {
            a.code.push((Insn::new(op::JMP | op::JEQ | op::K, 0, 0, 0x8100), Some((then, FALL))));
            a.code.push((Insn::new(op::JMP | op::JEQ | op::K, 0, 0, 0x88a8), Some((then, Label::Reject))));
        }
    }
    a.label(Label::Reject);
    a.op(op::RET | op::K, 0);
    a.label(Label::Accept);
    a.op(op::RET | op::K, ACCEPT);
    let insns = resolve_fallthrough(a)?;
    Program::new(insns).map_err(|e| crate::Error::Io(alloc::format!("link filter: {e}")))
}

/// A sentinel label meaning "the next instruction".
const FALL: Label = Label::Next(usize::MAX);

fn resolve_fallthrough(mut a: Asm) -> crate::Result<Vec<Insn>> {
    // Give every `FALL` its own label at the following instruction.
    for (pc, (_, jumps)) in a.code.iter_mut().enumerate() {
        a.labels.push((Label::Next(usize::MAX - 1 - pc), pc + 1));
        if let Some((t, f)) = jumps.as_mut() {
            if *t == FALL {
                *t = Label::Next(usize::MAX - 1 - pc);
            }
            if *f == FALL {
                *f = Label::Next(usize::MAX - 1 - pc);
            }
        }
    }
    a.finish().ok_or_else(|| crate::Error::Io(String::from("link filter: a jump does not fit")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(dst: [u8; 6], types: &[u16]) -> Vec<u8> {
        let mut f = dst.to_vec();
        f.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
        for t in types {
            f.extend_from_slice(&t.to_be_bytes());
            f.extend_from_slice(&[0x80, 0x05]);
        }
        f.resize(64, 0);
        f
    }

    const GOOSE_DST: [u8; 6] = [0x01, 0x0c, 0xcd, 0x01, 0x00, 0x05];
    const SV_DST: [u8; 6] = [0x01, 0x0c, 0xcd, 0x04, 0x00, 0x01];

    #[test]
    fn the_iec_ranges_and_types_pass_and_nothing_else_does() {
        let p = program(&[0x88b8, 0x88ba], &Destinations::Prefixes(alloc::vec![[1, 0x0c, 0xcd, 1], [1, 0x0c, 0xcd, 4]])).unwrap();
        for ok in [frame(GOOSE_DST, &[0x88b8]), frame(SV_DST, &[0x8100, 0x88ba]), frame(GOOSE_DST, &[0x88a8, 0x8100, 0x88b8])] {
            assert_eq!(p.run(&ok), ACCEPT);
        }
        for bad in [
            frame(GOOSE_DST, &[0x0800]),
            frame([1, 0x80, 0xc2, 0, 0, 0xe], &[0x88b8]),
            frame([0xff; 6], &[0x88ba]),
            frame(GOOSE_DST, &[0x8100, 0x8100, 0x8100, 0x88b8]),
        ] {
            assert_eq!(p.run(&bad), 0);
        }
        assert_eq!(p.run(&[0u8; 10]), 0);
    }

    #[test]
    fn exact_groups_admit_only_themselves() {
        let joined = Destinations::Exactly(alloc::vec![MacAddr(GOOSE_DST), MacAddr(SV_DST)]);
        let p = program(&[0x88b8, 0x88ba], &joined).unwrap();
        assert_eq!(p.run(&frame(GOOSE_DST, &[0x88b8])), ACCEPT);
        assert_eq!(p.run(&frame(SV_DST, &[0x88ba])), ACCEPT);
        let mut other = GOOSE_DST;
        other[5] = 6;
        assert_eq!(p.run(&frame(other, &[0x88b8])), 0, "a group nobody joined");
        other = GOOSE_DST;
        other[2] = 0;
        assert_eq!(p.run(&frame(other, &[0x88b8])), 0, "the high half differs");
    }

    #[test]
    fn sizes_are_bounded() {
        assert!(program(&[], &Destinations::Prefixes(alloc::vec![[1, 2, 3, 4]])).is_err());
        assert!(program(&[1], &Destinations::Exactly(Vec::new())).is_err());
        let many: Vec<MacAddr> = (0..16).map(|i| MacAddr([1, 0x0c, 0xcd, 1, 0, i])).collect();
        let p = program(&[0x88b8, 0x88ba], &Destinations::Exactly(many.clone())).unwrap();
        for m in &many {
            assert_eq!(p.run(&frame(m.0, &[0x88b8])), ACCEPT);
        }
        let mut more = many;
        more.push(MacAddr([1, 0x0c, 0xcd, 1, 0, 99]));
        assert!(program(&[0x88b8], &Destinations::Exactly(more)).is_err());
    }
}
