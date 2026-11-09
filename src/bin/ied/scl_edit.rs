//! `ied scl edit`: one engineering edit, written through the SCL editing DOM.
//!
//! The file is refused above a size limit before it is read; the edit is validated against the
//! file as it was, and refused if it adds an error; an in-place write replaces the file
//! atomically; `--dry-run` shows the diff instead of writing.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::Path;

use iec61850_rs::common::Edition;
use iec61850_rs::model::{GseAddress, SmvAddress};
use iec61850_rs::proto::ethernet::MacAddr;
use iec61850_rs::scl::{self, Document, Hitem};

/// Above this an input is refused before it is read; `--max-size` changes it.
const DEFAULT_MAX_SIZE: u64 = 1 << 30;

#[derive(Default)]
struct Options<'a> {
    out: Option<&'a str>,
    in_place: bool,
    dry_run: bool,
    check: bool,
    force: bool,
    max_size: Option<u64>,
    freq: Option<u32>,
    who: Option<&'a str>,
    what: Option<&'a str>,
    why: Option<&'a str>,
    version: Option<&'a str>,
    revision: Option<&'a str>,
    mac: Option<&'a str>,
    appid: Option<&'a str>,
    vlan: Option<&'a str>,
    vlan_priority: Option<&'a str>,
    min_time: Option<&'a str>,
    max_time: Option<&'a str>,
}

pub fn run(file: &str, args: &[&str]) -> Result<(), String> {
    let (op, rest) = args.split_first().ok_or("scl edit needs an operation; see `ied --help`")?;
    let mut o = Options::default();
    let mut positional = Vec::new();
    let mut it = rest.iter();
    while let Some(arg) = it.next() {
        let mut value = || it.next().copied().ok_or_else(|| format!("{arg} needs a value"));
        match *arg {
            "-o" | "--out" => o.out = Some(value()?),
            "--in-place" => o.in_place = true,
            "--dry-run" => o.dry_run = true,
            "--check" => o.check = true,
            "--force" => o.force = true,
            "--max-size" => o.max_size = Some(value()?.parse().map_err(|_| "--max-size needs a number of bytes".to_string())?),
            "--freq" => o.freq = Some(value()?.parse().map_err(|_| "--freq needs a number".to_string())?),
            "--who" => o.who = Some(value()?),
            "--what" => o.what = Some(value()?),
            "--why" => o.why = Some(value()?),
            "--version" => o.version = Some(value()?),
            "--revision" => o.revision = Some(value()?),
            "--mac" => o.mac = Some(value()?),
            "--appid" => o.appid = Some(value()?),
            "--vlan" => o.vlan = Some(value()?),
            "--vlan-priority" => o.vlan_priority = Some(value()?),
            "--min-time" => o.min_time = Some(value()?),
            "--max-time" => o.max_time = Some(value()?),
            other if other.starts_with('-') => return Err(format!("unknown option `{other}`")),
            other => positional.push(other),
        }
    }
    if o.in_place && o.out.is_some() {
        return Err("--in-place and -o are exclusive".into());
    }

    let max = o.max_size.unwrap_or(DEFAULT_MAX_SIZE);
    let size = fs::metadata(file).map_err(|e| format!("{file}: {e}"))?.len();
    if size > max {
        return Err(format!("{file}: {size} bytes is above the {max}-byte limit (--max-size)"));
    }
    let bytes = fs::read(file).map_err(|e| format!("{file}: {e}"))?;
    let mut doc = Document::from_bytes(bytes).map_err(|e| format!("{file}: {e}"))?;
    let before = doc.as_str().to_string();

    let what = apply(&mut doc, op, &positional, &o)?;
    if *op != "history" && (o.who.is_some() || o.why.is_some()) {
        let item = hitem(&doc, &o, Some(o.what.unwrap_or(&what)))?;
        doc.add_history(&item).map_err(|e| e.to_string())?;
    }
    let changes: usize = doc.history().iter().map(|t| t.patches().len()).sum();

    let freq = o.freq.unwrap_or(50);
    let (old, new) = (error_codes(&before, freq)?, error_codes(doc.as_str(), freq)?);
    let added: Vec<String> = new.iter().filter(|(code, n)| old.get(*code).copied().unwrap_or(0) < **n).map(|(code, n)| format!("{code} ({n})")).collect();
    if !added.is_empty() && !o.force {
        return Err(format!("the edit adds validation errors: {}; nothing written (--force to write anyway)", added.join(", ")));
    }
    if o.check && !new.is_empty() {
        return Err(format!("the result has validation errors ({}); nothing written", new.keys().cloned().collect::<Vec<_>>().join(", ")));
    }

    if o.dry_run {
        print!("{}", unified_diff(&before, doc.as_str(), file));
    } else if o.in_place {
        write_atomically(Path::new(file), doc.as_str())?;
    } else if let Some(out) = o.out {
        write_atomically(Path::new(out), doc.as_str())?;
    } else {
        print!("{}", doc.as_str());
    }
    eprintln!("{what}: {changes} change(s)");
    Ok(())
}

fn apply(doc: &mut Document, op: &str, p: &[&str], o: &Options<'_>) -> Result<String, String> {
    let arity = |n: usize| if p.len() == n { Ok(()) } else { Err(format!("`scl edit {op}` takes {n} argument(s), got {}", p.len())) };
    let e = |e: iec61850_rs::Error| e.to_string();
    match (op, p) {
        ("rename-ied", [old, new]) => doc.rename_ied(old, new).map(|_| format!("rename IED {old} → {new}")).map_err(e),
        ("remove-ied", [name]) => doc.remove_ied(name).map(|_| format!("remove IED {name}")).map_err(e),
        ("gse", [ied, ld, cb]) => {
            let cur = current_gse(doc, ied, ld, cb);
            let address = GseAddress {
                mac: mac(o.mac, cur.as_ref().map(|c| c.mac))?,
                appid: hex16(o.appid, cur.as_ref().map(|c| c.appid), "--appid")?,
                vlan_id: hex16(o.vlan, cur.as_ref().map(|c| c.vlan_id).or(Some(0)), "--vlan")?,
                vlan_priority: num(o.vlan_priority, cur.as_ref().map(|c| c.vlan_priority).or(Some(4)), "--vlan-priority")?,
                min_time_ms: o.min_time.map(|v| v.parse().map_err(|_| "--min-time needs milliseconds".to_string())).transpose()?,
                max_time_ms: o.max_time.map(|v| v.parse().map_err(|_| "--max-time needs milliseconds".to_string())).transpose()?,
            };
            doc.set_gse_address(ied, ld, cb, &address).map(|_| format!("set GSE address of {ied}{ld}/{cb}")).map_err(e)
        }
        ("smv", [ied, ld, cb]) => {
            let cur = current_smv(doc, ied, ld, cb);
            let address = SmvAddress {
                mac: mac(o.mac, cur.as_ref().map(|c| c.mac))?,
                appid: hex16(o.appid, cur.as_ref().map(|c| c.appid), "--appid")?,
                vlan_id: hex16(o.vlan, cur.as_ref().map(|c| c.vlan_id).or(Some(0)), "--vlan")?,
                vlan_priority: num(o.vlan_priority, cur.as_ref().map(|c| c.vlan_priority).or(Some(4)), "--vlan-priority")?,
            };
            doc.set_smv_address(ied, ld, cb, &address).map(|_| format!("set SMV address of {ied}{ld}/{cb}")).map_err(e)
        }
        ("ap-address", [ied, ap, p_type, value]) => doc.set_ap_address(ied, ap, p_type, value).map(|_| format!("set {p_type} of {ied}/{ap}")).map_err(e),
        ("history", []) => {
            let item = hitem(doc, o, o.what)?;
            doc.add_history(&item).map(|_| String::from("add history item")).map_err(e)
        }
        ("rename-ied", _) => arity(2).map(|()| String::new()),
        ("remove-ied", _) => arity(1).map(|()| String::new()),
        ("gse" | "smv", _) => arity(3).map(|()| String::new()),
        ("ap-address", _) => arity(4).map(|()| String::new()),
        ("history", _) => arity(0).map(|()| String::new()),
        (other, _) => Err(format!("unknown edit `{other}` (rename-ied, remove-ied, gse, smv, ap-address, history)")),
    }
}

fn current_gse(doc: &Document, ied: &str, ld: &str, cb: &str) -> Option<GseAddress> {
    let model = doc.scl().ok()?.model(Some(ied)).ok()?;
    let ld = model.logical_devices.iter().find(|l| l.inst == ld)?;
    ld.logical_nodes.iter().flat_map(|n| &n.gse_controls).find(|g| g.name == cb)?.address.clone()
}

fn current_smv(doc: &Document, ied: &str, ld: &str, cb: &str) -> Option<SmvAddress> {
    let model = doc.scl().ok()?.model(Some(ied)).ok()?;
    let ld = model.logical_devices.iter().find(|l| l.inst == ld)?;
    ld.logical_nodes.iter().flat_map(|n| &n.smv_controls).find(|s| s.name == cb)?.address.clone()
}

fn mac(given: Option<&str>, current: Option<MacAddr>) -> Result<MacAddr, String> {
    match given {
        Some(m) => MacAddr::parse(m).map_err(|_| format!("--mac {m:?} is not a MAC address")),
        None => current.ok_or_else(|| "the block has no address yet; give --mac".to_string()),
    }
}

fn hex16(given: Option<&str>, current: Option<u16>, flag: &str) -> Result<u16, String> {
    match given {
        Some(v) => u16::from_str_radix(v.trim_start_matches("0x"), 16).map_err(|_| format!("{flag} needs a hexadecimal number")),
        None => current.ok_or_else(|| format!("the block has no address yet; give {flag}")),
    }
}

fn num(given: Option<&str>, current: Option<u8>, flag: &str) -> Result<u8, String> {
    match given {
        Some(v) => v.parse().map_err(|_| format!("{flag} needs a number")),
        None => current.ok_or_else(|| format!("give {flag}")),
    }
}

/// A history item; `version` and `revision` default to the header's own.
fn hitem(doc: &Document, o: &Options<'_>, what: Option<&str>) -> Result<Hitem, String> {
    let (version, revision) = doc
        .read(|root| root.child("Header").map(|h| (h.attr_or_empty("version").to_string(), h.attr_or_empty("revision").to_string())))
        .map_err(|e| e.to_string())?
        .unwrap_or_default();
    Ok(Hitem {
        version: o.version.map_or(version, String::from),
        revision: o.revision.map_or(revision, String::from),
        when: now_rfc3339(),
        who: o.who.map(String::from),
        what: what.map(String::from),
        why: o.why.map(String::from),
    })
}

/// Validator errors per finding code. `at` and `message` carry names an edit legitimately
/// changes, so the comparison is by code.
fn error_codes(text: &str, freq: u32) -> Result<BTreeMap<String, usize>, String> {
    let report = scl::validate(text, freq, Edition::Ed2_1).map_err(|e| e.to_string())?;
    let mut out = BTreeMap::new();
    for f in report.errors() {
        *out.entry(format!("{:?}", f.code)).or_insert(0) += 1;
    }
    Ok(out)
}

/// Write to a temporary file beside the target, flush it to disk, then rename it over the
/// target: a crash leaves either the old file or the new one, never half of either.
fn write_atomically(path: &Path, text: &str) -> Result<(), String> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let name = path.file_name().ok_or_else(|| format!("{}: not a file name", path.display()))?;
    let tmp = dir.join(format!(".{}.ied-{}.tmp", name.to_string_lossy(), std::process::id()));
    let result = (|| -> std::io::Result<()> {
        let mut f = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        if let Ok(m) = fs::metadata(path) {
            fs::set_permissions(&tmp, m.permissions())?;
        }
        fs::rename(&tmp, path)?;
        // Make the rename itself durable where the platform allows opening a directory.
        if let Ok(d) = fs::File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(())
    })();
    result.map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!("{}: {e}; the original is unchanged", path.display())
    })
}

/// `YYYY-MM-DDTHH:MM:SSZ` for now.
fn now_rfc3339() -> String {
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Civil from days (Howard Hinnant's algorithm), in integers.
    let z = i64::try_from(days).unwrap_or(0) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// A unified diff with three lines of context. Common leading and trailing lines are trimmed
/// first, so the work is proportional to the changed region.
fn unified_diff(before: &str, after: &str, name: &str) -> String {
    let (a, b): (Vec<&str>, Vec<&str>) = (before.lines().collect(), after.lines().collect());
    let prefix = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let suffix = a.iter().rev().zip(b.iter().rev()).take(a.len().min(b.len()) - prefix).take_while(|(x, y)| x == y).count();
    let (am, bm) = (a.get(prefix..a.len() - suffix).unwrap_or(&[]), b.get(prefix..b.len() - suffix).unwrap_or(&[]));
    let mut ops: Vec<(char, &str)> = a.get(..prefix).unwrap_or(&[]).iter().map(|l| (' ', *l)).collect();
    ops.extend(edit_script(am, bm));
    ops.extend(a.get(a.len() - suffix..).unwrap_or(&[]).iter().map(|l| (' ', *l)));

    let mut out = format!("--- {name}\n+++ {name}\n");
    let changed: Vec<usize> = ops.iter().enumerate().filter(|(_, (k, _))| *k != ' ').map(|(i, _)| i).collect();
    let mut i = 0;
    while i < changed.len() {
        let start = changed.get(i).copied().unwrap_or(0).saturating_sub(3);
        let mut end = changed.get(i).copied().unwrap_or(0) + 3;
        while changed.get(i + 1).is_some_and(|&n| n <= end + 3) {
            i += 1;
            end = changed.get(i).copied().unwrap_or(0) + 3;
        }
        let end = end.min(ops.len().saturating_sub(1));
        let hunk = ops.get(start..=end).unwrap_or(&[]);
        let (a0, b0) = ops.get(..start).unwrap_or(&[]).iter().fold((0, 0), |(x, y), (k, _)| (x + usize::from(*k != '+'), y + usize::from(*k != '-')));
        let (al, bl) = hunk.iter().fold((0, 0), |(x, y), (k, _)| (x + usize::from(*k != '+'), y + usize::from(*k != '-')));
        let _ = writeln!(out, "@@ -{},{al} +{},{bl} @@", a0 + 1, b0 + 1);
        for (k, l) in hunk {
            let _ = writeln!(out, "{k}{l}");
        }
        i += 1;
    }
    out
}

/// A shortest edit script (Myers). Above a bound on the number of differences the middle is
/// shown as a replacement, which is still correct, just less minimal.
#[allow(clippy::many_single_char_names)] // the paper's names: x, y, k, d, v, n, m
fn edit_script<'a>(a: &[&'a str], b: &[&'a str]) -> Vec<(char, &'a str)> {
    const MAX_D: usize = 2_000;
    let (n, m) = (a.len(), b.len());
    let offset = n + m + 1;
    let mut v = vec![0usize; 2 * offset + 1];
    let mut trace: Vec<Vec<usize>> = Vec::new();
    let mut found = false;
    'search: for d in 0..=(n + m).min(MAX_D) {
        trace.push(v.clone());
        for k in (0..=2 * d).step_by(2) {
            let k = k as isize - d as isize;
            let idx = |k: isize| (k + offset as isize) as usize;
            let mut x = if k == -(d as isize) || (k != d as isize && v.get(idx(k - 1)) < v.get(idx(k + 1))) {
                v.get(idx(k + 1)).copied().unwrap_or(0)
            } else {
                v.get(idx(k - 1)).copied().unwrap_or(0) + 1
            };
            let mut y = (x as isize - k) as usize;
            while x < n && y < m && a.get(x) == b.get(y) {
                x += 1;
                y += 1;
            }
            if let Some(slot) = v.get_mut(idx(k)) {
                *slot = x;
            }
            if x >= n && y >= m {
                found = true;
                break 'search;
            }
        }
    }
    if !found {
        let mut out: Vec<(char, &str)> = a.iter().map(|l| ('-', *l)).collect();
        out.extend(b.iter().map(|l| ('+', *l)));
        return out;
    }
    // Walk the trace back from the end.
    let mut out = Vec::new();
    let (mut x, mut y) = (n, m);
    for (d, v) in trace.iter().enumerate().rev() {
        if d == 0 {
            // What is left is the common run both sequences start with.
            while x > 0 && y > 0 {
                x -= 1;
                y -= 1;
                out.push((' ', a.get(x).copied().unwrap_or("")));
            }
            break;
        }
        let k = x as isize - y as isize;
        let idx = |k: isize| (k + offset as isize) as usize;
        let prev_k = if k == -(d as isize) || (k != d as isize && v.get(idx(k - 1)) < v.get(idx(k + 1))) { k + 1 } else { k - 1 };
        let prev_x = v.get(idx(prev_k)).copied().unwrap_or(0);
        let prev_y = (prev_x as isize - prev_k) as usize;
        while x > prev_x && y > prev_y {
            x -= 1;
            y -= 1;
            out.push((' ', a.get(x).copied().unwrap_or("")));
        }
        if x == prev_x {
            y -= 1;
            out.push(('+', b.get(y).copied().unwrap_or("")));
        } else {
            x -= 1;
            out.push(('-', a.get(x).copied().unwrap_or("")));
        }
    }
    out.reverse();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_shows_only_changed_lines_with_context() {
        let a = "1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n";
        let b = "1\n2\n3\n4\nfive\n6\n7\n8\n9\n10\nnew\n";
        let d = unified_diff(a, b, "f");
        assert_eq!(d, "--- f\n+++ f\n@@ -2,9 +2,10 @@\n 2\n 3\n 4\n-5\n+five\n 6\n 7\n 8\n 9\n 10\n+new\n");
    }

    #[test]
    fn edit_script_is_minimal() {
        let s = edit_script(&["a", "b", "c"], &["a", "x", "c", "d"]);
        assert_eq!(s, [(' ', "a"), ('-', "b"), ('+', "x"), (' ', "c"), ('+', "d")]);
    }

    #[test]
    fn dates_are_civil() {
        let d = now_rfc3339();
        assert_eq!(d.len(), 20);
        assert!(d.starts_with("20") && d.ends_with('Z'));
    }
}
