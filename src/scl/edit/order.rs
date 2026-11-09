//! The order the SCL schema requires children in, for the parents an edit inserts into.
//!
//! Read off the 2007B4 XSD ✅ (`SCL.xsd`, `SCL_BaseTypes.xsd`, `SCL_IED.xsd`,
//! `SCL_Communication.xsd`); 2003 and 2007C5 agree for these elements.

/// Children of `parent` in schema order, or `None` for a parent with no table.
fn sequence(parent: &str) -> Option<&'static [&'static str]> {
    Some(match parent {
        "SCL" => &["Text", "Private", "Header", "Substation", "Communication", "IED", "DataTypeTemplates", "Line", "Process"],
        "Header" => &["Text", "History"],
        "History" => &["Hitem"],
        "Communication" => &["Text", "Private", "SubNetwork"],
        "SubNetwork" => &["Text", "Private", "BitRate", "ConnectedAP"],
        "ConnectedAP" => &["Text", "Private", "Address", "GSE", "SMV", "PhysConn"],
        "GSE" => &["Text", "Private", "Address", "MinTime", "MaxTime"],
        "SMV" => &["Text", "Private", "Address"],
        "Address" => &["P"],
        "IED" => &["Text", "Private", "Services", "AccessPoint", "KDC"],
        "LDevice" => &["Text", "Private", "LN0", "LN", "AccessControl"],
        "LN" => &["Text", "Private", "DataSet", "ReportControl", "LogControl", "DOI", "Inputs", "Log"],
        "LN0" => &["Text", "Private", "DataSet", "ReportControl", "LogControl", "DOI", "Inputs", "Log", "GSEControl", "SampledValueControl", "SettingControl"],
        "DataSet" => &["Text", "Private", "FCDA", "FCCB"],
        "Inputs" => &["Text", "Private", "ExtRef"],
        _ => return None,
    })
}

/// The position of `child` among `parent`'s children; unknown children sort last.
pub(crate) fn rank(parent: &str, child: &str) -> usize {
    sequence(parent).and_then(|s| s.iter().position(|c| *c == child)).unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ln0_puts_goose_after_inputs() {
        assert!(rank("LN0", "Inputs") < rank("LN0", "GSEControl"));
        assert!(rank("LN0", "DataSet") < rank("LN0", "ReportControl"));
        assert_eq!(rank("Nowhere", "X"), usize::MAX);
    }
}
