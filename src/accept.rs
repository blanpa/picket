//! Findings the user has consciously accepted ("I know, stop telling me").
//!
//! An acceptance is tied to the finding's summary at that moment: when the
//! finding changes (a fourth open port instead of three), it counts again.

use crate::model::Finding;
use crate::util;
use std::collections::BTreeMap;
use std::path::PathBuf;

fn path() -> PathBuf {
    util::state_dir().join("accepted.json")
}

/// finding id -> summary at the time of acceptance
pub fn load() -> BTreeMap<String, String> {
    util::read_json(&path()).unwrap_or_default()
}

/// Accept a finding in its current state, or (with `None`) report it again.
pub fn set(id: &str, summary: Option<&str>) -> Result<(), String> {
    let mut map = load();
    match summary {
        Some(s) => {
            map.insert(id.to_string(), s.to_string());
        }
        None => {
            map.remove(id);
        }
    }
    util::write_json(&path(), &map)
}

/// Mark the findings that are still accepted.
pub fn apply(findings: &mut [Finding], accepted: &BTreeMap<String, String>) {
    for f in findings {
        f.accepted = accepted.get(&f.id).map(|s| *s == f.summary).unwrap_or(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Category, Status};

    #[test]
    fn acceptance_ends_when_the_finding_changes() {
        let mut f = vec![
            Finding::new("a", Category::Network, "A").set(Status::Warn, "3 Ports offen"),
            Finding::new("b", Category::Network, "B").set(Status::Warn, "x"),
        ];
        let accepted = BTreeMap::from([("a".to_string(), "3 Ports offen".to_string())]);
        apply(&mut f, &accepted);
        assert!(f[0].accepted && !f[1].accepted);
        f[0].summary = "4 Ports offen".into();
        apply(&mut f, &accepted);
        assert!(!f[0].accepted);
    }
}
