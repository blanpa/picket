//! Domain blocklist (advertising, tracking, malware) for flagging names seen
//! in DNS requests and TLS handshakes. Downloaded once on request; matching is local.

#![cfg_attr(not(feature = "gui"), allow(dead_code))]

use crate::util;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

const URL: &str = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts";

static LIST: Mutex<Option<Arc<HashSet<String>>>> = Mutex::new(None);

fn file() -> PathBuf {
    util::data_dir().join("blocklist-hosts.txt")
}

pub fn available() -> bool {
    file().exists()
}

pub fn age_days() -> Option<u64> {
    util::age_days(file())
}

/// Parse a hosts-format list: "0.0.0.0 tracker.example" per line.
pub fn parse(text: &str) -> HashSet<String> {
    text.lines()
        .filter_map(|l| {
            let l = l.split('#').next()?.trim();
            let mut it = l.split_whitespace();
            let addr = it.next()?;
            let domain = it.next()?.to_ascii_lowercase();
            ((addr == "0.0.0.0" || addr == "127.0.0.1") && domain.contains('.') && domain != "0.0.0.0").then_some(domain)
        })
        .collect()
}

fn list() -> Arc<HashSet<String>> {
    let mut guard = LIST.lock().unwrap();
    if let Some(l) = guard.as_ref() {
        return l.clone();
    }
    let l = Arc::new(std::fs::read_to_string(file()).map(|t| parse(&t)).unwrap_or_default());
    *guard = Some(l.clone());
    l
}

pub fn listed_in(list: &HashSet<String>, domain: &str) -> bool {
    let d = domain.trim_end_matches('.').to_ascii_lowercase();
    // The name itself or any parent domain ("a.b.tracker.example" -> "tracker.example").
    let mut rest = d.as_str();
    loop {
        if list.contains(rest) {
            return true;
        }
        match rest.split_once('.') {
            Some((_, parent)) if parent.contains('.') => rest = parent,
            _ => return false,
        }
    }
}

pub fn is_listed(domain: &str) -> bool {
    listed_in(&list(), domain)
}

pub fn download() -> Result<String, String> {
    let path = file();
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension("tmp");
    let ok = util::run("curl", &["-fsSL", "--max-time", "120", "-o", &tmp.display().to_string(), URL], 130)
        .map(|o| o.ok)
        .unwrap_or(false);
    let entries = std::fs::read_to_string(&tmp).map(|t| parse(&t).len()).unwrap_or(0);
    if !ok || entries < 1000 {
        let _ = std::fs::remove_file(&tmp);
        return Err("Die Sperrliste konnte nicht geladen werden.".into());
    }
    std::fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
    *LIST.lock().unwrap() = None;
    Ok(format!("Sperrliste geladen ({entries} Domains)."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_domains_and_subdomains() {
        let list = parse("# comment\n127.0.0.1 localhost\n0.0.0.0 0.0.0.0\n0.0.0.0 tracker.example # ad\n0.0.0.0 Ads.Example.org\n");
        assert_eq!(list.len(), 2);
        assert!(listed_in(&list, "tracker.example"));
        assert!(listed_in(&list, "a.b.tracker.example."));
        assert!(listed_in(&list, "ADS.example.org"));
        assert!(!listed_in(&list, "example.org"));
        assert!(!listed_in(&list, "nottracker.example"));
        assert!(!listed_in(&list, "example"));
    }
}
