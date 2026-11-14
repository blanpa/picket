//! Connection history: who talked to whom, per day.
//!
//! The watcher samples the open connections every few minutes. Connections
//! that open and close between two samples are missed, and the data volume is
//! the growth of the TCP counters between samples, so it is a lower bound.

use crate::net::{NetSnapshot, Zone};
use crate::util;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

const KEEP_DAYS: usize = 30;
/// Samples further apart than this are not compared (laptop was asleep).
const MAX_GAP_S: u64 = 20 * 60;

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Entry {
    pub program: String,
    pub remote: String,
    pub port: u16,
    pub proto: String,
    pub zone: String,
    pub first: u64,
    pub last: u64,
    pub samples: u32,
    pub sent: u64,
    pub received: u64,
}

pub type Day = BTreeMap<String, Entry>;

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct Baseline {
    pub time: u64,
    pub counters: BTreeMap<String, (u64, u64)>,
}

/// Fold one snapshot into the day's record; returns the new baseline.
pub fn merge(day: &mut Day, base: &Baseline, snap: &NetSnapshot, now: u64) -> Baseline {
    let comparable = now.saturating_sub(base.time) <= MAX_GAP_S;
    let mut counters = BTreeMap::new();
    for p in &snap.programs {
        for e in p.endpoints.iter().filter(|e| e.zone != Zone::Loopback) {
            let key = format!("{}\t{}\t{}\t{}", p.name, e.remote, e.port, e.proto);
            counters.insert(key.clone(), (e.bytes_sent, e.bytes_received));
            let entry = day.entry(key.clone()).or_insert_with(|| Entry {
                program: p.name.clone(),
                remote: e.remote.clone(),
                port: e.port,
                proto: e.proto.clone(),
                zone: e.zone.label().to_string(),
                first: now,
                ..Default::default()
            });
            entry.last = now;
            entry.samples += 1;
            if let (true, Some((sent, received))) = (comparable, base.counters.get(&key)) {
                // Counters fall when a connection closes; that is not traffic.
                entry.sent += e.bytes_sent.saturating_sub(*sent);
                entry.received += e.bytes_received.saturating_sub(*received);
            }
        }
    }
    Baseline { time: now, counters }
}

fn dir() -> PathBuf {
    util::state_dir().join("history")
}

/// Record a snapshot under today's date.
pub fn record(snap: &NetSnapshot) {
    let today = util::date("+%F");
    if today.len() != 10 {
        return;
    }
    let path = dir().join(format!("{today}.json"));
    let base_path = dir().join("baseline.json");
    let mut day: Day = util::read_json(&path).unwrap_or_default();
    let base: Baseline = util::read_json(&base_path).unwrap_or_default();
    let new_base = merge(&mut day, &base, snap, util::now());
    let _ = util::write_json(&path, &day);
    let _ = util::write_json(&base_path, &new_base);
    // Forget old days.
    let mut all = days();
    while all.len() > KEEP_DAYS {
        if let Some(old) = all.pop() {
            let _ = std::fs::remove_file(dir().join(format!("{old}.json")));
        }
    }
}

/// Recorded days, newest first.
pub fn days() -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir())
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().to_str().and_then(|n| n.strip_suffix(".json")).map(String::from))
        .filter(|n| n.len() == 10 && n.as_bytes()[4] == b'-')
        .collect();
    v.sort_by(|a, b| b.cmp(a));
    v
}

/// The entries of one day, largest data volume first.
pub fn load(day: &str) -> Vec<Entry> {
    if !day.chars().all(|c| c.is_ascii_digit() || c == '-') {
        return Vec::new();
    }
    let map: Day = util::read_json(&dir().join(format!("{day}.json"))).unwrap_or_default();
    let mut v: Vec<Entry> = map.into_values().collect();
    v.sort_by(|a, b| (b.sent + b.received, b.samples).cmp(&(a.sent + a.received, a.samples)));
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{Endpoint, Program};

    fn snap(sent: u64, received: u64) -> NetSnapshot {
        let ep = |remote: &str, zone, s, r| Endpoint {
            remote: remote.into(),
            port: 443,
            proto: "tcp".into(),
            zone,
            inbound: false,
            service: None,
            count: 1,
            bytes_sent: s,
            bytes_received: r,
        };
        NetSnapshot {
            generated: 0,
            ifaces: vec![],
            listeners: vec![],
            programs: vec![Program {
                name: "browser".into(),
                pids: vec![],
                zones: BTreeMap::new(),
                endpoints: vec![ep("1.1.1.1", Zone::Internet, sent, received), ep("127.0.0.1", Zone::Loopback, 5, 5)],
            }],
            totals: BTreeMap::new(),
            docker: vec![],
            local_ports: BTreeMap::new(),
            docker_available: false,
            has_global_ipv6: false,
            complete: true,
        }
    }

    #[test]
    fn accumulates_traffic_between_samples() {
        let mut day = Day::new();
        let base = merge(&mut day, &Baseline::default(), &snap(1000, 5000), 1000);
        assert_eq!(day.len(), 1); // loopback is not recorded
        let e = day.values().next().unwrap().clone();
        assert_eq!((e.samples, e.sent, e.received, e.first), (1, 0, 0, 1000));

        let base = merge(&mut day, &base, &snap(1500, 9000), 1300);
        let e = day.values().next().unwrap().clone();
        assert_eq!((e.samples, e.sent, e.received, e.last), (2, 500, 4000, 1300));

        // Connection was replaced by a new one: counters start again, nothing negative.
        let base = merge(&mut day, &base, &snap(100, 200), 1600);
        assert_eq!(day.values().next().unwrap().sent, 500);

        // After a long sleep the samples are not compared.
        merge(&mut day, &base, &snap(999_999, 999_999), 1600 + 3600);
        let e = day.values().next().unwrap();
        assert_eq!((e.samples, e.sent, e.received), (4, 500, 4000));
    }
}
