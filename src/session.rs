//! What the window has seen since it was opened: every connection, including
//! those that have closed again, so they do not simply vanish from the view.

use crate::net::{NetSnapshot, Zone};
use std::collections::BTreeMap;

/// Upper bound on remembered connections; the oldest closed ones go first.
const MAX_ENTRIES: usize = 4000;

#[derive(Clone, Debug, PartialEq)]
pub struct Seen {
    pub program: String,
    pub remote: String,
    pub port: u16,
    pub proto: String,
    pub inbound: bool,
    pub zone: Zone,
    pub service: Option<&'static str>,
    pub first: u64,
    /// Last time the connection was seen open.
    pub last: u64,
    pub active: bool,
}

type Key = (String, String, u16, String, bool);

#[derive(Default)]
pub struct Session {
    entries: BTreeMap<Key, Seen>,
}

impl Session {
    /// Fold in a snapshot taken at `now`.
    pub fn update(&mut self, snap: &NetSnapshot, now: u64) {
        for e in self.entries.values_mut() {
            e.active = false;
        }
        for p in &snap.programs {
            // Traffic inside the laptop is too chatty to be worth remembering.
            for e in p.endpoints.iter().filter(|e| e.zone != Zone::Loopback) {
                let key = (p.name.clone(), e.remote.clone(), e.port, e.proto.clone(), e.inbound);
                let seen = self.entries.entry(key).or_insert_with(|| Seen {
                    program: p.name.clone(),
                    remote: e.remote.clone(),
                    port: e.port,
                    proto: e.proto.clone(),
                    inbound: e.inbound,
                    zone: e.zone,
                    service: e.service,
                    first: now,
                    last: now,
                    active: true,
                });
                seen.last = now;
                seen.active = true;
            }
        }
        if self.entries.len() > MAX_ENTRIES {
            let mut closed: Vec<(u64, Key)> = self.entries.iter().filter(|(_, e)| !e.active).map(|(k, e)| (e.last, k.clone())).collect();
            closed.sort();
            let excess = self.entries.len() - MAX_ENTRIES;
            for (_, key) in closed.into_iter().take(excess) {
                self.entries.remove(&key);
            }
        }
    }

    /// Connections that have closed, most recently closed first.
    /// `max_age`: only those closed within this many seconds; None = all.
    pub fn ended(&self, now: u64, max_age: Option<u64>) -> Vec<&Seen> {
        let mut v: Vec<&Seen> = self
            .entries
            .values()
            .filter(|e| !e.active && max_age.map(|m| now.saturating_sub(e.last) <= m).unwrap_or(true))
            .collect();
        v.sort_by(|a, b| b.last.cmp(&a.last).then(a.remote.cmp(&b.remote)));
        v
    }
}

/// "vor 3 min"
pub fn ago(seconds: u64) -> String {
    match seconds {
        0..=59 => "gerade eben".to_string(),
        60..=3599 => format!("vor {} min", seconds / 60),
        s => format!("vor {} h", s / 3600),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{Endpoint, Program};

    fn snap(remotes: &[(&str, Zone)]) -> NetSnapshot {
        NetSnapshot {
            generated: 0,
            ifaces: vec![],
            listeners: vec![],
            programs: vec![Program {
                name: "browser".into(),
                pids: vec![],
                zones: BTreeMap::new(),
                endpoints: remotes
                    .iter()
                    .map(|(r, z)| Endpoint {
                        remote: r.to_string(),
                        port: 443,
                        proto: "tcp".into(),
                        zone: *z,
                        inbound: false,
                        service: Some("HTTPS"),
                        count: 1,
                        bytes_sent: 0,
                        bytes_received: 0,
                    })
                    .collect(),
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
    fn remembers_closed_connections() {
        let mut s = Session::default();
        s.update(&snap(&[("1.1.1.1", Zone::Internet), ("9.9.9.9", Zone::Internet), ("127.0.0.1", Zone::Loopback)]), 100);
        assert!(s.ended(100, None).is_empty());
        // 9.9.9.9 closes; 1.1.1.1 stays.
        s.update(&snap(&[("1.1.1.1", Zone::Internet)]), 105);
        let ended = s.ended(105, None);
        assert_eq!(ended.len(), 1);
        assert_eq!((ended[0].remote.as_str(), ended[0].first, ended[0].last), ("9.9.9.9", 100, 100));
        // Later everything is closed; the most recent comes first.
        s.update(&snap(&[]), 400);
        let ended = s.ended(400, None);
        assert_eq!(ended.iter().map(|e| e.remote.as_str()).collect::<Vec<_>>(), ["1.1.1.1", "9.9.9.9"]);
        assert_eq!(s.ended(400, Some(299)).len(), 1); // 9.9.9.9 closed 300 s ago
        // It reopens: no longer listed as closed, and its first sighting is kept.
        s.update(&snap(&[("9.9.9.9", Zone::Internet)]), 500);
        assert_eq!(s.ended(500, None).iter().map(|e| e.remote.as_str()).collect::<Vec<_>>(), ["1.1.1.1"]);
        assert_eq!((ago(30), ago(185), ago(7300)), ("gerade eben".to_string(), "vor 3 min".to_string(), "vor 2 h".to_string()));
    }
}
