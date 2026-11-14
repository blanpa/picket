//! Background watcher: compare the current state with the last run and report
//! what changed (new finding, new open port, new device on the network).
//!
//! `picket watch` does one round; a systemd user timer runs it regularly.

use crate::model::{Report, Status};
use crate::{checks, devices, history, net, privileged, util};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

const UNIT: &str = "picket-watch";
/// The slow checks (package managers, firmware) only run this often.
const FULL_INTERVAL_S: u64 = 6 * 3600;
const MAX_EVENTS: usize = 500;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Event {
    pub time: u64,
    /// crit | warn | info | ok
    pub level: String,
    pub title: String,
    pub text: String,
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct State {
    pub last_full: u64,
    /// finding id -> (status, title)
    pub findings: BTreeMap<String, (Status, String)>,
    /// None until the first run has recorded a baseline.
    pub ports: Option<BTreeSet<String>>,
    /// network (subnet and router) -> hardware addresses seen there
    pub networks: BTreeMap<String, BTreeSet<String>>,
    /// Last time the known networks were searched actively.
    #[serde(default)]
    pub last_sweep: u64,
}

/// What the watcher looks at in one round.
pub struct Observation {
    /// (id, status, title, summary); a light round only contains the fast checks.
    pub findings: Vec<(String, Status, String, String)>,
    /// "tcp/1890" -> description. The key must not contain the program name:
    /// that depends on whether the root snapshot is fresh.
    pub ports: BTreeMap<String, String>,
    /// (network key, [(mac, description)])
    pub networks: Vec<(String, Vec<(String, String)>)>,
}

fn event(now: u64, level: &str, title: String, text: String) -> Event {
    Event { time: now, level: level.into(), title, text }
}

/// Compare an observation with the previous state. Pure, so it can be tested.
pub fn diff(prev: &State, obs: &Observation, now: u64) -> (Vec<Event>, State) {
    let mut events = Vec::new();
    let urgent = |s: Status| matches!(s, Status::Crit | Status::Warn);
    let baseline = prev.ports.is_some();

    let mut findings = prev.findings.clone();
    for (id, status, title, summary) in &obs.findings {
        let before = prev.findings.get(id).map(|f| f.0);
        if baseline {
            match before {
                Some(b) if urgent(*status) && (!urgent(b) || (*status == Status::Crit && b != Status::Crit)) => {
                    events.push(event(now, if *status == Status::Crit { "crit" } else { "warn" }, title.clone(), summary.clone()));
                }
                None if urgent(*status) => {
                    events.push(event(now, if *status == Status::Crit { "crit" } else { "warn" }, title.clone(), summary.clone()));
                }
                Some(b) if urgent(b) && !urgent(*status) => {
                    events.push(event(now, "ok", format!("Behoben: {title}"), summary.clone()));
                }
                _ => {}
            }
        }
        findings.insert(id.clone(), (*status, title.clone()));
    }

    let current: BTreeSet<String> = obs.ports.keys().cloned().collect();
    if let Some(old) = &prev.ports {
        // Older versions stored "tcp/1890 (program)"; compare on the port alone.
        let old: BTreeSet<String> = old.iter().map(|k| k.split(' ').next().unwrap_or(k).to_string()).collect();
        for p in current.difference(&old) {
            events.push(event(now, "warn", "Neuer offener Port".into(), format!("{p} ({}) ist jetzt aus dem Netz erreichbar.", obs.ports[p])));
        }
        for p in old.difference(&current) {
            events.push(event(now, "info", "Port geschlossen".into(), format!("{p} ist nicht mehr erreichbar.")));
        }
    }

    let mut networks = prev.networks.clone();
    for (key, devices) in &obs.networks {
        let known = networks.get(key);
        for (mac, description) in devices {
            // A network seen for the first time only sets the baseline.
            if known.map(|k| !k.contains(mac)).unwrap_or(false) {
                events.push(event(now, "warn", "Neues Gerät im Netz".into(), description.clone()));
            }
        }
        networks.entry(key.clone()).or_default().extend(devices.iter().map(|d| d.0.clone()));
    }

    let state = State { last_full: prev.last_full, findings, ports: Some(current), networks, last_sweep: prev.last_sweep };
    (events, state)
}

fn state_path() -> PathBuf {
    util::state_dir().join("watch.json")
}

fn events_path() -> PathBuf {
    util::state_dir().join("events.json")
}

/// Recorded events, newest first.
pub fn events() -> Vec<Event> {
    let mut v: Vec<Event> = util::read_json(&events_path()).unwrap_or_default();
    v.reverse();
    v
}

fn observe(report: &Report, snap: &net::NetSnapshot, sweep: bool) -> Observation {
    Observation {
        // An accepted finding is no longer urgent.
        findings: report
            .findings
            .iter()
            .map(|f| (f.id.clone(), if f.accepted { Status::Info } else { f.status }, f.title.clone(), f.summary.clone()))
            .collect(),
        ports: snap.exposed().iter().map(|l| (format!("{}/{}", l.proto, l.port), l.who())).collect(),
        // Devices are only watched on networks the user has searched before: there a
        // periodic search is welcome, and without one the list is too patchy to alert on.
        networks: devices::discover_with(if sweep { devices::Mode::ActiveKnown } else { devices::Mode::Passive })
            .into_iter()
            .filter(|n| n.inventoried)
            .map(|n| {
                let key = format!("{} via {}", n.subnet, n.gateway.clone().unwrap_or_default());
                let devs = n
                    .devices
                    .iter()
                    .filter(|d| !d.is_self)
                    .map(|d| (d.mac.clone(), format!("{} – {} ({})", d.title(), d.ip, d.mac)))
                    .collect();
                (key, devs)
            })
            .collect(),
    }
}

fn notify(events: &[Event]) {
    let urgent: Vec<&Event> = events.iter().filter(|e| e.level == "crit" || e.level == "warn").collect();
    let (title, body) = match urgent.as_slice() {
        [] => return,
        [one] => (one.title.clone(), one.text.clone()),
        many => (
            format!("{} neue Sicherheitshinweise", many.len()),
            many.iter().take(6).map(|e| format!("• {}", e.title)).collect::<Vec<_>>().join("\n"),
        ),
    };
    let critical = urgent.iter().any(|e| e.level == "crit");
    let _ = util::run_localized(
        "notify-send",
        &["-a", "Picket", "-i", crate::APP_ID, "-u", if critical { "critical" } else { "normal" }, &title, &body],
        10,
    );
}

/// One watcher round. Returns the new events.
pub fn run_once(send_notifications: bool) -> Vec<Event> {
    let now = util::now();
    let prev: State = util::read_json(&state_path()).unwrap_or_default();
    let full = now.saturating_sub(prev.last_full) > FULL_INTERVAL_S;
    let report = checks::build_report_opts(!full);
    let snap = net::snapshot(privileged::load().as_ref());
    history::record(&snap);

    let sweep = now.saturating_sub(prev.last_sweep) > 3600;
    let (mut new_events, mut state) = diff(&prev, &observe(&report, &snap, sweep), now);
    if sweep {
        state.last_sweep = now;
    }
    if prev.ports.is_none() {
        new_events = vec![event(now, "info", "Wächter eingerichtet".into(), "Der aktuelle Zustand ist der Ausgangspunkt; gemeldet werden Änderungen.".into())];
    }
    if full {
        state.last_full = now;
    }
    let _ = util::write_json(&state_path(), &state);
    if !new_events.is_empty() {
        let mut all: Vec<Event> = util::read_json(&events_path()).unwrap_or_default();
        all.extend(new_events.iter().cloned());
        let skip = all.len().saturating_sub(MAX_EVENTS);
        let _ = util::write_json(&events_path(), &all.into_iter().skip(skip).collect::<Vec<_>>());
        if send_notifications {
            notify(&new_events);
        }
    }
    new_events
}

// ------------------------------------------------------------------ timer

fn unit_dir() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| util::home().join(".config"))
        .join("systemd/user")
}

#[cfg_attr(not(feature = "gui"), allow(dead_code))]
pub fn timer_enabled() -> bool {
    util::run("systemctl", &["--user", "is-enabled", &format!("{UNIT}.timer")], 5)
        .map(|o| o.stdout.trim() == "enabled")
        .unwrap_or(false)
}

/// Install and start, or stop and remove, the systemd user timer.
pub fn set_timer(enabled: bool) -> Result<(), String> {
    let dir = unit_dir();
    let (service, timer) = (dir.join(format!("{UNIT}.service")), dir.join(format!("{UNIT}.timer")));
    let systemctl = |args: &[&str]| -> Result<(), String> {
        let mut a = vec!["--user"];
        a.extend(args);
        match util::run("systemctl", &a, 15) {
            Some(o) if o.ok => Ok(()),
            Some(o) => Err(o.stderr.trim().to_string()),
            None => Err("systemctl ist nicht verfügbar.".into()),
        }
    };
    if enabled {
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let exe = util::self_exe();
        std::fs::write(
            &service,
            format!("[Unit]\nDescription=Picket: Wächter\n\n[Service]\nType=oneshot\nExecStart=\"{exe}\" watch\nNice=10\n"),
        )
        .map_err(|e| e.to_string())?;
        std::fs::write(
            &timer,
            "[Unit]\nDescription=Picket: regelmäßige Prüfung\n\n[Timer]\nOnStartupSec=2min\nOnUnitActiveSec=5min\n\n[Install]\nWantedBy=timers.target\n",
        )
        .map_err(|e| e.to_string())?;
        systemctl(&["daemon-reload"])?;
        systemctl(&["enable", "--now", &format!("{UNIT}.timer")])
    } else {
        let _ = systemctl(&["disable", "--now", &format!("{UNIT}.timer")]);
        let _ = std::fs::remove_file(&service);
        let _ = std::fs::remove_file(&timer);
        systemctl(&["daemon-reload"])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(findings: &[(&str, Status)], ports: &[&str], devices: &[&str]) -> Observation {
        Observation {
            findings: findings.iter().map(|(id, s)| (id.to_string(), *s, format!("Titel {id}"), "Text".to_string())).collect(),
            ports: ports.iter().map(|p| (p.to_string(), "prog".to_string())).collect(),
            networks: vec![("192.168.1.0/24 via 192.168.1.1".into(), devices.iter().map(|m| (m.to_string(), format!("Gerät {m}"))).collect())],
        }
    }

    #[test]
    fn first_round_only_sets_the_baseline() {
        let (events, state) = diff(&State::default(), &obs(&[("fw", Status::Crit)], &["tcp/80"], &["aa"]), 1);
        assert!(events.is_empty());
        assert_eq!(state.ports.as_ref().unwrap().len(), 1);
        assert!(state.networks.values().next().unwrap().contains("aa"));
    }

    #[test]
    fn reports_changes_once() {
        let (_, base) = diff(&State::default(), &obs(&[("fw", Status::Ok), ("upd", Status::Warn)], &["tcp/80"], &["aa"]), 1);
        let next = obs(&[("fw", Status::Crit), ("upd", Status::Ok)], &["tcp/80", "tcp/8080"], &["aa", "bb"]);
        let (events, state) = diff(&base, &next, 2);
        let titles: Vec<&str> = events.iter().map(|e| e.title.as_str()).collect();
        assert_eq!(titles, ["Titel fw", "Behoben: Titel upd", "Neuer offener Port", "Neues Gerät im Netz"]);
        assert_eq!(events[0].level, "crit");
        assert!(events[2].text.starts_with("tcp/8080 (prog)"));
        // State written by an older version (port keys with program names) causes no false alarm.
        let mut old = State { ports: Some(["tcp/80 (nginx)".to_string(), "tcp/8080 (unbekannt (anderer Benutzer))".to_string()].into()), ..Default::default() };
        old.networks = state.networks.clone();
        old.findings = state.findings.clone();
        assert!(diff(&old, &next, 3).0.is_empty());
        // Nothing new the second time.
        let (events, _) = diff(&state, &next, 3);
        assert!(events.is_empty());
        // A light round without "upd" keeps its last known status.
        let (events, state) = diff(&state, &obs(&[("fw", Status::Crit)], &["tcp/80", "tcp/8080"], &["aa", "bb"]), 4);
        assert!(events.is_empty());
        assert_eq!(state.findings["upd"].0, Status::Ok);
        // A closed port and a different network: only the port is reported.
        let mut other = obs(&[], &["tcp/80"], &["zz"]);
        other.networks[0].0 = "10.0.0.0/24 via 10.0.0.1".into();
        let (events, _) = diff(&state, &other, 5);
        assert_eq!(events.iter().map(|e| e.title.as_str()).collect::<Vec<_>>(), ["Port geschlossen"]);
    }
}
