//! `sudo picket selftest-root`: exercise the root paths for real, without
//! leaving anything changed. Adds and removes one firewall rule for a
//! documentation address, closes its own test connection, and records two
//! seconds of loopback traffic.

use crate::fwctl::{self, Op, RuleSpec};
use crate::{capture, helper, pcap, privileged, util};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// TEST-NET-1 (RFC 5737): reserved for documentation, never routed.
const TEST_ADDR: &str = "192.0.2.123";

fn step(name: &str, result: Result<String, String>) -> bool {
    match &result {
        Ok(msg) => println!("  OK      {name}: {msg}"),
        Err(msg) => println!("  FEHLER  {name}: {msg}"),
    }
    result.is_ok()
}

fn snapshot() -> Result<String, String> {
    let p = privileged::collect();
    let missing: Vec<&str> = [
        ("ufw status", p.ufw_status.is_some()),
        ("ufw show added", p.ufw_added.is_some()),
        ("Socket-Liste", !p.ss_listen.is_empty()),
        ("/etc/shadow", p.empty_passwords.is_some()),
        ("sudoers", p.sudo_nopasswd.is_some()),
    ]
    .iter()
    .filter(|(_, ok)| !ok)
    .map(|(n, _)| *n)
    .collect();
    if !missing.is_empty() {
        return Err(format!("nicht lesbar: {}", missing.join(", ")));
    }
    let path = privileged::write(&p)?;
    Ok(format!("geschrieben nach {}", path.display()))
}

fn ufw_state() -> String {
    util::run("ufw", &["status"], 10).map(|o| o.stdout.lines().next().unwrap_or("").to_string()).unwrap_or_default()
}

fn added() -> Vec<fwctl::Rule> {
    fwctl::parse_added(&util::run("ufw", &["show", "added"], 10).map(|o| o.stdout).unwrap_or_default())
}

fn firewall_rule() -> Result<String, String> {
    let before = ufw_state();
    let rule = Op::Add(RuleSpec {
        action: "deny".into(),
        direction: "in".into(),
        addr: TEST_ADDR.into(),
        comment: "Selbsttest".into(),
        ..Default::default()
    });
    fwctl::apply(&[rule], false)?;
    let rules = added();
    let Some(pos) = rules.iter().position(|r| r.raw.contains(TEST_ADDR)) else {
        return Err("die Testregel taucht nicht in „ufw show added“ auf".into());
    };
    let raw = rules[pos].raw.clone();
    let delete = fwctl::apply(&[Op::Delete { rule: raw.clone() }], false);
    if added().iter().any(|r| r.raw.contains(TEST_ADDR)) {
        return Err(format!("die Testregel ließ sich nicht löschen – bitte von Hand: sudo ufw delete {raw}"));
    }
    delete?;
    if ufw_state() != before {
        return Err(format!("der Firewall-Status hat sich geändert: {before} → {}", ufw_state()));
    }
    Ok(format!(
        "Regel angelegt{}, gefunden und wieder gelöscht; Status unverändert ({before})",
        if pos == 0 { " (an erster Stelle)" } else { " (nicht an erster Stelle!)" }
    ))
}

fn close_connection() -> Result<String, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let mut client = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    let (_server, _) = listener.accept().map_err(|e| e.to_string())?;
    client.write_all(b"vorher").map_err(|e| e.to_string())?;
    fwctl::apply(&[Op::Drop { addr: "127.0.0.1".into(), port: port.to_string() }], false)?;
    client.set_read_timeout(Some(Duration::from_millis(500))).ok();
    std::thread::sleep(Duration::from_millis(100));
    let dead = client.write_all(b"nachher").is_err() || {
        let mut buf = [0u8; 8];
        matches!(client.read(&mut buf), Ok(0)) || client.write_all(b"x").is_err()
    };
    if dead {
        Ok(format!("Testverbindung zu 127.0.0.1:{port} wurde getrennt"))
    } else {
        Err("die Testverbindung lebt nach „ss -K“ noch".into())
    }
}

fn capture_loopback() -> Result<String, String> {
    // Traffic to record: a local connection that keeps sending.
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let request = capture::Request { iface: "lo".into(), host: String::new(), port: port.to_string(), proto: "tcp".into() };
    let json = serde_json::to_string(&request).map_err(|e| e.to_string())?;
    let mut child = Command::new(std::env::current_exe().map_err(|e| e.to_string())?)
        .arg("capture")
        .arg(json)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| e.to_string())?;
    let stdin = child.stdin.take();
    let mut stdout = child.stdout.take().ok_or("keine Ausgabe")?;
    let reader = std::thread::spawn(move || {
        let mut all = Vec::new();
        let _ = stdout.read_to_end(&mut all);
        all
    });
    std::thread::sleep(Duration::from_millis(800)); // let tcpdump start listening
    let sender = std::thread::spawn(move || {
        if let Ok(mut c) = TcpStream::connect(("127.0.0.1", port)) {
            for _ in 0..10 {
                let _ = c.write_all(b"picket selbsttest");
                std::thread::sleep(Duration::from_millis(80));
            }
        }
    });
    let _accepted = listener.accept();
    let _ = sender.join();
    std::thread::sleep(Duration::from_millis(400));

    // Stop exactly the way the window does: close the helper's standard input.
    drop(stdin);
    let started = Instant::now();
    let stopped = loop {
        match child.try_wait() {
            Ok(Some(_)) => break true,
            Ok(None) if started.elapsed() > Duration::from_secs(5) => break false,
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(_) => break false,
        }
    };
    if !stopped {
        let _ = child.kill();
        return Err("der Mitschnitt endet nicht, wenn die Eingabe geschlossen wird".into());
    }
    let bytes = reader.join().unwrap_or_default();
    let mut r = pcap::Reader::default();
    let packets = r.feed(&bytes);
    let ours = packets.iter().filter(|p| p.sport == port || p.dport == port).count();
    if r.invalid || ours == 0 {
        return Err(format!("keine passenden Pakete im Mitschnitt ({} Bytes, {} Pakete)", bytes.len(), packets.len()));
    }
    Ok(format!("{ours} Pakete aufgezeichnet, nach {} ms gestoppt", started.elapsed().as_millis()))
}

pub fn run() -> bool {
    if util::uid() != 0 {
        eprintln!("Der Selbsttest braucht Root-Rechte:\n  sudo {} selftest-root", util::self_exe());
        return false;
    }
    println!("Selbsttest der Root-Funktionen (ändert nichts dauerhaft):");
    let mut ok = true;
    ok &= step("Systemdaten lesen", snapshot());
    if util::which("ufw").is_some() {
        ok &= step("Firewall-Regel", firewall_rule());
    } else {
        println!("  –       Firewall-Regel: ufw ist nicht installiert");
    }
    ok &= step("Verbindung trennen", close_connection());
    ok &= step("Mitschnitt", capture_loopback());
    ok &= step("Helfer", helper::ready().map(|_| format!("{} ist eingerichtet und aktuell", helper::PATH)));
    println!("{}", if ok { "Alles in Ordnung." } else { "Mindestens ein Schritt ist fehlgeschlagen." });
    ok
}
