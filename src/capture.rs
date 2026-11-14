//! Packet capture through tcpdump.
//!
//! The window starts `pkexec picket capture <json>`. This root helper
//! validates the request and runs tcpdump, which writes raw pcap data to our
//! standard output. Decoding happens in the unprivileged window (`pcap.rs`).
//!
//! The capture ends when the window closes the helper's standard input, when
//! the reader goes away, or when the packet or time limit is reached.

use crate::util;
use serde::{Deserialize, Serialize};
use std::io::{IsTerminal, Read};
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAX_PACKETS: &str = "200000";
const MAX_DURATION: Duration = Duration::from_secs(15 * 60);

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Request {
    /// Interface name, or "any".
    pub iface: String,
    /// Remote address to limit the capture to ("" = all).
    #[serde(default)]
    pub host: String,
    /// Port to limit the capture to ("" = all).
    #[serde(default)]
    pub port: String,
    /// "", "tcp" or "udp"
    #[serde(default)]
    pub proto: String,
}

fn iface_exists(name: &str) -> bool {
    name == "any" || std::path::Path::new("/sys/class/net").join(name).exists()
}

/// The tcpdump arguments for a request. Only validated values end up in the filter.
pub fn tcpdump_args(r: &Request) -> Result<Vec<String>, String> {
    let name_ok = !r.iface.is_empty() && r.iface.chars().all(|c| c.is_ascii_alphanumeric() || "_.-".contains(c));
    if !name_ok || !iface_exists(&r.iface) {
        return Err(format!("Unbekannte Schnittstelle: {}", r.iface));
    }
    let mut filter: Vec<String> = Vec::new();
    let and = |part: &[&str], filter: &mut Vec<String>| {
        if !filter.is_empty() {
            filter.push("and".into());
        }
        filter.extend(part.iter().map(|s| s.to_string()));
    };
    let host = r.host.trim();
    if !host.is_empty() {
        let ip: IpAddr = host
            .parse()
            .map_err(|_| format!("Ungültige Adresse: „{host}“ (erwartet eine IP-Adresse)"))?;
        and(&["host", &ip.to_string()], &mut filter);
    }
    let port = r.port.trim();
    if !port.is_empty() {
        match port.parse::<u32>() {
            Ok(p @ 1..=65535) => and(&["port", &p.to_string()], &mut filter),
            _ => return Err(format!("Ungültiger Port: „{port}“")),
        }
    }
    match r.proto.as_str() {
        "" => {}
        p @ ("tcp" | "udp") => and(&[p], &mut filter),
        other => return Err(format!("Unbekanntes Protokoll: {other}")),
    }
    let mut args: Vec<String> = ["-i", &r.iface, "-n", "-U", "--immediate-mode", "-c", MAX_PACKETS, "-w", "-"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    args.extend(filter);
    Ok(args)
}

/// Root helper: run tcpdump until the caller closes our standard input.
pub fn run(r: &Request) -> Result<(), String> {
    let args = tcpdump_args(r)?;
    if std::io::stdout().is_terminal() {
        return Err("Der Mitschnitt ist ein Binärformat – bitte in eine Datei umleiten (> datei.pcap).".into());
    }
    let tcpdump = util::which("tcpdump").ok_or("tcpdump ist nicht installiert (sudo apt install tcpdump).")?;
    let mut child = Command::new(tcpdump)
        .args(&args)
        .stdin(Stdio::null())
        .spawn()
        .map_err(|e| format!("tcpdump konnte nicht gestartet werden: {e}"))?;

    // The window signals "stop" by closing the pipe to our standard input.
    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 256];
            let mut stdin = std::io::stdin();
            while matches!(stdin.read(&mut buf), Ok(n) if n > 0) {}
            stop.store(true, Ordering::SeqCst);
        });
    }
    let deadline = Instant::now() + MAX_DURATION;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return if status.success() || stop.load(Ordering::SeqCst) {
                    Ok(())
                } else {
                    Err("tcpdump wurde mit einem Fehler beendet.".into())
                };
            }
            Ok(None) => {
                if stop.load(Ordering::SeqCst) || Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Ok(());
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => return Err(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(iface: &str, host: &str, port: &str, proto: &str) -> Request {
        Request { iface: iface.into(), host: host.into(), port: port.into(), proto: proto.into() }
    }

    #[test]
    fn builds_filters() {
        let base = "-i any -n -U --immediate-mode -c 200000 -w -";
        assert_eq!(tcpdump_args(&req("any", "", "", "")).unwrap().join(" "), base);
        assert_eq!(
            tcpdump_args(&req("any", "192.168.178.6", "22", "tcp")).unwrap().join(" "),
            format!("{base} host 192.168.178.6 and port 22 and tcp")
        );
        assert_eq!(
            tcpdump_args(&req("lo", " 2a00:1450::5 ", "", "udp")).unwrap().join(" "),
            "-i lo -n -U --immediate-mode -c 200000 -w - host 2a00:1450::5 and udp"
        );
    }

    #[test]
    fn rejects_anything_else() {
        assert!(tcpdump_args(&req("any", "example.com", "", "")).is_err());
        assert!(tcpdump_args(&req("any", "1.2.3.4 or not arp", "", "")).is_err());
        assert!(tcpdump_args(&req("any", "", "443 -w /etc/passwd", "")).is_err());
        assert!(tcpdump_args(&req("any", "", "0", "")).is_err());
        assert!(tcpdump_args(&req("any", "", "", "icmp or tcp")).is_err());
        assert!(tcpdump_args(&req("-w", "", "", "")).is_err());
        assert!(tcpdump_args(&req("../../etc", "", "", "")).is_err());
        assert!(tcpdump_args(&req("gibtesnicht0", "", "", "")).is_err());
    }
}
