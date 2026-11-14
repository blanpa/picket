//! All security checks. Every check is read-only.

mod access;
mod antivirus;
mod docker;
mod extras;
mod firewall;
mod network;
mod software;
mod system;

use crate::model::{Category, Finding, HostInfo, PrivInfo, Report, Status};
use crate::net::NetSnapshot;
use crate::privileged::{self, Privileged};
use crate::util;
use std::path::PathBuf;
use std::time::Instant;

pub struct Ctx {
    pub net: NetSnapshot,
    pub privd: Option<Privileged>,
    pub home: PathBuf,
    /// `sudo <this binary> root-snapshot`
    pub root_cmd: String,
}

type Check = fn(&Ctx) -> Vec<Finding>;

/// Each entry runs in its own thread; slow tools (apt, pro, snap, fwupd) are separate entries.
const CHECKS: &[(&str, Category, Check)] = &[
    ("firewall", Category::Firewall, firewall::check),
    ("network", Category::Network, network::check),
    ("docker", Category::Docker, docker::check),
    ("tailscale", Category::Network, extras::tailscale),
    ("opensnitch", Category::Firewall, extras::opensnitch),
    ("backup", Category::System, extras::backup),
    ("antivirus", Category::Antivirus, antivirus::check),
    ("apt", Category::Software, software::apt),
    ("esm", Category::Software, software::esm),
    ("snap", Category::Software, software::snap),
    ("flatpak", Category::Software, software::flatpak),
    ("firmware", Category::Software, software::firmware),
    ("sources", Category::Software, software::sources),
    ("system", Category::System, system::check),
    ("hsi", Category::System, system::hsi),
    ("access", Category::Access, access::check),
];

fn host_info() -> HostInfo {
    let dmi = |f: &str| util::read(format!("/sys/class/dmi/id/{f}")).unwrap_or_default();
    let os = util::read("/etc/os-release")
        .and_then(|c| util::conf_value(&c, "PRETTY_NAME"))
        .unwrap_or_default();
    let cpu = util::read("/proc/cpuinfo")
        .and_then(|c| {
            c.lines()
                .find(|l| l.starts_with("model name"))
                .and_then(|l| l.split_once(':').map(|x| x.1.trim().to_string()))
        })
        .unwrap_or_default();
    HostInfo {
        hostname: util::read("/proc/sys/kernel/hostname").unwrap_or_default(),
        model: format!("{} {} {}", dmi("sys_vendor"), dmi("product_name"), dmi("product_version"))
            .trim()
            .to_string(),
        bios: format!("{} ({})", dmi("bios_version"), dmi("bios_date")),
        cpu,
        os,
        kernel: util::read("/proc/sys/kernel/osrelease").unwrap_or_default(),
    }
}

/// Checks that query package managers or firmware services (slow, and they use the network).
const SLOW: [&str; 6] = ["apt", "esm", "snap", "flatpak", "firmware", "hsi"];

pub fn build_report() -> Report {
    build_report_opts(false)
}

/// `light` skips the slow checks; the watcher uses that for its frequent rounds.
pub fn build_report_opts(light: bool) -> Report {
    if crate::demo::enabled() {
        return crate::demo::report();
    }
    let started = Instant::now();
    let privd = privileged::load();
    let net = crate::net::snapshot(privd.as_ref());
    let ctx = Ctx {
        net,
        privd,
        home: util::home(),
        root_cmd: format!("sudo {} root-snapshot", util::self_exe()),
    };

    let mut findings: Vec<Finding> = Vec::new();
    std::thread::scope(|s| {
        let ctx = &ctx;
        let handles: Vec<_> = CHECKS
            .iter()
            .filter(|(name, ..)| !(light && SLOW.contains(name)))
            .map(|(name, cat, f)| (*name, *cat, s.spawn(move || f(ctx))))
            .collect();
        for (name, cat, h) in handles {
            match h.join() {
                Ok(v) => findings.extend(v),
                Err(_) => findings.push(
                    Finding::new(&format!("internal.{name}"), cat, "Prüfung fehlgeschlagen").set(
                        Status::Unknown,
                        format!("Die Prüfung „{name}“ ist mit einem internen Fehler abgebrochen."),
                    ),
                ),
            }
        }
    });
    crate::accept::apply(&mut findings, &crate::accept::load());
    findings.sort_by_key(|f| (f.category, f.accepted, f.status));

    let counts = crate::model::tally(&findings);

    Report {
        generated: util::now(),
        duration_ms: started.elapsed().as_millis() as u64,
        host: host_info(),
        counts,
        privileged: PrivInfo {
            available: ctx.privd.is_some(),
            created: ctx.privd.as_ref().map(|p| p.created),
            command: ctx.root_cmd.clone(),
        },
        findings,
    }
}
