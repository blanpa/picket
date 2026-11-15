//! Picket: local security check for a Linux laptop.
//!
//! Read-only: the tool inspects the system and explains findings; it never
//! changes settings itself.

mod accept;
mod blocklist;
mod capture;
mod checks;
mod deep;
mod demo;
mod devices;
mod docker;
mod fixes;
mod fwctl;
mod geo;
mod helper;
mod i18n;
mod i18n_en;
mod history;
mod osv;
mod report;
mod selftest;
mod watch;
#[cfg(feature = "gui")]
mod graph;
#[cfg(feature = "gui")]
mod gui;
#[cfg(feature = "gui")]
mod session;
mod model;
mod net;
#[cfg_attr(not(feature = "gui"), allow(dead_code))]
mod pcap;
mod privileged;
mod scan;
mod server;
mod util;

use i18n::tr;
use model::{Category, Report, Status};
use net::{NetSnapshot, Zone};
use std::io::IsTerminal;
use std::process::ExitCode;

/// Application ID; the .desktop file and icon carry the same name.
pub const APP_ID: &str = "io.github.blanpa.Picket";
const ICON_SVG: &str = include_str!("../assets/icon.svg");

const HELP: &str = "\
picket – Sicherheits-Check für den Laptop

AUFRUF
  picket                 App-Fenster öffnen
  picket serve           Dashboard im Browser öffnen (nur lokal, 127.0.0.1)
  picket install-desktop Eintrag und Symbol im Ubuntu-App-Menü anlegen
  picket check           Prüfbericht im Terminal
  picket net             Netzwerkübersicht: was geht ins Internet, was bleibt im LAN
  picket devices         Geräte im lokalen Netz (mit --scan: Netz aktiv durchsuchen)
  picket ports <IP>      Übliche Dienste eines Geräts im Netz prüfen
  picket docker          Container, ihre Ports und Rechte
  picket images          Images der laufenden Container mit Trivy auf bekannte Lücken prüfen
  picket deep            Tiefenprüfung (Zugangsdaten, Autostart, set-uid, Lynis; dauert Minuten)
  picket watch           Eine Wächter-Runde: meldet, was sich geändert hat
  picket watch on|off    Wächter alle 5 Minuten im Hintergrund laufen lassen
  picket events          Was der Wächter bisher gemeldet hat
  picket history [TAG]   Verbindungs-Verlauf eines Tages (JJJJ-MM-TT)
  picket fix <BEFUND>    Korrektur für einen Befund ausführen (--dry-run zeigt sie nur)
  picket report          Bericht als HTML ausgeben
  picket cve             Bekannte Lücken in cargo-, pip- und npm-Programmen bei osv.dev abfragen
  picket accept <BEFUND> Befund akzeptieren: zählt und meldet nicht mehr, bis er sich ändert
  picket unaccept <BEFUND>
  sudo picket install-helper   Root-Helfer und polkit-Regel einrichten (einmalig)
  sudo picket selftest-root    Root-Funktionen echt durchtesten, ohne etwas zu ändern
  picket update-data     Länder-Datenbank und Sperrliste laden
  picket lookup <X>      Land/Anbieter einer IP oder Sperrlisten-Status einer Domain (offline)
  picket scan <PFAD>     Virenscan eines Ordners mit ClamAV
  sudo picket root-snapshot
                              Zusatzdaten sammeln, die nur root lesen kann
                              (Firewall-Regeln, fremde Prozessnamen, leere Passwörter)

OPTIONEN
  --port <N>     Port für das Browser-Dashboard (Standard: 7373)
  --no-open      Browser nicht automatisch öffnen (serve)
  --json         Ausgabe als JSON (check, net, devices)
  --scan         Alle Adressen des lokalen Netzes ansprechen (devices)
  --all          Auch unauffällige Prüfungen ausführlich zeigen (check)

Das Programm liest nur. Einzige Ausnahme: Firewall-Regeln, die du im App-Fenster
selbst setzt und mit deinem Passwort bestätigst.";

struct Paint(bool);

impl Paint {
    /// The text in the interface language, coloured on a terminal.
    fn c(&self, code: &str, s: &str) -> String {
        let s = tr(s);
        if self.0 {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s
        }
    }
    fn status(&self, st: Status) -> String {
        let code = match st {
            Status::Crit => "1;31",
            Status::Warn => "1;33",
            Status::Unknown => "35",
            Status::Info => "36",
            Status::Ok => "32",
        };
        self.c(code, &format!("{:<8}", tr(st.label())))
    }
}

fn print_report(r: &Report, all: bool) {
    let r = &r.localized();
    let p = Paint(std::io::stdout().is_terminal());
    crate::outln!("{}", p.c("1", &format!("Picket – {} ({})", r.host.model, r.host.hostname)));
    crate::outln!("{} · Kernel {} · BIOS {}\n", r.host.os, r.host.kernel, r.host.bios);
    for cat in Category::ALL {
        let items: Vec<_> = r.findings.iter().filter(|f| f.category == cat).collect();
        if items.is_empty() {
            continue;
        }
        crate::outln!("{}", p.c("1;4", cat.label()));
        for f in items {
            if f.accepted {
                crate::outln!("  {} {} – {}", p.c("2", "AKZEPT. "), f.title, p.c("2", &f.summary));
            } else {
                crate::outln!("  {} {} – {}", p.status(f.status), p.c("1", &f.title), f.summary);
            }
            let verbose = all || (!f.accepted && matches!(f.status, Status::Crit | Status::Warn | Status::Unknown));
            if !verbose {
                continue;
            }
            for d in f.details.iter().take(if all { usize::MAX } else { 12 }) {
                crate::outln!("             · {d}");
            }
            if !all && f.details.len() > 12 {
                crate::outln!("             · … {} weitere (mit --all anzeigen)", f.details.len() - 12);
            }
            if !f.fix.is_empty() {
                crate::outln!("             {} {}", p.c("1", "→"), f.fix);
            }
            for c in &f.commands {
                crate::outln!("               {}", p.c("2", &format!("$ {c}")));
            }
        }
        crate::outln!();
    }
    let c = &r.counts;
    crate::outln!(
        "{}  {} kritisch · {} Warnungen · {} unklar · {} Hinweise · {} in Ordnung · {} akzeptiert   ({:.1} s)",
        p.c("1", "Ergebnis:"),
        c.crit,
        c.warn,
        c.unknown,
        c.info,
        c.ok,
        c.accepted,
        r.duration_ms as f64 / 1000.0
    );
    if !r.privileged.available {
        crate::outln!("\nEinige Prüfungen brauchen Root-Rechte. Einmalig ausführen:\n  $ {}", r.privileged.command);
    }
}

fn print_net(n: &NetSnapshot) {
    let p = Paint(std::io::stdout().is_terminal());
    const ZONES: [Zone; 5] = [Zone::Internet, Zone::Lan, Zone::Vpn, Zone::Container, Zone::Loopback];
    crate::outln!("{}", p.c("1", "Aktive Verbindungen nach Ziel"));
    for z in ZONES {
        let t = n.totals.get(&z).cloned().unwrap_or_default();
        crate::outln!(
            "  {:<20} {:>4} Verbindungen · {:>3} Gegenstellen · {:>3} Programme",
            tr(z.label()),
            t.connections,
            t.hosts,
            t.programs
        );
    }
    crate::outln!("\n{}", p.c("1", "Programme mit Verbindungen nach außen"));
    crate::outln!("  {:<28} {:>8} {:>6} {:>5} {:>10}", tr("Programm"), "Internet", "LAN", "VPN", "Container");
    let count = |pr: &net::Program, z: Zone| pr.zones.get(&z).copied().unwrap_or(0);
    for pr in &n.programs {
        let outside = count(pr, Zone::Internet) + count(pr, Zone::Lan) + count(pr, Zone::Vpn) + count(pr, Zone::Container);
        if outside == 0 {
            continue;
        }
        let name = if pr.name.is_empty() { tr("(System / anderer Benutzer)") } else { pr.name.clone() };
        crate::outln!(
            "  {:<28} {:>8} {:>6} {:>5} {:>10}",
            name,
            count(pr, Zone::Internet),
            count(pr, Zone::Lan),
            count(pr, Zone::Vpn),
            count(pr, Zone::Container)
        );
    }
    crate::outln!("\n{}", p.c("1", "Offene Ports, die von anderen Geräten erreichbar sind"));
    let exposed = n.exposed();
    if exposed.is_empty() {
        crate::outln!("  keine");
    }
    for l in exposed {
        crate::outln!(
            "  {:<4} {:>5}  {:<22} {:<14} {}",
            l.proto,
            l.port,
            tr(l.service.unwrap_or("")),
            tr(l.exposure.label()),
            tr(&l.who())
        );
    }
    crate::outln!("\nHinweis: Verbindungen aus Docker-Containern und VMs erscheinen hier nicht.");
}

fn print_devices(networks: &[devices::Network]) {
    let p = Paint(std::io::stdout().is_terminal());
    if networks.is_empty() {
        crate::outln!("Kein lokales Netz verbunden.");
    }
    for n in networks {
        crate::outln!(
            "{}",
            p.c("1", &format!("{} {} · {} · {} Geräte", if n.wireless { "WLAN" } else { "Kabel" }, n.iface, n.subnet, n.devices.len()))
        );
        for d in &n.devices {
            let mut tags = Vec::new();
            if d.is_gateway {
                tags.push("Router");
            }
            if d.is_self {
                tags.push("dieser Laptop");
            }
            if d.is_new {
                tags.push("NEU");
            }
            if d.random_mac {
                tags.push("zufällige MAC");
            }
            if !d.active {
                tags.push("zuletzt gesehen");
            }
            crate::outln!(
                "  {:<16} {:<18} {:<34} {}",
                d.ip,
                d.mac,
                tr(&d.title()).chars().take(34).collect::<String>(),
                tags.iter().map(|tag| tr(tag)).collect::<Vec<_>>().join(", ")
            );
        }
        crate::outln!();
    }
}

fn run_scan_cli(path: &str) -> ExitCode {
    let Ok(abs) = std::fs::canonicalize(path) else {
        crate::errln!("Pfad nicht gefunden: {path}");
        return ExitCode::from(2);
    };
    let abs = abs.display().to_string();
    let job = scan::ScanJob::default();
    job.begin(&abs);
    crate::outln!("Scanne {abs} … (das Laden der Signaturen dauert einen Moment)");
    job.run(&abs);
    let info = job.snapshot();
    if let Some(e) = info.error {
        crate::errln!("{e}");
        return ExitCode::from(2);
    }
    crate::outln!("{} Dateien geprüft, {} nicht lesbar.", info.files, info.skipped);
    if info.infected.is_empty() {
        crate::outln!("Keine Funde.");
        ExitCode::SUCCESS
    } else {
        crate::outln!("{} Fund(e):", info.infected.len());
        for i in &info.infected {
            crate::outln!("  {} – {}", i.path, i.signature);
        }
        ExitCode::from(1)
    }
}

/// The launcher entry. English is the default; the desktop picks the `[de]` lines on a German system.
fn desktop_entry(exe: &str) -> String {
    // Desktop-entry quoting: wrap in double quotes and escape the reserved characters.
    let quoted: String = exe.chars().flat_map(|c| match c {
        '"' | '`' | '$' | '\\' => vec!['\\', c],
        _ => vec![c],
    }).collect();
    format!(
        "[Desktop Entry]\nType=Application\nName=Picket\n\
         GenericName=Security Check\nGenericName[de]=Sicherheitsprüfung\n\
         Comment=Check the firewall, antivirus, updates and network of this laptop\n\
         Comment[de]=Firewall, Virenscanner, Updates und Netzwerk des Laptops prüfen\n\
         Exec=\"{quoted}\" gui\nIcon={APP_ID}\nTerminal=false\nCategories=System;Security;GTK;\n\
         Keywords=Security;Firewall;Antivirus;Network;Updates;\n\
         Keywords[de]=Sicherheit;Firewall;Virenscanner;Netzwerk;Updates;Security;\nStartupNotify=true\n"
    )
}

/// Register the app with the desktop: launcher entry and icon for the current user.
fn install_desktop() -> Result<(), String> {
    let data = std::env::var_os("XDG_DATA_HOME")
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| util::home().join(".local/share"));
    let apps = data.join("applications");
    let icons = data.join("icons/hicolor/scalable/apps");
    let entry = desktop_entry(&util::self_exe());
    for (dir, name, content) in [
        (&apps, format!("{APP_ID}.desktop"), entry.as_str()),
        (&icons, format!("{APP_ID}.svg"), ICON_SVG),
    ] {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let path = dir.join(name);
        std::fs::write(&path, content).map_err(|e| format!("{}: {e}", path.display()))?;
        crate::outln!("geschrieben: {}", path.display());
    }
    // The desktop only notices a replaced icon when the theme directory itself changes:
    // without this, an updated icon keeps showing its old picture until the next login.
    if let Some(theme) = icons.parent().and_then(|p| p.parent()) {
        if let Ok(dir) = std::fs::File::open(theme) {
            let _ = dir.set_modified(std::time::SystemTime::now());
        }
    }
    // Entries from before the program was renamed.
    let _ = std::fs::remove_file(apps.join("io.fwsecurity.App.desktop"));
    let _ = std::fs::remove_file(icons.join("io.fwsecurity.App.svg"));
    // Best effort; the desktop also notices new entries on its own.
    let _ = util::run("update-desktop-database", &[&apps.display().to_string()], 10);
    Ok(())
}

fn start_gui() -> ExitCode {
    if util::uid() == 0 {
        crate::errln!("Die App bitte nicht als root starten.");
        return ExitCode::from(2);
    }
    #[cfg(feature = "gui")]
    {
        gui::run()
    }
    #[cfg(not(feature = "gui"))]
    {
        crate::errln!("Dieses Binary wurde ohne Oberfläche gebaut. Browser-Dashboard: picket serve");
        ExitCode::from(2)
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut positional: Vec<&str> = Vec::new();
    let (mut port, mut open, mut json, mut all) = (None, true, false, false);
    let (mut dry_run, mut scan_net) = (false, false);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--port" => match it.next().and_then(|p| p.parse::<u16>().ok()) {
                Some(p) => port = Some(p),
                None => {
                    crate::errln!("--port braucht eine Zahl zwischen 1 und 65535.");
                    return ExitCode::from(2);
                }
            },
            "--no-open" => open = false,
            "--json" => json = true,
            "--all" => all = true,
            "--dry-run" => dry_run = true,
            "--scan" => scan_net = true,
            "-h" | "--help" | "help" => {
                crate::outln!("{HELP}");
                return ExitCode::SUCCESS;
            }
            s if s.starts_with('-') => {
                crate::errln!("Unbekannte Option: {s}\n\n{HELP}");
                return ExitCode::from(2);
            }
            s => positional.push(s),
        }
    }

    if util::uid() != 0 {
        util::migrate_legacy_dirs();
    }
    // Terminal commands end quietly when their output is cut off (`picket check | head`)
    // instead of panicking on the closed pipe. The window and the dashboard keep the default.
    if !matches!(positional.first().copied(), None | Some("gui" | "serve")) {
        // SAFETY: restores the default action of SIGPIPE before any other thread exists.
        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        }
    }

    // The installed root helper only carries out the root commands, nothing else.
    if helper::is_helper() && !positional.first().map(|c| helper::COMMANDS.contains(c)).unwrap_or(false) {
        crate::errln!("Der Helfer führt nur diese Befehle aus: {}", helper::COMMANDS.join(", "));
        return ExitCode::from(2);
    }

    match positional.as_slice() {
        ["protocol"] => {
            crate::outln!("{}", helper::PROTOCOL);
            ExitCode::SUCCESS
        }
        ["install-helper"] => match helper::install() {
            Ok(()) => {
                crate::outln!("Helfer eingerichtet: {}\npolkit-Regel: {}", helper::PATH, helper::POLICY);
                ExitCode::SUCCESS
            }
            Err(e) => {
                crate::errln!("{e}");
                ExitCode::from(1)
            }
        },
        ["remove-helper"] => match helper::remove() {
            Ok(()) => {
                crate::outln!("Helfer und polkit-Regel entfernt.");
                ExitCode::SUCCESS
            }
            Err(e) => {
                crate::errln!("{e}");
                ExitCode::from(1)
            }
        },
        ["selftest-root"] => {
            if selftest::run() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        ["accept", id] => {
            let report = checks::build_report();
            match report.findings.iter().find(|f| f.id == *id) {
                Some(f) => match accept::set(id, Some(&f.summary)) {
                    Ok(()) => {
                        crate::outln!("Akzeptiert: {} – {}", f.title, f.summary);
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        crate::errln!("{e}");
                        ExitCode::from(1)
                    }
                },
                None => {
                    crate::errln!("Kein Befund mit der Kennung „{id}“. Kennungen zeigt: picket check --json");
                    ExitCode::from(2)
                }
            }
        }
        ["unaccept", id] => match accept::set(id, None) {
            Ok(()) => {
                crate::outln!("„{id}“ wird wieder gemeldet.");
                ExitCode::SUCCESS
            }
            Err(e) => {
                crate::errln!("{e}");
                ExitCode::from(1)
            }
        },
        [] | ["gui"] => start_gui(),
        // For packaging: the launcher entry of a system-wide installation.
        ["desktop-entry"] => {
            print!("{}", desktop_entry("/usr/bin/picket"));
            ExitCode::SUCCESS
        }
        ["install-desktop"] => match install_desktop() {
            Ok(()) => {
                crate::outln!("Die App „Picket“ steht jetzt im App-Menü.");
                ExitCode::SUCCESS
            }
            Err(e) => {
                crate::errln!("Installation fehlgeschlagen: {e}");
                ExitCode::from(2)
            }
        },
        ["serve"] => {
            if util::uid() == 0 {
                crate::errln!(
                    "Das Dashboard bitte nicht als root starten. Für Root-Daten: sudo {} root-snapshot",
                    util::self_exe()
                );
                return ExitCode::from(2);
            }
            match server::serve(port, open) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    crate::errln!("{e}");
                    ExitCode::from(2)
                }
            }
        }
        ["check"] => {
            let r = checks::build_report();
            if json {
                println!("{}", i18n::json(&r, true).unwrap_or_default());
            } else {
                print_report(&r, all);
            }
            // Exit code 1 signals critical findings (useful in scripts).
            if r.counts.crit > 0 {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        ["net"] => {
            let privd = privileged::load();
            let n = net::snapshot(privd.as_ref());
            if json {
                println!("{}", i18n::json(&n, true).unwrap_or_default());
            } else {
                print_net(&n);
            }
            ExitCode::SUCCESS
        }
        ["scan", path] => run_scan_cli(path),
        ["ports", ip] => {
            let Ok(addr) = ip.parse::<std::net::IpAddr>() else {
                crate::errln!("Keine gültige IP-Adresse: {ip}");
                return ExitCode::from(2);
            };
            let open = devices::port_check(addr);
            if json {
                println!("{}", i18n::json(&open, true).unwrap_or_default());
            } else if open.is_empty() {
                crate::outln!("Keiner der geprüften Dienste antwortet auf {ip}.");
            } else {
                for p in open {
                    crate::outln!("  {:>5}  {}{}", p.port, tr(p.service), if p.risky { "  ⚠" } else { "" });
                }
            }
            ExitCode::SUCCESS
        }
        ["docker"] => {
            match docker::list() {
                None => crate::outln!("Docker ist nicht installiert oder nicht zugänglich."),
                Some(list) if json => println!("{}", i18n::json(&list, true).unwrap_or_default()),
                Some(list) => {
                    for c in list {
                        let mut flags = Vec::new();
                        if c.privileged {
                            flags.push("privilegiert");
                        }
                        if c.docker_socket {
                            flags.push("docker.sock");
                        }
                        if c.host_network {
                            flags.push("Host-Netz");
                        }
                        if c.runs_as_root() {
                            flags.push("root");
                        }
                        crate::outln!("{:<34} {:<40} {}", c.name, c.image.chars().take(40).collect::<String>(), flags.iter().map(|f| tr(f)).collect::<Vec<_>>().join(", "));
                        for p in c.open_ports() {
                            crate::outln!("    offen: {}/{}  →  besser {}", p.proto, p.host_port, p.local_binding());
                        }
                    }
                }
            }
            ExitCode::SUCCESS
        }
        ["images"] => {
            if !docker::trivy_available() {
                crate::errln!("Trivy ist nicht installiert. Mit Homebrew: brew install trivy – sonst siehe trivy.dev.");
                return ExitCode::from(2);
            }
            let mut images: Vec<String> = docker::list().unwrap_or_default().into_iter().map(|c| c.image).collect();
            images.sort();
            images.dedup();
            let mut worst = ExitCode::SUCCESS;
            for image in images {
                crate::errln!("Prüfe {image} …");
                match docker::scan_image(&image) {
                    Ok(scan) if json => println!("{}", i18n::json(&scan, false).unwrap_or_default()),
                    Ok(scan) => {
                        crate::outln!("{}: {} kritisch, {} hoch", scan.image, scan.critical, scan.high);
                        for line in scan.examples.iter().take(if all { usize::MAX } else { 4 }) {
                            crate::outln!("    {line}");
                        }
                        if scan.critical > 0 {
                            worst = ExitCode::from(1);
                        }
                    }
                    Err(e) => crate::errln!("{image}: {e}"),
                }
            }
            worst
        }
        ["deep"] => {
            let findings = deep::run_all(&|step| crate::errln!("{step}"));
            if json {
                println!("{}", i18n::json(&findings, true).unwrap_or_default());
            } else {
                let p = Paint(std::io::stdout().is_terminal());
                for f in findings.iter().map(model::Finding::localized) {
                    crate::outln!("{} {} – {}", p.status(f.status), p.c("1", &f.title), f.summary);
                    for d in f.details.iter().take(if all { usize::MAX } else { 15 }) {
                        crate::outln!("           · {d}");
                    }
                }
            }
            ExitCode::SUCCESS
        }
        ["watch"] => {
            let events = watch::run_once(true);
            for e in &events {
                crate::outln!("[{}] {} – {}", e.level, tr(&e.title), tr(&e.text));
            }
            if events.is_empty() {
                crate::outln!("Keine Änderungen.");
            }
            ExitCode::SUCCESS
        }
        ["watch", mode @ ("on" | "off")] => match watch::set_timer(*mode == "on") {
            Ok(()) => {
                crate::outln!("Wächter {}.", if *mode == "on" { "eingeschaltet (alle 5 Minuten)" } else { "ausgeschaltet" });
                ExitCode::SUCCESS
            }
            Err(e) => {
                crate::errln!("{e}");
                ExitCode::from(1)
            }
        },
        ["events"] => {
            let events = watch::events();
            if json {
                println!("{}", i18n::json(&events, true).unwrap_or_default());
            } else {
                for e in events.iter().take(60) {
                    crate::outln!("{}  [{}] {} – {}", util::format_time(e.time, "+%d.%m. %H:%M"), e.level, tr(&e.title), tr(&e.text));
                }
            }
            ExitCode::SUCCESS
        }
        ["history"] | ["history", _] => {
            let days = history::days();
            let day = positional.get(1).map(|d| d.to_string()).or_else(|| days.first().cloned()).unwrap_or_default();
            let entries = history::load(&day);
            if json {
                println!("{}", i18n::json(&entries, true).unwrap_or_default());
            } else {
                crate::outln!("Aufgezeichnete Tage: {}", if days.is_empty() { "keine – der Wächter zeichnet auf".to_string() } else { days.join(", ") });
                for e in entries.iter().take(40) {
                    crate::outln!(
                        "  {:<22} {:<40} {:>5}/{}  ↑ {:>9}  ↓ {:>9}  {}",
                        if e.program.is_empty() { "(System)" } else { &e.program },
                        e.remote,
                        e.port,
                        e.proto,
                        util::format_bytes(e.sent),
                        util::format_bytes(e.received),
                        tr(&e.zone)
                    );
                }
            }
            ExitCode::SUCCESS
        }
        ["fix", id] => {
            let Some(fix) = fixes::for_finding(id) else {
                crate::errln!("Für „{id}“ gibt es keine automatische Korrektur.");
                return ExitCode::from(2);
            };
            if dry_run {
                for c in &fix.commands {
                    crate::outln!("{}{c}", if fix.root { "sudo " } else { "" });
                }
                return ExitCode::SUCCESS;
            }
            match fixes::apply(id) {
                Ok(msg) => {
                    crate::outln!("{msg}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    crate::errln!("{e}");
                    ExitCode::from(1)
                }
            }
        }
        ["report"] => {
            let r = checks::build_report();
            println!("{}", report::html(&r, &util::date("+%d.%m.%Y %H:%M")));
            ExitCode::SUCCESS
        }
        ["cve"] => {
            let packages = osv::inventory();
            if dry_run || packages.is_empty() {
                crate::outln!("An osv.dev würden {} Programme gemeldet (Name und Version):", packages.len());
                for p in &packages {
                    crate::outln!("  {} {} ({})", p.name, p.version, p.ecosystem);
                }
                return ExitCode::SUCCESS;
            }
            match osv::query(&packages) {
                Ok(v) if v.is_empty() => {
                    crate::outln!("Keine bekannten Lücken in {} Programmen.", packages.len());
                    ExitCode::SUCCESS
                }
                Ok(v) => {
                    for x in v {
                        crate::outln!("{} {} – {} {}", x.package, x.version, x.id, x.summary);
                    }
                    ExitCode::from(1)
                }
                Err(e) => {
                    crate::errln!("{e}");
                    ExitCode::from(2)
                }
            }
        }
        // Ask about one specific package instead of the installed ones (ecosystem: crates.io, PyPI, npm).
        ["cve", ecosystem, name, version] => match osv::query(&[osv::Package::new(ecosystem, name, version)]) {
            Ok(v) => {
                for x in &v {
                    crate::outln!("{} {} – {} {}", x.package, x.version, x.id, x.summary);
                }
                crate::outln!("{} bekannte Lücken.", v.len());
                ExitCode::SUCCESS
            }
            Err(e) => {
                crate::errln!("{e}");
                ExitCode::from(2)
            }
        },
        // Offline lookup: country and operator of an address, or whether a domain is on the blocklist.
        ["lookup", what] => {
            match what.parse::<std::net::IpAddr>() {
                Ok(ip) => match geo::lookup(ip) {
                    Some(g) => crate::outln!("{ip}: {}", g.label()),
                    None if geo::available() => crate::outln!("{ip}: kein Eintrag"),
                    None => crate::outln!("Die Länder-Datenbank fehlt (picket update-data)."),
                },
                Err(_) if blocklist::available() => crate::outln!(
                    "{what}: {}",
                    tr(if blocklist::is_listed(what) { "steht auf der Sperrliste (Werbung, Tracking oder Schadsoftware)" } else { "nicht auf der Sperrliste" })
                ),
                Err(_) => crate::outln!("Die Sperrliste fehlt (picket update-data)."),
            }
            ExitCode::SUCCESS
        }
        ["update-data"] => {
            let mut code = ExitCode::SUCCESS;
            for result in [geo::download(), blocklist::download()] {
                match result {
                    Ok(msg) => crate::outln!("{msg}"),
                    Err(e) => {
                        crate::errln!("{e}");
                        code = ExitCode::from(1);
                    }
                }
            }
            code
        }
        ["devices"] => {
            let networks = devices::discover(scan_net);
            if json {
                println!("{}", i18n::json(&networks, true).unwrap_or_default());
            } else {
                print_devices(&networks);
            }
            ExitCode::SUCCESS
        }
        // Root helper for the window's packet capture (started through pkexec):
        // raw pcap data on standard output until standard input is closed.
        ["capture", request] => {
            let req: capture::Request = match serde_json::from_str(request) {
                Ok(r) => r,
                Err(e) => {
                    crate::errln!("Ungültige Anfrage: {e}");
                    return ExitCode::from(2);
                }
            };
            if dry_run {
                return match capture::tcpdump_args(&req) {
                    Ok(args) => {
                        crate::outln!("sudo tcpdump {}", args.join(" "));
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        crate::errln!("{e}");
                        ExitCode::from(1)
                    }
                };
            }
            if util::uid() != 0 {
                crate::errln!("Der Mitschnitt braucht Root-Rechte (mit --dry-run nur den Befehl anzeigen).");
                return ExitCode::from(2);
            }
            match capture::run(&req) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    crate::errln!("{e}");
                    ExitCode::from(1)
                }
            }
        }
        // Root helper for the window's firewall controls (started through pkexec).
        ["fw-apply", request] => {
            let ops: Vec<fwctl::Op> = match serde_json::from_str::<Vec<fwctl::Op>>(request)
                .or_else(|_| serde_json::from_str::<fwctl::Op>(request).map(|op| vec![op]))
            {
                Ok(ops) => ops,
                Err(e) => {
                    crate::errln!("Ungültige Anfrage: {e}");
                    return ExitCode::from(2);
                }
            };
            if !dry_run && util::uid() != 0 {
                crate::errln!("Firewall-Änderungen brauchen Root-Rechte (mit --dry-run nur anzeigen).");
                return ExitCode::from(2);
            }
            match fwctl::apply(&ops, dry_run) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    crate::errln!("{e}");
                    ExitCode::from(1)
                }
            }
        }
        ["root-snapshot"] => {
            if util::uid() != 0 && std::env::var_os("PICKET_PRIV_FILE").is_none() {
                crate::errln!("Dieser Befehl braucht Root-Rechte:\n  sudo {} root-snapshot", util::self_exe());
                return ExitCode::from(2);
            }
            let p = privileged::collect();
            match privileged::write(&p) {
                Ok(path) => {
                    crate::outln!(
                        "Root-Snapshot geschrieben: {}\nIm Dashboard jetzt „Neu prüfen“ klicken. Der Snapshot gilt 24 Stunden bzw. bis zum Neustart.",
                        path.display()
                    );
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    crate::errln!("Snapshot konnte nicht geschrieben werden: {e}");
                    ExitCode::from(2)
                }
            }
        }
        _ => {
            crate::errln!("Unbekannter Aufruf.\n\n{HELP}");
            ExitCode::from(2)
        }
    }
}
