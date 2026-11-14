//! Smaller checks: Tailscale, OpenSnitch, backups.

use super::Ctx;
use crate::model::{Category, Finding, Status};
use crate::util;

pub fn tailscale(_ctx: &Ctx) -> Vec<Finding> {
    let Some(out) = util::run("tailscale", &["status", "--json"], 6) else {
        return Vec::new();
    };
    let f = Finding::new("net.tailscale", Category::Network, "Tailscale (VPN)")
        .why("Über Tailscale sind die Geräte deines Tailnets direkt miteinander verbunden – auch dieser Laptop ist für sie erreichbar.");
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&out.stdout) else {
        return vec![f.set(Status::Info, "Tailscale ist installiert, der Status ist nicht lesbar.")];
    };
    if v["BackendState"].as_str() != Some("Running") {
        return vec![f.set(Status::Info, format!("Tailscale ist nicht verbunden ({}).", v["BackendState"].as_str().unwrap_or("?")))];
    }
    let peers: Vec<&serde_json::Value> = v["Peer"].as_object().map(|m| m.values().collect()).unwrap_or_default();
    let online = peers.iter().filter(|p| p["Online"].as_bool().unwrap_or(false)).count();
    let exit: Vec<&str> = peers.iter().filter(|p| p["ExitNode"].as_bool().unwrap_or(false)).filter_map(|p| p["HostName"].as_str()).collect();
    // Key expiry as "YYYY-MM-DD…": compare against today's date as text.
    let expiry = v["Self"]["KeyExpiry"].as_str().unwrap_or("");
    let soon = util::date("--date=+14 days +%F");
    let mut f = f
        .detail(format!("Geräte im Tailnet: {} ({online} online)", peers.len()))
        .details(peers.iter().filter_map(|p| {
            Some(format!("{} – {}{}", p["HostName"].as_str()?, p["OS"].as_str().unwrap_or("?"), if p["Online"].as_bool().unwrap_or(false) { "" } else { " (offline)" }))
        }));
    if !exit.is_empty() {
        f = f.detail(format!("Exit-Node in Benutzung: {} – der gesamte Internetverkehr läuft darüber", exit.join(", ")));
    }
    vec![if !expiry.is_empty() && !soon.is_empty() && expiry.get(..10).map(|d| d < soon.as_str()).unwrap_or(false) {
        f.set(Status::Warn, format!("Der Tailscale-Schlüssel dieses Laptops läuft am {} ab.", &expiry[..10]))
            .fix("Neu anmelden, bevor die Verbindung abreißt.", &["sudo tailscale up --force-reauth"])
    } else {
        f.set(
            Status::Info,
            format!(
                "Verbunden mit {} ({online} online){}.",
                util::plural(peers.len(), "Gerät", "Geräten"),
                if expiry.len() >= 10 { format!(", Schlüssel gültig bis {}", &expiry[..10]) } else { String::new() }
            ),
        )
    }]
}

pub fn opensnitch(_ctx: &Ctx) -> Vec<Finding> {
    let f = Finding::new("fw.opensnitch", Category::Firewall, "Programm-Firewall (OpenSnitch)").why(
        "ufw filtert nach Ports und Adressen, nicht nach Programmen. OpenSnitch fragt bei jedem neuen Programm, das ins Internet will, ob es das darf – ähnlich wie Little Snitch auf dem Mac.",
    );
    let installed = util::which("opensnitchd").is_some();
    vec![if installed && util::service_active("opensnitch") {
        f.set(Status::Ok, "OpenSnitch läuft: Programme brauchen eine Erlaubnis für ausgehende Verbindungen.")
    } else if installed {
        f.set(Status::Info, "OpenSnitch ist installiert, läuft aber nicht.")
            .fix("Dienst einschalten und die Oberfläche starten.", &["sudo systemctl enable --now opensnitch", "opensnitch-ui"])
    } else {
        f.set(Status::Info, "Nicht installiert – jedes Programm darf ungefragt ins Internet.")
            .fix(
                "Wer pro Programm entscheiden will, installiert OpenSnitch. Rechne in den ersten Tagen mit vielen Nachfragen.",
                &["sudo apt install opensnitch python3-opensnitch-ui", "sudo systemctl enable --now opensnitch"],
            )
    }]
}

/// Days since something last touched this path.
fn age(path: std::path::PathBuf) -> Option<u64> {
    util::age_days(path)
}

pub fn backup(ctx: &Ctx) -> Vec<Finding> {
    let f = Finding::new("sys.backup", Category::System, "Datensicherung").why(
        "Gegen Erpressungstrojaner, Diebstahl und defekte SSDs hilft am Ende nur ein aktuelles Backup an einem anderen Ort.",
    );
    // (tool, days since its last visible activity)
    let mut seen: Vec<(String, Option<u64>)> = Vec::new();
    if util::which("restic").is_some() {
        seen.push(("restic".into(), age(ctx.home.join(".cache/restic"))));
    }
    if util::which("borg").is_some() {
        seen.push(("borg".into(), age(ctx.home.join(".cache/borg"))));
    }
    if std::path::Path::new("/timeshift/snapshots").exists() {
        seen.push(("Timeshift".into(), age("/timeshift/snapshots".into())));
    }
    if let Some(o) = util::run("gsettings", &["get", "org.gnome.DejaDup", "last-backup"], 5).filter(|o| o.ok) {
        let stamp = o.stdout.trim().trim_matches('\'').to_string();
        if stamp.len() >= 10 {
            seen.push((format!("Datensicherungen (Déjà Dup), zuletzt {}", &stamp[..10]), Some(0).filter(|_| stamp[..10] >= *util::date("--date=-7 days +%F"))));
        }
    }
    let recent = seen.iter().filter_map(|(_, d)| *d).min();
    let details = seen.iter().map(|(tool, d)| match d {
        Some(d) => format!("{tool}: letzte Aktivität vor {d} Tag(en)"),
        None => format!("{tool}: keine Aktivität erkennbar"),
    });
    vec![match recent {
        Some(d) if d <= 7 => f.set(Status::Ok, format!("Zuletzt vor {d} Tag(en) gesichert.")).details(details),
        Some(d) => f
            .set(Status::Warn, format!("Die letzte erkennbare Sicherung ist {d} Tage alt."))
            .details(details)
            .fix("Backup wieder regelmäßig laufen lassen, am besten automatisch.", &[]),
        None if seen.is_empty() => f
            .set(Status::Warn, "Es wurde kein Backup-Programm erkannt.")
            .fix("Ein Backup einrichten, z. B. mit „Datensicherungen“ (Déjà Dup) oder restic auf das NAS.", &[]),
        None => f
            .set(Status::Warn, "Ein Backup-Programm ist installiert, aber es ist kein Lauf erkennbar.")
            .details(details)
            .fix("Backup einrichten und testen, z. B. restic auf das NAS. Erkannt werden nur Läufe unter diesem Benutzerkonto.", &[]),
    }]
}
