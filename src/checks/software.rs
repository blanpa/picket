use super::Ctx;
use crate::model::{Category, Finding, Status};
use crate::util;
use std::fs;

const CAT: Category = Category::Software;

/// Parse `apt list` lines: "name/suite version arch [..]" -> (name, suite, version).
fn parse_apt_list(out: &str) -> Vec<(String, String, String)> {
    out.lines()
        .filter_map(|l| {
            let (name, rest) = l.split_once('/')?;
            let mut it = rest.split_whitespace();
            let suite = it.next()?;
            let version = it.next()?;
            l.contains('[').then(|| (name.to_string(), suite.to_string(), version.to_string()))
        })
        .collect()
}

pub fn apt(_ctx: &Ctx) -> Vec<Finding> {
    let mut out = Vec::new();

    // Pending updates
    let f = Finding::new("sw.updates", CAT, "Ausstehende System-Updates")
        .why("Die meisten Angriffe nutzen Lücken, für die es längst ein Update gibt.");
    out.push(match util::run("apt", &["list", "--upgradable"], 40) {
        None => f.set(Status::Unknown, "apt konnte nicht abgefragt werden."),
        Some(o) => {
            let pkgs = parse_apt_list(&o.stdout);
            let security = pkgs.iter().filter(|p| p.1.contains("security")).count();
            let lines = pkgs.iter().map(|(n, s, v)| format!("{n} → {v} ({s})"));
            if pkgs.is_empty() {
                f.set(Status::Ok, "Alle Pakete sind aktuell.")
            } else if security > 0 {
                f.set(
                    Status::Warn,
                    format!("{} ausstehend, davon {security} Sicherheitsupdates.", util::plural(pkgs.len(), "Update", "Updates")),
                )
                .details(lines)
                .fix("Updates installieren.", &["sudo apt update && sudo apt upgrade"])
            } else {
                f.set(
                    Status::Info,
                    format!("{} ausstehend (keine Sicherheitsupdates).", util::plural(pkgs.len(), "Update", "Updates")),
                )
                .details(lines)
                .fix(
                    "Updates installieren. Ubuntu verteilt manche Updates gestaffelt; sie kommen dann automatisch in den nächsten Tagen.",
                    &["sudo apt update && sudo apt upgrade"],
                )
            }
        }
    });

    // Age of the package lists
    let age = util::age_days("/var/lib/apt/periodic/update-success-stamp")
        .or_else(|| util::age_days("/var/lib/apt/lists"));
    let f = Finding::new("sw.listage", CAT, "Letzte Update-Suche");
    out.push(match age {
        None => f.set(Status::Unknown, "Zeitpunkt der letzten Update-Suche nicht feststellbar."),
        Some(d) if d > 7 => f
            .set(Status::Warn, format!("Zuletzt vor {d} Tagen nach Updates gesucht."))
            .why("Ohne aktuelle Paketlisten weiß das System nicht, dass es Updates gibt.")
            .fix("Paketlisten aktualisieren.", &["sudo apt update"]),
        Some(0) => f.set(Status::Ok, "Heute wurde nach Updates gesucht."),
        Some(d) => f.set(Status::Ok, format!("Zuletzt vor {d} Tag(en) nach Updates gesucht.")),
    });

    // Unattended upgrades
    let mut auto = false;
    if let Ok(rd) = fs::read_dir("/etc/apt/apt.conf.d") {
        for e in rd.flatten() {
            if let Ok(c) = fs::read_to_string(e.path()) {
                auto |= c.lines().any(|l| {
                    let l = l.trim();
                    !l.starts_with("//") && l.contains("APT::Periodic::Unattended-Upgrade") && l.contains("\"1\"")
                });
            }
        }
    }
    let f = Finding::new("sw.auto", CAT, "Automatische Sicherheitsupdates");
    out.push(if auto && util::which("unattended-upgrade").is_some() {
        f.set(Status::Ok, "Sicherheitsupdates werden automatisch installiert (unattended-upgrades).")
    } else {
        f.set(Status::Warn, "Automatische Sicherheitsupdates sind nicht eingerichtet.")
            .why("Ohne Automatik bleiben Lücken offen, bis du manuell aktualisierst.")
            .fix(
                "unattended-upgrades einrichten.",
                &["sudo apt install unattended-upgrades", "sudo dpkg-reconfigure -plow unattended-upgrades"],
            )
    });

    // Reboot required
    let f = Finding::new("sw.reboot", CAT, "Neustart nach Updates");
    out.push(if std::path::Path::new("/var/run/reboot-required").exists() {
        let pkgs = util::read("/var/run/reboot-required.pkgs").unwrap_or_default();
        f.set(Status::Warn, "Ein Neustart steht aus – installierte Updates sind noch nicht aktiv.")
            .details(pkgs.lines().map(String::from))
            .why("Kernel- und Bibliotheks-Updates wirken erst nach einem Neustart; bis dahin läuft die alte, verwundbare Version.")
            .fix("Laptop neu starten.", &[])
    } else {
        f.set(Status::Ok, "Kein Neustart nötig.")
    });

    // Installed packages without any repository (no automatic updates)
    let f = Finding::new("sw.orphans", CAT, "Programme ohne Update-Quelle").why(
        "Diese Pakete stammen aus keiner aktiven Paketquelle (manuell installierte .deb-Dateien oder eine abgeschaltete Quelle). \
         Sie bekommen keine automatischen Updates – auch keine Sicherheitsupdates.",
    );
    out.push(match util::run("apt", &["list", "?obsolete", "--installed"], 40) {
        None => f.set(Status::Unknown, "apt konnte nicht abgefragt werden."),
        Some(o) => {
            let pkgs = parse_apt_list(&o.stdout);
            if pkgs.is_empty() {
                f.set(Status::Ok, "Alle installierten Pakete stammen aus einer aktiven Paketquelle.")
            } else {
                f.set(
                    Status::Warn,
                    format!("{} ohne Update-Quelle.", util::plural(pkgs.len(), "Paket ist", "Pakete sind")),
                )
                .details(pkgs.iter().map(|(n, _, v)| format!("{n} {v}")))
                .fix(
                    "Prüfen, ob die passende Paketquelle noch eingerichtet ist (z. B. /etc/apt/sources.list.d/docker.sources), \
                     sonst die Programme regelmäßig von Hand aktualisieren oder entfernen.",
                    &["apt policy <paket>", "ls /etc/apt/sources.list.d/"],
                )
            }
        }
    });

    out
}

pub fn esm(_ctx: &Ctx) -> Vec<Finding> {
    let f = Finding::new("sw.esm", CAT, "Sicherheitsupdates über Ubuntu Pro").why(
        "Für Pakete aus „universe“ liefert Ubuntu Sicherheitsupdates nur über Ubuntu Pro (ESM). \
         Ohne Pro bleiben bekannte Lücken in diesen Paketen offen.",
    );
    let Some(o) = util::run("pro", &["security-status", "--format", "json"], 60) else {
        return Vec::new(); // not an Ubuntu system with the pro client
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&o.stdout) else {
        return vec![f.set(Status::Unknown, "Die Ausgabe von „pro security-status“ war nicht lesbar.")];
    };
    let s = &v["summary"];
    let apps = s["num_esm_apps_updates"].as_u64().unwrap_or(0);
    let infra = s["num_esm_infra_updates"].as_u64().unwrap_or(0);
    let attached = s["ua"]["attached"].as_bool().unwrap_or(false);
    let pending = apps + infra;
    let names: Vec<String> = v["packages"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|p| p["status"].as_str() == Some("pending_attach") || p["status"].as_str() == Some("pending_enable"))
        .filter_map(|p| Some(format!("{} → {}", p["package"].as_str()?, p["version"].as_str().unwrap_or("?"))))
        .collect();
    vec![if pending > 0 {
        f.set(
            Status::Warn,
            format!("{pending} Sicherheitsupdates gibt es nur mit Ubuntu Pro – sie sind nicht installiert."),
        )
        .details(names)
        .fix(
            "Ubuntu Pro ist für die private Nutzung auf bis zu 5 Geräten kostenlos. Token unter ubuntu.com/pro holen und den Laptop verbinden.",
            &["sudo pro attach <TOKEN>", "sudo apt update && sudo apt upgrade"],
        )
    } else if attached {
        f.set(Status::Ok, "Ubuntu Pro ist verbunden, keine ESM-Updates ausstehend.")
    } else {
        f.set(Status::Ok, "Derzeit keine Sicherheitsupdates, die Ubuntu Pro voraussetzen.")
    }]
}

pub fn snap(_ctx: &Ctx) -> Vec<Finding> {
    let Some(o) = util::run("snap", &["refresh", "--list"], 30) else {
        return Vec::new();
    };
    let pending: Vec<String> = o
        .stdout
        .lines()
        .skip(1)
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            Some(format!("{} → {}", it.next()?, it.next()?))
        })
        .collect();
    let installed = util::run("snap", &["list"], 15)
        .map(|o| o.stdout.lines().count().saturating_sub(1))
        .unwrap_or(0);
    let f = Finding::new("sw.snap", CAT, "Snap-Pakete");
    vec![if !o.ok && pending.is_empty() && !o.stderr.contains("up to date") {
        f.set(Status::Unknown, "Snap-Updates konnten nicht abgefragt werden.")
            .detail(o.stderr.trim().to_string())
    } else if pending.is_empty() {
        f.set(Status::Ok, format!("Alle {installed} Snaps sind aktuell."))
    } else {
        f.set(
            Status::Info,
            format!(
                "{} von {installed} Snaps warten auf ein Update (wird automatisch eingespielt).",
                pending.len()
            ),
        )
        .details(pending)
        .why("Snaps aktualisieren sich selbst, laufende Programme aber oft erst nach dem Schließen.")
        .fix("Sofort aktualisieren.", &["sudo snap refresh"])
    }]
}

pub fn flatpak(_ctx: &Ctx) -> Vec<Finding> {
    let Some(o) = util::run("flatpak", &["remote-ls", "--updates", "--columns=application"], 40) else {
        return Vec::new();
    };
    let f = Finding::new("sw.flatpak", CAT, "Flatpak-Programme");
    let pending: Vec<String> = o.stdout.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
    vec![if !o.ok {
        f.set(Status::Unknown, "Flatpak-Updates konnten nicht abgefragt werden.")
            .detail(o.stderr.trim().to_string())
    } else if pending.is_empty() {
        f.set(Status::Ok, "Alle Flatpak-Programme sind aktuell.")
    } else {
        f.set(Status::Warn, format!("{} ausstehend.", util::plural(pending.len(), "Flatpak-Update", "Flatpak-Updates")))
            .details(pending)
            .why("Flatpaks werden nicht von apt aktualisiert und bleiben ohne eigenes Update alt.")
            .fix("Flatpaks aktualisieren.", &["flatpak update"])
    }]
}

pub fn firmware(_ctx: &Ctx) -> Vec<Finding> {
    let f = Finding::new("sw.firmware", CAT, "Firmware- und BIOS-Updates").why(
        "BIOS/UEFI- und Geräte-Firmware enthält ebenfalls Sicherheitslücken. Framework verteilt Updates über LVFS (fwupd).",
    );
    let bios = format!(
        "BIOS {} vom {}",
        util::read("/sys/class/dmi/id/bios_version").unwrap_or_default(),
        util::read("/sys/class/dmi/id/bios_date").unwrap_or_default()
    );
    let Some(o) = util::run("fwupdmgr", &["get-updates", "--json", "--no-unreported-check"], 40) else {
        return vec![f
            .set(Status::Unknown, "fwupd ist nicht installiert – Firmware-Updates können nicht geprüft werden.")
            .detail(bios)
            .fix("fwupd installieren.", &["sudo apt install fwupd"])];
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&o.stdout) else {
        return vec![f.set(Status::Unknown, "fwupd lieferte keine lesbare Antwort.").detail(bios)];
    };
    let updates: Vec<String> = v["Devices"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|d| {
            let rel = d["Releases"].as_array()?.first()?;
            Some(format!(
                "{}: {} → {}",
                d["Name"].as_str().unwrap_or("Gerät"),
                d["Version"].as_str().unwrap_or("?"),
                rel["Version"].as_str().unwrap_or("?")
            ))
        })
        .collect();
    vec![if updates.is_empty() {
        f.set(Status::Ok, "fwupd meldet keine ausstehenden Firmware-Updates.").detail(bios)
    } else {
        f.set(Status::Warn, format!("{} verfügbar.", util::plural(updates.len(), "Firmware-Update", "Firmware-Updates")))
            .details(updates)
            .detail(bios)
            .fix("Firmware aktualisieren (Netzteil anschließen).", &["fwupdmgr refresh", "fwupdmgr update"])
    }]
}

/// Third-party APT sources.
pub fn sources(_ctx: &Ctx) -> Vec<Finding> {
    let mut third = Vec::new();
    let mut files: Vec<std::path::PathBuf> = vec!["/etc/apt/sources.list".into()];
    if let Ok(rd) = fs::read_dir("/etc/apt/sources.list.d") {
        files.extend(rd.flatten().map(|e| e.path()));
    }
    files.sort();
    for path in files {
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let is_main = path.ends_with("sources.list");
        if !is_main && ext != "list" && ext != "sources" {
            continue; // .disabled, .orig, .save ...
        }
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        let mut uris: Vec<String> = Vec::new();
        if ext == "sources" {
            for stanza in content.split("\n\n") {
                let disabled = stanza.lines().any(|l| {
                    let l = l.trim().to_ascii_lowercase();
                    l.starts_with("enabled:") && l.ends_with("no")
                });
                if disabled {
                    continue;
                }
                for l in stanza.lines() {
                    if let Some(u) = l.trim().strip_prefix("URIs:") {
                        uris.extend(u.split_whitespace().map(String::from));
                    }
                }
            }
        } else {
            for l in content.lines() {
                let l = l.trim();
                if l.starts_with("deb ") {
                    if let Some(u) = l.split_whitespace().find(|t| t.contains("://")) {
                        uris.push(u.to_string());
                    }
                }
            }
        }
        for u in uris {
            let host = u.split("://").nth(1).and_then(|r| r.split('/').next()).unwrap_or("");
            if !(host.ends_with("ubuntu.com") || host.ends_with("canonical.com")) {
                let entry = format!("{} ({})", host, path.file_name().and_then(|n| n.to_str()).unwrap_or(""));
                if !third.contains(&entry) {
                    third.push(entry);
                }
            }
        }
    }
    let f = Finding::new("sw.sources", CAT, "Fremde Paketquellen").why(
        "Jede Paketquelle kann bei Updates Software mit Root-Rechten installieren. \
         Nur Quellen von Herstellern behalten, denen du vertraust und deren Programme du noch nutzt.",
    );
    vec![if third.is_empty() {
        f.set(Status::Ok, "Es sind nur die offiziellen Ubuntu-Quellen eingerichtet.")
    } else {
        f.set(
            Status::Info,
            format!("{} neben Ubuntu eingerichtet.", util::plural(third.len(), "fremde Paketquelle", "fremde Paketquellen")),
        )
        .details(third)
        .fix("Nicht mehr benötigte Quellen in /etc/apt/sources.list.d/ entfernen.", &[])
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_apt_list() {
        let out = "Listing...\n\
                   distro-info/resolute-updates 1.15ubuntu0.1 amd64 [upgradable from: 1.15]\n\
                   openssl/resolute-security 3.5.1 amd64 [upgradable from: 3.5.0]\n\
                   cursor/now 3.4.17-1778710077 amd64 [installed,local]\n";
        let p = parse_apt_list(out);
        assert_eq!(p.len(), 3);
        assert_eq!(p[0], ("distro-info".into(), "resolute-updates".into(), "1.15ubuntu0.1".into()));
        assert!(p[1].1.contains("security"));
        assert_eq!(p[2].0, "cursor");
    }
}
