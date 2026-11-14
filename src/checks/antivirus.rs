use super::Ctx;
use crate::model::{Category, Finding, Status};
use crate::scan;
use crate::util;

const CAT: Category = Category::Antivirus;

pub fn check(_ctx: &Ctx) -> Vec<Finding> {
    let mut out = Vec::new();

    let installed = util::which("clamscan").is_some();
    let f = Finding::new("av.installed", CAT, "Virenscanner installiert").why(
        "Unter Linux ist Schadsoftware seltener, aber ein Scanner hilft bei heruntergeladenen Dateien, \
         E-Mail-Anhängen und Dateien, die an Windows-Rechner weitergegeben werden.",
    );
    if !installed {
        out.push(
            f.set(Status::Warn, "Es ist kein Virenscanner (ClamAV) installiert.")
                .fix("ClamAV installieren.", &["sudo apt install clamav clamav-freshclam"]),
        );
        return out;
    }
    let version = util::run("clamscan", &["--version"], 10)
        .map(|o| o.stdout.trim().to_string())
        .unwrap_or_default();
    out.push(f.set(Status::Ok, "ClamAV ist installiert.").detail(version));

    // Signature age: newest of daily.cvd / daily.cld
    let age = ["daily.cld", "daily.cvd"]
        .iter()
        .filter_map(|n| util::age_days(format!("/var/lib/clamav/{n}")))
        .min();
    let f = Finding::new("av.signatures", CAT, "Virensignaturen")
        .why("Ein Scanner erkennt nur, was seine Signaturen kennen. Veraltete Signaturen übersehen aktuelle Schadsoftware.");
    out.push(match age {
        None => f
            .set(Status::Warn, "Keine Signaturdatenbank gefunden (/var/lib/clamav).")
            .fix("Signaturen laden.", &["sudo systemctl enable --now clamav-freshclam"]),
        Some(d) if d > 30 => f
            .set(Status::Crit, format!("Die Signaturen sind {d} Tage alt."))
            .fix("Signaturen aktualisieren.", &["sudo systemctl restart clamav-freshclam"]),
        Some(d) if d > 7 => f
            .set(Status::Warn, format!("Die Signaturen sind {d} Tage alt."))
            .fix("Signaturen aktualisieren.", &["sudo systemctl restart clamav-freshclam"]),
        Some(0) => f.set(Status::Ok, "Die Signaturen wurden heute aktualisiert."),
        Some(d) => f.set(Status::Ok, format!("Die Signaturen sind {d} Tag(e) alt.")),
    });

    let fresh = util::service_active("clamav-freshclam");
    let f = Finding::new("av.freshclam", CAT, "Automatische Signatur-Updates");
    out.push(if fresh {
        f.set(Status::Ok, "Der Update-Dienst (clamav-freshclam) läuft.")
    } else {
        f.set(Status::Warn, "Der Update-Dienst (clamav-freshclam) läuft nicht.")
            .why("Ohne den Dienst veralten die Signaturen.")
            .fix("Dienst einschalten.", &["sudo systemctl enable --now clamav-freshclam"])
    });

    let onaccess = util::service_active("clamav-daemon") && util::service_active("clamav-clamonacc");
    let f = Finding::new("av.onaccess", CAT, "Echtzeitschutz").why(
        "ClamAV prüft standardmäßig nur auf Anforderung. Ein Echtzeitschutz (clamonacc) ist möglich, kostet aber dauerhaft ca. 1 GB RAM.",
    );
    out.push(if onaccess {
        f.set(Status::Ok, "Echtzeitschutz (clamonacc) ist aktiv.")
    } else {
        f.set(
            Status::Info,
            "Kein Echtzeitschutz – Dateien werden nur bei einem manuellen Scan geprüft.",
        )
        .fix("Regelmäßig den Download-Ordner scannen (Knopf oben auf dieser Seite).", &[])
    });

    // Last scan started from this tool
    let history = scan::load_history();
    let f = Finding::new("av.lastscan", CAT, "Letzter Scan");
    out.push(match history.last() {
        None => f
            .set(Status::Info, "Mit diesem Tool wurde noch kein Scan durchgeführt.")
            .fix("Einen Scan des Download-Ordners starten.", &[]),
        Some(r) => {
            let days = util::now().saturating_sub(r.finished) / 86400;
            let when = match days {
                0 => "heute".to_string(),
                1 => "gestern".to_string(),
                d => format!("vor {d} Tagen"),
            };
            if !r.infected.is_empty() {
                f.set(
                    Status::Crit,
                    format!("Letzter Scan ({when}, {}): {} Fund(e).", r.path, r.infected.len()),
                )
                .details(r.infected.iter().map(|i| format!("{} – {}", i.path, i.signature)))
                .fix("Betroffene Dateien prüfen und löschen oder in Quarantäne verschieben. Fehlalarme sind möglich.", &[])
            } else if r.cancelled {
                f.set(Status::Info, format!("Letzter Scan ({when}, {}) wurde abgebrochen.", r.path))
            } else if days > 30 {
                f.set(
                    Status::Info,
                    format!("Letzter Scan {when} ({}): keine Funde in {} Dateien.", r.path, r.files),
                )
            } else {
                f.set(
                    Status::Ok,
                    format!("Letzter Scan {when} ({}): keine Funde in {} Dateien.", r.path, r.files),
                )
            }
        }
    });

    out
}
