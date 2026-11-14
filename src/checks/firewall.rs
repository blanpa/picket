use super::Ctx;
use crate::model::{Category, Finding, Status};
use crate::util;

const CAT: Category = Category::Firewall;

/// Whether a host firewall is filtering incoming traffic.
/// The live `ufw status` from the root snapshot wins over the config file.
pub fn is_active(ctx: &Ctx) -> bool {
    let live = ctx
        .privd
        .as_ref()
        .and_then(|p| p.ufw_status.as_ref())
        .map(|s| s.lines().any(|l| l.trim() == "Status: active"));
    let configured = util::read("/etc/ufw/ufw.conf")
        .and_then(|c| util::conf_value(&c, "ENABLED"))
        .map(|v| v.eq_ignore_ascii_case("yes"));
    live.or(configured).unwrap_or(false) || util::service_active("firewalld")
}

pub fn check(ctx: &Ctx) -> Vec<Finding> {
    let mut out = Vec::new();
    let installed = util::which("ufw").is_some();
    let firewalld = util::service_active("firewalld");
    let active = is_active(ctx);
    let exposed = ctx.net.exposed();

    let f = Finding::new("fw.active", CAT, "Firewall-Status").why(
        "Ohne Firewall kann jedes Gerät im selben Netz (Heimnetz, Hotel-/Café-WLAN, Firmennetz) \
         alle offenen Ports dieses Laptops erreichen. Bei einem Laptop, der Netze wechselt, ist das die wichtigste Schutzschicht.",
    );
    out.push(if active {
        f.set(
            Status::Ok,
            if firewalld { "firewalld ist aktiv." } else { "ufw ist aktiv." },
        )
    } else if !installed {
        f.set(Status::Warn, "Es ist keine Firewall (ufw/firewalld) installiert.")
            .fix("ufw installieren und einschalten.", &["sudo apt install ufw", "sudo ufw enable"])
    } else {
        let status = if exposed.is_empty() { Status::Warn } else { Status::Crit };
        f.set(
            status,
            format!(
                "Die Firewall (ufw) ist ausgeschaltet – {} aus dem Netzwerk erreichbar.",
                match exposed.len() {
                    0 => "aktuell ist aber kein Dienst".to_string(),
                    1 => "1 Dienst ist".to_string(),
                    n => format!("{n} Dienste sind"),
                }
            ),
        )
        .detail("Welche Dienste das sind, steht im Reiter „Netzwerk“ unter „Von außen erreichbare Dienste“.")
        .fix(
            "Firewall einschalten: eingehende Verbindungen werden dann standardmäßig blockiert, ausgehende bleiben erlaubt. \
             Achtung: von Docker veröffentlichte Ports bleiben trotz ufw erreichbar (siehe Reiter „Netzwerk“).",
            &["sudo ufw enable", "sudo ufw status verbose"],
        )
    });

    // Default policies
    if installed {
        let defaults = util::read("/etc/default/ufw").unwrap_or_default();
        let input = util::conf_value(&defaults, "DEFAULT_INPUT_POLICY").unwrap_or_default();
        let output = util::conf_value(&defaults, "DEFAULT_OUTPUT_POLICY").unwrap_or_default();
        let forward = util::conf_value(&defaults, "DEFAULT_FORWARD_POLICY").unwrap_or_default();
        let f = Finding::new("fw.policy", CAT, "Standardregeln")
            .detail(format!("Eingehend: {input}"))
            .detail(format!("Ausgehend: {output}"))
            .detail(format!("Weiterleitung: {forward}"))
            .why("Die Standardregel entscheidet, was mit Verbindungen passiert, für die keine eigene Regel existiert.");
        out.push(match input.as_str() {
            "DROP" | "REJECT" if active => f.set(Status::Ok, "Eingehende Verbindungen werden standardmäßig blockiert."),
            "DROP" | "REJECT" => f.set(
                Status::Info,
                "Konfiguriert ist „eingehend blockieren“ – wirkt aber erst, wenn die Firewall eingeschaltet ist.",
            ),
            "" => f.set(Status::Unknown, "Standardregeln nicht lesbar (/etc/default/ufw)."),
            _ => f
                .set(Status::Warn, format!("Eingehende Verbindungen werden standardmäßig erlaubt ({input})."))
                .fix("Standard auf „blockieren“ stellen.", &["sudo ufw default deny incoming"]),
        });
    }

    // Rules (root only)
    let f = Finding::new("fw.rules", CAT, "Firewall-Regeln");
    out.push(match ctx.privd.as_ref() {
        Some(p) => {
            let mut f = f;
            match &p.ufw_status {
                Some(s) => {
                    let rules = s.lines().filter(|l| l.contains("ALLOW") || l.contains("DENY") || l.contains("REJECT") || l.contains("LIMIT")).count();
                    f = f
                        .set(Status::Info, format!("{} (aus Root-Snapshot).", util::plural(rules, "ufw-Regel", "ufw-Regeln")))
                        .details(s.lines().filter(|l| !l.trim().is_empty()).map(String::from));
                }
                None => f = f.set(Status::Info, "ufw-Regeln konnten nicht gelesen werden."),
            }
            if let Some(t) = &p.nft_tables {
                f = f.detail(format!(
                    "nftables-Tabellen: {}",
                    t.lines().map(|l| l.trim_start_matches("table ").trim()).collect::<Vec<_>>().join(", ")
                ));
            }
            f
        }
        None => f
            .set(Status::Unknown, "Die Regeln sind nur mit Root-Rechten lesbar.")
            .why("Für die Regelansicht wird einmalig ein Root-Snapshot benötigt. Er liest nur und ändert nichts.")
            .fix("Root-Snapshot erstellen, danach hier „Neu prüfen“.", &[ctx.root_cmd.as_str()]),
    });

    out
}
