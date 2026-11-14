use super::{firewall, Ctx};
use crate::model::{Category, Finding, Status};
use crate::net::Exposure;
use crate::util;

const CAT: Category = Category::Network;

pub fn check(ctx: &Ctx) -> Vec<Finding> {
    let mut out = Vec::new();
    let fw_active = firewall::is_active(ctx);
    let net = &ctx.net;

    // Services reachable from other machines
    let exposed = net.exposed();
    let f = Finding::new("net.exposed", CAT, "Von außen erreichbare Dienste").why(
        "Jeder Dienst, der nicht nur auf 127.0.0.1 lauscht, ist für andere Geräte im Netz sichtbar und angreifbar – \
         besonders in fremden WLANs.",
    );
    out.push(if !net.complete {
        f.set(Status::Unknown, "Offene Ports konnten nicht gelesen werden (ss fehlt).")
    } else if exposed.is_empty() {
        let blocked = net.blocked();
        f.set(
            Status::Ok,
            if blocked > 0 {
                format!("Kein Dienst ist aus dem Netzwerk erreichbar; die Firewall sperrt {blocked}.")
            } else {
                "Kein Dienst ist aus dem Netzwerk erreichbar.".to_string()
            },
        )
    } else {
        let mut f = f;
        if net.has_global_ipv6 {
            f = f.detail(
                "Dieser Laptop hat eine öffentliche IPv6-Adresse: Ports auf „alle Netze“ sind nur durch die Firewall des Routers vom Internet getrennt.",
            );
        }
        let f = f
            .set(
                if fw_active { Status::Info } else { Status::Warn },
                format!(
                    "{} aus dem Netzwerk erreichbar{}.",
                    match exposed.len() {
                        1 => "1 Dienst ist".to_string(),
                        n => format!("{n} Dienste sind"),
                    },
                    if fw_active { " (trotz Firewall – prüfe, ob das so gewollt ist)" } else { ", die Firewall ist aus" }
                ),
            )
            .details(exposed.iter().map(|l| {
                format!(
                    "{}/{}{} – {} – erreichbar aus: {}{}",
                    l.proto,
                    l.port,
                    l.service.map(|s| format!(" ({s})")).unwrap_or_default(),
                    l.who(),
                    l.exposure.label(),
                    match l.firewall {
                        crate::fwctl::Verdict::Restricted => " – laut Firewall nur für bestimmte Absender",
                        crate::fwctl::Verdict::Unknown => " – Firewall-Regeln nicht lesbar",
                        _ if fw_active && l.container.is_some() => " – Docker umgeht die Firewall",
                        _ => "",
                    }
                )
            }))
            .details((net.blocked() > 0).then(|| format!("{} weitere Ports sperrt die Firewall.", net.blocked())))
            .fix(
                "Dienste, die nur lokal gebraucht werden, an 127.0.0.1 binden oder beenden; den Rest per Firewall einschränken.",
                &[],
            );
        f
    });

    // Wi-Fi encryption
    if let Some(o) = util::run("nmcli", &["-t", "-f", "ACTIVE,SSID,SECURITY", "dev", "wifi", "list", "--rescan", "no"], 8) {
        if let Some(line) = o.stdout.lines().find(|l| l.starts_with("yes:")) {
            let rest = &line[4..];
            let (ssid, sec) = rest.rsplit_once(':').unwrap_or((rest, ""));
            let ssid = ssid.replace("\\:", ":");
            let f = Finding::new("net.wifi", CAT, "WLAN-Verschlüsselung")
                .why("In unverschlüsselten oder schwach verschlüsselten WLANs kann der Datenverkehr mitgelesen und manipuliert werden.");
            out.push(if sec.is_empty() || sec == "--" {
                f.set(Status::Crit, format!("Das WLAN „{ssid}“ ist unverschlüsselt (offen)."))
                    .fix("In offenen WLANs ein VPN verwenden und keine vertraulichen Dienste ohne HTTPS nutzen.", &[])
            } else if sec.contains("WEP") || sec.trim() == "WPA1" {
                f.set(Status::Warn, format!("Das WLAN „{ssid}“ nutzt veraltete Verschlüsselung ({sec})."))
                    .fix("Router auf WPA2/WPA3 umstellen.", &[])
            } else {
                f.set(Status::Ok, format!("WLAN „{ssid}“ ist mit {sec} verschlüsselt."))
            });
        }
    }

    // Network-facing system services
    const SERVICES: [(&str, &str, bool); 11] = [
        ("avahi-daemon", "macht den Laptop per mDNS im Netz sichtbar", false),
        ("cups-browsed", "sucht Netzwerkdrucker", false),
        ("bluetooth", "Bluetooth-Dienst", false),
        ("smbd", "Samba-Dateifreigabe", true),
        ("nmbd", "NetBIOS-Namensdienst", true),
        ("nfs-server", "NFS-Dateifreigabe", true),
        ("rpcbind", "RPC-Portmapper", true),
        ("xrdp", "Remote-Desktop", true),
        ("vsftpd", "FTP-Server (unverschlüsselt)", true),
        ("telnet.socket", "Telnet (unverschlüsselt)", true),
        ("gnome-remote-desktop", "Fernzugriff auf den Desktop", true),
    ];
    let names: Vec<&str> = SERVICES.iter().map(|s| s.0).collect();
    let mut args = vec!["is-active"];
    args.extend(&names);
    if let Some(o) = util::run("systemctl", &args, 6) {
        let states: Vec<&str> = o.stdout.lines().collect();
        let active: Vec<&(&str, &str, bool)> = SERVICES
            .iter()
            .zip(states.iter())
            .filter(|(_, st)| st.trim() == "active")
            .map(|(s, _)| s)
            .collect();
        let risky = active.iter().filter(|s| s.2).count();
        let f = Finding::new("net.services", CAT, "Netzwerkdienste des Systems")
            .details(active.iter().map(|s| format!("{} – {}", s.0, s.1)))
            .why("Dienste, die im Netz antworten oder den Laptop ankündigen, vergrößern die Angriffsfläche.");
        out.push(if active.is_empty() {
            f.set(Status::Ok, "Keiner der geprüften Netzwerkdienste läuft.")
        } else if risky > 0 {
            f.set(Status::Warn, format!("{risky} Freigabe-/Fernzugriffsdienst(e) aktiv."))
                .fix("Nicht benötigte Dienste abschalten.", &["sudo systemctl disable --now <dienst>"])
        } else {
            f.set(Status::Info, format!("{} aktiv (üblich für einen Desktop).", util::plural(active.len(), "Dienst", "Dienste")))
                .fix(
                    "Wer keine Netzwerkdrucker/-geräte automatisch finden will, kann avahi-daemon und cups-browsed abschalten.",
                    &["sudo systemctl disable --now avahi-daemon cups-browsed"],
                )
        });
    }

    // IP forwarding
    if util::read("/proc/sys/net/ipv4/ip_forward").as_deref() == Some("1") {
        let expected = net.docker_available
            || net.ifaces.iter().any(|i| i.kind == crate::net::Zone::Container || i.kind == crate::net::Zone::Vpn);
        out.push(
            Finding::new("net.forward", CAT, "IP-Weiterleitung")
                .set(
                    Status::Info,
                    if expected {
                        "Der Laptop leitet Pakete weiter (Routing) – erwartbar mit Docker/VMs/Tailscale."
                    } else {
                        "Der Laptop leitet Pakete weiter (Routing), obwohl keine Container/VPNs erkannt wurden."
                    },
                )
                .why("Mit aktivem Routing kann der Laptop Verkehr zwischen Netzen vermitteln. Für Container nötig, sonst unnötig."),
        );
    }

    // Summary of listening sockets for context
    let local_only = net.listeners.iter().filter(|l| l.exposure == Exposure::Loopback).count();
    if net.complete {
        out.push(
            Finding::new("net.local", CAT, "Nur lokal erreichbare Dienste")
                .set(Status::Ok, format!("{local_only} Ports lauschen nur auf 127.0.0.1 – von außen nicht erreichbar."))
                .why("Dienste auf 127.0.0.1 sind nur für Programme auf diesem Laptop sichtbar. Details im Live-Bereich oben."),
        );
    }

    out
}
