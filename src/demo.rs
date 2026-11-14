//! Demo mode (`PICKET_DEMO=1`): the window shows made-up sample data instead
//! of this machine's. Used for screenshots and for trying the interface
//! without exposing real hosts, devices or containers.
//!
//! Only the data sources are replaced. Nothing is changed on the system in
//! demo mode: the window refuses every action that would.

use crate::devices::{Device, Network};
use crate::docker::{Container, Port};
use crate::fwctl::{self, Verdict};
use crate::history::Entry;
use crate::model::{self, Category, Finding, HostInfo, PrivInfo, Report, Status};
use crate::net::{self, Endpoint, Exposure, IfAddr, Iface, Listener, NetSnapshot, Program, Zone, ZoneTotal};
use crate::util;
use crate::watch::Event;
use std::collections::{BTreeMap, HashSet};
use std::sync::OnceLock;
use std::time::Instant;

pub fn enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("PICKET_DEMO").is_some())
}

/// Seconds since demo mode started; drives the moving numbers.
fn elapsed() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_secs()
}

fn finding(id: &str, cat: Category, title: &str, status: Status, summary: &str) -> Finding {
    Finding::new(id, cat, title).set(status, summary)
}

pub fn report() -> Report {
    use Category::*;
    use Status::*;
    let mut findings = vec![
        finding("fw.active", Firewall, "Firewall-Status", Ok, "ufw ist aktiv."),
        finding("fw.policy", Firewall, "Standardregeln", Ok, "Eingehende Verbindungen werden standardmäßig blockiert."),
        finding("fw.rules", Firewall, "Firewall-Regeln", Info, "2 ufw-Regeln (aus Root-Snapshot)."),
        finding("fw.opensnitch", Firewall, "Programm-Firewall (OpenSnitch)", Info, "Nicht installiert – jedes Programm darf ungefragt ins Internet."),
        finding("net.exposed", Network, "Von außen erreichbare Dienste", Warn, "2 Dienste sind aus dem Netzwerk erreichbar (trotz Firewall – prüfe, ob das so gewollt ist).")
            .detail("tcp/22 (SSH) – sshd – erreichbar aus: alle Netze")
            .detail("tcp/8080 (HTTP (alternativ)) – Docker-Container „web“ – erreichbar aus: alle Netze – Docker umgeht die Firewall")
            .detail("1 weitere Ports sperrt die Firewall.")
            .why("Jeder Dienst, der nicht nur auf 127.0.0.1 lauscht, ist für andere Geräte im Netz sichtbar und angreifbar – besonders in fremden WLANs.")
            .fix("Dienste, die nur lokal gebraucht werden, an 127.0.0.1 binden oder beenden; den Rest per Firewall einschränken.", &[]),
        finding("net.wifi", Network, "WLAN-Verschlüsselung", Ok, "WLAN „Heimnetz“ ist mit WPA3 verschlüsselt."),
        finding("net.tailscale", Network, "Tailscale (VPN)", Info, "Verbunden mit 4 Geräten (3 online), Schlüssel gültig bis 2027-03-01."),
        finding("net.services", Network, "Netzwerkdienste des Systems", Info, "2 Dienste aktiv (üblich für einen Desktop)."),
        finding("net.local", Network, "Nur lokal erreichbare Dienste", Ok, "3 Ports lauschen nur auf 127.0.0.1 – von außen nicht erreichbar."),
        finding("docker.ports", Docker, "Aus dem Netz erreichbare Container-Ports", Warn, "1 Container-Port ist aus dem Netz erreichbar.")
            .detail("tcp/8080 – Container „web“")
            .detail("   ersetzen durch: \"127.0.0.1:8080:80\"   (in /home/demo/shop/docker-compose.yml)")
            .why("Docker schreibt eigene Firewall-Regeln. Ein mit „8080:80“ veröffentlichter Port ist aus dem ganzen Netz erreichbar – auch bei eingeschalteter ufw.")
            .fix("In der Compose-Datei 127.0.0.1 voranstellen, wenn der Dienst nur auf diesem Laptop gebraucht wird, und den Container neu erstellen.", &["docker compose up -d"]),
        finding("docker.power", Docker, "Container mit Zugriff auf das Wirtssystem", Warn, "1 Container kann das Wirtssystem übernehmen.").detail("portainer – Zugriff auf docker.sock"),
        finding("docker.root", Docker, "Container, die als root laufen", Info, "2 von 4 Containern laufen als root."),
        finding("av.installed", Antivirus, "Virenscanner installiert", Ok, "ClamAV ist installiert."),
        finding("av.signatures", Antivirus, "Virensignaturen", Ok, "Die Signaturen wurden heute aktualisiert."),
        finding("av.freshclam", Antivirus, "Automatische Signatur-Updates", Ok, "Der Update-Dienst (clamav-freshclam) läuft."),
        finding("av.onaccess", Antivirus, "Echtzeitschutz", Info, "Kein Echtzeitschutz – Dateien werden nur bei einem manuellen Scan geprüft."),
        finding("av.lastscan", Antivirus, "Letzter Scan", Ok, "Letzter Scan gestern (/home/demo/Downloads): keine Funde in 1842 Dateien."),
        finding("sw.updates", Software, "Ausstehende System-Updates", Warn, "12 Updates ausstehend, davon 3 Sicherheitsupdates.")
            .detail("openssl → 3.5.2 (resolute-security)")
            .detail("libssl3 → 3.5.2 (resolute-security)")
            .detail("curl → 8.14.1 (resolute-security)")
            .why("Die meisten Angriffe nutzen Lücken, für die es längst ein Update gibt.")
            .fix("Updates installieren.", &["sudo apt update && sudo apt upgrade"]),
        finding("sw.reboot", Software, "Neustart nach Updates", Warn, "Ein Neustart steht aus – installierte Updates sind noch nicht aktiv."),
        finding("sw.auto", Software, "Automatische Sicherheitsupdates", Ok, "Sicherheitsupdates werden automatisch installiert (unattended-upgrades)."),
        finding("sw.firmware", Software, "Firmware- und BIOS-Updates", Ok, "fwupd meldet keine ausstehenden Firmware-Updates."),
        finding("sw.flatpak", Software, "Flatpak-Programme", Ok, "Alle Flatpak-Programme sind aktuell."),
        finding("sw.snap", Software, "Snap-Pakete", Ok, "Alle 18 Snaps sind aktuell."),
        finding("sw.sources", Software, "Fremde Paketquellen", Info, "2 fremde Paketquellen neben Ubuntu eingerichtet."),
        finding("sys.luks", System, "Festplattenverschlüsselung", Ok, "Das System liegt auf einer LUKS-verschlüsselten Partition."),
        finding("sys.secureboot", System, "Secure Boot", Ok, "Secure Boot ist eingeschaltet."),
        finding("sys.hsi", System, "Firmware-Sicherheit (HSI)", Ok, "HSI:2 – guter Firmware-Schutz (34 von 36 Prüfungen bestanden)."),
        finding("sys.apparmor", System, "AppArmor", Ok, "AppArmor ist aktiv."),
        finding("sys.cpu", System, "CPU-Schwachstellen (Spectre & Co.)", Ok, "Alle 19 bekannten CPU-Lücken sind nicht relevant oder entschärft."),
        finding("sys.sysctl", System, "Kernel-Härtung", Ok, "Alle 10 geprüften Kernel-Schutzeinstellungen sind aktiv."),
        finding("sys.backup", System, "Datensicherung", Warn, "Die letzte erkennbare Sicherung ist 23 Tage alt.")
            .why("Gegen Erpressungstrojaner, Diebstahl und defekte SSDs hilft am Ende nur ein aktuelles Backup an einem anderen Ort."),
        finding("acc.users", Access, "Benutzerkonten", Ok, "1 Anmeldekonto: demo. Nur root hat UID 0."),
        finding("acc.sshd", Access, "SSH-Server (Fernzugriff)", Crit, "Der SSH-Server läuft und erlaubt die Root-Anmeldung mit Passwort.")
            .detail("PasswordAuthentication yes")
            .detail("PermitRootLogin yes")
            .why("Ein SSH-Server erlaubt die Anmeldung aus dem Netz. Mit Passwort-Anmeldung ist er ein beliebtes Ziel für Rateangriffe.")
            .fix("In /etc/ssh/sshd_config „PermitRootLogin no“ setzen.", &["sudo systemctl restart ssh"]),
        finding("acc.sshperm", Access, "Dateirechte in ~/.ssh", Ok, "Die Dateirechte in ~/.ssh sind in Ordnung."),
        finding("acc.lock", Access, "Bildschirmsperre", Ok, "Der Bildschirm sperrt nach 5 Minuten Inaktivität."),
        finding("acc.admins", Access, "Administratorrechte", Info, "1 Konto mit sudo-Rechten; Mitglieder der Gruppe „docker“ (demo) haben faktisch Root-Rechte ohne Passwortabfrage."),
    ];
    // One finding the user has consciously accepted.
    if let Some(f) = findings.iter_mut().find(|f| f.id == "docker.power") {
        f.accepted = true;
    }
    findings.sort_by_key(|f| (f.category, f.accepted, f.status));
    Report {
        generated: util::now(),
        duration_ms: 1400,
        host: HostInfo {
            hostname: "demo-laptop".into(),
            model: "Framework Laptop 13".into(),
            bios: "03.20 (06/03/2024)".into(),
            cpu: "11th Gen Intel(R) Core(TM) i7-1165G7".into(),
            os: "Ubuntu 26.04 LTS".into(),
            kernel: "7.0.0-43-generic".into(),
        },
        counts: model::tally(&findings),
        privileged: PrivInfo { available: true, created: Some(util::now()), command: String::new() },
        findings,
    }
}

fn endpoint(remote: &str, port: u16, proto: &str, zone: Zone, count: usize, rate: (u64, u64)) -> Endpoint {
    let t = 600 + elapsed();
    Endpoint {
        remote: remote.into(),
        port,
        proto: proto.into(),
        zone,
        inbound: false,
        service: net::service_name(port),
        count,
        // Counters grow at a steady rate, so the diagram shows moving traffic.
        bytes_sent: rate.0 * t,
        bytes_received: rate.1 * t,
    }
}

pub fn snapshot() -> NetSnapshot {
    use Zone::*;
    let mut programs = vec![
        ("firefox", vec![
            endpoint("140.82.121.4", 443, "tcp", Internet, 3, (310, 2_400)),
            endpoint("185.199.108.153", 443, "tcp", Internet, 2, (0, 0)),
            endpoint("104.16.132.229", 443, "tcp", Internet, 4, (120, 18_000)),
            endpoint("142.250.185.78", 443, "udp", Internet, 2, (0, 0)),
            endpoint("91.198.174.192", 443, "tcp", Internet, 1, (0, 0)),
        ]),
        ("thunderbird", vec![endpoint("142.250.102.108", 993, "tcp", Internet, 2, (0, 0))]),
        ("code", vec![endpoint("13.107.42.14", 443, "tcp", Internet, 2, (40, 260))]),
        ("nextcloud", vec![endpoint("192.168.1.10", 443, "tcp", Lan, 2, (184_000, 900))]),
        ("ssh", vec![endpoint("192.168.1.10", 22, "tcp", Lan, 1, (0, 0)), endpoint("100.64.0.7", 22, "tcp", Vpn, 1, (15, 30))]),
        ("tailscaled", vec![endpoint("176.58.90.147", 443, "tcp", Internet, 1, (0, 0)), endpoint("100.64.0.7", 41641, "udp", Vpn, 1, (0, 0))]),
        ("systemd-timesyncd", vec![endpoint("162.159.200.123", 123, "udp", Internet, 1, (0, 0))]),
        ("code-server", vec![endpoint("127.0.0.1", 8443, "tcp", Loopback, 6, (0, 0))]),
    ];
    // A package download that finishes shortly after start: it then shows up as "beendet".
    if elapsed() < 10 {
        programs.push(("apt", vec![endpoint("185.125.190.82", 80, "tcp", Internet, 2, (0, 0))]));
    }
    let programs: Vec<Program> = programs
        .into_iter()
        .map(|(name, endpoints)| {
            let mut zones = BTreeMap::new();
            for e in &endpoints {
                *zones.entry(e.zone).or_insert(0) += e.count;
            }
            Program { name: name.into(), pids: vec![1000], zones, endpoints }
        })
        .collect();
    let mut totals: BTreeMap<Zone, ZoneTotal> = BTreeMap::new();
    let mut hosts: BTreeMap<Zone, HashSet<&str>> = BTreeMap::new();
    for p in &programs {
        for (zone, count) in &p.zones {
            let t = totals.entry(*zone).or_default();
            t.connections += count;
            t.programs += 1;
        }
        for e in &p.endpoints {
            hosts.entry(e.zone).or_default().insert(&e.remote);
        }
    }
    for (zone, h) in hosts {
        totals.entry(zone).or_default().hosts = h.len();
    }
    let listener = |proto: &str, port: u16, addr: &str, exposure, process: Option<&str>, container: Option<&str>, firewall| Listener {
        proto: proto.into(),
        port,
        addrs: vec![addr.into()],
        exposure,
        process: process.map(String::from),
        pid: Some(1),
        container: container.map(String::from),
        service: net::service_name(port),
        ephemeral: false,
        firewall,
        sockets: 1,
    };
    let addr = |ip: &str, prefix| IfAddr { ip: ip.parse().expect("demo address"), prefix };
    NetSnapshot {
        generated: util::now(),
        ifaces: vec![
            Iface { name: "lo".into(), kind: Loopback, up: true, addrs: vec![addr("127.0.0.1", 8)] },
            Iface { name: "wlp2s0".into(), kind: Lan, up: true, addrs: vec![addr("192.168.1.23", 24)] },
            Iface { name: "tailscale0".into(), kind: Vpn, up: true, addrs: vec![addr("100.64.0.3", 32)] },
            Iface { name: "docker0".into(), kind: Container, up: true, addrs: vec![addr("172.17.0.1", 16)] },
        ],
        listeners: vec![
            listener("tcp", 22, "0.0.0.0", Exposure::All, Some("sshd"), None, Verdict::Open),
            listener("tcp", 8080, "0.0.0.0", Exposure::All, Some("docker-proxy"), Some("web"), Verdict::Open),
            listener("tcp", 3000, "0.0.0.0", Exposure::All, Some("node"), None, Verdict::Blocked),
            listener("tcp", 53, "127.0.0.53", Exposure::Loopback, Some("systemd-resolve"), None, Verdict::Open),
            listener("tcp", 631, "127.0.0.1", Exposure::Loopback, Some("cupsd"), None, Verdict::Open),
            listener("tcp", 5432, "127.0.0.1", Exposure::Loopback, Some("docker-proxy"), Some("db"), Verdict::Open),
        ],
        programs,
        totals,
        docker: Vec::new(),
        local_ports: BTreeMap::new(),
        docker_available: true,
        has_global_ipv6: false,
        complete: true,
    }
}

pub fn devices() -> Vec<Network> {
    let now = util::now();
    let device = |ip: &str, mac: &str, vendor: &str, hostname: Option<&str>, active: bool| Device {
        ip: ip.into(),
        other_ips: Vec::new(),
        mac: mac.into(),
        vendor: Some(vendor.into()),
        hostname: hostname.map(String::from),
        custom_name: None,
        active,
        is_gateway: false,
        is_self: false,
        random_mac: false,
        first_seen: now - 86_400 * 30,
        is_new: false,
    };
    let mut router = device("192.168.1.1", "3c:a6:2f:10:20:30", "AVM Audiovisuelles Marketing und Computersysteme GmbH", Some("fritz.box"), true);
    router.is_gateway = true;
    let mut this = device("192.168.1.23", "00:93:37:aa:bb:cc", "Intel Corporate", Some("demo-laptop"), true);
    this.is_self = true;
    let mut nas = device("192.168.1.10", "00:11:32:44:55:66", "Synology Incorporated", Some("nas.fritz.box"), true);
    nas.custom_name = Some("NAS im Keller".into());
    let mut phone = device("192.168.1.42", "da:a1:19:01:02:03", "", Some("Pixel-8.fritz.box"), true);
    phone.vendor = None;
    phone.random_mac = true;
    let mut plug = device("192.168.1.77", "ec:64:c9:0a:0b:0c", "Espressif Inc.", None, true);
    plug.is_new = true;
    plug.first_seen = now - 900;
    vec![Network {
        iface: "wlp2s0".into(),
        wireless: true,
        subnet: "192.168.1.0/24".into(),
        gateway: Some("192.168.1.1".into()),
        sweepable: true,
        inventoried: true,
        devices: vec![
            router,
            this,
            nas,
            device("192.168.1.20", "f4:39:09:11:22:33", "Hewlett Packard", Some("drucker.fritz.box"), true),
            device("192.168.1.31", "dc:a6:32:77:88:99", "Raspberry Pi Trading Ltd", Some("pi-hole.fritz.box"), true),
            phone,
            device("192.168.1.55", "8c:79:f5:de:ad:01", "Samsung Electronics Co.,Ltd", Some("tv-wohnzimmer.fritz.box"), false),
            plug,
        ],
    }]
}

pub fn containers() -> Vec<Container> {
    let port = |host_ip: &str, host_port, container_port: &str| Port { host_ip: host_ip.into(), host_port, container_port: container_port.into(), proto: "tcp".into() };
    let container = |name: &str, image: &str, user: &str, ports: Vec<Port>| Container {
        name: name.into(),
        image: image.into(),
        user: user.into(),
        ports,
        compose_file: "/home/demo/shop/docker-compose.yml".into(),
        ..Default::default()
    };
    let mut portainer = container("portainer", "portainer/portainer-ce:2.21", "", vec![port("127.0.0.1", 9443, "9443")]);
    portainer.docker_socket = true;
    vec![
        container("web", "nginx:1.27-alpine", "", vec![port("0.0.0.0", 8080, "80"), port("::", 8080, "80")]),
        container("db", "postgres:17-alpine", "postgres", vec![port("127.0.0.1", 5432, "5432")]),
        container("grafana", "grafana/grafana:11.3.0", "472", vec![port("127.0.0.1", 3001, "3000")]),
        portainer,
    ]
}

pub fn firewall() -> fwctl::State {
    fwctl::State {
        installed: true,
        active: true,
        incoming: "deny".into(),
        outgoing: "allow".into(),
        rules: Some(fwctl::parse_added(
            "ufw allow in proto tcp from 192.168.1.0/24 to any port 22 comment 'SSH nur aus dem Heimnetz'\n\
             ufw reject out from any to 203.0.113.50 comment 'gesperrte Gegenstelle'\n",
        )),
    }
}

pub fn blocked_domains() -> Vec<String> {
    vec!["ads.example.net".into(), "tracker.example.com".into()]
}

pub fn events() -> Vec<Event> {
    let now = util::now();
    let e = |ago: u64, level: &str, title: &str, text: &str| Event { time: now - ago, level: level.into(), title: title.into(), text: text.into() };
    vec![
        e(900, "warn", "Neues Gerät im Netz", "Espressif Inc. – 192.168.1.77 (ec:64:c9:0a:0b:0c)"),
        e(4_200, "warn", "Neues Programm im Internet", "nextcloud verbindet sich zum ersten Mal ins Internet (DE)."),
        e(9_000, "info", "Neues Zielland", "firefox spricht zum ersten Mal mit Servern in NL."),
        e(20_000, "warn", "Neuer offener Port", "tcp/8080 (Docker-Container „web“) ist jetzt aus dem Netz erreichbar."),
        e(80_000, "ok", "Behoben: Firewall-Status", "ufw ist aktiv."),
        e(90_000, "info", "Neues Netzwerk", "Der Laptop ist zum ersten Mal mit dem Netz 10.20.0.0/22 (Router 10.20.0.1) verbunden. Die Firewall ist eingeschaltet."),
    ]
}

pub fn history_days() -> Vec<String> {
    vec![util::date("+%F"), util::date("--date=-1 day +%F")]
}

pub fn history() -> Vec<Entry> {
    let now = util::now();
    let entry = |program: &str, remote: &str, port, zone: Zone, sent, received, minutes: u64| Entry {
        program: program.into(),
        remote: remote.into(),
        port,
        proto: "tcp".into(),
        zone: zone.label().into(),
        first: now - minutes * 60,
        last: now - 120,
        samples: (minutes / 5) as u32,
        sent,
        received,
    };
    vec![
        entry("nextcloud", "192.168.1.10", 443, Zone::Lan, 412_000_000, 3_100_000, 340),
        entry("firefox", "104.16.132.229", 443, Zone::Internet, 2_400_000, 96_000_000, 300),
        entry("firefox", "140.82.121.4", 443, Zone::Internet, 1_100_000, 14_500_000, 280),
        entry("code", "13.107.42.14", 443, Zone::Internet, 640_000, 8_900_000, 200),
        entry("thunderbird", "142.250.102.108", 993, Zone::Internet, 210_000, 5_200_000, 420),
        entry("ssh", "100.64.0.7", 22, Zone::Vpn, 88_000, 240_000, 95),
        entry("apt", "185.125.190.82", 80, Zone::Internet, 12_000, 64_000_000, 12),
    ]
}
