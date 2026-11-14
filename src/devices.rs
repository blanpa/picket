//! Devices on the local network.
//!
//! Passive by default: the kernel's neighbour table (ARP/NDP) lists every
//! machine this laptop has recently exchanged packets with. An explicit sweep
//! sends one tiny UDP packet to each address of the subnet, which makes the
//! kernel resolve its hardware address, so silent devices show up too.

use crate::net::{self, Zone};
use crate::util;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::OnceLock;
use std::time::Duration;

/// Largest subnet that is swept (a /22 has 1022 addresses).
const MIN_SWEEP_PREFIX: u8 = 22;

#[derive(Serialize, Clone, Debug)]
pub struct Device {
    pub ip: String,
    pub other_ips: Vec<String>,
    pub mac: String,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
    /// Name the user gave this device.
    pub custom_name: Option<String>,
    /// Answered recently (as opposed to a stale table entry).
    pub active: bool,
    pub is_gateway: bool,
    pub is_self: bool,
    /// Locally administered address, typically a randomised "private" MAC of a phone.
    pub random_mac: bool,
    pub first_seen: u64,
    /// Appeared after the first full search of this network, within the last 24 hours.
    pub is_new: bool,
}

impl Device {
    pub fn title(&self) -> String {
        if let Some(name) = &self.custom_name {
            return name.clone();
        }
        if self.is_self {
            return "Dieser Laptop".into();
        }
        // Generated names (UUIDs, "_gateway") say less than the manufacturer.
        let readable = |h: &&String| {
            let first = h.split('.').next().unwrap_or("");
            !h.starts_with('_') && !(first.len() >= 20 && first.chars().all(|c| c.is_ascii_hexdigit() || c == '-'))
        };
        self.hostname
            .as_ref()
            .filter(readable)
            .cloned()
            .or_else(|| self.vendor.clone())
            .or_else(|| self.hostname.clone())
            .unwrap_or_else(|| "Unbekanntes Gerät".into())
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct Network {
    pub iface: String,
    pub wireless: bool,
    pub subnet: String,
    pub gateway: Option<String>,
    /// False when the subnet is too large for an active sweep.
    pub sweepable: bool,
    /// The user has searched this network completely before (so it is one of theirs).
    pub inventoried: bool,
    pub devices: Vec<Device>,
}

// ---------------------------------------------------------------- vendors

/// "OUI:<hex prefix>*" / " ID_OUI_FROM_DATABASE=<name>" pairs from systemd's hardware database.
pub fn parse_oui(db: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut prefix: Option<&str> = None;
    for line in db.lines() {
        if let Some(p) = line.strip_prefix("OUI:") {
            prefix = Some(p.trim_end_matches('*'));
        } else if let (Some(p), Some(name)) = (prefix, line.trim().strip_prefix("ID_OUI_FROM_DATABASE=")) {
            map.insert(p.to_string(), name.to_string());
            prefix = None;
        }
    }
    map
}

fn oui_db() -> &'static HashMap<String, String> {
    static DB: OnceLock<HashMap<String, String>> = OnceLock::new();
    DB.get_or_init(|| {
        ["/usr/lib/udev/hwdb.d/20-OUI.hwdb", "/lib/udev/hwdb.d/20-OUI.hwdb"]
            .iter()
            .find_map(|p| std::fs::read_to_string(p).ok())
            .map(|s| parse_oui(&s))
            .unwrap_or_default()
    })
}

pub fn vendor_in(db: &HashMap<String, String>, mac: &str) -> Option<String> {
    let hex: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect::<String>().to_uppercase();
    // Longer assignments (MA-S, MA-M) win over the 24-bit block.
    [9, 7, 6].iter().find_map(|n| hex.get(..*n).and_then(|p| db.get(p)).cloned())
}

pub fn is_random_mac(mac: &str) -> bool {
    u8::from_str_radix(mac.get(..2).unwrap_or("00"), 16)
        .map(|b| b & 0x02 != 0)
        .unwrap_or(false)
}

// ----------------------------------------------------------- known devices

#[derive(Serialize, Deserialize, Default)]
struct KnownNetwork {
    /// When this network was first searched completely. Until then nothing counts as new:
    /// the passive list only knows devices this laptop happened to talk to.
    #[serde(default)]
    inventory: Option<u64>,
    /// First-seen timestamp per device MAC.
    devices: BTreeMap<String, u64>,
}

/// Networks are keyed by the MAC address of their gateway.
#[derive(Serialize, Deserialize, Default)]
struct Known {
    networks: BTreeMap<String, KnownNetwork>,
    /// Names the user gave to devices, by MAC address.
    #[serde(default)]
    names: BTreeMap<String, String>,
}

/// Give a device a name of your own; an empty name removes it.
#[cfg_attr(not(feature = "gui"), allow(dead_code))]
pub fn set_name(mac: &str, name: &str) {
    let mut known = load_known();
    let name: String = name.trim().chars().filter(|c| !c.is_control()).take(60).collect();
    if name.is_empty() {
        known.names.remove(mac);
    } else {
        known.names.insert(mac.to_lowercase(), name);
    }
    save_known(&known);
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct OpenPort {
    pub port: u16,
    pub service: &'static str,
    /// Unencrypted or typically unprotected service.
    pub risky: bool,
}

const PROBE_PORTS: [(u16, &str, bool); 28] = [
    (21, "FTP (unverschlüsselt)", true),
    (22, "SSH", false),
    (23, "Telnet (unverschlüsselt)", true),
    (53, "DNS", false),
    (80, "Weboberfläche (HTTP, unverschlüsselt)", true),
    (139, "Windows-Freigabe (NetBIOS)", false),
    (443, "Weboberfläche (HTTPS)", false),
    (445, "Windows-Freigabe (SMB)", false),
    (554, "Kamera-Stream (RTSP)", true),
    (631, "Drucker (IPP)", false),
    (1880, "Node-RED", true),
    (1883, "MQTT (unverschlüsselt)", true),
    (2375, "Docker-API ohne Schutz", true),
    (3000, "Weboberfläche (3000)", false),
    (3306, "MySQL-Datenbank", true),
    (3389, "Remote-Desktop (RDP)", false),
    (5000, "Weboberfläche (5000)", false),
    (5432, "PostgreSQL-Datenbank", true),
    (5900, "VNC-Fernsteuerung", true),
    (6379, "Redis-Datenbank", true),
    (8006, "Proxmox-Verwaltung", false),
    (8080, "Weboberfläche (8080)", false),
    (8123, "Home Assistant", false),
    (8443, "Weboberfläche (HTTPS, 8443)", false),
    (9000, "Weboberfläche (9000)", false),
    (9100, "Drucker (RAW)", false),
    (27017, "MongoDB-Datenbank", true),
    (32400, "Plex", false),
];

/// Try the usual service ports of one device (plain TCP connects, nothing is sent).
pub fn port_check(ip: IpAddr) -> Vec<OpenPort> {
    let mut open: Vec<OpenPort> = std::thread::scope(|s| {
        let handles: Vec<_> = PROBE_PORTS
            .iter()
            .map(|(port, service, risky)| {
                s.spawn(move || {
                    TcpStream::connect_timeout(&SocketAddr::new(ip, *port), Duration::from_millis(700))
                        .ok()
                        .map(|_| OpenPort { port: *port, service, risky: *risky })
                })
            })
            .collect();
        handles.into_iter().filter_map(|h| h.join().ok().flatten()).collect()
    });
    open.sort_by_key(|p| p.port);
    open
}

/// Devices known before or found during the first full search are not "new".
fn is_new(first_seen: u64, inventory: Option<u64>, now: u64) -> bool {
    match inventory {
        Some(t) => first_seen > t + 300 && now.saturating_sub(first_seen) < 86_400,
        None => false,
    }
}

fn known_path() -> std::path::PathBuf {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| util::home().join(".local/state"));
    base.join("picket/devices.json")
}

fn load_known() -> Known {
    std::fs::read_to_string(known_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_known(k: &Known) {
    let path = known_path();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Ok(json) = serde_json::to_string_pretty(k) {
        let _ = std::fs::write(path, json);
    }
}

// --------------------------------------------------------------- discovery

fn network_of(ip: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(prefix.min(32))) };
    Ipv4Addr::from(u32::from(ip) & mask)
}

/// Host addresses of a subnet, without network and broadcast address.
pub fn sweep_targets(ip: Ipv4Addr, prefix: u8) -> Vec<Ipv4Addr> {
    if !(MIN_SWEEP_PREFIX..=30).contains(&prefix) {
        return Vec::new();
    }
    let base = u32::from(network_of(ip, prefix));
    let size = 1u32 << (32 - u32::from(prefix));
    (1..size - 1).map(|i| Ipv4Addr::from(base + i)).filter(|a| *a != ip).collect()
}

/// Make the kernel resolve every address: one byte to the discard port each.
fn sweep(targets: &[Ipv4Addr]) {
    let Ok(sock) = UdpSocket::bind("0.0.0.0:0") else {
        return;
    };
    for chunk in targets.chunks(64) {
        for ip in chunk {
            let _ = sock.send_to(&[0], (*ip, 9));
        }
        // The neighbour table only queues a few packets per unresolved address.
        std::thread::sleep(Duration::from_millis(40));
    }
    std::thread::sleep(Duration::from_millis(1500));
}

struct Neighbour {
    ip: IpAddr,
    dev: String,
    mac: String,
    active: bool,
}

fn neighbours() -> Vec<Neighbour> {
    let Some(out) = util::run("ip", &["-j", "neigh"], 5) else {
        return Vec::new();
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&out.stdout) else {
        return Vec::new();
    };
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(|n| {
            let states: Vec<&str> = n["state"].as_array()?.iter().filter_map(|s| s.as_str()).collect();
            if states.iter().any(|s| matches!(*s, "FAILED" | "INCOMPLETE" | "NOARP")) {
                return None;
            }
            Some(Neighbour {
                ip: n["dst"].as_str()?.parse().ok()?,
                dev: n["dev"].as_str()?.to_string(),
                mac: n["lladdr"].as_str()?.to_lowercase(),
                active: states.iter().any(|s| matches!(*s, "REACHABLE" | "DELAY" | "PROBE" | "PERMANENT")),
            })
        })
        .collect()
}

fn default_gateways() -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(out) = util::run("ip", &["-j", "route", "show", "default"], 5) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&out.stdout) {
            for r in v.as_array().into_iter().flatten() {
                if let (Some(dev), Some(gw)) = (r["dev"].as_str(), r["gateway"].as_str()) {
                    map.entry(dev.to_string()).or_insert_with(|| gw.to_string());
                }
            }
        }
    }
    map
}

/// The attached local IPv4 networks, e.g. "192.168.178.0/24".
#[cfg_attr(not(feature = "gui"), allow(dead_code))]
pub fn local_subnets() -> Vec<String> {
    net::read_ifaces()
        .iter()
        .filter(|i| i.kind == Zone::Lan && i.up)
        .flat_map(|i| i.addrs.iter())
        .filter_map(|a| match a.ip {
            IpAddr::V4(ip) if !ip.is_link_local() => Some(format!("{}/{}", network_of(ip, a.prefix), a.prefix)),
            _ => None,
        })
        .collect()
}

/// List the devices on every attached local network. `active` additionally sweeps the subnets.
pub fn discover(active: bool) -> Vec<Network> {
    discover_with(if active { Mode::Active } else { Mode::Passive })
}

#[derive(Clone, Copy, PartialEq)]
pub enum Mode {
    /// Only read the neighbour table.
    Passive,
    /// Sweep every attached subnet (the user asked for it).
    Active,
    /// Sweep only networks the user has searched before; used by the watcher,
    /// which must not probe networks that are not the user's own.
    ActiveKnown,
}

/// Networks are told apart by their router's hardware address.
fn network_id(gateway: Option<&String>, neigh: &[Neighbour], iface: &str, own_ip: Ipv4Addr, prefix: u8) -> String {
    gateway
        .and_then(|gw| neigh.iter().find(|n| n.dev == iface && n.ip.to_string() == *gw))
        .map(|n| n.mac.clone())
        .unwrap_or_else(|| format!("{}/{prefix}", network_of(own_ip, prefix)))
}

pub fn discover_with(mode: Mode) -> Vec<Network> {
    let active = mode == Mode::Active;
    let ifaces: Vec<net::Iface> = net::read_ifaces()
        .into_iter()
        .filter(|i| i.kind == Zone::Lan && i.up)
        .collect();
    let v4 = |i: &net::Iface| {
        i.addrs.iter().find_map(|a| match a.ip {
            IpAddr::V4(ip) if !ip.is_link_local() => Some((ip, a.prefix)),
            _ => None,
        })
    };

    if mode != Mode::Passive {
        let (before, gateways, known) = (neighbours(), default_gateways(), load_known());
        let targets: Vec<Ipv4Addr> = ifaces
            .iter()
            .filter_map(|i| v4(i).map(|a| (i, a)))
            .filter(|(i, (ip, prefix))| {
                let id = network_id(gateways.get(&i.name), &before, &i.name, *ip, *prefix);
                active || known.networks.get(&id).map(|n| n.inventory.is_some()).unwrap_or(false)
            })
            .flat_map(|(_, (ip, prefix))| sweep_targets(ip, prefix))
            .collect();
        if !targets.is_empty() {
            sweep(&targets);
        }
    }

    let neigh = neighbours();
    let gateways = default_gateways();
    let mut known = load_known();
    let known_names = known.names.clone();
    let now = util::now();
    let mut networks = Vec::new();

    for iface in &ifaces {
        let Some((own_ip, prefix)) = v4(iface) else {
            continue;
        };
        let gateway = gateways.get(&iface.name).cloned();

        // Group addresses by hardware address.
        let mut by_mac: BTreeMap<String, (Vec<IpAddr>, bool)> = BTreeMap::new();
        for n in neigh.iter().filter(|n| n.dev == iface.name) {
            let e = by_mac.entry(n.mac.clone()).or_default();
            e.0.push(n.ip);
            e.1 |= n.active;
        }
        let gateway_mac = gateway
            .as_ref()
            .and_then(|gw| by_mac.iter().find(|(_, (ips, _))| ips.iter().any(|ip| ip.to_string() == *gw)))
            .map(|(mac, _)| mac.clone());
        // A network is identified by its router, so "new device" works per network.
        let net_id = network_id(gateway.as_ref(), &neigh, &iface.name, own_ip, prefix);
        let entry = known
            .networks
            .entry(net_id)
            .or_insert_with(|| KnownNetwork { inventory: None, devices: BTreeMap::new() });
        if active && entry.inventory.is_none() {
            entry.inventory = Some(now);
        }
        let (inventory, seen) = (entry.inventory, &mut entry.devices);

        let mut devices: Vec<Device> = Vec::new();
        for (mac, (mut ips, active)) in by_mac {
            ips.sort_by_key(|ip| (ip.is_ipv6(), *ip));
            let Some(primary) = ips.first().copied() else {
                continue;
            };
            let first_seen = *seen.entry(mac.clone()).or_insert(now);
            devices.push(Device {
                ip: primary.to_string(),
                other_ips: ips.iter().skip(1).map(|i| i.to_string()).collect(),
                vendor: vendor_in(oui_db(), &mac),
                hostname: None,
                custom_name: known_names.get(&mac).cloned(),
                active,
                is_gateway: gateway_mac.as_deref() == Some(mac.as_str()),
                is_self: false,
                random_mac: is_random_mac(&mac),
                first_seen,
                is_new: is_new(first_seen, inventory, now),
                mac,
            });
        }

        // Resolve names in parallel; each lookup may wait for a DNS timeout.
        std::thread::scope(|s| {
            let handles: Vec<_> = devices
                .iter()
                .map(|d| {
                    let ip = d.ip.clone();
                    s.spawn(move || ip.parse().ok().and_then(net::reverse_lookup))
                })
                .collect();
            for (d, h) in devices.iter_mut().zip(handles) {
                d.hostname = h.join().ok().flatten();
            }
        });

        let own_mac = util::read(format!("/sys/class/net/{}/address", iface.name)).unwrap_or_default();
        devices.push(Device {
            ip: own_ip.to_string(),
            other_ips: Vec::new(),
            vendor: vendor_in(oui_db(), &own_mac),
            hostname: util::read("/proc/sys/kernel/hostname"),
            custom_name: None,
            active: true,
            is_gateway: false,
            is_self: true,
            random_mac: is_random_mac(&own_mac),
            first_seen: now,
            is_new: false,
            mac: own_mac,
        });
        devices.sort_by_key(|d| {
            (!d.is_gateway, !d.is_self, d.ip.parse::<IpAddr>().map(|i| (i.is_ipv6(), i)).ok())
        });

        networks.push(Network {
            iface: iface.name.clone(),
            wireless: iface.name.starts_with("wl"),
            subnet: format!("{}/{prefix}", network_of(own_ip, prefix)),
            gateway,
            sweepable: (MIN_SWEEP_PREFIX..=30).contains(&prefix),
            inventoried: inventory.is_some(),
            devices,
        });
    }
    save_known(&known);
    networks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_up_vendors() {
        let db = parse_oui(
            "# comment\n\nOUI:DCA632*\n ID_OUI_FROM_DATABASE=Raspberry Pi Trading Ltd\n\n\
             OUI:70B3D5*\n ID_OUI_FROM_DATABASE=IEEE Registration Authority\n\n\
             OUI:70B3D5F2F*\n ID_OUI_FROM_DATABASE=TELEPLATFORMS\n",
        );
        assert_eq!(vendor_in(&db, "dc:a6:32:01:02:03").as_deref(), Some("Raspberry Pi Trading Ltd"));
        assert_eq!(vendor_in(&db, "70:b3:d5:f2:f1:00").as_deref(), Some("TELEPLATFORMS")); // longest prefix
        assert_eq!(vendor_in(&db, "70:b3:d5:00:00:00").as_deref(), Some("IEEE Registration Authority"));
        assert_eq!(vendor_in(&db, "aa:bb:cc:dd:ee:ff"), None);
    }

    #[test]
    fn flags_only_later_arrivals_as_new() {
        let (search, now) = (1_000_000, 1_000_000 + 7200);
        assert!(!is_new(now - 600, None, now)); // never searched: no baseline
        assert!(!is_new(search - 5000, Some(search), now)); // known before the search
        assert!(!is_new(search + 60, Some(search), now)); // found by the search itself
        assert!(is_new(now - 600, Some(search), now)); // showed up ten minutes ago
        assert!(!is_new(search + 400, Some(search), search + 400 + 90_000)); // older than a day
    }

    #[test]
    fn recognises_random_macs() {
        assert!(is_random_mac("da:a1:19:00:00:01"));
        assert!(is_random_mac("02:42:ac:11:00:02"));
        assert!(!is_random_mac("dc:a6:32:01:02:03"));
    }

    #[test]
    fn computes_sweep_targets() {
        let t = sweep_targets("192.168.178.190".parse().unwrap(), 24);
        assert_eq!(t.len(), 253); // .1–.254 without ourselves
        assert_eq!(t[0], Ipv4Addr::new(192, 168, 178, 1));
        assert!(!t.contains(&Ipv4Addr::new(192, 168, 178, 190)));
        assert!(!t.contains(&Ipv4Addr::new(192, 168, 178, 255)));
        assert_eq!(sweep_targets("10.0.0.5".parse().unwrap(), 30).len(), 1);
        assert!(sweep_targets("10.0.0.5".parse().unwrap(), 16).is_empty()); // too large
        assert_eq!(network_of("192.168.5.77".parse().unwrap(), 22), Ipv4Addr::new(192, 168, 4, 0));
    }
}
