//! Live network view: interfaces, listening ports and active connections,
//! each classified by where the other side is (Internet, LAN, VPN, ...).

use crate::privileged::Privileged;
use crate::util;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;

/// Where the remote end of a connection lives.
#[derive(Serialize, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Zone {
    Internet,
    Lan,
    Vpn,
    Container,
    Loopback,
}

impl Zone {
    pub fn label(self) -> &'static str {
        match self {
            Zone::Internet => "Internet",
            Zone::Lan => "Lokales Netz",
            Zone::Vpn => "VPN",
            Zone::Container => "Container/VM",
            Zone::Loopback => "nur dieser Rechner",
        }
    }
}

/// From where a listening port can be reached.
#[derive(Serialize, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Exposure {
    All,
    Lan,
    Vpn,
    Container,
    Loopback,
}

impl Exposure {
    pub fn label(self) -> &'static str {
        match self {
            Exposure::All => "alle Netze",
            Exposure::Lan => "lokales Netz",
            Exposure::Vpn => "VPN",
            Exposure::Container => "Container/VM",
            Exposure::Loopback => "nur lokal",
        }
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct IfAddr {
    pub ip: IpAddr,
    pub prefix: u8,
}

#[derive(Serialize, Clone, Debug)]
pub struct Iface {
    pub name: String,
    pub kind: Zone,
    pub up: bool,
    pub addrs: Vec<IfAddr>,
}

#[derive(Serialize, Clone, Debug)]
pub struct Listener {
    pub proto: String,
    pub port: u16,
    pub addrs: Vec<String>,
    pub exposure: Exposure,
    pub process: Option<String>,
    pub pid: Option<u32>,
    pub container: Option<String>,
    pub service: Option<&'static str>,
    /// Short-lived UDP socket in the ephemeral port range (not a real service).
    pub ephemeral: bool,
    /// What the host firewall does with incoming connections to this port.
    pub firewall: crate::fwctl::Verdict,
    pub sockets: usize,
}

impl Listener {
    /// Client-side or discovery sockets that are open but not a "service".
    pub fn is_noise(&self) -> bool {
        self.ephemeral || (self.proto == "udp" && matches!(self.port, 68 | 546 | 5353))
    }

    pub fn who(&self) -> String {
        match (&self.container, &self.process) {
            (Some(c), _) => format!("Docker-Container „{c}“"),
            (None, Some(p)) => p.clone(),
            (None, None) => "unbekannt (anderer Benutzer)".to_string(),
        }
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct Endpoint {
    pub remote: String,
    pub port: u16,
    pub proto: String,
    pub zone: Zone,
    pub inbound: bool,
    pub service: Option<&'static str>,
    pub count: usize,
    /// Byte counters summed over the open TCP connections (the kernel keeps none for UDP).
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

#[derive(Serialize, Clone, Debug)]
pub struct Program {
    /// Empty when the owning process is not visible without root.
    pub name: String,
    pub pids: Vec<u32>,
    pub zones: BTreeMap<Zone, usize>,
    pub endpoints: Vec<Endpoint>,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct ZoneTotal {
    pub connections: usize,
    pub hosts: usize,
    pub programs: usize,
}

#[derive(Serialize, Clone, Debug)]
pub struct Published {
    pub container: String,
    pub host_ip: String,
    pub port: u16,
    pub proto: String,
}

#[allow(dead_code)]
impl Published {
    pub fn wildcard(&self) -> bool {
        self.host_ip == "0.0.0.0" || self.host_ip == "::" || self.host_ip.is_empty()
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct NetSnapshot {
    pub generated: u64,
    pub ifaces: Vec<Iface>,
    pub listeners: Vec<Listener>,
    pub programs: Vec<Program>,
    pub totals: BTreeMap<Zone, ZoneTotal>,
    pub docker: Vec<Published>,
    /// "tcp/44620" -> program that owns this local port (for labelling captured packets).
    pub local_ports: BTreeMap<String, String>,
    pub docker_available: bool,
    pub has_global_ipv6: bool,
    /// False when `ss` could not be run at all.
    pub complete: bool,
}

impl NetSnapshot {
    /// Services reachable from other machines (all interfaces or a LAN address).
    pub fn exposed(&self) -> Vec<&Listener> {
        // Listeners are sorted widest exposure first; report each port once.
        let mut seen = HashSet::new();
        self.listeners
            .iter()
            .filter(|l| matches!(l.exposure, Exposure::All | Exposure::Lan) && !l.is_noise())
            .filter(|l| l.firewall != crate::fwctl::Verdict::Blocked)
            .filter(|l| seen.insert((l.proto.as_str(), l.port)))
            .collect()
    }

    /// Services that listen for the network but are closed off by the firewall.
    pub fn blocked(&self) -> usize {
        let mut seen = HashSet::new();
        self.listeners
            .iter()
            .filter(|l| matches!(l.exposure, Exposure::All | Exposure::Lan) && !l.is_noise())
            .filter(|l| l.firewall == crate::fwctl::Verdict::Blocked)
            .filter(|l| seen.insert((l.proto.as_str(), l.port)))
            .count()
    }
}

// ---------------------------------------------------------------- addresses

fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => ip,
        },
        _ => ip,
    }
}

fn is_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_link_local(),
        IpAddr::V6(v) => (v.segments()[0] & 0xffc0) == 0xfe80,
    }
}

fn in_subnet(ip: &IpAddr, net: &IpAddr, prefix: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let p = u32::from(prefix.min(32));
            if p == 0 {
                return true;
            }
            let mask = u32::MAX << (32 - p);
            (u32::from(*a) & mask) == (u32::from(*b) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let p = u32::from(prefix.min(128));
            if p == 0 {
                return true;
            }
            let mask = u128::MAX << (128 - p);
            (u128::from(*a) & mask) == (u128::from(*b) & mask)
        }
        _ => false,
    }
}

/// Zone by address range alone, without knowledge of local interfaces.
fn zone_by_range(ip: &IpAddr) -> Zone {
    match ip {
        IpAddr::V4(v) => {
            let o = v.octets();
            if o[0] == 100 && (o[1] & 0xc0) == 64 {
                Zone::Vpn // 100.64.0.0/10, used by Tailscale
            } else if v.is_private() || v.is_link_local() || v.is_multicast() || v.is_broadcast() {
                Zone::Lan
            } else {
                Zone::Internet
            }
        }
        IpAddr::V6(v) => {
            let s = v.segments();
            if s[0] == 0xfd7a && s[1] == 0x115c && s[2] == 0xa1e0 {
                Zone::Vpn // Tailscale ULA prefix
            } else if (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80 || (s[0] & 0xff00) == 0xff00 {
                Zone::Lan
            } else {
                Zone::Internet
            }
        }
    }
}

pub fn classify_remote(ip: IpAddr, ifaces: &[Iface]) -> Zone {
    let ip = unmap(ip);
    if ip.is_loopback() || ip.is_unspecified() {
        return Zone::Loopback;
    }
    // One of our own addresses: the traffic never leaves this machine.
    if ifaces.iter().any(|i| i.addrs.iter().any(|a| a.ip == ip)) {
        return Zone::Loopback;
    }
    // Directly attached subnet: the interface type decides.
    for i in ifaces.iter().filter(|i| i.kind != Zone::Loopback) {
        for a in &i.addrs {
            let host_route = match a.ip {
                IpAddr::V4(_) => a.prefix >= 32,
                IpAddr::V6(_) => a.prefix >= 128,
            };
            if host_route || is_link_local(&a.ip) {
                continue;
            }
            if in_subnet(&ip, &a.ip, a.prefix) {
                return i.kind;
            }
        }
    }
    zone_by_range(&ip)
}

fn exposure_of(addr: &str, ifaces: &[Iface]) -> Exposure {
    if addr == "*" {
        return Exposure::All;
    }
    let Ok(ip) = addr.parse::<IpAddr>() else {
        return Exposure::All;
    };
    let ip = unmap(ip);
    if ip.is_unspecified() {
        return Exposure::All;
    }
    if ip.is_loopback() {
        return Exposure::Loopback;
    }
    for i in ifaces {
        if i.addrs.iter().any(|a| a.ip == ip) {
            return match i.kind {
                Zone::Loopback => Exposure::Loopback,
                Zone::Container => Exposure::Container,
                Zone::Vpn => Exposure::Vpn,
                Zone::Lan | Zone::Internet => Exposure::Lan,
            };
        }
    }
    match zone_by_range(&ip) {
        Zone::Vpn => Exposure::Vpn,
        _ => Exposure::Lan,
    }
}

fn iface_kind(name: &str) -> Zone {
    const CONTAINER: [&str; 11] = [
        "docker", "br-", "veth", "virbr", "mpqemubr", "lxc", "lxd", "cni", "podman", "vnet", "tap",
    ];
    const VPN: [&str; 8] = ["tailscale", "wg", "tun", "proton", "mullvad", "nordlynx", "ppp", "zt"];
    if name == "lo" {
        Zone::Loopback
    } else if CONTAINER.iter().any(|p| name.starts_with(p)) {
        Zone::Container
    } else if VPN.iter().any(|p| name.starts_with(p)) {
        Zone::Vpn
    } else {
        Zone::Lan
    }
}

pub fn read_ifaces() -> Vec<Iface> {
    let Some(out) = util::run("ip", &["-j", "addr"], 5) else {
        return Vec::new();
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&out.stdout) else {
        return Vec::new();
    };
    let mut ifaces = Vec::new();
    for i in v.as_array().into_iter().flatten() {
        let name = i["ifname"].as_str().unwrap_or("").to_string();
        if name.is_empty() {
            continue;
        }
        let flags: Vec<&str> = i["flags"]
            .as_array()
            .map(|f| f.iter().filter_map(|x| x.as_str()).collect())
            .unwrap_or_default();
        let addrs = i["addr_info"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|a| {
                Some(IfAddr {
                    ip: a["local"].as_str()?.parse().ok()?,
                    prefix: u8::try_from(a["prefixlen"].as_u64()?).ok()?,
                })
            })
            .collect();
        ifaces.push(Iface {
            kind: iface_kind(&name),
            up: flags.contains(&"LOWER_UP"),
            name,
            addrs,
        });
    }
    ifaces
}

// ---------------------------------------------------------------------- ss

#[derive(Debug, Clone)]
pub struct RawSock {
    pub proto: String,
    pub state: String,
    pub laddr: String,
    pub lport: String,
    pub raddr: String,
    pub rport: String,
    pub process: Option<String>,
    pub pid: Option<u32>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

fn split_hostport(s: &str) -> Option<(String, String)> {
    let (h, p) = s.rsplit_once(':')?;
    // The scope may sit inside or outside the brackets: [fe80::1%eth0] or [fe80::1]%eth0
    let h = h.split('%').next().unwrap_or(h);
    let h = h.trim_start_matches('[').trim_end_matches(']');
    Some((h.to_string(), p.to_string()))
}

fn parse_proc(rest: &str) -> (Option<String>, Option<u32>) {
    let Some(i) = rest.find("((\"") else {
        return (None, None);
    };
    let after = &rest[i + 3..];
    let Some(j) = after.find("\",pid=") else {
        return (None, None);
    };
    let pid: String = after[j + 6..].chars().take_while(|c| c.is_ascii_digit()).collect();
    (Some(after[..j].to_string()), pid.parse().ok())
}

fn info_value(line: &str, key: &str) -> u64 {
    line.split_whitespace()
        .find_map(|t| t.strip_prefix(key))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// Parse `ss -H -tu[l]np[i]` output. With `-i`, TCP sockets are followed by an
/// indented line of statistics.
pub fn parse_ss(out: &str) -> Vec<RawSock> {
    let mut socks: Vec<RawSock> = Vec::new();
    for line in out.lines() {
        if line.starts_with(char::is_whitespace) {
            if let Some(last) = socks.last_mut() {
                last.bytes_sent = info_value(line, "bytes_sent:");
                last.bytes_received = info_value(line, "bytes_received:");
            }
            continue;
        }
        let mut it = line.split_whitespace();
        let (Some(proto), Some(state), Some(_), Some(_), Some(local), Some(peer)) =
            (it.next(), it.next(), it.next(), it.next(), it.next(), it.next())
        else {
            continue;
        };
        let rest = it.collect::<Vec<_>>().join(" ");
        let (Some((laddr, lport)), Some((raddr, rport))) = (split_hostport(local), split_hostport(peer)) else {
            continue;
        };
        let (process, pid) = parse_proc(&rest);
        socks.push(RawSock {
            proto: proto.to_string(),
            state: state.to_string(),
            laddr,
            lport,
            raddr,
            rport,
            process,
            pid,
            bytes_sent: 0,
            bytes_received: 0,
        });
    }
    socks
}

// ------------------------------------------------------------------ docker

fn parse_port_range(spec: &str) -> Vec<u16> {
    match spec.split_once('-') {
        Some((a, b)) => match (a.parse::<u16>(), b.parse::<u16>()) {
            (Ok(a), Ok(b)) if a <= b && b - a < 2000 => (a..=b).collect(),
            _ => Vec::new(),
        },
        None => spec.parse().into_iter().collect(),
    }
}

/// Parse `docker ps --format '{{.Names}}\t{{.Ports}}'`.
pub fn parse_docker_ports(out: &str) -> Vec<Published> {
    let mut v = Vec::new();
    for line in out.lines() {
        let Some((name, ports)) = line.split_once('\t') else {
            continue;
        };
        for part in ports.split(", ") {
            let Some((host, cont)) = part.split_once("->") else {
                continue;
            };
            let proto = cont.rsplit_once('/').map(|x| x.1).unwrap_or("tcp");
            let Some((ip, spec)) = split_hostport(host) else {
                continue;
            };
            for port in parse_port_range(&spec) {
                v.push(Published {
                    container: name.to_string(),
                    host_ip: ip.clone(),
                    port,
                    proto: proto.to_string(),
                });
            }
        }
    }
    v
}

fn docker_published() -> (Vec<Published>, bool) {
    match util::run("docker", &["ps", "--format", "{{.Names}}\t{{.Ports}}"], 5) {
        Some(o) if o.ok => (parse_docker_ports(&o.stdout), true),
        _ => (Vec::new(), false),
    }
}

// ---------------------------------------------------------------- services

pub fn service_name(port: u16) -> Option<&'static str> {
    Some(match port {
        20 | 21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 | 465 | 587 => "E-Mail (SMTP)",
        53 => "DNS",
        67 | 68 => "DHCP",
        80 => "HTTP",
        110 | 995 => "E-Mail (POP3)",
        111 => "rpcbind",
        123 => "Zeit (NTP)",
        137..=139 => "NetBIOS",
        143 | 993 => "E-Mail (IMAP)",
        443 => "HTTPS",
        445 => "Dateifreigabe (SMB)",
        546 | 547 => "DHCPv6",
        631 => "Drucken (CUPS)",
        853 => "DNS über TLS",
        1883 | 8883 => "MQTT",
        1900 => "UPnP/SSDP",
        2049 => "NFS",
        3306 => "MySQL",
        3389 => "Remote-Desktop (RDP)",
        3478 => "STUN",
        3702 => "WS-Discovery",
        5222 => "XMPP",
        5228 => "Google-Dienste",
        5353 => "mDNS",
        5355 => "LLMNR",
        5432 => "PostgreSQL",
        5900..=5903 => "VNC",
        6379 => "Redis",
        8080 | 8081 | 8000 | 8888 => "HTTP (alternativ)",
        8443 => "HTTPS (alternativ)",
        9100 => "Drucker",
        11434 => "Ollama",
        27017 => "MongoDB",
        41641 => "Tailscale",
        51820 => "WireGuard",
        _ => return None,
    })
}

/// Reverse DNS lookup through the system resolver.
pub fn reverse_lookup(ip: IpAddr) -> Option<String> {
    util::run("getent", &["hosts", &ip.to_string()], 3)
        .filter(|o| o.ok)
        .and_then(|o| o.stdout.split_whitespace().nth(1).map(String::from))
}

// ---------------------------------------------------------------- snapshot

type ConnKey = (String, String, String, String, String);

pub fn snapshot(privd: Option<&Privileged>) -> NetSnapshot {
    let ifaces = read_ifaces();
    let (docker, docker_available) = docker_published();
    let listen_out = util::run("ss", &["-H", "-tulnp"], 6);
    let conn_out = util::run("ss", &["-H", "-tunpi"], 6);
    let complete = listen_out.is_some() && conn_out.is_some();

    // Process names that only root can see, from the optional root snapshot.
    let mut priv_listen: HashMap<(String, String), (String, Option<u32>)> = HashMap::new();
    let mut priv_conn: HashMap<ConnKey, (String, Option<u32>)> = HashMap::new();
    if let Some(p) = privd {
        for s in parse_ss(&p.ss_listen) {
            if let Some(name) = s.process {
                priv_listen.insert((s.proto, s.lport), (name, s.pid));
            }
        }
        for s in parse_ss(&p.ss_conns) {
            if let Some(name) = s.process {
                priv_conn.insert((s.proto, s.laddr, s.lport, s.raddr, s.rport), (name, s.pid));
            }
        }
    }

    let fw_state = crate::fwctl::state(privd);

    // ---- listening sockets
    let mut grouped: BTreeMap<(Exposure, String, u16, String), Listener> = BTreeMap::new();
    let mut tcp_listen_ports: HashSet<u16> = HashSet::new();
    for s in parse_ss(listen_out.as_ref().map(|o| o.stdout.as_str()).unwrap_or("")) {
        let Ok(port) = s.lport.parse::<u16>() else {
            continue;
        };
        if s.proto == "tcp" {
            tcp_listen_ports.insert(port);
        }
        let exposure = exposure_of(&s.laddr, &ifaces);
        let container = docker
            .iter()
            .find(|d| d.port == port && d.proto == s.proto)
            .map(|d| d.container.clone());
        let (process, pid) = match s.process {
            Some(p) => (Some(p), s.pid),
            None => match priv_listen.get(&(s.proto.clone(), s.lport.clone())) {
                Some((n, pid)) => (Some(n.clone()), *pid),
                None => (None, None),
            },
        };
        let key = (
            exposure,
            s.proto.clone(),
            port,
            process.clone().unwrap_or_default(),
        );
        let firewall = crate::fwctl::verdict(&fw_state, &s.proto, port, container.is_some());
        let entry = grouped.entry(key).or_insert_with(|| Listener {
            firewall,
            proto: s.proto.clone(),
            port,
            addrs: Vec::new(),
            exposure,
            process,
            pid,
            container,
            service: service_name(port),
            ephemeral: s.proto == "udp" && port >= 32768,
            sockets: 0,
        });
        entry.sockets += 1;
        if !entry.addrs.contains(&s.laddr) {
            entry.addrs.push(s.laddr);
        }
    }
    let listeners: Vec<Listener> = grouped.into_values().collect();
    let mut local_ports: BTreeMap<String, String> = listeners
        .iter()
        .filter_map(|l| Some((format!("{}/{}", l.proto, l.port), l.container.clone().or_else(|| l.process.clone())?)))
        .collect();

    // ---- active connections, grouped per program
    struct Agg {
        pids: Vec<u32>,
        zones: BTreeMap<Zone, usize>,
        /// value: (connections, bytes sent, bytes received)
        endpoints: BTreeMap<(Zone, String, u16, String, bool), (usize, u64, u64)>,
    }
    let mut progs: BTreeMap<String, Agg> = BTreeMap::new();
    let mut hosts: BTreeMap<Zone, HashSet<String>> = BTreeMap::new();
    let mut totals: BTreeMap<Zone, ZoneTotal> = BTreeMap::new();

    for s in parse_ss(conn_out.as_ref().map(|o| o.stdout.as_str()).unwrap_or("")) {
        if s.state != "ESTAB" && s.state != "SYN-SENT" {
            continue;
        }
        let (Ok(lport), Ok(rport)) = (s.lport.parse::<u16>(), s.rport.parse::<u16>()) else {
            continue;
        };
        let Ok(rip) = s.raddr.parse::<IpAddr>() else {
            continue;
        };
        let rip = unmap(rip);
        let zone = classify_remote(rip, &ifaces);
        // Someone connected to one of our listening ports.
        let inbound = s.proto == "tcp" && tcp_listen_ports.contains(&lport);
        let (name, pid) = match s.process {
            Some(p) => (p, s.pid),
            None => {
                let key = (s.proto.clone(), s.laddr.clone(), s.lport.clone(), s.raddr.clone(), s.rport.clone());
                match priv_conn.get(&key) {
                    Some((n, pid)) => (n.clone(), *pid),
                    None => (String::new(), None),
                }
            }
        };
        if !name.is_empty() {
            local_ports.insert(format!("{}/{lport}", s.proto), name.clone());
        }
        let agg = progs.entry(name).or_insert_with(|| Agg {
            pids: Vec::new(),
            zones: BTreeMap::new(),
            endpoints: BTreeMap::new(),
        });
        if let Some(pid) = pid {
            if !agg.pids.contains(&pid) {
                agg.pids.push(pid);
            }
        }
        *agg.zones.entry(zone).or_insert(0) += 1;
        let service_port = if inbound { lport } else { rport };
        let e = agg
            .endpoints
            .entry((zone, rip.to_string(), service_port, s.proto.clone(), inbound))
            .or_insert((0, 0, 0));
        e.0 += 1;
        e.1 += s.bytes_sent;
        e.2 += s.bytes_received;
        hosts.entry(zone).or_default().insert(rip.to_string());
        totals.entry(zone).or_default().connections += 1;
    }

    let mut programs: Vec<Program> = progs
        .into_iter()
        .map(|(name, a)| Program {
            name,
            pids: a.pids,
            zones: a.zones,
            endpoints: a
                .endpoints
                .into_iter()
                .map(|((zone, remote, port, proto, inbound), (count, bytes_sent, bytes_received))| Endpoint {
                    remote,
                    port,
                    proto,
                    zone,
                    inbound,
                    service: service_name(port),
                    count,
                    bytes_sent,
                    bytes_received,
                })
                .collect(),
        })
        .collect();
    for p in &programs {
        for z in p.zones.keys() {
            totals.entry(*z).or_default().programs += 1;
        }
    }
    for (z, h) in hosts {
        totals.entry(z).or_default().hosts = h.len();
    }
    let n = |p: &Program, z: Zone| p.zones.get(&z).copied().unwrap_or(0);
    programs.sort_by(|a, b| {
        (n(b, Zone::Internet), n(b, Zone::Lan), n(b, Zone::Vpn), b.endpoints.len())
            .cmp(&(n(a, Zone::Internet), n(a, Zone::Lan), n(a, Zone::Vpn), a.endpoints.len()))
            .then_with(|| a.name.cmp(&b.name))
    });

    let has_global_ipv6 = ifaces.iter().filter(|i| i.kind == Zone::Lan).any(|i| {
        i.addrs
            .iter()
            .any(|a| matches!(a.ip, IpAddr::V6(_)) && zone_by_range(&a.ip) == Zone::Internet)
    });

    NetSnapshot {
        generated: util::now(),
        ifaces,
        listeners,
        programs,
        totals,
        docker,
        local_ports,
        docker_available,
        has_global_ipv6,
        complete,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(name: &str, addrs: &[(&str, u8)]) -> Iface {
        Iface {
            name: name.into(),
            kind: iface_kind(name),
            up: true,
            addrs: addrs
                .iter()
                .map(|(ip, prefix)| IfAddr { ip: ip.parse().unwrap(), prefix: *prefix })
                .collect(),
        }
    }

    fn test_ifaces() -> Vec<Iface> {
        vec![
            iface("lo", &[("127.0.0.1", 8), ("::1", 128)]),
            iface("wlp170s0", &[("192.168.178.190", 24), ("2001:db8:58f:8700::1", 64), ("fe80::1", 64)]),
            iface("tailscale0", &[("100.64.0.18", 32)]),
            iface("docker0", &[("172.17.0.1", 16)]),
            iface("br-fd6edbadd70f", &[("192.168.0.1", 20)]),
        ]
    }

    fn zone(ip: &str) -> Zone {
        classify_remote(ip.parse().unwrap(), &test_ifaces())
    }

    #[test]
    fn classifies_remote_addresses() {
        assert_eq!(zone("8.8.8.8"), Zone::Internet);
        assert_eq!(zone("2a00:1450:4001:42::1"), Zone::Internet);
        assert_eq!(zone("192.168.178.6"), Zone::Lan);
        assert_eq!(zone("2001:db8:58f:8700::99"), Zone::Lan); // same /64 as wifi
        assert_eq!(zone("fe80::abcd"), Zone::Lan);
        assert_eq!(zone("10.1.2.3"), Zone::Lan); // private, not attached
        assert_eq!(zone("100.64.0.7"), Zone::Vpn);
        assert_eq!(zone("172.17.0.5"), Zone::Container);
        assert_eq!(zone("192.168.3.4"), Zone::Container); // inside docker /20
        assert_eq!(zone("127.0.0.1"), Zone::Loopback);
        assert_eq!(zone("192.168.178.190"), Zone::Loopback); // own address
        assert_eq!(zone("::ffff:8.8.4.4"), Zone::Internet);
    }

    #[test]
    fn classifies_listen_addresses() {
        let i = test_ifaces();
        assert_eq!(exposure_of("*", &i), Exposure::All);
        assert_eq!(exposure_of("0.0.0.0", &i), Exposure::All);
        assert_eq!(exposure_of("::", &i), Exposure::All);
        assert_eq!(exposure_of("127.0.0.53", &i), Exposure::Loopback);
        assert_eq!(exposure_of("192.168.178.190", &i), Exposure::Lan);
        assert_eq!(exposure_of("100.64.0.18", &i), Exposure::Vpn);
        assert_eq!(exposure_of("172.17.0.1", &i), Exposure::Container);
        assert_eq!(exposure_of("224.0.0.251", &i), Exposure::Lan);
    }

    #[test]
    fn parses_ss_lines() {
        let out = "\
udp ESTAB 0 0 192.168.100.72%enx001122334455:68 192.168.100.1:67
udp ESTAB 0 0 [2001:db8::7ed]:53039 [2a00:1450:4001:42::1]:443 users:((\"msedge\",pid=1654284,fd=104))
tcp LISTEN 0 4096 *:8080 *:*
udp UNCONN 0 0 [fe80::1234:5678:9abc:def0]%wlp170s0:546 [::]:*
tcp LISTEN 0 511 [::]:1890 [::]:* users:((\"Web Content\",pid=7,fd=3),(\"x\",pid=8,fd=3))
";
        let mut s = parse_ss(out);
        assert_eq!(s.len(), 5);
        let scoped = s.remove(3);
        assert_eq!((scoped.laddr.as_str(), scoped.lport.as_str()), ("fe80::1234:5678:9abc:def0", "546"));
        assert_eq!(scoped.raddr, "::");
        assert_eq!((s[0].laddr.as_str(), s[0].lport.as_str()), ("192.168.100.72", "68"));
        assert_eq!(s[0].process, None);
        assert_eq!(s[1].raddr, "2a00:1450:4001:42::1");
        assert_eq!(s[1].process.as_deref(), Some("msedge"));
        assert_eq!(s[1].pid, Some(1654284));
        assert_eq!((s[2].laddr.as_str(), s[2].rport.as_str()), ("*", "*"));
        assert_eq!(s[3].laddr, "::");
        assert_eq!(s[3].process.as_deref(), Some("Web Content"));
    }

    #[test]
    fn parses_ss_statistics() {
        let out = "tcp ESTAB 0 0 192.168.178.190:44620 192.168.178.6:22 users:((\"ssh\",pid=1,fd=3))\n\
                   \t cubic wscale:7,7 rto:204 bytes_sent:2124181 bytes_retrans:1302 bytes_acked:2122880 bytes_received:33124107 segs_out:4890\n\
                   udp ESTAB 0 0 192.168.178.190:68 192.168.178.1:67\n";
        let s = parse_ss(out);
        assert_eq!(s.len(), 2);
        assert_eq!((s[0].bytes_sent, s[0].bytes_received), (2124181, 33124107));
        assert_eq!((s[1].bytes_sent, s[1].bytes_received), (0, 0));
        assert_eq!(s[1].rport, "67");
    }

    #[test]
    fn parses_docker_ports() {
        let out = "nodered\t0.0.0.0:1890->1880/tcp, [::]:1890->1880/tcp\n\
                   db\t127.0.0.1:5433->5432/tcp\n\
                   plain\t8080/tcp\n\
                   range\t0.0.0.0:9000-9002->9000-9002/udp\n";
        let p = parse_docker_ports(out);
        assert_eq!(p.len(), 6);
        assert!(p[0].wildcard() && p[1].wildcard());
        assert_eq!((p[0].container.as_str(), p[0].port), ("nodered", 1890));
        assert!(!p[2].wildcard());
        assert_eq!((p[5].port, p[5].proto.as_str()), (9002, "udp"));
    }
}
