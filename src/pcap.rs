//! Minimal pcap stream reader and packet decoder.
//!
//! The root helper only pipes raw `tcpdump -w -` output; everything here runs
//! unprivileged. Input comes straight from the network, so every access is
//! bounds-checked and malformed packets simply decode to less detail.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Debug, PartialEq)]
pub struct Packet {
    /// Seconds since the epoch.
    pub time: f64,
    /// Length on the wire.
    pub length: u32,
    pub src: Option<IpAddr>,
    pub dst: Option<IpAddr>,
    pub sport: u16,
    pub dport: u16,
    /// "tcp", "udp" or "" (decides which program owns the local port).
    pub transport: &'static str,
    /// Short protocol label: TCP, UDP, DNS, TLS, HTTP, QUIC, ICMP, ARP ...
    pub proto: &'static str,
    pub info: String,
    /// Direction as recorded by the capture (only on the "any" pseudo-interface).
    pub outgoing: Option<bool>,
    /// Host names learned from this packet (DNS answers, TLS server name).
    pub names: Vec<(IpAddr, String)>,
    /// The domain this packet asks for or connects to, if it says so.
    pub domain: Option<String>,
}

/// Bounds-checked reader over a byte slice.
struct Cur<'a>(&'a [u8]);

impl<'a> Cur<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Some(head)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(at)?, *b.get(at + 1)?]))
}

fn ipv4(b: &[u8]) -> Option<Ipv4Addr> {
    Some(Ipv4Addr::new(*b.first()?, *b.get(1)?, *b.get(2)?, *b.get(3)?))
}

fn ipv6(b: &[u8]) -> Option<Ipv6Addr> {
    let a: [u8; 16] = b.get(..16)?.try_into().ok()?;
    Some(Ipv6Addr::from(a))
}

// ------------------------------------------------------------------- DNS

fn dns_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut end = None; // position after the name in the original record
    for _ in 0..64 {
        let len = *msg.get(pos)? as usize;
        if len == 0 {
            return Some((name, end.unwrap_or(pos + 1)));
        }
        if len & 0xc0 == 0xc0 {
            // compression pointer
            let target = ((len & 0x3f) << 8) | *msg.get(pos + 1)? as usize;
            end.get_or_insert(pos + 2);
            pos = target;
            continue;
        }
        let label = msg.get(pos + 1..pos + 1 + len)?;
        if !name.is_empty() {
            name.push('.');
        }
        name.extend(label.iter().map(|c| if c.is_ascii_graphic() { *c as char } else { '?' }));
        if name.len() > 255 {
            return None;
        }
        pos += 1 + len;
    }
    None
}

fn dns_type(t: u16) -> &'static str {
    match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        64 => "SVCB",
        65 => "HTTPS",
        _ => "?",
    }
}

/// Returns the info text, the addresses the answers map the name to, and the name asked for.
fn parse_dns(msg: &[u8]) -> Option<(String, Vec<(IpAddr, String)>, String)> {
    let flags = be16(msg, 2)?;
    let (questions, answers) = (be16(msg, 4)?, be16(msg, 6)?);
    let response = flags & 0x8000 != 0;
    if questions == 0 {
        return None;
    }
    let (qname, mut pos) = dns_name(msg, 12)?;
    let qtype = be16(msg, pos)?;
    pos += 4;
    if !response {
        return Some((format!("DNS-Anfrage: {qname} ({})", dns_type(qtype)), Vec::new(), qname));
    }
    // skip remaining questions (normally there is exactly one)
    for _ in 1..questions {
        pos = dns_name(msg, pos)?.1 + 4;
    }
    let mut ips: Vec<IpAddr> = Vec::new();
    for _ in 0..answers.min(32) {
        let Some((_, after)) = dns_name(msg, pos) else { break };
        let (Some(rtype), Some(rdlen)) = (be16(msg, after), be16(msg, after + 8)) else { break };
        let data_at = after + 10;
        let Some(data) = msg.get(data_at..data_at + rdlen as usize) else { break };
        match rtype {
            1 => ips.extend(ipv4(data).map(IpAddr::V4)),
            28 => ips.extend(ipv6(data).map(IpAddr::V6)),
            _ => {}
        }
        pos = data_at + rdlen as usize;
    }
    let rcode = flags & 0x000f;
    let info = if rcode == 3 {
        format!("DNS-Antwort: {qname} existiert nicht")
    } else if ips.is_empty() {
        format!("DNS-Antwort: {qname} ({})", dns_type(qtype))
    } else {
        let list: Vec<String> = ips.iter().take(3).map(|i| i.to_string()).collect();
        format!("DNS-Antwort: {qname} → {}{}", list.join(", "), if ips.len() > 3 { " …" } else { "" })
    };
    Some((info, ips.into_iter().map(|ip| (ip, qname.clone())).collect(), qname))
}

// ------------------------------------------------------------------- TLS

/// Server name from a TLS ClientHello (the only readable part of an HTTPS connection).
fn tls_server_name(payload: &[u8]) -> Option<String> {
    let mut c = Cur(payload);
    if c.u8()? != 0x16 || c.u8()? != 3 {
        return None; // not a TLS handshake record
    }
    c.take(3)?; // minor version, record length
    if c.u8()? != 1 {
        return None; // not a ClientHello
    }
    c.take(3)?; // handshake length
    c.take(2 + 32)?; // version, random
    let n = c.u8()? as usize;
    c.take(n)?; // session id
    let n = c.u16()? as usize;
    c.take(n)?; // cipher suites
    let n = c.u8()? as usize;
    c.take(n)?; // compression methods
    let total = c.u16()? as usize;
    // The hello may continue in the next segment; read what is there.
    let mut ext = Cur(c.0.get(..total.min(c.0.len()))?);
    while let (Some(kind), Some(len)) = (ext.u16(), ext.u16()) {
        let body = ext.take(len as usize)?;
        if kind == 0 {
            let mut s = Cur(body);
            s.take(2)?; // list length
            if s.u8()? != 0 {
                return None;
            }
            let n = s.u16()? as usize;
            let name = s.take(n)?;
            if name.iter().all(|b| b.is_ascii_graphic()) {
                return Some(String::from_utf8_lossy(name).into_owned());
            }
            return None;
        }
    }
    None
}

// ------------------------------------------------------------- transport

fn udp_label(port: u16) -> Option<&'static str> {
    Some(match port {
        67 | 68 => "DHCP",
        123 => "NTP (Uhrzeit)",
        137 | 138 => "NetBIOS",
        546 | 547 => "DHCPv6",
        1900 => "SSDP (Gerätesuche)",
        3702 => "WS-Discovery (Gerätesuche)",
        5355 => "LLMNR (Namensauflösung)",
        41641 => "Tailscale",
        51820 => "WireGuard",
        _ => return None,
    })
}

fn decode_tcp(seg: &[u8], p: &mut Packet) {
    let (Some(sport), Some(dport), Some(off), Some(flags)) = (be16(seg, 0), be16(seg, 2), seg.get(12), seg.get(13)) else {
        p.info = "TCP (unvollständig)".into();
        return;
    };
    p.sport = sport;
    p.dport = dport;
    p.transport = "tcp";
    p.proto = "TCP";
    let payload = seg.get((*off as usize >> 4) * 4..).unwrap_or(&[]);
    let (fin, syn, rst, ack) = (flags & 1 != 0, flags & 2 != 0, flags & 4 != 0, flags & 16 != 0);
    if syn && ack {
        p.info = "Verbindung angenommen (SYN-ACK)".into();
    } else if syn {
        p.info = "Verbindungsaufbau (SYN)".into();
    } else if rst {
        p.info = "Verbindung abgebrochen (RST)".into();
    } else if payload.is_empty() {
        p.info = if fin { "Verbindungsende (FIN)".into() } else { "Bestätigung (ACK)".into() };
    } else if let Some(name) = tls_server_name(payload) {
        p.proto = "TLS";
        p.info = format!("TLS-Aufbau zu {name}");
        p.domain = Some(name.clone());
        if let Some(dst) = p.dst {
            p.names.push((dst, name));
        }
    } else if payload.len() > 5 && payload[1] == 3 && (0x14..=0x17).contains(&payload[0]) {
        p.proto = "TLS";
        p.info = match (payload[0], payload[5]) {
            (0x16, 1) => "TLS-Aufbau (Client)".to_string(),
            (0x16, 2) => "TLS-Antwort des Servers".to_string(),
            (0x16, _) => "TLS-Aushandlung".to_string(),
            (0x15, _) => "TLS-Meldung".to_string(),
            _ => format!("verschlüsselte Daten, {} Bytes", payload.len()),
        };
    } else if let Some(line) = plaintext_line(payload) {
        p.proto = if line.starts_with("SSH-") { "SSH" } else { "HTTP" };
        p.info = line;
    } else if sport == 22 || dport == 22 {
        p.proto = "SSH";
        p.info = format!("verschlüsselte Daten, {} Bytes", payload.len());
    } else {
        p.info = format!("{} Bytes Daten{}", payload.len(), if fin { ", Verbindungsende" } else { "" });
    }
}

/// First line of an unencrypted HTTP message or SSH banner.
fn plaintext_line(payload: &[u8]) -> Option<String> {
    const STARTS: [&[u8]; 9] = [b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"HTTP/1.", b"SSH-"];
    if !STARTS.iter().any(|s| payload.starts_with(s)) {
        return None;
    }
    let line = payload.split(|b| *b == b'\r' || *b == b'\n').next()?;
    let text: String = line.iter().take(160).map(|c| if c.is_ascii_graphic() || *c == b' ' { *c as char } else { '?' }).collect();
    Some(text)
}

fn decode_udp(seg: &[u8], p: &mut Packet) {
    let (Some(sport), Some(dport)) = (be16(seg, 0), be16(seg, 2)) else {
        p.info = "UDP (unvollständig)".into();
        return;
    };
    p.sport = sport;
    p.dport = dport;
    p.transport = "udp";
    p.proto = "UDP";
    let payload = seg.get(8..).unwrap_or(&[]);
    if [sport, dport].iter().any(|x| *x == 53 || *x == 5353) {
        if let Some((info, names, domain)) = parse_dns(payload) {
            p.domain = Some(domain);
            p.proto = if sport == 5353 || dport == 5353 { "mDNS" } else { "DNS" };
            p.info = info;
            p.names = names;
            return;
        }
    }
    if sport == 443 || dport == 443 {
        p.proto = "QUIC";
        p.info = format!("verschlüsselte Daten (HTTP/3), {} Bytes", payload.len());
    } else if let Some(label) = udp_label(sport).or_else(|| udp_label(dport)) {
        p.info = label.to_string();
    } else {
        p.info = format!("{} Bytes Daten", payload.len());
    }
}

fn decode_transport(proto: u8, seg: &[u8], p: &mut Packet) {
    match proto {
        6 => decode_tcp(seg, p),
        17 => decode_udp(seg, p),
        1 => {
            p.proto = "ICMP";
            p.info = match seg.first() {
                Some(8) => "Ping-Anfrage".into(),
                Some(0) => "Ping-Antwort".into(),
                Some(3) => "Ziel nicht erreichbar".into(),
                Some(11) => "Zeit überschritten".into(),
                Some(t) => format!("Typ {t}"),
                None => String::new(),
            };
        }
        58 => {
            p.proto = "ICMPv6";
            p.info = match seg.first() {
                Some(128) => "Ping-Anfrage".into(),
                Some(129) => "Ping-Antwort".into(),
                Some(133) => "Router-Suche".into(),
                Some(134) => "Router-Ankündigung".into(),
                Some(135) => "Nachbar-Anfrage".into(),
                Some(136) => "Nachbar-Antwort".into(),
                Some(1) => "Ziel nicht erreichbar".into(),
                Some(t) => format!("Typ {t}"),
                None => String::new(),
            };
        }
        2 => {
            p.proto = "IGMP";
            p.info = "Multicast-Gruppenverwaltung".into();
        }
        other => {
            p.proto = "IP";
            p.info = format!("Protokoll {other}");
        }
    }
}

fn decode_network(ethertype: u16, data: &[u8], p: &mut Packet) {
    match ethertype {
        0x0800 => {
            let Some(first) = data.first() else { return };
            let ihl = (first & 0x0f) as usize * 4;
            let (Some(proto), Some(frag)) = (data.get(9), be16(data, 6)) else { return };
            p.src = data.get(12..16).and_then(ipv4).map(IpAddr::V4);
            p.dst = data.get(16..20).and_then(ipv4).map(IpAddr::V4);
            if frag & 0x1fff != 0 {
                p.proto = "IP";
                p.info = "Fragment".into();
                return;
            }
            // Honour the IP total length so Ethernet padding is not mistaken for payload.
            let total = be16(data, 2).map(usize::from).filter(|t| *t >= ihl && *t <= data.len()).unwrap_or(data.len());
            decode_transport(*proto, data.get(ihl..total).unwrap_or(&[]), p);
        }
        0x86dd => {
            let Some(mut next) = data.get(6).copied() else { return };
            p.src = data.get(8..24).and_then(ipv6).map(IpAddr::V6);
            p.dst = data.get(24..40).and_then(ipv6).map(IpAddr::V6);
            let mut rest = data.get(40..).unwrap_or(&[]);
            // Skip extension headers: hop-by-hop, routing, fragment, destination options.
            for _ in 0..8 {
                let len = match next {
                    0 | 43 | 60 => rest.get(1).map(|l| (*l as usize + 1) * 8),
                    44 => Some(8),
                    _ => break,
                };
                let (Some(len), Some(n)) = (len, rest.first().copied()) else { return };
                next = n;
                rest = rest.get(len..).unwrap_or(&[]);
            }
            decode_transport(next, rest, p);
        }
        0x0806 => {
            p.proto = "ARP";
            let sender = data.get(14..18).and_then(ipv4);
            let target = data.get(24..28).and_then(ipv4);
            p.src = sender.map(IpAddr::V4);
            p.dst = target.map(IpAddr::V4);
            p.info = match (be16(data, 6), sender, target) {
                (Some(1), Some(s), Some(t)) => format!("Wer hat {t}? fragt {s}"),
                (Some(2), Some(s), _) => format!("{s} meldet seine Hardware-Adresse"),
                _ => "ARP".into(),
            };
        }
        other => {
            p.proto = "Sonstiges";
            p.info = format!("Ethertype 0x{other:04x}");
        }
    }
}

/// Decode one captured frame of the given pcap link type.
pub fn decode(linktype: u32, frame: &[u8], time: f64, length: u32) -> Packet {
    let mut p = Packet {
        time,
        length,
        src: None,
        dst: None,
        sport: 0,
        dport: 0,
        transport: "",
        proto: "?",
        info: String::new(),
        outgoing: None,
        names: Vec::new(),
        domain: None,
    };
    match linktype {
        // Ethernet, optionally with one VLAN tag
        1 => match be16(frame, 12) {
            Some(0x8100) => {
                if let Some(t) = be16(frame, 16) {
                    decode_network(t, frame.get(18..).unwrap_or(&[]), &mut p);
                }
            }
            Some(t) => decode_network(t, frame.get(14..).unwrap_or(&[]), &mut p),
            None => {}
        },
        // Linux "cooked" capture v1 (any interface)
        113 => {
            p.outgoing = be16(frame, 0).map(|t| t == 4);
            if let Some(t) = be16(frame, 14) {
                decode_network(t, frame.get(16..).unwrap_or(&[]), &mut p);
            }
        }
        // Linux "cooked" capture v2
        276 => {
            p.outgoing = frame.get(10).map(|t| *t == 4);
            if let Some(t) = be16(frame, 0) {
                decode_network(t, frame.get(20..).unwrap_or(&[]), &mut p);
            }
        }
        // raw IP
        12 | 101 => match frame.first().map(|b| b >> 4) {
            Some(4) => decode_network(0x0800, frame, &mut p),
            Some(6) => decode_network(0x86dd, frame, &mut p),
            _ => {}
        },
        other => p.info = format!("unbekannter Verbindungstyp {other}"),
    }
    p
}

// ---------------------------------------------------------------- stream

struct Header {
    linktype: u32,
    big_endian: bool,
    nanos: bool,
}

/// Incremental reader for a pcap byte stream.
#[derive(Default)]
pub struct Reader {
    buf: Vec<u8>,
    header: Option<Header>,
    /// Set when the stream is not a pcap capture.
    pub invalid: bool,
}

impl Reader {
    fn u32_at(&self, at: usize) -> Option<u32> {
        let b: [u8; 4] = self.buf.get(at..at + 4)?.try_into().ok()?;
        let big = self.header.as_ref().map(|h| h.big_endian).unwrap_or(false);
        Some(if big { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) })
    }

    /// Add bytes from the stream and return the packets that are now complete.
    pub fn feed(&mut self, data: &[u8]) -> Vec<Packet> {
        let mut out = Vec::new();
        if self.invalid {
            return out;
        }
        self.buf.extend_from_slice(data);
        if self.header.is_none() {
            if self.buf.len() < 24 {
                return out;
            }
            let magic = [self.buf[0], self.buf[1], self.buf[2], self.buf[3]];
            let (big_endian, nanos) = match magic {
                [0xd4, 0xc3, 0xb2, 0xa1] => (false, false),
                [0xa1, 0xb2, 0xc3, 0xd4] => (true, false),
                [0x4d, 0x3c, 0xb2, 0xa1] => (false, true),
                [0xa1, 0xb2, 0x3c, 0x4d] => (true, true),
                _ => {
                    self.invalid = true;
                    return out;
                }
            };
            self.header = Some(Header { linktype: 0, big_endian, nanos });
            let linktype = self.u32_at(20).unwrap_or(0);
            self.header = Some(Header { linktype, big_endian, nanos });
            self.buf.drain(..24);
        }
        let mut pos = 0;
        loop {
            let (Some(sec), Some(frac), Some(incl), Some(orig)) =
                (self.u32_at(pos), self.u32_at(pos + 4), self.u32_at(pos + 8), self.u32_at(pos + 12))
            else {
                break;
            };
            let incl = incl as usize;
            if incl > 1 << 20 {
                self.invalid = true; // not a sane record; stop instead of buffering forever
                break;
            }
            let Some(frame) = self.buf.get(pos + 16..pos + 16 + incl) else { break };
            let h = self.header.as_ref().expect("header parsed above");
            let time = f64::from(sec) + f64::from(frac) / if h.nanos { 1e9 } else { 1e6 };
            out.push(decode(h.linktype, frame, time, orig));
            pos += 16 + incl;
        }
        self.buf.drain(..pos);
        out
    }
}

#[cfg(test)]
pub mod testdata {
    //! Hand-built frames shared by the tests.

    pub fn ipv4_packet(proto: u8, src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let total = (20 + payload.len()) as u16;
        let mut p = vec![0x45, 0, (total >> 8) as u8, total as u8, 0, 0, 0, 0, 64, proto, 0, 0];
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(payload);
        p
    }

    pub fn tcp(sport: u16, dport: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
        let mut s = Vec::new();
        s.extend_from_slice(&sport.to_be_bytes());
        s.extend_from_slice(&dport.to_be_bytes());
        s.extend_from_slice(&[0; 8]); // seq, ack
        s.extend_from_slice(&[0x50, flags, 0, 0, 0, 0, 0, 0]);
        s.extend_from_slice(payload);
        s
    }

    pub fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let mut s = Vec::new();
        s.extend_from_slice(&sport.to_be_bytes());
        s.extend_from_slice(&dport.to_be_bytes());
        s.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        s.extend_from_slice(&[0, 0]);
        s.extend_from_slice(payload);
        s
    }

    pub fn ethernet(ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&ethertype.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    /// Linux cooked v2 header (as written for `tcpdump -i any`).
    pub fn sll2(ethertype: u16, outgoing: bool, payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::new();
        f.extend_from_slice(&ethertype.to_be_bytes());
        f.extend_from_slice(&[0, 0, 0, 0, 0, 3, 0, 1, if outgoing { 4 } else { 0 }, 6]);
        f.extend_from_slice(&[0; 8]);
        f.extend_from_slice(payload);
        f
    }

    fn dns_qname(name: &str) -> Vec<u8> {
        let mut q = Vec::new();
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q
    }

    pub fn dns_query(name: &str) -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend(dns_qname(name));
        m.extend_from_slice(&[0, 1, 0, 1]);
        m
    }

    pub fn dns_answer(name: &str, ip: [u8; 4]) -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        m.extend(dns_qname(name));
        m.extend_from_slice(&[0, 1, 0, 1]);
        m.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]); // pointer to the question name
        m.extend_from_slice(&ip);
        m
    }

    pub fn client_hello(server: &str) -> Vec<u8> {
        let mut sni = vec![0, 0]; // extension type: server_name
        let name = server.as_bytes();
        sni.extend_from_slice(&((name.len() + 5) as u16).to_be_bytes());
        sni.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        sni.push(0);
        sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
        sni.extend_from_slice(name);
        let mut ext = vec![0x00, 0x0a, 0, 2, 0, 0]; // some other extension first
        ext.extend(sni);

        let mut hello = vec![3, 3];
        hello.extend_from_slice(&[7; 32]); // random
        hello.push(0); // session id
        hello.extend_from_slice(&[0, 2, 0x13, 0x01]); // cipher suites
        hello.extend_from_slice(&[1, 0]); // compression
        hello.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        hello.extend(ext);

        let mut hs = vec![1, 0];
        hs.extend_from_slice(&(hello.len() as u16).to_be_bytes());
        hs.extend(hello);
        let mut rec = vec![0x16, 3, 1];
        rec.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        rec.extend(hs);
        rec
    }

    /// A little-endian pcap stream with one record per frame, one second apart.
    pub fn pcap(linktype: u32, frames: &[Vec<u8>]) -> Vec<u8> {
        let mut f = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0];
        f.extend_from_slice(&linktype.to_le_bytes());
        for (i, frame) in frames.iter().enumerate() {
            f.extend_from_slice(&(1_700_000_000u32 + i as u32).to_le_bytes());
            f.extend_from_slice(&500_000u32.to_le_bytes());
            f.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            f.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            f.extend_from_slice(frame);
        }
        f
    }
}

#[cfg(test)]
mod tests {
    use super::testdata::*;
    use super::*;

    const ME: [u8; 4] = [192, 168, 178, 190];
    const DNS: [u8; 4] = [192, 168, 178, 1];
    const WEB: [u8; 4] = [93, 184, 216, 34];

    #[test]
    fn decodes_dns_query_and_answer() {
        let q = decode(1, &ethernet(0x0800, &ipv4_packet(17, ME, DNS, &udp(40000, 53, &dns_query("example.com")))), 0.0, 80);
        assert_eq!((q.proto, q.info.as_str()), ("DNS", "DNS-Anfrage: example.com (A)"));
        assert_eq!((q.sport, q.dport), (40000, 53));
        let a = decode(1, &ethernet(0x0800, &ipv4_packet(17, DNS, ME, &udp(53, 40000, &dns_answer("example.com", WEB)))), 0.0, 96);
        assert_eq!(a.info, "DNS-Antwort: example.com → 93.184.216.34");
        assert_eq!(a.names, vec![("93.184.216.34".parse().unwrap(), "example.com".to_string())]);
    }

    #[test]
    fn decodes_tls_server_name_and_tcp_states() {
        let hello = decode(276, &sll2(0x0800, true, &ipv4_packet(6, ME, WEB, &tcp(50000, 443, 0x18, &client_hello("example.com")))), 0.0, 300);
        assert_eq!((hello.proto, hello.info.as_str()), ("TLS", "TLS-Aufbau zu example.com"));
        assert_eq!(hello.outgoing, Some(true));
        assert_eq!(hello.names[0].1, "example.com");
        let syn = decode(276, &sll2(0x0800, true, &ipv4_packet(6, ME, WEB, &tcp(50000, 443, 0x02, &[]))), 0.0, 60);
        assert_eq!(syn.info, "Verbindungsaufbau (SYN)");
        let data = decode(276, &sll2(0x0800, false, &ipv4_packet(6, WEB, ME, &tcp(443, 50000, 0x18, &[0x17, 3, 3, 0, 4, 1, 2, 3, 4]))), 0.0, 60);
        assert_eq!((data.proto, data.outgoing), ("TLS", Some(false)));
        assert!(data.info.starts_with("verschlüsselte Daten"));
        let http = decode(1, &ethernet(0x0800, &ipv4_packet(6, ME, WEB, &tcp(50001, 80, 0x18, b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n"))), 0.0, 90);
        assert_eq!((http.proto, http.info.as_str()), ("HTTP", "GET /index.html HTTP/1.1"));
    }

    #[test]
    fn decodes_ipv6_arp_and_quic() {
        let mut v6 = vec![0x60, 0, 0, 0, 0, 20, 17, 64];
        v6.extend_from_slice(&"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets());
        v6.extend_from_slice(&"2a00:1450::5".parse::<Ipv6Addr>().unwrap().octets());
        v6.extend(udp(50000, 443, &[1, 2, 3, 4]));
        let quic = decode(1, &ethernet(0x86dd, &v6), 0.0, 70);
        assert_eq!(quic.proto, "QUIC");
        assert_eq!(quic.dst, Some("2a00:1450::5".parse().unwrap()));

        let mut arp = vec![0, 1, 8, 0, 6, 4, 0, 1];
        arp.extend_from_slice(&[0; 6]);
        arp.extend_from_slice(&ME);
        arp.extend_from_slice(&[0; 6]);
        arp.extend_from_slice(&DNS);
        let p = decode(1, &ethernet(0x0806, &arp), 0.0, 42);
        assert_eq!((p.proto, p.info.as_str()), ("ARP", "Wer hat 192.168.178.1? fragt 192.168.178.190"));
    }

    #[test]
    fn survives_truncated_and_garbage_input() {
        let full = ethernet(0x0800, &ipv4_packet(6, ME, WEB, &tcp(50000, 443, 0x18, &client_hello("example.com"))));
        for cut in 0..full.len() {
            let _ = decode(1, &full[..cut], 0.0, 0); // must not panic
            let _ = decode(276, &full[..cut], 0.0, 0);
            let _ = decode(113, &full[..cut], 0.0, 0);
        }
        let dns = dns_answer("example.com", WEB);
        for cut in 0..dns.len() {
            let _ = parse_dns(&dns[..cut]);
        }
        // A compression pointer that points at itself must terminate.
        assert_eq!(dns_name(&[0xc0, 0x00], 0), None);
    }

    #[test]
    fn reads_a_stream_in_arbitrary_chunks() {
        let frames = vec![
            sll2(0x0800, true, &ipv4_packet(17, ME, DNS, &udp(40000, 53, &dns_query("example.com")))),
            sll2(0x0800, false, &ipv4_packet(17, DNS, ME, &udp(53, 40000, &dns_answer("example.com", WEB)))),
            sll2(0x0800, true, &ipv4_packet(6, ME, WEB, &tcp(50000, 443, 0x02, &[]))),
        ];
        let stream = pcap(276, &frames);
        for chunk in [1, 7, 64, stream.len()] {
            let mut r = Reader::default();
            let packets: Vec<Packet> = stream.chunks(chunk).flat_map(|c| r.feed(c)).collect();
            assert_eq!(packets.len(), 3, "chunk size {chunk}");
            assert_eq!(packets[0].info, "DNS-Anfrage: example.com (A)");
            assert_eq!(packets[2].time, 1_700_000_002.5);
        }
        let mut r = Reader::default();
        assert!(r.feed(b"this is not a capture file at all").is_empty());
        assert!(r.invalid);
    }

    /// With PICKET_WRITE_SAMPLE=<path> this writes a small capture file for trying out the window.
    #[test]
    fn writes_sample_capture() {
        let Ok(path) = std::env::var("PICKET_WRITE_SAMPLE") else { return };
        let frames = vec![
            sll2(0x0800, true, &ipv4_packet(17, ME, DNS, &udp(40000, 53, &dns_query("example.com")))),
            sll2(0x0800, false, &ipv4_packet(17, DNS, ME, &udp(53, 40000, &dns_answer("example.com", WEB)))),
            sll2(0x0800, true, &ipv4_packet(6, ME, WEB, &tcp(50000, 443, 0x02, &[]))),
            sll2(0x0800, false, &ipv4_packet(6, WEB, ME, &tcp(443, 50000, 0x12, &[]))),
            sll2(0x0800, true, &ipv4_packet(6, ME, WEB, &tcp(50000, 443, 0x18, &client_hello("example.com")))),
            sll2(0x0800, false, &ipv4_packet(6, WEB, ME, &tcp(443, 50000, 0x18, &[0x17, 3, 3, 0, 4, 1, 2, 3, 4]))),
            sll2(0x0800, true, &ipv4_packet(6, ME, WEB, &tcp(50001, 80, 0x18, b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n"))),
            sll2(0x0800, true, &ipv4_packet(1, ME, DNS, &[8, 0, 0, 0])),
        ];
        std::fs::write(path, pcap(276, &frames)).unwrap();
    }
}
