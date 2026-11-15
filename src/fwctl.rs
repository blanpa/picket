//! Firewall control (ufw).
//!
//! This is the only part of the program that changes the system. The window
//! never runs ufw itself: it starts `pkexec picket fw-apply <json>`, the
//! system asks for the password, and the root helper below turns the request
//! into one of a small set of validated ufw commands. Free-form arguments
//! never reach ufw.

use crate::i18n::tr;
use crate::privileged::{self, Privileged};
use crate::util;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum Op {
    Enable,
    Disable,
    /// Default policy for incoming or outgoing connections.
    Default { direction: String, policy: String },
    Add(RuleSpec),
    /// Delete an existing rule, given as printed by `ufw show added` (without the leading "ufw").
    Delete { rule: String },
    /// Make a host name unreachable for programs on this laptop (entry in /etc/hosts), or allow it again.
    BlockDomain { domain: String, block: bool },
    /// Close the existing connections to an address right now (`ss -K`). A firewall
    /// rule alone does not do that: established connections stay allowed.
    Drop {
        addr: String,
        #[serde(default)]
        port: String,
    },
}

impl Op {
    /// The system tool that carries out the request ("hosts": /etc/hosts is edited directly).
    pub fn program(&self) -> &'static str {
        match self {
            Op::Drop { .. } => "ss",
            Op::BlockDomain { .. } => "hosts",
            _ => "ufw",
        }
    }
}

const HOSTS: &str = "/etc/hosts";
const HOSTS_BEGIN: &str = "# BEGIN picket: gesperrte Domains";
const HOSTS_END: &str = "# END picket";

/// A plain host name such as "tracker.example.com": nothing that could smuggle a second entry into /etc/hosts.
pub fn valid_domain(d: &str) -> bool {
    d.len() <= 253
        && d.contains('.')
        && d.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && label.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

/// Domains in Picket's section of a hosts file.
pub fn hosts_blocked(text: &str) -> Vec<String> {
    let mut inside = false;
    let mut out: Vec<String> = Vec::new();
    for l in text.lines() {
        match l.trim() {
            HOSTS_BEGIN => inside = true,
            HOSTS_END => inside = false,
            entry if inside => {
                if let Some(d) = entry.strip_prefix("0.0.0.0 ") {
                    out.push(d.trim().to_string());
                }
            }
            _ => {}
        }
    }
    out
}

/// The hosts file with a domain added to or removed from Picket's section; everything else stays untouched.
pub fn hosts_edit(text: &str, domain: &str, block: bool) -> String {
    let mut domains = hosts_blocked(text);
    domains.retain(|d| d != domain);
    if block {
        domains.push(domain.to_string());
    }
    domains.sort();
    // Everything outside our section, unchanged.
    let mut inside = false;
    let mut out: Vec<&str> = Vec::new();
    for l in text.lines() {
        match l.trim() {
            HOSTS_BEGIN => inside = true,
            HOSTS_END => inside = false,
            _ if !inside => out.push(l),
            _ => {}
        }
    }
    while out.last().map(|l| l.trim().is_empty()).unwrap_or(false) {
        out.pop();
    }
    let mut result = out.join("\n");
    result.push('\n');
    if !domains.is_empty() {
        result.push_str(&format!("\n{HOSTS_BEGIN}\n"));
        for d in &domains {
            result.push_str(&format!("0.0.0.0 {d}\n:: {d}\n"));
        }
        result.push_str(&format!("{HOSTS_END}\n"));
    }
    result
}

/// Domains currently blocked through /etc/hosts (readable without root).
#[cfg_attr(not(feature = "gui"), allow(dead_code))]
pub fn blocked_domains() -> Vec<String> {
    if crate::demo::enabled() {
        return crate::demo::blocked_domains();
    }
    hosts_blocked(&std::fs::read_to_string(HOSTS).unwrap_or_default())
}

fn write_hosts(domain: &str, block: bool) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let text = std::fs::read_to_string(HOSTS).map_err(|e| format!("{HOSTS}: {e}"))?;
    let tmp = format!("{HOSTS}.picket-tmp");
    std::fs::write(&tmp, hosts_edit(&text, domain, block)).map_err(|e| format!("{tmp}: {e}"))?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o644)).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, HOSTS).map_err(|e| format!("{HOSTS}: {e}"))
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct RuleSpec {
    /// allow | deny | reject | limit
    pub action: String,
    /// in | out
    pub direction: String,
    /// "", "22", "8000:8010" or "80,443"
    #[serde(default)]
    pub port: String,
    /// "", "tcp" or "udp"
    #[serde(default)]
    pub proto: String,
    /// "", an IP address or a network like 192.168.178.0/24 (source for `in`, destination for `out`)
    #[serde(default)]
    pub addr: String,
    #[serde(default)]
    pub comment: String,
}

const ACTIONS: [&str; 4] = ["allow", "deny", "reject", "limit"];

fn valid_port(p: &str) -> bool {
    matches!(p.parse::<u32>(), Ok(1..=65535))
}

/// Normalise a port expression; `8000-8010` is accepted as a range.
fn parse_ports(input: &str) -> Result<(String, bool), String> {
    let p = input.trim().replace('-', ":").replace(' ', "");
    if p.is_empty() {
        return Ok((p, false));
    }
    let multi = p.contains(':') || p.contains(',');
    for part in p.split(',') {
        let ok = match part.split_once(':') {
            Some((a, b)) => valid_port(a) && valid_port(b) && a.parse::<u32>().ok() < b.parse::<u32>().ok(),
            None => valid_port(part),
        };
        if !ok {
            return Err(format!("Ungültiger Port: „{}“ (erlaubt: 1–65535, Bereich 8000-8010, Liste 80,443)", input.trim()));
        }
    }
    Ok((p, multi))
}

fn parse_addr(input: &str) -> Result<String, String> {
    let a = input.trim();
    if a.is_empty() || a.eq_ignore_ascii_case("any") {
        return Ok("any".into());
    }
    let (ip, prefix) = match a.split_once('/') {
        Some((ip, p)) => (ip, Some(p)),
        None => (a, None),
    };
    let parsed: IpAddr = ip
        .parse()
        .map_err(|_| format!("Ungültige Adresse: „{a}“ (erwartet z. B. 192.168.178.20 oder 192.168.178.0/24)"))?;
    if let Some(p) = prefix {
        let max = if parsed.is_ipv4() { 32 } else { 128 };
        match p.parse::<u8>() {
            Ok(n) if n <= max => {}
            _ => return Err(format!("Ungültige Netzmaske in „{a}“")),
        }
    }
    Ok(a.to_string())
}

/// The arguments for a request (for `Op::program`). Everything is validated
/// here; the result is passed as separate arguments, never through a shell.
pub fn ufw_args(op: &Op) -> Result<Vec<String>, String> {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
    match op {
        Op::Enable => Ok(s(&["--force", "enable"])),
        Op::Disable => Ok(s(&["disable"])),
        Op::Default { direction, policy } => {
            if !["incoming", "outgoing"].contains(&direction.as_str()) {
                return Err(format!("Unbekannte Richtung: {direction}"));
            }
            if !["allow", "deny", "reject"].contains(&policy.as_str()) {
                return Err(format!("Unbekannte Standardregel: {policy}"));
            }
            Ok(s(&["default", policy, direction]))
        }
        Op::Add(r) => {
            if !ACTIONS.contains(&r.action.as_str()) {
                return Err(format!("Unbekannte Aktion: {}", r.action));
            }
            if !["in", "out"].contains(&r.direction.as_str()) {
                return Err(format!("Unbekannte Richtung: {}", r.direction));
            }
            if !["", "tcp", "udp"].contains(&r.proto.as_str()) {
                return Err(format!("Unbekanntes Protokoll: {}", r.proto));
            }
            let (port, multi) = parse_ports(&r.port)?;
            if multi && r.proto.is_empty() {
                return Err("Für Portbereiche und -listen muss TCP oder UDP gewählt werden.".into());
            }
            let addr = parse_addr(&r.addr)?;
            if port.is_empty() && addr == "any" && r.proto.is_empty() {
                return Err("Bitte mindestens einen Port oder eine Adresse angeben.".into());
            }
            let comment = r.comment.trim();
            if comment.chars().count() > 60 || comment.chars().any(|c| c.is_control() || "'\"\\`$".contains(c)) {
                return Err("Der Kommentar darf höchstens 60 Zeichen haben und keine Anführungszeichen enthalten.".into());
            }
            // Rules are evaluated in order: a block must come before any earlier "allow".
            let mut a = if matches!(r.action.as_str(), "deny" | "reject") { s(&["prepend"]) } else { Vec::new() };
            a.extend([r.action.clone(), r.direction.clone()]);
            if !r.proto.is_empty() {
                a.extend(s(&["proto", &r.proto]));
            }
            if r.direction == "in" {
                a.extend(s(&["from", &addr, "to", "any"]));
            } else {
                a.extend(s(&["from", "any", "to", &addr]));
            }
            if !port.is_empty() {
                a.extend(s(&["port", &port]));
            }
            if !comment.is_empty() {
                a.extend(s(&["comment", comment]));
            }
            Ok(a)
        }
        Op::BlockDomain { domain, block } => {
            if !valid_domain(domain) {
                return Err(format!("Kein gültiger Domain-Name: „{domain}“ (erwartet z. B. tracker.example.com, ohne https:// und Pfad)"));
            }
            Ok(s(&[if *block { "sperren" } else { "freigeben" }, domain]))
        }
        Op::Drop { addr, port } => {
            let ip: IpAddr = addr.trim().parse().map_err(|_| format!("Ungültige Adresse: „{}“", addr.trim()))?;
            // ss wants IPv6 addresses in brackets.
            let dst = match ip {
                IpAddr::V4(v4) => v4.to_string(),
                IpAddr::V6(v6) => format!("[{v6}]"),
            };
            let mut a = s(&["-K", "-t", "-u", "dst", &dst]);
            let port = port.trim();
            if !port.is_empty() {
                if !valid_port(port) {
                    return Err(format!("Ungültiger Port: „{port}“"));
                }
                a.extend(s(&["dport", "=", port]));
            }
            Ok(a)
        }
        Op::Delete { rule } => {
            let rule = strip_comment(rule);
            let tokens: Vec<&str> = rule.split_whitespace().collect();
            let ok_token = |t: &&str| !t.is_empty() && t.chars().all(|c| c.is_ascii_alphanumeric() || "./:,_-".contains(c));
            if tokens.is_empty() || !ACTIONS.contains(&tokens[0]) || !tokens.iter().all(ok_token) {
                return Err(format!("Diese Regel kann nicht gelöscht werden: {rule}"));
            }
            let mut a = s(&["--force", "delete"]);
            a.extend(tokens.iter().map(|t| t.to_string()));
            Ok(a)
        }
    }
}

/// The command as the user would type it, for display before confirming.
pub fn command_line(op: &Op) -> Result<String, String> {
    if let Op::BlockDomain { domain, block } = op {
        ufw_args(op)?;
        return Ok(if *block {
            format!("in /etc/hosts eintragen: 0.0.0.0 {domain} und :: {domain}")
        } else {
            format!("aus /etc/hosts entfernen: {domain}")
        });
    }
    Ok(ufw_args(op)?
        .iter()
        .map(|a| if a.contains(' ') { format!("'{a}'") } else { a.clone() })
        .fold(format!("sudo {}", op.program()), |acc, a| acc + " " + &a))
}

fn strip_comment(rule: &str) -> &str {
    rule.split(" comment '").next().unwrap_or(rule).trim()
}

#[cfg_attr(not(feature = "gui"), allow(dead_code))]
#[derive(Clone, Debug, PartialEq)]
pub struct Rule {
    /// Rule exactly as ufw prints it (without the leading "ufw"), used for deleting.
    pub raw: String,
    pub action: String,
    pub comment: String,
}

#[cfg_attr(not(feature = "gui"), allow(dead_code))]
impl Rule {
    /// Short description in the interface language, e.g. "Erlauben: eingehend Port 22".
    pub fn describe(&self) -> String {
        let action = tr(match self.action.as_str() {
            "allow" => "Erlauben",
            "deny" => "Blockieren",
            "reject" => "Ablehnen",
            "limit" => "Begrenzen",
            other => other,
        });
        let body = strip_comment(&self.raw);
        let rest = body.strip_prefix(self.action.as_str()).unwrap_or(body).trim();
        let words: Vec<String> = rest
            .split_whitespace()
            .map(|w| {
                tr(match w {
                    "in" => "eingehend",
                    "out" => "ausgehend",
                    "from" => "von",
                    "to" => "nach",
                    "any" => "überall",
                    "port" => "Port",
                    "proto" => "Protokoll",
                    "on" => "an",
                    other => other,
                })
            })
            .collect();
        format!("{action}: {}", words.join(" "))
    }
}

/// Parse `ufw show added`.
pub fn parse_added(out: &str) -> Vec<Rule> {
    out.lines()
        .filter_map(|l| l.trim().strip_prefix("ufw "))
        .filter_map(|raw| {
            let action = raw.split_whitespace().next()?;
            if !ACTIONS.contains(&action) {
                return None;
            }
            let comment = raw
                .split_once(" comment '")
                .map(|(_, c)| c.trim_end_matches('\'').to_string())
                .unwrap_or_default();
            Some(Rule { raw: raw.to_string(), action: action.to_string(), comment })
        })
        .collect()
}

/// What the firewall does with incoming connections to a port.
#[derive(Serialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// Reachable (no firewall, an allow rule, or Docker's own rules).
    #[default]
    Open,
    Blocked,
    /// Allowed for some sources or interfaces only.
    Restricted,
    /// Firewall is on, but its rules are not readable or not understood.
    Unknown,
}

struct Parsed {
    action: String,
    inbound: bool,
    proto: Option<String>,
    /// Port ranges; None = any port.
    ports: Option<Vec<(u16, u16)>>,
    /// Applies to every source on every interface.
    general: bool,
}

fn parse_port_spec(spec: &str) -> Option<Vec<(u16, u16)>> {
    spec.split(',')
        .map(|part| match part.split_once(':') {
            Some((a, b)) => Some((a.parse().ok()?, b.parse().ok()?)),
            None => part.parse().ok().map(|p| (p, p)),
        })
        .collect()
}

/// Understand a rule from `ufw show added`; None for forms this does not cover (app profiles etc.).
fn parse_rule(raw: &str) -> Option<Parsed> {
    let t: Vec<&str> = strip_comment(raw).split_whitespace().collect();
    let mut p = Parsed { action: t.first()?.to_string(), inbound: true, proto: None, ports: None, general: true };
    let mut i = 1;
    if let Some(dir @ ("in" | "out")) = t.get(i).copied() {
        p.inbound = dir == "in";
        i += 1;
        if t.get(i) == Some(&"on") {
            p.general = false;
            i += 2;
        }
    }
    let rest = &t[i.min(t.len())..];
    if !rest.iter().any(|w| matches!(*w, "from" | "to" | "proto")) {
        // Simple form: "22", "22/tcp", "80,443/tcp", "8000:8010/udp"
        let [spec] = rest else { return None };
        let (ports, proto) = match spec.split_once('/') {
            Some((ports, proto)) => (ports, Some(proto.to_string())),
            None => (*spec, None),
        };
        p.ports = Some(parse_port_spec(ports)?);
        p.proto = proto;
        return Some(p);
    }
    let mut j = 0;
    while j < rest.len() {
        match rest[j] {
            "proto" => {
                p.proto = Some(rest.get(j + 1)?.to_string());
                j += 2;
            }
            "from" => {
                if *rest.get(j + 1)? != "any" {
                    p.general = false;
                }
                j += 2;
                if rest.get(j) == Some(&"port") {
                    return None; // source-port rules are not evaluated
                }
            }
            "to" => {
                if *rest.get(j + 1)? != "any" {
                    return None; // rules for one destination address are not evaluated
                }
                j += 2;
                if rest.get(j) == Some(&"port") {
                    p.ports = Some(parse_port_spec(rest.get(j + 1)?)?);
                    j += 2;
                }
            }
            "log" | "log-all" => j += 1,
            _ => return None,
        }
    }
    Some(p)
}

/// Is a listening port reachable from the network, given the firewall state?
/// `docker`: the port is published by Docker, which bypasses ufw.
pub fn verdict(state: &State, proto: &str, port: u16, docker: bool) -> Verdict {
    if docker || !state.active {
        return Verdict::Open;
    }
    let Some(rules) = &state.rules else {
        return if state.incoming == "allow" { Verdict::Open } else { Verdict::Unknown };
    };
    let mut unclear = false;
    for rule in rules {
        let Some(p) = parse_rule(&rule.raw) else {
            unclear = true;
            continue;
        };
        let matches = p.inbound
            && p.proto.as_deref().map(|x| x == proto).unwrap_or(true)
            && p.ports.as_ref().map(|r| r.iter().any(|(a, b)| (*a..=*b).contains(&port))).unwrap_or(true);
        if !matches {
            continue;
        }
        match (p.action.as_str(), p.general) {
            ("allow" | "limit", true) => return Verdict::Open,
            ("allow" | "limit", false) => return Verdict::Restricted,
            ("deny" | "reject", true) => return Verdict::Blocked,
            _ => {} // blocks only some sources: keep looking
        }
    }
    if unclear {
        Verdict::Unknown
    } else if state.incoming == "allow" {
        Verdict::Open
    } else {
        Verdict::Blocked
    }
}

#[cfg_attr(not(feature = "gui"), allow(dead_code))]
#[derive(Clone, Debug, Default)]
pub struct State {
    pub installed: bool,
    pub active: bool,
    /// allow | deny | reject, empty when unknown
    pub incoming: String,
    pub outgoing: String,
    /// None when the rules are not readable without a root snapshot.
    pub rules: Option<Vec<Rule>>,
}

fn policy_word(conf: &str, key: &str) -> String {
    match util::conf_value(conf, key).unwrap_or_default().as_str() {
        "DROP" => "deny".into(),
        "REJECT" => "reject".into(),
        "ACCEPT" => "allow".into(),
        _ => String::new(),
    }
}

/// Current firewall state from the config files plus the optional root snapshot.
pub fn state(privd: Option<&Privileged>) -> State {
    if crate::demo::enabled() {
        return crate::demo::firewall();
    }
    let live = privd
        .and_then(|p| p.ufw_status.as_ref())
        .map(|s| s.lines().any(|l| l.trim() == "Status: active"));
    let configured = util::read("/etc/ufw/ufw.conf")
        .and_then(|c| util::conf_value(&c, "ENABLED"))
        .map(|v| v.eq_ignore_ascii_case("yes"));
    let defaults = util::read("/etc/default/ufw").unwrap_or_default();
    State {
        installed: util::which("ufw").is_some(),
        active: live.or(configured).unwrap_or(false),
        incoming: policy_word(&defaults, "DEFAULT_INPUT_POLICY"),
        outgoing: policy_word(&defaults, "DEFAULT_OUTPUT_POLICY"),
        rules: privd.and_then(|p| p.ufw_added.as_deref()).map(parse_added),
    }
}

/// Root helper: apply the requests, then refresh the root snapshot so the
/// window can show the result without asking for the password again.
pub fn apply(ops: &[Op], dry_run: bool) -> Result<(), String> {
    // Validate everything before changing anything.
    let commands: Vec<Vec<String>> = ops.iter().map(ufw_args).collect::<Result<_, _>>()?;
    if dry_run {
        for (op, _) in ops.iter().zip(&commands) {
            crate::outln!("{}", command_line(op)?);
        }
        return Ok(());
    }
    if ops.iter().any(|op| op.program() == "ufw") && util::which("ufw").is_none() {
        return Err("ufw ist nicht installiert (sudo apt install ufw).".into());
    }
    for (op, args) in ops.iter().zip(&commands) {
        if let Op::Delete { rule } = op {
            // Only rules that really exist can be deleted.
            let added = util::run("ufw", &["show", "added"], 10).map(|o| o.stdout).unwrap_or_default();
            let wanted = strip_comment(rule);
            if !parse_added(&added).iter().any(|r| strip_comment(&r.raw) == wanted) {
                return Err(format!("Die Regel existiert nicht mehr: {wanted}"));
            }
        }
        if let Op::BlockDomain { domain, block } = op {
            write_hosts(domain, *block)?;
            continue;
        }
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let program = op.program();
        let out = util::run(program, &refs, 30)
            .ok_or_else(|| format!("{program} konnte nicht gestartet werden oder hat nicht geantwortet."))?;
        print!("{}", out.stdout);
        if !out.ok {
            let msg = if out.stderr.trim().is_empty() { out.stdout.trim() } else { out.stderr.trim() };
            return Err(format!("{program} meldet einen Fehler: {msg}"));
        }
    }
    privileged::write(&privileged::collect()).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn add(action: &str, dir: &str, port: &str, proto: &str, addr: &str, comment: &str) -> Op {
        Op::Add(RuleSpec {
            action: action.into(),
            direction: dir.into(),
            port: port.into(),
            proto: proto.into(),
            addr: addr.into(),
            comment: comment.into(),
        })
    }

    fn line(op: &Op) -> String {
        ufw_args(op).unwrap().join(" ")
    }

    #[test]
    fn builds_rule_commands() {
        assert_eq!(line(&add("allow", "in", "22", "tcp", "", "")), "allow in proto tcp from any to any port 22");
        assert_eq!(
            line(&add("allow", "in", "8080", "tcp", "192.168.178.0/24", "Node RED")),
            "allow in proto tcp from 192.168.178.0/24 to any port 8080 comment Node RED"
        );
        assert_eq!(line(&add("deny", "out", "53", "", "8.8.8.8", "")), "prepend deny out from any to 8.8.8.8 port 53");
        assert_eq!(line(&add("limit", "in", "8000-8010", "tcp", "", "")), "limit in proto tcp from any to any port 8000:8010");
        assert_eq!(line(&add("deny", "in", "", "", "10.0.0.5", "")), "prepend deny in from 10.0.0.5 to any");
        assert_eq!(line(&Op::Enable), "--force enable");
        assert_eq!(
            line(&Op::Default { direction: "incoming".into(), policy: "deny".into() }),
            "default deny incoming"
        );
    }

    #[test]
    fn rejects_bad_requests() {
        assert!(ufw_args(&add("allow", "in", "0", "tcp", "", "")).is_err());
        assert!(ufw_args(&add("allow", "in", "70000", "tcp", "", "")).is_err());
        assert!(ufw_args(&add("allow", "in", "80,443", "", "", "")).is_err()); // list needs a protocol
        assert!(ufw_args(&add("allow", "in", "22; reboot", "tcp", "", "")).is_err());
        assert!(ufw_args(&add("allow", "in", "22", "tcp", "example.com", "")).is_err());
        assert!(ufw_args(&add("allow", "in", "22", "tcp", "10.0.0.0/40", "")).is_err());
        assert!(ufw_args(&add("allow", "in", "", "", "", "")).is_err()); // would open everything
        assert!(ufw_args(&add("reset", "in", "22", "tcp", "", "")).is_err());
        assert!(ufw_args(&add("allow", "in", "22", "tcp", "", "it's")).is_err());
        assert!(ufw_args(&Op::Default { direction: "incoming".into(), policy: "--force".into() }).is_err());
        assert!(ufw_args(&Op::Delete { rule: "--force reset".into() }).is_err());
        assert!(ufw_args(&Op::Delete { rule: "allow 22/tcp; id".into() }).is_err());
    }

    #[test]
    fn parses_and_deletes_existing_rules() {
        let out = "Added user rules (see 'ufw status' for running firewall):\n\
                   ufw allow 22/tcp\n\
                   ufw allow from 192.168.178.0/24 to any port 8080 proto tcp comment 'Node RED'\n\
                   ufw limit in on wlp170s0 to any port 5900\n";
        let rules = parse_added(out);
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[1].comment, "Node RED");
        assert_eq!(rules[0].describe(), "Erlauben: 22/tcp");
        assert_eq!(rules[1].describe(), "Erlauben: von 192.168.178.0/24 nach überall Port 8080 Protokoll tcp");
        assert_eq!(
            line(&Op::Delete { rule: rules[1].raw.clone() }),
            "--force delete allow from 192.168.178.0/24 to any port 8080 proto tcp"
        );
        assert!(parse_added("Added user rules (see 'ufw status' for running firewall):\n(None)\n").is_empty());
    }

    #[test]
    fn builds_commands_to_close_connections() {
        let drop = |addr: &str, port: &str| Op::Drop { addr: addr.into(), port: port.into() };
        assert_eq!(command_line(&drop("192.168.178.6", "22")).unwrap(), "sudo ss -K -t -u dst 192.168.178.6 dport = 22");
        assert_eq!(command_line(&drop("2607:6bc0::10", "")).unwrap(), "sudo ss -K -t -u dst [2607:6bc0::10]");
        assert!(ufw_args(&drop("example.com", "")).is_err());
        assert!(ufw_args(&drop("1.2.3.4", "22 or sport = 1")).is_err());
        assert!(ufw_args(&drop("1.2.3.0/24", "")).is_err()); // single addresses only
        // Blocking a remote host: reject outgoing traffic to it.
        assert_eq!(line(&add("reject", "out", "", "", "8.8.8.8", "")), "prepend reject out from any to 8.8.8.8");
    }

    #[test]
    fn judges_ports_by_the_rules() {
        let rules = "ufw deny 23/tcp\nufw allow 22/tcp\nufw allow in proto tcp from 192.168.178.0/24 to any port 8080\n\
                     ufw allow 8000:8010/tcp\nufw deny in from 10.0.0.9 to any\nufw allow out 53\nufw limit 5900\n";
        let mut st = State { installed: true, active: true, incoming: "deny".into(), outgoing: "allow".into(), rules: Some(parse_added(rules)) };
        assert_eq!(verdict(&st, "tcp", 22, false), Verdict::Open);
        assert_eq!(verdict(&st, "udp", 22, false), Verdict::Blocked); // rule is tcp only
        assert_eq!(verdict(&st, "tcp", 23, false), Verdict::Blocked);
        assert_eq!(verdict(&st, "tcp", 8080, false), Verdict::Restricted);
        assert_eq!(verdict(&st, "tcp", 8005, false), Verdict::Open);
        assert_eq!(verdict(&st, "udp", 53, false), Verdict::Blocked); // the rule is for outgoing traffic
        assert_eq!(verdict(&st, "udp", 5900, false), Verdict::Open);
        assert_eq!(verdict(&st, "tcp", 1890, false), Verdict::Blocked); // default policy
        assert_eq!(verdict(&st, "tcp", 1890, true), Verdict::Open); // Docker bypasses ufw
        st.incoming = "allow".into();
        assert_eq!(verdict(&st, "tcp", 1890, false), Verdict::Open);
        // Unknown rule forms and unreadable rules give no false comfort.
        st.incoming = "deny".into();
        st.rules = Some(parse_added("ufw allow OpenSSH\n"));
        assert_eq!(verdict(&st, "tcp", 1890, false), Verdict::Unknown);
        st.rules = None;
        assert_eq!(verdict(&st, "tcp", 22, false), Verdict::Unknown);
        st.active = false;
        assert_eq!(verdict(&st, "tcp", 22, false), Verdict::Open);
    }

    #[test]
    fn edits_only_its_own_section_of_the_hosts_file() {
        let original = "127.0.0.1 localhost\n127.0.1.1 laptop\n\n# eigene Einträge\n10.0.0.5 nas\n";
        let one = hosts_edit(original, "tracker.example.com", true);
        assert!(one.starts_with(original.trim_end()));
        assert_eq!(hosts_blocked(&one), ["tracker.example.com"]);
        assert!(one.contains("0.0.0.0 tracker.example.com\n:: tracker.example.com\n"));
        let two = hosts_edit(&hosts_edit(&one, "ads.example.org", true), "tracker.example.com", true); // twice: no duplicate
        assert_eq!(hosts_blocked(&two), ["ads.example.org", "tracker.example.com"]);
        let back = hosts_edit(&hosts_edit(&two, "ads.example.org", false), "tracker.example.com", false);
        assert_eq!(back, original); // nothing of ours is left behind

        assert!(valid_domain("tracker.example.com") && valid_domain("a-b.example.de"));
        for bad in ["localhost", "example.com evil.com", "exa mple.com", "-a.example.com", "example.com\n0.0.0.0 x", "https://example.com", "Example.com", ".example.com", ""] {
            assert!(!valid_domain(bad), "{bad:?}");
        }
        assert!(ufw_args(&Op::BlockDomain { domain: "x.de\n127.0.0.1 bank.de".into(), block: true }).is_err());
        assert_eq!(command_line(&Op::BlockDomain { domain: "ads.example.org".into(), block: false }).unwrap(), "aus /etc/hosts entfernen: ads.example.org");
    }

    #[test]
    fn round_trips_json() {
        let op: Op = serde_json::from_str(r#"{"op":"add","action":"allow","direction":"in","port":"22","proto":"tcp"}"#).unwrap();
        assert_eq!(op, add("allow", "in", "22", "tcp", "", ""));
        let ops: Vec<Op> = serde_json::from_str(r#"[{"op":"enable"},{"op":"delete","rule":"allow 22/tcp"}]"#).unwrap();
        assert_eq!(ops.len(), 2);
    }
}
