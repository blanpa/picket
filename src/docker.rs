//! Docker containers: what they expose and how much power they have.

use crate::util;
use serde::Serialize;

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Port {
    pub host_ip: String,
    pub host_port: u16,
    pub container_port: String,
    pub proto: String,
}

impl Port {
    /// Bound to every interface, i.e. reachable from the network.
    pub fn open(&self) -> bool {
        matches!(self.host_ip.as_str(), "" | "0.0.0.0" | "::")
    }

    /// The compose line that keeps this port on the laptop.
    pub fn local_binding(&self) -> String {
        let proto = if self.proto == "udp" { "/udp" } else { "" };
        format!("\"127.0.0.1:{}:{}{proto}\"", self.host_port, self.container_port)
    }
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct Container {
    pub name: String,
    pub image: String,
    pub privileged: bool,
    /// Empty or "0"/"root" means the process inside runs as root.
    pub user: String,
    pub host_network: bool,
    /// The Docker control socket is mounted: the container can take over the host.
    pub docker_socket: bool,
    pub added_capabilities: Vec<String>,
    pub ports: Vec<Port>,
    /// docker-compose file that defines the container, if any.
    pub compose_file: String,
}

impl Container {
    pub fn runs_as_root(&self) -> bool {
        let user = self.user.split(':').next().unwrap_or("");
        user.is_empty() || user == "0" || user == "root"
    }

    pub fn open_ports(&self) -> Vec<&Port> {
        let mut seen = std::collections::HashSet::new();
        self.ports.iter().filter(|p| p.open() && seen.insert((p.host_port, p.proto.as_str()))).collect()
    }
}

/// Parse `docker inspect` output (a JSON array of containers).
pub fn parse_inspect(json: &str) -> Vec<Container> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for c in v.as_array().into_iter().flatten() {
        let host = &c["HostConfig"];
        let labels = &c["Config"]["Labels"];
        let mut ports = Vec::new();
        for (key, bindings) in c["NetworkSettings"]["Ports"].as_object().into_iter().flatten() {
            let (cport, proto) = key.split_once('/').unwrap_or((key.as_str(), "tcp"));
            for b in bindings.as_array().into_iter().flatten() {
                if let Some(hp) = b["HostPort"].as_str().and_then(|p| p.parse().ok()) {
                    ports.push(Port {
                        host_ip: b["HostIp"].as_str().unwrap_or("").to_string(),
                        host_port: hp,
                        container_port: cport.to_string(),
                        proto: proto.to_string(),
                    });
                }
            }
        }
        ports.sort_by_key(|p| (p.host_port, p.host_ip.clone()));
        let dir = labels["com.docker.compose.project.working_dir"].as_str().unwrap_or("");
        let files = labels["com.docker.compose.project.config_files"].as_str().unwrap_or("");
        out.push(Container {
            name: c["Name"].as_str().unwrap_or("").trim_start_matches('/').to_string(),
            image: c["Config"]["Image"].as_str().unwrap_or("").to_string(),
            privileged: host["Privileged"].as_bool().unwrap_or(false),
            user: c["Config"]["User"].as_str().unwrap_or("").to_string(),
            host_network: host["NetworkMode"].as_str() == Some("host"),
            docker_socket: c["Mounts"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|m| m["Source"].as_str().map(|s| s.ends_with("docker.sock")).unwrap_or(false)),
            added_capabilities: host["CapAdd"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|x| x.as_str().map(String::from))
                .collect(),
            ports,
            compose_file: if files.is_empty() { dir.to_string() } else { files.split(',').next().unwrap_or("").to_string() },
        });
    }
    out.sort_by(|a, b| b.open_ports().len().cmp(&a.open_ports().len()).then(a.name.cmp(&b.name)));
    out
}

/// Running containers; None when Docker is not installed or not accessible.
pub fn list() -> Option<Vec<Container>> {
    if crate::demo::enabled() {
        return Some(crate::demo::containers());
    }
    let ids = util::run("docker", &["ps", "-q"], 6).filter(|o| o.ok)?;
    let ids: Vec<&str> = ids.stdout.split_whitespace().collect();
    if ids.is_empty() {
        return Some(Vec::new());
    }
    let mut args = vec!["inspect"];
    args.extend(ids);
    let out = util::run("docker", &args, 15).filter(|o| o.ok)?;
    Some(parse_inspect(&out.stdout))
}

#[cfg_attr(not(feature = "gui"), allow(dead_code))]
/// Rewrite the `ports:` entries that publish `container_port` so that they bind to
/// 127.0.0.1. Returns the new text and the changed lines (before, after); None when
/// nothing needs changing. Works on lines, so comments and layout stay as they are.
pub fn bind_local(compose: &str, container_port: &str) -> Option<(String, Vec<(String, String)>)> {
    let mut changes = Vec::new();
    let mut out = String::with_capacity(compose.len() + 32);
    for line in compose.split_inclusive('\n') {
        let body = line.trim_end_matches(['\n', '\r']);
        let ending = &line[body.len()..];
        match rewrite_port_line(body, container_port) {
            Some(new) => {
                changes.push((body.trim().to_string(), new.trim().to_string()));
                out.push_str(&new);
                out.push_str(ending);
            }
            None => out.push_str(line),
        }
    }
    (!changes.is_empty()).then_some((out, changes))
}

#[cfg_attr(not(feature = "gui"), allow(dead_code))]
fn rewrite_port_line(line: &str, container_port: &str) -> Option<String> {
    let indent_len = line.len() - line.trim_start().len();
    let rest = line.trim_start().strip_prefix("- ")?.trim_start();
    // value, optional trailing comment
    let value = match rest.find(" #") {
        Some(i) => rest[..i].trim_end(),
        None => rest.trim_end(),
    };
    let comment = &rest[value.len()..]; // keeps the spacing in front of the comment
    let quote = value.chars().next().filter(|c| *c == '"' || *c == '\'');
    let inner = match quote {
        Some(q) => value.strip_prefix(q)?.strip_suffix(q)?,
        None => value,
    };
    // HOST:CONTAINER[/proto]; the host part may be a variable such as ${PORT:-8081}.
    let (host, container) = inner.rsplit_once(':')?;
    if container.split('/').next()? != container_port || host.is_empty() || host.contains(' ') {
        return None;
    }
    let host = match host.strip_prefix("0.0.0.0:") {
        Some(h) => h,
        // Already bound to an address (127.0.0.1:…, 192.168…:…, [::1]:…): leave it alone.
        None if host.starts_with('[') || host.split(':').next().map(|p| p.parse::<std::net::Ipv4Addr>().is_ok()).unwrap_or(false) => return None,
        None => host,
    };
    Some(format!("{}- \"127.0.0.1:{host}:{container}\"{comment}", &line[..indent_len]))
}

#[cfg_attr(not(feature = "gui"), allow(dead_code))]
/// Apply `bind_local` to a compose file (a backup is kept next to it) and recreate the service.
pub fn restrict_port(compose_file: &str, container_port: &str) -> Result<String, String> {
    let text = std::fs::read_to_string(compose_file).map_err(|e| format!("{compose_file}: {e}"))?;
    let (new, changes) = bind_local(&text, container_port).ok_or("In der Compose-Datei gibt es keine passende Port-Zeile.")?;
    let backup = format!("{compose_file}.picket-sicherung");
    if !std::path::Path::new(&backup).exists() {
        std::fs::write(&backup, &text).map_err(|e| format!("{backup}: {e}"))?;
    }
    std::fs::write(compose_file, new).map_err(|e| format!("{compose_file}: {e}"))?;
    match util::run("docker", &["compose", "-f", compose_file, "up", "-d"], 600) {
        Some(o) if o.ok => Ok(format!("{} Zeile(n) geändert, Container neu gestartet.", changes.len())),
        Some(o) => Err(format!("Die Datei ist geändert, aber „docker compose up -d“ meldet: {}", o.stderr.trim().lines().last().unwrap_or(""))),
        None => Err("Die Datei ist geändert, aber „docker compose up -d“ ließ sich nicht starten.".into()),
    }
}

#[derive(Serialize, Clone, Debug, Default, PartialEq)]
pub struct ImageScan {
    pub image: String,
    pub critical: usize,
    pub high: usize,
    /// "CVE-… paket version → fix: titel" for the most severe ones.
    pub examples: Vec<String>,
}

/// Parse `trivy image --format json` output.
pub fn parse_trivy(image: &str, json: &str) -> Option<ImageScan> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let mut scan = ImageScan { image: image.to_string(), ..Default::default() };
    let mut lines: Vec<(bool, String)> = Vec::new();
    for vuln in v["Results"].as_array().into_iter().flatten().flat_map(|r| r["Vulnerabilities"].as_array().into_iter().flatten()) {
        let critical = match vuln["Severity"].as_str() {
            Some("CRITICAL") => true,
            Some("HIGH") => false,
            _ => continue,
        };
        if critical {
            scan.critical += 1;
        } else {
            scan.high += 1;
        }
        let fixed = vuln["FixedVersion"].as_str().filter(|f| !f.is_empty()).map(|f| format!(" → behoben in {f}")).unwrap_or_default();
        lines.push((
            critical,
            format!(
                "{} · {} {}{fixed} · {}",
                vuln["VulnerabilityID"].as_str().unwrap_or("?"),
                vuln["PkgName"].as_str().unwrap_or("?"),
                vuln["InstalledVersion"].as_str().unwrap_or(""),
                vuln["Title"].as_str().unwrap_or("").chars().take(90).collect::<String>()
            ),
        ));
    }
    lines.sort_by_key(|(critical, _)| !critical);
    scan.examples = lines.into_iter().take(15).map(|(_, l)| l).collect();
    Some(scan)
}

#[cfg_attr(not(feature = "gui"), allow(dead_code))]
/// Trivy in the system directories or, since it is often installed that way, from Homebrew.
/// It runs without privileges, so a copy in a user-managed directory is acceptable here.
fn trivy_path() -> Option<std::path::PathBuf> {
    util::which("trivy").or_else(|| {
        let brew = std::path::PathBuf::from("/home/linuxbrew/.linuxbrew/bin/trivy");
        brew.is_file().then_some(brew)
    })
}

pub fn trivy_available() -> bool {
    trivy_path().is_some()
}

/// Look for known vulnerabilities in a local image (Trivy; the first run downloads its database).
pub fn scan_image(image: &str) -> Result<ImageScan, String> {
    let trivy = trivy_path().ok_or("Trivy ist nicht installiert.")?;
    let out = util::run_at(&trivy, &["image", "--quiet", "--format", "json", "--scanners", "vuln", "--severity", "HIGH,CRITICAL", image], 900)
        .ok_or("Trivy hat nicht rechtzeitig geantwortet.")?;
    if !out.ok {
        return Err(format!("Trivy meldet: {}", out.stderr.trim().lines().last().unwrap_or("unbekannter Fehler")));
    }
    parse_trivy(image, &out.stdout).ok_or_else(|| "Die Ausgabe von Trivy war nicht lesbar.".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restricts_published_ports_in_compose_files() {
        let file = "services:\n  web:\n    ports:\n      - \"${PORT:-8081}:8080\"\n    restart: unless-stopped\n  api:\n    ports:\n      - 9000:9000   # debug\n      - '0.0.0.0:8443:8080/tcp'\n      - \"127.0.0.1:7000:8080\"\n    volumes:\n      - ./data:/data\n";
        let (new, changes) = bind_local(file, "8080").unwrap();
        assert_eq!(changes, [
            ("- \"${PORT:-8081}:8080\"".to_string(), "- \"127.0.0.1:${PORT:-8081}:8080\"".to_string()),
            ("- '0.0.0.0:8443:8080/tcp'".to_string(), "- \"127.0.0.1:8443:8080/tcp\"".to_string()),
        ]);
        // Everything else, including the already local binding and the volume, is untouched.
        assert!(new.contains("      - 9000:9000   # debug\n      - \"127.0.0.1:8443:8080/tcp\"\n      - \"127.0.0.1:7000:8080\"\n"));
        assert!(new.contains("      - ./data:/data\n"));
        assert_eq!(new.lines().count(), file.lines().count());
        let (new, changes) = bind_local(file, "9000").unwrap();
        assert_eq!(changes[0].1, "- \"127.0.0.1:9000:9000\"   # debug");
        assert!(new.contains("- \"127.0.0.1:9000:9000\"   # debug\n"));
        assert!(bind_local(file, "1234").is_none());
        assert!(bind_local(&bind_local(file, "8080").unwrap().0, "8080").is_none()); // idempotent
    }

    #[test]
    fn parses_trivy_reports() {
        let json = r#"{"Results":[{"Target":"img (debian 12)","Vulnerabilities":[
            {"VulnerabilityID":"CVE-2024-1","PkgName":"openssl","InstalledVersion":"3.0.1","FixedVersion":"3.0.2","Severity":"HIGH","Title":"buffer overflow"},
            {"VulnerabilityID":"CVE-2024-2","PkgName":"zlib","InstalledVersion":"1.2","Severity":"CRITICAL","Title":"heap corruption"},
            {"VulnerabilityID":"CVE-2024-3","PkgName":"curl","InstalledVersion":"8","Severity":"LOW"}]},
            {"Target":"node","Vulnerabilities":null}]}"#;
        let scan = parse_trivy("img", json).unwrap();
        assert_eq!((scan.critical, scan.high), (1, 1));
        assert_eq!(scan.examples[0], "CVE-2024-2 · zlib 1.2 · heap corruption"); // critical first
        assert_eq!(scan.examples[1], "CVE-2024-1 · openssl 3.0.1 → behoben in 3.0.2 · buffer overflow");
        assert_eq!(parse_trivy("img", r#"{"Results":[]}"#).unwrap().critical, 0);
        assert!(parse_trivy("img", "kaputt").is_none());
    }

    #[test]
    fn parses_inspect_output() {
        let json = r#"[
          {"Name":"/nodered","Config":{"Image":"nodered/node-red","User":"node-red",
             "Labels":{"com.docker.compose.project.working_dir":"/home/x/cm","com.docker.compose.project.config_files":"/home/x/cm/docker-compose.yml"}},
           "HostConfig":{"Privileged":false,"NetworkMode":"cm_default","CapAdd":null},
           "Mounts":[{"Source":"/home/x/data"}],
           "NetworkSettings":{"Ports":{"1880/tcp":[{"HostIp":"0.0.0.0","HostPort":"1890"},{"HostIp":"::","HostPort":"1890"}],"9000/tcp":null}}},
          {"Name":"/admin","Config":{"Image":"portainer","User":"","Labels":{}},
           "HostConfig":{"Privileged":true,"NetworkMode":"host","CapAdd":["NET_ADMIN"]},
           "Mounts":[{"Source":"/var/run/docker.sock"}],
           "NetworkSettings":{"Ports":{"8000/udp":[{"HostIp":"127.0.0.1","HostPort":"8000"}]}}}]"#;
        let c = parse_inspect(json);
        assert_eq!(c.len(), 2);
        let node = &c[0]; // sorted: most open ports first
        assert_eq!(node.name, "nodered");
        assert!(!node.runs_as_root() && !node.privileged && !node.docker_socket);
        assert_eq!(node.open_ports().len(), 1); // IPv4 and IPv6 binding of the same port
        assert_eq!(node.open_ports()[0].local_binding(), "\"127.0.0.1:1890:1880\"");
        assert_eq!(node.compose_file, "/home/x/cm/docker-compose.yml");
        let admin = &c[1];
        assert!(admin.privileged && admin.host_network && admin.docker_socket && admin.runs_as_root());
        assert!(admin.open_ports().is_empty());
        assert_eq!(admin.ports[0].local_binding(), "\"127.0.0.1:8000:8000/udp\"");
    }
}
