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

#[cfg(test)]
mod tests {
    use super::*;

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
