//! Known vulnerabilities of programs installed outside the system package
//! manager (cargo, pip, npm), looked up at osv.dev. Only runs on request: the
//! names and versions of those packages are sent to the service.

use crate::util;
use serde::Serialize;

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Package {
    /// OSV ecosystem: "crates.io", "PyPI" or "npm".
    pub ecosystem: String,
    pub name: String,
    pub version: String,
}

impl Package {
    pub fn new(ecosystem: &str, name: &str, version: &str) -> Package {
        Package { ecosystem: ecosystem.into(), name: name.into(), version: version.into() }
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct Vulnerability {
    pub package: String,
    pub version: String,
    pub id: String,
    pub summary: String,
}

/// Parse cargo's install registry: keys look like "ripgrep 14.1.0 (registry+https://...)".
pub fn parse_crates2(json: &str) -> Vec<Package> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let mut out: Vec<Package> = v["installs"]
        .as_object()
        .into_iter()
        .flat_map(|m| m.keys())
        .filter_map(|k| {
            let mut it = k.split_whitespace();
            let (name, version, source) = (it.next()?, it.next()?, it.next()?);
            // Local paths and git checkouts are not on crates.io.
            source.starts_with("(registry+").then(|| Package::new("crates.io", name, version))
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// "requests-2.31.0.dist-info" -> ("requests", "2.31.0")
pub fn parse_dist_info(dir_name: &str) -> Option<(String, String)> {
    let stem = dir_name.strip_suffix(".dist-info")?;
    let (name, version) = stem.rsplit_once('-')?;
    (!name.is_empty() && version.starts_with(|c: char| c.is_ascii_digit())).then(|| (name.replace('_', "-"), version.to_string()))
}

fn pip_packages(out: &mut Vec<Package>) {
    let lib = util::home().join(".local/lib");
    for py in std::fs::read_dir(lib).into_iter().flatten().flatten() {
        for e in std::fs::read_dir(py.path().join("site-packages")).into_iter().flatten().flatten() {
            if let Some((name, version)) = e.file_name().to_str().and_then(parse_dist_info) {
                out.push(Package::new("PyPI", &name, &version));
            }
        }
    }
}

fn npm_packages(out: &mut Vec<Package>) {
    let home = util::home();
    let roots = [
        home.join(".npm-global/lib/node_modules"),
        home.join(".local/lib/node_modules"),
        "/usr/local/lib/node_modules".into(),
        "/usr/lib/node_modules".into(),
        "/home/linuxbrew/.linuxbrew/lib/node_modules".into(),
    ];
    let read = |dir: &std::path::Path, out: &mut Vec<Package>| {
        let Ok(text) = std::fs::read_to_string(dir.join("package.json")) else { return };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else { return };
        if let (Some(name), Some(version)) = (v["name"].as_str(), v["version"].as_str()) {
            out.push(Package::new("npm", name, version));
        }
    };
    for root in roots {
        for e in std::fs::read_dir(&root).into_iter().flatten().flatten() {
            let path = e.path();
            if e.file_name().to_string_lossy().starts_with('@') {
                for scoped in std::fs::read_dir(&path).into_iter().flatten().flatten() {
                    read(&scoped.path(), out);
                }
            } else {
                read(&path, out);
            }
        }
    }
}

/// Programs installed for this user outside apt: cargo (crates.io), pip --user, global npm.
pub fn inventory() -> Vec<Package> {
    let mut out = std::fs::read_to_string(util::home().join(".cargo/.crates2.json"))
        .map(|s| parse_crates2(&s))
        .unwrap_or_default();
    pip_packages(&mut out);
    npm_packages(&mut out);
    out.sort_by(|a, b| (&a.ecosystem, &a.name).cmp(&(&b.ecosystem, &b.name)));
    out.dedup();
    out.truncate(900); // osv.dev accepts 1000 queries per request
    out
}

fn curl_json(args: &[&str]) -> Result<serde_json::Value, String> {
    let out = util::run("curl", args, 40).ok_or("curl ist nicht installiert oder antwortet nicht.")?;
    if !out.ok {
        return Err(format!("osv.dev ist nicht erreichbar: {}", out.stderr.trim()));
    }
    serde_json::from_str(&out.stdout).map_err(|_| "Unerwartete Antwort von osv.dev.".to_string())
}

/// Ask osv.dev about the given packages.
pub fn query(packages: &[Package]) -> Result<Vec<Vulnerability>, String> {
    if packages.is_empty() {
        return Ok(Vec::new());
    }
    let body = serde_json::json!({
        "queries": packages.iter().map(|p| serde_json::json!({
            "package": { "name": p.name, "ecosystem": p.ecosystem },
            "version": p.version,
        })).collect::<Vec<_>>()
    })
    .to_string();
    let v = curl_json(&[
        "-fsS", "--max-time", "30", "-H", "Content-Type: application/json", "--data-binary", &body,
        "https://api.osv.dev/v1/querybatch",
    ])?;
    let mut out = Vec::new();
    for (p, r) in packages.iter().zip(v["results"].as_array().into_iter().flatten()) {
        for vuln in r["vulns"].as_array().into_iter().flatten() {
            let Some(id) = vuln["id"].as_str() else { continue };
            // Only identifiers made of the usual characters go into the URL below.
            if !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                continue;
            }
            out.push(Vulnerability { package: p.name.clone(), version: p.version.clone(), id: id.to_string(), summary: String::new() });
        }
    }
    // The batch answer only carries identifiers; fetch a description for the first few.
    for v in out.iter_mut().take(25) {
        if let Ok(d) = curl_json(&["-fsS", "--max-time", "20", &format!("https://api.osv.dev/v1/vulns/{}", v.id)]) {
            v.summary = d["summary"].as_str().or_else(|| d["details"].as_str()).unwrap_or("").lines().next().unwrap_or("").chars().take(160).collect();
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_cargo_installs() {
        let json = r#"{"installs":{
            "ripgrep 14.1.0 (registry+https://github.com/rust-lang/crates.io-index)":{"bins":["rg"]},
            "picket 0.1.0 (path+file:///home/x/picket)":{"bins":["picket"]},
            "bat 0.24.0 (registry+https://github.com/rust-lang/crates.io-index)":{}}}"#;
        let p = parse_crates2(json);
        assert_eq!(p.len(), 2); // the local path install is not sent anywhere
        assert_eq!((p[0].name.as_str(), p[0].version.as_str()), ("bat", "0.24.0"));
        assert!(parse_crates2("not json").is_empty());
        assert_eq!(p[0].ecosystem, "crates.io");
        assert_eq!(parse_dist_info("typing_extensions-4.12.2.dist-info"), Some(("typing-extensions".into(), "4.12.2".into())));
        assert_eq!(parse_dist_info("requests-2.31.0.dist-info"), Some(("requests".into(), "2.31.0".into())));
        assert_eq!(parse_dist_info("README.txt"), None);
    }
}
