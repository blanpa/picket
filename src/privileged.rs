//! Optional root snapshot.
//!
//! The dashboard runs unprivileged. A few facts are only readable as root
//! (firewall rules, process names of other users' sockets, /etc/shadow,
//! sudoers). `sudo picket root-snapshot` collects exactly those, read-only,
//! and stores them in /run so the unprivileged dashboard can merge them in.

use crate::util;
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;

pub const DEFAULT_PATH: &str = "/run/picket/privileged.json";
const MAX_AGE_S: u64 = 24 * 3600;

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct Privileged {
    pub created: u64,
    pub ufw_status: Option<String>,
    /// `ufw show added`: the user's rules in command form.
    #[serde(default)]
    pub ufw_added: Option<String>,
    pub nft_tables: Option<String>,
    pub ss_listen: String,
    pub ss_conns: String,
    pub empty_passwords: Option<Vec<String>>,
    pub sudo_nopasswd: Option<Vec<String>>,
}

/// Snapshot location. PICKET_PRIV_FILE overrides it (used for testing).
fn target() -> (PathBuf, bool) {
    match std::env::var_os("PICKET_PRIV_FILE") {
        Some(p) if !p.is_empty() => (PathBuf::from(p), true),
        _ => (PathBuf::from(DEFAULT_PATH), false),
    }
}

pub fn load() -> Option<Privileged> {
    let (path, overridden) = target();
    let meta = fs::metadata(&path).ok()?;
    // Only trust a snapshot that root wrote.
    if !overridden && meta.uid() != 0 {
        return None;
    }
    let p: Privileged = serde_json::from_str(&fs::read_to_string(&path).ok()?).ok()?;
    if util::now().saturating_sub(p.created) > MAX_AGE_S {
        return None;
    }
    Some(p)
}

fn stdout_if_ok(name: &str, args: &[&str]) -> Option<String> {
    util::run(name, args, 10)
        .filter(|o| o.ok)
        .map(|o| o.stdout.trim().to_string())
}

pub fn collect() -> Privileged {
    let empty_passwords = fs::read_to_string("/etc/shadow").ok().map(|s| {
        s.lines()
            .filter_map(|l| {
                let mut f = l.split(':');
                let name = f.next()?;
                let hash = f.next()?;
                hash.is_empty().then(|| name.to_string())
            })
            .collect()
    });

    let sudo_nopasswd = fs::read_to_string("/etc/sudoers").ok().map(|main| {
        let mut files = vec![("/etc/sudoers".to_string(), main)];
        if let Ok(rd) = fs::read_dir("/etc/sudoers.d") {
            for e in rd.flatten() {
                if let Ok(c) = fs::read_to_string(e.path()) {
                    files.push((e.path().display().to_string(), c));
                }
            }
        }
        let mut hits = Vec::new();
        for (name, content) in files {
            for l in content.lines() {
                let l = l.trim();
                if !l.starts_with('#') && l.contains("NOPASSWD") {
                    hits.push(format!("{name}: {l}"));
                }
            }
        }
        hits
    });

    Privileged {
        created: util::now(),
        ufw_status: stdout_if_ok("ufw", &["status", "verbose"]),
        ufw_added: stdout_if_ok("ufw", &["show", "added"]),
        nft_tables: stdout_if_ok("nft", &["list", "tables"]),
        ss_listen: stdout_if_ok("ss", &["-H", "-tulnp"]).unwrap_or_default(),
        ss_conns: stdout_if_ok("ss", &["-H", "-tunp"]).unwrap_or_default(),
        empty_passwords,
        sudo_nopasswd,
    }
}

/// Primary group of the user who elevated to root (sudo sets SUDO_GID, pkexec only PKEXEC_UID).
fn caller_gid() -> Option<u32> {
    if let Some(gid) = std::env::var("SUDO_GID").ok().and_then(|g| g.parse().ok()) {
        return Some(gid);
    }
    let uid = std::env::var("PKEXEC_UID").ok()?;
    fs::read_to_string("/etc/passwd").ok()?.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() > 3 && f[2] == uid).then(|| f[3].parse().ok()).flatten()
    })
}

pub fn write(p: &Privileged) -> Result<PathBuf, String> {
    let (path, overridden) = target();
    let dir = path.parent().ok_or("ungültiger Pfad")?;
    fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    if !overridden {
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o755));
    }
    let json = serde_json::to_string_pretty(p).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, json).map_err(|e| format!("{}: {e}", tmp.display()))?;

    // Readable by root and by the group of the user who called sudo/pkexec, not by everyone.
    let mode = match (overridden, caller_gid()) {
        (true, _) => 0o600,
        (false, Some(gid)) => {
            std::os::unix::fs::chown(&tmp, Some(0), Some(gid)).map_err(|e| e.to_string())?;
            0o640
        }
        (false, None) => 0o600,
    };
    fs::set_permissions(&tmp, fs::Permissions::from_mode(mode)).map_err(|e| e.to_string())?;
    fs::rename(&tmp, &path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(path)
}
