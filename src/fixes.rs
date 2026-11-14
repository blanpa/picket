//! One-click fixes for findings with an unambiguous remedy.
//!
//! A fix is identified by the finding it belongs to. The commands are fixed
//! here; nothing from outside is executed. Fixes that need root are started by
//! the window through pkexec (`picket fix <id>`).

use crate::util;
use std::os::unix::fs::PermissionsExt;

#[cfg_attr(not(feature = "gui"), allow(dead_code))]
pub struct Fix {
    pub root: bool,
    /// What will be done, for the confirmation dialog.
    pub commands: Vec<String>,
    pub note: &'static str,
}

fn fix(root: bool, commands: &[&str], note: &'static str) -> Option<Fix> {
    Some(Fix { root, commands: commands.iter().map(|c| c.to_string()).collect(), note })
}

/// The fix that belongs to a finding, if there is one.
pub fn for_finding(id: &str) -> Option<Fix> {
    match id {
        "acc.sshperm" => fix(false, &["chmod 700 ~/.ssh", "chmod -R go-w ~/.ssh", "chmod 600 <private Schlüssel>"], ""),
        "acc.home" => fix(false, &["chmod 750 ~"], ""),
        "acc.lock" => fix(
            false,
            &["gsettings set org.gnome.desktop.screensaver lock-enabled true", "gsettings set org.gnome.desktop.session idle-delay 300"],
            "Der Bildschirm sperrt danach nach 5 Minuten ohne Eingabe.",
        ),
        "sw.flatpak" => fix(false, &["flatpak update -y"], "Kann einige Minuten dauern."),
        "sw.snap" => fix(true, &["snap refresh"], "Kann einige Minuten dauern; laufende Snap-Programme werden erst nach einem Neustart des Programms aktualisiert."),
        "sw.updates" => fix(true, &["apt-get update", "apt-get -y upgrade"], "Kann einige Minuten dauern. Geänderte Konfigurationsdateien bleiben erhalten."),
        "sw.listage" => fix(true, &["apt-get update"], ""),
        "av.freshclam" | "av.signatures" => fix(true, &["systemctl enable --now clamav-freshclam", "systemctl restart clamav-freshclam"], ""),
        _ => None,
    }
}

fn run(name: &str, args: &[&str], timeout_s: u64) -> Result<(), String> {
    match util::run(name, args, timeout_s) {
        Some(o) if o.ok => Ok(()),
        Some(o) => {
            let msg = if o.stderr.trim().is_empty() { o.stdout } else { o.stderr };
            Err(format!("{name} meldet einen Fehler: {}", msg.trim().lines().last().unwrap_or("")))
        }
        None => Err(format!("{name} ist nicht verfügbar oder hat nicht rechtzeitig geantwortet.")),
    }
}

/// Tighten ~/.ssh: directory 700, nothing writable by others, private keys 600.
pub fn fix_ssh_permissions(dir: &std::path::Path) -> Result<String, String> {
    let chmod = |p: &std::path::Path, mode: u32| std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode)).map_err(|e| format!("{}: {e}", p.display()));
    let mode_of = |p: &std::path::Path| std::fs::symlink_metadata(p).map(|m| m.permissions().mode() & 0o7777).ok();
    let mut changed = 0;
    if mode_of(dir).map(|m| m & 0o077 != 0).unwrap_or(false) {
        chmod(dir, 0o700)?;
        changed += 1;
    }
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).map_err(|e| e.to_string())?.flatten() {
            let path = e.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
            if meta.file_type().is_symlink() {
                continue; // never follow links out of the directory
            }
            let mode = meta.permissions().mode() & 0o7777;
            let mut wanted = mode & !0o022;
            if meta.is_file() {
                let mut head = [0u8; 64];
                let n = std::fs::File::open(&path).and_then(|mut f| std::io::Read::read(&mut f, &mut head)).unwrap_or(0);
                let text = String::from_utf8_lossy(&head[..n]);
                if text.starts_with("-----BEGIN") && text.contains("PRIVATE KEY") {
                    wanted = 0o600;
                }
            } else if meta.is_dir() {
                stack.push(path.clone());
            }
            if wanted != mode {
                chmod(&path, wanted)?;
                changed += 1;
            }
        }
    }
    Ok(format!("{changed} Einträge korrigiert."))
}

/// Carry out the fix for a finding. Root fixes fail unless run as root.
pub fn apply(id: &str) -> Result<String, String> {
    let fix = for_finding(id).ok_or_else(|| format!("Für „{id}“ gibt es keine automatische Korrektur."))?;
    if fix.root && util::uid() != 0 {
        return Err("Diese Korrektur braucht Root-Rechte.".into());
    }
    if !fix.root && util::uid() == 0 {
        return Err("Diese Korrektur betrifft dein Benutzerkonto und darf nicht als root laufen.".into());
    }
    match id {
        "acc.sshperm" => fix_ssh_permissions(&util::home().join(".ssh")),
        "acc.home" => std::fs::set_permissions(util::home(), std::fs::Permissions::from_mode(0o750))
            .map(|_| "Rechte gesetzt.".to_string())
            .map_err(|e| e.to_string()),
        "acc.lock" => {
            run("gsettings", &["set", "org.gnome.desktop.screensaver", "lock-enabled", "true"], 10)?;
            run("gsettings", &["set", "org.gnome.desktop.session", "idle-delay", "300"], 10)?;
            Ok("Bildschirmsperre eingeschaltet.".into())
        }
        "sw.flatpak" => run("flatpak", &["update", "-y", "--noninteractive"], 1800).map(|_| "Flatpaks aktualisiert.".into()),
        "sw.snap" => run("snap", &["refresh"], 1800).map(|_| "Snaps aktualisiert.".into()),
        "sw.listage" => run("apt-get", &["update"], 600).map(|_| "Paketlisten aktualisiert.".into()),
        "sw.updates" => {
            run("apt-get", &["update"], 600)?;
            run(
                "env",
                &["DEBIAN_FRONTEND=noninteractive", "apt-get", "-y", "-o", "Dpkg::Options::=--force-confold", "upgrade"],
                3600,
            )?;
            Ok("Updates installiert.".into())
        }
        "av.freshclam" | "av.signatures" => {
            run("systemctl", &["enable", "--now", "clamav-freshclam"], 60)?;
            run("systemctl", &["restart", "clamav-freshclam"], 60)?;
            Ok("Signatur-Dienst läuft.".into())
        }
        _ => Err("Unbekannte Korrektur.".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn tightens_ssh_directory() {
        let dir = std::env::temp_dir().join(format!("picket-sshfix-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("old")).unwrap();
        let set = |name: &str, content: &str, mode: u32| {
            let p = dir.join(name);
            fs::write(&p, content).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
        };
        set("id_test", "-----BEGIN OPENSSH PRIVATE KEY-----\nxxxx\n", 0o664);
        set("id_test.pub", "ssh-ed25519 AAAA test", 0o664);
        set("config", "Host *", 0o600);
        set("old/known_hosts", "host key", 0o666);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o775)).unwrap();
        fs::set_permissions(dir.join("old"), fs::Permissions::from_mode(0o775)).unwrap();

        let msg = fix_ssh_permissions(&dir).unwrap();
        let mode = |name: &str| fs::metadata(dir.join(name)).unwrap().permissions().mode() & 0o777;
        assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(mode("id_test"), 0o600);
        assert_eq!(mode("id_test.pub"), 0o644);
        assert_eq!(mode("config"), 0o600);
        assert_eq!(mode("old"), 0o755);
        assert_eq!(mode("old/known_hosts"), 0o644);
        assert_eq!(msg, "5 Einträge korrigiert.");
        assert_eq!(fix_ssh_permissions(&dir).unwrap(), "0 Einträge korrigiert."); // idempotent
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn knows_which_findings_are_fixable() {
        assert!(for_finding("sw.updates").unwrap().root);
        assert!(!for_finding("acc.sshperm").unwrap().root);
        assert!(for_finding("sys.luks").is_none());
        assert!(apply("sys.luks").is_err());
    }
}
