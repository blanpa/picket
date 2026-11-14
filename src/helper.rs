//! The root helper.
//!
//! Root actions (firewall, capture, system data, root fixes) are not run from
//! the binary in the user's home directory: any program under the user's
//! account could replace that file and wait for the next password prompt.
//! Instead a copy is installed once to a root-owned location, and a polkit
//! rule names exactly that file. The window only ever asks polkit to start
//! this copy.

use crate::util;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

pub const PATH: &str = "/usr/local/libexec/picket-helper";
pub const POLICY: &str = "/usr/share/polkit-1/actions/io.github.blanpa.Picket.policy";
/// Raised whenever the helper's commands change, so the window notices an outdated copy.
pub const PROTOCOL: u32 = 2;

/// What the helper copy may be asked to do.
/// Files installed under the program's former name; removed when the helper is (re)installed.
const LEGACY: [&str; 2] = ["/usr/local/libexec/fw-security-helper", "/usr/share/polkit-1/actions/io.fwsecurity.App.policy"];

pub const COMMANDS: [&str; 5] = ["protocol", "root-snapshot", "fw-apply", "capture", "fix"];

fn policy() -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1.0/policyconfig.dtd">
<policyconfig>
  <vendor>Picket</vendor>
  <action id="io.github.blanpa.Picket.helper">
    <description>Picket: Firewall, Mitschnitt und Systemdaten</description>
    <message>Picket braucht Administratorrechte für Firewall, Mitschnitt oder Systemdaten</message>
    <icon_name>io.github.blanpa.Picket</icon_name>
    <defaults>
      <allow_any>auth_admin</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>auth_admin_keep</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.exec.path">{PATH}</annotate>
  </action>
</policyconfig>
"#
    )
}

/// Is this process the installed helper copy?
pub fn is_helper() -> bool {
    std::env::current_exe().map(|p| p == Path::new(PATH)).unwrap_or(false)
}

/// Check that the helper is installed, root-owned, not replaceable, and current.
pub fn ready() -> Result<(), String> {
    let meta = std::fs::metadata(PATH).map_err(|_| "Der Helfer ist noch nicht eingerichtet.".to_string())?;
    if meta.uid() != 0 || meta.permissions().mode() & 0o022 != 0 {
        return Err("Der Helfer gehört nicht root oder ist für andere schreibbar.".into());
    }
    if !Path::new(POLICY).exists() {
        return Err("Die polkit-Regel fehlt.".into());
    }
    let out = std::process::Command::new(PATH)
        .arg("protocol")
        .output()
        .map_err(|e| format!("Der Helfer lässt sich nicht starten: {e}"))?;
    match String::from_utf8_lossy(&out.stdout).trim().parse::<u32>() {
        Ok(p) if p == PROTOCOL => Ok(()),
        _ => Err("Der Helfer stammt von einer älteren Version.".into()),
    }
}

/// Install this binary as the helper (run as root, once and after updates that change the helper).
pub fn install() -> Result<(), String> {
    if util::uid() != 0 {
        return Err(format!("Die Einrichtung braucht Root-Rechte:\n  sudo {} install-helper", util::self_exe()));
    }
    let dst = Path::new(PATH);
    let dir = dst.parent().ok_or("ungültiger Pfad")?;
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    // The directory itself must not be writable by anyone but root either.
    let dmeta = std::fs::metadata(dir).map_err(|e| e.to_string())?;
    if dmeta.uid() != 0 || dmeta.permissions().mode() & 0o022 != 0 {
        return Err(format!("{} ist nicht nur für root schreibbar – der Helfer wäre dort austauschbar.", dir.display()));
    }
    let src = std::env::current_exe().map_err(|e| e.to_string())?;
    let tmp = dst.with_extension("tmp");
    std::fs::copy(&src, &tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::os::unix::fs::chown(&tmp, Some(0), Some(0)).map_err(|e| e.to_string())?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, dst).map_err(|e| format!("{PATH}: {e}"))?;
    std::fs::write(POLICY, policy()).map_err(|e| format!("{POLICY}: {e}"))?;
    std::fs::set_permissions(POLICY, std::fs::Permissions::from_mode(0o644)).map_err(|e| e.to_string())?;
    for old in LEGACY {
        let _ = std::fs::remove_file(old);
    }
    Ok(())
}

pub fn remove() -> Result<(), String> {
    if util::uid() != 0 {
        return Err(format!("Das Entfernen braucht Root-Rechte:\n  sudo {} remove-helper", util::self_exe()));
    }
    for p in [PATH, POLICY].into_iter().chain(LEGACY) {
        if Path::new(p).exists() {
            std::fs::remove_file(p).map_err(|e| format!("{p}: {e}"))?;
        }
    }
    Ok(())
}
