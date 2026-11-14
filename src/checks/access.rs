use super::Ctx;
use crate::model::{Category, Finding, Status};
use crate::util;
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

const CAT: Category = Category::Access;

fn b64_decode(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => continue,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

/// Some(true) = private key protected by a passphrase, Some(false) = unprotected,
/// None = not a private key. Only the header of the file is inspected.
pub fn key_is_encrypted(head: &str) -> Option<bool> {
    let first = head.lines().next()?;
    if !first.starts_with("-----BEGIN") || !first.contains("PRIVATE KEY") {
        return None;
    }
    if first.contains("OPENSSH PRIVATE KEY") {
        let body: String = head.lines().skip(1).take(3).collect();
        let raw = b64_decode(&body);
        // "openssh-key-v1\0", then a length-prefixed cipher name ("none" = no passphrase)
        let magic = b"openssh-key-v1\0";
        if raw.len() < magic.len() + 8 || &raw[..magic.len()] != magic {
            return None;
        }
        let p = magic.len();
        let len = u32::from_be_bytes([raw[p], raw[p + 1], raw[p + 2], raw[p + 3]]) as usize;
        let cipher = raw.get(p + 4..p + 4 + len)?;
        return Some(cipher != b"none");
    }
    Some(first.contains("ENCRYPTED") || head.contains("Proc-Type: 4,ENCRYPTED"))
}

fn mode(path: &Path) -> Option<u32> {
    fs::metadata(path).ok().map(|m| m.permissions().mode() & 0o777)
}

fn accounts(ctx: &Ctx, out: &mut Vec<Finding>) {
    let passwd = util::read("/etc/passwd").unwrap_or_default();
    let mut uid0 = Vec::new();
    let mut humans = Vec::new();
    for l in passwd.lines() {
        let f: Vec<&str> = l.split(':').collect();
        if f.len() < 7 {
            continue;
        }
        let uid: u32 = f[2].parse().unwrap_or(u32::MAX);
        if uid == 0 && f[0] != "root" {
            uid0.push(f[0].to_string());
        }
        if (1000..65000).contains(&uid) && !f[6].ends_with("nologin") && !f[6].ends_with("false") {
            humans.push(f[0].to_string());
        }
    }
    let f = Finding::new("acc.users", CAT, "Benutzerkonten")
        .why("Unbekannte Konten oder weitere Konten mit Root-Rechten (UID 0) sind ein typisches Zeichen für eine Kompromittierung.");
    out.push(if uid0.is_empty() {
        f.set(
            Status::Ok,
            format!("{}: {}. Nur root hat UID 0.", util::plural(humans.len(), "Anmeldekonto", "Anmeldekonten"), humans.join(", ")),
        )
    } else {
        f.set(Status::Crit, format!("Weitere Konten mit Root-Rechten (UID 0): {}", uid0.join(", ")))
            .fix("Prüfen, woher diese Konten stammen, und sie entfernen, wenn sie nicht bewusst angelegt wurden.", &[])
    });

    // Admin-equivalent groups
    let group = util::read("/etc/group").unwrap_or_default();
    let members = |name: &str| -> Vec<String> {
        group
            .lines()
            .find(|l| l.starts_with(&format!("{name}:")))
            .and_then(|l| l.split(':').nth(3))
            .map(|m| m.split(',').filter(|x| !x.is_empty()).map(String::from).collect())
            .unwrap_or_default()
    };
    let sudo = members("sudo");
    let docker = members("docker");
    let mut f = Finding::new("acc.admins", CAT, "Administratorrechte")
        .detail(format!("Gruppe sudo: {}", if sudo.is_empty() { "–".into() } else { sudo.join(", ") }))
        .why("Wer in diesen Gruppen ist, kann das gesamte System verändern.");
    if !docker.is_empty() {
        f = f.detail(format!("Gruppe docker: {}", docker.join(", ")));
    }
    out.push(if docker.is_empty() {
        f.set(Status::Ok, format!("{} mit sudo-Rechten.", util::plural(sudo.len(), "Konto", "Konten")))
    } else {
        f.set(
            Status::Info,
            format!(
                "{} mit sudo-Rechten; Mitglieder der Gruppe „docker“ ({}) haben faktisch Root-Rechte ohne Passwortabfrage.",
                util::plural(sudo.len(), "Konto", "Konten"),
                docker.join(", ")
            ),
        )
        .fix(
            "Das ist bei Docker so vorgesehen. Wer es strenger will, nutzt Docker im Rootless-Modus oder entfernt das Konto aus der Gruppe.",
            &[],
        )
    });

    // Root-only facts
    if let Some(p) = &ctx.privd {
        if let Some(empty) = &p.empty_passwords {
            let f = Finding::new("acc.emptypw", CAT, "Konten ohne Passwort");
            out.push(if empty.is_empty() {
                f.set(Status::Ok, "Kein Konto hat ein leeres Passwort.")
            } else {
                f.set(Status::Crit, format!("Konten mit leerem Passwort: {}", empty.join(", ")))
                    .why("Ein Konto ohne Passwort kann von jedem benutzt werden, der an den Laptop kommt.")
                    .fix("Passwort setzen oder Konto sperren.", &["sudo passwd <konto>", "sudo passwd -l <konto>"])
            });
        }
        if let Some(np) = &p.sudo_nopasswd {
            let f = Finding::new("acc.nopasswd", CAT, "sudo ohne Passwort");
            out.push(if np.is_empty() {
                f.set(Status::Ok, "sudo verlangt immer ein Passwort.")
            } else {
                f.set(Status::Warn, format!("{} erlauben Root-Befehle ohne Passwort.", util::plural(np.len(), "sudo-Regel", "sudo-Regeln")))
                    .details(np.iter().cloned())
                    .why("Mit NOPASSWD genügt es, dass ein beliebiges Programm unter deinem Konto läuft, um Root zu werden.")
                    .fix("Regeln prüfen und auf einzelne Befehle beschränken.", &["sudo visudo"])
            });
        }
    }
}

fn ssh_server(out: &mut Vec<Finding>) {
    let f = Finding::new("acc.sshd", CAT, "SSH-Server (Fernzugriff)")
        .why("Ein SSH-Server erlaubt die Anmeldung aus dem Netz. Mit Passwort-Anmeldung ist er ein beliebtes Ziel für Rateangriffe.");
    if util::which("sshd").is_none() {
        out.push(f.set(Status::Ok, "Kein SSH-Server installiert – keine Anmeldung aus dem Netz möglich."));
        return;
    }
    let active = util::service_active("ssh") || util::service_active("sshd") || util::service_active("ssh.socket");
    let mut cfg = String::new();
    if let Ok(rd) = fs::read_dir("/etc/ssh/sshd_config.d") {
        let mut files: Vec<_> = rd.flatten().map(|e| e.path()).collect();
        files.sort();
        for p in files {
            cfg.push_str(&fs::read_to_string(p).unwrap_or_default());
            cfg.push('\n');
        }
    }
    cfg.push_str(&fs::read_to_string("/etc/ssh/sshd_config").unwrap_or_default());
    // sshd uses the first value it sees.
    let get = |key: &str| -> Option<String> {
        cfg.lines().find_map(|l| {
            let mut it = l.split_whitespace();
            let k = it.next()?;
            k.eq_ignore_ascii_case(key).then(|| it.next().unwrap_or("").to_ascii_lowercase())
        })
    };
    let password = get("PasswordAuthentication").unwrap_or_else(|| "yes".into());
    let root = get("PermitRootLogin").unwrap_or_else(|| "prohibit-password".into());
    let f = f
        .detail(format!("PasswordAuthentication {password}"))
        .detail(format!("PermitRootLogin {root}"));
    out.push(if !active {
        f.set(Status::Ok, "Ein SSH-Server ist installiert, läuft aber nicht.")
    } else if root == "yes" {
        f.set(Status::Crit, "Der SSH-Server läuft und erlaubt die Root-Anmeldung mit Passwort.")
            .fix("In /etc/ssh/sshd_config „PermitRootLogin no“ setzen.", &["sudo systemctl restart ssh"])
    } else if password == "yes" {
        f.set(Status::Warn, "Der SSH-Server läuft und erlaubt die Anmeldung mit Passwort.")
            .fix(
                "Auf Schlüssel-Anmeldung umstellen: „PasswordAuthentication no“ in /etc/ssh/sshd_config.",
                &["sudo systemctl restart ssh"],
            )
    } else {
        f.set(Status::Info, "Der SSH-Server läuft, Anmeldung nur mit Schlüssel.")
    });
}

fn ssh_keys(ctx: &Ctx, out: &mut Vec<Finding>) {
    let dir = ctx.home.join(".ssh");
    let Ok(rd) = fs::read_dir(&dir) else {
        return;
    };
    let mut loose = Vec::new();
    let mut fixes: Vec<String> = Vec::new();
    let quote = |name: &str| format!("~/.ssh/'{}'", name.replace('\'', "'\\''"));
    let mut unprotected = Vec::new();
    let mut keys = 0;
    if let Some(m) = mode(&dir) {
        if m & 0o077 != 0 {
            loose.push(format!("~/.ssh hat die Rechte {m:o} (sollte 700 sein)"));
            fixes.push("chmod 700 ~/.ssh".into());
        }
    }
    let mut entries: Vec<_> = rd.flatten().collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let path = e.path();
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(m) = mode(&path) else {
            continue;
        };
        if m & 0o022 != 0 {
            loose.push(format!("~/.ssh/{name} ist für Gruppe/andere schreibbar ({m:o})"));
            if !fixes.iter().any(|c| c.starts_with("chmod -R go-w")) {
                fixes.push("chmod -R go-w ~/.ssh".into());
            }
        }
        if !path.is_file() {
            continue;
        }
        let mut head = vec![0u8; 400];
        let n = fs::File::open(&path).and_then(|mut f| f.read(&mut head)).unwrap_or(0);
        let head = String::from_utf8_lossy(&head[..n]);
        if let Some(encrypted) = key_is_encrypted(&head) {
            keys += 1;
            if m & 0o077 != 0 {
                loose.push(format!("Privater Schlüssel ~/.ssh/{name} ist für andere lesbar ({m:o})"));
                fixes.push(format!("chmod 600 {}", quote(&name)));
            }
            if !encrypted {
                unprotected.push(format!("~/.ssh/{name} – ohne Passphrase"));
            }
        }
    }

    let f = Finding::new("acc.sshperm", CAT, "Dateirechte in ~/.ssh")
        .why("Sind Schlüssel oder Konfiguration für andere Konten les- oder schreibbar, können sie kopiert oder manipuliert werden.");
    out.push(if loose.is_empty() {
        f.set(Status::Ok, "Die Dateirechte in ~/.ssh sind in Ordnung.")
    } else {
        f.set(Status::Warn, format!("{} mit zu offenen Rechten.", util::plural(loose.len(), "Eintrag", "Einträge")))
            .details(loose)
            .fix_cmds("Rechte einschränken.", fixes)
    });

    if keys > 0 {
        let f = Finding::new("acc.sshkeys", CAT, "SSH-Schlüssel").why(
            "Ein privater Schlüssel ohne Passphrase kann von jedem Programm unter deinem Konto kopiert und sofort benutzt werden. \
             Die Festplattenverschlüsselung schützt nur bei ausgeschaltetem Laptop.",
        );
        out.push(if unprotected.is_empty() {
            f.set(Status::Ok, format!("Alle {keys} privaten Schlüssel sind mit einer Passphrase geschützt."))
        } else {
            f.set(
                Status::Info,
                format!("{} von {keys} privaten Schlüsseln haben keine Passphrase.", unprotected.len()),
            )
            .details(unprotected)
            .fix(
                "Passphrase nachträglich setzen; der ssh-agent merkt sie sich für die Sitzung.",
                &["ssh-keygen -p -f ~/.ssh/<schlüssel>"],
            )
        });
    }
}

fn desktop(ctx: &Ctx, out: &mut Vec<Finding>) {
    // Home directory permissions
    if let Some(m) = mode(&ctx.home) {
        let f = Finding::new("acc.home", CAT, "Rechte des persönlichen Ordners");
        out.push(if m & 0o007 != 0 {
            f.set(Status::Warn, format!("Der persönliche Ordner ist für alle Konten lesbar (Rechte {m:o})."))
                .why("Andere Konten und Systemdienste können dann deine Dateien lesen.")
                .fix("Zugriff auf dich beschränken.", &["chmod 750 ~"])
        } else {
            f.set(Status::Ok, format!("Der persönliche Ordner ist für andere Konten gesperrt (Rechte {m:o})."))
        });
    }

    // Automatic login
    let gdm = util::read("/etc/gdm3/custom.conf").unwrap_or_default();
    let autologin = gdm.lines().any(|l| {
        let l = l.trim().replace(' ', "").to_ascii_lowercase();
        l == "automaticloginenable=true"
    });
    let f = Finding::new("acc.autologin", CAT, "Automatische Anmeldung");
    out.push(if autologin {
        f.set(Status::Warn, "Beim Start wird automatisch ohne Passwort angemeldet.")
            .why("Wer den Laptop einschaltet, ist sofort in deinem Konto.")
            .fix("In den Einstellungen unter „System → Benutzer“ die automatische Anmeldung abschalten.", &[])
    } else {
        f.set(Status::Ok, "Die Anmeldung verlangt ein Passwort.")
    });

    // Screen lock (GNOME)
    let gs = |schema: &str, key: &str| -> Option<String> {
        util::run("gsettings", &["get", schema, key], 5)
            .filter(|o| o.ok)
            .map(|o| o.stdout.trim().to_string())
    };
    let num = |s: Option<String>| s.and_then(|v| v.split_whitespace().last().and_then(|n| n.parse::<u64>().ok()));
    if let Some(lock) = gs("org.gnome.desktop.screensaver", "lock-enabled") {
        let idle = num(gs("org.gnome.desktop.session", "idle-delay"));
        let delay = num(gs("org.gnome.desktop.screensaver", "lock-delay")).unwrap_or(0);
        let f = Finding::new("acc.lock", CAT, "Bildschirmsperre")
            .why("Ein unbeaufsichtigter, entsperrter Laptop gibt jedem Zugriff auf alles – die Verschlüsselung hilft dann nicht.");
        out.push(match (lock.as_str(), idle) {
            ("false", _) => f
                .set(Status::Warn, "Die automatische Bildschirmsperre ist ausgeschaltet.")
                .fix("Sperre einschalten.", &["gsettings set org.gnome.desktop.screensaver lock-enabled true"]),
            (_, Some(0)) => f
                .set(Status::Warn, "Der Bildschirm schaltet sich nie automatisch ab und sperrt daher nie.")
                .fix("Abschaltzeit setzen (hier 5 Minuten).", &["gsettings set org.gnome.desktop.session idle-delay 300"]),
            (_, Some(i)) if i + delay > 900 => f.set(
                Status::Info,
                format!("Der Bildschirm sperrt erst nach {} Minuten Inaktivität.", (i + delay) / 60),
            ),
            (_, Some(i)) => f.set(
                Status::Ok,
                format!("Der Bildschirm sperrt nach {} Minuten Inaktivität.", ((i + delay) as f64 / 60.0).ceil()),
            ),
            (_, None) => f.set(Status::Ok, "Die Bildschirmsperre ist eingeschaltet."),
        });
    }
}

pub fn check(ctx: &Ctx) -> Vec<Finding> {
    let mut out = Vec::new();
    accounts(ctx, &mut out);
    ssh_server(&mut out);
    ssh_keys(ctx, &mut out);
    desktop(ctx, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_key_passphrase() {
        // Headers only; the key material is not real.
        let plain = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n";
        let enc = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABD\n";
        assert_eq!(key_is_encrypted(plain), Some(false));
        assert_eq!(key_is_encrypted(enc), Some(true));
        assert_eq!(key_is_encrypted("-----BEGIN RSA PRIVATE KEY-----\nMIIE"), Some(false));
        assert_eq!(
            key_is_encrypted("-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n"),
            Some(true)
        );
        assert_eq!(key_is_encrypted("-----BEGIN ENCRYPTED PRIVATE KEY-----\n"), Some(true));
        assert_eq!(key_is_encrypted("ssh-ed25519 AAAA user@host"), None);
    }
}
