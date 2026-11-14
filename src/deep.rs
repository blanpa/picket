//! Deep check: slower inspections that are run on request.
//!
//! Secrets lying around in the home directory, programs that start by
//! themselves, set-uid files nobody packaged, modified system files, and a
//! Lynis audit. Everything is read-only.

use crate::model::{Category, Finding, Status};
use crate::util;
use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const CAT: Category = Category::System;

// ---------------------------------------------------------------- secrets

/// (prefix, minimum number of token characters after it, description)
const TOKENS: [(&str, usize, &str); 12] = [
    ("AKIA", 16, "AWS-Zugangsschlüssel"),
    ("ghp_", 30, "GitHub-Token"),
    ("gho_", 30, "GitHub-Token"),
    ("github_pat_", 30, "GitHub-Token"),
    ("glpat-", 18, "GitLab-Token"),
    ("sk-ant-", 30, "Anthropic-API-Schlüssel"),
    ("sk-proj-", 30, "OpenAI-API-Schlüssel"),
    ("xoxb-", 20, "Slack-Token"),
    ("xoxp-", 20, "Slack-Token"),
    ("AIza", 35, "Google-API-Schlüssel"),
    ("hf_", 30, "Hugging-Face-Token"),
    ("npm_", 30, "npm-Token"),
];

/// Kinds of secrets that appear in a text. The secrets themselves are never returned.
pub fn find_secrets(text: &str) -> BTreeSet<&'static str> {
    let mut found = BTreeSet::new();
    if text.contains("-----BEGIN") && text.contains("PRIVATE KEY-----") {
        found.insert("privater Schlüssel");
    }
    for (prefix, min, kind) in TOKENS {
        let mut rest = text;
        while let Some(i) = rest.find(prefix) {
            // A token starts at a word boundary and continues with token characters.
            let boundary = rest[..i].chars().next_back().map(|c| !c.is_ascii_alphanumeric() && c != '_').unwrap_or(true);
            let tail = &rest[i + prefix.len()..];
            let len = tail.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-').count();
            if boundary && len >= min {
                found.insert(kind);
                break;
            }
            rest = tail;
        }
    }
    // KEY=value lines whose name says it is a secret.
    for line in text.lines() {
        let line = line.trim().trim_start_matches("export ");
        let Some((key, value)) = line.split_once('=') else { continue };
        let key = key.trim().to_ascii_uppercase();
        let value = value.trim().trim_matches(|c| c == '"' || c == '\'');
        let named = ["PASSWORD", "PASSWD", "SECRET", "TOKEN", "API_KEY", "APIKEY", "PRIVATE_KEY"].iter().any(|k| key.contains(k));
        let placeholder = value.is_empty()
            || value.starts_with('$')
            || value.starts_with('<')
            || ["changeme", "xxx", "your", "example", "todo", "none", "null", "false", "true"].iter().any(|p| value.to_ascii_lowercase().starts_with(p));
        if named && !key.contains(' ') && key.len() < 60 && value.len() >= 6 && !placeholder {
            found.insert("Passwort oder Token im Klartext");
        }
    }
    // Credentials inside a URL: https://user:secret@host
    if text.split("://").skip(1).any(|after| {
        let authority = after.split(['/', ' ', '\n', '"', '\'']).next().unwrap_or("");
        authority.split_once('@').map(|(cred, _)| cred.contains(':') && cred.len() > 6).unwrap_or(false)
    }) {
        found.insert("Zugangsdaten in einer URL");
    }
    found
}

const SKIP_DIRS: [&str; 25] = [
    "fixtures", "testdata", ".oh-my-zsh",
    ".cache", "node_modules", "target", ".rustup", ".cargo", ".npm", ".nvm", "snap", ".var", ".local", ".mozilla", ".thunderbird",
    ".steam", ".wine", "venv", ".venv", "__pycache__", ".gradle", ".m2", "go", "Trash", ".vscode",
];

fn is_candidate(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    // Templates only hold placeholders.
    if ["example", "sample", "template", ".dist"].iter().any(|w| lower.contains(w)) {
        return false;
    }
    lower.starts_with(".env")
        || lower.ends_with(".env")
        || [".pem", ".key", ".tfvars", ".netrc", ".npmrc", ".pypirc"].iter().any(|e| lower.ends_with(e))
        || ["credentials", ".git-credentials", ".bash_history", ".zsh_history", "secrets.yml", "secrets.yaml", "secrets.json", "config.json", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"].contains(&lower.as_str())
}

fn scan_secrets(home: &Path) -> Finding {
    let f = Finding::new("deep.secrets", CAT, "Zugangsdaten im persönlichen Ordner").why(
        "API-Schlüssel und Passwörter in Klartextdateien kann jedes Programm lesen, das unter deinem Konto läuft – ein einziger bösartiger Download genügt.",
    );
    let mut hits: Vec<String> = Vec::new();
    let mut visited = 0usize;
    let mut stack: Vec<(PathBuf, u32)> = vec![(home.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            visited += 1;
            if visited > 400_000 || hits.len() >= 200 {
                break;
            }
            let path = e.path();
            let name = e.file_name().to_string_lossy().into_owned();
            let Ok(meta) = std::fs::symlink_metadata(&path) else { continue };
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                // ~/.ssh is covered by its own check; .git only holds history.
                if depth < 7 && !SKIP_DIRS.contains(&name.as_str()) && name != ".ssh" && name != ".git" {
                    stack.push((path, depth + 1));
                }
                continue;
            }
            // config.json is only interesting where Docker keeps registry logins.
            if !meta.is_file() || meta.len() > 512 * 1024 || !is_candidate(&name) || (name == "config.json" && !dir.ends_with(".docker")) {
                continue;
            }
            let Ok(bytes) = std::fs::read(&path) else { continue };
            let text = String::from_utf8_lossy(&bytes);
            let mut kinds = find_secrets(&text);
            if name == "config.json" && text.contains("\"auth\"") && !text.contains("credsStore") {
                kinds.insert("Docker-Registry-Login");
            }
            if kinds.is_empty() {
                continue;
            }
            let shown = path.strip_prefix(home).map(|p| format!("~/{}", p.display())).unwrap_or_else(|_| path.display().to_string());
            let others = if meta.permissions().mode() & 0o044 != 0 { " – für andere Konten lesbar" } else { "" };
            hits.push(format!("{shown}: {}{others}", kinds.into_iter().collect::<Vec<_>>().join(", ")));
        }
    }
    hits.sort();
    if hits.is_empty() {
        f.set(Status::Ok, "Keine Zugangsdaten in den üblichen Klartextdateien gefunden.")
    } else {
        f.set(Status::Warn, format!("{} mit Zugangsdaten im Klartext.", util::plural(hits.len(), "Datei", "Dateien")))
            .details(hits)
            .fix(
                "Schlüssel in einen Passwort-Manager oder den Schlüsselbund legen, Dateien mit chmod 600 schützen, und Schlüssel, die in einer Shell-Historie stehen, beim Anbieter erneuern.",
                &["chmod 600 <datei>"],
            )
    }
}

// --------------------------------------------------------------- autostart

fn suspicious_path(command: &str) -> bool {
    let first = command.split_whitespace().next().unwrap_or("");
    ["/tmp/", "/dev/shm/", "/var/tmp/"].iter().any(|p| first.starts_with(p))
}

fn autostart(home: &Path) -> Finding {
    let f = Finding::new("deep.autostart", CAT, "Programme, die von selbst starten")
        .why("Schadsoftware trägt sich ein, um jeden Neustart zu überleben. Diese Liste zeigt, was unter deinem Konto automatisch startet.");
    let mut entries: Vec<String> = Vec::new();
    let mut odd: Vec<String> = Vec::new();
    let mut add = |source: &str, name: &str, command: &str| {
        let line = format!("{source}: {name}{}", if command.is_empty() { String::new() } else { format!(" → {command}") });
        if suspicious_path(command) {
            odd.push(line.clone());
        }
        entries.push(line);
    };
    let key_of = |text: &str, key: &str| -> String {
        text.lines().find_map(|l| l.trim().strip_prefix(key)).unwrap_or("").trim().to_string()
    };
    for (dir, source, key) in [(home.join(".config/autostart"), "Autostart", "Exec="), (home.join(".config/systemd/user"), "systemd (Benutzer)", "ExecStart=")] {
        let mut files: Vec<PathBuf> = std::fs::read_dir(&dir).into_iter().flatten().flatten().map(|e| e.path()).filter(|p| p.is_file()).collect();
        files.sort();
        for p in files {
            let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !["desktop", "service", "timer"].contains(&ext) {
                continue;
            }
            let text = std::fs::read_to_string(&p).unwrap_or_default();
            add(source, &p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(), &key_of(&text, key));
        }
    }
    if let Some(o) = util::run("crontab", &["-l"], 5).filter(|o| o.ok) {
        for l in o.stdout.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
            let command = l.split_whitespace().skip(5).collect::<Vec<_>>().join(" ");
            add("cron", l, &command);
        }
    }
    if Path::new("/etc/rc.local").exists() {
        add("System", "/etc/rc.local", "");
    }
    for rc in [".bashrc", ".zshrc", ".profile", ".bash_profile"] {
        let text = std::fs::read_to_string(home.join(rc)).unwrap_or_default();
        for l in text.lines().map(str::trim).filter(|l| !l.starts_with('#')) {
            // Download-and-run or decode-and-run in a shell start file.
            let piped = (l.contains("curl ") || l.contains("wget ")) && (l.contains("| sh") || l.contains("| bash") || l.contains("|sh") || l.contains("|bash"));
            if piped || (l.contains("base64 -d") && l.contains("eval")) {
                odd.push(format!("~/{rc}: lädt oder entschlüsselt Code beim Start der Shell"));
            }
        }
    }
    if !odd.is_empty() {
        f.set(Status::Warn, format!("{} mit ungewöhnlichem Startbefehl.", util::plural(odd.len(), "Eintrag", "Einträge")))
            .details(odd)
            .fix("Prüfen, woher diese Einträge stammen, und unbekannte entfernen.", &[])
    } else {
        f.set(Status::Info, format!("{} gefunden, nichts Auffälliges.", util::plural(entries.len(), "Autostart-Eintrag", "Autostart-Einträge")))
            .details(entries)
    }
}

// --------------------------------------------------------------- set-uid

fn setuid(home: &Path) -> Finding {
    let f = Finding::new("deep.setuid", CAT, "Programme mit Root-Rechten (set-uid)").why(
        "Ein set-uid-Programm läuft mit den Rechten seines Besitzers, meist root – egal wer es startet. Solche Dateien außerhalb der Paketverwaltung sind ein klassisches Hintertürchen.",
    );
    let find = |roots: &[&str], timeout| -> Vec<String> {
        let mut args: Vec<&str> = roots.to_vec();
        args.extend(["-xdev", "-type", "f", "-perm", "/6000"]);
        util::run("find", &args, timeout).map(|o| o.stdout.lines().map(String::from).collect()).unwrap_or_default()
    };
    let system = find(&["/usr", "/opt", "/bin", "/sbin"], 60);
    let home_s = home.display().to_string();
    let loose = find(&[&home_s, "/tmp", "/var/tmp", "/dev/shm"], 90);

    // Which system files belong to no package?
    let mut unowned: Vec<String> = Vec::new();
    for chunk in system.chunks(100) {
        let mut args = vec!["-S"];
        args.extend(chunk.iter().map(String::as_str));
        let owned: BTreeSet<String> = util::run("dpkg", &args, 60)
            .map(|o| o.stdout.lines().filter_map(|l| l.split_once(": ").map(|x| x.1.trim().to_string())).collect())
            .unwrap_or_default();
        unowned.extend(chunk.iter().filter(|p| !owned.contains(*p)).cloned());
    }
    if !loose.is_empty() {
        f.set(Status::Crit, format!("{} in deinem Ordner oder in /tmp.", util::plural(loose.len(), "set-uid-Datei liegt", "set-uid-Dateien liegen")))
            .details(loose)
            .details(unowned.iter().map(|p| format!("ohne Paket: {p}")))
            .fix("Diese Dateien haben dort nichts zu suchen. Herkunft prüfen; im Zweifel das set-uid-Bit entfernen.", &["chmod u-s,g-s <datei>"])
    } else if !unowned.is_empty() {
        f.set(Status::Warn, format!("{} zu keinem installierten Paket.", util::plural(unowned.len(), "set-uid-Datei gehört", "set-uid-Dateien gehören")))
            .details(unowned)
            .fix("Prüfen, welches Programm die Dateien installiert hat (oft Software außerhalb der Paketverwaltung).", &[])
    } else {
        f.set(Status::Ok, format!("Alle {} set-uid-Dateien gehören zu installierten Paketen.", system.len()))
    }
}

// ------------------------------------------------------------ dpkg verify

/// Paths of changed program files in `dpkg --verify` output (configuration files are expected to change).
pub fn parse_dpkg_verify(out: &str) -> Vec<String> {
    out.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let flags = it.next()?;
            let mut path = it.next()?;
            if path == "c" {
                return None;
            }
            if path.len() == 1 {
                path = it.next()?;
            }
            (flags.len() == 9 && flags.as_bytes()[2] == b'5').then(|| path.to_string())
        })
        .collect()
}

fn verify() -> Finding {
    let f = Finding::new("deep.verify", CAT, "Unveränderte Systemprogramme").why(
        "Jedes Paket bringt Prüfsummen seiner Dateien mit. Ein Systemprogramm, dessen Inhalt nicht mehr dazu passt, wurde nachträglich verändert.",
    );
    let Some(o) = util::run("dpkg", &["--verify"], 600) else {
        return f.set(Status::Unknown, "dpkg --verify konnte nicht ausgeführt werden.");
    };
    let changed = parse_dpkg_verify(&o.stdout);
    let programs: Vec<&String> = changed
        .iter()
        .filter(|p| ["/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/usr/libexec/"].iter().any(|d| p.starts_with(d)))
        .collect();
    if programs.is_empty() {
        f.set(Status::Ok, "Die Prüfsummen der installierten Programme stimmen.")
            .detail(format!("{} sonstige geänderte Dateien (Daten, Dokumentation)", changed.len()))
    } else {
        f.set(Status::Warn, format!("{} seit der Installation verändert.", util::plural(programs.len(), "Programmdatei wurde", "Programmdateien wurden")))
            .details(programs.iter().take(60).map(|p| p.to_string()))
            .fix(
                "Herausfinden, zu welchem Paket die Datei gehört, und es neu installieren. Manche Programme (z. B. Treiber-Installer) ersetzen Dateien absichtlich.",
                &["dpkg -S <datei>", "sudo apt install --reinstall <paket>"],
            )
    }
}

// ------------------------------------------------------------------ lynis

/// (hardening index, warnings, suggestions) from a Lynis report file.
pub fn parse_lynis(report: &str) -> (Option<u32>, Vec<String>, Vec<String>) {
    let text_of = |v: &str| {
        let mut parts = v.split('|');
        let (id, text) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
        format!("{text} ({id})")
    };
    let mut index = None;
    let (mut warnings, mut suggestions) = (Vec::new(), Vec::new());
    for l in report.lines() {
        if let Some(v) = l.strip_prefix("hardening_index=") {
            index = v.trim().parse().ok();
        } else if let Some(v) = l.strip_prefix("warning[]=") {
            warnings.push(text_of(v));
        } else if let Some(v) = l.strip_prefix("suggestion[]=") {
            suggestions.push(text_of(v));
        }
    }
    (index, warnings, suggestions)
}

fn lynis() -> Option<Finding> {
    util::which("lynis")?;
    let f = Finding::new("deep.lynis", CAT, "Lynis-Audit").why(
        "Lynis ist ein verbreitetes Prüfwerkzeug für Linux-Systeme. Es läuft hier ohne Root-Rechte und bewertet die Härtung des Systems mit einem Index von 0 bis 100.",
    );
    let dir = util::state_dir();
    let _ = std::fs::create_dir_all(&dir);
    let (log, report) = (dir.join("lynis.log"), dir.join("lynis-report.dat"));
    let _ = std::fs::remove_file(&report);
    let ran = util::run(
        "lynis",
        &["audit", "system", "--pentest", "--quick", "--quiet", "--no-colors", "--logfile", &log.display().to_string(), "--report-file", &report.display().to_string()],
        600,
    );
    let text = std::fs::read_to_string(&report).unwrap_or_default();
    let (index, warnings, suggestions) = parse_lynis(&text);
    Some(match (ran, index) {
        (None, _) | (_, None) => f.set(Status::Unknown, "Lynis lieferte kein Ergebnis."),
        (_, Some(i)) => f
            .set(
                if !warnings.is_empty() || i < 55 { Status::Warn } else { Status::Info },
                format!("Härtungsindex {i} von 100 · {} Warnungen · {} Vorschläge.", warnings.len(), suggestions.len()),
            )
            .details(warnings.iter().map(|w| format!("Warnung: {w}")))
            .details(suggestions.iter().take(40).cloned())
            .fix("Die Vorschläge sind allgemein gehalten; nicht jeder passt zu einem Laptop. Details stehen im Lynis-Protokoll.", &["lynis show details <ID>"]),
    })
}

/// Run all deep checks; `progress` is told which step starts.
pub fn run_all(progress: &dyn Fn(&str)) -> Vec<Finding> {
    let home = util::home();
    let mut out = Vec::new();
    progress("Suche nach Zugangsdaten im persönlichen Ordner …");
    out.push(scan_secrets(&home));
    progress("Prüfe Autostart-Einträge …");
    out.push(autostart(&home));
    progress("Suche set-uid-Dateien …");
    out.push(setuid(&home));
    progress("Vergleiche Systemdateien mit den Paket-Prüfsummen …");
    out.push(verify());
    progress("Lynis-Audit läuft (ein bis zwei Minuten) …");
    out.extend(lynis());
    out.sort_by_key(|f| f.status);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_secrets_without_false_alarms() {
        let kinds = |t: &str| find_secrets(t).into_iter().collect::<Vec<_>>();
        // Made-up tokens, assembled here so that no token-shaped literal sits in the source.
        let aws = ["AWS_KEY=AK", "IAABCDEFGHIJKLMNOP"].concat();
        let github = ["export GITHUB=gh", "p_0123456789abcdefghijklmnopqrstuvwxyz"].concat();
        assert_eq!(kinds(&aws), ["AWS-Zugangsschlüssel"]);
        assert_eq!(kinds(&github), ["GitHub-Token"]);
        assert_eq!(kinds("DB_PASSWORD=\"hunter2-very-secret\"\n"), ["Passwort oder Token im Klartext"]);
        assert_eq!(kinds("url = https://deploy:s3cr3tpass@git.example.com/repo.git"), ["Zugangsdaten in einer URL"]);
        assert_eq!(kinds("-----BEGIN RSA PRIVATE KEY-----\nMIIE\n"), ["privater Schlüssel"]);
        // Placeholders, variables and ordinary text are not secrets.
        assert!(kinds("DB_PASSWORD=${DB_PASSWORD}\nAPI_KEY=\nTOKEN=changeme\nSECRET=<dein-token>").is_empty());
        assert!(kinds("see https://example.com/path@2x.png and mailto:a@b.de").is_empty());
        assert!(kinds("the task_ghp_helper and AKIA are mentioned, sk-ant- too").is_empty());
        assert!(kinds("PASSWORD_MIN_LENGTH=12345678").len() == 1); // named like a secret: reported, by design
    }

    #[test]
    fn parses_tool_output() {
        let v = parse_dpkg_verify("??5?????? c /etc/ssh/ssh_config\n??5??????   /usr/bin/sudo\n??5?????? /usr/share/doc/x/README\nmissing     /usr/bin/gone\n");
        assert_eq!(v, ["/usr/bin/sudo", "/usr/share/doc/x/README"]);
        let (i, w, s) = parse_lynis("hardening_index=67\nwarning[]=FIRE-4512|iptables module(s) loaded, but no rules active|-|-|\nsuggestion[]=AUTH-9262|Install a PAM module for password strength testing|-|-|\nother=1\n");
        assert_eq!(i, Some(67));
        assert_eq!(w, ["iptables module(s) loaded, but no rules active (FIRE-4512)"]);
        assert_eq!(s.len(), 1);
        assert!(suspicious_path("/tmp/.x/run --daemon") && !suspicious_path("/usr/bin/remmina -i"));
        assert!(is_candidate(".env") && is_candidate("prod.env") && is_candidate("server.key"));
        assert!(!is_candidate(".env.example") && !is_candidate(".env-sample") && !is_candidate("notes.txt"));
    }
}
