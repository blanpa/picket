use super::Ctx;
use crate::model::{Category, Finding, Status};
use crate::util;
use serde_json::Value;
use std::fs;

const CAT: Category = Category::System;

/// Walk the lsblk tree and record every mountpoint with whether it sits on a dm-crypt device.
fn collect_mounts(node: &Value, parent_encrypted: bool, mounts: &mut Vec<(String, bool)>) {
    let ty = node["type"].as_str().unwrap_or("");
    if ty == "loop" || ty == "rom" {
        return;
    }
    let encrypted = parent_encrypted || ty == "crypt";
    for m in node["mountpoints"].as_array().into_iter().flatten() {
        if let Some(m) = m.as_str() {
            mounts.push((m.to_string(), encrypted));
        }
    }
    for c in node["children"].as_array().into_iter().flatten() {
        collect_mounts(c, encrypted, mounts);
    }
}

pub fn parse_lsblk(json: &str) -> Vec<(String, bool)> {
    let mut mounts = Vec::new();
    if let Ok(v) = serde_json::from_str::<Value>(json) {
        for d in v["blockdevices"].as_array().into_iter().flatten() {
            collect_mounts(d, false, &mut mounts);
        }
    }
    mounts
}

/// Is the filesystem containing `path` encrypted? (longest matching mountpoint)
fn path_encrypted(path: &str, mounts: &[(String, bool)]) -> Option<bool> {
    mounts
        .iter()
        .filter(|(m, _)| m.starts_with('/') && (path == m || m == "/" || path.starts_with(&format!("{m}/"))))
        .max_by_key(|(m, _)| m.len())
        .map(|(_, e)| *e)
}

fn encryption(out: &mut Vec<Finding>) {
    let f = Finding::new("sys.luks", CAT, "Festplattenverschlüsselung").why(
        "Ein Laptop kann verloren gehen oder gestohlen werden. Ohne Verschlüsselung lassen sich alle Daten \
         (Dokumente, Browser-Passwörter, SSH-Schlüssel) einfach von der SSD lesen.",
    );
    let Some(o) = util::run("lsblk", &["-J", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINTS"], 10) else {
        out.push(f.set(Status::Unknown, "lsblk konnte nicht ausgeführt werden."));
        return;
    };
    let mounts = parse_lsblk(&o.stdout);
    let plain: Vec<&str> = mounts
        .iter()
        .filter(|(m, e)| !e && m.starts_with('/') && !m.starts_with("/boot") && !m.starts_with("/snap"))
        .map(|(m, _)| m.as_str())
        .collect();
    out.push(match path_encrypted("/", &mounts) {
        None => f.set(Status::Unknown, "Das Root-Dateisystem wurde in lsblk nicht gefunden."),
        Some(false) => f
            .set(Status::Crit, "Die Systemplatte ist nicht verschlüsselt.")
            .fix(
                "Nachträglich lässt sich das System nur mit Aufwand verschlüsseln; üblich ist eine Neuinstallation mit der Option \
                 „Festplatte verschlüsseln (LUKS)“. Bis dahin sensible Daten in einem verschlüsselten Container ablegen.",
                &[],
            ),
        Some(true) if plain.iter().any(|m| *m == "/home" || m.starts_with("/home/")) => f
            .set(Status::Crit, "Das System ist verschlüsselt, /home liegt aber auf einer unverschlüsselten Partition.")
            .details(plain.iter().map(|m| format!("unverschlüsselt: {m}"))),
        Some(true) => {
            let f = f.set(Status::Ok, "Das System liegt auf einer LUKS-verschlüsselten Partition.");
            if plain.is_empty() {
                f
            } else {
                f.details(plain.iter().map(|m| format!("unverschlüsselt eingehängt: {m}")))
            }
        }
    });

    // Swap
    let swaps = util::read("/proc/swaps").unwrap_or_default();
    let mut plain_swap = Vec::new();
    let mut any = false;
    for l in swaps.lines().skip(1) {
        let mut it = l.split_whitespace();
        let (Some(name), Some(ty)) = (it.next(), it.next()) else {
            continue;
        };
        if name.starts_with("/dev/zram") {
            continue;
        }
        any = true;
        let enc = if ty == "file" {
            path_encrypted(name, &mounts)
        } else {
            mounts.iter().find(|(m, _)| m == "[SWAP]").map(|(_, e)| *e)
        };
        if enc != Some(true) {
            plain_swap.push(name.to_string());
        }
    }
    if any {
        let f = Finding::new("sys.swap", CAT, "Auslagerungsspeicher (Swap)")
            .why("In den Swap werden Teile des Arbeitsspeichers geschrieben – darunter Passwörter und Schlüssel.");
        out.push(if plain_swap.is_empty() {
            f.set(Status::Ok, "Der Swap liegt auf dem verschlüsselten Datenträger.")
        } else {
            f.set(Status::Warn, "Der Swap ist nicht verschlüsselt.")
                .details(plain_swap)
                .fix("Swap auf den verschlüsselten Datenträger legen (Swap-Datei statt eigener Partition).", &[])
        });
    }
}

fn cpu_vulnerabilities(out: &mut Vec<Finding>) {
    let dir = "/sys/devices/system/cpu/vulnerabilities";
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    let mut vulnerable = Vec::new();
    let mut total = 0;
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some(v) = util::read(e.path()) else {
            continue;
        };
        total += 1;
        if v.starts_with("Vulnerable") {
            vulnerable.push(format!("{name}: {v}"));
        }
    }
    vulnerable.sort();
    let cmdline = util::read("/proc/cmdline").unwrap_or_default();
    let disabled = cmdline.split_whitespace().any(|a| a == "mitigations=off");
    let microcode = util::read("/proc/cpuinfo")
        .and_then(|c| {
            c.lines()
                .find(|l| l.starts_with("microcode"))
                .and_then(|l| l.split_once(':').map(|x| x.1.trim().to_string()))
        })
        .unwrap_or_default();
    let f = Finding::new("sys.cpu", CAT, "CPU-Schwachstellen (Spectre & Co.)").why(
        "Prozessorlücken erlauben es einem Programm, Speicher anderer Programme auszulesen. \
         Kernel und Microcode enthalten Gegenmaßnahmen, die aktiv sein sollten.",
    );
    out.push(if vulnerable.is_empty() {
        f.set(Status::Ok, format!("Alle {total} bekannten CPU-Lücken sind nicht relevant oder entschärft."))
    } else {
        let mut f = f
            .set(
                Status::Warn,
                format!("{} von {total} CPU-Lücken ohne aktive Gegenmaßnahme.", vulnerable.len()),
            )
            .details(vulnerable)
            .detail(format!("Microcode-Version: {microcode}"));
        if disabled {
            f = f.detail("Kernel-Parameter „mitigations=off“ ist gesetzt.");
        }
        f.fix(
            "BIOS/Firmware und das Paket intel-microcode (bzw. amd64-microcode) aktuell halten und neu starten. \
             „Vulnerable: No microcode“ bedeutet: der Hersteller muss ein Microcode-Update liefern (über ein BIOS-Update).",
            &["sudo apt install --only-upgrade intel-microcode", "fwupdmgr get-updates"],
        )
    });
}

fn sysctl(out: &mut Vec<Finding>) {
    // (path below /proc/sys, minimum, exact match required, meaning)
    const RULES: [(&str, i64, bool, &str); 10] = [
        ("kernel/randomize_va_space", 2, true, "Speicher-Layout wird zufällig gewählt (ASLR)"),
        ("kernel/kptr_restrict", 1, false, "Kernel-Adressen sind verborgen"),
        ("kernel/dmesg_restrict", 1, true, "Kernel-Log nur für Admins lesbar"),
        ("kernel/yama/ptrace_scope", 1, false, "Programme können fremde Prozesse nicht auslesen"),
        ("kernel/unprivileged_bpf_disabled", 1, false, "BPF nur für Admins"),
        ("fs/protected_symlinks", 1, true, "Schutz vor Symlink-Angriffen in /tmp"),
        ("fs/protected_hardlinks", 1, true, "Schutz vor Hardlink-Angriffen"),
        ("net/ipv4/tcp_syncookies", 1, true, "Schutz vor SYN-Flood"),
        ("net/ipv4/conf/all/accept_redirects", 0, true, "ICMP-Umleitungen werden ignoriert"),
        ("net/ipv4/conf/all/accept_source_route", 0, true, "Source-Routing wird abgelehnt"),
    ];
    let mut bad = Vec::new();
    let mut good = 0;
    for (path, want, exact, meaning) in RULES {
        let Some(v) = util::read(format!("/proc/sys/{path}")).and_then(|s| s.parse::<i64>().ok()) else {
            continue;
        };
        let ok = if exact { v == want } else { v >= want };
        if ok {
            good += 1;
        } else {
            bad.push(format!("{} = {v} (erwartet {}{want}) – {meaning}", path.replace('/', "."), if exact { "" } else { "≥ " }));
        }
    }
    let f = Finding::new("sys.sysctl", CAT, "Kernel-Härtung")
        .why("Diese Kernel-Einstellungen erschweren es, Lücken in Programmen auszunutzen.");
    out.push(if bad.is_empty() {
        f.set(Status::Ok, format!("Alle {good} geprüften Kernel-Schutzeinstellungen sind aktiv."))
    } else {
        f.set(Status::Warn, format!("{} Kernel-Schutzeinstellung(en) weichen ab.", bad.len()))
            .details(bad)
            .fix("Werte in /etc/sysctl.d/99-hardening.conf setzen und laden.", &["sudo sysctl --system"])
    });
}

pub fn check(_ctx: &Ctx) -> Vec<Finding> {
    let mut out = Vec::new();
    encryption(&mut out);

    // Secure Boot
    let f = Finding::new("sys.secureboot", CAT, "Secure Boot").why(
        "Secure Boot startet nur signierte Bootloader und Kernel und erschwert Manipulationen am Startvorgang (Bootkits, „Evil Maid“).",
    );
    out.push(match util::run("mokutil", &["--sb-state"], 8) {
        Some(o) if o.stdout.contains("SecureBoot enabled") => f.set(Status::Ok, "Secure Boot ist eingeschaltet."),
        Some(o) if o.stdout.contains("SecureBoot disabled") => f
            .set(Status::Warn, "Secure Boot ist ausgeschaltet.")
            .fix("Im BIOS (F2 beim Start) unter „Security → Secure Boot“ einschalten.", &[]),
        _ => f.set(Status::Unknown, "Secure-Boot-Status nicht feststellbar (mokutil fehlt oder kein UEFI)."),
    });

    // AppArmor
    let f = Finding::new("sys.apparmor", CAT, "AppArmor")
        .why("AppArmor sperrt Programme (Browser, Snaps) in Profile ein und begrenzt den Schaden nach einem erfolgreichen Angriff.");
    out.push(match util::read("/sys/module/apparmor/parameters/enabled").as_deref() {
        Some("Y") => f.set(Status::Ok, "AppArmor ist aktiv."),
        _ => f
            .set(Status::Warn, "AppArmor ist nicht aktiv.")
            .fix("AppArmor einschalten.", &["sudo systemctl enable --now apparmor"]),
    });

    cpu_vulnerabilities(&mut out);
    sysctl(&mut out);
    out
}

/// Firmware security attributes from fwupd (Host Security ID).
pub fn hsi(_ctx: &Ctx) -> Vec<Finding> {
    let f = Finding::new("sys.hsi", CAT, "Firmware-Sicherheit (HSI)").why(
        "Die „Host Security ID“ von fwupd bewertet, wie gut die Firmware des Laptops gegen Manipulation geschützt ist \
         (Schreibschutz des BIOS-Chips, BootGuard, TPM, DMA-Schutz). HSI:0 ist ungeschützt, HSI:4 das Maximum.",
    );
    let Some(o) = util::run_localized("fwupdmgr", &["security", "--json"], 40) else {
        return Vec::new();
    };
    let Ok(v) = serde_json::from_str::<Value>(&o.stdout) else {
        return vec![f.set(Status::Unknown, "fwupd lieferte keine lesbare Antwort.")];
    };
    let Some(attrs) = v["SecurityAttributes"].as_array() else {
        return vec![f.set(Status::Unknown, "fwupd meldet keine Sicherheitsattribute.")];
    };
    let success = |a: &Value| {
        a["Flags"]
            .as_array()
            .map(|fl| fl.iter().any(|x| x.as_str() == Some("success")))
            .unwrap_or(false)
    };
    let mut level = 0;
    for l in 1..=4u64 {
        let at_level: Vec<&Value> = attrs.iter().filter(|a| a["HsiLevel"].as_u64() == Some(l)).collect();
        if at_level.is_empty() || !at_level.iter().all(|a| success(a)) {
            break;
        }
        level = l;
    }
    let failing: Vec<String> = attrs
        .iter()
        .filter(|a| !success(a))
        // The swap attribute is covered by our own check, which also understands swap files on LUKS.
        .filter(|a| a["AppstreamId"].as_str() != Some("org.fwupd.hsi.Kernel.Swap"))
        .map(|a| {
            format!(
                "{}: {}{}",
                a["Name"].as_str().unwrap_or("?"),
                a["HsiResult"].as_str().unwrap_or("?"),
                a["HsiLevel"].as_u64().map(|l| format!(" (Stufe {l})")).unwrap_or_default()
            )
        })
        .collect();
    let total = attrs.len();
    let f = f.details(failing.iter().map(|s| format!("nicht erfüllt – {s}")));
    vec![match level {
        0 => f
            .set(Status::Warn, format!("HSI:0 – grundlegende Firmware-Schutzfunktionen fehlen ({} von {total} Prüfungen nicht erfüllt).", failing.len()))
            .fix("BIOS aktualisieren und Secure Boot/TPM im BIOS einschalten.", &["fwupdmgr security"]),
        1 => f.set(Status::Info, format!("HSI:1 – Basisschutz vorhanden ({} von {total} Prüfungen nicht erfüllt).", failing.len())),
        l => f.set(Status::Ok, format!("HSI:{l} – guter Firmware-Schutz ({} von {total} Prüfungen bestanden).", total - failing.len())),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    const LSBLK: &str = r#"{"blockdevices":[
      {"name":"loop0","type":"loop","fstype":null,"mountpoints":["/snap/x/1"]},
      {"name":"nvme0n1","type":"disk","fstype":null,"mountpoints":[null],"children":[
        {"name":"nvme0n1p1","type":"part","fstype":"vfat","mountpoints":["/boot/efi"]},
        {"name":"nvme0n1p2","type":"part","fstype":"ext4","mountpoints":["/boot"]},
        {"name":"nvme0n1p3","type":"part","fstype":"crypto_LUKS","mountpoints":[null],"children":[
          {"name":"dm_crypt-0","type":"crypt","fstype":"LVM2_member","mountpoints":[null],"children":[
            {"name":"ubuntu--vg-ubuntu--lv","type":"lvm","fstype":"ext4","mountpoints":["/"]}]}]},
        {"name":"nvme0n1p4","type":"part","fstype":"ext4","mountpoints":["/data"]}]}]}"#;

    #[test]
    fn detects_encrypted_mounts() {
        let m = parse_lsblk(LSBLK);
        assert_eq!(path_encrypted("/", &m), Some(true));
        assert_eq!(path_encrypted("/swap.img", &m), Some(true));
        assert_eq!(path_encrypted("/boot/vmlinuz", &m), Some(false));
        assert_eq!(path_encrypted("/data/x", &m), Some(false));
        assert_eq!(path_encrypted("/database", &m), Some(true)); // not below /data
        assert!(!m.iter().any(|(p, _)| p.starts_with("/snap")));
    }
}
