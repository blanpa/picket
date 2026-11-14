//! On-demand virus scan with ClamAV (`clamscan`), plus a small scan history.

use crate::util;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Infected {
    pub path: String,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ScanRecord {
    pub finished: u64,
    pub path: String,
    pub files: u64,
    pub infected: Vec<Infected>,
    pub cancelled: bool,
}

#[derive(Serialize, Clone, Debug, Default)]
pub struct ScanInfo {
    pub running: bool,
    pub path: String,
    pub started: u64,
    pub finished: Option<u64>,
    pub files: u64,
    pub current: String,
    pub infected: Vec<Infected>,
    pub cancelled: bool,
    pub error: Option<String>,
    /// Files clamscan could not read (permissions etc.).
    pub skipped: u64,
}

#[derive(Default)]
pub struct ScanJob {
    pub info: Mutex<ScanInfo>,
    child: Mutex<Option<Child>>,
}

#[derive(Serialize, Clone)]
pub struct Target {
    pub key: &'static str,
    pub label: &'static str,
    pub path: String,
}

/// The dashboard may only scan these fixed locations (no arbitrary paths over HTTP).
pub fn targets() -> Vec<Target> {
    let home = util::home();
    let downloads = util::run_localized("xdg-user-dir", &["DOWNLOAD"], 5)
        .map(|o| o.stdout.trim().to_string())
        .filter(|p| !p.is_empty() && p != home.to_str().unwrap_or(""))
        .unwrap_or_else(|| home.join("Downloads").display().to_string());
    vec![
        Target { key: "downloads", label: "Download-Ordner", path: downloads },
        Target { key: "home", label: "Persönlicher Ordner (dauert lange)", path: home.display().to_string() },
        Target { key: "tmp", label: "Temporäre Dateien (/tmp)", path: "/tmp".into() },
    ]
}

fn history_path() -> PathBuf {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| util::home().join(".local/state"));
    base.join("picket/scans.json")
}

pub fn load_history() -> Vec<ScanRecord> {
    fs::read_to_string(history_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_record(rec: ScanRecord) {
    let mut h = load_history();
    h.push(rec);
    let skip = h.len().saturating_sub(20);
    let h: Vec<_> = h.into_iter().skip(skip).collect();
    let path = history_path();
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    if let Ok(json) = serde_json::to_string_pretty(&h) {
        let _ = fs::write(path, json);
    }
}

impl ScanJob {
    pub fn snapshot(&self) -> ScanInfo {
        self.info.lock().unwrap().clone()
    }

    /// Mark the job as running. Returns false when a scan is already in progress.
    pub fn begin(&self, path: &str) -> bool {
        let mut info = self.info.lock().unwrap();
        if info.running {
            return false;
        }
        *info = ScanInfo {
            running: true,
            path: path.to_string(),
            started: util::now(),
            ..Default::default()
        };
        true
    }

    pub fn cancel(&self) {
        self.info.lock().unwrap().cancelled = true;
        if let Some(child) = self.child.lock().unwrap().as_mut() {
            let _ = child.kill();
        }
    }

    fn fail(&self, msg: String) {
        let mut info = self.info.lock().unwrap();
        info.running = false;
        info.finished = Some(util::now());
        info.error = Some(msg);
    }

    /// Run the scan (blocking). Call `begin` first.
    pub fn run(&self, path: &str) {
        let Some(clamscan) = util::which("clamscan") else {
            return self.fail("clamscan ist nicht installiert (sudo apt install clamav).".into());
        };
        // Low CPU priority so the laptop stays usable.
        let mut cmd = match util::which("nice") {
            Some(nice) => {
                let mut c = Command::new(nice);
                c.args(["-n", "19"]).arg(&clamscan);
                c
            }
            None => Command::new(&clamscan),
        };
        cmd.args(["-r", "--no-summary", "--max-filesize=200M", "--max-scansize=400M", "--"])
            .arg(path)
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => return self.fail(format!("clamscan konnte nicht gestartet werden: {e}")),
        };
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        *self.child.lock().unwrap() = Some(child);

        let err_thread = std::thread::spawn(move || {
            let mut s = String::new();
            if let Some(mut e) = stderr {
                let _ = e.read_to_string(&mut s);
            }
            s
        });

        if let Some(out) = stdout {
            for line in BufReader::new(out).split(b'\n').flatten() {
                let line = String::from_utf8_lossy(&line).into_owned();
                let Some((file, result)) = line.rsplit_once(": ") else {
                    continue;
                };
                let mut info = self.info.lock().unwrap();
                if let Some(sig) = result.strip_suffix(" FOUND") {
                    info.files += 1;
                    info.infected.push(Infected { path: file.to_string(), signature: sig.to_string() });
                } else if result == "OK" {
                    info.files += 1;
                    info.current = file.to_string();
                } else if result.contains("ERROR") || result.contains("denied") {
                    info.skipped += 1;
                }
            }
        }

        let status = self.child.lock().unwrap().take().and_then(|mut c| c.wait().ok());
        let stderr = err_thread.join().unwrap_or_default();
        let mut info = self.info.lock().unwrap();
        info.running = false;
        info.finished = Some(util::now());
        info.current.clear();
        // clamscan: 0 = clean, 1 = virus found, 2 = some error (often just unreadable files)
        let code = status.and_then(|s| s.code());
        if !info.cancelled && code == Some(2) && info.files == 0 {
            let last = stderr.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("unbekannter Fehler");
            info.error = Some(format!("clamscan meldet einen Fehler: {last}"));
        } else if !info.cancelled && code.is_none() {
            info.error = Some("clamscan wurde unerwartet beendet.".into());
        }
        if info.error.is_none() {
            save_record(ScanRecord {
                finished: info.finished.unwrap_or(0),
                path: info.path.clone(),
                files: info.files,
                infected: info.infected.clone(),
                cancelled: info.cancelled,
            });
        }
    }
}
