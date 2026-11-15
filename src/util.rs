//! Small helpers: running system tools with a timeout, reading files, time.

use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub struct Out {
    pub ok: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Tools are only looked up in system directories, never via $PATH, so a
/// planted binary earlier in the user's PATH cannot fake the results.
const BIN_DIRS: [&str; 7] = ["/usr/sbin", "/usr/bin", "/sbin", "/bin", "/snap/bin", "/usr/local/sbin", "/usr/local/bin"];

pub fn which(name: &str) -> Option<PathBuf> {
    BIN_DIRS
        .iter()
        .map(|d| Path::new(d).join(name))
        .find(|p| p.is_file())
}

/// Run a tool with the C locale (stable, parseable output).
pub fn run(name: &str, args: &[&str], timeout_s: u64) -> Option<Out> {
    run_inner(name, args, timeout_s, true)
}

/// Run a tool in the user's locale (for text that is shown as-is).
pub fn run_localized(name: &str, args: &[&str], timeout_s: u64) -> Option<Out> {
    run_inner(name, args, timeout_s, false)
}

/// Run a program at a known path (for tools that live outside the system directories).
#[cfg_attr(not(feature = "gui"), allow(dead_code))]
pub fn run_at(path: &Path, args: &[&str], timeout_s: u64) -> Option<Out> {
    run_bin(path.to_path_buf(), args, timeout_s, true)
}

fn run_inner(name: &str, args: &[&str], timeout_s: u64, c_locale: bool) -> Option<Out> {
    run_bin(which(name)?, args, timeout_s, c_locale)
}

fn run_bin(bin: PathBuf, args: &[&str], timeout_s: u64, c_locale: bool) -> Option<Out> {
    let mut cmd = Command::new(bin);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    if c_locale {
        cmd.env("LC_ALL", "C").env("LANGUAGE", "C");
    }
    let mut child = cmd.spawn().ok()?;
    let mut so = child.stdout.take()?;
    let mut se = child.stderr.take()?;
    let t_out = thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = so.read_to_end(&mut buf);
        buf
    });
    let t_err = thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = se.read_to_end(&mut buf);
        buf
    });
    let deadline = Instant::now() + Duration::from_secs(timeout_s);
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) => {
                if Instant::now() >= deadline {
                    // Kill the whole process group so helpers holding the pipes die too.
                    let _ = Command::new("/bin/kill")
                        .args(["-KILL", "--", &format!("-{}", child.id())])
                        .stderr(Stdio::null())
                        .status();
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break None,
        }
    };
    let stdout = String::from_utf8_lossy(&t_out.join().unwrap_or_default()).into_owned();
    let stderr = String::from_utf8_lossy(&t_err.join().unwrap_or_default()).into_owned();
    let status = status?;
    Some(Out {
        ok: status.success(),
        stdout,
        stderr,
    })
}

pub fn read(path: impl AsRef<Path>) -> Option<String> {
    std::fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn mtime(path: impl AsRef<Path>) -> Option<u64> {
    let m = std::fs::metadata(path).ok()?;
    u64::try_from(m.mtime()).ok()
}

/// Age of a file in whole days.
pub fn age_days(path: impl AsRef<Path>) -> Option<u64> {
    mtime(path).map(|t| now().saturating_sub(t) / 86400)
}

pub fn home() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

pub fn uid() -> u32 {
    std::fs::metadata("/proc/self").map(|m| m.uid()).unwrap_or(u32::MAX)
}

pub fn service_active(name: &str) -> bool {
    run("systemctl", &["is-active", name], 5)
        .map(|o| o.stdout.trim() == "active")
        .unwrap_or(false)
}

/// `KEY=value` / `KEY="value"` lookup in shell-style config files.
pub fn conf_value(content: &str, key: &str) -> Option<String> {
    content.lines().find_map(|l| {
        let l = l.trim();
        if l.starts_with('#') {
            return None;
        }
        let (k, v) = l.split_once('=')?;
        (k.trim() == key).then(|| v.trim().trim_matches('"').to_string())
    })
}

pub fn plural(n: usize, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

/// Path of this executable, for commands shown to the user.
pub fn self_exe() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(String::from))
        .unwrap_or_else(|| "picket".into())
}

pub fn random_token() -> String {
    let mut buf = [0u8; 16];
    let ok = std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .is_ok();
    if !ok {
        panic!("/dev/urandom nicht lesbar – kein sicheres Token möglich");
    }
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn xdg_dir(var: &str, fallback: &str) -> PathBuf {
    std::env::var_os(var)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home().join(fallback))
        .join("picket")
}

/// ~/.local/state/picket: history, known devices, watcher state.
pub fn state_dir() -> PathBuf {
    xdg_dir("XDG_STATE_HOME", ".local/state")
}

/// ~/.local/share/picket: downloaded databases.
pub fn data_dir() -> PathBuf {
    xdg_dir("XDG_DATA_HOME", ".local/share")
}

/// Local date in the given `date` format, e.g. "+%F".
pub fn date(format: &str) -> String {
    run_localized("date", &[format], 5).map(|o| o.stdout.trim().to_string()).unwrap_or_default()
}

pub fn write_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(value).map_err(|e| e.to_string())?;
    std::fs::write(path, json).map_err(|e| format!("{}: {e}", path.display()))
}

pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Option<T> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

/// Human-readable size, e.g. "3,4 MB".
/// A number written with a decimal point, as the interface language writes it.
pub fn decimal(number: String) -> String {
    if crate::i18n::german() {
        number.replace('.', ",")
    } else {
        number
    }
}

pub fn format_bytes(n: u64) -> String {
    let n = n as f64;
    if n >= 1e9 {
        decimal(format!("{:.1} GB", n / 1e9))
    } else if n >= 1e6 {
        decimal(format!("{:.1} MB", n / 1e6))
    } else if n >= 1e3 {
        format!("{:.0} kB", n / 1e3)
    } else {
        format!("{n:.0} B")
    }
}

/// Format a Unix timestamp in local time with a `date` format such as "+%d.%m. %H:%M".
pub fn format_time(epoch: u64, format: &str) -> String {
    run_localized("date", &[&format!("--date=@{epoch}"), format], 5).map(|o| o.stdout.trim().to_string()).unwrap_or_default()
}

/// The program was called "fw-security" before it became Picket: carry the
/// user's data over once, so history, known devices and databases survive.
pub fn migrate_legacy_dirs() {
    for (var, fallback) in [("XDG_STATE_HOME", ".local/state"), ("XDG_DATA_HOME", ".local/share"), ("XDG_CACHE_HOME", ".cache")] {
        let new = xdg_dir(var, fallback);
        let old = new.with_file_name("fw-security");
        if old.is_dir() && !new.exists() {
            let _ = std::fs::rename(&old, &new);
        }
    }
}
