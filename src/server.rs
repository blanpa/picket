//! Local dashboard server.
//!
//! Security model: binds to 127.0.0.1 only; the page needs a random per-run
//! token in the URL, the API needs it as a header (which blocks cross-site
//! requests from other web pages); the Host header must be local (which blocks
//! DNS rebinding). Nothing here changes the system.

use crate::checks;
use crate::model::Report;
use crate::net;
use crate::privileged;
use crate::scan::{self, ScanJob};
use crate::util;
use std::collections::HashMap;
use std::io::Read;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use tiny_http::{Header, Method, Request, Response, Server};

const INDEX_HTML: &str = include_str!("../assets/index.html");
const DEFAULT_PORT: u16 = 7373;

struct State {
    token: String,
    port: u16,
    report: Mutex<Option<Arc<Report>>>,
    building: Mutex<()>,
    scan: Arc<ScanJob>,
    dns: Mutex<HashMap<IpAddr, Option<String>>>,
}

fn header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("statischer Header")
}

fn respond(req: Request, code: u16, content_type: &str, body: String) {
    let resp = Response::from_string(body)
        .with_status_code(code)
        .with_header(header("Content-Type", content_type))
        .with_header(header("Cache-Control", "no-store"))
        .with_header(header("X-Content-Type-Options", "nosniff"))
        .with_header(header("X-Frame-Options", "DENY"))
        .with_header(header("Referrer-Policy", "no-referrer"))
        .with_header(header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; \
             img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        ));
    let _ = req.respond(resp);
}

fn json(req: Request, value: &impl serde::Serialize) {
    match serde_json::to_string(value) {
        Ok(s) => respond(req, 200, "application/json; charset=utf-8", s),
        Err(e) => error(req, 500, &e.to_string()),
    }
}

fn error(req: Request, code: u16, msg: &str) {
    let body = serde_json::json!({ "error": msg }).to_string();
    respond(req, code, "application/json; charset=utf-8", body);
}

fn header_value<'a>(req: &'a Request, name: &'static str) -> Option<&'a str> {
    req.headers()
        .iter()
        .find(|h| h.field.equiv(name))
        .map(|h| h.value.as_str())
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hex = std::str::from_utf8(&b[i + 1..i + 3]).ok();
            if let Some(v) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn query(url: &str) -> HashMap<String, String> {
    url.split_once('?')
        .map(|(_, q)| {
            q.split('&')
                .filter_map(|kv| {
                    let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                    (!k.is_empty()).then(|| (percent_decode(k), percent_decode(v)))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Constant-time comparison of the access token.
fn token_ok(given: &str, expected: &str) -> bool {
    given.len() == expected.len()
        && given.bytes().zip(expected.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0
}

fn get_report(st: &State, refresh: bool) -> Arc<Report> {
    let _guard = st.building.lock().unwrap();
    if !refresh {
        if let Some(r) = st.report.lock().unwrap().as_ref() {
            return r.clone();
        }
    }
    let r = Arc::new(checks::build_report());
    *st.report.lock().unwrap() = Some(r.clone());
    r
}

fn resolve(st: &State, ip: IpAddr) -> Option<String> {
    if let Some(cached) = st.dns.lock().unwrap().get(&ip) {
        return cached.clone();
    }
    let name = net::reverse_lookup(ip);
    let mut cache = st.dns.lock().unwrap();
    if cache.len() > 5000 {
        cache.clear();
    }
    cache.insert(ip, name.clone());
    name
}

fn handle(mut req: Request, st: &State) {
    // DNS-rebinding protection: only accept requests addressed to this local server.
    let host_ok = header_value(&req, "Host")
        .map(|h| h == format!("127.0.0.1:{}", st.port) || h == format!("localhost:{}", st.port))
        .unwrap_or(false);
    if !host_ok {
        return error(req, 403, "Ungültiger Host-Header");
    }
    let url = req.url().to_string();
    let path = url.split('?').next().unwrap_or("/").to_string();
    let q = query(&url);
    let method = req.method().clone();

    if path == "/" && method == Method::Get {
        if !token_ok(q.get("t").map(String::as_str).unwrap_or(""), &st.token) {
            return respond(
                req,
                403,
                "text/plain; charset=utf-8",
                "Zugriff verweigert. Bitte die vollständige Adresse aus dem Terminal verwenden (mit ?t=…).".into(),
            );
        }
        return respond(req, 200, "text/html; charset=utf-8", INDEX_HTML.to_string());
    }

    if !path.starts_with("/api/") {
        return error(req, 404, "Nicht gefunden");
    }
    if !token_ok(header_value(&req, "X-Picket-Token").unwrap_or(""), &st.token) {
        return error(req, 403, "Token fehlt oder ist falsch");
    }

    match (&method, path.as_str()) {
        (Method::Get, "/api/report") => {
            let r = get_report(st, q.contains_key("refresh"));
            json(req, r.as_ref())
        }
        (Method::Get, "/api/network") => {
            let privd = privileged::load();
            json(req, &net::snapshot(privd.as_ref()))
        }
        (Method::Get, "/api/resolve") => match q.get("ip").and_then(|s| s.parse::<IpAddr>().ok()) {
            Some(ip) => {
                let name = resolve(st, ip);
                json(req, &serde_json::json!({ "ip": ip, "name": name }))
            }
            None => error(req, 400, "Parameter ip fehlt oder ist ungültig"),
        },
        (Method::Get, "/api/scan") => json(
            req,
            &serde_json::json!({ "scan": st.scan.snapshot(), "targets": scan::targets(), "available": util::which("clamscan").is_some() }),
        ),
        (Method::Post, "/api/scan/start") => {
            let mut body = String::new();
            let _ = req.as_reader().take(4096).read_to_string(&mut body);
            let key = serde_json::from_str::<serde_json::Value>(&body)
                .ok()
                .and_then(|v| v["target"].as_str().map(String::from))
                .unwrap_or_default();
            let Some(target) = scan::targets().into_iter().find(|t| t.key == key) else {
                return error(req, 400, "Unbekanntes Scan-Ziel");
            };
            if !st.scan.begin(&target.path) {
                return error(req, 409, "Es läuft bereits ein Scan");
            }
            let job = st.scan.clone();
            std::thread::spawn(move || job.run(&target.path));
            json(req, &st.scan.snapshot())
        }
        (Method::Post, "/api/scan/cancel") => {
            st.scan.cancel();
            json(req, &st.scan.snapshot())
        }
        _ => error(req, 404, "Nicht gefunden"),
    }
}

pub fn serve(port: Option<u16>, open: bool) -> Result<(), String> {
    let server = match port {
        Some(p) => Server::http(("127.0.0.1", p)).map_err(|e| format!("Port {p} nicht verfügbar: {e}"))?,
        // Preferred port first, any free port as fallback.
        None => Server::http(("127.0.0.1", DEFAULT_PORT))
            .or_else(|_| Server::http(("127.0.0.1", 0)))
            .map_err(|e| format!("Kein freier Port: {e}"))?,
    };
    let port = server
        .server_addr()
        .to_ip()
        .map(|a| a.port())
        .ok_or("Serveradresse nicht ermittelbar")?;
    let state = Arc::new(State {
        token: util::random_token(),
        port,
        report: Mutex::new(None),
        building: Mutex::new(()),
        scan: Arc::new(ScanJob::default()),
        dns: Mutex::new(HashMap::new()),
    });
    let url = format!("http://127.0.0.1:{port}/?t={}", state.token);
    println!("Sicherheits-Dashboard läuft (nur auf diesem Rechner erreichbar):\n\n  {url}\n\nBeenden mit Strg+C.");
    if open {
        if let Some(x) = util::which("xdg-open") {
            let _ = std::process::Command::new(x)
                .arg(&url)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
        }
    }

    let server = Arc::new(server);
    let workers: Vec<_> = (0..6)
        .map(|_| {
            let server = server.clone();
            let state = state.clone();
            std::thread::spawn(move || loop {
                match server.recv() {
                    Ok(req) => handle(req, &state),
                    Err(_) => break,
                }
            })
        })
        .collect();
    for w in workers {
        let _ = w.join();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_query() {
        let q = query("/api/resolve?ip=2a00%3A1450%3A%3A1&x");
        assert_eq!(q.get("ip").map(String::as_str), Some("2a00:1450::1"));
        assert!(q.contains_key("x"));
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
    }

    #[test]
    fn compares_tokens() {
        assert!(token_ok("abc", "abc"));
        assert!(!token_ok("abd", "abc"));
        assert!(!token_ok("", "abc"));
    }
}
