//! Country and network operator of an IP address, from an offline database.
//!
//! The databases (DB-IP "lite", CC BY 4.0) are downloaded once on request;
//! every lookup afterwards is local.

#![cfg_attr(not(feature = "gui"), allow(dead_code))]

use crate::util;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Geo {
    pub country_code: String,
    pub country: String,
    pub org: String,
}

impl Geo {
    /// Compact form for tight places, e.g. "Google LLC · US".
    pub fn short(&self) -> String {
        [self.org.as_str(), self.country_code.as_str()]
            .iter()
            .filter(|s| !s.is_empty())
            .copied()
            .collect::<Vec<_>>()
            .join(" · ")
    }

    /// e.g. "Google LLC · Vereinigte Staaten von Amerika"
    pub fn label(&self) -> String {
        [self.org.as_str(), self.country.as_str()]
            .iter()
            .filter(|s| !s.is_empty())
            .copied()
            .collect::<Vec<_>>()
            .join(" · ")
    }
}

#[derive(Deserialize)]
struct CountryInner {
    iso_code: Option<String>,
    names: Option<BTreeMap<String, String>>,
}

#[derive(Deserialize)]
struct CountryRecord {
    country: Option<CountryInner>,
}

#[derive(Deserialize)]
struct AsnRecord {
    autonomous_system_organization: Option<String>,
}

struct Db {
    country: Option<maxminddb::Reader<Vec<u8>>>,
    asn: Option<maxminddb::Reader<Vec<u8>>>,
}

static DB: Mutex<Option<Arc<Db>>> = Mutex::new(None);

fn file(kind: &str) -> PathBuf {
    util::data_dir().join(format!("dbip-{kind}.mmdb"))
}

fn db() -> Arc<Db> {
    let mut guard = DB.lock().unwrap();
    if let Some(db) = guard.as_ref() {
        return db.clone();
    }
    let db = Arc::new(Db {
        country: maxminddb::Reader::open_readfile(file("country")).ok(),
        asn: maxminddb::Reader::open_readfile(file("asn")).ok(),
    });
    *guard = Some(db.clone());
    db
}

pub fn available() -> bool {
    file("country").exists() || file("asn").exists()
}

/// Age of the database in days.
pub fn age_days() -> Option<u64> {
    util::age_days(file("country")).or_else(|| util::age_days(file("asn")))
}

pub fn lookup(ip: IpAddr) -> Option<Geo> {
    let db = db();
    let mut geo = Geo::default();
    if let Some(r) = &db.country {
        if let Ok(Some(rec)) = r.lookup(ip).and_then(|l| l.decode::<CountryRecord>()) {
            if let Some(c) = rec.country {
                geo.country_code = c.iso_code.unwrap_or_default();
                let names = c.names.unwrap_or_default();
                geo.country = names.get("de").or_else(|| names.get("en")).cloned().unwrap_or_else(|| geo.country_code.clone());
            }
        }
    }
    if let Some(r) = &db.asn {
        if let Ok(Some(rec)) = r.lookup(ip).and_then(|l| l.decode::<AsnRecord>()) {
            geo.org = rec.autonomous_system_organization.unwrap_or_default();
        }
    }
    (geo != Geo::default()).then_some(geo)
}

/// Download both databases from db-ip.com (this month's files, else last month's).
pub fn download() -> Result<String, String> {
    let dir = util::data_dir();
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let months = [util::date("+%Y-%m"), util::date("--date=-25 days +%Y-%m")];
    let mut total = 0;
    for kind in ["country", "asn"] {
        let gz = dir.join(format!("dbip-{kind}.mmdb.gz"));
        let gz_str = gz.display().to_string();
        let ok = months.iter().filter(|m| !m.is_empty()).any(|month| {
            let url = format!("https://download.db-ip.com/free/dbip-{kind}-lite-{month}.mmdb.gz");
            util::run("curl", &["-fsSL", "--max-time", "120", "-o", &gz_str, &url], 130)
                .map(|o| o.ok)
                .unwrap_or(false)
        });
        if !ok {
            let _ = std::fs::remove_file(&gz);
            return Err(format!("Die Datei dbip-{kind}-lite konnte nicht von db-ip.com geladen werden."));
        }
        // gzip -df replaces dbip-<kind>.mmdb with the unpacked download.
        if !util::run("gzip", &["-df", &gz_str], 60).map(|o| o.ok).unwrap_or(false) {
            return Err(format!("dbip-{kind} konnte nicht entpackt werden."));
        }
        // Reject anything that is not a readable database.
        if maxminddb::Reader::open_readfile(file(kind)).is_err() {
            let _ = std::fs::remove_file(file(kind));
            return Err(format!("dbip-{kind} ist keine gültige Datenbank."));
        }
        total += std::fs::metadata(file(kind)).map(|m| m.len()).unwrap_or(0);
    }
    *DB.lock().unwrap() = None; // reload on next lookup
    Ok(format!("Datenbank geladen ({}).", util::format_bytes(total)))
}
