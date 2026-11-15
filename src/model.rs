//! Data model shared by the checks, the CLI output and the dashboard API.

use serde::{Deserialize, Serialize};

/// Ordered by urgency: the derived `Ord` is used for sorting.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Crit,
    Warn,
    Unknown,
    Info,
    Ok,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::Crit => "KRITISCH",
            Status::Warn => "WARNUNG",
            Status::Unknown => "UNKLAR",
            Status::Info => "HINWEIS",
            Status::Ok => "OK",
        }
    }
}

#[derive(Serialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    Firewall,
    Network,
    Docker,
    Antivirus,
    Software,
    System,
    Access,
}

impl Category {
    pub const ALL: [Category; 7] = [
        Category::Firewall,
        Category::Network,
        Category::Docker,
        Category::Antivirus,
        Category::Software,
        Category::System,
        Category::Access,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Category::Firewall => "Firewall",
            Category::Network => "Netzwerk",
            Category::Docker => "Docker",
            Category::Antivirus => "Virenscanner",
            Category::Software => "Programme & Updates",
            Category::System => "System & Firmware",
            Category::Access => "Konten & Zugang",
        }
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct Finding {
    pub id: String,
    pub category: Category,
    pub title: String,
    pub status: Status,
    /// One-line result.
    pub summary: String,
    /// Evidence lines (what was actually found on this machine).
    pub details: Vec<String>,
    /// Why this matters.
    pub why: String,
    /// What to do about it.
    pub fix: String,
    pub commands: Vec<String>,
    /// The user has accepted this finding as it is; it no longer counts or alerts.
    #[serde(default)]
    pub accepted: bool,
}

impl Finding {
    pub fn new(id: &str, category: Category, title: &str) -> Self {
        Finding {
            id: id.to_string(),
            category,
            title: title.to_string(),
            status: Status::Unknown,
            summary: String::new(),
            details: Vec::new(),
            why: String::new(),
            fix: String::new(),
            commands: Vec::new(),
            accepted: false,
        }
    }

    pub fn set(mut self, status: Status, summary: impl Into<String>) -> Self {
        self.status = status;
        self.summary = summary.into();
        self
    }

    pub fn detail(mut self, d: impl Into<String>) -> Self {
        self.details.push(d.into());
        self
    }

    pub fn details<I, S>(mut self, it: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.details.extend(it.into_iter().map(Into::into));
        self
    }

    pub fn why(mut self, w: &str) -> Self {
        self.why = w.to_string();
        self
    }

    pub fn fix_cmds(mut self, text: &str, cmds: Vec<String>) -> Self {
        self.fix = text.to_string();
        self.commands = cmds;
        self
    }

    pub fn fix(mut self, text: &str, cmds: &[&str]) -> Self {
        self.fix = text.to_string();
        self.commands = cmds.iter().map(|c| c.to_string()).collect();
        self
    }

    /// A copy in the interface language, for showing. Findings themselves stay in the
    /// original German, so that what is stored (accepted findings, watcher state) does
    /// not depend on the language.
    pub fn localized(&self) -> Finding {
        use crate::i18n::tr;
        Finding {
            title: tr(&self.title),
            summary: tr(&self.summary),
            details: self.details.iter().map(|d| tr(d)).collect(),
            why: tr(&self.why),
            fix: tr(&self.fix),
            commands: self.commands.iter().map(|c| tr(c)).collect(),
            ..self.clone()
        }
    }
}

#[derive(Serialize, Clone, Default)]
pub struct HostInfo {
    pub hostname: String,
    pub model: String,
    pub bios: String,
    pub cpu: String,
    pub os: String,
    pub kernel: String,
}

#[derive(Serialize, Clone, Default)]
pub struct Counts {
    pub crit: usize,
    pub warn: usize,
    pub unknown: usize,
    pub info: usize,
    pub ok: usize,
    /// Accepted findings are counted here instead of under their status.
    #[serde(default)]
    pub accepted: usize,
}

/// Count findings by status; accepted ones are counted separately.
pub fn tally(findings: &[Finding]) -> Counts {
    let mut counts = Counts::default();
    for f in findings {
        if f.accepted {
            counts.accepted += 1;
            continue;
        }
        match f.status {
            Status::Crit => counts.crit += 1,
            Status::Warn => counts.warn += 1,
            Status::Unknown => counts.unknown += 1,
            Status::Info => counts.info += 1,
            Status::Ok => counts.ok += 1,
        }
    }
    counts
}

#[derive(Serialize, Clone)]
pub struct PrivInfo {
    pub available: bool,
    pub created: Option<u64>,
    pub command: String,
}

#[derive(Serialize, Clone)]
pub struct Report {
    pub generated: u64,
    pub duration_ms: u64,
    pub host: HostInfo,
    pub counts: Counts,
    pub privileged: PrivInfo,
    pub findings: Vec<Finding>,
}

impl Report {
    /// The report in the interface language (see `Finding::localized`).
    pub fn localized(&self) -> Report {
        Report { findings: self.findings.iter().map(Finding::localized).collect(), ..self.clone() }
    }
}
