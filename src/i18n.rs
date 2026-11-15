//! Interface language.
//!
//! The German text in the source is the original. When the system language is
//! not German, text is translated to English at the point where it is shown,
//! using the table in `i18n_en.rs`. A table entry is either a fixed string or
//! a format template such as `"{} Dateien geprüft"`: a template is matched
//! against the finished German sentence, the values are picked out and put
//! into the English template.
//!
//! Anything without an entry is shown as it is, so a missing translation
//! degrades to German instead of breaking.

use crate::i18n_en::TABLE;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

/// Is the interface language German? `PICKET_LANG=de|en` overrides the system setting.
pub fn german() -> bool {
    // Tests compare against the German originals, whatever the machine's language.
    if cfg!(test) {
        return true;
    }
    static GERMAN: OnceLock<bool> = OnceLock::new();
    *GERMAN.get_or_init(|| {
        let pick = ["PICKET_LANG", "LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"]
            .iter()
            .filter_map(|v| std::env::var(v).ok())
            .find(|v| !v.is_empty() && v != "C" && v != "POSIX");
        // LANGUAGE is a priority list ("de_DE:en"): the first entry decides.
        pick.map(|v| v.split(':').next().unwrap_or("").to_ascii_lowercase().starts_with("de")).unwrap_or(false)
    })
}

/// One piece of a format template.
#[derive(Debug, PartialEq)]
enum Part {
    Text(String),
    /// A placeholder, kept as written between the braces ("", "n", ":>4", "0").
    Hole(String),
}

fn parse(template: &str) -> Vec<Part> {
    let mut parts = Vec::new();
    let mut text = String::new();
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' if chars.peek() == Some(&'{') => {
                chars.next();
                text.push('{');
            }
            '}' if chars.peek() == Some(&'}') => {
                chars.next();
                text.push('}');
            }
            '{' => {
                let mut hole = String::new();
                for h in chars.by_ref() {
                    if h == '}' {
                        break;
                    }
                    hole.push(h);
                }
                parts.push(Part::Text(std::mem::take(&mut text)));
                parts.push(Part::Hole(hole));
            }
            _ => text.push(c),
        }
    }
    parts.push(Part::Text(text));
    merge_adjacent(parts)
}

/// Placeholders that touch ("{}{more}") cannot be told apart in a finished sentence:
/// they count as one, filled by one value.
fn merge_adjacent(parts: Vec<Part>) -> Vec<Part> {
    let mut out: Vec<Part> = Vec::with_capacity(parts.len());
    for part in parts {
        if let Part::Hole(h) = &part {
            let n = out.len();
            if n >= 2 && matches!(&out[n - 1], Part::Text(t) if t.is_empty()) && matches!(out[n - 2], Part::Hole(_)) {
                out.pop();
                if let Some(Part::Hole(previous)) = out.last_mut() {
                    previous.push('+');
                    previous.push_str(h);
                }
                continue;
            }
        }
        out.push(part);
    }
    out
}

struct Pattern {
    /// Literal text around the placeholders: one more entry than there are placeholders.
    texts: Vec<String>,
    /// English pieces: text, or the index of the captured value.
    english: Vec<Result<String, usize>>,
    /// Length of the literal text; the most specific pattern wins.
    weight: usize,
}

impl Pattern {
    fn new(german: &str, english: &str) -> Option<Pattern> {
        let parts = parse(german);
        let holes: Vec<&String> = parts.iter().filter_map(|p| if let Part::Hole(h) = p { Some(h) } else { None }).collect();
        if holes.is_empty() {
            return None;
        }
        let texts: Vec<String> = parts.iter().filter_map(|p| if let Part::Text(t) = p { Some(t.clone()) } else { None }).collect();
        // English placeholders refer to the German ones by number ("{1}"), by the same
        // name or format ("{n}"), or simply by position.
        let mut used = vec![false; holes.len()];
        let mut position = 0;
        let english = parse(english)
            .into_iter()
            .map(|p| match p {
                Part::Text(t) => Ok(t),
                Part::Hole(h) => {
                    let index = h
                        .parse::<usize>()
                        .ok()
                        .filter(|i| *i < holes.len())
                        .or_else(|| (0..holes.len()).find(|i| !used[*i] && *holes[*i] == h && !h.is_empty()))
                        .unwrap_or_else(|| {
                            while position < holes.len() - 1 && used[position] {
                                position += 1;
                            }
                            position
                        });
                    used[index] = true;
                    Err(index)
                }
            })
            .collect();
        Some(Pattern { weight: texts.iter().map(|t| t.chars().count()).sum(), texts, english })
    }

    /// The values behind the placeholders, if `s` was built from this template.
    fn capture<'a>(&self, s: &'a str) -> Option<Vec<&'a str>> {
        let (first, last) = (&self.texts[0], &self.texts[self.texts.len() - 1]);
        if s.len() < first.len() + last.len() || !s.starts_with(first.as_str()) || !s.ends_with(last.as_str()) {
            return None;
        }
        let mut rest = &s[first.len()..s.len() - last.len()];
        let mut values = Vec::with_capacity(self.texts.len() - 1);
        for text in &self.texts[1..self.texts.len() - 1] {
            let at = rest.find(text.as_str())?;
            values.push(&rest[..at]);
            rest = &rest[at + text.len()..];
        }
        values.push(rest);
        Some(values)
    }
}

struct Dictionary {
    exact: HashMap<&'static str, &'static str>,
    patterns: Vec<Pattern>,
    /// Entries that are the end of a sentence built elsewhere (" (offline)", ", Verbindungsende"):
    /// fixed ones, longest first, and the indexes of the patterns among them.
    tails: Vec<(&'static str, &'static str)>,
    tail_patterns: Vec<usize>,
}

/// Does this text continue another one?
fn is_tail(text: &str) -> bool {
    text.starts_with([' ', ','])
}

fn dictionary() -> &'static Dictionary {
    static DICT: OnceLock<Dictionary> = OnceLock::new();
    DICT.get_or_init(|| {
        let mut exact = HashMap::new();
        let mut patterns = Vec::new();
        for (german, english) in TABLE {
            match Pattern::new(german, english) {
                Some(p) if p.weight >= 3 => patterns.push(p),
                Some(_) => {} // too little text to recognise a sentence by
                None => {
                    exact.insert(*german, *english);
                }
            }
        }
        patterns.sort_by(|a, b| b.weight.cmp(&a.weight));
        let mut tails: Vec<(&str, &str)> = exact.iter().filter(|(g, _)| is_tail(g)).map(|(g, e)| (*g, *e)).collect();
        tails.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then(a.0.cmp(b.0)));
        let tail_patterns = (0..patterns.len()).filter(|i| is_tail(&patterns[*i].texts[0])).collect();
        Dictionary { exact, patterns, tails, tail_patterns }
    })
}

fn translate(s: &str, depth: u8) -> String {
    let dict = dictionary();
    if let Some(e) = dict.exact.get(s) {
        return e.to_string();
    }
    if depth >= 4 || s.len() < 4 {
        return s.to_string();
    }
    // The values may be German fragments themselves ("3 Pakete sind").
    let fill = |p: &Pattern, values: Vec<&str>| -> String {
        p.english
            .iter()
            .map(|piece| match piece {
                Ok(text) => text.clone(),
                Err(i) => translate(values[*i], depth + 1),
            })
            .collect()
    };
    for p in &dict.patterns {
        if let Some(values) = p.capture(s) {
            return fill(p, values);
        }
    }
    // Several lines: translate each on its own.
    if s.contains('\n') {
        return s.split('\n').map(|line| translate(line, depth + 1)).collect::<Vec<_>>().join("\n");
    }
    // Padding around the text, as in a table column.
    let core = s.trim();
    if core.len() != s.len() {
        let start = s.len() - s.trim_start().len();
        return format!("{}{}{}", &s[..start], translate(core, depth + 1), &s[start + core.len()..]);
    }
    // A known ending on a sentence built elsewhere: "…, Verbindungsende", "… (Stufe 3)".
    for (german, english) in &dict.tails {
        if s.len() > german.len() && s.ends_with(german) {
            return translate(&s[..s.len() - german.len()], depth + 1) + english;
        }
    }
    for p in dict.tail_patterns.iter().map(|i| &dict.patterns[*i]) {
        for (at, _) in s.match_indices(p.texts[0].as_str()).filter(|(at, _)| *at > 0) {
            if let Some(values) = p.capture(&s[at..]) {
                return translate(&s[..at], depth + 1) + &fill(p, values);
            }
        }
    }
    // Something in brackets at the end: "8081 (HTTP (alternativ))".
    if let Some((before, inside)) = s.strip_suffix(')').and_then(|rest| rest.split_once(" (")) {
        let (b, i) = (translate(before, depth + 1), translate(inside, depth + 1));
        if b != before || i != inside {
            return format!("{b} ({i})");
        }
    }
    // A list of short pieces: "Router, dieser Laptop" or "WLAN · 12 Geräte".
    for separator in [" · ", ", ", " – "] {
        if s.contains(separator) {
            let pieces: Vec<String> = s.split(separator).map(|piece| translate(piece, depth + 1)).collect();
            let joined = pieces.join(separator);
            if joined != s {
                return joined;
            }
        }
    }
    // A count in front: "3 Pakete sind".
    if let Some((count, rest)) = s.split_once(' ') {
        if !count.is_empty() && count.bytes().all(|b| b.is_ascii_digit()) {
            return format!("{count} {}", translate(rest, depth + 1));
        }
    }
    log_untranslated(s);
    s.to_string()
}

/// Development aid: with `PICKET_I18N_LOG=<file>`, every piece of text that has no
/// translation is appended to that file (names and addresses included).
fn log_untranslated(s: &str) {
    use std::io::Write;
    static PATH: OnceLock<Option<std::ffi::OsString>> = OnceLock::new();
    let Some(path) = PATH.get_or_init(|| std::env::var_os("PICKET_I18N_LOG").filter(|_| crate::util::uid() != 0)) else { return };
    if !s.chars().any(char::is_alphabetic) {
        return;
    }
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{}", s.replace('\n', "\\n"));
    }
}

/// The text in the interface language.
pub fn tr(s: &str) -> String {
    if german() || s.is_empty() {
        return s.to_string();
    }
    // The same rows are drawn again and again: remember the answers.
    static CACHE: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);
    let mut guard = CACHE.lock().unwrap();
    let cache = guard.get_or_insert_with(HashMap::new);
    if let Some(hit) = cache.get(s) {
        return hit.clone();
    }
    let out = translate(s, 0);
    if cache.len() > 20_000 {
        cache.clear();
    }
    cache.insert(s.to_string(), out.clone());
    out
}

/// A value as JSON, with every text in it in the interface language. Field names stay as they are.
pub fn json(value: &impl serde::Serialize, pretty: bool) -> serde_json::Result<String> {
    fn localize(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::String(s) => *s = tr(s),
            serde_json::Value::Array(items) => items.iter_mut().for_each(localize),
            serde_json::Value::Object(fields) => fields.values_mut().for_each(localize),
            _ => {}
        }
    }
    if german() {
        return if pretty { serde_json::to_string_pretty(value) } else { serde_json::to_string(value) };
    }
    let mut value = serde_json::to_value(value)?;
    localize(&mut value);
    if pretty { serde_json::to_string_pretty(&value) } else { serde_json::to_string(&value) }
}

/// `println!` in the interface language.
#[macro_export]
macro_rules! outln {
    () => { println!() };
    ($($arg:tt)*) => { println!("{}", $crate::i18n::tr(&format!($($arg)*))) };
}

/// `eprintln!` in the interface language.
#[macro_export]
macro_rules! errln {
    () => { eprintln!() };
    ($($arg:tt)*) => { eprintln!("{}", $crate::i18n::tr(&format!($($arg)*))) };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(german: &str, english: &str, s: &str) -> Option<String> {
        let p = Pattern::new(german, english)?;
        let values = p.capture(s)?;
        Some(p.english.iter().map(|piece| match piece { Ok(t) => t.clone(), Err(i) => values[*i].to_string() }).collect())
    }

    #[test]
    fn fills_english_templates_from_german_sentences() {
        assert_eq!(pattern("{} Dateien geprüft", "{} files checked", "12 Dateien geprüft").as_deref(), Some("12 files checked"));
        // by name, in a different order
        assert_eq!(
            pattern("{n} von {total} Snaps warten", "of {total} snaps, {n} are waiting", "4 von 76 Snaps warten").as_deref(),
            Some("of 76 snaps, 4 are waiting")
        );
        // by number
        assert_eq!(pattern("{} beendet {}", "{1}: {0} closed", "ssh beendet vor 3 min").as_deref(), Some("vor 3 min: ssh closed"));
        // format specifications and escaped braces do not matter
        assert_eq!(pattern("{:>4} Verbindungen {{aktiv}}", "{:>4} connections {{active}}", "  12 Verbindungen {aktiv}").as_deref(), Some("  12 connections {active}"));
        // the sentence must fit the template from start to end
        assert_eq!(pattern("{} Dateien geprüft", "{} files checked", "12 Dateien geprüft, 3 Funde"), None);
        assert_eq!(pattern("Port {} ist offen", "port {} is open", "Der Port 22 ist offen"), None);
        // placeholders that touch are filled as one
        assert_eq!(
            pattern("{} = {v} (erwartet {}{want}) – {m}", "{} = {v} (expected {}{want}) – {m}", "a.b = 0 (erwartet ≥ 1) – gut").as_deref(),
            Some("a.b = 0 (expected ≥ 1) – gut")
        );
        // nothing to hold on to
        assert_eq!(Pattern::new("{}{}", "{}{}").map(|p| p.weight), Some(0));
        assert!(Pattern::new("ohne Platzhalter", "no placeholder").is_none());
    }

    #[test]
    fn falls_back_to_the_parts_of_a_text() {
        // These go through the real table.
        assert_eq!(translate("  Übersicht   ", 0), "  Overview   ");
        assert_eq!(translate("3 Firmware-Updates", 0), "3 firmware updates");
        assert_eq!(translate("Router, dieser Laptop", 0), "Router, this laptop");
        assert_eq!(translate("Übersicht\nEinstellungen", 0), "Overview\nSettings");
        assert_eq!(translate("kein deutscher Tabelleneintrag", 0), "kein deutscher Tabelleneintrag");
        // known endings and brackets
        assert_eq!(translate("alle Netze – Docker umgeht die Firewall", 0), "all networks – Docker bypasses the firewall");
        assert_eq!(translate("Im RAM: enabled (Stufe 3)", 0), "Im RAM: enabled (level 3)");
        assert_eq!(translate("8081 (HTTP (alternativ))", 0), "8081 (HTTP (alternative))");
    }

    #[test]
    fn the_table_is_well_formed() {
        let mut seen = std::collections::HashSet::new();
        for (german, english) in TABLE {
            assert!(seen.insert(*german), "duplicate entry: {german}");
            let holes = |t: &str| parse(t).iter().filter(|p| matches!(p, Part::Hole(_))).count();
            assert_eq!(holes(german), holes(english), "placeholders differ: {german} / {english}");
        }
    }
}
