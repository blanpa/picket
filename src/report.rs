//! Standalone HTML export of a report.

use crate::i18n::tr;
use crate::model::{Category, Report, Status};

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn class(s: Status) -> &'static str {
    match s {
        Status::Crit => "crit",
        Status::Warn => "warn",
        Status::Unknown => "unknown",
        Status::Info => "info",
        Status::Ok => "ok",
    }
}

/// The report as a page of its own, in the interface language.
pub fn html(r: &Report, created: &str) -> String {
    let r = &r.localized();
    let title = tr("Sicherheitsbericht");
    let mut h = format!(
        "<!doctype html><html lang=\"{}\"><head><meta charset=\"utf-8\"><title>{title}</title><style>",
        if crate::i18n::german() { "de" } else { "en" }
    );
    h.push_str(
        "body{font:15px/1.5 system-ui,sans-serif;max-width:900px;margin:32px auto;padding:0 16px;color:#1c2330}\
         h1{margin:0}h2{margin:32px 0 8px;border-bottom:1px solid #d5dae1;padding-bottom:4px}\
         .f{border-left:4px solid var(--c);padding:6px 12px;margin:10px 0;background:#f6f7f9;break-inside:avoid}\
         .b{font-size:11px;font-weight:700;text-transform:uppercase;color:var(--c)}\
         .crit{--c:#c62828}.warn{--c:#a35a00}.info{--c:#1f5fbf}.ok{--c:#1b7a43}.unknown{--c:#6b5b95}\
         pre{white-space:pre-wrap;background:#eceff3;padding:8px;margin:6px 0;font-size:13px}.m{color:#5d6b7a}\
         </style></head><body>",
    );
    h += &format!(
        "<h1>{title}</h1><p class=\"m\">{} · {} · Kernel {} · BIOS {}<br>{} {}</p>",
        esc(&r.host.model),
        esc(&r.host.os),
        esc(&r.host.kernel),
        esc(&r.host.bios),
        tr("Erstellt am"),
        esc(created)
    );
    h += &tr(&format!(
        "<p><b>{}</b> kritisch · <b>{}</b> Warnungen · <b>{}</b> unklar · <b>{}</b> Hinweise · <b>{}</b> in Ordnung</p>",
        r.counts.crit, r.counts.warn, r.counts.unknown, r.counts.info, r.counts.ok
    ));
    for cat in Category::ALL {
        let items: Vec<_> = r.findings.iter().filter(|f| f.category == cat).collect();
        if items.is_empty() {
            continue;
        }
        h += &format!("<h2>{}</h2>", esc(&tr(cat.label())));
        for f in items {
            h += &format!(
                "<div class=\"f {}\"><span class=\"b\">{}</span> <b>{}</b><br>{}",
                if f.accepted { "ok" } else { class(f.status) },
                tr(if f.accepted { "AKZEPTIERT" } else { f.status.label() }),
                esc(&f.title),
                esc(&f.summary)
            );
            if !f.details.is_empty() {
                h += &format!("<pre>{}</pre>", esc(&f.details.join("\n")));
            }
            if !f.fix.is_empty() {
                h += &format!("<div><b>{}</b> {}</div>", tr("Empfehlung:"), esc(&f.fix));
            }
            if !f.commands.is_empty() {
                h += &format!("<pre>{}</pre>", esc(&f.commands.join("\n")));
            }
            h += "</div>";
        }
    }
    h += "</body></html>";
    h
}
