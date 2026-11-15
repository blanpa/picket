//! Native GTK4/libadwaita window.
//!
//! The window only displays data. Checks, network snapshots and scans run in
//! background threads so the interface never blocks.

use crate::model::{Category, Finding, Report, Status};
use crate::net::{self, Exposure, NetSnapshot, Zone};
use crate::i18n::tr;
use crate::scan::{self, ScanInfo, ScanJob};
use crate::session::{self, Session};
use crate::{accept, blocklist, capture, checks, deep, devices, docker, fixes, fwctl, geo, graph, helper, history, osv, pcap, privileged, report, tray, util, watch, APP_ID};
use adw::prelude::*;
use gtk::{gio, glib};
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const CSS: &str = "
.fw-stat { padding: 14px 16px; }
.fw-cards > flowboxchild { padding: 0; }
.fw-cards > flowboxchild:hover, .fw-cards > flowboxchild:focus { background: none; outline: none; }
.fw-clickable > flowboxchild:hover .card { background-color: alpha(currentColor, 0.09); }
.fw-stat.fw-selected { box-shadow: inset 0 0 0 2px @accent_color; }
.fw-stat .fw-number { font-size: 26pt; font-weight: 800; }
.fw-tag { padding: 2px 10px; border-radius: 99px; font-size: 0.82em; font-weight: 700; }
.fw-tag.error { color: @error_color; background: alpha(@error_color, 0.14); }
.fw-tag.warning { color: @warning_color; background: alpha(@warning_color, 0.16); }
.fw-tag.success { color: @success_color; background: alpha(@success_color, 0.14); }
.fw-tag.accent { color: @accent_color; background: alpha(@accent_color, 0.14); }
.fw-unknown, .fw-z-internet { color: #9141ac; }
.fw-tag.fw-unknown, .fw-tag.fw-z-internet { background: alpha(#9141ac, 0.16); }
.fw-z-lan { color: #1c8f96; }
.fw-tag.fw-z-lan { background: alpha(#1c8f96, 0.16); }
.fw-z-vpn { color: #3584e4; }
.fw-tag.fw-z-vpn { background: alpha(#3584e4, 0.16); }
.fw-z-container { color: #a5732a; }
.fw-tag.fw-z-container { background: alpha(#a5732a, 0.18); }
.fw-z-loopback { color: alpha(currentColor, 0.65); }
.fw-tag.fw-z-loopback { background: alpha(currentColor, 0.10); }
.fw-dark .fw-unknown, .fw-dark .fw-z-internet { color: #dc8add; }
.fw-dark .fw-tag.fw-unknown, .fw-dark .fw-tag.fw-z-internet { background: alpha(#dc8add, 0.18); }
.fw-dark .fw-z-lan { color: #5fd3d9; }
.fw-dark .fw-tag.fw-z-lan { background: alpha(#5fd3d9, 0.16); }
.fw-dark .fw-z-vpn { color: #99c1f1; }
.fw-dark .fw-tag.fw-z-vpn { background: alpha(#99c1f1, 0.16); }
.fw-dark .fw-z-container { color: #e6c07b; }
.fw-dark .fw-tag.fw-z-container { background: alpha(#e6c07b, 0.16); }
.fw-badge { min-width: 18px; padding: 0 6px; border-radius: 99px; font-size: 0.8em; font-weight: 700; }
.fw-badge.error { color: white; background: @error_bg_color; }
.fw-badge.warning { color: black; background: @warning_bg_color; }
";

/// (stack name, title, icon, category, sidebar section)
const PAGES: [(&str, &str, &str, Option<Category>, &str); 13] = [
    ("overview", "Übersicht", "go-home-symbolic", None, ""),
    ("firewall", "Firewall", "security-high-symbolic", Some(Category::Firewall), "Schutz"),
    ("antivirus", "Virenscanner", "security-medium-symbolic", Some(Category::Antivirus), "Schutz"),
    ("software", "Programme & Updates", "software-update-available-symbolic", Some(Category::Software), "Schutz"),
    ("system", "System & Firmware", "computer-symbolic", Some(Category::System), "Schutz"),
    ("access", "Konten & Zugang", "system-users-symbolic", Some(Category::Access), "Schutz"),
    ("network", "Verbindungen", "network-workgroup-symbolic", Some(Category::Network), "Netzwerk"),
    ("devices", "Geräte im Netz", "network-wired-symbolic", None, "Netzwerk"),
    ("capture", "Mitschnitt", "media-record-symbolic", None, "Netzwerk"),
    ("docker", "Docker", "application-x-executable-symbolic", Some(Category::Docker), "Netzwerk"),
    ("deep", "Tiefenprüfung", "system-search-symbolic", None, "Werkzeuge"),
    ("history", "Verlauf", "document-open-recent-symbolic", None, "Werkzeuge"),
    ("settings", "Einstellungen", "preferences-system-symbolic", None, "Werkzeuge"),
];

const ZONES: [(Zone, &str, &str, &str); 5] = [
    (Zone::Internet, "Internet", "Server außerhalb deines Netzes", "fw-z-internet"),
    (Zone::Lan, "Lokales Netz", "Router, NAS, Drucker, andere Geräte", "fw-z-lan"),
    (Zone::Vpn, "VPN", "Tailscale, WireGuard & Co.", "fw-z-vpn"),
    (Zone::Container, "Container / VM", "Docker, virtuelle Maschinen", "fw-z-container"),
    (Zone::Loopback, "Nur dieser Rechner", "Programme untereinander", "fw-z-loopback"),
];

static NO_NAMES: std::sync::LazyLock<HashMap<String, Option<String>>> = std::sync::LazyLock::new(HashMap::new);

fn zone_meta(z: Zone) -> (&'static str, &'static str) {
    ZONES.iter().find(|m| m.0 == z).map(|m| (m.1, m.3)).unwrap_or(("?", "fw-z-loopback"))
}

fn status_style(s: Status) -> (&'static str, &'static str, &'static str) {
    match s {
        Status::Crit => ("dialog-error-symbolic", "error", "Kritisch"),
        Status::Warn => ("dialog-warning-symbolic", "warning", "Warnung"),
        Status::Unknown => ("dialog-question-symbolic", "fw-unknown", "Unklar"),
        Status::Info => ("dialog-information-symbolic", "accent", "Hinweis"),
        Status::Ok => ("object-select-symbolic", "success", "OK"),
    }
}

fn exposure_style(e: Exposure) -> (&'static str, &'static str) {
    match e {
        Exposure::All => ("Alle Netze", "error"),
        Exposure::Lan => ("Lokales Netz", "warning"),
        Exposure::Vpn => ("VPN", "fw-z-vpn"),
        Exposure::Container => ("Container / VM", "fw-z-container"),
        Exposure::Loopback => ("Nur lokal", "success"),
    }
}

/// Local time in the given strftime format, e.g. "%d.%m. %H:%M".
fn clock_fmt(epoch: u64, format: &str) -> String {
    glib::DateTime::from_unix_local(epoch as i64)
        .ok()
        .and_then(|d| d.format(format).ok())
        .map(|s| s.to_string())
        .unwrap_or_default()
}

/// A list of choices in the interface language.
fn string_list(items: &[&str]) -> gtk::StringList {
    let translated: Vec<String> = items.iter().map(|s| tr(s)).collect();
    gtk::StringList::new(&translated.iter().map(String::as_str).collect::<Vec<_>>())
}

fn clock(epoch: u64) -> String {
    glib::DateTime::from_unix_local(epoch as i64)
        .ok()
        .and_then(|d| d.format("%H:%M").ok())
        .map(|s| s.to_string())
        .unwrap_or_default()
}

// ------------------------------------------------------------------ widgets

fn tag(text: &str, css: &str) -> gtk::Label {
    let l = gtk::Label::new(Some(tr(text).as_str()));
    l.add_css_class("fw-tag");
    l.add_css_class(css);
    l.set_valign(gtk::Align::Center);
    l
}

/// A full-width text block inside an expander row.
fn text_row(text: &str, classes: &[&str], selectable: bool) -> gtk::ListBoxRow {
    let label = gtk::Label::builder()
        .label(tr(text).as_str())
        .wrap(true)
        .wrap_mode(gtk::pango::WrapMode::WordChar)
        .xalign(0.0)
        .selectable(selectable)
        .margin_top(10)
        .margin_bottom(10)
        .margin_start(14)
        .margin_end(14)
        .build();
    for c in classes {
        label.add_css_class(c);
    }
    gtk::ListBoxRow::builder().child(&label).activatable(false).selectable(false).build()
}

fn command_row(cmd: &str, toasts: &adw::ToastOverlay) -> adw::ActionRow {
    let row = adw::ActionRow::new();
    row.set_use_markup(false);
    row.set_title(tr(cmd).as_str());
    row.set_title_lines(0);
    row.add_css_class("monospace");
    let btn = gtk::Button::from_icon_name("edit-copy-symbolic");
    btn.add_css_class("flat");
    btn.set_valign(gtk::Align::Center);
    btn.set_tooltip_text(Some(tr("Befehl kopieren").as_str()));
    let (cmd, toasts) = (cmd.to_string(), toasts.clone());
    btn.connect_clicked(move |b| {
        b.clipboard().set_text(&cmd);
        toasts.add_toast(adw::Toast::new(tr("Befehl in die Zwischenablage kopiert").as_str()));
    });
    row.add_suffix(&btn);
    row.set_activatable_widget(Some(&btn));
    row
}

/// What the buttons inside a finding do.
struct RowActions {
    /// Start the automatic fix for a finding id.
    fix: Rc<dyn Fn(String)>,
    /// Accept a finding in its current state (id, summary), or report it again (None).
    accept: Rc<dyn Fn(String, Option<String>)>,
}

fn finding_row(f: &Finding, toasts: &adw::ToastOverlay, actions: Option<&RowActions>) -> adw::ExpanderRow {
    let (icon, css, label) = if f.accepted { ("object-select-symbolic", "fw-z-loopback", "Akzeptiert") } else { status_style(f.status) };
    let row = adw::ExpanderRow::new();
    row.set_use_markup(false);
    row.set_title(tr(&f.title).as_str());
    row.set_subtitle(tr(&f.summary).as_str());
    let img = gtk::Image::from_icon_name(icon);
    img.add_css_class(css);
    row.add_prefix(&img);
    row.add_suffix(&tag(label, css));
    if !f.why.is_empty() {
        row.add_row(&text_row(&f.why, &[], false));
    }
    if !f.details.is_empty() {
        row.add_row(&text_row(&f.details.join("\n"), &["monospace", "caption"], true));
    }
    if !f.fix.is_empty() {
        row.add_row(&text_row(&format!("Empfehlung: {}", f.fix), &["heading"], false));
    }
    for c in &f.commands {
        row.add_row(&command_row(c, toasts));
    }
    let urgent = matches!(f.status, Status::Crit | Status::Warn | Status::Unknown);
    let fixable = !f.accepted && matches!(f.status, Status::Crit | Status::Warn) && (f.id == "fw.active" || fixes::for_finding(&f.id).is_some());
    if let (true, Some(actions)) = (urgent, actions) {
        // A conscious decision should not nag forever.
        let (title, subtitle, button) = if f.accepted {
            ("Akzeptiert", "Zählt und meldet nicht mehr, solange sich der Befund nicht ändert.", "Wieder melden")
        } else {
            ("Bewusst so lassen", "Zählt und meldet dann nicht mehr – bis sich der Befund ändert.", "Akzeptieren")
        };
        let accept_row = info_row(title, subtitle);
        let btn = gtk::Button::with_label(tr(button).as_str());
        btn.set_valign(gtk::Align::Center);
        let (accept, id, summary) = (actions.accept.clone(), f.id.clone(), (!f.accepted).then(|| f.summary.clone()));
        btn.connect_clicked(move |_| accept(id.clone(), summary.clone()));
        accept_row.add_suffix(&btn);
        row.add_row(&accept_row);
    }
    if let (true, Some(on_fix)) = (fixable, actions.map(|a| &a.fix)) {
        let fix_row = info_row("Automatisch beheben", "Du siehst vorher, was genau ausgeführt wird.");
        let btn = gtk::Button::with_label(tr("Beheben …").as_str());
        btn.add_css_class("suggested-action");
        btn.set_valign(gtk::Align::Center);
        let (on_fix, id) = (on_fix.clone(), f.id.clone());
        btn.connect_clicked(move |_| on_fix(id.clone()));
        fix_row.add_suffix(&btn);
        row.add_row(&fix_row);
    }
    if f.why.is_empty() && f.details.is_empty() && f.fix.is_empty() && !fixable && !(urgent && actions.is_some()) {
        row.set_enable_expansion(false);
    }
    row
}

fn info_row(title: &str, subtitle: &str) -> adw::ActionRow {
    let row = adw::ActionRow::new();
    row.set_use_markup(false);
    row.set_title(tr(title).as_str());
    row.set_subtitle(tr(subtitle).as_str());
    row
}

struct StatCard {
    root: gtk::Box,
    number: gtk::Label,
    sub: gtk::Label,
}

/// A row of stat cards that wraps onto several lines in a narrow window.
fn card_flow() -> gtk::FlowBox {
    let flow = gtk::FlowBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .homogeneous(true)
        .column_spacing(6)
        .row_spacing(6)
        .min_children_per_line(2)
        .max_children_per_line(5)
        .build();
    flow.add_css_class("fw-cards");
    flow
}

fn stat_card(caption: &str, css: &str) -> StatCard {
    let root = gtk::Box::new(gtk::Orientation::Vertical, 2);
    root.add_css_class("card");
    root.add_css_class("fw-stat");
    let number = gtk::Label::builder().label(tr("–").as_str()).xalign(0.0).build();
    number.add_css_class("fw-number");
    number.add_css_class(css);
    let cap = gtk::Label::builder().label(tr(caption).as_str()).xalign(0.0).wrap(true).max_width_chars(12).build();
    cap.add_css_class("heading");
    // A small natural width lets five cards share one line in a normal window.
    let sub = gtk::Label::builder().xalign(0.0).wrap(true).max_width_chars(15).build();
    sub.add_css_class("caption");
    sub.add_css_class("dim-label");
    sub.set_visible(false);
    root.append(&number);
    root.append(&cap);
    root.append(&sub);
    StatCard { root, number, sub }
}

/// A scrolling page of preference groups, wider than AdwPreferencesPage allows.
struct Page {
    scroller: gtk::ScrolledWindow,
    body: gtk::Box,
}

fn page() -> Page {
    let body = gtk::Box::new(gtk::Orientation::Vertical, 24);
    body.set_margin_top(24);
    body.set_margin_bottom(32);
    body.set_margin_start(16);
    body.set_margin_end(16);
    let clamp = adw::Clamp::builder().maximum_size(1160).tightening_threshold(760).child(&body).build();
    let scroller = gtk::ScrolledWindow::builder()
        .hscrollbar_policy(gtk::PolicyType::Never)
        .vexpand(true)
        .child(&clamp)
        .build();
    Page { scroller, body }
}

fn group(title: &str, description: Option<&str>) -> adw::PreferencesGroup {
    let g = adw::PreferencesGroup::new();
    g.set_title(tr(title).as_str());
    g.set_description(description.map(tr).as_deref());
    g
}

/// Turn a decoded packet into a list row. Returns None for traffic that never
/// leaves this machine (both ends are our own addresses).
fn capture_row(
    p: &pcap::Packet,
    local: &HashSet<IpAddr>,
    ports: &BTreeMap<String, String>,
    names: &HashMap<IpAddr, String>,
) -> Option<CapRow> {
    let is_local = |ip: &Option<IpAddr>| ip.map(|i| i.is_loopback() || local.contains(&i)).unwrap_or(false);
    if is_local(&p.src) && is_local(&p.dst) {
        return None;
    }
    let outgoing = if is_local(&p.src) {
        true
    } else if is_local(&p.dst) {
        false
    } else {
        p.outgoing.unwrap_or(false) // broadcast, multicast or forwarded traffic
    };
    let (remote_ip, remote_port, local_port) = if outgoing { (p.dst, p.dport, p.sport) } else { (p.src, p.sport, p.dport) };
    let remote = match remote_ip {
        Some(ip) => {
            let host = match names.get(&ip) {
                Some(name) => format!("{name} ({ip})"),
                None => ip.to_string(),
            };
            if remote_port > 0 {
                format!("{host} : {remote_port}")
            } else {
                host
            }
        }
        None => String::new(),
    };
    let secs = p.time.floor();
    let time = glib::DateTime::from_unix_local(secs as i64)
        .ok()
        .and_then(|d| d.format("%H:%M:%S").ok())
        .map(|s| format!("{s}.{:03}", ((p.time - secs) * 1000.0) as u32))
        .unwrap_or_default();
    Some(CapRow {
        remote_ip: remote_ip.map(|i| i.to_string()).unwrap_or_default(),
        length: p.length,
        time,
        direction: if outgoing { "→" } else { "←" },
        program: ports.get(&format!("{}/{local_port}", p.transport)).cloned().unwrap_or_default(),
        remote,
        proto: p.proto,
        size: format!("{} B", p.length),
        info: match &p.domain {
            Some(d) if blocklist::available() && blocklist::is_listed(d) => format!("⚠ Sperrliste · {}", p.info),
            _ => tr(&p.info),
        },
    })
}

// ----------------------------------------------------------------------- UI

struct NetView {
    cards: Vec<(Zone, gtk::Label, gtk::Label, gtk::Box)>,
    /// Zone chosen by clicking a card; None shows everything that leaves the laptop.
    zone: Cell<Option<Zone>>,
    /// Live-Bild / Programme / Offene Ports
    tabs: gtk::Stack,
    /// Everything seen since the window opened, including closed connections.
    session: RefCell<Session>,
    traffic: graph::Throughput,
    /// How long closed connections stay visible.
    keep: adw::ComboRow,
    ticks: Cell<u32>,
    stamp: gtk::Label,
    live: adw::SwitchRow,
    resolve: adw::SwitchRow,
    show_local: adw::SwitchRow,
    programs: adw::PreferencesGroup,
    ports: adw::PreferencesGroup,
    program_rows: RefCell<Vec<gtk::Widget>>,
    port_rows: RefCell<Vec<gtk::Widget>>,
    expanded: Rc<RefCell<HashSet<String>>>,
    names: Arc<Mutex<HashMap<String, Option<String>>>>,
    last: RefCell<Option<NetSnapshot>>,
    fingerprint: RefCell<String>,
    loading: Cell<bool>,
    resolving: Cell<bool>,
}

struct FwView {
    status: adw::ActionRow,
    toggle: gtk::Button,
    policy: adw::ComboRow,
    add: gtk::Button,
    rules: adw::PreferencesGroup,
    rule_rows: RefCell<Vec<gtk::Widget>>,
    domains: adw::PreferencesGroup,
    domain_entry: adw::EntryRow,
    domain_rows: RefCell<Vec<gtk::Widget>>,
    state: RefCell<fwctl::State>,
    /// Set while the controls are being filled in, so that does not count as a user change.
    updating: Cell<bool>,
}

struct DevView {
    body: gtk::Box,
    button: gtk::Button,
    spinner: gtk::Spinner,
    groups: RefCell<Vec<adw::PreferencesGroup>>,
    loading: Cell<bool>,
    loaded: Cell<bool>,
}

/// One line of the packet list.
/// What was exchanged with one remote address during a capture.
#[derive(Default)]
struct Talk {
    packets: u64,
    bytes: u64,
    protos: std::collections::BTreeSet<&'static str>,
}

struct CapRow {
    /// Remote address without name or port, for the summary.
    remote_ip: String,
    length: u32,
    time: String,
    direction: &'static str,
    program: String,
    remote: String,
    proto: &'static str,
    size: String,
    info: String,
}

enum CapMsg {
    Packets(Vec<pcap::Packet>, usize),
    Done { code: Option<i32>, stderr: String, invalid: bool },
}

const CAPTURE_ROWS: u32 = 5000;
const CAPTURE_FILE_LIMIT: u64 = 500 * 1024 * 1024;

struct CapView {
    /// Interface names matching the entries of `iface`; index 0 is "any".
    ifaces: Vec<String>,
    iface: adw::ComboRow,
    host: adw::EntryRow,
    port: adw::EntryRow,
    proto: adw::ComboRow,
    status: adw::ActionRow,
    button: gtk::Button,
    save: gtk::Button,
    block: gtk::Button,
    disconnect: gtk::Button,
    store: gio::ListStore,
    search: gtk::SearchEntry,
    talk: RefCell<HashMap<String, Talk>>,
    talk_group: adw::PreferencesGroup,
    talk_rows: RefCell<Vec<gtk::Widget>>,
    talk_rendered: Cell<u64>,
    /// Closing this pipe tells the root helper to stop.
    stdin: RefCell<Option<std::process::ChildStdin>>,
    running: Cell<bool>,
    packets: Cell<u64>,
    bytes: Cell<u64>,
    names: RefCell<HashMap<IpAddr, String>>,
    file: std::path::PathBuf,
}

struct Extras {
    watch: adw::SwitchRow,
    tray: adw::SwitchRow,
    autostart: adw::SwitchRow,
    geo: adw::ActionRow,
    blocklist: adw::ActionRow,
    updating: Cell<bool>,
}

struct DockerView {
    group: adw::PreferencesGroup,
    rows: RefCell<Vec<gtk::Widget>>,
    loading: Cell<bool>,
    /// Distinct images of the running containers, for the vulnerability scan.
    images: RefCell<Vec<String>>,
    scan_button: gtk::Button,
    scans: adw::PreferencesGroup,
    scan_rows: RefCell<Vec<gtk::Widget>>,
    scanning: Cell<bool>,
}

struct HistView {
    events: adw::PreferencesGroup,
    conns: adw::PreferencesGroup,
    day: adw::ComboRow,
    days: RefCell<Vec<String>>,
    event_rows: RefCell<Vec<gtk::Widget>>,
    conn_rows: RefCell<Vec<gtk::Widget>>,
    updating: Cell<bool>,
}

struct DeepView {
    status: adw::ActionRow,
    button: gtk::Button,
    spinner: gtk::Spinner,
    cve: adw::ActionRow,
    cve_button: gtk::Button,
    results: adw::PreferencesGroup,
    rows: RefCell<Vec<gtk::Widget>>,
    running: Cell<bool>,
}

struct ScanView {
    job: Arc<ScanJob>,
    targets: Vec<scan::Target>,
    group: adw::PreferencesGroup,
    target: adw::ComboRow,
    status: adw::ActionRow,
    spinner: gtk::Spinner,
    button: gtk::Button,
    found_rows: RefCell<Vec<gtk::Widget>>,
    available: bool,
}

pub struct Ui {
    window: adw::ApplicationWindow,
    sidebar: gtk::ListBox,
    toasts: adw::ToastOverlay,
    stack: gtk::Stack,
    banner: adw::Banner,
    refresh_btn: gtk::Button,
    spinner: gtk::Spinner,
    stamp: gtk::Label,
    badges: Vec<(Category, gtk::Label)>,
    counts: Vec<(Status, gtk::Label)>,
    device: [adw::ActionRow; 4],
    pages: HashMap<&'static str, gtk::Box>,
    /// Groups that are rebuilt for every report (findings per page).
    dynamic: RefCell<Vec<(gtk::Box, adw::PreferencesGroup)>>,
    net: NetView,
    graph: graph::Graph,
    fw: FwView,
    dev: DevView,
    cap: CapView,
    extras: Extras,
    docker: DockerView,
    hist: HistView,
    deep: DeepView,
    report: RefCell<Option<Report>>,
    scan: ScanView,
    busy: Cell<bool>,
    /// The icon in the top bar; None when the session has no D-Bus.
    tray: Option<tray::Tray>,
    /// Set when the program is to end, not just the window to be put away.
    quitting: Cell<bool>,
}

impl Ui {
    fn build(app: &adw::Application) -> Rc<Ui> {
        // ---- sidebar
        let list = gtk::ListBox::new();
        list.add_css_class("navigation-sidebar");
        list.set_selection_mode(gtk::SelectionMode::Single);
        let mut badges = Vec::new();
        for (_, title, icon, cat, _) in PAGES {
            let b = gtk::Box::new(gtk::Orientation::Horizontal, 12);
            b.set_margin_end(6);
            b.append(&gtk::Image::from_icon_name(icon));
            b.append(&gtk::Label::builder().label(tr(title).as_str()).xalign(0.0).hexpand(true).build());
            if let Some(cat) = cat {
                let badge = gtk::Label::new(None);
                badge.add_css_class("fw-badge");
                badge.set_valign(gtk::Align::Center);
                badge.set_visible(false);
                b.append(&badge);
                badges.push((cat, badge));
            }
            list.append(&gtk::ListBoxRow::builder().child(&b).build());
        }
        // Section headings between the groups of pages.
        list.set_header_func(|row, before| {
            let section = |r: &gtk::ListBoxRow| usize::try_from(r.index()).ok().and_then(|i| PAGES.get(i)).map(|p| p.4).unwrap_or("");
            let name = section(row);
            if !name.is_empty() && before.map(|b| section(b) != name).unwrap_or(true) {
                let label = gtk::Label::builder().label(tr(name).as_str()).xalign(0.0).margin_top(14).margin_bottom(4).margin_start(10).build();
                label.add_css_class("caption-heading");
                label.add_css_class("dim-label");
                row.set_header(Some(&label));
            } else {
                row.set_header(gtk::Widget::NONE);
            }
        });
        let menu = gio::Menu::new();
        menu.append(Some(tr("Neu prüfen").as_str()), Some("app.refresh"));
        menu.append(Some(tr("Bericht speichern …").as_str()), Some("app.export"));
        menu.append(Some(tr("Einstellungen").as_str()), Some("app.settings"));
        menu.append(Some(tr("Info zu Picket").as_str()), Some("app.about"));
        let menu_button = gtk::MenuButton::builder().icon_name("open-menu-symbolic").menu_model(&menu).tooltip_text(tr("Hauptmenü").as_str()).build();
        let sidebar_header = adw::HeaderBar::new();
        sidebar_header.pack_end(&menu_button);
        let sidebar_view = adw::ToolbarView::new();
        sidebar_view.add_top_bar(&sidebar_header);
        sidebar_view.set_content(Some(
            &gtk::ScrolledWindow::builder().hscrollbar_policy(gtk::PolicyType::Never).child(&list).build(),
        ));
        let sidebar_page = adw::NavigationPage::new(&sidebar_view, tr("Picket").as_str());

        // ---- content chrome
        let stack = gtk::Stack::new();
        stack.set_transition_type(gtk::StackTransitionType::None);
        let toasts = adw::ToastOverlay::new();
        toasts.set_child(Some(&stack));
        let header = adw::HeaderBar::new();
        let refresh_btn = gtk::Button::from_icon_name("view-refresh-symbolic");
        refresh_btn.set_tooltip_text(Some(tr("Neu prüfen").as_str()));
        header.pack_start(&refresh_btn);
        let spinner = gtk::Spinner::new();
        let stamp = gtk::Label::new(None);
        stamp.add_css_class("dim-label");
        header.pack_end(&stamp);
        header.pack_end(&spinner);
        let banner = adw::Banner::new(tr("Einige Prüfungen brauchen Administratorrechte (Firewall-Regeln, Prozessnamen, Passwortprüfung)").as_str());
        banner.set_button_label(Some(tr("Freischalten").as_str()));
        let content_view = adw::ToolbarView::new();
        content_view.add_top_bar(&header);
        content_view.add_top_bar(&banner);
        content_view.set_content(Some(&toasts));
        let content_page = adw::NavigationPage::new(&content_view, tr(PAGES[0].1).as_str());

        let split = adw::NavigationSplitView::new();
        split.set_min_sidebar_width(230.0);
        split.set_max_sidebar_width(280.0);
        split.set_sidebar(Some(&sidebar_page));
        split.set_content(Some(&content_page));

        // ---- pages
        let mut pages = HashMap::new();
        for (name, ..) in PAGES {
            let p = page();
            stack.add_named(&p.scroller, Some(name));
            pages.insert(name, p.body);
        }

        // overview
        let overview = &pages["overview"];
        let cards = card_flow();
        let mut counts = Vec::new();
        for (status, caption) in [
            (Status::Crit, "Kritisch"),
            (Status::Warn, "Warnungen"),
            (Status::Unknown, "Unklar"),
            (Status::Info, "Hinweise"),
            (Status::Ok, "In Ordnung"),
        ] {
            let c = stat_card(caption, status_style(status).1);
            cards.append(&c.root);
            counts.push((status, c.number));
        }
        overview.append(&cards);
        let device_group = group("Gerät", None);
        let device = [
            info_row("Modell", "…"),
            info_row("System", "…"),
            info_row("Kernel", "…"),
            info_row("BIOS", "…"),
        ];
        for r in &device {
            r.add_css_class("property");
            device_group.add(r);
        }
        overview.append(&device_group);

        let settings = group("Wächter und Zusatzdaten", None);
        let watch_row = adw::SwitchRow::new();
        watch_row.set_title(tr("Wächter im Hintergrund").as_str());
        watch_row.set_subtitle(tr("Prüft alle 5 Minuten und meldet nur Änderungen: neues Gerät, neuer offener Port, neue Warnung").as_str());
        let geo_row = info_row("Länder und Anbieter der Gegenstellen", "…");
        let geo_btn = gtk::Button::with_label(tr("Neu laden").as_str());
        geo_btn.set_valign(gtk::Align::Center);
        geo_row.add_suffix(&geo_btn);
        let block_row = info_row("Sperrliste für Werbung, Tracker und Schadseiten", "…");
        let block_btn = gtk::Button::with_label(tr("Neu laden").as_str());
        block_btn.set_valign(gtk::Align::Center);
        block_row.add_suffix(&block_btn);
        let export_row = info_row("Bericht speichern", "Alle Befunde als HTML-Datei, z. B. zum Ausdrucken oder Vergleichen");
        let export_btn = gtk::Button::with_label(tr("Speichern …").as_str());
        export_btn.set_valign(gtk::Align::Center);
        export_row.add_suffix(&export_btn);
        for row in [watch_row.upcast_ref::<gtk::Widget>(), geo_row.upcast_ref(), block_row.upcast_ref(), export_row.upcast_ref()] {
            settings.add(row);
        }
        pages["settings"].append(&settings);

        let tray_row = adw::SwitchRow::new();
        tray_row.set_title(tr("Symbol in der oberen Leiste").as_str());
        tray_row.set_subtitle(tr("Zeigt, ob etwas kritisch ist. Picket läuft dann weiter, wenn das Fenster geschlossen wird; „Beenden“ im Menü des Symbols schließt es ganz.").as_str());
        tray_row.set_active(tray::enabled());
        let autostart_row = adw::SwitchRow::new();
        autostart_row.set_title(tr("Beim Anmelden starten").as_str());
        autostart_row.set_subtitle(tr("Ohne Fenster, nur mit dem Symbol in der Leiste").as_str());
        autostart_row.set_active(tray::autostart());
        autostart_row.set_sensitive(tray::enabled());
        let background = group("Im Hintergrund", None);
        background.add(&tray_row);
        background.add(&autostart_row);
        pages["settings"].append(&background);

        // docker
        let docker_group = group("Laufende Container", Some("Aufklappen zeigt die Ports. Offene Ports lassen sich mit der angezeigten Zeile auf den Laptop beschränken."));
        pages["docker"].append(&docker_group);
        let docker_scans = group(
            "Bekannte Lücken in den Images",
            Some("Prüft die Images der laufenden Container mit Trivy auf bekannte Lücken (kritisch und hoch). Der erste Lauf lädt die Lücken-Datenbank."),
        );
        let docker_scan_button = gtk::Button::builder().label(tr("Images prüfen").as_str()).valign(gtk::Align::Center).build();
        docker_scans.set_header_suffix(Some(&docker_scan_button));
        pages["docker"].append(&docker_scans);

        // history
        let histp = pages["history"].clone();
        let hist_events = group("Meldungen des Wächters", Some("Was sich geändert hat, neueste zuerst."));
        histp.append(&hist_events);
        let hist_conns = group(
            "Verbindungen pro Tag",
            Some("Der Wächter notiert alle 5 Minuten die offenen Verbindungen. Kurze Verbindungen dazwischen fehlen; die Datenmenge ist ein Mindestwert (nur TCP)."),
        );
        let hist_day = adw::ComboRow::new();
        hist_day.set_title(tr("Tag").as_str());
        hist_conns.add(&hist_day);
        histp.append(&hist_conns);

        // deep check
        let deepp = pages["deep"].clone();
        let deep_group = group(
            "Tiefenprüfung",
            Some("Sucht Zugangsdaten im persönlichen Ordner, prüft Autostart-Einträge, set-uid-Dateien und die Prüfsummen der Systemprogramme und führt ein Lynis-Audit aus. Liest nur; dauert einige Minuten."),
        );
        let deep_status = info_row("Bereit", "Noch nicht gelaufen.");
        let deep_spinner = gtk::Spinner::new();
        deep_spinner.set_visible(false);
        deep_status.add_prefix(&deep_spinner);
        let deep_button = gtk::Button::with_label(tr("Prüfung starten").as_str());
        deep_button.add_css_class("suggested-action");
        deep_button.set_valign(gtk::Align::Center);
        deep_status.add_suffix(&deep_button);
        let cve_row = info_row("Bekannte Lücken online abgleichen", "Fragt osv.dev nach Lücken in Programmen, die mit cargo, pip oder npm installiert wurden.");
        let cve_button = gtk::Button::with_label(tr("Abgleichen …").as_str());
        cve_button.set_valign(gtk::Align::Center);
        cve_row.add_suffix(&cve_button);
        deep_group.add(&deep_status);
        deep_group.add(&cve_row);
        deepp.append(&deep_group);
        let deep_results = group("Ergebnisse", None);
        deepp.append(&deep_results);

        // firewall controls
        let fwp = &pages["firewall"];
        let fw_group = group(
            "Firewall",
            Some("Änderungen werden mit ufw ausgeführt. Vor jeder Änderung siehst du den Befehl und bestätigst mit deinem Passwort."),
        );
        let fw_status = info_row("…", "");
        let fw_toggle = gtk::Button::with_label(tr("Einschalten").as_str());
        fw_toggle.set_valign(gtk::Align::Center);
        fw_status.add_suffix(&fw_toggle);
        let fw_policy = adw::ComboRow::new();
        fw_policy.set_title(tr("Eingehende Verbindungen ohne passende Regel").as_str());
        fw_policy.set_model(Some(&string_list(&["Blockieren (empfohlen)", "Ablehnen", "Erlauben"])));
        fw_group.add(&fw_status);
        fw_group.add(&fw_policy);
        fwp.append(&fw_group);
        let fw_rules = group(
            "Regeln",
            Some("Ausnahmen von der Standardregel. Von Docker veröffentlichte Ports lassen sich so nicht sperren – Docker umgeht ufw."),
        );
        let fw_add = gtk::Button::builder().label(tr("Regel hinzufügen").as_str()).valign(gtk::Align::Center).build();
        fw_add.add_css_class("flat");
        fw_rules.set_header_suffix(Some(&fw_add));
        fwp.append(&fw_rules);
        let fw_domains = group(
            "Gesperrte Domains",
            Some("Trägt den Namen in /etc/hosts ein; Programme auf diesem Laptop erreichen ihn dann nicht mehr. Gilt für genau diesen Namen (Unterdomains einzeln) und nicht für Programme mit eigenem verschlüsseltem DNS, etwa Browser mit „sicherem DNS“."),
        );
        let fw_domain_entry = adw::EntryRow::new();
        fw_domain_entry.set_title(tr("Domain sperren, z. B. tracker.example.com").as_str());
        fw_domain_entry.set_show_apply_button(true);
        fw_domains.add(&fw_domain_entry);
        fwp.append(&fw_domains);

        // devices
        let devp = pages["devices"].clone();
        let dev_intro = group(
            "Geräte im lokalen Netz",
            Some("Gezeigt werden Geräte, mit denen dieser Laptop zuletzt Kontakt hatte. „Netz durchsuchen“ spricht jede Adresse des lokalen Netzes einmal an und findet so auch stille Geräte."),
        );
        let dev_spinner = gtk::Spinner::new();
        let dev_button = gtk::Button::builder().label(tr("Netz durchsuchen").as_str()).valign(gtk::Align::Center).build();
        let dev_head = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        dev_head.append(&dev_spinner);
        dev_head.append(&dev_button);
        dev_intro.set_header_suffix(Some(&dev_head));
        devp.append(&dev_intro);

        // capture
        let capp = pages["capture"].clone();
        let cap_group = group(
            "Mitschnitt",
            Some("Zeichnet die Pakete dieses Laptops mit tcpdump auf und fragt dafür nach deinem Passwort. Inhalte von HTTPS sind verschlüsselt: Sichtbar sind Gegenstelle, Größe, DNS-Namen und der Servername beim Verbindungsaufbau. Unverschlüsseltes (HTTP, DNS) ist im Klartext lesbar."),
        );
        let mut cap_ifaces = vec!["any".to_string()];
        cap_ifaces.extend(crate::net::read_ifaces().into_iter().filter(|i| i.kind == Zone::Lan && i.up).map(|i| i.name));
        let mut cap_labels = vec!["Alle Schnittstellen".to_string()];
        cap_labels.extend(cap_ifaces.iter().skip(1).map(|n| if n.starts_with("wl") { format!("WLAN ({n})") } else { format!("Kabel ({n})") }));
        let cap_iface = adw::ComboRow::new();
        cap_iface.set_title(tr("Schnittstelle").as_str());
        cap_iface.set_model(Some(&string_list(&cap_labels.iter().map(String::as_str).collect::<Vec<_>>())));
        let cap_host = adw::EntryRow::new();
        cap_host.set_title(tr("Nur diese Gegenstelle (IP-Adresse, leer = alle)").as_str());
        let cap_port = adw::EntryRow::new();
        cap_port.set_title(tr("Nur dieser Port (leer = alle)").as_str());
        let cap_proto = adw::ComboRow::new();
        cap_proto.set_title(tr("Protokoll").as_str());
        cap_proto.set_model(Some(&string_list(&["Alle", "TCP", "UDP"])));
        let cap_status = info_row("Bereit", "Noch kein Mitschnitt in dieser Sitzung.");
        let cap_button = gtk::Button::with_label(tr("Mitschnitt starten").as_str());
        cap_button.add_css_class("suggested-action");
        cap_button.set_valign(gtk::Align::Center);
        cap_status.add_suffix(&cap_button);
        for row in [cap_iface.upcast_ref::<gtk::Widget>(), cap_host.upcast_ref(), cap_port.upcast_ref(), cap_proto.upcast_ref(), cap_status.upcast_ref()] {
            cap_group.add(row);
        }
        capp.append(&cap_group);

        let cap_actions = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        cap_actions.set_halign(gtk::Align::End);
        let cap_disconnect = gtk::Button::with_label(tr("Verbindungen trennen").as_str());
        cap_disconnect.set_tooltip_text(Some(tr("Beendet die bestehenden Verbindungen zur eingetragenen Gegenstelle").as_str()));
        let cap_block = gtk::Button::with_label(tr("Gegenstelle blockieren …").as_str());
        cap_block.set_tooltip_text(Some(tr("Legt eine Firewall-Regel gegen die eingetragene Gegenstelle an").as_str()));
        let cap_save = gtk::Button::with_label(tr("Als .pcap speichern …").as_str());
        cap_save.set_tooltip_text(Some(tr("Speichert den Mitschnitt, z. B. zum Öffnen in Wireshark").as_str()));
        cap_save.set_sensitive(false);
        cap_actions.append(&cap_disconnect);
        cap_actions.append(&cap_block);
        cap_actions.append(&cap_save);
        capp.append(&cap_actions);

        let cap_store = gio::ListStore::new::<glib::BoxedAnyObject>();
        // The search field narrows the list to rows that contain the text.
        let cap_search = gtk::SearchEntry::builder().placeholder_text(tr("Filtern: Name, Adresse, Protokoll …").as_str()).width_request(280).valign(gtk::Align::Center).build();
        let cap_filter = {
            let search = cap_search.clone();
            gtk::CustomFilter::new(move |obj| {
                let query = search.text().to_lowercase();
                if query.is_empty() {
                    return true;
                }
                obj.downcast_ref::<glib::BoxedAnyObject>()
                    .map(|o| {
                        let r = o.borrow::<CapRow>();
                        [r.program.as_str(), r.remote.as_str(), r.proto, r.info.as_str()].iter().any(|f| f.to_lowercase().contains(&query))
                    })
                    .unwrap_or(true)
            })
        };
        {
            let filter = cap_filter.clone();
            cap_search.connect_search_changed(move |_| filter.changed(gtk::FilterChange::Different));
        }
        let cap_filtered = gtk::FilterListModel::new(Some(cap_store.clone()), Some(cap_filter));
        let cap_view = gtk::ColumnView::new(Some(gtk::NoSelection::new(Some(cap_filtered))));
        cap_view.set_show_row_separators(true);
        let columns: [(&str, bool, i32, fn(&CapRow) -> String); 7] = [
            ("Zeit", false, 105, |r| r.time.clone()),
            ("", false, 30, |r| r.direction.to_string()),
            ("Programm", false, 120, |r| r.program.clone()),
            ("Gegenstelle", true, 0, |r| r.remote.clone()),
            ("Protokoll", false, 80, |r| r.proto.to_string()),
            ("Größe", false, 75, |r| r.size.clone()),
            ("Was passiert", true, 0, |r| r.info.clone()),
        ];
        for (title, expand, width, text) in columns {
            let factory = gtk::SignalListItemFactory::new();
            factory.connect_setup(|_, item| {
                if let Some(item) = item.downcast_ref::<gtk::ListItem>() {
                    let label = gtk::Label::builder().xalign(0.0).ellipsize(gtk::pango::EllipsizeMode::End).build();
                    item.set_child(Some(&label));
                }
            });
            factory.connect_bind(move |_, item| {
                let Some(item) = item.downcast_ref::<gtk::ListItem>() else { return };
                let (Some(obj), Some(label)) = (item.item().and_downcast::<glib::BoxedAnyObject>(), item.child().and_downcast::<gtk::Label>()) else {
                    return;
                };
                let shown = text(&obj.borrow::<CapRow>());
                label.set_tooltip_text(Some(tr(&shown).as_str()));
                label.set_label(tr(&shown).as_str());
            });
            let column = gtk::ColumnViewColumn::new(Some(tr(title).as_str()), Some(factory));
            column.set_expand(expand);
            column.set_resizable(true);
            if !expand {
                column.set_fixed_width(width); // the two text columns share the remaining space
            }
            cap_view.append_column(&column);
        }
        let cap_scroller = gtk::ScrolledWindow::builder().min_content_height(440).child(&cap_view).build();
        let cap_frame = gtk::Frame::new(None);
        cap_frame.set_child(Some(&cap_scroller));
        let cap_talk = group("Wer mit wem", Some("Die Gegenstellen dieses Mitschnitts nach Datenmenge."));
        cap_talk.set_visible(false);
        capp.append(&cap_talk);
        let cap_list_group = group("Pakete", Some("Neueste zuerst. → von diesem Laptop, ← zu diesem Laptop."));
        cap_list_group.set_header_suffix(Some(&cap_search));
        cap_list_group.add(&cap_frame);
        capp.append(&cap_list_group);
        let cap_file = std::env::var_os("XDG_CACHE_HOME")
            .map(std::path::PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| util::home().join(".cache"))
            .join("picket/mitschnitt.pcap");

        // network
        let netp = &pages["network"];
        let zone_cards = card_flow();
        let mut ncards = Vec::new();
        for (zone, label, _, css) in ZONES {
            let c = stat_card(label, css);
            c.sub.set_visible(true);
            zone_cards.append(&c.root);
            ncards.push((zone, c.number, c.sub, c.root));
        }
        zone_cards.add_css_class("fw-clickable");
        zone_cards.set_activate_on_single_click(true);
        let zones_group = group(
            "Wohin gehen die Verbindungen?",
            Some("Aktive Verbindungen dieses Laptops nach dem Ort der Gegenstelle. Eine Kachel anklicken, um nur dieses Ziel zu zeigen."),
        );
        let net_stamp = gtk::Label::new(None);
        net_stamp.add_css_class("dim-label");
        zones_group.set_header_suffix(Some(&net_stamp));
        zones_group.add(&zone_cards);
        netp.append(&zones_group);
        // Total throughput from the kernel's interface counters: includes UDP/QUIC,
        // which the per-connection counters cannot see.
        let traffic = graph::Throughput::new();
        let traffic_card = gtk::Box::new(gtk::Orientation::Vertical, 0);
        traffic_card.add_css_class("card");
        traffic.area.set_margin_top(10);
        traffic.area.set_margin_bottom(8);
        traffic.area.set_margin_start(14);
        traffic.area.set_margin_end(14);
        traffic_card.append(&traffic.area);
        netp.append(&traffic_card);

        let graph = graph::Graph::new();
        let graph_group = group(
            "Live-Bild",
            Some("Jede Linie verbindet ein Programm mit einer Gegenstelle. Wandernde Punkte zeigen gemessenen Datenverkehr und seine Richtung (nur TCP – für UDP/QUIC führt das System keine Zähler). Fahre mit der Maus über einen Kasten, um seine Verbindungen hervorzuheben."),
        );
        let graph_card = gtk::Box::new(gtk::Orientation::Vertical, 0);
        graph_card.add_css_class("card");
        graph.area.set_margin_top(12);
        graph.area.set_margin_bottom(12);
        graph.area.set_margin_start(12);
        graph.area.set_margin_end(12);
        graph_card.append(&graph.area);
        graph_group.add(&graph_card);

        let live = adw::SwitchRow::new();
        live.set_title(tr("Live aktualisieren").as_str());
        live.set_subtitle(tr("Alle 5 Sekunden, solange diese Seite offen ist").as_str());
        live.set_active(true);
        let resolve = adw::SwitchRow::new();
        resolve.set_title(tr("Hostnamen auflösen").as_str());
        resolve.set_subtitle(tr("Fragt den DNS-Server nach den Namen der Gegenstellen").as_str());
        live.set_subtitle(tr("Alle 5 Sekunden; bei anderer Seite oder im Hintergrund alle 15 Sekunden, damit nichts unbemerkt bleibt").as_str());
        let keep = adw::ComboRow::new();
        keep.set_title(tr("Beendete Verbindungen anzeigen").as_str());
        keep.set_subtitle(tr("Abgeblendet im Live-Bild und in der Programmliste").as_str());
        keep.set_model(Some(&string_list(&["Nicht anzeigen", "5 Minuten lang", "30 Minuten lang", "Bis die App geschlossen wird"])));
        keep.set_selected(2);
        let net_settings = group("Seite „Verbindungen“", None);
        net_settings.add(&live);
        net_settings.add(&keep);
        net_settings.add(&resolve);
        pages["settings"].append(&net_settings);

        let programs = group(
            "Programme mit Verbindungen",
            Some("→ ausgehend, ← eingehend. Verbindungen aus Docker-Containern und VMs erscheinen nicht als eigene Programme."),
        );
        let ports = group(
            "Offene Ports – wer kann diesen Laptop erreichen?",
            Some("Dienste, die auf eingehende Verbindungen warten."),
        );
        let show_local = adw::SwitchRow::new();
        show_local.set_title(tr("Auch nur lokal erreichbare Ports zeigen").as_str());
        ports.add(&show_local);

        // Three views of the same data instead of one long page.
        let net_tabs = gtk::Stack::new();
        net_tabs.set_vhomogeneous(false);
        net_tabs.add_titled(&graph_group, Some("graph"), tr("Live-Bild").as_str());
        net_tabs.add_titled(&programs, Some("programs"), tr("Programme").as_str());
        net_tabs.add_titled(&ports, Some("ports"), tr("Offene Ports").as_str());
        let net_switcher = gtk::StackSwitcher::new();
        net_switcher.set_stack(Some(&net_tabs));
        net_switcher.set_halign(gtk::Align::Center);
        netp.append(&net_switcher);
        netp.append(&net_tabs);

        // antivirus
        let avp = &pages["antivirus"];
        let scan_group = group(
            "Virenscan",
            Some("Der Scan läuft mit niedriger Priorität; ClamAV braucht dabei etwa 1 GB Arbeitsspeicher."),
        );
        let targets = scan::targets();
        let target = adw::ComboRow::new();
        target.set_title(tr("Ordner").as_str());
        let labels: Vec<&str> = targets.iter().map(|t| t.label).collect();
        target.set_model(Some(&string_list(&labels)));
        target.set_use_markup(false);
        target.set_subtitle(tr(targets.first().map(|t| t.path.as_str()).unwrap_or("")).as_str());
        let status = info_row("Bereit", "Noch kein Scan in dieser Sitzung.");
        status.set_subtitle_lines(2);
        let scan_spinner = gtk::Spinner::new();
        scan_spinner.set_visible(false);
        status.add_prefix(&scan_spinner);
        let button = gtk::Button::with_label(tr("Scan starten").as_str());
        button.add_css_class("suggested-action");
        button.set_valign(gtk::Align::Center);
        status.add_suffix(&button);
        scan_group.add(&target);
        scan_group.add(&status);
        avp.append(&scan_group);
        let available = util::which("clamscan").is_some();
        if !available {
            status.set_title(tr("ClamAV ist nicht installiert").as_str());
            status.set_subtitle(tr("Installieren mit: sudo apt install clamav").as_str());
            button.set_sensitive(false);
        }

        let window = adw::ApplicationWindow::builder()
            .application(app)
            .title(tr("Picket").as_str())
            .default_width(1120)
            .default_height(780)
            .width_request(360)
            .height_request(320)
            .content(&split)
            .build();
        // Narrow window: the sidebar becomes its own page with a back button.
        let narrow = adw::Breakpoint::new(adw::BreakpointCondition::new_length(
            adw::BreakpointConditionLengthType::MaxWidth,
            820.0,
            adw::LengthUnit::Sp,
        ));
        narrow.add_setter(&split, "collapsed", Some(&true.to_value()));
        window.add_breakpoint(narrow);
        if let Some((w, h)) = std::env::var("PICKET_SHOT_SIZE").ok().and_then(|s| {
            let (w, h) = s.split_once('x')?;
            Some((w.parse().ok()?, h.parse().ok()?))
        }) {
            window.set_default_size(w, h); // test aid
        }

        let ui = Rc::new(Ui {
            window,
            sidebar: list.clone(),
            toasts,
            stack,
            banner,
            refresh_btn,
            spinner,
            stamp,
            badges,
            counts,
            device,
            pages,
            dynamic: RefCell::new(Vec::new()),
            net: NetView {
                cards: ncards,
                stamp: net_stamp,
                live,
                resolve,
                zone: Cell::new(None),
                tabs: net_tabs,
                session: RefCell::new(Session::default()),
                traffic,
                keep,
                ticks: Cell::new(0),
                show_local,
                programs,
                ports,
                program_rows: RefCell::new(Vec::new()),
                port_rows: RefCell::new(Vec::new()),
                expanded: Rc::new(RefCell::new(HashSet::new())),
                names: Arc::new(Mutex::new(HashMap::new())),
                last: RefCell::new(None),
                fingerprint: RefCell::new(String::new()),
                loading: Cell::new(false),
                resolving: Cell::new(false),
            },
            graph,
            fw: FwView {
                status: fw_status,
                toggle: fw_toggle,
                policy: fw_policy,
                add: fw_add,
                domains: fw_domains,
                domain_entry: fw_domain_entry,
                domain_rows: RefCell::new(Vec::new()),
                rules: fw_rules,
                rule_rows: RefCell::new(Vec::new()),
                state: RefCell::new(fwctl::State::default()),
                updating: Cell::new(false),
            },
            dev: DevView {
                body: devp,
                button: dev_button,
                spinner: dev_spinner,
                groups: RefCell::new(Vec::new()),
                loading: Cell::new(false),
                loaded: Cell::new(false),
            },
            extras: Extras { watch: watch_row, tray: tray_row, autostart: autostart_row, geo: geo_row, blocklist: block_row, updating: Cell::new(false) },
            docker: DockerView {
                group: docker_group,
                rows: RefCell::new(Vec::new()),
                loading: Cell::new(false),
                images: RefCell::new(Vec::new()),
                scan_button: docker_scan_button,
                scans: docker_scans,
                scan_rows: RefCell::new(Vec::new()),
                scanning: Cell::new(false),
            },
            hist: HistView {
                events: hist_events,
                conns: hist_conns,
                day: hist_day,
                days: RefCell::new(Vec::new()),
                event_rows: RefCell::new(Vec::new()),
                conn_rows: RefCell::new(Vec::new()),
                updating: Cell::new(false),
            },
            deep: DeepView {
                status: deep_status,
                button: deep_button,
                spinner: deep_spinner,
                cve: cve_row,
                cve_button,
                results: deep_results,
                rows: RefCell::new(Vec::new()),
                running: Cell::new(false),
            },
            report: RefCell::new(None),
            cap: CapView {
                ifaces: cap_ifaces,
                iface: cap_iface,
                host: cap_host,
                port: cap_port,
                proto: cap_proto,
                status: cap_status,
                button: cap_button,
                save: cap_save,
                block: cap_block,
                disconnect: cap_disconnect,
                store: cap_store,
                search: cap_search,
                talk: RefCell::new(HashMap::new()),
                talk_group: cap_talk,
                talk_rows: RefCell::new(Vec::new()),
                talk_rendered: Cell::new(0),
                stdin: RefCell::new(None),
                running: Cell::new(false),
                packets: Cell::new(0),
                bytes: Cell::new(0),
                names: RefCell::new(HashMap::new()),
                file: cap_file,
            },
            scan: ScanView {
                job: Arc::new(ScanJob::default()),
                targets,
                group: scan_group,
                target,
                status,
                spinner: scan_spinner,
                button,
                found_rows: RefCell::new(Vec::new()),
                available,
            },
            busy: Cell::new(false),
            tray: app.dbus_connection().and_then(|bus| tray::Tray::new(&bus, tray::enabled())),
            quitting: Cell::new(false),
        });

        // ---- signals
        {
            let (ui2, page, split) = (ui.clone(), content_page.clone(), split.clone());
            list.connect_row_selected(move |_, row| {
                let Some(row) = row else { return };
                let Some((name, title, ..)) = usize::try_from(row.index()).ok().and_then(|i| PAGES.get(i)) else {
                    return;
                };
                ui2.stack.set_visible_child_name(name);
                page.set_title(tr(title).as_str());
                split.set_show_content(true);
                if *name == "network" {
                    ui2.load_net();
                }
                if *name == "devices" && !ui2.dev.loaded.get() {
                    ui2.load_devices(false);
                }
                if *name == "history" {
                    ui2.render_history();
                }
            });
            list.select_row(list.row_at_index(0).as_ref());
        }
        {
            let ui2 = ui.clone();
            ui.refresh_btn.connect_clicked(move |_| ui2.refresh());
        }
        {
            let ui2 = ui.clone();
            ui.banner.connect_button_clicked(move |_| ui2.unlock());
        }
        {
            let ui2 = ui.clone();
            ui.net.keep.connect_selected_notify(move |_| ui2.render_net(true));
        }
        for sw in [&ui.net.resolve, &ui.net.show_local] {
            let ui2 = ui.clone();
            sw.connect_active_notify(move |_| {
                ui2.render_net(true);
                ui2.resolve_names();
            });
        }
        {
            // Clicking a zone card filters by that zone; clicking it again shows everything.
            let ui2 = ui.clone();
            zone_cards.connect_child_activated(move |_, child| {
                let zone = usize::try_from(child.index()).ok().and_then(|i| ZONES.get(i)).map(|z| z.0);
                let nv = &ui2.net;
                nv.zone.set(if nv.zone.get() == zone { None } else { zone });
                for (z, _, _, card) in &nv.cards {
                    if nv.zone.get() == Some(*z) {
                        card.add_css_class("fw-selected");
                    } else {
                        card.remove_css_class("fw-selected");
                    }
                }
                ui2.render_net(true);
            });
        }
        {
            // Clicks in the diagram: a program opens its connection list, a host its actions.
            let weak = Rc::downgrade(&ui);
            ui.graph.connect_click(move |click| {
                let Some(ui) = weak.upgrade() else { return };
                match click {
                    graph::Click::Program(name) => {
                        ui.net.expanded.borrow_mut().insert(name);
                        ui.net.tabs.set_visible_child_name("programs");
                        ui.render_net(true);
                    }
                    graph::Click::Host { remote, port, x, y } => {
                        let popover = gtk::Popover::new();
                        popover.set_parent(&ui.graph.area);
                        popover.set_pointing_to(Some(&gtk::gdk::Rectangle::new(x as i32, y as i32, 1, 1)));
                        popover.set_child(Some(&ui.endpoint_actions(&remote, port, false, &popover)));
                        popover.connect_closed(|p| p.unparent());
                        popover.popup();
                    }
                }
            });
        }
        {
            // Menu actions and keyboard shortcuts.
            let add = |name: &str, accels: &[&str], f: Box<dyn Fn(&Rc<Ui>)>| {
                let action = gio::SimpleAction::new(name, None);
                let weak = Rc::downgrade(&ui);
                action.connect_activate(move |_, _| {
                    if let Some(ui) = weak.upgrade() {
                        f(&ui);
                    }
                });
                app.add_action(&action);
                app.set_accels_for_action(&format!("app.{name}"), accels);
            };
            add("refresh", &["<Ctrl>r", "F5"], Box::new(|ui| ui.refresh()));
            add("export", &["<Ctrl>s"], Box::new(|ui| ui.export_report()));
            add("settings", &["<Ctrl>comma"], Box::new(|ui| ui.go_to("settings")));
            add("quit", &["<Ctrl>q"], Box::new(|ui| ui.quit()));
            add(
                "about",
                &[],
                Box::new(|ui| {
                    adw::AboutDialog::builder()
                        .application_name("Picket")
                        .application_icon(APP_ID)
                        .version(env!("CARGO_PKG_VERSION"))
                        .copyright("© 2026 blanpa")
                        .license_type(gtk::License::Gpl30)
                        .comments(tr("Prüft Firewall, Virenscanner, Updates, Netzwerk und System dieses Laptops. Die Prüfungen lesen nur; geändert wird erst nach deiner Bestätigung.").as_str())
                        .build()
                        .present(Some(&ui.window));
                }),
            );
        }
        {
            let ui2 = ui.clone();
            ui.net.live.connect_active_notify(move |sw| {
                if sw.is_active() {
                    ui2.load_net();
                }
            });
        }
        {
            let ui2 = ui.clone();
            ui.scan.button.connect_clicked(move |_| ui2.toggle_scan());
        }
        {
            let ui2 = ui.clone();
            ui.dev.button.connect_clicked(move |_| ui2.load_devices(true));
        }
        if let Some(icon) = &ui.tray {
            // What the icon in the top bar offers.
            let weak = Rc::downgrade(&ui);
            icon.connect(move |action| {
                let Some(ui) = weak.upgrade() else { return };
                match action {
                    tray::Action::Open => ui.window.present(),
                    tray::Action::Check => ui.refresh(),
                    tray::Action::Quit => ui.quit(),
                }
            });
        }
        {
            // With the icon in the top bar, closing the window only puts it away. This handler
            // comes before the ones that tidy up, so a scan or a capture keeps running then.
            let weak = Rc::downgrade(&ui);
            ui.window.connect_close_request(move |window| {
                let Some(ui) = weak.upgrade() else { return glib::Propagation::Proceed };
                if !ui.quitting.get() && ui.tray.as_ref().is_some_and(|icon| icon.is_shown()) {
                    window.set_visible(false);
                    return glib::Propagation::Stop;
                }
                glib::Propagation::Proceed
            });
        }
        {
            let ui2 = ui.clone();
            ui.extras.tray.connect_active_notify(move |sw| {
                let on = sw.is_active();
                if let Err(e) = tray::save_enabled(on) {
                    ui2.toast(&e);
                }
                if let Some(icon) = &ui2.tray {
                    icon.set_enabled(on);
                }
                // Starting unseen at login only makes sense with the icon.
                ui2.extras.autostart.set_sensitive(on);
                if !on {
                    ui2.extras.autostart.set_active(false);
                }
            });
            let ui2 = ui.clone();
            ui.extras.autostart.connect_active_notify(move |sw| {
                if sw.is_active() != tray::autostart() {
                    if let Err(e) = tray::set_autostart(sw.is_active()) {
                        ui2.toast(&e);
                    }
                }
            });
        }
        {
            // Put away in the top bar, the icon should still tell the truth: check again now and then.
            let weak = Rc::downgrade(&ui);
            glib::timeout_add_seconds_local(600, move || {
                let Some(ui) = weak.upgrade() else { return glib::ControlFlow::Break };
                if !ui.window.is_visible() {
                    ui.refresh();
                }
                glib::ControlFlow::Continue
            });
        }
        {
            let ui2 = ui.clone();
            ui.extras.watch.connect_active_notify(move |sw| {
                if ui2.extras.updating.get() {
                    return;
                }
                let (on, ui3) = (sw.is_active(), ui2.clone());
                glib::spawn_future_local(async move {
                    let result = gio::spawn_blocking(move || {
                        let r = watch::set_timer(on);
                        if on && r.is_ok() {
                            watch::run_once(false); // record the starting point right away
                        }
                        r
                    })
                    .await
                    .unwrap_or_else(|_| Err("Abbruch".into()));
                    match result {
                        Ok(()) => ui3.toast(if on { "Wächter läuft jetzt im Hintergrund" } else { "Wächter ausgeschaltet" }),
                        Err(e) => ui3.toast(&format!("Wächter: {e}")),
                    }
                    ui3.render_extras();
                });
            });
        }
        for (button, which) in [(&geo_btn, 0u8), (&block_btn, 1u8)] {
            let ui2 = ui.clone();
            button.connect_clicked(move |b| {
                b.set_sensitive(false);
                let (ui3, b) = (ui2.clone(), b.clone());
                glib::spawn_future_local(async move {
                    let result = gio::spawn_blocking(move || if which == 0 { geo::download() } else { blocklist::download() })
                        .await
                        .unwrap_or_else(|_| Err("Abbruch".into()));
                    ui3.toast(&match result {
                        Ok(msg) => msg,
                        Err(e) => e,
                    });
                    b.set_sensitive(true);
                    ui3.render_extras();
                    ui3.render_net(true);
                });
            });
        }
        {
            let ui2 = ui.clone();
            export_btn.connect_clicked(move |_| ui2.export_report());
        }
        {
            let ui2 = ui.clone();
            ui.hist.day.connect_selected_notify(move |_| {
                if !ui2.hist.updating.get() {
                    ui2.render_history_day();
                }
            });
        }
        {
            let ui2 = ui.clone();
            ui.deep.button.connect_clicked(move |_| ui2.run_deep());
        }
        {
            let ui2 = ui.clone();
            ui.deep.cve_button.connect_clicked(move |_| ui2.confirm_cve());
        }
        {
            let ui2 = ui.clone();
            ui.cap.button.connect_clicked(move |_| ui2.toggle_capture());
        }
        {
            let ui2 = ui.clone();
            ui.cap.save.connect_clicked(move |_| ui2.save_capture());
        }
        {
            let ui2 = ui.clone();
            ui.cap.block.connect_clicked(move |_| {
                let host = ui2.cap.host.text().to_string();
                ui2.block_host(host.trim(), false);
            });
        }
        {
            let ui2 = ui.clone();
            ui.cap.disconnect.connect_clicked(move |_| {
                let (host, port) = (ui2.cap.host.text().to_string(), ui2.cap.port.text().to_string());
                ui2.disconnect_host(host.trim(), port.trim());
            });
        }
        {
            let ui2 = ui.clone();
            ui.fw.toggle.connect_clicked(move |_| {
                if ui2.fw.state.borrow().active {
                    ui2.fw_confirm(
                        fwctl::Op::Disable,
                        "Firewall ausschalten?",
                        "Danach sind alle offenen Ports dieses Laptops aus dem Netz erreichbar.",
                        true,
                    );
                } else {
                    let mut body = String::from(
                        "Eingehende Verbindungen werden blockiert, sofern keine Regel sie erlaubt. Ausgehende Verbindungen bleiben erlaubt.\n\n\
                         Von Docker veröffentlichte Ports bleiben erreichbar. Virtuelle Maschinen und Container erreichen Dienste auf diesem Laptop nur noch mit passender Regel.",
                    );
                    if util::service_active("ssh") || util::service_active("sshd") {
                        body.push_str("\n\nAchtung: Der SSH-Server läuft. Ohne Erlauben-Regel für Port 22 sperrst du dich bei einer Fernverbindung aus.");
                    }
                    ui2.fw_confirm(fwctl::Op::Enable, "Firewall einschalten?", &body, false);
                }
            });
        }
        {
            let ui2 = ui.clone();
            ui.fw.policy.connect_selected_notify(move |row| {
                if ui2.fw.updating.get() {
                    return;
                }
                let policy = ["deny", "reject", "allow"][(row.selected() as usize).min(2)];
                if ui2.fw.state.borrow().incoming == policy {
                    return;
                }
                let body = match policy {
                    "allow" => "Jede eingehende Verbindung wird dann angenommen, sofern keine Regel sie verbietet. Das ist nur selten sinnvoll.",
                    "reject" => "Unerwünschte Verbindungen werden mit einer Fehlermeldung abgewiesen statt still verworfen.",
                    _ => "Unerwünschte eingehende Verbindungen werden still verworfen.",
                };
                ui2.fw_confirm(
                    fwctl::Op::Default { direction: "incoming".into(), policy: policy.into() },
                    "Standardregel ändern?",
                    body,
                    policy == "allow",
                );
            });
        }
        {
            let ui2 = ui.clone();
            ui.fw.add.connect_clicked(move |_| ui2.rule_dialog("", 0));
        }
        {
            let ui2 = ui.clone();
            ui.fw.domain_entry.connect_apply(move |entry| {
                let domain = entry.text().trim().trim_end_matches('.').to_lowercase();
                ui2.fw_confirm(
                    fwctl::Op::BlockDomain { domain: domain.clone(), block: true },
                    "Domain sperren?",
                    &format!("Programme auf diesem Laptop erreichen {domain} danach nicht mehr."),
                    false,
                );
                entry.set_text("");
            });
        }
        {
            let ui2 = ui.clone();
            ui.docker.scan_button.connect_clicked(move |_| ui2.scan_images());
        }
        {
            let ui2 = ui.clone();
            ui.scan.target.connect_selected_notify(move |row| {
                if let Some(t) = ui2.scan.targets.get(row.selected() as usize) {
                    row.set_subtitle(tr(&t.path).as_str());
                }
            });
        }
        {
            // Do not leave clamscan running after the window is gone.
            let job = ui.scan.job.clone();
            ui.window.connect_close_request(move |_| {
                if job.snapshot().running {
                    job.cancel();
                }
                glib::Propagation::Proceed
            });
        }
        {
            // End a running capture and do not leave recorded traffic behind.
            let ui2 = ui.clone();
            ui.window.connect_close_request(move |_| {
                ui2.cap.stdin.borrow_mut().take();
                let _ = std::fs::remove_file(&ui2.cap.file);
                glib::Propagation::Proceed
            });
        }
        {
            // Zone colours need a lighter variant on dark backgrounds.
            let style = adw::StyleManager::default();
            let apply = {
                let window = ui.window.clone();
                move |style: &adw::StyleManager| {
                    if style.is_dark() {
                        window.add_css_class("fw-dark");
                    } else {
                        window.remove_css_class("fw-dark");
                    }
                }
            };
            apply(&style);
            style.connect_dark_notify(apply);
        }
        {
            // One throughput sample per second, so the chart has history when the page is opened.
            let weak = Rc::downgrade(&ui);
            let last = Cell::new((net::interface_totals(), std::time::Instant::now()));
            glib::timeout_add_seconds_local(1, move || {
                let Some(ui) = weak.upgrade() else {
                    return glib::ControlFlow::Break;
                };
                let ((rx0, tx0), t0) = last.get();
                let (now, (rx, tx)) = (std::time::Instant::now(), net::interface_totals());
                let dt = now.duration_since(t0).as_secs_f64().max(0.2);
                // An interface that disappears lowers the sum; that is not traffic.
                ui.net.traffic.push(rx.saturating_sub(rx0) as f64 / dt, tx.saturating_sub(tx0) as f64 / dt);
                last.set(((rx, tx), now));
                glib::ControlFlow::Continue
            });
        }
        {
            // Live network refresh while the network page is visible.
            let weak = Rc::downgrade(&ui);
            glib::timeout_add_seconds_local(5, move || {
                let Some(ui) = weak.upgrade() else {
                    return glib::ControlFlow::Break;
                };
                // On the page every 5 s; otherwise every 15 s, so that connections
                // opened and closed in the meantime still show up as "beendet".
                // With the window put away in the top bar, once a minute is enough.
                let on_page = ui.stack.visible_child_name().as_deref() == Some("network") && ui.window.is_active();
                let tick = ui.net.ticks.get().wrapping_add(1);
                ui.net.ticks.set(tick);
                let every = if ui.window.is_visible() { 3 } else { 12 };
                if ui.net.live.is_active() && (on_page || tick % every == 0) {
                    ui.load_net();
                }
                glib::ControlFlow::Continue
            });
        }
        ui
    }

    /// Test aid (PICKET_SHOT=<prefix>): render every page of the window to
    /// <prefix>-<page>.png and quit. Renders only this window, not the screen.
    fn screenshot_tour(self: &Rc<Self>, prefix: String) {
        let ui = self.clone();
        let step = Cell::new(0usize);
        let retries = Cell::new(0u32);
        // Not a whole number of seconds, so a retry does not land on the same beat as the one-second timers.
        glib::timeout_add_local(Duration::from_millis(2900), move || {
            let i = step.get();
            if (1..=PAGES.len()).contains(&i) {
                let name = PAGES[i - 1].0;

                let paintable = gtk::WidgetPaintable::new(Some(&ui.window));
                let snapshot = gtk::Snapshot::new();
                paintable.snapshot(&snapshot, f64::from(ui.window.width()), f64::from(ui.window.height()));
                let renderer = ui.window.native().and_then(|n| n.renderer());
                match (snapshot.to_node(), renderer) {
                    (Some(node), Some(renderer)) => {
                        if let Err(e) = renderer.render_texture(&node, None).save_to_png(format!("{prefix}-{name}.png")) {
                            eprintln!("[tour] {name}: {e}");
                        }
                    }
                    // The window is between two layouts (something just changed size):
                    // stay on this page and try again at the next tick.
                    _ if retries.get() < 5 => {
                        retries.set(retries.get() + 1);
                        return glib::ControlFlow::Continue;
                    }
                    _ => eprintln!("[tour] {name}: kein Bild – die Seite ordnet sich dauernd neu an"),
                }
                retries.set(0);
            }
            if i == PAGES.len() && std::env::var_os("PICKET_SHOT_DIALOG").is_some() {
                // One extra picture: the rule form, opened for an example port.
                ui.sidebar.select_row(ui.sidebar.row_at_index(1).as_ref());
                ui.rule_dialog("8765", 1);
                step.set(i + 1);
                return glib::ControlFlow::Continue;
            }
            if i >= PAGES.len() {
                if i > PAGES.len() {
                    let paintable = gtk::WidgetPaintable::new(Some(&ui.window));
                    let snapshot = gtk::Snapshot::new();
                    paintable.snapshot(&snapshot, f64::from(ui.window.width()), f64::from(ui.window.height()));
                    let renderer = ui.window.native().and_then(|n| n.renderer());
                    if let (Some(node), Some(renderer)) = (snapshot.to_node(), renderer) {
                        let _ = renderer.render_texture(&node, None).save_to_png(format!("{prefix}-dialog.png"));
                    }
                }
                ui.quit();
                return glib::ControlFlow::Break;
            }
            ui.sidebar.select_row(ui.sidebar.row_at_index(i as i32).as_ref());
            if PAGES[i].0 == "capture" && std::env::var_os("PICKET_PCAP_REPLAY").is_some() {
                ui.toggle_capture();
            }
            if PAGES[i].0 == "antivirus" && std::env::var_os("PICKET_SHOT_SCAN").is_some() {
                ui.scan.target.set_selected(2); // /tmp
                ui.toggle_scan();
            }
            if PAGES[i].0 == "network" {
                // Show an expanded program in the picture.
                if let Some(first) = ui.net.last.borrow().as_ref().and_then(|n| n.programs.first()) {
                    ui.net.expanded.borrow_mut().insert(std::env::var("PICKET_SHOT_EXPAND").unwrap_or_else(|_| first.name.clone()));
                }
                if let Ok(tab) = std::env::var("PICKET_SHOT_TAB") {
                    ui.net.tabs.set_visible_child_name(&tab);
                }
                ui.render_net(true);
            }
            step.set(i + 1);
            glib::ControlFlow::Continue
        });
    }

    fn toast(&self, text: &str) {
        self.toasts.add_toast(adw::Toast::new(tr(text).as_str()));
    }

    /// End the program, also when the window would otherwise only be put away.
    fn quit(&self) {
        self.quitting.set(true);
        self.window.close();
    }

    // ------------------------------------------------------------ report

    fn refresh(self: &Rc<Self>) {
        if self.busy.replace(true) {
            return;
        }
        self.refresh_btn.set_sensitive(false);
        self.spinner.start();
        let ui = self.clone();
        glib::spawn_future_local(async move {
            let result = gio::spawn_blocking(checks::build_report).await;
            ui.busy.set(false);
            ui.refresh_btn.set_sensitive(true);
            ui.spinner.stop();
            match result {
                Ok(report) => ui.show_report(&report),
                Err(_) => ui.toast("Die Prüfung ist fehlgeschlagen."),
            }
        });
    }

    fn show_report(self: &Rc<Self>, r: &Report) {
        self.stamp.set_label(tr(&format!("Stand {}", clock(r.generated))).as_str());
        self.banner.set_revealed(!r.privileged.available);
        self.render_firewall();
        *self.report.borrow_mut() = Some(r.clone());
        if let Some(icon) = &self.tray {
            let summary = if r.counts.crit + r.counts.warn == 0 {
                "Keine kritischen Befunde oder Warnungen".to_string()
            } else {
                format!("{} kritisch · {} Warnungen", r.counts.crit, r.counts.warn)
            };
            icon.set_status(&summary, r.counts.crit > 0);
        }
        self.render_extras();
        self.load_docker();
        let (weak, weak2) = (Rc::downgrade(self), Rc::downgrade(self));
        let actions = RowActions {
            fix: Rc::new(move |id| {
                if let Some(ui) = weak.upgrade() {
                    ui.confirm_fix(&id);
                }
            }),
            accept: Rc::new(move |id, summary| {
                let Some(ui) = weak2.upgrade() else { return };
                if let Err(e) = accept::set(&id, summary.as_deref()) {
                    ui.toast(&e);
                    return;
                }
                // Re-evaluate the report at hand instead of running every check again.
                let Some(mut r) = ui.report.borrow().clone() else { return };
                accept::apply(&mut r.findings, &accept::load());
                r.findings.sort_by_key(|f| (f.category, f.accepted, f.status));
                r.counts = crate::model::tally(&r.findings);
                ui.toast(if summary.is_some() { "Akzeptiert – meldet sich wieder, wenn sich etwas ändert" } else { "Wird wieder gemeldet" });
                ui.show_report(&r);
            }),
        };
        for (status, label) in &self.counts {
            let n = match status {
                Status::Crit => r.counts.crit,
                Status::Warn => r.counts.warn,
                Status::Unknown => r.counts.unknown,
                Status::Info => r.counts.info,
                Status::Ok => r.counts.ok,
            };
            label.set_label(tr(&n.to_string()).as_str());
        }
        let host = [&r.host.model, &r.host.os, &r.host.kernel, &r.host.bios];
        for (row, value) in self.device.iter().zip(host) {
            row.set_subtitle(tr(value).as_str());
        }
        for (cat, badge) in &self.badges {
            let of = |s: Status| r.findings.iter().filter(|f| f.category == *cat && f.status == s && !f.accepted).count();
            let (crit, warn) = (of(Status::Crit), of(Status::Warn));
            badge.remove_css_class("error");
            badge.remove_css_class("warning");
            badge.set_visible(crit + warn > 0);
            if crit > 0 {
                badge.add_css_class("error");
                badge.set_label(tr(&crit.to_string()).as_str());
            } else if warn > 0 {
                badge.add_css_class("warning");
                badge.set_label(tr(&warn.to_string()).as_str());
            }
        }

        // Replace the per-report groups.
        let mut dynamic = self.dynamic.borrow_mut();
        for (parent, g) in dynamic.drain(..) {
            parent.remove(&g);
        }
        let urgent: Vec<&Finding> = r
            .findings
            .iter()
            .filter(|f| !f.accepted && matches!(f.status, Status::Crit | Status::Warn))
            .collect();
        let g = group(
            &format!("Handlungsbedarf ({})", urgent.len()),
            Some("Die Prüfungen lesen nur. Geändert wird erst, wenn du „Beheben“ oder eine Firewall-Aktion bestätigst – vorher siehst du immer den Befehl."),
        );
        if urgent.is_empty() {
            g.add(&info_row("Keine kritischen Befunde oder Warnungen", "Alles Wichtige ist in Ordnung."));
        }
        let mut sorted = urgent;
        sorted.sort_by_key(|f| f.status);
        for f in sorted {
            g.add(&finding_row(f, &self.toasts, Some(&actions)));
        }
        let overview = &self.pages["overview"];
        overview.append(&g);
        dynamic.push((overview.clone(), g));

        for (name, _, _, cat, _) in PAGES {
            let Some(cat) = cat else { continue };
            let g = group("Prüfungen", None);
            for f in r.findings.iter().filter(|f| f.category == cat) {
                g.add(&finding_row(f, &self.toasts, Some(&actions)));
            }
            let parent = &self.pages[name];
            parent.append(&g);
            dynamic.push((parent.clone(), g));
        }
    }

    /// Collect root-only data through the system's password dialog (polkit).
    fn unlock(self: &Rc<Self>) {
        self.with_helper(Rc::new(|ui: &Rc<Ui>| {
            let ui = ui.clone();
            glib::spawn_future_local(async move {
                let ok = gio::spawn_blocking(|| {
                    util::which("pkexec")
                        .and_then(|p| std::process::Command::new(p).arg(helper::PATH).arg("root-snapshot").output().ok())
                        .map(|o| o.status.success())
                        .unwrap_or(false)
                })
                .await
                .unwrap_or(false);
                if ok {
                    ui.toast("Zusatzdaten geladen");
                    ui.refresh();
                    ui.load_net();
                } else {
                    ui.toast("Freischalten abgebrochen oder fehlgeschlagen");
                }
            });
        }));
    }

    /// Run `then` once the root helper is installed and current; offer the one-time setup otherwise.
    fn with_helper(self: &Rc<Self>, then: Rc<dyn Fn(&Rc<Ui>)>) {
        if crate::demo::enabled() {
            self.toast("Demo-Modus: Hier wird nichts am System geändert.");
            return;
        }
        let problem = match helper::ready() {
            Ok(()) => return then(self),
            Err(e) => e,
        };
        let command = format!("sudo {} install-helper", util::self_exe());
        let dialog = adw::AlertDialog::new(
            Some(tr("Einmalige Einrichtung").as_str()),
            Some(tr(&format!(
                "{problem}\n\nFür Firewall, Mitschnitt und Systemdaten braucht die App einen Helfer mit Administratorrechten. \
                 Er wird nach {} kopiert und gehört dann root – so kann kein Programm unter deinem Konto ihn unbemerkt austauschen. \
                 Dazu kommt eine Regel, mit der die Passwortabfrage einige Minuten gültig bleibt.\n\nAusgeführt wird:\n{command}",
                helper::PATH
            )).as_str()),
        );
        dialog.add_response("cancel", tr("Abbrechen").as_str());
        dialog.add_response("setup", tr("Einrichten").as_str());
        dialog.set_response_appearance("setup", adw::ResponseAppearance::Suggested);
        dialog.set_default_response(Some("setup"));
        dialog.set_close_response("cancel");
        let ui = self.clone();
        dialog.connect_response(None, move |_, response| {
            if response != "setup" {
                return;
            }
            let (ui, then) = (ui.clone(), then.clone());
            glib::spawn_future_local(async move {
                // The only time the copy in the home directory runs as root: to install the helper.
                let ok = gio::spawn_blocking(|| {
                    util::which("pkexec")
                        .and_then(|p| std::process::Command::new(p).arg(util::self_exe()).arg("install-helper").output().ok())
                        .map(|o| o.status.success())
                        .unwrap_or(false)
                })
                .await
                .unwrap_or(false);
                if ok && helper::ready().is_ok() {
                    ui.toast("Helfer eingerichtet");
                    then(&ui);
                } else {
                    ui.toast("Einrichtung abgebrochen oder fehlgeschlagen");
                }
            });
        });
        dialog.present(Some(&self.window));
    }

    // ---------------------------------------------------------- firewall

    fn render_firewall(self: &Rc<Self>) {
        let fv = &self.fw;
        let privd = privileged::load();
        let st = fwctl::state(privd.as_ref());

        fv.updating.set(true);
        fv.toggle.remove_css_class("suggested-action");
        fv.toggle.remove_css_class("destructive-action");
        if !st.installed {
            fv.status.set_title(tr("ufw ist nicht installiert").as_str());
            fv.status.set_subtitle(tr("Installieren mit: sudo apt install ufw").as_str());
        } else if st.active {
            fv.status.set_title(tr("Firewall ist eingeschaltet").as_str());
            fv.status.set_subtitle(tr(&format!(
                "Eingehende Verbindungen werden nach den Regeln unten gefiltert, ausgehende sind {}.",
                if st.outgoing == "allow" { "erlaubt" } else { "eingeschränkt" }
            )).as_str());
            fv.toggle.set_label(tr("Ausschalten").as_str());
            fv.toggle.add_css_class("destructive-action");
        } else {
            fv.status.set_title(tr("Firewall ist ausgeschaltet").as_str());
            fv.status.set_subtitle(tr("Alle offenen Ports sind aus dem Netz erreichbar. Regeln wirken erst nach dem Einschalten.").as_str());
            fv.toggle.set_label(tr("Einschalten").as_str());
            fv.toggle.add_css_class("suggested-action");
        }
        for w in [fv.toggle.upcast_ref::<gtk::Widget>(), fv.policy.upcast_ref(), fv.add.upcast_ref()] {
            w.set_sensitive(st.installed);
        }
        fv.policy.set_selected(match st.incoming.as_str() {
            "reject" => 1,
            "allow" => 2,
            _ => 0,
        });
        fv.updating.set(false);

        for w in fv.rule_rows.borrow_mut().drain(..) {
            fv.rules.remove(&w);
        }
        let mut rows: Vec<gtk::Widget> = Vec::new();
        match &st.rules {
            None => {
                let row = info_row(
                    "Die vorhandenen Regeln sind nur mit Administratorrechten lesbar",
                    "Neue Regeln kannst du trotzdem anlegen.",
                );
                let btn = gtk::Button::with_label(tr("Regeln anzeigen").as_str());
                btn.set_valign(gtk::Align::Center);
                let weak = Rc::downgrade(self);
                btn.connect_clicked(move |_| {
                    if let Some(ui) = weak.upgrade() {
                        ui.unlock();
                    }
                });
                row.add_suffix(&btn);
                rows.push(row.upcast());
            }
            Some(rules) if rules.is_empty() => {
                rows.push(info_row("Keine eigenen Regeln", "Es gilt nur die Standardregel oben.").upcast());
            }
            Some(rules) => {
                for rule in rules {
                    let subtitle = if rule.comment.is_empty() {
                        format!("ufw {}", rule.raw)
                    } else {
                        format!("{} · ufw {}", rule.comment, rule.raw.split(" comment '").next().unwrap_or(&rule.raw))
                    };
                    let row = info_row(&rule.describe(), &subtitle);
                    let (icon, css) = match rule.action.as_str() {
                        "allow" => ("object-select-symbolic", "success"),
                        "limit" => ("dialog-warning-symbolic", "warning"),
                        _ => ("dialog-error-symbolic", "error"),
                    };
                    let img = gtk::Image::from_icon_name(icon);
                    img.add_css_class(css);
                    row.add_prefix(&img);
                    let btn = gtk::Button::from_icon_name("user-trash-symbolic");
                    btn.add_css_class("flat");
                    btn.set_valign(gtk::Align::Center);
                    btn.set_tooltip_text(Some(tr("Regel löschen").as_str()));
                    let (weak, raw, text) = (Rc::downgrade(self), rule.raw.clone(), rule.describe());
                    btn.connect_clicked(move |_| {
                        if let Some(ui) = weak.upgrade() {
                            ui.fw_confirm(fwctl::Op::Delete { rule: raw.clone() }, "Regel löschen?", &text, true);
                        }
                    });
                    row.add_suffix(&btn);
                    rows.push(row.upcast());
                }
            }
        }
        for r in &rows {
            fv.rules.add(r);
        }
        *fv.rule_rows.borrow_mut() = rows;
        *fv.state.borrow_mut() = st;

        for w in fv.domain_rows.borrow_mut().drain(..) {
            fv.domains.remove(&w);
        }
        let mut rows: Vec<gtk::Widget> = Vec::new();
        for domain in fwctl::blocked_domains() {
            let row = info_row(&domain, "gesperrt über /etc/hosts");
            let btn = gtk::Button::from_icon_name("user-trash-symbolic");
            btn.add_css_class("flat");
            btn.set_valign(gtk::Align::Center);
            btn.set_tooltip_text(Some(tr("Wieder freigeben").as_str()));
            let (weak, d) = (Rc::downgrade(self), domain.clone());
            btn.connect_clicked(move |_| {
                if let Some(ui) = weak.upgrade() {
                    ui.fw_confirm(
                        fwctl::Op::BlockDomain { domain: d.clone(), block: false },
                        "Domain wieder freigeben?",
                        &format!("{d} ist danach wieder erreichbar."),
                        false,
                    );
                }
            });
            row.add_suffix(&btn);
            fv.domains.add(&row);
            rows.push(row.upcast());
        }
        *fv.domain_rows.borrow_mut() = rows;
    }

    fn fw_confirm(self: &Rc<Self>, op: fwctl::Op, heading: &str, body: &str, destructive: bool) {
        self.fw_confirm_all(vec![op], heading, body, destructive);
    }

    /// Show what will be run and ask before changing anything.
    fn fw_confirm_all(self: &Rc<Self>, ops: Vec<fwctl::Op>, heading: &str, body: &str, destructive: bool) {
        let command = match ops.iter().map(fwctl::command_line).collect::<Result<Vec<_>, _>>() {
            Ok(c) => c.join("\n"),
            Err(e) => {
                self.toast(&e);
                self.render_firewall();
                return;
            }
        };
        let dialog = adw::AlertDialog::new(Some(tr(heading).as_str()), Some(tr(&format!("{body}\n\nAusgeführt wird:\n{command}")).as_str()));
        dialog.add_response("cancel", tr("Abbrechen").as_str());
        dialog.add_response("apply", tr("Anwenden").as_str());
        dialog.set_response_appearance(
            "apply",
            if destructive { adw::ResponseAppearance::Destructive } else { adw::ResponseAppearance::Suggested },
        );
        dialog.set_default_response(Some("cancel"));
        dialog.set_close_response("cancel");
        let ui = self.clone();
        dialog.connect_response(None, move |_, response| {
            if response == "apply" {
                ui.fw_run_all(ops.clone());
            } else {
                ui.render_firewall(); // put the controls back
            }
        });
        dialog.present(Some(&self.window));
    }

    fn fw_run(self: &Rc<Self>, op: fwctl::Op) {
        self.fw_run_all(vec![op]);
    }

    /// Hand the changes to the root helper; the system asks for the password once.
    fn fw_run_all(self: &Rc<Self>, ops: Vec<fwctl::Op>) {
        self.with_helper(Rc::new(move |ui: &Rc<Ui>| ui.fw_run_now(ops.clone())));
    }

    fn fw_run_now(self: &Rc<Self>, ops: Vec<fwctl::Op>) {
        let Ok(request) = serde_json::to_string(&ops) else { return };
        let ui = self.clone();
        glib::spawn_future_local(async move {
            let output = gio::spawn_blocking(move || {
                let pkexec = util::which("pkexec")?;
                std::process::Command::new(pkexec).arg(helper::PATH).arg("fw-apply").arg(request).output().ok()
            })
            .await
            .ok()
            .flatten();
            match output {
                Some(o) if o.status.success() => ui.toast("Änderung durchgeführt"),
                // pkexec: 126 = dialog dismissed, 127 = not authorised
                Some(o) if matches!(o.status.code(), Some(126) | Some(127)) => ui.toast("Abgebrochen – nichts geändert"),
                Some(o) => {
                    let msg = String::from_utf8_lossy(&o.stderr).trim().to_string();
                    let dialog = adw::AlertDialog::new(Some(tr("Die Änderung ist fehlgeschlagen").as_str()), Some(tr(&msg).as_str()));
                    dialog.add_response("ok", tr("Schließen").as_str());
                    dialog.present(Some(&ui.window));
                }
                None => ui.toast("pkexec ist nicht verfügbar"),
            }
            ui.render_firewall();
            ui.refresh();
        });
    }

    /// Form for a new rule. `proto`: 0 = TCP and UDP, 1 = TCP, 2 = UDP.
    fn rule_dialog(self: &Rc<Self>, port: &str, proto: u32) {
        let combo = |title: &str, items: &[&str]| {
            let row = adw::ComboRow::new();
            row.set_title(tr(title).as_str());
            row.set_model(Some(&string_list(items)));
            row
        };
        let entry = |title: &str| {
            let row = adw::EntryRow::new();
            row.set_title(tr(title).as_str());
            row
        };
        let action = combo("Aktion", &["Erlauben", "Blockieren", "Ablehnen", "Begrenzen"]);
        let direction = combo("Richtung", &["Eingehend", "Ausgehend"]);
        let port_row = entry("Port, z. B. 22, 8000-8010 oder 80,443 (leer = alle)");
        port_row.set_text(port);
        let proto_row = combo("Protokoll", &["TCP und UDP", "TCP", "UDP"]);
        proto_row.set_selected(proto);
        let addr = entry("Adresse oder Netz (leer = alle)");
        let comment = entry("Kommentar (optional)");

        // Offer the attached local networks as a hint for the address field.
        let local: Vec<String> = devices::local_subnets();
        let form = group(
            "",
            if local.is_empty() { None } else { Some("") },
        );
        if !local.is_empty() {
            form.set_description(Some(tr(&format!("Dein lokales Netz: {}", local.join(", "))).as_str()));
        }
        for row in [action.upcast_ref::<gtk::Widget>(), direction.upcast_ref(), port_row.upcast_ref(), proto_row.upcast_ref(), addr.upcast_ref(), comment.upcast_ref()] {
            form.add(row);
        }

        let preview = gtk::Label::builder().wrap(true).xalign(0.0).build();
        preview.add_css_class("monospace");
        let cancel = gtk::Button::with_label(tr("Abbrechen").as_str());
        let apply = gtk::Button::with_label(tr("Regel anlegen").as_str());
        apply.add_css_class("suggested-action");
        let buttons = gtk::Box::new(gtk::Orientation::Horizontal, 8);
        buttons.set_halign(gtk::Align::End);
        buttons.append(&cancel);
        buttons.append(&apply);

        let content = gtk::Box::new(gtk::Orientation::Vertical, 16);
        content.set_margin_top(12);
        content.set_margin_bottom(16);
        content.set_margin_start(16);
        content.set_margin_end(16);
        content.append(&form);
        content.append(&preview);
        content.append(&buttons);
        let view = adw::ToolbarView::new();
        view.add_top_bar(&adw::HeaderBar::new());
        view.set_content(Some(&content));
        let dialog = adw::Dialog::new();
        dialog.set_title(tr("Firewall-Regel anlegen").as_str());
        dialog.set_content_width(560);
        dialog.set_child(Some(&view));

        let read = {
            let (action, direction, port_row, proto_row, addr, comment) =
                (action.clone(), direction.clone(), port_row.clone(), proto_row.clone(), addr.clone(), comment.clone());
            move || {
                fwctl::Op::Add(fwctl::RuleSpec {
                    action: ["allow", "deny", "reject", "limit"][(action.selected() as usize).min(3)].into(),
                    direction: if direction.selected() == 1 { "out" } else { "in" }.into(),
                    port: port_row.text().to_string(),
                    proto: ["", "tcp", "udp"][(proto_row.selected() as usize).min(2)].into(),
                    addr: addr.text().to_string(),
                    comment: comment.text().to_string(),
                })
            }
        };
        // Live preview of the command, or of what is still wrong.
        let update = {
            let (read, preview, apply) = (read.clone(), preview.clone(), apply.clone());
            Rc::new(move || match fwctl::command_line(&read()) {
                Ok(cmd) => {
                    preview.remove_css_class("error");
                    preview.set_label(tr(&cmd).as_str());
                    apply.set_sensitive(true);
                }
                Err(e) => {
                    preview.add_css_class("error");
                    preview.set_label(tr(&e).as_str());
                    apply.set_sensitive(false);
                }
            })
        };
        update();
        for row in [&port_row, &addr, &comment] {
            let update = update.clone();
            row.connect_changed(move |_| update());
        }
        for row in [&action, &direction, &proto_row] {
            let update = update.clone();
            row.connect_selected_notify(move |_| update());
        }
        {
            let dialog = dialog.clone();
            cancel.connect_clicked(move |_| {
                dialog.close();
            });
        }
        {
            let (ui, dialog) = (self.clone(), dialog.clone());
            apply.connect_clicked(move |_| {
                dialog.close();
                ui.fw_run(read());
            });
        }
        dialog.present(Some(&self.window));
    }

    // ----------------------------------------------------------- devices

    fn load_devices(self: &Rc<Self>, active: bool) {
        let dv = &self.dev;
        if dv.loading.replace(true) {
            return;
        }
        dv.button.set_sensitive(false);
        dv.spinner.start();
        let ui = self.clone();
        glib::spawn_future_local(async move {
            let result = gio::spawn_blocking(move || devices::discover(active)).await;
            ui.dev.loading.set(false);
            ui.dev.loaded.set(true);
            ui.dev.button.set_sensitive(true);
            ui.dev.spinner.stop();
            match result {
                Ok(networks) => ui.render_devices(&networks),
                Err(_) => ui.toast("Die Gerätesuche ist fehlgeschlagen."),
            }
        });
    }

    fn render_devices(self: &Rc<Self>, networks: &[devices::Network]) {
        let dv = &self.dev;
        for g in dv.groups.borrow_mut().drain(..) {
            dv.body.remove(&g);
        }
        let mut groups = Vec::new();
        if networks.is_empty() {
            let g = group("Kein lokales Netz verbunden", None);
            g.add(&info_row("Keine Geräte", "Verbinde den Laptop mit einem WLAN oder Netzwerkkabel."));
            groups.push(g);
        }
        for n in networks {
            let kind = if n.wireless { "WLAN" } else { "Kabelnetz" };
            let mut description = format!("{} · {} · {} Geräte", n.iface, n.subnet, n.devices.len());
            if !n.sweepable {
                description.push_str(" · zu groß zum Durchsuchen");
            }
            let g = group(kind, Some(&description));
            for d in &n.devices {
                let mut info = vec![d.ip.clone(), d.mac.to_uppercase()];
                let title = d.title();
                for extra in [&d.vendor, &d.hostname].into_iter().flatten() {
                    if *extra != title && !d.is_self {
                        info.push(extra.clone());
                    }
                }
                let row = info_row(&title, &info.join(" · "));
                row.set_subtitle_selectable(true);
                let icon = if d.is_gateway {
                    "network-server-symbolic"
                } else if d.is_self {
                    "computer-symbolic"
                } else if d.random_mac {
                    "phone-symbolic"
                } else if n.wireless {
                    "network-wireless-symbolic"
                } else {
                    "network-wired-symbolic"
                };
                row.add_prefix(&gtk::Image::from_icon_name(icon));
                if !d.other_ips.is_empty() {
                    row.set_tooltip_text(Some(tr(&format!("Weitere Adressen: {}", d.other_ips.join(", "))).as_str()));
                }
                // Suffixes are packed from the right; the most important tag goes last.
                if !d.active {
                    row.add_suffix(&tag("zuletzt gesehen", "fw-z-loopback"));
                }
                if d.random_mac && !d.is_self {
                    row.add_suffix(&tag("zufällige MAC", "fw-z-loopback"));
                }
                if d.is_new {
                    row.add_suffix(&tag("Neu", "warning"));
                }
                if d.is_self {
                    row.add_suffix(&tag("Dieser Laptop", "success"));
                }
                if d.is_gateway {
                    row.add_suffix(&tag("Router", "accent"));
                }
                if !d.is_self {
                    row.add_suffix(&self.device_menu(d));
                }
                g.add(&row);
            }
            groups.push(g);
        }
        for g in &groups {
            dv.body.append(g);
        }
        *dv.groups.borrow_mut() = groups;
    }

    // ----------------------------------------------------------- network

    fn load_net(self: &Rc<Self>) {
        if self.net.loading.replace(true) {
            return;
        }
        let ui = self.clone();
        glib::spawn_future_local(async move {
            let result = gio::spawn_blocking(|| {
                let privd = privileged::load();
                net::snapshot(privd.as_ref())
            })
            .await;
            ui.net.loading.set(false);
            if let Ok(snap) = result {
                ui.net.session.borrow_mut().update(&snap, util::now());
                *ui.net.last.borrow_mut() = Some(snap);
                ui.render_net(false);
                ui.resolve_names();
            }
        });
    }

    fn selected_zone(&self) -> Option<Zone> {
        self.net.zone.get()
    }

    fn render_net(self: &Rc<Self>, force: bool) {
        let nv = &self.net;
        let last = nv.last.borrow();
        let Some(n) = last.as_ref() else { return };

        nv.stamp.set_label(tr(&format!("Stand {}", clock(n.generated))).as_str());
        for (zone, number, sub, _) in &nv.cards {
            let t = n.totals.get(zone).cloned().unwrap_or_default();
            number.set_label(tr(&t.connections.to_string()).as_str());
            sub.set_label(tr(&format!("{} Gegenstellen · {} Programme", t.hosts, t.programs)).as_str());
        }

        let zone_filter = self.selected_zone();
        let names = nv.names.lock().unwrap().clone();
        let show_names = nv.resolve.is_active();
        // Country and operator of every remote address (offline lookup).
        let origin: HashMap<String, String> = if geo::available() {
            n.programs
                .iter()
                .flat_map(|p| p.endpoints.iter())
                .filter(|e| e.zone == Zone::Internet)
                .filter_map(|e| Some((e.remote.clone(), geo::lookup(e.remote.parse().ok()?)?.short())))
                .collect()
        } else {
            HashMap::new()
        };
        let shown = |z: Zone| match zone_filter {
            Some(f) => z == f,
            None => z != Zone::Loopback,
        };
        // Connections that have closed, for as long as the setting says.
        let now = util::now();
        let session = nv.session.borrow();
        let ended: Vec<&session::Seen> = match nv.keep.selected() {
            0 => Vec::new(),
            1 => session.ended(now, Some(300)),
            2 => session.ended(now, Some(1800)),
            _ => session.ended(now, None),
        }
        .into_iter()
        .filter(|e| shown(e.zone))
        .collect();
        let ended_for_graph: Vec<graph::Ended> = ended
            .iter()
            .map(|e| graph::Ended { program: &e.program, remote: &e.remote, zone: e.zone, port: e.port, service: e.service, age: now.saturating_sub(e.last) })
            .collect();
        let mut origin = origin;
        if geo::available() {
            for e in ended.iter().filter(|e| e.zone == Zone::Internet) {
                if !origin.contains_key(&e.remote) {
                    if let Some(g) = e.remote.parse().ok().and_then(geo::lookup) {
                        origin.insert(e.remote.clone(), g.short());
                    }
                }
            }
        }
        self.graph.update(n, zone_filter, if show_names { &names } else { &NO_NAMES }, &origin, &ended_for_graph);

        // Rebuilding rows resets hover and focus, so skip it when the set of
        // connections is unchanged (byte counters change all the time).
        let mut fingerprint = serde_json::to_string(&n.listeners).unwrap_or_default();
        for p in &n.programs {
            fingerprint.push_str(&p.name);
            for e in &p.endpoints {
                fingerprint.push_str(&format!("|{} {} {} {} {}", e.remote, e.port, e.proto, e.inbound, e.count));
            }
        }
        for e in &ended {
            // The "vor n min" text changes once a minute.
            fingerprint.push_str(&format!("|-{} {} {} {}", e.program, e.remote, e.port, now.saturating_sub(e.last) / 60));
        }
        if !force && *nv.fingerprint.borrow() == fingerprint {
            return;
        }
        *nv.fingerprint.borrow_mut() = fingerprint;

        for w in nv.program_rows.borrow_mut().drain(..) {
            nv.programs.remove(&w);
        }
        let addr_of = |remote: &str, port: u16| if remote.contains(':') { format!("[{remote}]:{port}") } else { format!("{remote}:{port}") };
        // Programs with open connections first, then those where everything has closed.
        let mut closed_by_program: BTreeMap<&str, Vec<&session::Seen>> = BTreeMap::new();
        for e in &ended {
            closed_by_program.entry(e.program.as_str()).or_default().push(e);
        }
        let open: Vec<&net::Program> = n.programs.iter().filter(|p| p.zones.keys().any(|z| shown(*z)) || closed_by_program.contains_key(p.name.as_str())).collect();
        let only_closed: Vec<&str> = closed_by_program.keys().copied().filter(|name| !open.iter().any(|p| p.name == *name)).collect();
        let entries = open.iter().map(|p| (p.name.as_str(), Some(*p))).chain(only_closed.iter().map(|name| (*name, None)));

        let mut rows = Vec::new();
        for (name, program) in entries {
            let closed = closed_by_program.get(name).map(Vec::as_slice).unwrap_or(&[]);
            let row = adw::ExpanderRow::new();
            row.set_use_markup(false);
            row.set_title(tr(if name.is_empty() { "System / anderer Benutzer" } else { name }).as_str());
            match program {
                Some(p) if p.pids.len() > 1 => row.set_subtitle(tr(&format!("{} Prozesse", p.pids.len())).as_str()),
                None => {
                    row.set_subtitle(tr("Keine offene Verbindung mehr").as_str());
                    row.add_css_class("dim-label");
                }
                _ => {}
            }
            // Suffixes are packed from the right, so add them in reverse order.
            if !closed.is_empty() {
                row.add_suffix(&tag(&format!("{} beendet", closed.len()), "fw-z-loopback"));
            }
            if let Some(p) = program {
                for (zone, label, _, css) in ZONES.into_iter().rev() {
                    if let Some(c) = p.zones.get(&zone).filter(|_| shown(zone)) {
                        row.add_suffix(&tag(&format!("{label} {c}"), css));
                    }
                }
            }
            for e in program.iter().flat_map(|p| p.endpoints.iter()).filter(|e| shown(e.zone)) {
                let mut info: Vec<String> = Vec::new();
                if show_names {
                    if let Some(Some(host)) = names.get(&e.remote) {
                        info.push(host.clone());
                    }
                }
                info.extend(origin.get(&e.remote).cloned());
                info.extend(e.service.map(String::from));
                info.push(e.proto.to_uppercase());
                if e.count > 1 {
                    info.push(format!("×{}", e.count));
                }
                let child = info_row(&format!("{} {}", if e.inbound { "←" } else { "→" }, addr_of(&e.remote, e.port)), &info.join(" · "));
                child.add_css_class("monospace");
                let (zlabel, zcss) = zone_meta(e.zone);
                child.add_suffix(&tag(zlabel, zcss));
                if e.zone != Zone::Loopback {
                    child.add_suffix(&self.endpoint_menu(&e.remote, e.port, e.inbound));
                }
                row.add_row(&child);
            }
            for e in closed.iter().take(60) {
                let mut info = vec![format!("beendet {}", session::ago(now.saturating_sub(e.last)))];
                if show_names {
                    if let Some(Some(host)) = names.get(&e.remote) {
                        info.push(host.clone());
                    }
                }
                info.extend(origin.get(&e.remote).cloned());
                info.extend(e.service.map(String::from));
                info.push(e.proto.to_uppercase());
                let child = info_row(&format!("{} {}", if e.inbound { "←" } else { "→" }, addr_of(&e.remote, e.port)), &info.join(" · "));
                child.add_css_class("monospace");
                child.add_css_class("dim-label");
                child.add_suffix(&tag("beendet", "fw-z-loopback"));
                child.add_suffix(&self.endpoint_menu(&e.remote, e.port, e.inbound));
                row.add_row(&child);
            }
            row.set_expanded(nv.expanded.borrow().contains(name));
            let (expanded, name, weak) = (nv.expanded.clone(), name.to_string(), Rc::downgrade(self));
            row.connect_expanded_notify(move |r| {
                if r.is_expanded() {
                    expanded.borrow_mut().insert(name.clone());
                    if let Some(ui) = weak.upgrade() {
                        ui.resolve_names();
                    }
                } else {
                    expanded.borrow_mut().remove(&name);
                }
            });
            nv.programs.add(&row);
            rows.push(row.upcast::<gtk::Widget>());
        }
        if rows.is_empty() {
            let empty = info_row("Keine Verbindungen in dieser Auswahl", "");
            nv.programs.add(&empty);
            rows.push(empty.upcast());
        }
        *nv.program_rows.borrow_mut() = rows;

        for w in nv.port_rows.borrow_mut().drain(..) {
            nv.ports.remove(&w);
        }
        let mut rows = Vec::new();
        let show_local = nv.show_local.is_active();
        for l in n.listeners.iter().filter(|l| !l.ephemeral && (show_local || l.exposure != Exposure::Loopback)) {
            let who = match (&l.container, &l.process) {
                (Some(c), _) => format!("Docker: {c}"),
                (None, Some(p)) => p.clone(),
                (None, None) => "unbekannt (anderer Benutzer)".to_string(),
            };
            let title = match l.service {
                Some(s) => format!("{} {} · {s}", l.proto.to_uppercase(), l.port),
                None => format!("{} {}", l.proto.to_uppercase(), l.port),
            };
            let row = info_row(&title, &format!("{who} · {}", l.addrs.join(", ")));
            let reachable = matches!(l.exposure, Exposure::All | Exposure::Lan);
            let (label, css) = match l.firewall {
                fwctl::Verdict::Blocked if reachable => ("Firewall sperrt", "success"),
                fwctl::Verdict::Restricted if reachable => ("Firewall: nur bestimmte Absender", "warning"),
                _ => exposure_style(l.exposure),
            };
            row.add_suffix(&tag(label, css));
            if matches!(l.exposure, Exposure::All | Exposure::Lan) && l.container.is_none() {
                let btn = gtk::Button::from_icon_name("security-high-symbolic");
                btn.add_css_class("flat");
                btn.set_valign(gtk::Align::Center);
                btn.set_tooltip_text(Some(tr("Firewall-Regel für diesen Port anlegen").as_str()));
                let (weak, port, proto) = (Rc::downgrade(self), l.port.to_string(), if l.proto == "udp" { 2 } else { 1 });
                btn.connect_clicked(move |_| {
                    if let Some(ui) = weak.upgrade() {
                        ui.rule_dialog(&port, proto);
                    }
                });
                row.add_suffix(&btn);
            }
            nv.ports.add(&row);
            rows.push(row.upcast::<gtk::Widget>());
        }
        if rows.is_empty() {
            let empty = info_row("Kein Port ist von außen erreichbar", "");
            nv.ports.add(&empty);
            rows.push(empty.upcast());
        }
        *nv.port_rows.borrow_mut() = rows;
    }

    /// Reverse-resolve the remote addresses in the background, a batch at a time.
    fn resolve_names(self: &Rc<Self>) {
        let nv = &self.net;
        if !nv.resolve.is_active() || nv.resolving.get() {
            return;
        }
        let wanted: Vec<String> = {
            let last = nv.last.borrow();
            let Some(n) = last.as_ref() else { return };
            let known = nv.names.lock().unwrap();
            let mut seen = HashSet::new();
            n.programs
                .iter()
                .flat_map(|p| p.endpoints.iter())
                .filter(|e| e.zone != Zone::Loopback && !known.contains_key(&e.remote))
                .filter(|e| seen.insert(e.remote.clone()))
                .map(|e| e.remote.clone())
                .take(25)
                .collect()
        };
        if wanted.is_empty() {
            return;
        }
        nv.resolving.set(true);
        let names = nv.names.clone();
        let ui = self.clone();
        glib::spawn_future_local(async move {
            let _ = gio::spawn_blocking(move || {
                for ip in wanted {
                    let name = ip.parse().ok().and_then(net::reverse_lookup);
                    names.lock().unwrap().insert(ip, name);
                }
            })
            .await;
            ui.net.resolving.set(false);
            ui.render_net(true);
            ui.resolve_names();
        });
    }


    // ------------------------------------------------- block / disconnect

    /// The three things one can do with a connection, as a list for a popover.
    fn endpoint_actions(self: &Rc<Self>, remote: &str, port: u16, inbound: bool, popover: &gtk::Popover) -> gtk::Box {
        let list = gtk::Box::new(gtk::Orientation::Vertical, 2);
        for (label, action) in [("Mitschneiden", 0u8), ("Verbindung trennen", 1), ("Gegenstelle blockieren …", 2)] {
            let item = gtk::Button::with_label(tr(label).as_str());
            item.add_css_class("flat");
            if let Some(l) = item.child().and_downcast::<gtk::Label>() {
                l.set_xalign(0.0);
            }
            let (weak, remote, popover) = (Rc::downgrade(self), remote.to_string(), popover.clone());
            item.connect_clicked(move |_| {
                popover.popdown();
                let Some(ui) = weak.upgrade() else { return };
                let port = port.to_string();
                match action {
                    0 => ui.open_capture(&remote, &port),
                    1 => ui.disconnect_host(&remote, if inbound { "" } else { &port }),
                    _ => ui.block_host(&remote, inbound),
                }
            });
            list.append(&item);
        }
        list
    }

    /// "⋮" button of a connection: record it, close it, or block the other side.
    fn endpoint_menu(self: &Rc<Self>, remote: &str, port: u16, inbound: bool) -> gtk::MenuButton {
        let button = gtk::MenuButton::new();
        button.set_icon_name("view-more-symbolic");
        button.add_css_class("flat");
        button.set_valign(gtk::Align::Center);
        button.set_tooltip_text(Some(tr("Mitschneiden, trennen oder blockieren").as_str()));
        let (weak, remote) = (Rc::downgrade(self), remote.to_string());
        // The popover is built when first opened; the list is rebuilt often.
        button.set_create_popup_func(move |button| {
            let Some(ui) = weak.upgrade() else { return };
            let popover = gtk::Popover::new();
            popover.set_child(Some(&ui.endpoint_actions(&remote, port, inbound, &popover)));
            button.set_popover(Some(&popover));
        });
        button
    }

    /// Select a page by its name.
    fn go_to(&self, page: &str) {
        if let Some(i) = PAGES.iter().position(|p| p.0 == page) {
            self.sidebar.select_row(self.sidebar.row_at_index(i as i32).as_ref());
        }
    }

    /// Firewall rule against one address, and close what is already open.
    fn block_host(self: &Rc<Self>, host: &str, inbound: bool) {
        if host.parse::<IpAddr>().is_err() {
            self.toast("Bitte zuerst die IP-Adresse der Gegenstelle eintragen.");
            return;
        }
        let rule = fwctl::RuleSpec {
            action: if inbound { "deny" } else { "reject" }.into(),
            direction: if inbound { "in" } else { "out" }.into(),
            addr: host.into(),
            ..Default::default()
        };
        let mut body = if inbound {
            format!("{host} kann danach keine Verbindung mehr zu diesem Laptop aufbauen. Bestehende Verbindungen werden sofort getrennt.")
        } else {
            format!("Programme auf diesem Laptop erreichen {host} danach nicht mehr. Bestehende Verbindungen werden sofort getrennt.")
        };
        body.push_str("\n\nBlockiert wird nur diese eine Adresse – große Dienste nutzen viele Adressen. Die Regel lässt sich auf der Seite „Firewall“ wieder löschen.");
        if !self.fw.state.borrow().active {
            body.push_str("\n\nAchtung: Die Firewall ist ausgeschaltet. Die Regel wirkt erst, wenn du sie einschaltest.");
        }
        self.fw_confirm_all(
            vec![fwctl::Op::Add(rule), fwctl::Op::Drop { addr: host.into(), port: String::new() }],
            "Gegenstelle blockieren?",
            &body,
            true,
        );
    }

    fn disconnect_host(self: &Rc<Self>, host: &str, port: &str) {
        if host.parse::<IpAddr>().is_err() {
            self.toast("Bitte zuerst die IP-Adresse der Gegenstelle eintragen.");
            return;
        }
        self.fw_confirm(
            fwctl::Op::Drop { addr: host.into(), port: port.into() },
            "Verbindung trennen?",
            &format!("Die bestehenden Verbindungen zu {host} werden sofort beendet. Das Programm kann sich danach neu verbinden – dauerhaft hilft nur Blockieren."),
            true,
        );
    }


    // ---------------------------------------------------- settings, fixes

    fn render_extras(&self) {
        let ex = &self.extras;
        ex.updating.set(true);
        ex.watch.set_active(watch::timer_enabled());
        ex.updating.set(false);
        let age = |days: Option<u64>| match days {
            Some(0) => "heute geladen".to_string(),
            Some(d) => format!("{d} Tage alt"),
            None => "noch nicht geladen".to_string(),
        };
        ex.geo.set_subtitle(tr(&if geo::available() {
            format!("Vorhanden ({}) · Zuordnung läuft offline · Quelle: db-ip.com", age(geo::age_days()))
        } else {
            "Fehlt · lädt einmalig ca. 18 MB von db-ip.com, danach offline".to_string()
        }).as_str());
        ex.blocklist.set_subtitle(tr(&if blocklist::available() {
            format!("Vorhanden ({}) · markiert bekannte Domains im Mitschnitt · Quelle: StevenBlack/hosts", age(blocklist::age_days()))
        } else {
            "Fehlt · lädt einmalig ca. 2 MB von GitHub, danach offline".to_string()
        }).as_str());
    }

    fn export_report(self: &Rc<Self>) {
        let Some(r) = self.report.borrow().clone() else {
            self.toast("Der Bericht ist noch nicht fertig.");
            return;
        };
        let dialog = gtk::FileDialog::builder().title(tr("Bericht speichern").as_str()).initial_name(tr("sicherheitsbericht.html").as_str()).build();
        let ui = self.clone();
        dialog.save(Some(&self.window), gio::Cancellable::NONE, move |result| {
            let Some(path) = result.ok().and_then(|f| f.path()) else { return };
            let html = report::html(&r, &clock_fmt(r.generated, "%d.%m.%Y %H:%M"));
            match std::fs::write(&path, html) {
                Ok(()) => ui.toast(&format!("Gespeichert: {}", path.display())),
                Err(e) => ui.toast(&format!("Speichern fehlgeschlagen: {e}")),
            }
        });
    }

    /// Show what the fix for a finding does, then run it (through pkexec when it needs root).
    fn confirm_fix(self: &Rc<Self>, id: &str) {
        if crate::demo::enabled() {
            self.toast("Demo-Modus: Hier wird nichts am System geändert.");
            return;
        }
        if id == "fw.active" {
            self.fw.toggle.emit_clicked(); // same dialog as on the firewall page
            return;
        }
        let Some(fix) = fixes::for_finding(id) else { return };
        if fix.root && helper::ready().is_err() {
            let id = id.to_string();
            return self.with_helper(Rc::new(move |ui: &Rc<Ui>| ui.confirm_fix(&id)));
        }
        let prefix = if fix.root { "sudo " } else { "" };
        let commands: Vec<String> = fix.commands.iter().map(|c| format!("{prefix}{c}")).collect();
        let mut body = format!("Ausgeführt wird:\n{}", commands.join("\n"));
        if !fix.note.is_empty() {
            body = format!("{}\n\n{body}", fix.note);
        }
        if fix.root {
            body.push_str("\n\nDas System fragt dafür nach deinem Passwort.");
        }
        let dialog = adw::AlertDialog::new(Some(tr("Befund beheben?").as_str()), Some(tr(&body).as_str()));
        dialog.add_response("cancel", tr("Abbrechen").as_str());
        dialog.add_response("apply", tr("Beheben").as_str());
        dialog.set_response_appearance("apply", adw::ResponseAppearance::Suggested);
        dialog.set_default_response(Some("cancel"));
        dialog.set_close_response("cancel");
        let (ui, id, root) = (self.clone(), id.to_string(), fix.root);
        dialog.connect_response(None, move |_, response| {
            if response != "apply" {
                return;
            }
            ui.toast("Korrektur läuft …");
            let (ui, id) = (ui.clone(), id.clone());
            glib::spawn_future_local(async move {
                let result: Result<String, String> = gio::spawn_blocking(move || {
                    if !root {
                        return fixes::apply(&id);
                    }
                    let pkexec = util::which("pkexec").ok_or("pkexec ist nicht verfügbar")?;
                    let out = std::process::Command::new(pkexec)
                        .arg(helper::PATH)
                        .arg("fix")
                        .arg(&id)
                        .output()
                        .map_err(|e| e.to_string())?;
                    match out.status.code() {
                        Some(0) => Ok(String::from_utf8_lossy(&out.stdout).trim().to_string()),
                        Some(126) | Some(127) => Err("Abgebrochen – nichts geändert".into()),
                        _ => Err(String::from_utf8_lossy(&out.stderr).trim().to_string()),
                    }
                })
                .await
                .unwrap_or_else(|_| Err("Die Korrektur ist abgebrochen.".into()));
                match result {
                    Ok(msg) => ui.toast(&msg),
                    Err(e) => {
                        let dialog = adw::AlertDialog::new(Some(tr("Die Korrektur ist fehlgeschlagen").as_str()), Some(tr(&e).as_str()));
                        dialog.add_response("ok", tr("Schließen").as_str());
                        dialog.present(Some(&ui.window));
                    }
                }
                ui.refresh();
            });
        });
        dialog.present(Some(&self.window));
    }

    // ------------------------------------------------------------ docker

    fn load_docker(self: &Rc<Self>) {
        if self.docker.loading.replace(true) {
            return;
        }
        let ui = self.clone();
        glib::spawn_future_local(async move {
            let list = gio::spawn_blocking(docker::list).await.ok().flatten();
            let dv = &ui.docker;
            dv.loading.set(false);
            for w in dv.rows.borrow_mut().drain(..) {
                dv.group.remove(&w);
            }
            let mut rows: Vec<gtk::Widget> = Vec::new();
            match list {
                None => rows.push(info_row("Docker ist nicht installiert oder nicht zugänglich", "").upcast()),
                Some(l) if l.is_empty() => rows.push(info_row("Es läuft kein Container", "").upcast()),
                Some(containers) => {
                    let mut images: Vec<String> = containers.iter().map(|c| c.image.clone()).collect();
                    images.sort();
                    images.dedup();
                    *dv.images.borrow_mut() = images;
                    for c in containers {
                        let row = adw::ExpanderRow::new();
                        row.set_use_markup(false);
                        row.set_title(tr(&c.name).as_str());
                        row.set_subtitle(tr(&c.image).as_str());
                        // Suffixes are packed from the right.
                        if c.runs_as_root() {
                            row.add_suffix(&tag("root", "fw-z-loopback"));
                        }
                        if c.host_network {
                            row.add_suffix(&tag("Host-Netz", "warning"));
                        }
                        if c.privileged || c.docker_socket {
                            row.add_suffix(&tag(if c.privileged { "privilegiert" } else { "docker.sock" }, "error"));
                        }
                        let open = c.open_ports().len();
                        if open > 0 {
                            row.add_suffix(&tag(&format!("{open} offen"), "error"));
                        }
                        let mut seen = HashSet::new();
                        for p in c.ports.iter().filter(|p| seen.insert((p.host_port, p.proto.clone(), p.open()))) {
                            let child = info_row(
                                &format!("{} {} → Container-Port {}", p.proto.to_uppercase(), p.host_port, p.container_port),
                                &if p.open() {
                                    format!("Aus dem ganzen Netz erreichbar. Besser: {}", p.local_binding())
                                } else {
                                    format!("Nur auf diesem Laptop erreichbar ({})", p.host_ip)
                                },
                            );
                            child.add_suffix(&tag(if p.open() { "Alle Netze" } else { "Nur lokal" }, if p.open() { "error" } else { "success" }));
                            if p.open() {
                                let btn = gtk::Button::from_icon_name("edit-copy-symbolic");
                                btn.add_css_class("flat");
                                btn.set_valign(gtk::Align::Center);
                                btn.set_tooltip_text(Some(tr("Zeile für die Compose-Datei kopieren").as_str()));
                                let (line, toasts) = (p.local_binding(), ui.toasts.clone());
                                btn.connect_clicked(move |b| {
                                    b.clipboard().set_text(&line);
                                    toasts.add_toast(adw::Toast::new(tr("Zeile kopiert – in der Compose-Datei unter „ports:“ einsetzen").as_str()));
                                });
                                child.add_suffix(&btn);
                                if c.compose_file.ends_with(".yml") || c.compose_file.ends_with(".yaml") {
                                    let fix = gtk::Button::with_label(tr("Beschränken …").as_str());
                                    fix.set_valign(gtk::Align::Center);
                                    fix.set_tooltip_text(Some(tr("Ändert die Compose-Datei so, dass der Port nur noch auf diesem Laptop erreichbar ist").as_str()));
                                    let (weak, file, port) = (Rc::downgrade(&ui), c.compose_file.clone(), p.container_port.clone());
                                    fix.connect_clicked(move |_| {
                                        if let Some(ui) = weak.upgrade() {
                                            ui.confirm_restrict(&file, &port);
                                        }
                                    });
                                    child.add_suffix(&fix);
                                }
                            }
                            row.add_row(&child);
                        }
                        if !c.compose_file.is_empty() {
                            row.add_row(&info_row("Compose-Datei", &c.compose_file));
                        }
                        if c.ports.is_empty() && c.compose_file.is_empty() {
                            row.set_enable_expansion(false);
                        }
                        rows.push(row.upcast());
                    }
                }
            }
            for r in &rows {
                dv.group.add(r);
            }
            *dv.rows.borrow_mut() = rows;
        });
    }


    // --------------------------------------- docker: restrict, image scan

    /// Show the exact change to the compose file, then apply it and recreate the container.
    fn confirm_restrict(self: &Rc<Self>, compose_file: &str, container_port: &str) {
        if crate::demo::enabled() {
            self.toast("Demo-Modus: Hier wird nichts am System geändert.");
            return;
        }
        let changes = std::fs::read_to_string(compose_file).ok().and_then(|t| docker::bind_local(&t, container_port));
        let Some((_, changes)) = changes else {
            self.toast("In der Compose-Datei steht keine Port-Zeile, die sich automatisch ändern lässt.");
            return;
        };
        let diff: Vec<String> = changes.iter().map(|(old, new)| format!("{old}\nwird zu\n{new}")).collect();
        let dialog = adw::AlertDialog::new(
            Some(tr("Port auf diesen Laptop beschränken?").as_str()),
            Some(tr(&format!(
                "In {compose_file}:\n\n{}\n\nDanach läuft „docker compose up -d“; der Container startet dabei kurz neu. \
                 Der Dienst ist anschließend nur noch von diesem Laptop aus erreichbar. \
                 Die bisherige Datei bleibt als {compose_file}.picket-sicherung erhalten.",
                diff.join("\n\n")
            )).as_str()),
        );
        dialog.add_response("cancel", tr("Abbrechen").as_str());
        dialog.add_response("apply", tr("Ändern und neu starten").as_str());
        dialog.set_response_appearance("apply", adw::ResponseAppearance::Suggested);
        dialog.set_default_response(Some("cancel"));
        dialog.set_close_response("cancel");
        let (ui, file, port) = (self.clone(), compose_file.to_string(), container_port.to_string());
        dialog.connect_response(None, move |_, response| {
            if response != "apply" {
                return;
            }
            ui.toast("Container wird neu gestartet …");
            let (ui, file, port) = (ui.clone(), file.clone(), port.clone());
            glib::spawn_future_local(async move {
                let result = gio::spawn_blocking(move || docker::restrict_port(&file, &port)).await.unwrap_or_else(|_| Err("Abbruch".into()));
                match result {
                    Ok(msg) => ui.toast(&msg),
                    Err(e) => {
                        let dialog = adw::AlertDialog::new(Some(tr("Das hat nicht geklappt").as_str()), Some(tr(&e).as_str()));
                        dialog.add_response("ok", tr("Schließen").as_str());
                        dialog.present(Some(&ui.window));
                    }
                }
                ui.refresh();
            });
        });
        dialog.present(Some(&self.window));
    }

    /// Scan the images of the running containers with Trivy, one after the other.
    fn scan_images(self: &Rc<Self>) {
        let dv = &self.docker;
        if !docker::trivy_available() {
            let dialog = adw::AlertDialog::new(
                Some(tr("Trivy ist nicht installiert").as_str()),
                Some(tr("Die Prüfung nutzt das freie Werkzeug Trivy. Installieren mit Homebrew:\n\nbrew install trivy\n\nOder über die Paketquelle des Herstellers, siehe trivy.dev (Installation).").as_str()),
            );
            dialog.add_response("ok", tr("Schließen").as_str());
            dialog.present(Some(&self.window));
            return;
        }
        let images = dv.images.borrow().clone();
        if images.is_empty() || dv.scanning.replace(true) {
            return;
        }
        dv.scan_button.set_sensitive(false);
        for w in dv.scan_rows.borrow_mut().drain(..) {
            dv.scans.remove(&w);
        }
        let (tx, rx) = std::sync::mpsc::channel::<Result<docker::ImageScan, (String, String)>>();
        std::thread::spawn(move || {
            for image in images {
                if tx.send(docker::scan_image(&image).map_err(|e| (image.clone(), e))).is_err() {
                    break;
                }
            }
        });
        let ui = self.clone();
        glib::timeout_add_local(Duration::from_millis(400), move || {
            let dv = &ui.docker;
            loop {
                match rx.try_recv() {
                    Ok(result) => {
                        let row = adw::ExpanderRow::new();
                        row.set_use_markup(false);
                        match result {
                            Ok(scan) => {
                                row.set_title(tr(&scan.image).as_str());
                                row.set_subtitle(tr(&format!("{} kritisch · {} hoch", scan.critical, scan.high)).as_str());
                                let (label, css) = match (scan.critical, scan.high) {
                                    (0, 0) => ("Keine", "success"),
                                    (0, _) => ("Hoch", "warning"),
                                    _ => ("Kritisch", "error"),
                                };
                                row.add_suffix(&tag(label, css));
                                if scan.examples.is_empty() {
                                    row.set_enable_expansion(false);
                                } else {
                                    row.add_row(&text_row(&scan.examples.join("\n"), &["monospace", "caption"], true));
                                    row.add_row(&text_row("Empfehlung: ein neueres Image ziehen (docker compose pull && docker compose up -d) oder das Image neu bauen.", &["heading"], false));
                                }
                            }
                            Err((image, e)) => {
                                row.set_title(tr(&image).as_str());
                                row.set_subtitle(tr(&e).as_str());
                                row.set_enable_expansion(false);
                            }
                        }
                        dv.scans.add(&row);
                        dv.scan_rows.borrow_mut().push(row.upcast());
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => return glib::ControlFlow::Continue,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        dv.scanning.set(false);
                        dv.scan_button.set_sensitive(true);
                        return glib::ControlFlow::Break;
                    }
                }
            }
        });
    }

    /// The busiest remote addresses of the running capture.
    fn render_talk(&self) {
        let cv = &self.cap;
        for w in cv.talk_rows.borrow_mut().drain(..) {
            cv.talk_group.remove(&w);
        }
        let talk = cv.talk.borrow();
        let names = cv.names.borrow();
        let mut top: Vec<(&String, &Talk)> = talk.iter().collect();
        top.sort_by(|a, b| b.1.bytes.cmp(&a.1.bytes).then(a.0.cmp(b.0)));
        cv.talk_group.set_visible(!top.is_empty());
        let mut rows: Vec<gtk::Widget> = Vec::new();
        for (ip, t) in top.into_iter().take(8) {
            let name = ip.parse::<IpAddr>().ok().and_then(|a| names.get(&a).cloned());
            let mut info: Vec<String> = Vec::new();
            if name.is_some() {
                info.push(ip.clone());
            }
            info.extend(ip.parse().ok().and_then(geo::lookup).map(|g| g.short()));
            info.push(format!("{} Pakete", t.packets));
            info.push(t.protos.iter().copied().collect::<Vec<_>>().join(", "));
            let row = info_row(name.as_deref().unwrap_or(ip), &info.join(" · "));
            row.add_suffix(&gtk::Label::new(Some(tr(&util::format_bytes(t.bytes)).as_str())));
            let btn = gtk::Button::with_label(tr("Nur diese").as_str());
            btn.add_css_class("flat");
            btn.set_valign(gtk::Align::Center);
            btn.set_tooltip_text(Some(tr("Die Paketliste auf diese Gegenstelle einschränken").as_str()));
            let (search, ip) = (cv.search.clone(), ip.clone());
            btn.connect_clicked(move |_| search.set_text(&ip));
            row.add_suffix(&btn);
            cv.talk_group.add(&row);
            rows.push(row.upcast());
        }
        *cv.talk_rows.borrow_mut() = rows;
    }

    // ----------------------------------------------------------- history

    fn render_history(self: &Rc<Self>) {
        let hv = &self.hist;
        for w in hv.event_rows.borrow_mut().drain(..) {
            hv.events.remove(&w);
        }
        let mut rows: Vec<gtk::Widget> = Vec::new();
        let events = watch::events();
        if events.is_empty() {
            rows.push(
                info_row(
                    "Noch keine Meldungen",
                    if watch::timer_enabled() { "Der Wächter läuft; hier erscheint, was sich ändert." } else { "Der Wächter ist ausgeschaltet (Seite „Übersicht“)." },
                )
                .upcast(),
            );
        }
        for e in events.iter().take(60) {
            let row = info_row(&e.title, &format!("{} · {}", clock_fmt(e.time, "%d.%m. %H:%M"), e.text));
            let (icon, css) = match e.level.as_str() {
                "crit" => ("dialog-error-symbolic", "error"),
                "warn" => ("dialog-warning-symbolic", "warning"),
                "ok" => ("object-select-symbolic", "success"),
                _ => ("dialog-information-symbolic", "accent"),
            };
            let img = gtk::Image::from_icon_name(icon);
            img.add_css_class(css);
            row.add_prefix(&img);
            rows.push(row.upcast());
        }
        for r in &rows {
            hv.events.add(r);
        }
        *hv.event_rows.borrow_mut() = rows;

        let days = history::days();
        hv.updating.set(true);
        hv.day.set_model(Some(&string_list(&days.iter().map(String::as_str).collect::<Vec<_>>())));
        hv.updating.set(false);
        *hv.days.borrow_mut() = days;
        self.render_history_day();
    }

    fn render_history_day(&self) {
        let hv = &self.hist;
        for w in hv.conn_rows.borrow_mut().drain(..) {
            hv.conns.remove(&w);
        }
        let mut rows: Vec<gtk::Widget> = Vec::new();
        let day = hv.days.borrow().get(hv.day.selected() as usize).cloned();
        let entries = day.map(|d| history::load(&d)).unwrap_or_default();
        if entries.is_empty() {
            rows.push(info_row("Noch nichts aufgezeichnet", "Der Wächter zeichnet auf, sobald er eingeschaltet ist.").upcast());
        }
        let names = self.net.names.lock().unwrap().clone();
        for e in entries.iter().take(80) {
            let host = match names.get(&e.remote) {
                Some(Some(n)) => format!("{n} ({})", e.remote),
                _ => e.remote.clone(),
            };
            let program = if e.program.is_empty() { "System" } else { &e.program };
            let mut info = vec![format!("Port {}/{}", e.port, e.proto)];
            info.extend(e.remote.parse().ok().and_then(geo::lookup).map(|g| g.label()));
            info.push(format!("{}–{}", clock_fmt(e.first, "%H:%M"), clock_fmt(e.last, "%H:%M")));
            let row = info_row(&format!("{program} → {host}"), &info.join(" · "));
            if e.sent + e.received > 0 {
                row.add_suffix(&gtk::Label::new(Some(tr(&format!("↑ {}  ↓ {}", util::format_bytes(e.sent), util::format_bytes(e.received))).as_str())));
            }
            let css = ZONES.iter().find(|z| z.0.label() == e.zone).map(|z| z.3).unwrap_or("fw-z-loopback");
            row.add_suffix(&tag(&e.zone, css));
            rows.push(row.upcast());
        }
        for r in &rows {
            hv.conns.add(r);
        }
        *hv.conn_rows.borrow_mut() = rows;
    }

    // -------------------------------------------------------- deep check

    fn show_deep_results(&self, findings: &[Finding], replace: bool) {
        let dv = &self.deep;
        if replace {
            for w in dv.rows.borrow_mut().drain(..) {
                dv.results.remove(&w);
            }
        }
        for f in findings {
            let row = finding_row(f, &self.toasts, None);
            dv.results.add(&row);
            dv.rows.borrow_mut().push(row.upcast());
        }
    }

    fn run_deep(self: &Rc<Self>) {
        let dv = &self.deep;
        if dv.running.replace(true) {
            return;
        }
        dv.button.set_sensitive(false);
        dv.spinner.set_visible(true);
        dv.spinner.start();
        dv.status.set_title(tr("Tiefenprüfung läuft").as_str());
        enum Msg {
            Step(String),
            Done(Vec<Finding>),
        }
        let (tx, rx) = std::sync::mpsc::channel::<Msg>();
        std::thread::spawn(move || {
            let progress_tx = tx.clone();
            let findings = deep::run_all(&move |step| {
                let _ = progress_tx.send(Msg::Step(step.to_string()));
            });
            let _ = tx.send(Msg::Done(findings));
        });
        let ui = self.clone();
        glib::timeout_add_local(Duration::from_millis(300), move || {
            let dv = &ui.deep;
            loop {
                match rx.try_recv() {
                    Ok(Msg::Step(text)) => dv.status.set_subtitle(tr(&text).as_str()),
                    Ok(Msg::Done(findings)) => {
                        let urgent = findings.iter().filter(|f| matches!(f.status, Status::Crit | Status::Warn)).count();
                        dv.status.set_title(tr("Tiefenprüfung abgeschlossen").as_str());
                        dv.status.set_subtitle(tr(&format!("{} · {urgent} mit Handlungsbedarf", clock_fmt(util::now(), "%H:%M"))).as_str());
                        ui.show_deep_results(&findings, true);
                        dv.running.set(false);
                        dv.button.set_sensitive(true);
                        dv.spinner.stop();
                        dv.spinner.set_visible(false);
                        return glib::ControlFlow::Break;
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => return glib::ControlFlow::Continue,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        dv.running.set(false);
                        dv.button.set_sensitive(true);
                        dv.spinner.stop();
                        dv.status.set_title(tr("Tiefenprüfung abgebrochen").as_str());
                        return glib::ControlFlow::Break;
                    }
                }
            }
        });
    }

    /// Show exactly what would be sent to osv.dev before sending it.
    fn confirm_cve(self: &Rc<Self>) {
        let packages = osv::inventory();
        if packages.is_empty() {
            self.deep.cve.set_subtitle(tr("Es sind keine Programme über cargo, pip oder npm installiert – es gibt nichts abzugleichen.").as_str());
            return;
        }
        let list: Vec<String> = packages.iter().map(|p| format!("{} {} ({})", p.name, p.version, p.ecosystem)).collect();
        let dialog = adw::AlertDialog::new(
            Some(tr("Programmliste an osv.dev senden?").as_str()),
            Some(tr(&format!(
                "Für den Abgleich werden Name und Version dieser {} Programme an die Schwachstellen-Datenbank osv.dev (Google) übertragen:\n\n{}",
                list.len(),
                list.join("\n")
            )).as_str()),
        );
        dialog.add_response("cancel", tr("Abbrechen").as_str());
        dialog.add_response("send", tr("Senden und abgleichen").as_str());
        dialog.set_default_response(Some("cancel"));
        dialog.set_close_response("cancel");
        let ui = self.clone();
        dialog.connect_response(None, move |_, response| {
            if response != "send" {
                return;
            }
            let (ui, packages) = (ui.clone(), packages.clone());
            ui.deep.cve_button.set_sensitive(false);
            glib::spawn_future_local(async move {
                let count = packages.len();
                let result = gio::spawn_blocking(move || osv::query(&packages)).await.unwrap_or_else(|_| Err("Abbruch".into()));
                ui.deep.cve_button.set_sensitive(true);
                let finding = Finding::new("deep.cve", Category::Software, "Bekannte Lücken in cargo-, pip- und npm-Programmen");
                let finding = match result {
                    Err(e) => finding.set(Status::Unknown, e),
                    Ok(v) if v.is_empty() => finding.set(Status::Ok, format!("Keine bekannten Lücken in {count} Programmen.")),
                    Ok(v) => finding
                        .set(Status::Warn, format!("{} bekannte Lücken in den installierten Programmen.", v.len()))
                        .details(v.iter().map(|x| format!("{} {} – {} {}", x.package, x.version, x.id, x.summary)))
                        .fix("Betroffene Programme aktualisieren.", &["cargo install <programm>", "pip install --user -U <paket>", "npm update -g <paket>"]),
                };
                ui.deep.cve.set_subtitle(tr(&finding.summary).as_str());
                ui.show_deep_results(&[finding], false);
            });
        });
        dialog.present(Some(&self.window));
    }

    // ----------------------------------------------- devices: name, ports

    fn device_menu(self: &Rc<Self>, d: &devices::Device) -> gtk::MenuButton {
        let button = gtk::MenuButton::new();
        button.set_icon_name("view-more-symbolic");
        button.add_css_class("flat");
        button.set_valign(gtk::Align::Center);
        button.set_tooltip_text(Some(tr("Umbenennen oder Dienste prüfen").as_str()));
        let (weak, mac, ip, title) = (Rc::downgrade(self), d.mac.clone(), d.ip.clone(), d.title());
        button.set_create_popup_func(move |button| {
            let popover = gtk::Popover::new();
            let list = gtk::Box::new(gtk::Orientation::Vertical, 2);
            for (label, action) in [("Umbenennen …", 0u8), ("Dienste prüfen", 1u8)] {
                let item = gtk::Button::with_label(tr(label).as_str());
                item.add_css_class("flat");
                let (weak, mac, ip, title, popover) = (weak.clone(), mac.clone(), ip.clone(), title.clone(), popover.clone());
                item.connect_clicked(move |_| {
                    popover.popdown();
                    let Some(ui) = weak.upgrade() else { return };
                    if action == 0 {
                        ui.rename_device(&mac, &title);
                    } else {
                        ui.check_device_ports(&ip, &title);
                    }
                });
                list.append(&item);
            }
            popover.set_child(Some(&list));
            button.set_popover(Some(&popover));
        });
        button
    }

    fn rename_device(self: &Rc<Self>, mac: &str, current: &str) {
        let entry = gtk::Entry::new();
        entry.set_text(current);
        let dialog = adw::AlertDialog::new(Some(tr("Gerät benennen").as_str()), Some(tr("Der Name gilt nur in dieser App. Leer lassen, um ihn zu entfernen.").as_str()));
        dialog.set_extra_child(Some(&entry));
        dialog.add_response("cancel", tr("Abbrechen").as_str());
        dialog.add_response("save", tr("Speichern").as_str());
        dialog.set_response_appearance("save", adw::ResponseAppearance::Suggested);
        dialog.set_default_response(Some("save"));
        dialog.set_close_response("cancel");
        let (ui, mac) = (self.clone(), mac.to_string());
        dialog.connect_response(None, move |_, response| {
            if response == "save" {
                devices::set_name(&mac, &entry.text());
                ui.load_devices(false);
            }
        });
        dialog.present(Some(&self.window));
    }

    fn check_device_ports(self: &Rc<Self>, ip: &str, title: &str) {
        let Ok(addr) = ip.parse::<IpAddr>() else { return };
        self.toast(&format!("Prüfe Dienste von {title} …"));
        let (ui, title, ip) = (self.clone(), title.to_string(), ip.to_string());
        glib::spawn_future_local(async move {
            let open = gio::spawn_blocking(move || devices::port_check(addr)).await.unwrap_or_default();
            let body = if open.is_empty() {
                "Keiner der geprüften üblichen Dienste antwortet.".to_string()
            } else {
                let mut lines: Vec<String> = open.iter().map(|p| format!("{} Port {} – {}", if p.risky { "⚠" } else { "•" }, p.port, p.service)).collect();
                if open.iter().any(|p| p.risky) {
                    lines.push("\n⚠ = unverschlüsselt oder oft ungeschützt. Prüfe, ob der Dienst gebraucht wird und ein Passwort gesetzt ist.".into());
                }
                lines.join("\n")
            };
            let dialog = adw::AlertDialog::new(Some(tr(&format!("Dienste von {title} ({ip})")).as_str()), Some(tr(&body).as_str()));
            dialog.add_response("ok", tr("Schließen").as_str());
            dialog.present(Some(&ui.window));
        });
    }

    // ----------------------------------------------------------- capture

    /// Jump to the capture page with this connection filled in.
    fn open_capture(self: &Rc<Self>, host: &str, port: &str) {
        self.cap.host.set_text(host);
        self.cap.port.set_text(port);
        self.go_to("capture");
    }

    fn toggle_capture(self: &Rc<Self>) {
        let cv = &self.cap;
        if cv.running.get() {
            // Closing the pipe makes the root helper stop tcpdump.
            cv.stdin.borrow_mut().take();
            cv.status.set_subtitle(tr("Wird beendet …").as_str());
            return;
        }
        let request = capture::Request {
            iface: cv.ifaces.get(cv.iface.selected() as usize).cloned().unwrap_or_else(|| "any".into()),
            host: cv.host.text().trim().to_string(),
            port: cv.port.text().trim().to_string(),
            proto: ["", "tcp", "udp"][(cv.proto.selected() as usize).min(2)].into(),
        };
        if let Err(e) = capture::tcpdump_args(&request) {
            self.toast(&e);
            return;
        }
        let Ok(json) = serde_json::to_string(&request) else { return };
        if std::env::var_os("PICKET_PCAP_REPLAY").is_none() && helper::ready().is_err() {
            return self.with_helper(Rc::new(|ui: &Rc<Ui>| ui.toggle_capture()));
        }

        // Test aid: replay a capture file instead of recording.
        let mut command = match std::env::var_os("PICKET_PCAP_REPLAY") {
            Some(file) => {
                let mut c = std::process::Command::new("/bin/cat");
                c.arg(file);
                c
            }
            None => {
                let Some(pkexec) = util::which("pkexec") else {
                    self.toast("pkexec ist nicht verfügbar");
                    return;
                };
                let mut c = std::process::Command::new(pkexec);
                c.arg(helper::PATH).arg("capture").arg(json);
                c
            }
        };
        use std::process::Stdio;
        let mut child = match command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn() {
            Ok(c) => c,
            Err(e) => {
                self.toast(&format!("Mitschnitt konnte nicht gestartet werden: {e}"));
                return;
            }
        };
        *cv.stdin.borrow_mut() = child.stdin.take();
        let (stdout, stderr) = (child.stdout.take(), child.stderr.take());

        // Which addresses are ours, and which program owns which local port.
        let (local, ports): (HashSet<IpAddr>, BTreeMap<String, String>) = match self.net.last.borrow().as_ref() {
            Some(n) => (n.ifaces.iter().flat_map(|i| i.addrs.iter().map(|a| a.ip)).collect(), n.local_ports.clone()),
            None => (crate::net::read_ifaces().iter().flat_map(|i| i.addrs.iter().map(|a| a.ip)).collect(), BTreeMap::new()),
        };
        // Start with the names already resolved on the network page.
        *cv.names.borrow_mut() = self
            .net
            .names
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(ip, name)| Some((ip.parse().ok()?, name.clone()?)))
            .collect();

        cv.store.remove_all();
        cv.talk.borrow_mut().clear();
        cv.packets.set(0);
        cv.bytes.set(0);
        cv.running.set(true);
        cv.save.set_sensitive(false);
        cv.button.set_label(tr("Stoppen").as_str());
        cv.button.remove_css_class("suggested-action");
        cv.button.add_css_class("destructive-action");
        cv.status.set_title(tr("Mitschnitt startet …").as_str());
        cv.status.set_subtitle(tr("Warte auf die Passwortabfrage des Systems.").as_str());

        // Reader thread: store the raw capture, decode it, hand packets to the window.
        let (tx, rx) = std::sync::mpsc::channel::<CapMsg>();
        let file_path = cv.file.clone();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            use std::os::unix::fs::OpenOptionsExt;
            if let Some(dir) = file_path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            // Recorded traffic is private: readable by the owner only.
            let mut file = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&file_path).ok();
            let mut reader = pcap::Reader::default();
            let mut written: u64 = 0;
            if let Some(mut out) = stdout {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    let n = match out.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    written += n as u64;
                    if let Some(f) = file.as_mut() {
                        let _ = f.write_all(&buf[..n]);
                    }
                    let packets = reader.feed(&buf[..n]);
                    if reader.invalid || written > CAPTURE_FILE_LIMIT || tx.send(CapMsg::Packets(packets, n)).is_err() {
                        break; // dropping the pipe ends tcpdump
                    }
                }
            }
            let mut text = String::new();
            if let Some(mut e) = stderr {
                let _ = e.read_to_string(&mut text);
            }
            let code = child.wait().ok().and_then(|s| s.code());
            let _ = tx.send(CapMsg::Done { code, stderr: text, invalid: reader.invalid });
        });

        // Window side: drain the channel a few times per second.
        let ui = self.clone();
        glib::timeout_add_local(Duration::from_millis(150), move || {
            let cv = &ui.cap;
            let mut rows: Vec<glib::BoxedAnyObject> = Vec::new();
            let mut done = None;
            loop {
                match rx.try_recv() {
                    Ok(CapMsg::Packets(packets, bytes)) => {
                        cv.bytes.set(cv.bytes.get() + bytes as u64);
                        for p in packets {
                            for (ip, name) in &p.names {
                                cv.names.borrow_mut().insert(*ip, name.clone());
                            }
                            if let Some(row) = capture_row(&p, &local, &ports, &cv.names.borrow()) {
                                if !row.remote_ip.is_empty() {
                                    let mut talk = cv.talk.borrow_mut();
                                    let t = talk.entry(row.remote_ip.clone()).or_default();
                                    t.packets += 1;
                                    t.bytes += u64::from(row.length);
                                    t.protos.insert(row.proto);
                                }
                                rows.push(glib::BoxedAnyObject::new(row));
                            }
                        }
                    }
                    Ok(CapMsg::Done { code, stderr, invalid }) => {
                        done = Some((code, stderr, invalid));
                        break;
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        done = Some((None, String::new(), false));
                        break;
                    }
                }
            }
            if !rows.is_empty() {
                cv.packets.set(cv.packets.get() + rows.len() as u64);
                rows.reverse(); // newest first
                cv.store.splice(0, 0, &rows);
                let n = cv.store.n_items();
                if n > CAPTURE_ROWS {
                    cv.store.splice(CAPTURE_ROWS, n - CAPTURE_ROWS, &[] as &[glib::BoxedAnyObject]);
                }
            }
            // The summary changes with every packet; redrawing once a second is enough.
            if done.is_some() || cv.talk_rendered.get() != util::now() {
                cv.talk_rendered.set(util::now());
                ui.render_talk();
            }
            let size = format!("{} Pakete · {} kB", cv.packets.get(), cv.bytes.get() / 1000);
            let Some((code, stderr, invalid)) = done else {
                if cv.bytes.get() > 0 {
                    cv.status.set_title(tr("Mitschnitt läuft").as_str());
                    cv.status.set_subtitle(tr(&size).as_str());
                }
                return glib::ControlFlow::Continue;
            };
            cv.running.set(false);
            cv.stdin.borrow_mut().take();
            cv.button.set_label(tr("Mitschnitt starten").as_str());
            cv.button.remove_css_class("destructive-action");
            cv.button.add_css_class("suggested-action");
            cv.save.set_sensitive(cv.bytes.get() > 24);
            if cv.bytes.get() > 0 && !invalid {
                cv.status.set_title(tr("Mitschnitt beendet").as_str());
                cv.status.set_subtitle(tr(&size).as_str());
            } else if matches!(code, Some(126) | Some(127)) {
                cv.status.set_title(tr("Abgebrochen").as_str());
                cv.status.set_subtitle(tr("Ohne Passwort kann nichts aufgezeichnet werden.").as_str());
            } else {
                cv.status.set_title(tr("Mitschnitt fehlgeschlagen").as_str());
                let last = stderr.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("Es kamen keine Daten an.");
                cv.status.set_subtitle(tr(last).as_str());
            }
            glib::ControlFlow::Break
        });
    }

    fn save_capture(self: &Rc<Self>) {
        let dialog = gtk::FileDialog::builder().title(tr("Mitschnitt speichern").as_str()).initial_name(tr("mitschnitt.pcap").as_str()).build();
        let ui = self.clone();
        dialog.save(Some(&self.window), gio::Cancellable::NONE, move |result| {
            let Some(path) = result.ok().and_then(|f| f.path()) else { return };
            match std::fs::copy(&ui.cap.file, &path) {
                Ok(_) => ui.toast(&format!("Gespeichert: {}", path.display())),
                Err(e) => ui.toast(&format!("Speichern fehlgeschlagen: {e}")),
            }
        });
    }

    // -------------------------------------------------------------- scan

    fn toggle_scan(self: &Rc<Self>) {
        let sv = &self.scan;
        if sv.job.snapshot().running {
            sv.job.cancel();
            return;
        }
        let Some(target) = sv.targets.get(sv.target.selected() as usize) else {
            return;
        };
        if !sv.job.begin(&target.path) {
            return;
        }
        let (job, path) = (sv.job.clone(), target.path.clone());
        std::thread::spawn(move || job.run(&path));
        self.render_scan(&sv.job.snapshot());
        let ui = self.clone();
        glib::timeout_add_local(Duration::from_millis(600), move || {
            let info = ui.scan.job.snapshot();
            ui.render_scan(&info);
            if info.running {
                glib::ControlFlow::Continue
            } else {
                ui.refresh(); // updates the "Letzter Scan" check
                glib::ControlFlow::Break
            }
        });
    }

    fn render_scan(&self, s: &ScanInfo) {
        let sv = &self.scan;
        sv.spinner.set_visible(s.running);
        sv.spinner.set_spinning(s.running);
        sv.target.set_sensitive(!s.running);
        sv.button.set_label(tr(if s.running { "Abbrechen" } else { "Scan starten" }).as_str());
        if s.running {
            sv.button.remove_css_class("suggested-action");
            let found = if s.infected.is_empty() {
                String::new()
            } else {
                format!(" · {} Fund(e)", s.infected.len())
            };
            sv.status.set_title(tr(&format!("Scan läuft – {} Dateien geprüft{found}", s.files)).as_str());
            sv.status.set_subtitle(tr(if s.current.is_empty() { "Signaturen werden geladen …" } else { &s.current }).as_str());
        } else {
            sv.button.add_css_class("suggested-action");
            if let Some(e) = &s.error {
                sv.status.set_title(tr("Scan fehlgeschlagen").as_str());
                sv.status.set_subtitle(tr(e).as_str());
            } else if let Some(finished) = s.finished {
                let secs = finished.saturating_sub(s.started);
                sv.status.set_title(tr(&if s.cancelled {
                    "Scan abgebrochen".to_string()
                } else if s.infected.is_empty() {
                    "Keine Funde".to_string()
                } else {
                    format!("{} Fund(e)", s.infected.len())
                }).as_str());
                let skipped = if s.skipped > 0 { format!(" · {} nicht lesbar", s.skipped) } else { String::new() };
                sv.status.set_subtitle(tr(&format!(
                    "{} · {} Dateien geprüft{skipped} · {}:{:02} min",
                    s.path,
                    s.files,
                    secs / 60,
                    secs % 60
                )).as_str());
            }
        }
        if sv.found_rows.borrow().len() != s.infected.len() {
            for w in sv.found_rows.borrow_mut().drain(..) {
                sv.group.remove(&w);
            }
            let mut rows = Vec::new();
            for i in &s.infected {
                let row = info_row(&i.signature, &i.path);
                row.set_subtitle_selectable(true);
                let img = gtk::Image::from_icon_name("dialog-error-symbolic");
                img.add_css_class("error");
                row.add_prefix(&img);
                sv.group.add(&row);
                rows.push(row.upcast::<gtk::Widget>());
            }
            *sv.found_rows.borrow_mut() = rows;
        }
        let _ = sv.available;
    }
}

/// Open the window. With `background`, start put away: only the icon in the top bar appears.
pub fn run(background: bool) -> std::process::ExitCode {
    // The screenshot test aid runs beside an already open window instead of handing over to it.
    let flags = if std::env::var_os("PICKET_SHOT").is_some() {
        gio::ApplicationFlags::NON_UNIQUE
    } else {
        gio::ApplicationFlags::empty()
    };
    let app = adw::Application::builder().application_id(APP_ID).flags(flags).build();
    app.connect_startup(|_| {
        gtk::Window::set_default_icon_name(APP_ID);
        let provider = gtk::CssProvider::new();
        provider.load_from_string(CSS);
        if let Some(display) = gtk::gdk::Display::default() {
            gtk::style_context_add_provider_for_display(&display, &provider, gtk::STYLE_PROVIDER_PRIORITY_APPLICATION);
        }
    });
    app.connect_activate(move |app| {
        // A second launch just brings the existing window to the front.
        if let Some(w) = app.active_window() {
            w.present();
            return;
        }
        let ui = Ui::build(app);
        if background {
            // Nothing to see without the icon: give the desktop a moment to take it, then give up.
            let unseen = ui.clone();
            glib::timeout_add_seconds_local_once(30, move || {
                if !unseen.window.is_visible() && !unseen.tray.as_ref().is_some_and(|icon| icon.is_shown()) {
                    unseen.quit();
                }
            });
        } else {
            ui.window.present();
        }
        ui.refresh();
        ui.load_net();
        if let Some(prefix) = std::env::var("PICKET_SHOT").ok().filter(|p| !p.is_empty()) {
            ui.screenshot_tour(prefix);
        }
    });
    // Our own CLI arguments are already handled; GTK gets none.
    app.run_with_args::<&str>(&[]).into()
}
