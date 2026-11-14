//! Live network diagram: programs on the left, the machines they talk to on
//! the right, one line per program/host pair. Lines with measured traffic move
//! in the direction the data flows.

use crate::net::{NetSnapshot, Zone};
use gtk::prelude::*;
use gtk::{cairo, glib, pango};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap};
use std::f64::consts::PI;
use std::rc::Rc;
use std::time::Instant;

const ROW_H: f64 = 44.0;
const GAP: f64 = 8.0;
const HEADER_H: f64 = 28.0;
const TOP: f64 = 30.0;
const MAX_PROGRAMS: usize = 14;

const ZONE_ORDER: [Zone; 5] = [Zone::Internet, Zone::Lan, Zone::Vpn, Zone::Container, Zone::Loopback];

fn zone_title(z: Zone) -> &'static str {
    match z {
        Zone::Internet => "Internet",
        Zone::Lan => "Lokales Netz",
        Zone::Vpn => "VPN",
        Zone::Container => "Container / VM",
        Zone::Loopback => "Nur dieser Rechner",
    }
}

fn zone_rgb(z: Zone, dark: bool) -> (f64, f64, f64) {
    let hex: u32 = match (z, dark) {
        (Zone::Internet, false) => 0x9141ac,
        (Zone::Internet, true) => 0xdc8add,
        (Zone::Lan, false) => 0x1c8f96,
        (Zone::Lan, true) => 0x5fd3d9,
        (Zone::Vpn, false) => 0x1c71d8,
        (Zone::Vpn, true) => 0x99c1f1,
        (Zone::Container, false) => 0x986a44,
        (Zone::Container, true) => 0xe6c07b,
        (Zone::Loopback, false) => 0x77767b,
        (Zone::Loopback, true) => 0xc0bfbc,
    };
    (
        f64::from((hex >> 16) & 0xff) / 255.0,
        f64::from((hex >> 8) & 0xff) / 255.0,
        f64::from(hex & 0xff) / 255.0,
    )
}

pub fn format_rate(bytes_per_s: f64) -> String {
    if bytes_per_s >= 1_000_000.0 {
        format!("{:.1} MB/s", bytes_per_s / 1_000_000.0).replace('.', ",")
    } else if bytes_per_s >= 1000.0 {
        format!("{:.0} kB/s", bytes_per_s / 1000.0)
    } else {
        format!("{bytes_per_s:.0} B/s")
    }
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Node {
    pub label: String,
    pub sub: String,
    /// Zone of a remote host; None for programs.
    pub zone: Option<Zone>,
    /// First host of its zone: a zone heading is drawn above it.
    pub first_in_zone: bool,
    /// What a click on the node refers to: the remote address of a host, or
    /// the program name. None for merged "+ n weitere" nodes.
    pub target: Option<String>,
    /// Port of the connection to a host (for the actions offered on click).
    pub port: u16,
    /// Nothing is open any more; kept for a while so it does not just vanish.
    pub ended: bool,
}

/// A connection that was seen earlier and has closed since.
pub struct Ended<'a> {
    pub program: &'a str,
    pub remote: &'a str,
    pub zone: Zone,
    pub port: u16,
    pub service: Option<&'static str>,
    /// Seconds since it was last seen open.
    pub age: u64,
}

/// What the user clicked in the diagram.
pub enum Click {
    Program(String),
    /// A remote host, with the click position inside the drawing area.
    Host { remote: String, port: u16, x: f64, y: f64 },
}

#[derive(Clone, Debug, PartialEq)]
pub struct Link {
    pub program: usize,
    pub host: usize,
    pub zone: Zone,
    pub connections: usize,
    /// Bytes per second since the previous snapshot (TCP only).
    pub up: f64,
    pub down: f64,
    pub is_new: bool,
    /// The connection has closed.
    pub ended: bool,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Layout {
    pub programs: Vec<Node>,
    pub hosts: Vec<Node>,
    pub links: Vec<Link>,
}

/// Cumulative counters of one program/host pair.
#[derive(Clone, Copy, Default)]
struct Pair {
    zone: Option<Zone>,
    connections: usize,
    sent: u64,
    received: u64,
    port: u16,
    service: Option<&'static str>,
    /// Seconds since the pair was last open, when it is closed now.
    ended: Option<u64>,
}

type PairKey = (String, String);

/// Turn a snapshot into the diagram. `previous` holds the byte counters of the
/// last snapshot and `dt` the seconds since then, which gives the rates.
pub fn build(
    snap: &NetSnapshot,
    filter: Option<Zone>,
    names: &HashMap<String, Option<String>>,
    origin: &HashMap<String, String>,
    ended: &[Ended],
    previous: &HashMap<PairKey, (u64, u64)>,
    dt: f64,
) -> (Layout, HashMap<PairKey, (u64, u64)>) {
    let shown = |z: Zone| match filter {
        Some(f) => z == f,
        None => z != Zone::Loopback,
    };

    // Aggregate per (program, remote address).
    let mut pairs: BTreeMap<PairKey, Pair> = BTreeMap::new();
    for p in &snap.programs {
        for e in &p.endpoints {
            let pair = pairs.entry((p.name.clone(), e.remote.clone())).or_default();
            pair.zone = Some(e.zone);
            pair.connections += e.count;
            pair.sent += e.bytes_sent;
            pair.received += e.bytes_received;
            if pair.port == 0 {
                pair.port = e.port;
                pair.service = e.service;
            }
        }
    }
    // Counters cover every pair, so changing the filter does not reset the rates.
    let counters: HashMap<PairKey, (u64, u64)> =
        pairs.iter().map(|(k, p)| (k.clone(), (p.sent, p.received))).collect();
    pairs.retain(|_, p| p.zone.map(shown).unwrap_or(false));
    // Closed connections join the picture, unless the same pair is open again.
    for e in ended.iter().filter(|e| shown(e.zone)) {
        let pair = pairs.entry((e.program.to_string(), e.remote.to_string())).or_insert(Pair {
            zone: Some(e.zone),
            port: e.port,
            service: e.service,
            ended: Some(e.age),
            ..Default::default()
        });
        if let Some(age) = pair.ended.as_mut() {
            *age = (*age).min(e.age);
        }
    }
    let rate = |key: &PairKey, pair: &Pair| -> (f64, f64) {
        match previous.get(key) {
            // A closed connection lowers the sum; that is not traffic.
            Some((s, r)) if dt > 0.5 => (
                pair.sent.saturating_sub(*s) as f64 / dt,
                pair.received.saturating_sub(*r) as f64 / dt,
            ),
            _ => (0.0, 0.0),
        }
    };

    // Programs, busiest first; the tail is merged into one node.
    let mut prog_conns: BTreeMap<&str, usize> = BTreeMap::new();
    for ((prog, _), pair) in &pairs {
        *prog_conns.entry(prog.as_str()).or_insert(0) += pair.connections;
    }
    let mut prog_order: Vec<(&str, usize)> = prog_conns.into_iter().collect();
    prog_order.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    let merged_programs = prog_order.len() > MAX_PROGRAMS;
    let visible = if merged_programs { MAX_PROGRAMS - 1 } else { prog_order.len() };
    let prog_index: HashMap<&str, usize> = prog_order
        .iter()
        .enumerate()
        .map(|(i, (name, _))| (*name, i.min(visible)))
        .collect();

    // Hosts per zone, busiest first, capped so the picture stays readable.
    // per host: (open connections, rate, seconds since the last one closed)
    let mut host_conns: BTreeMap<(Zone, &str), (usize, f64, u64)> = BTreeMap::new();
    for (key, pair) in &pairs {
        let Some(zone) = pair.zone else { continue };
        let (up, down) = rate(key, pair);
        let h = host_conns.entry((zone, key.1.as_str())).or_insert((0, 0.0, u64::MAX));
        h.0 += pair.connections;
        h.1 += up + down;
        h.2 = h.2.min(pair.ended.unwrap_or(u64::MAX));
    }
    let mut hosts: Vec<Node> = Vec::new();
    let mut host_index: HashMap<(Zone, &str), usize> = HashMap::new();
    for zone in ZONE_ORDER {
        let mut list: Vec<(&str, usize, f64, u64)> = host_conns
            .iter()
            .filter(|((z, _), _)| *z == zone)
            .map(|((_, ip), (c, r, age))| (*ip, *c, *r, *age))
            .collect();
        if list.is_empty() {
            continue;
        }
        // Busiest first; closed ones last, the most recently closed leading them.
        list.sort_by(|a, b| b.2.total_cmp(&a.2).then(b.1.cmp(&a.1)).then(a.3.cmp(&b.3)).then(a.0.cmp(b.0)));
        let cap = match (filter, zone) {
            (Some(_), _) => 22,
            (None, Zone::Internet) => 10,
            (None, Zone::Lan) => 6,
            _ => 4,
        };
        let merged = list.len() > cap;
        let individual = if merged { cap - 1 } else { list.len() };
        for (i, (ip, conns, _, age)) in list.iter().enumerate() {
            if i < individual {
                let pair = pairs.iter().find(|(k, _)| k.1 == *ip).map(|(_, p)| *p).unwrap_or_default();
                let service = pair.service.map(String::from).unwrap_or_else(|| format!("Port {}", pair.port));
                let (label, mut sub) = match names.get(*ip) {
                    Some(Some(host)) => (host.clone(), format!("{ip} · {service}")),
                    _ => (ip.to_string(), format!("{service} · {conns}×")),
                };
                // Operator and country say more than the connection count.
                if let Some(o) = origin.get(*ip) {
                    sub = format!("{o} · {service}");
                }
                let closed = *conns == 0;
                if closed {
                    let when = crate::session::ago(*age);
                    sub = match origin.get(*ip) {
                        Some(o) => format!("beendet {when} · {o}"),
                        None => format!("beendet {when} · {service}"),
                    };
                }
                host_index.insert((zone, ip), hosts.len());
                hosts.push(Node { label, sub, zone: Some(zone), first_in_zone: i == 0, target: Some(ip.to_string()), port: pair.port, ended: closed });
            } else {
                if i == individual {
                    hosts.push(Node {
                        label: format!("+ {} weitere", list.len() - individual),
                        sub: "weniger aktive Gegenstellen".into(),
                        zone: Some(zone),
                        first_in_zone: i == 0,
                        target: None,
                        port: 0,
                        ended: false,
                    });
                }
                host_index.insert((zone, ip), hosts.len() - 1);
            }
        }
    }

    // Links, merged where several pairs collapse into the same two nodes.
    let mut merged_links: BTreeMap<(usize, usize), Link> = BTreeMap::new();
    for (key, pair) in &pairs {
        let Some(zone) = pair.zone else { continue };
        let (Some(&program), Some(&host)) = (prog_index.get(key.0.as_str()), host_index.get(&(zone, key.1.as_str()))) else {
            continue;
        };
        let (up, down) = rate(key, pair);
        let is_new = pair.ended.is_none() && !previous.is_empty() && !previous.contains_key(key);
        let link = merged_links.entry((program, host)).or_insert(Link {
            program,
            host,
            zone,
            connections: 0,
            up: 0.0,
            down: 0.0,
            is_new: false,
            ended: true,
        });
        link.ended &= pair.ended.is_some();
        link.connections += pair.connections;
        link.up += up;
        link.down += down;
        link.is_new |= is_new;
    }
    let links: Vec<Link> = merged_links.into_values().collect();

    let mut programs: Vec<Node> = Vec::new();
    for (i, (name, conns)) in prog_order.iter().enumerate() {
        if i < visible {
            let (up, down) = links
                .iter()
                .filter(|l| l.program == i)
                .fold((0.0, 0.0), |acc, l| (acc.0 + l.up, acc.1 + l.down));
            let mut sub = match *conns {
                0 => "keine offene Verbindung mehr".to_string(),
                1 => "1 Verbindung".to_string(),
                n => format!("{n} Verbindungen"),
            };
            if up + down >= 1.0 {
                sub = format!("↓ {} · ↑ {}", format_rate(down), format_rate(up));
            }
            programs.push(Node {
                label: if name.is_empty() { "System / anderer Benutzer".into() } else { name.to_string() },
                sub,
                zone: None,
                first_in_zone: false,
                target: Some(name.to_string()),
                port: 0,
                ended: *conns == 0,
            });
        } else if i == visible {
            programs.push(Node {
                label: format!("+ {} weitere Programme", prog_order.len() - visible),
                sub: String::new(),
                zone: None,
                first_in_zone: false,
                target: None,
                port: 0,
                ended: false,
            });
        }
    }

    (Layout { programs, hosts, links }, counters)
}

struct Model {
    layout: Layout,
    /// Counters of the previous and the current snapshot, with their arrival times.
    previous: HashMap<PairKey, (u64, u64)>,
    current: HashMap<PairKey, (u64, u64)>,
    previous_at: Option<Instant>,
    current_at: Option<Instant>,
    current_id: u64,
    pointer: Option<(f64, f64)>,
    started: Instant,
    last_frame: i64,
}

type ClickFn = Rc<RefCell<Option<Box<dyn Fn(Click)>>>>;

#[derive(Clone)]
pub struct Graph {
    pub area: gtk::DrawingArea,
    model: Rc<RefCell<Model>>,
    on_click: ClickFn,
}

fn rounded_rect(cr: &cairo::Context, x: f64, y: f64, w: f64, h: f64, r: f64) {
    cr.new_sub_path();
    cr.arc(x + w - r, y + r, r, -PI / 2.0, 0.0);
    cr.arc(x + w - r, y + h - r, r, 0.0, PI / 2.0);
    cr.arc(x + r, y + h - r, r, PI / 2.0, PI);
    cr.arc(x + r, y + r, r, PI, 1.5 * PI);
    cr.close_path();
}

fn text(area: &gtk::DrawingArea, cr: &cairo::Context, markup: &str, x: f64, y: f64, width: f64) {
    let layout = area.create_pango_layout(None);
    layout.set_markup(markup);
    layout.set_width((width.max(1.0) * f64::from(pango::SCALE)) as i32);
    layout.set_ellipsize(pango::EllipsizeMode::End);
    cr.move_to(x, y);
    pangocairo::functions::show_layout(cr, &layout);
}

/// Vertical positions of the nodes in one column.
fn column(nodes: &[Node]) -> (Vec<f64>, f64) {
    let mut ys = Vec::with_capacity(nodes.len());
    let mut y = 0.0;
    for n in nodes {
        if n.first_in_zone {
            y += HEADER_H;
        }
        ys.push(y);
        y += ROW_H + GAP;
    }
    (ys, (y - GAP).max(0.0))
}

/// Where the two columns sit for a given width.
struct Geometry {
    prog_x: f64,
    prog_w: f64,
    prog_y: Vec<f64>,
    host_x: f64,
    host_w: f64,
    host_y: Vec<f64>,
}

fn geometry(layout: &Layout, width: f64) -> Geometry {
    let prog_w = (width * 0.30).clamp(100.0, 280.0);
    let host_w = (width * 0.38).clamp(120.0, 360.0);
    // Both columns start at the top; the zone heading shifts the first host down a little.
    Geometry {
        prog_x: 4.0,
        prog_w,
        prog_y: column(&layout.programs).0.iter().map(|y| TOP + HEADER_H + y).collect(),
        host_x: width - host_w - 4.0,
        host_w,
        host_y: column(&layout.hosts).0.iter().map(|y| TOP + y).collect(),
    }
}

impl Geometry {
    fn program_at(&self, p: (f64, f64)) -> Option<usize> {
        self.prog_y.iter().position(|y| p.0 >= self.prog_x && p.0 <= self.prog_x + self.prog_w && p.1 >= *y && p.1 <= y + ROW_H)
    }
    fn host_at(&self, p: (f64, f64)) -> Option<usize> {
        self.host_y.iter().position(|y| p.0 >= self.host_x && p.0 <= self.host_x + self.host_w && p.1 >= *y && p.1 <= y + ROW_H)
    }
}

fn content_height(layout: &Layout) -> i32 {
    let left = column(&layout.programs).1;
    let right = column(&layout.hosts).1;
    (TOP + (left + HEADER_H).max(right).max(120.0) + 16.0) as i32
}

fn draw(area: &gtk::DrawingArea, cr: &cairo::Context, width: f64, model: &Model) {
    let fg = area.color();
    let (fr, fg_g, fb) = (f64::from(fg.red()), f64::from(fg.green()), f64::from(fg.blue()));
    let dark = fr + fg_g + fb > 1.5; // light text means a dark background
    let layout = &model.layout;
    let esc = |s: &str| glib::markup_escape_text(s).to_string();

    if layout.links.is_empty() {
        cr.set_source_rgba(fr, fg_g, fb, 0.6);
        text(area, cr, "Keine aktiven Verbindungen in dieser Auswahl", 16.0, 60.0, width - 32.0);
        return;
    }

    let Geometry { prog_x, prog_w, prog_y, host_x, host_w, host_y } = geometry(layout, width);
    let geo = geometry(layout, width);
    let hover_prog = model.pointer.and_then(|p| geo.program_at(p));
    let hover_host = model.pointer.and_then(|p| geo.host_at(p));
    let hovering = hover_prog.is_some() || hover_host.is_some();
    let lit = |l: &Link| hover_prog == Some(l.program) || hover_host == Some(l.host);

    cr.set_source_rgba(fr, fg_g, fb, 0.6);
    text(area, cr, "<span size='small' weight='bold'>Programme auf diesem Laptop</span>", prog_x, 4.0, prog_w);
    text(area, cr, "<span size='small' weight='bold'>Gegenstellen</span>", host_x, 4.0, host_w);

    // Links
    let t = model.started.elapsed().as_secs_f64();
    let animate = gtk::Settings::default().map(|s| s.is_gtk_enable_animations()).unwrap_or(true);
    for l in &layout.links {
        let (x1, y1) = (prog_x + prog_w, prog_y[l.program] + ROW_H / 2.0);
        let (x2, y2) = (host_x, host_y[l.host] + ROW_H / 2.0);
        let mid = (x1 + x2) / 2.0;
        let (r, g, b) = zone_rgb(l.zone, dark);
        let width = 1.5 + ((1 + l.connections) as f64).ln().min(3.5) * 1.4;
        let dim = hovering && !lit(l);
        let path = |cr: &cairo::Context| {
            cr.move_to(x1, y1);
            cr.curve_to(mid, y1, mid, y2, x2, y2);
        };
        let rate = l.up + l.down;
        cr.set_dash(&[], 0.0);
        if l.ended {
            // Closed: a thin dotted trace of where the connection went.
            cr.set_dash(&[2.0, 5.0], 0.0);
            cr.set_source_rgba(r, g, b, if dim { 0.10 } else if hovering && lit(l) { 0.7 } else { 0.38 });
            cr.set_line_width(1.4);
            path(cr);
            let _ = cr.stroke();
            cr.set_dash(&[], 0.0);
            continue;
        }
        if l.is_new && !dim {
            // New since the last update: a soft halo.
            let pulse = if animate { 0.25 + 0.2 * (t * 4.0).sin().abs() } else { 0.35 };
            cr.set_source_rgba(r, g, b, pulse);
            cr.set_line_width(width + 6.0);
            path(cr);
            let _ = cr.stroke();
        }
        let base = if dim { 0.10 } else if rate > 0.0 { 0.45 } else { 0.30 };
        cr.set_source_rgba(r, g, b, if hovering && lit(l) { 0.75 } else { base });
        cr.set_line_width(width);
        path(cr);
        let _ = cr.stroke();
        if rate > 0.0 && !dim {
            // Moving dashes: towards the host when sending dominates, towards the program otherwise.
            let speed = 26.0 + 16.0 * (1.0 + rate / 1000.0).log10();
            let period = 22.0;
            let phase = if animate { (t * speed) % period } else { 0.0 };
            let offset = if l.up >= l.down { period - phase } else { phase };
            cr.set_dash(&[8.0, period - 8.0], offset);
            cr.set_source_rgba(r, g, b, 0.95);
            cr.set_line_width(width.max(2.5));
            cr.set_line_cap(cairo::LineCap::Round);
            path(cr);
            let _ = cr.stroke();
            cr.set_line_cap(cairo::LineCap::Butt);
            cr.set_dash(&[], 0.0);
        }
    }

    // Nodes
    let node = |x: f64, y: f64, w: f64, n: &Node, highlighted: bool, dimmed: bool| {
        // Closed connections stay readable but step back.
        let alpha = if dimmed { 0.45 } else if n.ended && !highlighted { 0.55 } else { 1.0 };
        rounded_rect(cr, x, y, w, ROW_H, 9.0);
        cr.set_source_rgba(fr, fg_g, fb, if highlighted { 0.14 } else if n.ended { 0.035 } else { 0.07 });
        let _ = cr.fill();
        let mut text_x = x + 12.0;
        if let Some(z) = n.zone {
            let (r, g, b) = zone_rgb(z, dark);
            rounded_rect(cr, x + 5.0, y + 8.0, 4.0, ROW_H - 16.0, 2.0);
            cr.set_source_rgba(r, g, b, alpha);
            let _ = cr.fill();
            text_x += 6.0;
        }
        let text_w = w - (text_x - x) - 10.0;
        cr.set_source_rgba(fr, fg_g, fb, alpha);
        if n.sub.is_empty() {
            text(area, cr, &format!("<b>{}</b>", esc(&n.label)), text_x, y + 12.0, text_w);
        } else {
            text(area, cr, &format!("<b>{}</b>", esc(&n.label)), text_x, y + 4.0, text_w);
            cr.set_source_rgba(fr, fg_g, fb, 0.62 * alpha);
            text(area, cr, &format!("<span size='small'>{}</span>", esc(&n.sub)), text_x, y + 23.0, text_w);
        }
    };
    for (i, n) in layout.programs.iter().enumerate() {
        let connected = layout.links.iter().any(|l| l.program == i && lit(l));
        node(prog_x, prog_y[i], prog_w, n, hover_prog == Some(i) || connected, hovering && hover_prog != Some(i) && !connected);
    }
    for (i, n) in layout.hosts.iter().enumerate() {
        if n.first_in_zone {
            if let Some(z) = n.zone {
                let (r, g, b) = zone_rgb(z, dark);
                cr.set_source_rgba(r, g, b, 1.0);
                text(
                    area,
                    cr,
                    &format!("<span size='small' weight='bold'>{}</span>", esc(zone_title(z))),
                    host_x + 2.0,
                    host_y[i] - HEADER_H + 8.0,
                    host_w,
                );
            }
        }
        let connected = layout.links.iter().any(|l| l.host == i && lit(l));
        node(host_x, host_y[i], host_w, n, hover_host == Some(i) || connected, hovering && hover_host != Some(i) && !connected);
    }
}

impl Graph {
    pub fn new() -> Graph {
        let area = gtk::DrawingArea::new();
        area.set_content_height(160);
        area.set_hexpand(true);
        let model = Rc::new(RefCell::new(Model {
            layout: Layout::default(),
            previous: HashMap::new(),
            current: HashMap::new(),
            previous_at: None,
            current_at: None,
            current_id: 0,
            pointer: None,
            started: Instant::now(),
            last_frame: 0,
        }));

        {
            let model = model.clone();
            area.set_draw_func(move |area, cr, width, _height| {
                draw(area, cr, f64::from(width), &model.borrow());
            });
        }
        {
            let motion = gtk::EventControllerMotion::new();
            let (m1, a1) = (model.clone(), area.clone());
            motion.connect_motion(move |_, x, y| {
                let mut m = m1.borrow_mut();
                m.pointer = Some((x, y));
                // A hand cursor over everything that reacts to a click.
                let geo = geometry(&m.layout, f64::from(a1.width()));
                let clickable = geo.program_at((x, y)).map(|i| m.layout.programs[i].target.is_some()).unwrap_or(false)
                    || geo.host_at((x, y)).map(|i| m.layout.hosts[i].target.is_some()).unwrap_or(false);
                drop(m);
                a1.set_cursor_from_name(clickable.then_some("pointer"));
                a1.queue_draw();
            });
            let (m2, a2) = (model.clone(), area.clone());
            motion.connect_leave(move |_| {
                m2.borrow_mut().pointer = None;
                a2.queue_draw();
            });
            area.add_controller(motion);
        }
        {
            // Animate at about 30 fps, and only while something is moving.
            // Tick callbacks stop by themselves while the page is hidden.
            let model = model.clone();
            area.add_tick_callback(move |area, clock| {
                let mut m = model.borrow_mut();
                let now = clock.frame_time();
                let moving = m.layout.links.iter().any(|l| l.up + l.down > 0.0 || l.is_new);
                let animate = gtk::Settings::default().map(|s| s.is_gtk_enable_animations()).unwrap_or(true);
                if moving && animate && now - m.last_frame > 33_000 {
                    m.last_frame = now;
                    area.queue_draw();
                }
                glib::ControlFlow::Continue
            });
        }
        let on_click: ClickFn = Rc::new(RefCell::new(None));
        {
            let click = gtk::GestureClick::new();
            let (model, area2, on_click) = (model.clone(), area.clone(), on_click.clone());
            click.connect_released(move |_, _, x, y| {
                let hit = {
                    let m = model.borrow();
                    let geo = geometry(&m.layout, f64::from(area2.width()));
                    if let Some(node) = geo.program_at((x, y)).map(|i| &m.layout.programs[i]) {
                        node.target.clone().map(Click::Program)
                    } else if let Some(node) = geo.host_at((x, y)).map(|i| &m.layout.hosts[i]) {
                        node.target.clone().map(|remote| Click::Host { remote, port: node.port, x, y })
                    } else {
                        None
                    }
                };
                // The model borrow is released before the handler runs: it may redraw.
                if let (Some(hit), Some(f)) = (hit, on_click.borrow().as_ref()) {
                    f(hit);
                }
            });
            area.add_controller(click);
        }
        Graph { area, model, on_click }
    }

    /// Call `f` when a program or host is clicked.
    pub fn connect_click(&self, f: impl Fn(Click) + 'static) {
        *self.on_click.borrow_mut() = Some(Box::new(f));
    }

    pub fn update(
        &self,
        snap: &NetSnapshot,
        filter: Option<Zone>,
        names: &HashMap<String, Option<String>>,
        origin: &HashMap<String, String>,
        ended: &[Ended],
    ) {
        let mut m = self.model.borrow_mut();
        if snap.generated != m.current_id {
            // A new snapshot: the current counters become the baseline.
            m.previous = std::mem::take(&mut m.current);
            m.previous_at = m.current_at;
            m.current_at = Some(Instant::now());
            m.current_id = snap.generated;
        }
        let dt = match (m.previous_at, m.current_at) {
            (Some(a), Some(b)) => b.duration_since(a).as_secs_f64(),
            _ => 0.0,
        };
        let (layout, counters) = build(snap, filter, names, origin, ended, &m.previous, dt);
        self.area.set_content_height(content_height(&layout));
        m.layout = layout;
        m.current = counters;
        drop(m);
        self.area.queue_draw();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{Endpoint, Program};

    fn endpoint(remote: &str, zone: Zone, count: usize, sent: u64, received: u64) -> Endpoint {
        Endpoint {
            remote: remote.into(),
            port: 443,
            proto: "tcp".into(),
            zone,
            inbound: false,
            service: Some("HTTPS"),
            count,
            bytes_sent: sent,
            bytes_received: received,
        }
    }

    fn snapshot(programs: Vec<Program>) -> NetSnapshot {
        NetSnapshot {
            generated: 0,
            ifaces: vec![],
            listeners: vec![],
            programs,
            totals: BTreeMap::new(),
            docker: vec![],
            local_ports: BTreeMap::new(),
            docker_available: false,
            has_global_ipv6: false,
            complete: true,
        }
    }

    fn program(name: &str, endpoints: Vec<Endpoint>) -> Program {
        Program { name: name.into(), pids: vec![], zones: BTreeMap::new(), endpoints }
    }

    #[test]
    fn builds_nodes_links_and_rates() {
        let names = HashMap::from([("1.1.1.1".to_string(), Some("one.one.one.one".to_string()))]);
        let first = snapshot(vec![
            program("browser", vec![endpoint("1.1.1.1", Zone::Internet, 2, 1000, 5000), endpoint("192.168.1.1", Zone::Lan, 1, 0, 0)]),
            program("code", vec![endpoint("127.0.0.1", Zone::Loopback, 5, 10, 10)]),
        ]);
        let (layout, counters) = build(&first, None, &names, &HashMap::new(), &[], &HashMap::new(), 0.0);
        assert_eq!(layout.programs.len(), 1); // loopback-only program hidden
        assert_eq!(layout.hosts.len(), 2);
        assert_eq!(layout.hosts[0].label, "one.one.one.one");
        assert!(layout.hosts[0].first_in_zone && layout.hosts[1].first_in_zone);
        assert_eq!(layout.links.len(), 2);
        assert!(layout.links.iter().all(|l| l.up == 0.0 && !l.is_new));

        // Five seconds later: 10 kB more received, plus a new host.
        let second = snapshot(vec![program(
            "browser",
            vec![endpoint("1.1.1.1", Zone::Internet, 2, 2000, 15000), endpoint("9.9.9.9", Zone::Internet, 1, 0, 0)],
        )]);
        let (layout, _) = build(&second, None, &names, &HashMap::from([("9.9.9.9".to_string(), "Quad9 · Schweiz".to_string())]), &[], &counters, 5.0);
        let moving = layout.links.iter().find(|l| l.down > 0.0).unwrap();
        assert_eq!((moving.up, moving.down), (200.0, 2000.0));
        assert_eq!(layout.hosts[moving.host].label, "one.one.one.one"); // busiest first
        assert!(layout.links.iter().any(|l| l.is_new));
        assert!(layout.hosts.iter().any(|h| h.sub == "Quad9 · Schweiz · HTTPS"));
        assert_eq!(layout.programs[0].sub, "↓ 2 kB/s · ↑ 200 B/s");

        // A closed connection must not look like negative or huge traffic.
        let third = snapshot(vec![program("browser", vec![endpoint("1.1.1.1", Zone::Internet, 1, 500, 500)])]);
        let (layout, _) = build(&third, None, &names, &HashMap::new(), &[], &counters, 5.0);
        assert_eq!((layout.links[0].up, layout.links[0].down), (0.0, 0.0));
    }

    #[test]
    fn keeps_closed_connections_in_the_picture() {
        let now = snapshot(vec![program("browser", vec![endpoint("1.1.1.1", Zone::Internet, 2, 0, 0)])]);
        let ended = [
            Ended { program: "browser", remote: "9.9.9.9", zone: Zone::Internet, port: 443, service: Some("HTTPS"), age: 130 },
            Ended { program: "mail", remote: "8.8.4.4", zone: Zone::Internet, port: 993, service: None, age: 20 },
            Ended { program: "browser", remote: "1.1.1.1", zone: Zone::Internet, port: 443, service: None, age: 5 }, // open again
            Ended { program: "code", remote: "127.0.0.1", zone: Zone::Loopback, port: 1, service: None, age: 5 }, // filtered out
        ];
        let (layout, counters) = build(&now, None, &HashMap::new(), &HashMap::new(), &ended, &HashMap::new(), 0.0);
        assert_eq!(layout.hosts.iter().map(|h| (h.label.as_str(), h.ended)).collect::<Vec<_>>(), [("1.1.1.1", false), ("8.8.4.4", true), ("9.9.9.9", true)]);
        assert_eq!(layout.hosts[2].sub, "beendet vor 2 min · HTTPS");
        assert_eq!(layout.programs.iter().map(|p| (p.label.as_str(), p.ended)).collect::<Vec<_>>(), [("browser", false), ("mail", true)]);
        assert_eq!(layout.links.iter().filter(|l| l.ended).count(), 2);
        assert!(layout.links.iter().all(|l| !l.is_new));
        assert_eq!(counters.len(), 1); // closed pairs do not count as traffic baselines
    }

    #[test]
    fn merges_long_host_lists() {
        let endpoints: Vec<Endpoint> = (1..=30).map(|i| endpoint(&format!("8.8.8.{i}"), Zone::Internet, 1, 0, 0)).collect();
        let (layout, _) = build(&snapshot(vec![program("p", endpoints)]), None, &HashMap::new(), &HashMap::new(), &[], &HashMap::new(), 0.0);
        assert_eq!(layout.hosts.len(), 10);
        assert_eq!(layout.hosts[9].label, "+ 21 weitere");
        assert_eq!(layout.links.len(), 10);
        assert_eq!(layout.links.iter().map(|l| l.connections).sum::<usize>(), 30);
    }

    #[test]
    fn formats_rates() {
        assert_eq!(format_rate(850.0), "850 B/s");
        assert_eq!(format_rate(12_400.0), "12 kB/s");
        assert_eq!(format_rate(3_400_000.0), "3,4 MB/s");
    }
}
