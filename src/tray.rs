//! The icon in the desktop's top bar.
//!
//! Speaks the StatusNotifierItem protocol and its menu protocol (com.canonical.dbusmenu)
//! over the application's own D-Bus connection, so no further library is needed. On GNOME
//! the icon is drawn by the AppIndicator extension, which Ubuntu ships switched on; where
//! nothing shows such icons, nothing happens.

use crate::i18n::tr;
use crate::util;
use gtk::gio::{self, prelude::*};
use gtk::glib::{self, Variant};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::path::PathBuf;
use std::rc::Rc;

const WATCHER: &str = "org.kde.StatusNotifierWatcher";
const ITEM_PATH: &str = "/StatusNotifierItem";
const ITEM: &str = "org.kde.StatusNotifierItem";
const MENU_PATH: &str = "/StatusNotifierItem/Menu";
const MENU: &str = "com.canonical.dbusmenu";

const ICON: &str = "picket-tray";
const ICON_ATTENTION: &str = "picket-tray-attention";

/// The logo, and what is drawn over it when something is critical: a red mark in the corner.
const LOGO: &str = include_str!("../assets/icon.svg");
const BADGE: &str = r##"<circle cx="92" cy="36" r="29" fill="#e01b24" stroke="#ffffff" stroke-width="7"/>
  <path d="M87 17h10v24H87z M87 46h10v10H87z" fill="#ffffff"/>
"##;

const ITEM_XML: &str = r#"<node><interface name="org.kde.StatusNotifierItem">
  <property name="Category" type="s" access="read"/>
  <property name="Id" type="s" access="read"/>
  <property name="Title" type="s" access="read"/>
  <property name="Status" type="s" access="read"/>
  <property name="WindowId" type="i" access="read"/>
  <property name="IconThemePath" type="s" access="read"/>
  <property name="IconName" type="s" access="read"/>
  <property name="AttentionIconName" type="s" access="read"/>
  <property name="OverlayIconName" type="s" access="read"/>
  <property name="ToolTip" type="(sa(iiay)ss)" access="read"/>
  <property name="ItemIsMenu" type="b" access="read"/>
  <property name="Menu" type="o" access="read"/>
  <method name="ContextMenu"><arg name="x" type="i" direction="in"/><arg name="y" type="i" direction="in"/></method>
  <method name="Activate"><arg name="x" type="i" direction="in"/><arg name="y" type="i" direction="in"/></method>
  <method name="SecondaryActivate"><arg name="x" type="i" direction="in"/><arg name="y" type="i" direction="in"/></method>
  <method name="Scroll"><arg name="delta" type="i" direction="in"/><arg name="orientation" type="s" direction="in"/></method>
  <signal name="NewTitle"/>
  <signal name="NewIcon"/>
  <signal name="NewAttentionIcon"/>
  <signal name="NewOverlayIcon"/>
  <signal name="NewToolTip"/>
  <signal name="NewStatus"><arg name="status" type="s"/></signal>
</interface></node>"#;

const MENU_XML: &str = r#"<node><interface name="com.canonical.dbusmenu">
  <property name="Version" type="u" access="read"/>
  <property name="TextDirection" type="s" access="read"/>
  <property name="Status" type="s" access="read"/>
  <property name="IconThemePath" type="as" access="read"/>
  <method name="GetLayout">
    <arg name="parentId" type="i" direction="in"/>
    <arg name="recursionDepth" type="i" direction="in"/>
    <arg name="propertyNames" type="as" direction="in"/>
    <arg name="revision" type="u" direction="out"/>
    <arg name="layout" type="(ia{sv}av)" direction="out"/>
  </method>
  <method name="GetGroupProperties">
    <arg name="ids" type="ai" direction="in"/>
    <arg name="propertyNames" type="as" direction="in"/>
    <arg name="properties" type="a(ia{sv})" direction="out"/>
  </method>
  <method name="GetProperty">
    <arg name="id" type="i" direction="in"/>
    <arg name="name" type="s" direction="in"/>
    <arg name="value" type="v" direction="out"/>
  </method>
  <method name="Event">
    <arg name="id" type="i" direction="in"/>
    <arg name="eventId" type="s" direction="in"/>
    <arg name="data" type="v" direction="in"/>
    <arg name="timestamp" type="u" direction="in"/>
  </method>
  <method name="EventGroup">
    <arg name="events" type="a(isvu)" direction="in"/>
    <arg name="idErrors" type="ai" direction="out"/>
  </method>
  <method name="AboutToShow">
    <arg name="id" type="i" direction="in"/>
    <arg name="needUpdate" type="b" direction="out"/>
  </method>
  <method name="AboutToShowGroup">
    <arg name="ids" type="ai" direction="in"/>
    <arg name="updatesNeeded" type="ai" direction="out"/>
    <arg name="idErrors" type="ai" direction="out"/>
  </method>
  <signal name="ItemsPropertiesUpdated">
    <arg name="updatedProps" type="a(ia{sv})"/>
    <arg name="removedProps" type="a(ias)"/>
  </signal>
  <signal name="LayoutUpdated">
    <arg name="revision" type="u"/>
    <arg name="parent" type="i"/>
  </signal>
  <signal name="ItemActivationRequested">
    <arg name="id" type="i"/>
    <arg name="timestamp" type="u"/>
  </signal>
</interface></node>"#;

/// What can be chosen from the icon.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Action {
    Open,
    Check,
    Quit,
}

/// One line of the icon's menu.
struct Entry {
    id: i32,
    /// Empty for a separator.
    label: String,
    action: Option<Action>,
}

/// The menu, with the state of the last check as its second line.
fn entries(summary: &str) -> Vec<Entry> {
    let line = |id, label: &str, action| Entry { id, label: tr(label), action };
    vec![
        line(1, "Picket öffnen", Some(Action::Open)),
        line(2, summary, None),
        line(3, "", None),
        line(4, "Neu prüfen", Some(Action::Check)),
        line(5, "", None),
        line(6, "Beenden", Some(Action::Quit)),
    ]
}

type Properties = HashMap<String, Variant>;

fn properties(entry: &Entry) -> Properties {
    if entry.label.is_empty() {
        return HashMap::from([("type".to_string(), "separator".to_variant())]);
    }
    HashMap::from([
        // An underscore would mark the next letter as a shortcut.
        ("label".to_string(), entry.label.replace('_', "__").to_variant()),
        ("enabled".to_string(), entry.action.is_some().to_variant()),
    ])
}

/// The answer to GetLayout: the revision and the menu below `parent`, type (u(ia{sv}av)).
fn layout(revision: u32, parent: i32, entries: &[Entry]) -> Variant {
    let leaf = |e: &Entry| (e.id, properties(e), Vec::<Variant>::new());
    let node = match entries.iter().find(|e| e.id == parent) {
        Some(entry) => leaf(entry),
        None => (
            0,
            HashMap::from([("children-display".to_string(), "submenu".to_variant())]),
            entries.iter().map(|e| leaf(e).to_variant()).collect(),
        ),
    };
    (revision, node).to_variant()
}

struct State {
    connection: gio::DBusConnection,
    /// Directory with the icon files, handed to the desktop as an extra place to look.
    icons: String,
    /// The result of the last check, in German; translated when it is shown.
    summary: RefCell<String>,
    attention: Cell<bool>,
    enabled: Cell<bool>,
    /// Something on the desktop has taken the icon.
    hosted: Cell<bool>,
    revision: Cell<u32>,
    handler: RefCell<Option<Rc<dyn Fn(Action)>>>,
}

impl State {
    fn status(&self) -> &'static str {
        match (self.enabled.get(), self.attention.get()) {
            (false, _) => "Passive", // the desktop hides a passive icon
            (true, true) => "NeedsAttention",
            (true, false) => "Active",
        }
    }

    fn property(&self, name: &str) -> Variant {
        match name {
            "Category" => "ApplicationStatus".to_variant(),
            "Id" => "picket".to_variant(),
            "Title" => "Picket".to_variant(),
            "Status" => self.status().to_variant(),
            "WindowId" => 0i32.to_variant(),
            "IconThemePath" => self.icons.to_variant(),
            "IconName" => ICON.to_variant(),
            "AttentionIconName" => ICON_ATTENTION.to_variant(),
            "ToolTip" => ("", Vec::<(i32, i32, Vec<u8>)>::new(), "Picket", tr(&self.summary.borrow())).to_variant(),
            "ItemIsMenu" => false.to_variant(),
            "Menu" => glib::variant::ObjectPath::try_from(MENU_PATH.to_string()).map(|p| p.to_variant()).unwrap_or_else(|_| "/".to_variant()),
            _ => "".to_variant(),
        }
    }

    fn signal(&self, path: &str, interface: &str, name: &str, parameters: Option<Variant>) {
        let _ = self.connection.emit_signal(None, path, interface, name, parameters.as_ref());
    }

    /// Run what was chosen once the D-Bus call has been answered.
    fn act(&self, action: Action) {
        if let Some(handler) = self.handler.borrow().clone() {
            glib::idle_add_local_once(move || handler(action));
        }
    }

    fn clicked(&self, id: i32, event: &str) {
        if event == "clicked" {
            if let Some(action) = entries("").iter().find(|e| e.id == id).and_then(|e| e.action) {
                self.act(action);
            }
        }
    }

    fn menu_call(&self, method: &str, parameters: &Variant) -> Option<Variant> {
        let entries = entries(&self.summary.borrow());
        match method {
            "GetLayout" => {
                let parent = parameters.child_value(0).get::<i32>().unwrap_or(0);
                Some(layout(self.revision.get(), parent, &entries))
            }
            "GetGroupProperties" => {
                let ids = parameters.child_value(0).get::<Vec<i32>>().unwrap_or_default();
                let wanted: Vec<(i32, Properties)> =
                    entries.iter().filter(|e| ids.is_empty() || ids.contains(&e.id)).map(|e| (e.id, properties(e))).collect();
                Some((wanted,).to_variant())
            }
            "GetProperty" => {
                let (id, name) = parameters.get::<(i32, String)>().unwrap_or_default();
                let value = entries.iter().find(|e| e.id == id).and_then(|e| properties(e).remove(&name));
                Some((value.unwrap_or_else(|| "".to_variant()),).to_variant())
            }
            "Event" => {
                if let Some((id, event, _, _)) = parameters.get::<(i32, String, Variant, u32)>() {
                    self.clicked(id, &event);
                }
                None
            }
            "EventGroup" => {
                for (id, event, _, _) in parameters.child_value(0).get::<Vec<(i32, String, Variant, u32)>>().unwrap_or_default() {
                    self.clicked(id, &event);
                }
                Some((Vec::<i32>::new(),).to_variant())
            }
            "AboutToShow" => Some((false,).to_variant()),
            "AboutToShowGroup" => Some((Vec::<i32>::new(), Vec::<i32>::new()).to_variant()),
            _ => None,
        }
    }
}

pub struct Tray {
    state: Rc<State>,
}

impl Tray {
    /// Offer the icon to the desktop. `enabled` is the user's setting; a disabled icon stays hidden.
    pub fn new(connection: &gio::DBusConnection, enabled: bool) -> Option<Tray> {
        let state = Rc::new(State {
            connection: connection.clone(),
            icons: write_icons()?,
            summary: RefCell::new(String::new()),
            attention: Cell::new(false),
            enabled: Cell::new(enabled),
            hosted: Cell::new(false),
            revision: Cell::new(1),
            handler: RefCell::new(None),
        });
        let interface = |xml: &str, name: &str| gio::DBusNodeInfo::for_xml(xml).ok()?.lookup_interface(name);

        let (s, p) = (state.clone(), state.clone());
        connection
            .register_object(ITEM_PATH, &interface(ITEM_XML, ITEM)?)
            .method_call(move |_, _, _, _, method, _, invocation| {
                // A plain click opens the window; the menu is the desktop's business.
                if matches!(method, "Activate" | "SecondaryActivate") {
                    s.act(Action::Open);
                }
                invocation.return_value(None);
            })
            .property(move |_, _, _, _, name| p.property(name))
            .build()
            .ok()?;

        let m = state.clone();
        connection
            .register_object(MENU_PATH, &interface(MENU_XML, MENU)?)
            .method_call(move |_, _, _, _, method, parameters, invocation| {
                invocation.return_value(m.menu_call(method, &parameters).as_ref());
            })
            .property(|_, _, _, _, name| match name {
                "Version" => 3u32.to_variant(),
                "TextDirection" => "ltr".to_variant(),
                "Status" => "normal".to_variant(),
                _ => Vec::<String>::new().to_variant(),
            })
            .build()
            .ok()?;

        // Whatever shows such icons announces itself under this name; it may come and go
        // (a restarted shell, an extension switched on later).
        let (appeared, vanished) = (Rc::downgrade(&state), Rc::downgrade(&state));
        gio::bus_watch_name_on_connection(
            connection,
            WATCHER,
            gio::BusNameWatcherFlags::NONE,
            move |connection, _, _| {
                let state = appeared.clone();
                connection.call(
                    Some(WATCHER),
                    "/StatusNotifierWatcher",
                    WATCHER,
                    "RegisterStatusNotifierItem",
                    Some(&(ITEM_PATH,).to_variant()),
                    None,
                    gio::DBusCallFlags::NONE,
                    5000,
                    gio::Cancellable::NONE,
                    move |result| {
                        if let Some(state) = state.upgrade() {
                            state.hosted.set(result.is_ok());
                        }
                    },
                );
            },
            move |_, _| {
                if let Some(state) = vanished.upgrade() {
                    state.hosted.set(false);
                }
            },
        );
        Some(Tray { state })
    }

    /// What to do when something is chosen from the icon.
    pub fn connect(&self, handler: impl Fn(Action) + 'static) {
        *self.state.handler.borrow_mut() = Some(Rc::new(handler));
    }

    /// Is the icon on screen? Only then may the window be closed without ending the program.
    pub fn is_shown(&self) -> bool {
        self.state.enabled.get() && self.state.hosted.get()
    }

    pub fn set_enabled(&self, enabled: bool) {
        self.state.enabled.set(enabled);
        self.state.signal(ITEM_PATH, ITEM, "NewStatus", Some((self.state.status(),).to_variant()));
    }

    /// Show the result of a check: `summary` in German, `attention` when something is critical.
    pub fn set_status(&self, summary: &str, attention: bool) {
        let state = &self.state;
        if *state.summary.borrow() == summary && state.attention.get() == attention {
            return;
        }
        *state.summary.borrow_mut() = summary.to_string();
        state.attention.set(attention);
        state.revision.set(state.revision.get() + 1);
        state.signal(ITEM_PATH, ITEM, "NewStatus", Some((state.status(),).to_variant()));
        state.signal(ITEM_PATH, ITEM, "NewToolTip", None);
        state.signal(MENU_PATH, MENU, "LayoutUpdated", Some((state.revision.get(), 0i32).to_variant()));
    }
}

/// The logo with the red mark.
fn attention_logo() -> String {
    LOGO.replace("</svg>", &format!("  {BADGE}</svg>"))
}

/// The icon files: the logo, as it is and with the red mark. They are written next to the
/// program's other data, so the icon works however the program was installed.
fn write_icons() -> Option<String> {
    let dir = util::data_dir().join("tray");
    std::fs::create_dir_all(&dir).ok()?;
    for (name, svg) in [(ICON, LOGO.to_string()), (ICON_ATTENTION, attention_logo())] {
        let path = dir.join(format!("{name}.svg"));
        if std::fs::read_to_string(&path).ok().as_deref() != Some(svg.as_str()) {
            std::fs::write(&path, &svg).ok()?;
        }
    }
    dir.to_str().map(String::from)
}

// ------------------------------------------------------------ settings

#[derive(serde::Serialize, serde::Deserialize)]
struct Settings {
    tray: bool,
}

fn settings_file() -> PathBuf {
    util::state_dir().join("settings.json")
}

/// The user's choice; the icon is on unless it was switched off.
pub fn enabled() -> bool {
    util::read_json::<Settings>(&settings_file()).map(|s| s.tray).unwrap_or(true)
}

pub fn save_enabled(tray: bool) -> Result<(), String> {
    util::write_json(&settings_file(), &Settings { tray })
}

fn autostart_file() -> PathBuf {
    let config = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from).filter(|p| p.is_absolute()).unwrap_or_else(|| util::home().join(".config"));
    config.join("autostart").join(format!("{}.desktop", crate::APP_ID))
}

/// Does Picket start with the desktop session?
pub fn autostart() -> bool {
    autostart_file().exists()
}

/// Start at login, without a window: only the icon appears.
pub fn set_autostart(on: bool) -> Result<(), String> {
    let file = autostart_file();
    if !on {
        return match std::fs::remove_file(&file) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(format!("{}: {e}", file.display())),
            _ => Ok(()),
        };
    }
    if let Some(dir) = file.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let entry = crate::desktop_entry(&util::self_exe(), "gui --background") + "X-GNOME-Autostart-enabled=true\n";
    std::fs::write(&file, entry).map_err(|e| format!("{}: {e}", file.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_menu_has_the_shape_the_protocol_asks_for() {
        let entries = entries("2 kritisch · 5 Warnungen");
        let all = layout(7, 0, &entries);
        assert_eq!(all.type_().as_str(), "(u(ia{sv}av))");
        let (revision, (root, _, children)) = all.get::<(u32, (i32, Properties, Vec<Variant>))>().unwrap();
        assert_eq!((revision, root, children.len()), (7, 0, 6));
        let (id, props, below) = children[1].get::<(i32, Properties, Vec<Variant>)>().unwrap();
        assert_eq!((id, below.len()), (2, 0));
        assert_eq!(props["label"].get::<String>().as_deref(), Some("2 kritisch · 5 Warnungen"));
        // the state is a line to read, not to click
        assert_eq!(props["enabled"].get::<bool>(), Some(false));
        let (_, separator, _) = children[2].get::<(i32, Properties, Vec<Variant>)>().unwrap();
        assert_eq!(separator["type"].get::<String>().as_deref(), Some("separator"));
        // one entry on its own
        let (_, (id, props, _)) = layout(7, 6, &entries).get::<(u32, (i32, Properties, Vec<Variant>))>().unwrap();
        assert_eq!((id, props["label"].get::<String>().as_deref()), (6, Some("Beenden")));
    }

    #[test]
    fn the_mark_is_drawn_into_the_logo() {
        let marked = attention_logo();
        assert!(marked.contains("#e01b24") && marked.trim_end().ends_with("</svg>"));
        assert_eq!(marked.matches("</svg>").count(), 1);
    }

    #[test]
    fn the_interface_descriptions_are_valid() {
        assert!(gio::DBusNodeInfo::for_xml(ITEM_XML).unwrap().lookup_interface(ITEM).is_some());
        assert!(gio::DBusNodeInfo::for_xml(MENU_XML).unwrap().lookup_interface(MENU).is_some());
    }
}
