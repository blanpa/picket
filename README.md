# Picket

Sicherheits-Check für den Linux-Laptop (entwickelt auf einem Framework-Laptop mit Ubuntu). Ein einzelnes Rust-Binary,
das das System prüft und die Ergebnisse im Terminal oder in einem lokalen Dashboard zeigt.

**Die Prüfungen lesen nur.** Vorgeschlagene Befehle führst du selbst aus. Einzige Ausnahme: Firewall-Regeln,
die du im App-Fenster setzt – dabei siehst du vorher den ufw-Befehl und bestätigst mit deinem Passwort.

## Benutzung

```sh
picket                 # App-Fenster (GTK4/libadwaita)
picket install-desktop # Eintrag „Picket“ und Symbol ins App-Menü legen
picket check           # Bericht im Terminal (Exit-Code 1 bei kritischen Befunden)
picket check --all     # … mit allen Details
picket net             # Was geht ins Internet, was bleibt im LAN, welche Ports sind offen
picket devices         # Geräte im lokalen Netz (--scan spricht jede Adresse einmal an)
picket scan ~/Downloads            # Virenscan mit ClamAV
picket serve           # dieselbe Übersicht als Browser-Dashboard (nur 127.0.0.1, mit Token)
sudo $(which picket) root-snapshot # Zusatzdaten, die nur root lesen kann
```

In der App holt der Knopf „Freischalten“ die Root-Daten über den Passwortdialog des Systems (pkexec).

### Root-Helfer

Root-Aktionen (Firewall, Mitschnitt, Systemdaten, Root-Korrekturen) startet die App nicht aus `~/.cargo/bin` –
diese Datei könnte jedes Programm unter deinem Konto austauschen. Stattdessen wird einmalig eine Kopie nach
`/usr/local/libexec/picket-helper` installiert (gehört root) und eine polkit-Regel
(`/usr/share/polkit-1/actions/io.github.blanpa.Picket.policy`) benennt genau diese Datei; die Passwortabfrage gilt
dadurch einige Minuten. Der Helfer nimmt nur `root-snapshot`, `fw-apply`, `capture` und `fix` an.

```sh
sudo picket install-helper   # einmalig; die App bietet es beim ersten Bedarf auch an
sudo picket selftest-root    # testet Snapshot, ufw-Regel, Verbindung trennen und Mitschnitt echt – ohne bleibende Änderung
sudo picket remove-helper
```

Nach Updates, die den Helfer betreffen (`helper::PROTOCOL`), meldet die App, dass er neu eingerichtet werden muss.

### Befunde akzeptieren

Bewusste Entscheidungen lassen sich abhaken („Akzeptieren“ im Befund bzw. `picket accept <kennung>`).
Ein akzeptierter Befund zählt und meldet nicht mehr – bis sich seine Zusammenfassung ändert.

### Firewall in der App

Seite „Firewall“: ein-/ausschalten, Standardregel für eingehende Verbindungen, Regeln anlegen und löschen.
Die App startet dafür den Root-Helfer mit `fw-apply <json>`; `src/fwctl.rs` prüft die Anfrage und führt nur
fest definierte ufw-Befehle aus. Blockier-Regeln werden vorangestellt (`ufw prepend`), damit eine ältere
Erlauben-Regel sie nicht aushebelt. Ist die Firewall aktiv, bewertet die App offene Ports anhand der Regeln:
gesperrte Ports gelten nicht mehr als erreichbar; Docker-Ports bleiben offen, weil Docker ufw umgeht. Ansehen ohne Ausführen:

```sh
picket fw-apply --dry-run '{"op":"add","action":"allow","direction":"in","port":"22","proto":"tcp"}'
```

### Beendete Verbindungen

Die Seite „Verbindungen“ merkt sich, was seit dem Öffnen der App zu sehen war (`src/session.rs`). Geschlossene
Verbindungen bleiben abgeblendet stehen – im Live-Bild als gepunktete Linie, in der Programmliste mit
„beendet vor n min“. Wie lange, steht unter Einstellungen (Standard: 30 Minuten). Damit nichts unbemerkt bleibt,
wird auch im Hintergrund alle 15 Sekunden nachgesehen. Was kürzer lebt als der Abstand zweier Blicke
(5 bzw. 15 Sekunden), fehlt weiterhin; lückenlos ist nur der Mitschnitt.

### Netzwerk grafisch

Seite „Netzwerk“: Live-Bild mit Programmen links und Gegenstellen rechts. Wandernde Punkte zeigen gemessenen
TCP-Verkehr und dessen Richtung (Byte-Zähler aus `ss -i`); für UDP/QUIC führt der Kernel keine Zähler.

### Mitschnitt, Trennen, Blockieren

Seite „Mitschnitt“: zeichnet Pakete mit `tcpdump` auf (`pkexec picket capture <json>`, der Root-Helfer in
`src/capture.rs` prüft Schnittstelle, Adresse, Port und Protokoll). Die Rohdaten kommen über eine Pipe; zerlegt
werden sie ohne Root-Rechte in `src/pcap.rs`. Angezeigt werden Zeit, Richtung, Programm, Gegenstelle, Protokoll,
Größe und eine Beschreibung (DNS-Namen, TLS-Servername, HTTP-Zeile, TCP-Zustand). Der Mitschnitt endet beim
Stoppen, beim Schließen des Fensters, nach 15 Minuten oder 200 000 Paketen; die Aufzeichnung liegt bis dahin
in `~/.cache/picket/mitschnitt.pcap` (nur für dich lesbar) und lässt sich als `.pcap` für Wireshark speichern.

Im Menü „⋮“ jeder Verbindung (Seite „Netzwerk“) und auf der Mitschnitt-Seite:

- **Verbindung trennen** – `ss -K` beendet die bestehenden Verbindungen zur Gegenstelle.
- **Gegenstelle blockieren** – ufw-Regel gegen die Adresse plus sofortiges Trennen. Wirkt nur bei eingeschalteter Firewall.

### Wächter und Verlauf

`picket watch` vergleicht den aktuellen Zustand mit dem letzten Lauf und meldet Änderungen als
Desktop-Benachrichtigung: neuer kritischer Befund oder neue Warnung, neuer offener Port, neues Gerät im Netz.
Der Schalter „Wächter im Hintergrund“ (Übersicht) bzw. `picket watch on` richtet einen systemd-User-Timer ein
(alle 5 Minuten; die langsamen Prüfungen nur alle 6 Stunden). Dabei werden auch die offenen Verbindungen notiert
(`~/.local/state/picket/history/`, 30 Tage). Seite „Verlauf“ bzw. `picket events` / `history`.

### Docker, Korrekturen, Tiefenprüfung

- **Docker:** Container mit Ports und Rechten; für offene Ports die passende `127.0.0.1`-Zeile zum Kopieren.
- **Beheben:** Befunde mit eindeutiger Lösung haben einen Knopf (`src/fixes.rs`, feste Befehle; Root-Korrekturen über pkexec).
  `picket fix <befund> --dry-run` zeigt die Befehle.
- **Tiefenprüfung** (`picket deep`): Zugangsdaten in Klartextdateien (gemeldet werden nur Pfad und Art),
  Autostart-Einträge, set-uid-Dateien ohne Paket, `dpkg --verify`, Lynis-Audit ohne Root.
- **Lücken-Abgleich** (`picket cve`): fragt osv.dev nach Lücken in Programmen aus cargo, pip (--user) und
  globalem npm. Sendet Namen und Versionen; `--dry-run` zeigt die Liste. Pakete aus apt deckt Ubuntu selbst ab,
  für manuell installierte .deb-Programme gibt es keine solche Datenbank.

### Zusatzdaten (einmal laden, danach offline)

`picket update-data` bzw. die Knöpfe auf der Übersicht laden nach `~/.local/share/picket/`:
die Länder-/Anbieter-Datenbank von db-ip.com (IP → „Google LLC · USA“) und die Sperrliste StevenBlack/hosts
(markiert Werbe-, Tracking- und Schad-Domains im Mitschnitt). `picket lookup <IP|Domain>` fragt beides ab.

### Geräte im Netz

Seite „Geräte im Netz“: Geräte aus der Nachbartabelle des Kernels (ARP/NDP) mit IP, MAC, Hersteller und Name.
„Netz durchsuchen“ schickt ein UDP-Paket an jede Adresse des Subnetzes (bis /22) und findet so auch stille Geräte.
Über „⋮“ lässt sich ein Gerät benennen und auf übliche Dienste prüfen (`picket ports <IP>`: 28 Ports, nur TCP-Verbindungsaufbau).

## Was geprüft wird

| Bereich | Prüfungen |
|---|---|
| Firewall | ufw/firewalld aktiv, Standardregeln, Regeln (Root-Snapshot); in der App änderbar |
| Netzwerk | Live: Verbindungen je Programm nach Ziel (Internet / LAN / VPN / Container / lokal), offene Ports und von wo sie erreichbar sind, Docker-Portfreigaben, WLAN-Verschlüsselung, Netzwerkdienste |
| Virenscanner | ClamAV installiert, Alter der Signaturen, Update-Dienst, Echtzeitschutz, letzter Scan |
| Programme & Updates | apt-Updates, Ubuntu-Pro/ESM-Updates, Snap, Flatpak, Firmware (fwupd), Pakete ohne Update-Quelle, fremde Paketquellen, ausstehender Neustart |
| System & Firmware | LUKS-Verschlüsselung, Swap, Secure Boot, HSI-Stufe, AppArmor, CPU-Lücken, Kernel-Härtung |
| Konten & Zugang | Konten/UID 0, sudo/docker-Gruppe, SSH-Server, SSH-Schlüssel und Dateirechte, Bildschirmsperre, Auto-Login |

## Root-Snapshot

Das Dashboard läuft ohne Root. Firewall-Regeln, Prozessnamen fremder Ports, leere Passwörter und
`NOPASSWD`-Regeln kann nur root lesen. `root-snapshot` sammelt genau diese Daten (nur lesend) nach
`/run/picket/privileged.json` (Rechte 640, root + deine Gruppe); der Snapshot gilt 24 h bzw. bis zum Neustart.

## Bauen

```sh
sudo apt install libgtk-4-dev libadwaita-1-dev   # nur zum Bauen der Oberfläche nötig
cargo build --release        # Binary: target/release/picket
cargo test
cargo install --path .       # nach ~/.cargo/bin
picket install-desktop

cargo build --release --no-default-features   # ohne Oberfläche: nur Terminal und Browser-Dashboard
```

Abhängigkeiten: `gtk4`, `libadwaita` (Feature `gui`), `tiny_http`, `serde`, `serde_json`.
Systemwerkzeuge werden nur aus `/usr/sbin`, `/usr/bin`, `/sbin`, `/bin`, `/snap/bin` gestartet, nicht über `$PATH`.

## Grenzen

- Verbindungen aus Docker-Containern und VMs erscheinen nicht als eigene Programme.
- Die Netzwerkansicht ist eine Momentaufnahme (alle 5 s), kein Mitschnitt: sehr kurze Verbindungen können fehlen.
- Kein CVE-Abgleich einzelner Programmversionen; bewertet wird, ob Updates ausstehen.
