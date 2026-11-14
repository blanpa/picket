# Development

## Building

```sh
sudo apt install libgtk-4-dev libadwaita-1-dev   # plus a Rust toolchain, 1.80 or newer
cargo build --release                         # target/release/picket, with the window
cargo build --release --no-default-features   # terminal and browser dashboard only
cargo test
cargo install --path .                        # ~/.cargo/bin/picket
```

The window is behind the cargo feature `gui` (on by default). The checks, the terminal interface and the
root helper do not depend on GTK.

After changing anything the root helper does, raise `PROTOCOL` in `src/helper.rs`. The window then notices
that the installed helper is outdated and asks to install it again.

## Layout

Interface text is German; code, comments and commit messages are English.

| File | Role |
|---|---|
| `src/main.rs` | command line: every subcommand, including the root helper's |
| `src/gui.rs` | the GTK4/libadwaita window |
| `src/graph.rs` | the live connection diagram and the throughput chart (cairo) |
| `src/session.rs` | what the window has seen since it opened, including closed connections |
| `src/model.rs` | findings, statuses, the report |
| `src/checks/` | the checks, one file per area; each returns a list of findings |
| `src/net.rs` | interfaces, listening sockets and connections from `ss`/`ip`, classified by zone |
| `src/devices.rs` | devices on the local network: neighbour table, sweep, vendors, port check |
| `src/docker.rs` | containers, compose-file rewriting, Trivy |
| `src/fwctl.rs` | firewall requests, their validation, the verdict for a port, `/etc/hosts` |
| `src/capture.rs`, `src/pcap.rs` | starting `tcpdump` as root / decoding the packets without privileges |
| `src/privileged.rs` | the root data snapshot |
| `src/helper.rs`, `src/selftest.rs` | installing the root helper / testing the root paths |
| `src/fixes.rs`, `src/accept.rs` | one-click fixes / accepted findings |
| `src/watch.rs`, `src/history.rs` | the background watcher / connections per day |
| `src/deep.rs` | the deep check |
| `src/scan.rs` | ClamAV scans |
| `src/geo.rs`, `src/blocklist.rs`, `src/osv.rs` | country database, domain blocklist, vulnerability look-up |
| `src/report.rs` | HTML export |
| `src/server.rs`, `assets/index.html` | the browser dashboard |
| `src/demo.rs` | sample data for demo mode |
| `src/util.rs` | running tools with a timeout, paths, small helpers |

### Conventions

- **Parsing is separate from running.** Every parser of a tool's output (`ss`, `ufw show added`,
  `docker inspect`, `dpkg --verify`, pcap …) is a pure function with a unit test, so it can be tested
  without the tool and without root.
- **Tools are run through `util::run`**, which looks them up in system directories only, sets the C locale
  for stable output and enforces a timeout.
- **Long work never runs on the GTK main thread.** Checks, snapshots and scans run in
  `gio::spawn_blocking` or a thread; results come back through a future or a channel.
- **Anything that changes the system** goes through `fwctl::Op` or `fixes::apply`, both of which build
  their commands from validated parts.

## Tests

```sh
cargo test                        # all unit tests
cargo test --no-default-features  # without the window's modules
sudo picket selftest-root         # the root paths, for real, without lasting changes
```

There are no automated tests of the window itself. The test aids below are what is used to look at it.

## Demo mode and test aids

These environment variables exist for development; none of them is needed in normal use.

| Variable | Effect |
|---|---|
| `PICKET_DEMO=1` | the window and the terminal show sample data (`src/demo.rs`); actions that change the system are refused |
| `PICKET_SHOT=<prefix>` | the window visits every page, saves `<prefix>-<page>.png` and quits. It renders only its own window, not the screen, and runs beside an already open Picket. |
| `PICKET_SHOT_SIZE=1120x820` | window size for that tour |
| `PICKET_SHOT_TAB=programs` | which tab of the connections page to show (`graph`, `programs`, `ports`) |
| `PICKET_SHOT_EXPAND=<program>` | which program to open in the list |
| `PICKET_SHOT_DIALOG=1` | also save a picture of the firewall rule form |
| `PICKET_PCAP_REPLAY=<file>` | the capture page replays a pcap file instead of starting `tcpdump` |
| `PICKET_WRITE_SAMPLE=<file>` | the test `writes_sample_capture` writes a small pcap file there |
| `PICKET_PRIV_FILE=<file>` | read and write the root data snapshot there instead of `/run/picket` |

### Regenerating the screenshots

```sh
cargo build --release
PICKET_WRITE_SAMPLE=/tmp/sample.pcap cargo test --release writes_sample_capture

# every page, 1120x820
PICKET_DEMO=1 PICKET_SHOT=/tmp/shots/a PICKET_SHOT_SIZE=1120x820 \
  PICKET_PCAP_REPLAY=/tmp/sample.pcap ./target/release/picket gui

# the connections page, tall enough for the diagram
PICKET_DEMO=1 PICKET_SHOT=/tmp/shots/tall PICKET_SHOT_SIZE=1120x1180 ./target/release/picket gui

# the list of programs
PICKET_DEMO=1 PICKET_SHOT=/tmp/shots/prog PICKET_SHOT_SIZE=1120x900 \
  PICKET_SHOT_TAB=programs PICKET_SHOT_EXPAND=firefox ./target/release/picket gui
```

The pictures follow the desktop's light or dark style; `ADW_DEBUG_COLOR_SCHEME=prefer-light` forces the
light one. Copy the results into `docs/screenshots/`.
