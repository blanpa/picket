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

Interface text is written in German in the code and translated to English when it is shown (see
[Languages](#languages)). Code, comments and commit messages are English.

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
| `src/i18n.rs`, `src/i18n_en.rs` | the interface language: the translator and the German-to-English table |
| `src/util.rs` | running tools with a timeout, paths, small helpers |
| `packaging/`, `.github/workflows/release.yml` | building the `.deb`, `.rpm` and `.tar.gz` packages / the release pipeline |

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

## Languages

The interface follows the system language (`LANGUAGE`, `LC_ALL`, `LC_MESSAGES`, `LANG`): German when it
starts with `de`, English otherwise. `PICKET_LANG=de` or `PICKET_LANG=en` overrides it.

The German text in the code is the original, and everything that is stored (accepted findings, watcher
state, history) stays German. Text is translated where it is shown: `i18n::tr()` for a string, `outln!` and
`errln!` in place of `println!` and `eprintln!`, `Finding::localized()` for a finding, `i18n::json()` for
JSON output. The translator looks the text up in the table in `src/i18n_en.rs`:

- An entry is either a fixed string or a format template such as `"{} Dateien geprüft"`. A template is
  matched against the finished German sentence; the values are picked out, translated themselves and put
  into the English template. English placeholders may be reordered by name (`{n}`) or number (`{1}`).
- What has no entry of its own is tried in parts: line by line, without its padding, a known ending
  (`" (offline)"`), text in brackets, pieces of a list (`", "`, `" · "`, `" – "`), a count in front.
- Text without a translation is shown in German.

To add or change interface text, write it in German in the code and add the pair to `src/i18n_en.rs`:

```sh
python3 tools/i18n.py missing     # German strings in the code without an English entry
python3 tools/i18n.py stale       # entries whose German text is no longer in the code
PICKET_LANG=en PICKET_I18N_LOG=/tmp/untranslated.log picket check --all   # what stayed German at run time
```

`cargo test` checks that every entry has the same placeholders on both sides. Tests always run in German.

The browser dashboard (`assets/index.html`) is a German page; `src/server.rs` holds the list of its
English replacements, and a test makes sure the list matches the page.

## Tests

```sh
cargo test                        # all unit tests
cargo test --no-default-features  # without the window's modules
sudo picket selftest-root         # the root paths, for real, without lasting changes
```

There are no automated tests of the window itself. The test aids below are what is used to look at it.

## Releases

A release is made by a tag:

```sh
# set the new version in Cargo.toml, then
cargo build --release            # also updates Cargo.lock
git commit -am "Version 0.2.0"
git tag v0.2.0
git push origin main v0.2.0
```

The workflow in `.github/workflows/release.yml` then runs on Ubuntu 24.04, once for x86_64 and once for
ARM64: it runs the tests, builds the program, packs it with `packaging/build.sh`, installs every package on
a fresh system with `packaging/smoke-test.sh` (Ubuntu 24.04 and 26.04, Debian 13, Fedora) and publishes the
files with a `SHA256SUMS` as a GitHub release. The tag has to match the version in `Cargo.toml`.

*Run workflow* on the workflow's page (or `gh workflow run release.yml`) does the same without publishing;
the packages can be downloaded from the run. Use it to try a change to the packaging.

Ubuntu 24.04 is the build system because it is the oldest one with GTK 4.12 and libadwaita 1.5: a program
built there also runs on everything newer, but not the other way round.

The packaging uses only `dpkg-deb` and `rpmbuild`:

```sh
cargo build --release --locked
packaging/build.sh deb           # or rpm, tar, all; results in dist/
packaging/smoke-test.sh          # needs docker and all three kinds of package
```

- The `.deb` and `.rpm` install `/usr/bin/picket`, the menu entry (`picket desktop-entry` prints it) and the
  icon. Their post-install script runs `picket install-helper`, their removal script `picket remove-helper`.
- The `.tar.gz` holds the program and `install.sh`, which installs for the current user.
- `packaging/third-party.py` collects the licences of the Rust libraries compiled into the program; every
  package carries the result as `THIRD-PARTY-LICENSES.txt`.

The packages are not signed and there is no package repository: an update means installing the next file.

## Demo mode and test aids

These environment variables exist for development; none of them is needed in normal use.

| Variable | Effect |
|---|---|
| `PICKET_LANG=de\|en` | interface language, instead of the system's |
| `PICKET_I18N_LOG=<file>` | every piece of text that has no English translation is appended to that file (names and addresses included) |
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

export PICKET_LANG=en PICKET_DEMO=1

# every page, 1120x820
PICKET_SHOT=/tmp/shots/a PICKET_SHOT_SIZE=1120x820 \
  PICKET_PCAP_REPLAY=/tmp/sample.pcap ./target/release/picket gui

# the connections page, tall enough for the diagram
PICKET_SHOT=/tmp/shots/tall PICKET_SHOT_SIZE=1120x1170 ./target/release/picket gui

# the list of programs
PICKET_SHOT=/tmp/shots/prog PICKET_SHOT_SIZE=1120x900 \
  PICKET_SHOT_TAB=programs PICKET_SHOT_EXPAND=firefox ./target/release/picket gui
```

The pictures follow the desktop's light or dark style; `ADW_DEBUG_COLOR_SCHEME=prefer-light` forces the
light one. Copy the results into `docs/screenshots/`.
