# Security model

A tool that inspects a machine's security should be careful with that machine. This page describes what
Picket does with elevated rights, what leaves the computer, and what it stores.

## Checks read, actions ask

Every check is read-only. The system changes only when you confirm an action, and each confirmation shows
the exact command first. The actions are:

| Action | What happens | Rights |
|---|---|---|
| Firewall on/off, default policy, add or delete a rule | `ufw` | root |
| Block a domain | an entry in Picket's own section of `/etc/hosts` | root |
| Close a connection | `ss -K` for one remote address | root |
| Block a host | a `ufw` rule plus closing its connections | root |
| Fix: system updates, snap refresh, signature service | `apt-get`, `snap`, `systemctl` | root |
| Fix: permissions in `~/.ssh`, home directory, screen lock, Flatpak update | `chmod`, `gsettings`, `flatpak` | user |
| Restrict a Docker port | edits the compose file (a backup is kept) and runs `docker compose up -d` | user |
| Background watcher | a systemd user timer | user |

Commands are fixed in the code. A fix is identified by the finding it belongs to; nothing typed or received
from outside is executed.

## The root helper

The window runs without privileges. For root actions it does not start the binary in your home directory:
any program running under your account could replace that file and wait for the next password prompt.

Instead, a copy is installed once:

```sh
sudo picket install-helper
```

- The copy lives at `/usr/local/libexec/picket-helper` and belongs to root.
- A polkit rule (`/usr/share/polkit-1/actions/io.github.blanpa.Picket.policy`) names exactly that file.
  The window asks polkit to start it, and polkit shows the password dialog. The authorisation is kept for a
  few minutes (`auth_admin_keep`), so a series of actions asks once.
- Run as the helper, the binary accepts only these commands: `protocol`, `root-snapshot`, `fw-apply`,
  `capture`, `fix`.
- Before every use the window checks that the helper exists, belongs to root, is not writable by anyone
  else and speaks the current protocol version. After an update that changes the helper it asks to install
  it again.

The one moment the copy in your home directory runs as root is the installation itself.

`sudo picket remove-helper` removes the helper and the polkit rule.

### What the helper validates

- **Firewall requests** are structured (`{"op": "add", "action": "allow", "port": "22", …}`), not command
  lines. Actions, directions and protocols come from fixed lists; ports must be numbers, ranges or lists;
  addresses must parse as IP addresses or networks; comments may not contain quotes or control characters.
  A rule can only be deleted if it currently exists.
- **Domains** must be plain host names. Only Picket's own section of `/etc/hosts`, between two marker
  lines, is ever rewritten.
- **Capture requests** name an existing interface and optionally one IP address, one port and `tcp` or
  `udp`. The capture filter is assembled from these validated parts.
- Tools are started with separate arguments, never through a shell.

### Root data

Some facts are only readable as root: the firewall rules, the process names behind other users' sockets,
accounts with an empty password, `NOPASSWD` rules in sudoers. `root-snapshot` collects exactly these into
`/run/picket/privileged.json`, readable by root and your group. The window only trusts a snapshot owned by
root and ignores it after 24 hours; it disappears on reboot.

### Capture

`tcpdump` runs as root and writes raw packets into a pipe. Decoding them, which means parsing data that
comes straight from the network, happens in the unprivileged window (`src/pcap.rs`). The capture ends when
the window closes the pipe, after 15 minutes, or after 200,000 packets. The recording is kept in
`~/.cache/picket/mitschnitt.pcap`, readable only by you, and is deleted when the window closes.

### Testing the root paths

```sh
sudo picket selftest-root
```

exercises every root path for real and leaves nothing behind: it reads the root data, adds and deletes a
firewall rule for a documentation address, blocks and unblocks a reserved test domain, closes a connection
it opened itself and records two seconds of loopback traffic.

## System tools

Picket calls many system tools (`ss`, `ip`, `ufw`, `apt`, `docker` …). They are looked up in fixed system
directories (`/usr/sbin`, `/usr/bin`, `/sbin`, `/bin`, `/snap/bin`, `/usr/local/sbin`, `/usr/local/bin`),
never through `$PATH`, so a program planted earlier in your `PATH` cannot fake a result. The one exception
is Trivy, which is also accepted from Homebrew's directory because it only ever runs without privileges.

## What leaves the machine

Nothing is sent to the author or to any service of Picket's own; there is none. These things reach the
network:

| When | What |
|---|---|
| You press *load* for the country database | two files are downloaded from db-ip.com; look-ups are then offline |
| You press *load* for the blocklist | one file is downloaded from GitHub (StevenBlack/hosts); matching is offline |
| You confirm the online vulnerability look-up | names and versions of your cargo, pip and npm packages go to osv.dev. The list is shown first. |
| You scan container images | Trivy downloads its vulnerability database |
| *Resolve host names* is on, or the devices page is open | reverse DNS queries to your configured resolver |
| You search the network | one small UDP packet to every address of the local subnet |
| You check a device's services | TCP connections to 28 common ports of that device |
| A check runs | `snap`, `flatpak`, `fwupdmgr` and `pro` are asked for pending updates and may contact their own servers, as they do when you run them yourself |

The watcher only searches networks actively that you have searched yourself before, so it never probes a
café or company network on its own.

## What is stored

| Where | What |
|---|---|
| `~/.local/state/picket/` | accepted findings, known devices and their names, watcher state and events, scan results, the Lynis report, and `history/`: connections per day for 30 days |
| `~/.local/share/picket/` | the country database and the blocklist |
| `~/.cache/picket/` | the current capture, until the window closes |
| `/run/picket/` | the root data, until reboot |
| `~/.config/systemd/user/picket-watch.*` | the watcher's timer, while it is switched on |
| `<compose file>.picket-sicherung` | the previous version of a compose file Picket changed |

The connection history records which program talked to which address. It stays on the machine.

## The browser dashboard

`picket serve` binds to `127.0.0.1` only. The page needs a random token that changes on every start; the
API needs it as a header, which stops other websites from calling it, and requests with a foreign `Host`
header are refused, which stops DNS rebinding. The dashboard cannot change anything.

## Demo mode

With `PICKET_DEMO=1` the window shows made-up data instead of this machine's, for screenshots and
demonstrations. Every action that would change the system is refused in this mode.
