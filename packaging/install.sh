#!/bin/sh
# Installs Picket for the current user: the program in ~/.local/bin and an entry in the
# application menu. Nothing here needs root.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
bin=${XDG_BIN_HOME:-$HOME/.local/bin}

install -Dm755 "$here/picket" "$bin/picket"
"$bin/picket" install-desktop

cat <<NOTE

Picket is installed as $bin/picket.
Start it from the application menu, or run it from a terminal.

Firewall changes, captures and some checks need a root helper. The window offers to
set it up when it is first needed; to do it now:

  sudo $bin/picket install-helper

Picket needs GTK 4.12 and libadwaita 1.5 or newer (Ubuntu 24.04, Debian 13, Fedora 40).
NOTE
