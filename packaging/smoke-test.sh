#!/bin/sh
# Installs the packages from dist/ on fresh systems (containers), starts the program there
# and removes it again. Run after packaging/build.sh; needs docker.
set -eu

cd "$(dirname "$0")/.."
dist=$(pwd)/dist

# The program starts, reads the network state, and the package has set up the root helper.
works='
    picket help >/dev/null
    picket net >/dev/null
    /usr/local/libexec/picket-helper protocol >/dev/null
    test -f /usr/share/polkit-1/actions/io.github.blanpa.Picket.policy
'
gone='
    test ! -e /usr/bin/picket
    test ! -e /usr/local/libexec/picket-helper
    test ! -e /usr/share/polkit-1/actions/io.github.blanpa.Picket.policy
'

for image in ubuntu:24.04 ubuntu:26.04 debian:13; do
    echo "== .deb on $image"
    docker run --rm -v "$dist:/dist:ro" -e DEBIAN_FRONTEND=noninteractive "$image" sh -ec "
        apt-get update -qq
        apt-get install -y -qq --no-install-recommends /dist/picket_*.deb >/dev/null
        $works
        apt-get remove -y -qq picket >/dev/null
        $gone
    "
done

echo "== .rpm on fedora:latest"
docker run --rm -v "$dist:/dist:ro" fedora:latest sh -ec "
    dnf install -y -q /dist/picket-*.rpm >/dev/null
    $works
    dnf remove -y -q picket >/dev/null
    $gone
"

echo "== .tar.gz"
tmp=$(mktemp -d)
tar -C "$tmp" -xzf "$dist"/picket-*-linux-*.tar.gz
HOME=$tmp/home XDG_DATA_HOME=$tmp/home/.local/share XDG_BIN_HOME=$tmp/home/.local/bin "$tmp"/picket-*/install.sh >/dev/null
"$tmp/home/.local/bin/picket" help >/dev/null
test -f "$tmp/home/.local/share/applications/io.github.blanpa.Picket.desktop"
rm -rf "$tmp"

echo "All packages install and start."
