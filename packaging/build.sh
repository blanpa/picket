#!/bin/sh
# Packs an already built target/release/picket into installable packages:
#
#   packaging/build.sh deb    Ubuntu, Debian           dist/picket_<version>_<arch>.deb
#   packaging/build.sh rpm    Fedora                   dist/picket-<version>-1.<arch>.rpm
#   packaging/build.sh tar    any distribution         dist/picket-<version>-linux-<arch>.tar.gz
#   packaging/build.sh all
#
# Needs dpkg-deb and dpkg-shlibdeps for the .deb and rpmbuild for the .rpm. The packages
# run on the system they were built on and on newer ones; releases are built on Ubuntu 24.04.
set -eu
umask 022

cd "$(dirname "$0")/.."
top=$(pwd)
bin=$top/target/release/picket
[ -x "$bin" ] || { echo "Build first: cargo build --release --locked" >&2; exit 1; }

version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
machine=$(uname -m)
case "$machine" in
    x86_64) deb_arch=amd64 ;;
    aarch64) deb_arch=arm64 ;;
    *) echo "No packages for this machine type: $machine" >&2; exit 1 ;;
esac
id=io.github.blanpa.Picket
dist=$top/dist
work=$top/target/packaging
rm -rf "$work"
mkdir -p "$work" "$dist"

# The licences of the libraries that are compiled into the program.
python3 packaging/third-party.py > "$work/THIRD-PARTY-LICENSES.txt"

# The files of a system-wide installation, the same for .deb and .rpm.
stage() {
    install -Dm755 "$bin" "$1/usr/bin/picket"
    install -Dm644 assets/icon.svg "$1/usr/share/icons/hicolor/scalable/apps/$id.svg"
    install -d -m755 "$1/usr/share/applications"
    "$bin" desktop-entry > "$1/usr/share/applications/$id.desktop"
    chmod 644 "$1/usr/share/applications/$id.desktop"
}

build_deb() {
    root=$work/deb
    stage "$root"
    install -Dm644 packaging/deb/copyright "$root/usr/share/doc/picket/copyright"
    install -m644 "$work/THIRD-PARTY-LICENSES.txt" "$root/usr/share/doc/picket/"
    # The library packages the program needs, as dpkg works them out.
    mkdir -p "$work/shlibs/debian"
    printf 'Source: picket\n\nPackage: picket\nArchitecture: any\n' > "$work/shlibs/debian/control"
    libraries=$(cd "$work/shlibs" && dpkg-shlibdeps -O "$bin" 2>/dev/null | sed -n 's/^shlibs:Depends=//p')
    [ -n "$libraries" ] || { echo "dpkg-shlibdeps found no libraries" >&2; exit 1; }
    mkdir -p "$root/DEBIAN"
    cat > "$root/DEBIAN/control" <<CONTROL
Package: picket
Version: $version
Architecture: $deb_arch
Maintainer: blanpa <54003618+blanpa@users.noreply.github.com>
Installed-Size: $(du -sk "$root/usr" | cut -f1)
Depends: $libraries, iproute2, pkexec
Recommends: ufw, tcpdump, libnotify-bin, curl
Suggests: clamav, clamav-freshclam, fwupd, mokutil, lynis
Section: admin
Priority: optional
Homepage: https://github.com/blanpa/picket
Description: Security check-up for your Linux laptop
 Picket checks the firewall, open ports, updates, disk encryption, accounts
 and more, shows which program talks to which server, lists the devices on
 the local network and records packets. Every finding is explained in plain
 language, and common problems can be fixed on the spot.
CONTROL
    install -m755 packaging/deb/postinst packaging/deb/prerm "$root/DEBIAN/"
    # xz rather than Ubuntu's default zstd, so that every Debian can unpack it.
    dpkg-deb --root-owner-group -Zxz --build "$root" "$dist/picket_${version}_${deb_arch}.deb"
}

build_rpm() {
    stage "$work/rpm/stage"
    install -Dm644 LICENSE "$work/rpm/stage/usr/share/licenses/picket/LICENSE"
    install -m644 "$work/THIRD-PARTY-LICENSES.txt" "$work/rpm/stage/usr/share/licenses/picket/"
    rpmbuild -bb packaging/picket.spec --target "$machine" \
        --define "_topdir $work/rpm" \
        --define "picket_version $version" \
        --define "picket_stage $work/rpm/stage"
    cp "$work/rpm/RPMS/$machine/"*.rpm "$dist/"
}

build_tar() {
    name=picket-$version-linux-$machine
    install -Dm755 "$bin" "$work/tar/$name/picket"
    install -m755 packaging/install.sh "$work/tar/$name/"
    install -m644 LICENSE "$work/THIRD-PARTY-LICENSES.txt" "$work/tar/$name/"
    tar -C "$work/tar" --owner=0 --group=0 -czf "$dist/$name.tar.gz" "$name"
}

case "${1:-all}" in
    deb) build_deb ;;
    rpm) build_rpm ;;
    tar) build_tar ;;
    all) build_deb; build_rpm; build_tar ;;
    *) echo "Usage: $0 [deb|rpm|tar|all]" >&2; exit 2 ;;
esac
ls -l "$dist"
