# Packs the files that packaging/build.sh has laid out; nothing is compiled here.
Name:           picket
Version:        %{picket_version}
Release:        1
Summary:        Security check-up for your Linux laptop
License:        GPL-3.0-or-later
URL:            https://github.com/blanpa/picket

# The libraries (GTK 4, libadwaita, glibc) are found automatically from the program file.
Requires:       iproute
Requires:       polkit
Recommends:     tcpdump
Recommends:     libnotify
Recommends:     curl
Suggests:       ufw
Suggests:       clamav
Suggests:       fwupd
Suggests:       mokutil
Suggests:       lynis

%global debug_package %{nil}
%global __os_install_post %{nil}
%global _build_id_links none

%description
Picket checks the firewall, open ports, updates, disk encryption, accounts
and more, shows which program talks to which server, lists the devices on
the local network and records packets. Every finding is explained in plain
language, and common problems can be fixed on the spot.

%install
mkdir -p %{buildroot}
cp -a %{picket_stage}/. %{buildroot}/

# The root helper for firewall changes, captures and system data: a root-owned copy of the
# program with its own polkit rule. Installing it here saves the one-time set-up step.
%post
/usr/bin/picket install-helper >/dev/null 2>&1 || :

%preun
if [ "$1" -eq 0 ]; then
    /usr/bin/picket remove-helper >/dev/null 2>&1 || :
fi

%files
/usr/bin/picket
/usr/share/applications/io.github.blanpa.Picket.desktop
/usr/share/icons/hicolor/scalable/apps/io.github.blanpa.Picket.svg
%dir /usr/share/licenses/picket
%license /usr/share/licenses/picket/LICENSE
%license /usr/share/licenses/picket/THIRD-PARTY-LICENSES.txt
