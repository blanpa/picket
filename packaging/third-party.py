#!/usr/bin/env python3
"""Prints the licences of the Rust libraries that are compiled into Picket.

Their licences (MIT, Apache-2.0 and the like) ask for the licence text to travel with
every copy of the program; the packages ship this output as THIRD-PARTY-LICENSES.txt.
The list comes from `cargo metadata`, the texts from the files the libraries bring along.
"""
import json, pathlib, re, subprocess


def run(*command):
    return subprocess.run(command, check=True, capture_output=True, text=True).stdout


host = re.search(r"^host: (.+)$", run("rustc", "-vV"), re.M).group(1)
meta = json.loads(run("cargo", "metadata", "--format-version", "1", "--locked", "--filter-platform", host))
packages = {p["id"]: p for p in meta["packages"]}
nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}

# What ends up in the program: the normal dependencies, followed from Picket itself.
linked, todo = set(), [meta["resolve"]["root"]]
while todo:
    for dep in nodes[todo.pop()]["deps"]:
        if dep["pkg"] not in linked and any(kind["kind"] is None for kind in dep["dep_kinds"]):
            linked.add(dep["pkg"])
            todo.append(dep["pkg"])

libraries = sorted((packages[i] for i in linked), key=lambda p: (p["name"], p["version"]))
texts = {}  # licence text -> the libraries that ship it
for p in libraries:
    folder = pathlib.Path(p["manifest_path"]).parent
    for f in sorted(folder.iterdir()):
        if f.is_file() and re.match(r"(?i)(licen[sc]e|copying|copyright|notice)", f.name):
            texts.setdefault(f.read_text(errors="replace").strip(), []).append(f'{p["name"]} {p["version"]}')

print("Picket is licensed under the GNU General Public License, version 3 or later.")
print("It contains the following libraries, each under its own licence.\n")
for p in libraries:
    print(f'  {p["name"]} {p["version"]}  ({p.get("license") or "see below"})  {p.get("repository") or ""}'.rstrip())
for text, users in texts.items():
    print("\n" + "=" * 78)
    print("Licence text shipped with: " + ", ".join(users))
    print("=" * 78 + "\n")
    print(text)
