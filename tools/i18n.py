#!/usr/bin/env python3
"""Translation helper for Picket.

The German text in the source code is the original. `src/i18n_en.rs` maps
every German string (or format template) to English.

  tools/i18n.py list      the German strings found in the code
  tools/i18n.py missing   strings in the code that have no English entry yet
  tools/i18n.py stale     entries in the table whose German text is no longer in the code

Short and lower-case strings are not recognised as text; they are found at run time
instead, with PICKET_I18N_LOG (see docs/development.md).
"""
import pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
# demo.rs only holds sample sentences that the real templates already cover
SKIP_FILES = {"i18n_en.rs", "i18n.rs", "demo.rs"}


def literals(text):
    """Yield (source_literal, value, line) for every ordinary string literal outside comments."""
    i, n, line = 0, len(text), 1
    while i < n:
        c = text[i]
        if c == "\n":
            line += 1
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i)
            j = n if j < 0 else j + 2
            line += text.count("\n", i, j)
            i = j
        elif c == "r" and re.match(r'r#*"', text[i:]):  # raw string: not translated
            m = re.match(r'r(#*)"', text[i:])
            end = text.find('"' + m.group(1), i + len(m.group(0)))
            end = n if end < 0 else end + 1 + len(m.group(1))
            line += text.count("\n", i, end)
            i = end
        elif c == "'":  # char literal or lifetime
            m = re.match(r"'(\\.[^']*|[^\\'])'", text[i:])
            i += len(m.group(0)) if m else 1
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            src = text[i : j + 1]
            yield src, evaluate(src[1:-1]), line
            line += src.count("\n")
            i = j + 1
        else:
            i += 1


def evaluate(body):
    """The runtime value of a Rust string literal body."""
    body = re.sub(r"\\\n\s*", "", body)  # line continuation
    out, i = [], 0
    while i < len(body):
        if body[i] == "\\" and i + 1 < len(body):
            e = body[i + 1]
            if e == "u":
                m = re.match(r"\\u\{([0-9a-fA-F]+)\}", body[i:])
                out.append(chr(int(m.group(1), 16)))
                i += len(m.group(0))
                continue
            out.append({"n": "\n", "t": "\t", "r": "\r", "0": "\0", "\\": "\\", '"': '"', "'": "'"}.get(e, e))
            i += 2
        else:
            out.append(body[i])
            i += 1
    return "".join(out)


GERMAN = re.compile(r"[äöüÄÖÜß„“–…·→←↓↑]")
WORD = re.compile(r"[A-Za-zÄÖÜäöüß]{3,}")


def looks_like_text(value):
    """Interface text, as opposed to identifiers, paths, commands and CSS classes."""
    plain = re.sub(r"\{[^{}]*\}", "", value)  # without format placeholders
    if not WORD.search(plain):
        return False
    if GERMAN.search(plain):
        return True
    if " " not in plain.strip():
        # a single word: text if it is capitalised and not an identifier or path
        return bool(re.fullmatch(r"[A-ZÄÖÜ][A-Za-zäöüß-]{2,}[.:!?…]?", plain.strip()))
    # several words: not a command line, path or key=value
    return not re.search(r"^[a-z0-9_./-]+( -|$)|^[A-Z_]+=|://|^\s*-A |^[a-z]+\.[a-z.]+ ", plain) and bool(re.search(r"[A-ZÄÖÜ]", plain))


def collect():
    seen, out = {}, []
    for path in sorted((ROOT / "src").rglob("*.rs")):
        if path.name in SKIP_FILES:
            continue
        text = path.read_text()
        cut = text.find("#[cfg(test)]\nmod tests")
        cut2 = text.find("#[cfg(test)]\npub mod testdata")
        cuts = [c for c in (cut, cut2) if c >= 0]
        if cuts:
            text = text[: min(cuts)]
        for src, value, line in literals(text):
            if looks_like_text(value) and value not in seen:
                seen[value] = len(out)
                out.append((src, value, f"{path.relative_to(ROOT)}:{line}"))
    return out


def table_keys():
    f = ROOT / "src" / "i18n_en.rs"
    if not f.exists():
        return set()
    return {v for i, (_, v, _) in enumerate(literals(f.read_text())) if i % 2 == 0}


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "list"
    items = collect()
    if cmd == "list":
        for _, value, where in items:
            print(f"{where}\t{value!r}")
    elif cmd == "count":
        print(len(items))
    elif cmd == "missing":
        keys = table_keys()
        for _, value, where in items:
            if value not in keys:
                print(f"{where}\t{value!r}")
    elif cmd == "stale":
        text = "\n".join(p.read_text() for p in sorted((ROOT / "src").rglob("*.rs")) if p.name != "i18n_en.rs")
        for line in (ROOT / "src" / "i18n_en.rs").read_text().splitlines():
            found = list(literals(line))
            # "// piece": part of a text that the code puts together, so not a literal there
            if len(found) == 2 and "// piece" not in line and found[0][0] not in text:
                print(found[0][0])


main()
