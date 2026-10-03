#!/usr/bin/env python3
"""Fail if Cyrillic appears anywhere outside a language place.

The project language is English. Russian and Ukrainian live only in their own places, on par with
every other language:

  * a path part named after the language: `ru/`, `uk/` (`tests/fixtures/ru/`, ...);
  * a file named for the language: `README.ru.md`, `lang/ru.json`, `lang/uk.json`;
  * the self-names of the two languages in a list where every language is named in its own way
    (`English · Español · Português · <Russian> · <Ukrainian>`, each in its own script).

Every file under the plugin folder is checked - each part of its path, and its text - walked on the
disk, not asked from git: this plugin may sit inside another repository (or none) while it is built,
and a git listing there would be empty and silently green. There are no in-file exemption markers -
the list above is the whole list. (The Russian and Ukrainian words that stand next to an ID number
live in lang/ru.json and lang/uk.json for that reason.)

    python3 scripts/check_language.py          # prints offenders, exits 1 if any
"""
import os
import re
import sys
from pathlib import Path


def _word(*codes):
    """A word from its code points: this file stays ASCII, so it never trips its own check."""
    return "".join(chr(code) for code in codes)


CYRILLIC = re.compile("[%s-%s]" % (chr(0x0400), chr(0x04FF)))
# Self-names of the two Cyrillic-script languages (Russian, Ukrainian).
SELF_NAMES = (_word(0x420, 0x443, 0x441, 0x441, 0x43A, 0x438, 0x439),
              _word(0x423, 0x43A, 0x440, 0x430, 0x457, 0x43D, 0x441, 0x44C, 0x43A, 0x430))
LANGUAGE_CODES = ("ru", "uk")
BINARY_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".shortcut",
                   ".plist", ".wav", ".mp3", ".mp4", ".woff", ".woff2", ".ttf", ".otf", ".pyc"}
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", "dist", "node_modules"}


def is_language_place(path):
    """True when `path` (a posix relative path) belongs to the Russian or Ukrainian place."""
    parts = path.split("/")
    if any(part in LANGUAGE_CODES for part in parts[:-1]):
        return True
    name = parts[-1]
    for code in LANGUAGE_CODES:
        if re.fullmatch(r"[^/]*\.%s\.[^/]+" % code, name):
            return True
        if len(parts) >= 2 and parts[-2] == "lang" and name == "%s.json" % code:
            return True
    return False


def offending_lines(text):
    """Line numbers that hold Cyrillic once the allowed self-names are removed."""
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        for name in SELF_NAMES:
            line = line.replace(name, "")
        if CYRILLIC.search(line):
            found.append(number)
    return found


def violations(root, paths):
    """List of "path: why" strings for `paths` (relative, posix) under `root`."""
    out = []
    root = Path(root)
    for path in sorted(set(paths)):
        if is_language_place(path):
            continue
        if CYRILLIC.search(path):
            out.append("%s: Cyrillic in the file name" % path)
        full = root / path
        if not full.is_file() or full.suffix.lower() in BINARY_SUFFIXES:
            continue
        try:
            data = full.read_bytes()
        except OSError as error:
            out.append("%s: cannot be read (%s)" % (path, error.strerror))
            continue
        if b"\0" in data:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            # Not UTF-8: a legacy single-byte Cyrillic encoding would otherwise slip through.
            text = data.decode("cp1251", errors="replace")
        lines = offending_lines(text)
        if lines:
            shown = ", ".join(str(n) for n in lines[:10]) + (" ..." if len(lines) > 10 else "")
            out.append("%s: Cyrillic on line(s) %s" % (path, shown))
    return out


def plugin_files(root):
    """Every file under `root`, relative and posix, junk folders left out."""
    out = []
    root = str(root)
    for folder, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in names:
            rel = os.path.relpath(os.path.join(folder, name), root)
            out.append(rel.replace(os.sep, "/"))
    return sorted(out)


def main():
    root = Path(__file__).resolve().parent.parent
    found = violations(root, plugin_files(root))
    for line in found:
        print(line)
    print("check_language: %d file(s) with Cyrillic outside a language place" % len(found))
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
