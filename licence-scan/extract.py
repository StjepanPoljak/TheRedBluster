"""Walk a project, find licence-relevant text, read declared licences from manifests."""

import hashlib
import json
import os
import re
import tomllib
from dataclasses import dataclass, field

import catalogue

SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache",
             ".pytest_cache", ".idea", ".vscode", ".licence-scan"}
DEP_DIRS = {"node_modules", "vendor", "third_party", "third-party", "site-packages", "bower_components"}
LICENCE_FILE = re.compile(r"^(un)?licen[cs]e|^copying|^notice|^copyright|^patents|\.licen[cs]e$|"
                          r"^third[_-]?party[_-]?(notices|licen[cs]es)", re.I)
LICENCE_DIR = re.compile(r"(^|/)(third[_-]?party[_-]?)?licen[cs]es(/|$)", re.I)

MAX_FILE_BYTES = 2_000_000
MAX_SNIPPET_CHARS = 24_000  # ~6k tokens; Jev's limit is 32k tokens for state + longest question
HEADER_LINES = 60
WINDOW = 15  # lines of context either side of a keyword hit outside the header
MAX_WINDOWS = 3

STRONG = re.compile(r"spdx-license-identifier|licensed under|permission is hereby granted|"
                    r"copyright\s*(\(c\)|©)?\s*\d{4}|all rights reserved|public domain|"
                    r"redistribution and use|general public license|terms of the .{0,30}licen[cs]e|"
                    r"@license\b|^\s*/\*!.*\|", re.I | re.M)
WEAK = re.compile(r"\blicen[cs]e[ds]?\b|\bcopyright\b|\bwarrant(y|ies)\b|\bredistribut|©|"
                  r"commercial|proprietary|confidential|\bpermi(tted|ssion)\b|you may (not )?use", re.I)


@dataclass
class Candidate:
    path: str                  # relative to project root
    kind: str                  # "licence-file" | "header" | "embedded"
    text: str
    start_line: int
    spdx: list = field(default_factory=list)
    fingerprints: list = field(default_factory=list)
    or_later: bool = False

    @property
    def digest(self):
        return hashlib.sha256(catalogue.normalise(self.text).lower().encode()).hexdigest()[:16]


def iter_files(root, include_deps=False):
    skip = SKIP_DIRS | (set() if include_deps else DEP_DIRS)
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in skip)
        for name in sorted(filenames):
            yield os.path.join(dirpath, name)


def read_text(path):
    """Return file text, or None for binary/huge/unreadable files."""
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return None
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None
    for enc in ("utf-8", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return None


def _relevant(text):
    """Cheap pre-filter: one strong signal, or two distinct weak ones."""
    if STRONG.search(text):
        return True
    return len({m.group(0).lower()[:6] for m in WEAK.finditer(text)}) >= 2


def candidates_for(root, path, text):
    rel = os.path.relpath(path, root)
    lines = text.splitlines()
    spans = []
    if LICENCE_FILE.search(os.path.basename(path)) or LICENCE_DIR.search(os.path.dirname(rel)):
        spans.append(("licence-file", 0, len(lines)))
    else:
        if _relevant("\n".join(lines[:HEADER_LINES])):
            spans.append(("header", 0, min(HEADER_LINES, len(lines))))
        # Licence blocks further down, e.g. vendored code pasted into a file or /*! ... */ banners.
        hits = [i for i, line in enumerate(lines[HEADER_LINES:], HEADER_LINES) if STRONG.search(line)]
        for i in hits:
            lo, hi = max(HEADER_LINES, i - WINDOW), min(len(lines), i + WINDOW)
            if spans and spans[-1][0] == "embedded" and lo <= spans[-1][2]:
                spans[-1] = ("embedded", spans[-1][1], hi)
            elif sum(s[0] == "embedded" for s in spans) < MAX_WINDOWS:
                spans.append(("embedded", lo, hi))

    out = []
    for kind, lo, hi in spans:
        chunk = "\n".join(lines[lo:hi])
        if kind != "licence-file" and not _relevant(chunk):
            continue
        if len(chunk) > MAX_SNIPPET_CHARS:  # keep the head (names the licence) and a bit of the tail
            chunk = chunk[: MAX_SNIPPET_CHARS - 2000] + "\n[...truncated...]\n" + chunk[-2000:]
        c = Candidate(rel, kind, chunk, lo + 1)
        c.spdx = [m.strip() for m in catalogue.SPDX_TAG.findall(chunk)]
        c.fingerprints = catalogue.fingerprint(chunk)
        # Full GPL texts contain "any later version" in their how-to-apply appendix, so only trust it in notices.
        c.or_later = kind != "licence-file" and catalogue.says_or_later(chunk)
        out.append(c)
    return out


def scan(root, include_deps=False):
    cands, stats = [], {"files": 0, "text_files": 0, "skipped_binary_or_large": 0}
    for path in iter_files(root, include_deps):
        stats["files"] += 1
        text = read_text(path)
        if text is None:
            stats["skipped_binary_or_large"] += 1
            continue
        stats["text_files"] += 1
        cands.extend(candidates_for(root, path, text))
    return cands, stats


# --- declared licences -----------------------------------------------------

def declared_licences(root):
    """Licence fields from package manifests at the project root: [(source, spdx_expression)]."""
    found = []

    def load(name, parser):
        p = os.path.join(root, name)
        if os.path.isfile(p):
            try:
                with open(p, "rb") as fh:
                    return parser(fh)
            except (ValueError, OSError):
                return None
        return None

    pkg = load("package.json", json.load)
    if isinstance(pkg, dict) and isinstance(pkg.get("license"), str):
        found.append(("package.json", pkg["license"]))
    comp = load("composer.json", json.load)
    if isinstance(comp, dict) and comp.get("license"):
        lic = comp["license"]
        found.append(("composer.json", " OR ".join(lic) if isinstance(lic, list) else lic))
    pyp = load("pyproject.toml", tomllib.load)
    if isinstance(pyp, dict):
        lic = (pyp.get("project") or {}).get("license") or ((pyp.get("tool") or {}).get("poetry") or {}).get("license")
        if isinstance(lic, dict):
            lic = lic.get("text")  # {file = ...} is covered by scanning the file itself
        if isinstance(lic, str) and len(lic) < 100:
            found.append(("pyproject.toml", lic))
    cargo = load("Cargo.toml", tomllib.load)
    if isinstance(cargo, dict) and (cargo.get("package") or {}).get("license"):
        found.append(("Cargo.toml", cargo["package"]["license"].replace("/", " OR ")))
    cfg = os.path.join(root, "setup.cfg")
    if os.path.isfile(cfg):
        m = re.search(r"^\s*license\s*=\s*(.+)$", read_text(cfg) or "", re.M)
        if m:
            found.append(("setup.cfg", m.group(1).strip()))
    return found
