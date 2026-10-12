"""Licence catalogue: SPDX ids, categories, text fingerprints, SPDX expression parsing.

Everything here is deterministic. Jev is only asked about text this module cannot
classify, or to double-check it (see jev.py).
"""

import re

# Ordered from least to most restrictive for a typical "can I ship this?" question.
CATEGORIES = {
    "public-domain": (0, "Dedicated to the public domain or equivalent; no conditions (Unlicense, CC0)."),
    "permissive": (1, "Allows use, modification and redistribution, including in closed-source products, "
                      "with only attribution/notice conditions (MIT, BSD, Apache-2.0, ISC)."),
    "weak-copyleft": (2, "Changes to the licensed files themselves must stay under the same licence, "
                         "but it may be combined with code under other licences (LGPL, MPL, EPL)."),
    "strong-copyleft": (3, "Any distributed work that includes or links this material must be released "
                           "under the same licence with source code (GPL)."),
    "network-copyleft": (4, "Like strong copyleft, and offering the software to users over a network also "
                            "requires releasing source code (AGPL)."),
    "source-available": (5, "Source can be read but use is restricted, e.g. no competing hosted service "
                            "or a time-delayed open licence (SSPL, BUSL, Elastic License)."),
    "non-commercial": (5, "Use is forbidden or restricted for commercial purposes (CC BY-NC, "
                          "'non-commercial use only' terms)."),
    "proprietary": (6, "All rights reserved, confidential, or no permission to use, copy or redistribute "
                       "is granted."),
    "unknown": (7, "Cannot tell what is allowed."),
}

# id -> (category, description sent to Jev as Choice criteria)
LICENCES = {
    "MIT": ("permissive", "MIT License: 'Permission is hereby granted, free of charge, to any person obtaining a copy'"),
    "Apache-2.0": ("permissive", "Apache License, Version 2.0"),
    "BSD-2-Clause": ("permissive", "BSD 2-Clause: redistribution conditions with no endorsement clause"),
    "BSD-3-Clause": ("permissive", "BSD 3-Clause: redistribution conditions plus 'neither the name of ... may be used to endorse'"),
    "ISC": ("permissive", "ISC License: 'Permission to use, copy, modify, and/or distribute this software for any purpose'"),
    "0BSD": ("permissive", "Zero-Clause BSD: ISC-like grant with no attribution requirement"),
    "Zlib": ("permissive", "zlib License: 'altered source versions must be plainly marked'"),
    "BSL-1.0": ("permissive", "Boost Software License 1.0"),
    "PSF-2.0": ("permissive", "Python Software Foundation License"),
    "Artistic-2.0": ("permissive", "Artistic License 2.0 (Perl)"),
    "CC-BY-4.0": ("permissive", "Creative Commons Attribution 4.0 (no NonCommercial or ShareAlike terms)"),
    "OFL-1.1": ("permissive", "SIL Open Font License 1.1 (fonts)"),
    "HPND": ("permissive", "Historical Permission Notice: 'permission to use, copy, modify, distribute, and sell this software'"),
    "LPPL-1.3c": ("permissive", "LaTeX Project Public License"),
    "Unlicense": ("public-domain", "The Unlicense: 'free and unencumbered software released into the public domain'"),
    "CC0-1.0": ("public-domain", "Creative Commons Zero / CC0 1.0 public domain dedication"),
    "MPL-2.0": ("weak-copyleft", "Mozilla Public License 2.0"),
    "LGPL-2.1": ("weak-copyleft", "GNU Lesser (or Library) General Public License version 2 or 2.1"),
    "LGPL-3.0": ("weak-copyleft", "GNU Lesser General Public License version 3"),
    "EPL-2.0": ("weak-copyleft", "Eclipse Public License 1.0 or 2.0"),
    "GFDL-1.3": ("weak-copyleft", "GNU Free Documentation License (documentation)"),
    "CC-BY-SA-4.0": ("weak-copyleft", "Creative Commons Attribution-ShareAlike"),
    "GPL": ("strong-copyleft", "GNU General Public License, version not stated"),
    "GPL-2.0": ("strong-copyleft", "GNU General Public License version 2 (not Lesser, not Affero)"),
    "GPL-3.0": ("strong-copyleft", "GNU General Public License version 3 (not Lesser, not Affero)"),
    "AGPL-3.0": ("network-copyleft", "GNU Affero General Public License version 3"),
    "SSPL-1.0": ("source-available", "Server Side Public License (MongoDB)"),
    "BUSL-1.1": ("source-available", "Business Source License 1.1"),
    "Elastic-2.0": ("source-available", "Elastic License 2.0"),
    "CC-BY-NC-4.0": ("non-commercial", "Creative Commons Attribution-NonCommercial (any NC variant)"),
    "PolyForm-Noncommercial-1.0.0": ("non-commercial", "PolyForm Noncommercial License"),
    "PolyForm-Shield-1.0.0": ("source-available", "PolyForm Shield, Small Business, Internal Use, Strict or Perimeter license"),
}

# SPDX ids seen in real repos that are not worth a Choice option: category only.
EXTRA_CATEGORY = {"Linux-OpenIB": "permissive", "OpenSSL": "permissive", "BSD-2-Clause-Patent": "permissive",
                  "Linux-man-pages-copyleft": "permissive", "CDDL-1.0": "weak-copyleft",
                  "copyleft-next-0.3.1": "strong-copyleft"}

# Pseudo-ids for things that are not a named licence. Category comes from Jev or code.
OTHER = "other-custom"
PROPRIETARY = "proprietary"
COPYRIGHT_ONLY = "copyright-only"
NONE = "none"
PSEUDO = {
    OTHER: "Licence terms are present but they are none of the named licences above (custom or rare licence)",
    PROPRIETARY: "Explicitly proprietary: says the material is confidential, unpublished or proprietary, or forbids "
                 "copying or distribution. A copyright line or 'All rights reserved' alone is not proprietary.",
    COPYRIGHT_ONLY: "Only a copyright notice (possibly with 'All rights reserved'), a warranty disclaimer, or a pointer "
                    "to licence terms stated in another file, without naming the licence",
    NONE: "Not about licensing or copyright at all",
}


def category_of(licence_id):
    if licence_id in LICENCES:
        return LICENCES[licence_id][0]
    if licence_id in EXTRA_CATEGORY:
        return EXTRA_CATEGORY[licence_id]
    if licence_id == PROPRIETARY:
        return "proprietary"
    return "unknown"


def rank(category):
    return CATEGORIES.get(category, CATEGORIES["unknown"])[0]


# Fingerprints. Order matters: more specific variants come first. Text is matched
# after collapsing whitespace and stripping comment markers, case-insensitively.
_FP = [
    ("AGPL-3.0", [r"gnu affero general public license"]),
    ("LGPL-3.0", [r"gnu lesser general public license.{0,40}version 3"]),
    ("LGPL-3.0", [r"gnu lgpl,? (version |v)3"]),
    ("LGPL-2.1", [r"gnu (lesser|library) general public license", r"gnu lgpl\b"]),
    ("GPL-3.0", [r"gnu general public license.{0,60}version 3", r"\bgplv3\b", r"gnu gpl,? (version |v)3"]),
    ("GPL-2.0", [r"gnu general public license.{0,60}version 2", r"\bgplv2\b", r"gnu gpl,? (version |v)2"]),
    ("GPL", [r"gnu general public license", r"\bgnu gpl\b"]),
    ("Apache-2.0", [r"apache license,? version 2\.0", r"licensed under the apache license"]),
    ("MPL-2.0", [r"mozilla public license,? (v\. ?|version )?2\.0"]),
    ("EPL-2.0", [r"eclipse public license"]),
    ("SSPL-1.0", [r"server side public license"]),
    ("BUSL-1.1", [r"business source license"]),
    ("Elastic-2.0", [r"elastic license 2\.0"]),
    ("PolyForm-Noncommercial-1.0.0", [r"polyform non-?commercial"]),
    ("PolyForm-Shield-1.0.0", [r"polyform (shield|small business|internal use|strict|perimeter)"]),
    ("CC-BY-NC-4.0", [r"creative commons attribution[- ]non-?commercial", r"\bcc[- ]by[- ]nc\b"]),
    ("CC-BY-SA-4.0", [r"creative commons attribution[- ]share-?alike", r"\bcc[- ]by[- ]sa\b"]),
    ("CC-BY-4.0", [r"creative commons attribution 4\.0"]),
    ("CC0-1.0", [r"\bcc0\b", r"creative commons zero"]),
    ("Unlicense", [r"this is free and unencumbered software released into the public domain"]),
    ("BSL-1.0", [r"boost software license"]),
    ("PSF-2.0", [r"python software foundation license"]),
    ("Artistic-2.0", [r"artistic license 2\.0"]),
    ("Zlib", [r"altered source versions must be plainly marked as such"]),
    ("LPPL-1.3c", [r"latex project public licen[cs]e"]),
    ("GFDL-1.3", [r"gnu free documentation licen[cs]e"]),
    ("HPND", [r"permission to use, copy, modify, distribute,? and sell this software"]),
    ("OFL-1.1", [r"sil open font licen[cs]e", r"\bofl-1\.1\b"]),
    ("ISC", [r"permission to use, copy, modify, (and/?or |and )?distribute this software for any purpose",
             r"\bisc licen[cs]e\b"]),
    # "X11 license" / "MIT license" are short-name notices; the full text is matched by its grant sentence.
    ("MIT", [r"permission is hereby granted, free of charge, to any person obtaining a copy",
             r"\b(mit|x11|expat) licen[cs]e\b"]),
    ("BSD-3-Clause", [r"redistributions of source code must retain.*(may be used to endorse|neither the name)",
                      r"\bbsd[- ]style licen[cs]e", r"\b(the|a|new|modified|revised) bsd licen[cs]e"]),
    ("BSD-2-Clause", [r"redistributions of source code must retain the above copyright notice"]),
]
_FP = [(lid, [re.compile(p, re.I | re.S) for p in pats]) for lid, pats in _FP]
_COMMENT_MARKERS = re.compile(r"(^|\n)\s*(#+|//+|/?\*+/?|--|;+|%|!|rem\b|<!--|-->)", re.I)
_OR_LATER = re.compile(r"(or|,)\s*\(?\s*at your option\s*\)?\s*any later version|\bversion \d(\.\d)?\+|or later", re.I)


def normalise(text):
    text = _COMMENT_MARKERS.sub(" ", text)
    return re.sub(r"\s+", " ", text).strip()


_GNU = {"GPL", "GPL-2.0", "GPL-3.0", "LGPL-2.1", "LGPL-3.0", "AGPL-3.0"}
_DUAL = re.compile(r"dual[- ]licen[cs]ed|under (a|your) choice of|choice of (the )?(following )?licen[cs]es|"
                   r"(use|redistribute|distribute) it either under|either under the terms of|"
                   r"licen[cs]ed under either|at your (option|choice),? (under )?(either )?the|"
                   r"\balternatively,? (this|the) (software|file|program|code) may be (distributed|used|licen[cs]ed)", re.I)
_BANNER_ID = re.compile(r"(?:@license|^\s*/\*!.*\|)\s*([A-Za-z][A-Za-z0-9.\-]+)", re.I | re.M)


def fingerprint(text):
    """Return licence ids whose fingerprint appears in text, most specific first.

    A family match (e.g. AGPL) suppresses its less specific relatives (GPL).
    """
    norm = normalise(text)
    # A full licence text names itself in its title, and may mention other licences later
    # (GPLv2 ends by recommending the "Library General Public License"). Trust the title.
    head = norm[:300]
    if len(norm) > 2000 and (titled := [lid for lid, pats in _FP if any(p.search(head) for p in pats)]):
        return titled[:1]
    # Minified-bundle banners: "/*! lib v1.2 | MIT */", "@license MIT"
    found = [b for b in (base_id(m) for m in _BANNER_ID.findall(text)) if b != OTHER]
    for lid, pats in _FP:
        if lid not in found and any(p.search(norm) for p in pats):
            found.append(lid)
    if "MPL-2.0" in found and "secondary licen" in norm.lower():
        # MPL-2.0 names the GNU licences as "Secondary Licenses"; that is not a GPL grant.
        found = [f for f in found if f not in _GNU]
    if "CC-BY-NC-4.0" in found:  # BY-NC-SA is one licence, not NC plus SA
        found = [f for f in found if f not in ("CC-BY-SA-4.0", "CC-BY-4.0")]
    if "GPL-2.0" in found or "GPL-3.0" in found:
        found = [f for f in found if f != "GPL"]
    if "AGPL-3.0" in found or "LGPL-3.0" in found or "LGPL-2.1" in found:
        found = [f for f in found if not (f == "GPL" or f.startswith("GPL-"))]
    if "LGPL-3.0" in found:
        found = [f for f in found if f != "LGPL-2.1"]
    if "BSD-3-Clause" in found:
        found = [f for f in found if f != "BSD-2-Clause"]
    if "GPL-3.0" in found and "GPL-2.0" in found:
        found.remove("GPL-2.0")  # GPLv3 text mentions version 2 in passing
    return found


def is_dual(text):
    """True when the text offers a choice between licences ("dual-licensed", "either ... or")."""
    return bool(_DUAL.search(normalise(text)))


def says_or_later(text):
    return bool(_OR_LATER.search(normalise(text)))


# --- SPDX -----------------------------------------------------------------

SPDX_TAG = re.compile(r"SPDX-License-Identifier:\s*([A-Za-z0-9.+\-() ]+?)\s*(?:\*/|-->|#\}|\*\)|\"|'|$)", re.M)
_SPDX_TOKEN = re.compile(r"[A-Za-z0-9.+\-]+")


def base_id(spdx_id):
    """GPL-3.0-or-later -> GPL-3.0, LGPL-2.1+ -> LGPL-2.1, LicenseRef-x -> other-custom."""
    sid = spdx_id.rstrip("+")
    for suffix in ("-only", "-or-later"):
        if sid.endswith(suffix):
            sid = sid[: -len(suffix)]
    if sid.startswith(("LicenseRef-", "DocumentRef-")):
        return OTHER
    if sid.upper().startswith("GFDL"):
        return "GFDL-1.3"
    if sid.upper().startswith("LPPL"):
        return "LPPL-1.3c"
    for known in (*LICENCES, *EXTRA_CATEGORY):
        if known.lower() == sid.lower():
            return known
    aliases = {"EPL-1.0": "EPL-2.0", "LGPL-2.0": "LGPL-2.1", "CC-BY-3.0": "CC-BY-4.0",
               "CC-BY-SA-3.0": "CC-BY-SA-4.0", "CC-BY-NC-3.0": "CC-BY-NC-4.0",
               "CC-BY-NC-SA-4.0": "CC-BY-NC-4.0", "CC-BY-NC-ND-4.0": "CC-BY-NC-4.0",
               "Python-2.0": "PSF-2.0", "GPL-1.0": "GPL", "MPL-1.1": "MPL-2.0", "copyleft-next": "copyleft-next-0.3.1", "BSD-3-Clause-Clear": "BSD-3-Clause", "X11": "MIT", "Expat": "MIT"}
    return aliases.get(sid, OTHER)


def expression_category(expr):
    """Category of an SPDX expression. 'A OR B' -> licensee may pick the least restrictive;
    'A AND B' (or anything else) -> all obligations apply, so the most restrictive.
    Simplification: mixed AND/OR expressions are treated as AND.
    """
    # Exception ids after WITH (Classpath-exception-2.0, Linux-syscall-note) are not licences.
    expr = re.sub(r"\s+WITH\s+[A-Za-z0-9.+\-]+", "", expr, flags=re.I)
    expr = re.sub(r"\s+or\s+later\b", "+", expr, flags=re.I)        # "GPL-2.0 or later"
    expr = re.sub(r"\s(or|and)\s", lambda m: f" {m.group(1).upper()} ", expr, flags=re.I)
    ids = [t.strip(".") for t in _SPDX_TOKEN.findall(expr) if t.upper() not in ("AND", "OR")]
    ids = [t for t in ids if t]
    cats = [category_of(base_id(i)) for i in ids] or ["unknown"]
    pick = min if (" OR " in expr and " AND " not in expr) else max
    return pick(cats, key=rank)
