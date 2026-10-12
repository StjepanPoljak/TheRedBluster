"""Turn classifications into findings. Deliberately simple and conservative. Not legal advice."""

import catalogue

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "REVIEW": 2, "INFO": 3}
COPYLEFT = {"strong-copyleft", "network-copyleft"}
RESTRICTED = {"source-available", "non-commercial", "proprietary"}


def project_category(declared):
    """declared: [(source, licence_id_or_expr)] -> (category, ids)."""
    if not declared:
        return None, []
    cats = [catalogue.expression_category(expr) for _, expr in declared]
    return max(cats, key=catalogue.rank), [expr for _, expr in declared]


def findings_for(candidate, cl, proj_cat, root_licence_files):
    where = f"{candidate.path}:{candidate.start_line}"
    base = {"file": where, "licence": cl.licence_id, "category": cl.category, "source": cl.source,
            "confidence": cl.confidence, "reasons": list(cl.reasons), "flags": cl.flags}
    if cl.licence_id.startswith("GPL") and candidate.or_later:
        base["licence"] += " (or later)"

    def f(sev, msg):
        return [{**base, "severity": sev, "message": msg}]

    if candidate.path in root_licence_files:
        return []  # it *is* the project declaration; reported in the summary
    if cl.notice_only:
        return f("INFO", "copyright notice only; assumed to be covered by the project licence")
    if cl.uncertain:  # never raise HIGH on an answer Jev itself is unsure about
        return f("REVIEW", f"Jev unsure; leans {cl.licence_id} ({cl.category})")
    if cl.category in RESTRICTED:
        return f("HIGH", f"{cl.category} terms: may not be redistributable in this project")
    if cl.category in COPYLEFT and proj_cat not in COPYLEFT:
        return f("HIGH", f"{cl.category} material in a {proj_cat or 'unlicensed'} project")
    if cl.category == "network-copyleft" and proj_cat == "strong-copyleft":
        return f("MEDIUM", "AGPL-style network obligations in a GPL project")
    if cl.category == "weak-copyleft" and proj_cat in COPYLEFT and ("LGPL" in cl.licence_id or "GFDL" in cl.licence_id):
        return f("INFO", "LGPL/GFDL inside a GPL project")
    if cl.category == "weak-copyleft":
        return f("MEDIUM", "file-level copyleft: modifications to this file must stay under its licence")
    if cl.licence_id == "restrictive-notice":
        return f("REVIEW", "copyright with 'do not distribute'-style wording: is this a real restriction?")
    if cl.licence_id == "all-rights-reserved":
        return f("REVIEW", "'All rights reserved' and no licence grant: check it is covered by the project licence")
    if cl.category == "unknown" or cl.needs_review:
        return f("REVIEW", "could not classify with confidence")
    return f("INFO", "permissive; keep its notice when redistributing")


def project_findings(declared, root_cls):
    """Checks on the project's own declaration. root_cls: {path: Classification} for root licence files."""
    out = []
    if not declared and not root_cls:
        out.append({"severity": "HIGH", "file": ".", "message": "no project licence found (no LICENSE file or manifest licence field)"})
        return out
    declared_cats = {catalogue.expression_category(e) for _, e in declared}
    file_cats = {cl.category for cl in root_cls.values() if not cl.notice_only}
    if declared_cats and file_cats and not (declared_cats & file_cats):
        out.append({"severity": "MEDIUM", "file": ".",
                    "message": f"manifest says {sorted(declared_cats)} but LICENSE file reads as {sorted(file_cats)}"})
    return out
