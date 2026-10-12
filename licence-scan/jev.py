"""TypeSafe Jev integration: questions, HTTP client, a mock client, and answer interpretation.

API contract: https://docs.typesafe.ai/api.md (POST /v1/systemone). Stdlib only, so the
prototype runs without installing typesafe-sdk; swapping in the SDK later is mechanical.
"""

import json
import os
import random
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

import catalogue

API_URL = "https://api.typesafe.ai/v1/systemone"
MODEL = os.environ.get("TYPESAFE_MODEL", "jev-latest")
PRICE_PER_MTOK = 0.042  # USD, input tokens only (docs.typesafe.ai/models, jev-1.13)

# Thresholds are placeholders. They must be tuned on labelled data before anyone trusts them.
NOT_LICENCE_BELOW = 0.25
LICENCE_SURE_ABOVE = 0.6
MIN_CONFIDENCE = 0.6
FLAG_YES = 0.7


def build_questions():
    """All questions are asked together over the same snippet (speculative fan-out).

    `category` and the four obligation Nouls only matter when the licence is not a
    named one; code ignores them otherwise.
    """
    licence_options = {lid: desc for lid, (_, desc) in catalogue.LICENCES.items()}
    licence_options.update(catalogue.PSEUDO)
    return {
        "is_licence": {
            "type": "noul",
            "instructions": "Does `text` state the licence, copyright terms, or usage permissions "
                            "that apply to this file or project?",
            "criteria": {
                "true": "It contains a licence grant, a licence name or identifier applied to the material, "
                        "licence terms, or a copyright notice such as 'Copyright 2020 Jane Doe' or 'All rights reserved'.",
                "false": "It only uses the word licence or copyright for another purpose, for example program "
                         "code that validates licence keys, a UI string, or documentation about licensing in general.",
            },
        },
        "licence_id": {
            "type": "choice",
            "instructions": "Which licence applies to the material in `text`? Identify it by its name, "
                            "SPDX identifier, or full licence text.",
            "criteria": licence_options,
        },
        "category": {
            "type": "choice",
            "instructions": "Which category best describes what the licence terms in `text` allow?",
            "criteria": {c: d for c, (_, d) in catalogue.CATEGORIES.items()},
        },
        "restricts_commercial": {
            "type": "noul",
            "instructions": "Do the terms in `text` forbid or restrict commercial use of the material?",
        },
        "requires_source": {
            "type": "noul",
            "instructions": "Do the terms in `text` require that source code be made available "
                            "when the material is distributed?",
        },
        "network_clause": {
            "type": "noul",
            "instructions": "Do the terms in `text` impose obligations when the software is offered "
                            "to users over a network or as a hosted service?",
        },
        "requires_attribution": {
            "type": "noul",
            "instructions": "Do the terms in `text` require keeping a copyright notice or giving "
                            "credit when the material is redistributed?",
        },
    }


def build_request(candidate):
    return {
        "model": MODEL,
        "state": {"file_path": candidate.path, "text": candidate.text},
        "questions": build_questions(),
    }


def estimate_tokens(request):
    return len(json.dumps(request)) // 4  # rough: ~4 chars/token for English


class JevClient:
    def __init__(self, api_key, retries=5, timeout=60):
        self.api_key, self.retries, self.timeout = api_key, retries, timeout

    def ask(self, request):
        body = json.dumps(request).encode()
        for attempt in range(self.retries + 1):
            req = urllib.request.Request(API_URL, data=body, method="POST", headers={
                "Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return json.load(resp)
            except urllib.error.HTTPError as e:
                if e.code in (429, 500, 502, 503, 529) and attempt < self.retries:
                    wait = float(e.headers.get("retry-after") or 0) or min(30, 2 ** attempt + random.random())
                    time.sleep(wait)
                    continue
                detail = e.read().decode(errors="replace")[:500]
                raise RuntimeError(f"TypeSafe API {e.code}: {detail}") from None
            except urllib.error.URLError:
                if attempt < self.retries:
                    time.sleep(min(30, 2 ** attempt))
                    continue
                raise


class MockClient:
    """Answers shaped like Jev's, derived from regexes. Exercises the pipeline without
    credits; its answers say nothing about how well Jev itself would do."""

    def ask(self, request):
        text = request["state"]["text"]
        fps = catalogue.fingerprint(text)
        has = lambda pat: bool(re.search(pat, text, re.I))
        if fps:
            lid, conf = fps[0], 0.9
        elif has(r"all rights reserved|proprietary|confidential"):
            lid, conf = catalogue.PROPRIETARY, 0.7
        elif has(r"licen[cs]e|permission"):
            lid, conf = catalogue.OTHER, 0.55
        else:
            lid, conf = catalogue.NONE, 0.8
        nc = has(r"non-?commercial|not for commercial|commercial use (is )?(not permitted|prohibited)")
        cat = (catalogue.category_of(lid) if lid in catalogue.LICENCES else
               "non-commercial" if nc else "proprietary" if lid == catalogue.PROPRIETARY else "unknown")
        is_lic = 0.95 if (fps or has(r"copyright|licensed under|permission is hereby|you may use|commercial use")) else 0.15
        p = lambda b: 0.9 if b else 0.1
        return {"model": "mock", "usage": {"input_tokens": estimate_tokens(request), "output_tokens": 0},
                "answers": {
                    "is_licence": {"type": "noul", "noul": is_lic},
                    "licence_id": {"type": "choice", "choice": lid, "confidence": conf, "probabilities": {lid: conf}},
                    "category": {"type": "choice", "choice": cat, "confidence": 0.7, "probabilities": {cat: 0.7}},
                    "restricts_commercial": {"type": "noul", "noul": p(nc)},
                    "requires_source": {"type": "noul", "noul": p(has(r"source code .{0,40}(available|disclose)"))},
                    "network_clause": {"type": "noul", "noul": p(has(r"over a network|as a service"))},
                    "requires_attribution": {"type": "noul", "noul": p(has(r"retain|attribution|credit"))},
                }}


# --- turning answers + deterministic evidence into one classification ------

@dataclass
class Classification:
    licence_id: str
    category: str
    source: str              # spdx | fingerprint | jev | regex
    confidence: float | None = None
    needs_review: bool = False
    notice_only: bool = False
    uncertain: bool = False  # Jev's answer is not confident enough to act on (policy reports REVIEW)
    reasons: list = field(default_factory=list)
    flags: dict = field(default_factory=dict)
    jev_model: str | None = None


PROPRIETARY_PHRASES = re.compile(
    r"proprietary and confidential|confidential and proprietary|strictly confidential|"
    r"unauthori[sz]ed (copying|use|distribution|reproduction)", re.I)
# Also used in ordinary prose and templates ("Under review by ICML. Do not distribute."): REVIEW, not HIGH.
RESTRICTIVE_PHRASES = re.compile(
    r"internal use only|(do not|may not be|must not be) (copied|distributed|redistributed|disclosed)|"
    r"do not (copy|distribute|redistribute)\b", re.I)


def classify_offline(c):
    if c.spdx:
        expr = " AND ".join(f"({e})" if " " in e else e for e in c.spdx)
        return Classification(expr, catalogue.expression_category(expr), "spdx")
    if c.fingerprints:
        cats = [catalogue.category_of(f) for f in c.fingerprints]
        if len(c.fingerprints) > 1 and catalogue.is_dual(c.text):
            return Classification(" OR ".join(c.fingerprints), min(cats, key=catalogue.rank), "fingerprint",
                                  reasons=["dual-licensed; using the least restrictive option"])
        cl = Classification(" AND ".join(c.fingerprints), max(cats, key=catalogue.rank), "fingerprint")
        if len(c.fingerprints) > 1:
            cl.needs_review = True
            cl.reasons.append("several licences in one text; using the most restrictive")
        return cl
    licence_words = re.search(r"licen[cs]|permission|permitted", c.text, re.I)
    # Only with a copyright notice: "unauthorized access" or "must not be distributed" also appear in prose.
    if PROPRIETARY_PHRASES.search(c.text) and re.search(r"copyright|©|\(c\) \d{4}", c.text, re.I):
        return Classification(catalogue.PROPRIETARY, "proprietary", "regex", needs_review=True,
                              reasons=["explicit proprietary/confidential wording"])
    if RESTRICTIVE_PHRASES.search(c.text) and re.search(r"copyright|©|\(c\) \d{4}", c.text, re.I):
        return Classification("restrictive-notice", "unknown", "regex", needs_review=True,
                              reasons=["copyright plus 'do not distribute'-style wording"])
    if not licence_words and re.search(r"all rights reserved", c.text, re.I):
        return Classification("all-rights-reserved", "unknown", "regex", needs_review=True,
                              reasons=["'All rights reserved' with no licence grant in this text"])
    if not licence_words and re.search(r"copyright|©", c.text, re.I):
        return Classification(catalogue.NONE, "unknown", "regex", notice_only=True,
                              reasons=["copyright notice with no licence terms"])
    return Classification(catalogue.OTHER, "unknown", "regex", needs_review=True,
                          reasons=["licence-like text not recognised; needs Jev or a human"])


def _milder(category, than):
    return category == "unknown" or catalogue.rank(category) < catalogue.rank(than)


def classify_with_jev(c, response):
    """Return a Classification, or None when Jev says the text is not about licensing."""
    a = response["answers"]
    p_lic = a["is_licence"]["noul"]
    lid, conf = a["licence_id"]["choice"], a["licence_id"]["confidence"]
    if p_lic < NOT_LICENCE_BELOW and not c.fingerprints:
        return None

    cl = Classification(lid, catalogue.category_of(lid), "jev", conf, jev_model=response.get("model"))

    def unsure(reason):
        cl.needs_review = cl.uncertain = True
        cl.reasons.append(reason)

    if p_lic < LICENCE_SURE_ABOVE:
        unsure(f"unsure this is licence text (p={p_lic:.2f})")

    if lid in catalogue.LICENCES:
        # Overlapping options (GPL vs GPL-2.0) split the probability while the category is
        # still clear, so judge certainty on the total probability of the chosen category.
        p_cat = sum(p for o, p in a["licence_id"].get("probabilities", {}).items()
                    if o in catalogue.LICENCES and catalogue.category_of(o) == cl.category)
        if conf < MIN_CONFIDENCE and p_cat < MIN_CONFIDENCE:
            unsure(f"low licence confidence ({conf:.2f}; category probability {p_cat:.2f})")
        fp_cats = {catalogue.category_of(f) for f in c.fingerprints}
        if fp_cats and cl.category not in fp_cats:
            unsure(f"Jev says {lid}, fingerprint says {', '.join(c.fingerprints)}")
    elif lid == catalogue.NONE:
        cl.notice_only = True
    elif lid == catalogue.COPYRIGHT_ONLY:
        # Same treatment as the offline rules: a bare notice is covered by the project licence,
        # "All rights reserved" with no grant in sight is worth a human look.
        if re.search(r"all rights reserved", c.text, re.I):
            cl.licence_id, cl.category, cl.needs_review = "all-rights-reserved", "unknown", True
        else:
            cl.licence_id, cl.notice_only = catalogue.NONE, True
    else:  # other-custom or proprietary: the category and obligation flags are the useful part
        cl.flags = {k: round(a[k]["noul"], 2) for k in
                    ("restricts_commercial", "requires_source", "network_clause", "requires_attribution")}
        if lid == catalogue.PROPRIETARY:
            if conf < MIN_CONFIDENCE:
                unsure(f"low licence confidence ({conf:.2f})")
        else:
            cat = a["category"]
            cl.category = cat["choice"]
            flagged = any(v >= FLAG_YES for k, v in cl.flags.items() if k != "requires_attribution")
            if cat["confidence"] < MIN_CONFIDENCE and not flagged:
                unsure(f"low category confidence ({cat['confidence']:.2f})")
            # Policy in code: specific red flags override a milder overall category.
            if cl.flags["restricts_commercial"] >= FLAG_YES and _milder(cl.category, "non-commercial"):
                cl.reasons.append(f"custom terms restrict commercial use; category raised from {cl.category}")
                cl.category = "non-commercial"
            elif cl.flags["network_clause"] >= FLAG_YES and _milder(cl.category, "network-copyleft"):
                cl.reasons.append(f"custom terms have a network clause; category raised from {cl.category}")
                cl.category = "network-copyleft"
            elif cl.flags["requires_source"] >= FLAG_YES and _milder(cl.category, "strong-copyleft"):
                cl.reasons.append(f"custom terms require source disclosure; category raised from {cl.category}")
                cl.category = "strong-copyleft"
            cl.needs_review = True
            cl.reasons.append("custom licence: a human should read it once")
    return cl
