#!/usr/bin/env python3
"""Licence scanner prototype: deterministic detection first, TypeSafe Jev for the rest.

  python3 licence_scan.py PROJECT                    # offline (default when TYPESAFE_API_KEY is unset)
  python3 licence_scan.py PROJECT --dry-run out.jsonl  # write the Jev requests + cost estimate, send nothing
  python3 licence_scan.py PROJECT --mock             # run the Jev code path against a regex mock
  TYPESAFE_API_KEY=... python3 licence_scan.py PROJECT --jev
"""

import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor

import catalogue
import extract
import jev
import policy


def parse_args(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("project")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--jev", action="store_true", help="ask TypeSafe Jev (needs TYPESAFE_API_KEY)")
    mode.add_argument("--mock", action="store_true", help="use the regex mock instead of the real API")
    mode.add_argument("--dry-run", metavar="JSONL", help="write the Jev requests to JSONL and estimate cost")
    ap.add_argument("--include-deps", action="store_true", help="also scan node_modules, vendor, third_party, ...")
    ap.add_argument("--jev-scope", choices=["unresolved", "no-spdx", "all"], default="unresolved",
                    help="which snippets go to Jev: only those code could not settle (default), "
                         "everything without an SPDX tag, or everything")
    ap.add_argument("--json", metavar="FILE", help="write the full report as JSON")
    ap.add_argument("--fail-on", choices=["HIGH", "MEDIUM", "REVIEW"], help="exit 1 if any finding is this severe")
    ap.add_argument("--show-info", action="store_true", help="list INFO findings too")
    ap.add_argument("--excerpts", action="store_true", help="store a short excerpt of each snippet in the JSON report")
    ap.add_argument("--workers", type=int, default=8)
    return ap.parse_args(argv)


def needs_jev(c, offline_cl, scope):
    if scope == "all":
        return True
    if scope == "no-spdx":
        return not c.spdx
    return offline_cl.source == "regex" and not offline_cl.notice_only or offline_cl.needs_review


def run(args):
    root = os.path.abspath(args.project)
    cands, stats = extract.scan(root, args.include_deps)
    declared = extract.declared_licences(root)

    offline = [jev.classify_offline(c) for c in cands]
    ask_jev = [needs_jev(c, cl, args.jev_scope) for c, cl in zip(cands, offline)]
    # One Jev request per distinct text: the same Apache header in 500 files costs one call.
    unique = {}
    for c, ask in zip(cands, ask_jev):
        if ask:
            unique.setdefault(c.digest, c)

    if args.dry_run:
        tokens = 0
        with open(args.dry_run, "w") as fh:
            for c in unique.values():
                req = jev.build_request(c)
                tokens += jev.estimate_tokens(req)
                fh.write(json.dumps({"file": c.path, "line": c.start_line, "request": req}) + "\n")
        print(f"{len(cands)} candidate snippets, {len(unique)} distinct needing Jev -> {args.dry_run}")
        print(f"~{tokens:,} input tokens, ~${tokens / 1e6 * jev.PRICE_PER_MTOK:.5f} at ${jev.PRICE_PER_MTOK}/Mtok")
        return 0

    client = None
    if args.jev:
        key = os.environ.get("TYPESAFE_API_KEY")
        if not key:
            sys.exit("--jev needs TYPESAFE_API_KEY (https://console.typesafe.ai/)")
        client = jev.JevClient(key)
    elif args.mock:
        client = jev.MockClient()

    answers, usage = {}, 0
    if client:
        def ask(item):
            digest, c = item
            try:
                return digest, client.ask(jev.build_request(c)), None
            except Exception as e:  # keep scanning; fall back to offline for this snippet
                return digest, None, str(e)
        with ThreadPoolExecutor(args.workers) as pool:
            for digest, resp, err in pool.map(ask, unique.items()):
                answers[digest] = resp or err
                if resp:
                    usage += resp.get("usage", {}).get("input_tokens", 0)

    # Raw answers, one entry per distinct snippet sent, kept for threshold tuning and audits.
    jev_log = []
    for digest, c in unique.items():
        resp = answers.get(digest)
        if resp is None:
            continue
        entry = {"digest": digest, "file": f"{c.path}:{c.start_line}"}
        if isinstance(resp, dict):
            entry.update(model=resp.get("model"), usage=resp.get("usage"), answers=resp.get("answers"))
        else:
            entry["error"] = resp
        jev_log.append(entry)

    classified = []  # (candidate, Classification)
    dropped = []
    for c, cl, ask in zip(cands, offline, ask_jev):
        resp = answers.get(c.digest) if ask else None
        if isinstance(resp, dict):
            cl = jev.classify_with_jev(c, resp)
            if cl is None:
                d = {"file": f"{c.path}:{c.start_line}", "digest": c.digest,
                     "is_licence": round(resp["answers"]["is_licence"]["noul"], 3)}
                if args.excerpts:
                    d["excerpt"] = catalogue.normalise(c.text)[:400]
                dropped.append(d)
                continue
        elif isinstance(resp, str):
            cl.reasons.append(f"Jev call failed: {resp}")
        classified.append((c, cl))

    root_files = {c.path for c in cands if c.kind == "licence-file" and os.sep not in c.path}
    root_cls = {c.path: cl for c, cl in classified if c.path in root_files}
    if not declared:  # fall back to what the root LICENSE file says
        declared = [(p, cl.licence_id) for p, cl in root_cls.items() if not cl.notice_only]
    proj_cat, proj_ids = policy.project_category(declared)

    findings = policy.project_findings(declared, root_cls)
    for c, cl in classified:
        new = policy.findings_for(c, cl, proj_cat, root_files)
        for f in new:
            f["digest"] = c.digest
            if cl.jev_model:
                f["jev_model"] = cl.jev_model
            if args.excerpts:
                f["excerpt"] = catalogue.normalise(c.text)[:400]
        findings.extend(new)
    findings.sort(key=lambda f: (policy.SEVERITY_ORDER[f["severity"]], f["file"]))

    report = {
        "project": root, "mode": "jev" if args.jev else "mock" if args.mock else "offline",
        "declared": declared, "project_category": proj_cat, "stats": stats,
        "candidates": len(cands), "jev_requests": len(answers), "jev_input_tokens": usage,
        "jev_errors": sum(isinstance(v, str) for v in answers.values()),
        "dropped_as_not_licence": len(dropped), "dropped": dropped, "findings": findings,
        "jev_log": jev_log,
    }
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(report, fh, indent=2)
    print_report(report, args.show_info)

    if args.fail_on:
        limit = policy.SEVERITY_ORDER[args.fail_on]
        return int(any(policy.SEVERITY_ORDER[f["severity"]] <= limit for f in findings))
    return 0


def print_report(r, show_info):
    s = r["stats"]
    print(f"Project: {r['project']}  [{r['mode']}]")
    print(f"Declared: {', '.join(f'{e} ({src})' for src, e in r['declared']) or 'nothing'}"
          f"  -> {r['project_category'] or 'unknown'}")
    print(f"Scanned {s['text_files']} text files ({s['skipped_binary_or_large']} binary/large skipped), "
          f"{r['candidates']} licence snippets", end="")
    if r["mode"] != "offline":
        print(f", {r['jev_requests']} Jev requests, {r['jev_input_tokens']:,} tokens, "
              f"{r['dropped_as_not_licence']} dropped as not-a-licence, {r['jev_errors']} failed", end="")
    print("\n")
    counts = {}
    for f in r["findings"]:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        if f["severity"] == "INFO" and not show_info:
            continue
        lic = f.get("licence", "")
        conf = f" conf={f['confidence']:.2f}" if f.get("confidence") is not None else ""
        print(f"  {f['severity']:<7} {f['file']:<45} {lic:<22} {f['message']}")
        for reason in f.get("reasons", []):
            print(f"  {'':<7} {'':<45} {'':<22} - {reason}{conf}")
            conf = ""
        if f.get("flags"):
            print(f"  {'':<7} {'':<45} {'':<22} flags: {f['flags']}")
    print("\n" + "  ".join(f"{k}: {counts.get(k, 0)}" for k in policy.SEVERITY_ORDER))


if __name__ == "__main__":
    sys.exit(run(parse_args(sys.argv[1:])))
