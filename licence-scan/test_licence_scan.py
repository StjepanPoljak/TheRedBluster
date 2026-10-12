"""Offline tests: python3 -m unittest -v (from this directory)."""

import os
import subprocess
import sys
import unittest

import catalogue
import extract
import jev
import policy

HERE = os.path.dirname(os.path.abspath(__file__))
DEMO = os.path.join(HERE, "fixtures", "demo-project")


def response(is_licence, licence_id, conf=0.9, category="unknown", cat_conf=0.9, probs=None, **flags):
    nouls = {k: {"type": "noul", "noul": flags.get(k, 0.05)} for k in
             ("restricts_commercial", "requires_source", "network_clause", "requires_attribution")}
    return {"model": "jev-test", "answers": {
        "is_licence": {"type": "noul", "noul": is_licence},
        "licence_id": {"type": "choice", "choice": licence_id, "confidence": conf, "probabilities": probs or {licence_id: conf}},
        "category": {"type": "choice", "choice": category, "confidence": cat_conf, "probabilities": {}},
        **nouls}}


class Fingerprints(unittest.TestCase):
    def test_family_specificity(self):
        self.assertEqual(catalogue.fingerprint("GNU Affero General Public License version 3"), ["AGPL-3.0"])
        self.assertEqual(catalogue.fingerprint("GNU Lesser General Public License, version 3"), ["LGPL-3.0"])
        self.assertEqual(catalogue.fingerprint(" * GNU General Public License\n * version 2"), ["GPL-2.0"])

    def test_full_text_title_wins(self):
        gpl2 = "GNU GENERAL PUBLIC LICENSE Version 2, June 1991 " + "terms " * 400 + \
               "consider it more useful to permit linking; use the GNU Library General Public License instead"
        self.assertEqual(catalogue.fingerprint(gpl2), ["GPL-2.0"])

    def test_gpl_shorthand(self):
        self.assertEqual(catalogue.fingerprint("licensed under the terms of the GNU GPL, version 2 or later"), ["GPL-2.0"])

    def test_banner(self):
        self.assertEqual(catalogue.fingerprint("/*! lib v1 | MIT */"), ["MIT"])

    def test_spdx_expressions(self):
        self.assertEqual(catalogue.expression_category("MIT OR GPL-3.0-only"), "permissive")
        self.assertEqual(catalogue.expression_category("MIT AND GPL-3.0-or-later"), "strong-copyleft")
        self.assertEqual(catalogue.expression_category("GPL-2.0-only WITH Classpath-exception-2.0"), "strong-copyleft")
        self.assertEqual(catalogue.expression_category("GPL-2.0 WITH Linux-syscall-note"), "strong-copyleft")
        self.assertEqual(catalogue.base_id("LicenseRef-Acme"), catalogue.OTHER)


class Offline(unittest.TestCase):
    def test_all_rights_reserved_with_licence_is_not_proprietary(self):
        c = extract.Candidate("x.c", "header", "Copyright 2022 Amazon. All Rights Reserved. "
                              "This work is licensed under the terms of the Foo licence.", 1)
        self.assertNotEqual(jev.classify_offline(c).category, "proprietary")


class RealWorldRegressions(unittest.TestCase):
    """Snippets (shortened) that the first 10-repo run misclassified. See ../repo-test/results/."""

    def classify(self, text, path="x.c"):
        c = extract.Candidate(path, "header", text, 1)
        c.fingerprints = catalogue.fingerprint(text)
        return jev.classify_offline(c)

    def test_react_short_mit_notice(self):
        cl = self.classify("Copyright (c) Meta Platforms, Inc. and affiliates. This source code is licensed "
                           "under the MIT license found in the LICENSE file in the root directory of this source tree.")
        self.assertEqual((cl.licence_id, cl.needs_review), ("MIT", False))

    def test_linux_unversioned_gpl(self):
        cl = self.classify("This file is subject to the terms and conditions of the GNU General Public "
                           "License. See the file \"COPYING\" in the main directory of this archive")
        self.assertEqual((cl.licence_id, cl.category), ("GPL", "strong-copyleft"))

    def test_linux_dual_gpl_x11(self):
        cl = self.classify("This file is dual-licensed: you can use it either under the terms of the GPL "
                           "or the X11 license, at your option. a) This library is free software; you can "
                           "redistribute it under the GNU General Public License version 2")
        self.assertEqual((cl.category, cl.needs_review), ("permissive", False))
        self.assertIn(" OR ", cl.licence_id)

    def test_mpl_secondary_licenses_are_not_gpl(self):
        text = ("Mozilla Public License Version 2.0 1.12. \"Secondary License\" means either the GNU General "
                "Public License, Version 2.0, the GNU Lesser General Public License, Version 2.1, the GNU Affero "
                "General Public License, Version 3.0, or any later versions of those licenses.")
        self.assertEqual(catalogue.fingerprint(text), ["MPL-2.0"])

    def test_cc_by_nc_sa_is_one_licence(self):
        self.assertEqual(catalogue.fingerprint("Creative Commons Attribution-NonCommercial-ShareAlike 4.0 "
                                               "International Public License"), ["CC-BY-NC-4.0"])

    def test_prose_about_proprietary_is_not_proprietary(self):
        cl = self.classify("Confidentiality tests focus on preventing leakage of training data or "
                           "proprietary model details. Copyright notice.")
        self.assertNotEqual(cl.category, "proprietary")

    def test_all_rights_reserved_alone_is_review_not_high(self):
        cl = self.classify("Copyright (c) 2017 Oracle and/or its affiliates. All rights reserved.")
        self.assertEqual((cl.licence_id, cl.category, cl.needs_review), ("all-rights-reserved", "unknown", True))

    def test_explicit_proprietary_still_flagged(self):
        cl = self.classify("Copyright 2025 MegaCorp. PROPRIETARY AND CONFIDENTIAL. Do not distribute.")
        self.assertEqual(cl.category, "proprietary")

    def test_lppl_natbib(self):
        self.assertEqual(catalogue.fingerprint("This program can be redistributed and/or modified under the terms "
                                               "of the LaTeX Project Public License Distributed from CTAN"), ["LPPL-1.3c"])

    def test_proprietary_words_in_prose_without_copyright(self):
        for text in ("This should reduce the chances of unauthorized access to our data.",
                     "The final versions must not be distributed before the camera-ready deadline."):
            self.assertNotEqual(self.classify(text).category, "proprietary")

    def test_icml_template_footer_is_review_not_proprietary(self):
        cl = self.classify("Under review by the International Conference on Machine Learning (ICML). Do not "
                           "distribute. Proceedings of the 43rd ICML. Copyright 2026 by the author(s).")
        self.assertEqual((cl.licence_id, cl.needs_review), ("restrictive-notice", True))

    def test_hpnd(self):
        self.assertEqual(catalogue.fingerprint("Permission to use, copy, modify, distribute, and sell this software "
                                               "and its documentation for any purpose is hereby granted"), ["HPND"])

    def test_alternatively_gpl_is_dual(self):
        cl = self.classify("Redistribution and use in source and binary forms, with or without modification, are "
                           "permitted provided that: Redistributions of source code must retain the above copyright "
                           "notice. Neither the name of Freescale nor the names of its contributors may be used to "
                           "endorse. ALTERNATIVELY, this software may be distributed under the terms of the GNU "
                           "General Public License (\"GPL\") as published by the Free Software Foundation")
        self.assertEqual((cl.category, cl.needs_review), ("permissive", False))

    def test_spdx_in_jinja_and_gfdl(self):
        self.assertEqual(catalogue.SPDX_TAG.findall("{# SPDX-License-Identifier: GPL-2.0 #}"), ["GPL-2.0"])
        self.assertEqual(catalogue.expression_category("GFDL-1.1-no-invariants-or-later"), "weak-copyleft")

    def test_ofl_fonts(self):
        self.assertEqual(catalogue.fingerprint("This Font Software is licensed under the SIL Open Font "
                                               "License, Version 1.1."), ["OFL-1.1"])

    def test_third_party_licences_dir_is_licence_file(self):
        cands = extract.candidates_for("/r", "/r/apps/THIRD_PARTY_LICENSES/x/DOMPurify.txt",
                                       "Mozilla Public License Version 2.0\n" + "terms\n" * 300)
        self.assertEqual(cands[0].kind, "licence-file")


class JevInterpretation(unittest.TestCase):
    def cand(self, text, fps=()):
        c = extract.Candidate("x.py", "header", text, 1)
        c.fingerprints = list(fps)
        return c

    def test_not_a_licence_is_dropped(self):
        self.assertIsNone(jev.classify_with_jev(self.cand("check_license_key()"), response(0.05, "none")))

    def test_custom_noncommercial_is_escalated(self):
        cl = jev.classify_with_jev(self.cand("personal use only"),
                                   response(0.9, "other-custom", category="permissive", restricts_commercial=0.92))
        self.assertEqual(cl.category, "non-commercial")
        self.assertTrue(cl.needs_review)

    def test_disagreement_with_fingerprint_needs_review(self):
        cl = jev.classify_with_jev(self.cand("...", ["GPL-3.0"]), response(0.95, "LGPL-3.0"))
        self.assertTrue(cl.needs_review)

    def test_confident_named_licence(self):
        cl = jev.classify_with_jev(self.cand("...", ["MIT"]), response(0.97, "MIT", conf=0.95))
        self.assertEqual((cl.licence_id, cl.category, cl.needs_review), ("MIT", "permissive", False))


class EndToEnd(unittest.TestCase):
    def test_demo_offline_and_mock(self):
        for mode in ([], ["--mock"]):
            out = subprocess.run([sys.executable, "licence_scan.py", DEMO, "--fail-on", "HIGH", *mode],
                                 cwd=HERE, capture_output=True, text=True)
            self.assertEqual(out.returncode, 1, out.stdout + out.stderr)
            for needle in ("src/parser.c", "src/server.go", "src/internal.ts"):
                self.assertIn(needle, out.stdout)


class JevRegressions(unittest.TestCase):
    """Cases from the first live Jev run over 10 repos (../repo-test/results-jev-v1)."""

    def cand(self, text, fps=()):
        c = extract.Candidate("x.c", "header", text, 1)
        c.fingerprints = list(fps)
        return c

    def severity(self, cl, proj="strong-copyleft"):
        c = self.cand("")
        return policy.findings_for(c, cl, proj, set())[0]["severity"]

    def test_all_rights_reserved_copyright_only_is_review(self):
        cl = jev.classify_with_jev(self.cand("Copyright (c) 2016 Oracle. All rights reserved."),
                                   response(0.9, "copyright-only", conf=0.9))
        self.assertEqual((cl.licence_id, self.severity(cl)), ("all-rights-reserved", "REVIEW"))

    def test_plain_copyright_only_is_notice(self):
        cl = jev.classify_with_jev(self.cand("Copyright 2012 Coraid, Inc. See COPYING for terms."),
                                   response(0.9, "copyright-only"))
        self.assertTrue(cl.notice_only)

    def test_gpl_vs_gpl2_split_is_not_uncertain(self):
        cl = jev.classify_with_jev(self.cand("Licensed under GPLv2"),
                                   response(0.95, "GPL-2.0", conf=0.35, probs={"GPL-2.0": 0.5, "GPL": 0.45, "MIT": 0.05}))
        self.assertFalse(cl.uncertain)

    def test_unsure_proprietary_is_review_not_high(self):
        cl = jev.classify_with_jev(self.cand("<p>© 2024 Fitness Dashboard. All Rights Reserved.</p>"),
                                   response(0.54, "proprietary", conf=0.67))
        self.assertEqual(self.severity(cl, "permissive"), "REVIEW")

    def test_confident_custom_noncommercial_stays_high(self):
        cl = jev.classify_with_jev(self.cand("Licence: PolyForm Noncommercial 1.0.0"),
                                   response(0.95, "other-custom", conf=0.8, category="non-commercial",
                                            cat_conf=0.5, restricts_commercial=0.96))
        self.assertEqual(self.severity(cl, "permissive"), "HIGH")

    def test_polyform_and_spdx_gaps(self):
        self.assertEqual(catalogue.fingerprint("Licence is PolyForm Noncommercial 1.0.0"),
                         ["PolyForm-Noncommercial-1.0.0"])
        self.assertEqual(catalogue.expression_category("GPL-2.0 or later"), "strong-copyleft")
        self.assertEqual(catalogue.expression_category("MIT."), "permissive")
        self.assertEqual(catalogue.expression_category("GPL-2.0 OR Linux-OpenIB"), "permissive")
        self.assertEqual(catalogue.expression_category("GPL-1.0+"), "strong-copyleft")


class ReportLogging(unittest.TestCase):
    def test_mock_report_has_raw_answers_and_dropped(self):
        import json, tempfile
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "r.json")
            subprocess.run([sys.executable, "licence_scan.py", DEMO, "--mock", "--excerpts", "--json", out],
                           cwd=HERE, capture_output=True, check=True)
            with open(out) as fh:
                r = json.load(fh)
        self.assertEqual(len(r["jev_log"]), r["jev_requests"])
        self.assertTrue(all("answers" in e and e["model"] == "mock" for e in r["jev_log"]))
        self.assertEqual(r["jev_errors"], 0)
        self.assertEqual([d["file"] for d in r["dropped"]], ["src/licensing.py:1"])
        self.assertTrue(any(f.get("jev_model") == "mock" for f in r["findings"]))


if __name__ == "__main__":
    unittest.main()
