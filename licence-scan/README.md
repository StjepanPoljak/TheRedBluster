# licence-scan: prototype

Scans a project's text files for licence notices. Code classifies what it can on its own,
and [TypeSafe Jev](https://docs.typesafe.ai) classifies the rest. Policy rules then turn
each classification into a finding (HIGH / MEDIUM / REVIEW / INFO).

Python 3.11+, standard library only. **Not legal advice.** It flags things for a human to look at.

```sh
python3 licence_scan.py PROJECT                       # offline: regex/SPDX only (default)
python3 licence_scan.py PROJECT --dry-run req.jsonl   # write the exact Jev requests + cost, send nothing
python3 licence_scan.py PROJECT --mock                # run the Jev code path against a regex mock
TYPESAFE_API_KEY=... python3 licence_scan.py PROJECT --jev
#   --show-info  --json report.json  --fail-on HIGH  --include-deps  --jev-scope unresolved|no-spdx|all
python3 -m unittest -v                                # offline tests
```

`fixtures/demo-project` is a small project full of traps: GPL and AGPL headers, a custom
non-commercial snippet, a proprietary header, a vendored MPL library, a minified banner,
an Apache block buried mid-file, licence-key *code* that is not a licence, and a binary file.

## How it works

```
walk files ──► candidate snippets ──► deterministic layer ──► Jev (only what's left) ──► policy ──► report
 skip .git,      LICENSE/COPYING/...     SPDX tags                one request per          code, not model:
 binaries,       file header (60 ln)     ~32 licence fingerprints  distinct snippet,        category vs project
 >2MB, deps      embedded blocks         "/*! x | MIT */" banners  7 questions in parallel  licence → severity
                 keyword pre-filter      manifests (package.json,
                                         pyproject, Cargo, ...)
```

The design follows the TypeSafe guidance: code owns the workflow, and Jev answers narrow
typed questions. Exact things such as SPDX tags, known licence texts and manifest fields
are handled in code, because a model adds nothing there. Jev handles the semantic part,
where a regex can't tell what the text means.

### The Jev questions (`jev.py: build_questions`)

All are asked in **one request per snippet**. State is `{file_path, text}`.

| id | type | purpose |
|---|---|---|
| `is_licence` | Noul | Is this actually licence/copyright text, or code/docs that just say "license"? Filters false positives such as `check_license_key()`. |
| `licence_id` | Choice (36 options) | Which named licence: 32 licence ids plus `other-custom`, `proprietary`, `copyright-only` and `none`. |
| `category` | Choice (9 options) | permissive / weak / strong / network copyleft / source-available / non-commercial / proprietary / public-domain / unknown. |
| `restricts_commercial`, `requires_source`, `network_clause`, `requires_attribution` | Noul ×4 | What the terms oblige you to do. |

The last five are **speculative** (the fan-out pattern). Code reads them only when
`licence_id` is `other-custom` or `proprietary`, where the category and obligations are
the useful answer. Policy stays in code. For example, if a custom licence has
`restricts_commercial ≥ 0.7`, the scanner treats it as `non-commercial` whatever
category Jev picked. Jev is also cross-checked against the fingerprints, and a
disagreement goes to REVIEW.

### Cost (measured with `--dry-run`, at $0.042 / Mtok, input tokens only)

| project | snippets | sent to Jev (default scope) | est. cost |
|---|---|---|---|
| demo fixture | 11 | 3 | $0.00015 |
| `~/Develop/qemu` (12k text files, 36s scan) | 8,305 | 343 | **$0.023** |
| qemu, `--jev-scope all` | 8,305 | 8,227 | $0.56 |

By default (`unresolved`), only snippets the deterministic layer couldn't settle go to
Jev. On qemu that's 4% of them.

## What it can do

- Find licence text in LICENSE-type files, file headers, comment blocks deeper in a file,
  and minified-bundle banners.
- Parse SPDX tags, including `OR` (you may pick the least restrictive licence), `AND`
  (the most restrictive applies) and `WITH` exceptions.
- Recognise about 32 common licences by their text, picking the more specific one where
  texts overlap (AGPL before GPL, LGPL before GPL). A full licence text is identified by
  its title. Otherwise GPLv2 would read as LGPL, because GPLv2 mentions the Library GPL at the end.
- Note GPL "or later" wording in notices.
- Read the project's declared licence from package.json, pyproject, Cargo.toml,
  composer.json or setup.cfg, falling back to the root LICENSE file. Flag a mismatch
  between the two, or no licence at all.
- Flag copyleft code in a permissive or proprietary project, AGPL inside a GPL project,
  MPL/LGPL file-level obligations, non-commercial or source-available terms, and
  "All rights reserved" with no licence grant. The last one found a real case in qemu:
  `include/crypto/desrfb.h`.
- **With Jev (tested live on 10 repos):**
  - Throw out false positives.
  - Classify custom or rare licences and paraphrased notices ("This work is licensed
    under the terms of the GNU GPL…").
  - Pull out obligations as probabilities.
  - Send low-confidence answers to REVIEW instead of guessing.
- Run in CI with `--fail-on HIGH` and `--json`.

## Tested on 10 popular GitHub repos

See [`../repo-test/REPORT.md`](../repo-test/REPORT.md): linux, react, freeCodeCamp, openclaw
and six others, 233k text files in total, offline and with Jev on the same pinned commits.
- **Offline:** settles 99.3% of 91k snippets.
- **Jev:** cuts the remaining REVIEW from 587 to 132 for $0.06. All 4 HIGH findings
  were confirmed as true positives.
- **Question wording matters:** the first Jev run raised 94 false HIGHs because of how
  one Choice option was worded (see the report's "Lessons").

## What it can't do (yet, or ever)

**Limits of the prototype (fixable):**

- **The thresholds are guesses.** `NOT_LICENCE_BELOW=0.25`, `MIN_CONFIDENCE=0.6` and
  `FLAG_YES=0.7` need tuning on a labelled set (see next steps).
- **One licence per snippet.** A Choice picks one option, so a THIRD-PARTY-NOTICES file
  listing 40 licences gets squashed. Fix: split such files into sections, or ask one Noul
  per licence.
- **Choice option order bias.** Jev leans slightly toward the first option. The fix is
  to re-ask with the options shuffled when confidence is borderline.
- **Dependencies aren't resolved.** `node_modules` and similar are skipped by default
  (`--include-deps` scans them as files). Proper dependency scanning means reading
  lockfiles and looking up package metadata (npm, PyPI, crates.io). That's a different
  tool, and it's deterministic.
- **Deduplication is weak on real code.** Headers include author names and file
  descriptions, so qemu has 8,227 distinct snippets out of 8,305. Deduplicating on only
  the licence sentences would cut Jev calls further.
- **Most of the tokens are the questions, not the snippet.** The 7 questions (mostly the 36 licence descriptions)
  come to about 1.2k tokens per request.
- No on-disk cache between runs, and no SARIF output.

**Limits of the approach (inherent):**

- **The compatibility rules are a simplification.** Real compatibility depends on
  linking, distribution, versions and exceptions. For example, GPL-2.0-only and
  Apache-2.0 are incompatible, but this scanner doesn't model that. Treat the output as
  triage, not a verdict.
- **It can't tell where code came from.** A file copied from a GPL project with its
  header stripped looks clean. That needs code-similarity search, such as ScanCode's
  matching or snippet fingerprinting.
- **It can't tell whether the project owner wrote a file.** "Copyright 2019 Someone
  Else" in your MIT repo may be fine, or may be vendored code. Deciding that requires
  comparing copyright holders. That's possible, but asking Jev "is this someone else's
  code?" is the kind of multi-step question its docs warn against.
- **Jev is text-only and reads literally** (see the
  [jev-1.13 known weaknesses](https://docs.typesafe.ai/model-jaggedness/jev-1.13.md)).
  A snippet that argues for its own classification ("this is basically MIT") can sway
  it. Its answers are always well-formed, but they can still be wrong.
- **Context limit:** 32k tokens for state plus the longest question. Snippets are capped
  at 24k characters (the head plus 2k of the tail), so very long custom licences are truncated.
- Mostly English. Images and PDFs of licences are ignored.
- Jev doesn't generate text, so it can't explain *why* it chose a licence. The reasons
  in the report come from code.

## Next steps once there's credit

1. `--dry-run` on the demo, paste 2–3 requests into the Playground, confirm the response shape.
2. Run `--jev` on `fixtures/demo-project`, then on qemu with the default scope
   (343 requests, about 2 cents).
3. Build a labelled set: take qemu's and the Linux kernel's SPDX-tagged files, remove
   the tags, and use the tags as ground truth. That gives thousands of free labels for
   tuning thresholds and measuring Jev's accuracy against the fingerprints.
4. Then: split multi-licence files, add an option-order check, a disk cache, SARIF
   output, and a lockfile-based dependency scan.

## Files

- `licence_scan.py`: command-line interface and orchestration
- `extract.py`: file walk, binary detection, snippet extraction, manifests
- `catalogue.py`: licence list, categories, fingerprints, SPDX parsing
- `jev.py`: questions, HTTP client with retry/backoff, mock client, answer interpretation
- `policy.py`: findings and severities
- `test_licence_scan.py`: tests and `fixtures/demo-project`
