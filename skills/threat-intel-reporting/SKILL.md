---
name: threat-intel-reporting
description: Write intel briefs and IOC packages.
version: 0.2.0
author: Pascal (pascal), Hermes Agent
license: MIT
platforms: [linux, macos]
prerequisites:
  commands: [jq, python3]
metadata:
  hermes:
    tags: [reporting, intel-brief, ioc-package, stix, handoff, prioritization]
    related_skills: [ioc-enrichment, threat-feed-aggregation, markdown-to-pdf]
---

# Threat Intel Reporting Skill

Assemble the role's deliverable: a prioritized, confidence-qualified intel brief
(`brief.md`) plus a machine-readable IOC package (STIX-style JSON and/or CSV)
that the Detection Engineer and Incident Responder can consume directly. It is a
synthesis-and-formatting step over work already produced by the other skills; it
creates no new findings and takes no response action.

## When to Use

- Turning tracked CVEs, a campaign profile, and an enriched IOC set into a brief.
- Producing a machine-readable IOC package for detection/response hand-off.
- Writing the recurring (e.g. weekly) threat brief.
- **Don't use for:** making the underlying judgments (those come from the
  tracking/enrichment skills), or authoring detections (Detection Engineer).

## Prerequisites

- `jq`, `python3` (stdlib). No network, no privilege, no keys.
- Inputs ready: the prioritized CVE watch list, TTP/campaign summaries, and the
  enriched + deduped IOC set (from the other skills).
- The brief template `templates/brief.md`.
- Optional: `markdown-to-pdf` (companion skill) to render `brief.md` → PDF.

## How to Run

Assemble the Markdown brief from a single findings file (YAML or JSON) with the
bundled offline builder. It renders the exec summary, ATT&CK/TTP table, a
**defanged** IOC table, assessment, and recommendations:
`terminal(command="python3 scripts/intel_report_build.py intel/<id>/findings.yaml -o intel/<id>/brief.md", timeout=30)`

Build the machine-readable IOC package from an enriched-IOC JSON array with `jq`
(no bundled script needed), then fill `templates/brief.md`:
`terminal(command="jq -r '.[] | [.value,.type,.disposition,.confidence,(.sources|join(\";\")),.last_seen] | @csv' intel/<id>/enriched.json > intel/<id>/iocs.csv", timeout=30)`

The STIX 2.1 bundle is one more `jq` pass (see Quick Reference). Render the brief
to PDF, when needed, with the `markdown-to-pdf` companion skill.

## Quick Reference

```
# enriched IOC array -> CSV (indicator,type,disposition,confidence,source,last_seen)
jq -r '.[] | [.value,.type,.disposition,.confidence,(.sources|join(";")),.last_seen] | @csv' enriched.json > iocs.csv
# enriched IOC array -> minimal STIX 2.1 bundle of indicator SDOs
jq '{type:"bundle", id:("bundle--"+(now|tostring)), objects:[ .[] | {type:"indicator", spec_version:"2.1", id:("indicator--"+(.value|@base64)), name:.value, pattern_type:"stix", pattern:("["+.type+":value = \x27"+.value+"\x27]"), confidence:(if .confidence=="high" then 85 elif .confidence=="medium" then 50 else 15 end), labels:[.disposition]} ]}' enriched.json > iocs.json
# count indicators by disposition for the brief summary
jq -r '.[].disposition' enriched.json | sort | uniq -c
# validate the brief has all required sections
rg -n '^## (Key Judgments|Prioritized CVEs|Campaign / TTP Summary|ATT&CK Mapping|Indicators|Confidence|Sources)' templates/brief.md
```

## Procedure

1. **Gather inputs + assign an intel ID.** Collect the CVE list, campaign/TTP
   summaries, and enriched IOC set into `intel/<id>/`. Completion: all inputs
   present and the ID chosen.
2. **Write key judgments first.** State the 3–5 bottom-line judgments up top, each
   with a confidence (high/medium/low) and the single driving fact — the reader
   acts on these. Completion: a BLUF section a busy responder can act on alone.
3. **Fill the body from the template.** Prioritized CVEs (KEV/EPSS/exposure),
   campaign/TTP summary, ATT&CK mapping table, and the indicator list (defanged
   in the prose). Completion: every `templates/brief.md` section filled or marked
   N/A with reason.
4. **Build the IOC package.** Emit `iocs.csv` and a STIX-style `iocs.json` with
   indicator, type, disposition, confidence, source(s), and first/last-seen.
   Indicators in the machine package may be raw (fanged) since it is a data file,
   but the brief prose stays defanged. Completion: both files validate (parse) and
   match the brief's indicator count.
5. **Attach provenance + confidence.** Every judgment and indicator cites a source
   (stored response / report URL + date) and carries a confidence. Completion: no
   unsourced claim remains.
6. **Route the deliverable.** IOC package → Detection Engineer; actor/campaign
   context during an incident → Incident Responder; KEV-on-exposed-asset or active
   targeting → escalate to the Security Team Lead. Produce a `handoff.yaml`
   (`HANDOFF-FORMAT.md`). Optionally render `brief.md` → PDF with
   `markdown-to-pdf`. Completion: deliverables stored and the correct hand-off
   created.

## Pitfalls

- **BLUF or it won't be read.** Lead with judgments and priorities; bury them and
  the brief fails its job.
- **Confidence is mandatory.** Unqualified claims read as fact — label observed /
  inferred / assumed and high/medium/low, and keep reporting separate from your
  own analysis.
- **Defang the prose, not necessarily the data file.** A raw URL in the narrative
  can be clicked; keep `brief.md` defanged. The machine IOC package is a data
  artifact consumed by tooling and may carry raw values — label it clearly.
- **Match the counts.** The indicator count in the brief must equal the IOC
  package size; a mismatch means something was dropped silently.
- **No action in the report.** The brief *recommends*; it never deploys a
  detection or a block. Those are downstream, human-approved steps.

## Verification

- Brief builder is offline-tested: `python3 -m pytest tests/test_intel_report_build.py -q`
  covers section rendering, IOC-table defang, placeholder handling, and the
  missing-`subject` error path (exit 2). It never emits a raw (fanged) indicator
  into the prose — the rendered table shows `1[.]2[.]3[.]4`, never `1.2.3.4`.
- `python3 -c "import json,sys; json.load(open('intel/<id>/iocs.json'))"` exits 0
  (valid JSON STIX bundle); `iocs.csv` opens with the expected header columns.
- The `rg` section check lists all required `brief.md` headings.
- Indicator count matches: `jq '.objects|length' iocs.json` equals the data rows
  in `iocs.csv` (`tail -n +1` count) equals the brief's stated indicator count.
- Every key judgment carries a confidence and at least one cited source.
