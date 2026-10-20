#!/usr/bin/env python3
"""Assemble a structured Markdown threat-intel brief from a findings file.

Reads a findings file (YAML or JSON) the analyst has filled from the other
skills and renders a consistent Markdown brief with an executive summary (key
judgments), an ATT&CK/TTP table, a defanged IOC table, an assessment, and
recommendations. IOC values in the prose/table are **defanged** so the rendered
brief never carries a clickable attacker indicator (Security Policy §2).

This is a formatting step only: it creates no new findings, performs no lookups,
and takes no response action. Offline, read-only.

Findings schema (all sections optional except ``subject``):
  subject, intel_id, date, analyst, scope, overall_confidence, distribution
  key_judgments: [{text, confidence, driver}]
  ttps:          [{tactic, technique, id, basis, confidence}]
  iocs:          [{value, type, disposition, confidence, source, last_seen}]
  assessment:    <text>
  recommendations: [<text>]  or  [{audience, action}]
  sources:       [<text>]

Usage:
  intel_report_build.py findings.yaml
  intel_report_build.py findings.json -o brief.md

Exit: 0 report built, 2 missing required field, 3 usage/parse error.
"""
from __future__ import annotations

import argparse
import sys


def _load(path: str) -> dict:
    with open(path, encoding="utf-8-sig") as f:
        text = f.read()
    try:
        import yaml  # YAML is a JSON superset, so this parses both.
        data = yaml.safe_load(text)
    except ImportError:
        import json
        data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("findings file must be a mapping/object at the top level")
    return data


def defang(value: str, itype: str = "") -> str:
    """Render an IOC value inert for inclusion in the brief."""
    v = str(value)
    t = itype.lower()
    if t in ("url",):
        v = v.replace("https://", "hxxps://").replace("http://", "hxxp://")
    if t in ("ip", "ipv4", "ipv6", "domain", "url", "hostname", "email", ""):
        v = v.replace(".", "[.]")
    if t in ("email",) or "@" in v:
        v = v.replace("@", "[at]")
    return v


def _cell(text) -> str:
    """Escape a value for a Markdown table cell."""
    return str(text if text is not None else "").replace("|", "\\|").replace("\n", " ")


def _md_table(headers, rows) -> str:
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join(["---"] * len(headers)) + "|"]
    for r in rows:
        out.append("| " + " | ".join(_cell(c) for c in r) + " |")
    return "\n".join(out)


def _section(title: str, body: str) -> str:
    return f"## {title}\n\n{body}\n"


def render(data: dict) -> str:
    subject = data.get("subject")
    parts = [f"# Threat Intelligence Brief — {subject} "
             f"({data.get('intel_id', 'no-id')})", ""]

    meta = [
        f"- Date (UTC): {data.get('date', 'TBD')}",
        f"- Analyst: {data.get('analyst', 'threat-intelligence-analyst')}",
        f"- Scope / question: {data.get('scope', 'N/A')}",
        f"- Distribution: {data.get('distribution', 'Detection Engineer, Incident Responder, Security Team Lead')}",
        f"- Overall confidence: {data.get('overall_confidence', 'N/A')}",
    ]
    parts.append("\n".join(meta))
    parts.append("")
    parts.append("> All indicators in this brief are **defanged**. This brief is "
                 "advisory — it recommends; it takes no response action.")
    parts.append("")

    # Executive summary / key judgments
    kjs = data.get("key_judgments") or []
    if kjs:
        lines = []
        for i, kj in enumerate(kjs, 1):
            if isinstance(kj, dict):
                text = kj.get("text", "")
                conf = kj.get("confidence", "N/A")
                driver = kj.get("driver", "")
                lines.append(f"- **J{i}.** {text} (Confidence: {conf}; "
                             f"driver: {driver})")
            else:
                lines.append(f"- **J{i}.** {kj}")
        body = "\n".join(lines)
    else:
        body = "_No key judgments supplied._"
    parts.append(_section("Executive Summary", body))

    # TTP / ATT&CK table
    ttps = data.get("ttps") or []
    if ttps:
        rows = [[t.get("tactic", ""), t.get("technique", ""), t.get("id", ""),
                 t.get("basis", ""), t.get("confidence", "")] for t in ttps]
        body = _md_table(["Tactic", "Technique", "ATT&CK ID", "Basis", "Confidence"],
                         rows)
    else:
        body = "_No TTPs mapped._"
    parts.append(_section("ATT&CK / TTP Mapping", body))

    # IOC table (defanged)
    iocs = data.get("iocs") or []
    if iocs:
        rows = []
        for ioc in iocs:
            itype = ioc.get("type", "")
            rows.append([defang(ioc.get("value", ""), itype), itype,
                         ioc.get("disposition", ""), ioc.get("confidence", ""),
                         ioc.get("source", ""), ioc.get("last_seen", "")])
        body = (f"Count: {len(iocs)} (defanged).\n\n"
                + _md_table(["Indicator (defanged)", "Type", "Disposition",
                             "Confidence", "Source", "Last seen"], rows))
    else:
        body = "_No indicators._"
    parts.append(_section("Indicators", body))

    # Assessment
    parts.append(_section("Assessment",
                          data.get("assessment") or "_No assessment supplied._"))

    # Recommendations
    recs = data.get("recommendations") or []
    if recs:
        lines = []
        for r in recs:
            if isinstance(r, dict):
                lines.append(f"- {r.get('audience', 'All')}: {r.get('action', '')}")
            else:
                lines.append(f"- {r}")
        body = "\n".join(lines)
    else:
        body = "_No recommendations supplied._"
    parts.append(_section("Recommendations (advisory)", body))

    # Sources
    sources = data.get("sources") or []
    if sources:
        body = "\n".join(f"{i}. {s}" for i, s in enumerate(sources, 1))
    else:
        body = "_No sources cited._"
    parts.append(_section("Sources", body))

    return "\n".join(parts).rstrip() + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Build a Markdown threat-intel brief")
    ap.add_argument("findings", help="findings YAML or JSON file")
    ap.add_argument("-o", "--output", help="write Markdown here (default stdout)")
    args = ap.parse_args(argv)

    try:
        data = _load(args.findings)
    except (OSError, ValueError) as e:
        print(f"error reading findings: {e}", file=sys.stderr)
        return 3
    except Exception as e:  # YAML/JSON parse errors
        print(f"error parsing findings: {e}", file=sys.stderr)
        return 3

    if not data.get("subject"):
        print("error: findings file is missing required field: subject",
              file=sys.stderr)
        return 2

    report = render(data)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(report)
        except OSError as e:
            print(f"error writing {args.output}: {e}", file=sys.stderr)
            return 3
        print(f"wrote brief to {args.output}")
    else:
        sys.stdout.write(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
