#!/usr/bin/env python3
"""Summarize a STIX 2.x bundle: indicators, malware, attack-patterns, relations.

Reads a STIX 2.0/2.1 bundle (JSON) that the analyst already exported from a feed
(MISP, OTX, TAXII, CTI repo) and lists:
  * indicator SDOs   — name, pattern, pattern_type, and the concrete values
                       pulled out of the STIX pattern (hashes/IPs/domains/URLs);
  * malware SDOs     — name, whether it is a family, malware_types;
  * attack-pattern SDOs — name and the MITRE ATT&CK external_id (Txxxx);
  * relationship SROs — resolved to "<source name> --type--> <target name>".

Purely offline and read-only: it parses the bundle as DATA and never executes,
fetches, or resolves anything the bundle references.

Usage:
  stix_ioc_extract.py bundle.json              # text summary
  stix_ioc_extract.py --json bundle.json        # structured JSON
  cat bundle.json | stix_ioc_extract.py --json  # stdin

Exit: 0 if the bundle parsed and held >=1 SDO, 1 if empty, 3 usage/parse error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys

# A STIX pattern comparison looks like:  file:hashes.'SHA-256' = 'ab12..'
# or [ipv4-addr:value = '198.51.100.23'].  Capture object-path and quoted value.
_PATTERN_TERM = re.compile(
    r"(?P<path>[a-z0-9_-]+:[A-Za-z0-9_.'\-\[\]]+)\s*=\s*'(?P<value>[^']*)'",
    re.IGNORECASE,
)


def extract_pattern_values(pattern: str) -> list:
    """Return [{'path':..., 'value':...}] parsed from a STIX comparison pattern."""
    out = []
    for m in _PATTERN_TERM.finditer(pattern or ""):
        out.append({"path": m.group("path").strip("[]"), "value": m.group("value")})
    return out


def _mitre_external_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []) or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"]
    return None


def summarize(bundle: dict) -> dict:
    """Build a typed summary of the SDOs/SROs in a parsed STIX bundle."""
    objects = bundle.get("objects", [])
    if not isinstance(objects, list):
        raise ValueError("STIX bundle 'objects' is not a list")

    by_id = {o.get("id"): o for o in objects if isinstance(o, dict) and o.get("id")}

    indicators, malware, attack_patterns, relationships = [], [], [], []
    for o in objects:
        if not isinstance(o, dict):
            continue
        otype = o.get("type")
        if otype == "indicator":
            indicators.append({
                "id": o.get("id"),
                "name": o.get("name"),
                "pattern_type": o.get("pattern_type", "stix"),
                "pattern": o.get("pattern"),
                "labels": o.get("labels") or o.get("indicator_types") or [],
                "values": extract_pattern_values(o.get("pattern", "")),
            })
        elif otype == "malware":
            indicators_types = o.get("malware_types") or o.get("labels") or []
            malware.append({
                "id": o.get("id"),
                "name": o.get("name"),
                "is_family": o.get("is_family"),
                "malware_types": indicators_types,
            })
        elif otype == "attack-pattern":
            attack_patterns.append({
                "id": o.get("id"),
                "name": o.get("name"),
                "attack_id": _mitre_external_id(o),
            })

    def _name(ref):
        obj = by_id.get(ref)
        if not obj:
            return ref  # dangling reference — keep the raw id
        return obj.get("name") or _mitre_external_id(obj) or ref

    for o in objects:
        if isinstance(o, dict) and o.get("type") == "relationship":
            relationships.append({
                "relationship_type": o.get("relationship_type"),
                "source_ref": o.get("source_ref"),
                "target_ref": o.get("target_ref"),
                "source_name": _name(o.get("source_ref")),
                "target_name": _name(o.get("target_ref")),
            })

    return {
        "counts": {
            "indicators": len(indicators),
            "malware": len(malware),
            "attack_patterns": len(attack_patterns),
            "relationships": len(relationships),
        },
        "indicators": indicators,
        "malware": malware,
        "attack_patterns": attack_patterns,
        "relationships": relationships,
    }


def _render_text(s: dict) -> str:
    lines = []
    c = s["counts"]
    lines.append(f"STIX bundle: {c['indicators']} indicator(s), {c['malware']} "
                 f"malware, {c['attack_patterns']} attack-pattern(s), "
                 f"{c['relationships']} relationship(s)")
    if s["indicators"]:
        lines.append("\nIndicators:")
        for i in s["indicators"]:
            vals = ", ".join(v["value"] for v in i["values"]) or "-"
            lines.append(f"  - {i.get('name') or i['id']}: {vals}")
    if s["malware"]:
        lines.append("\nMalware:")
        for m in s["malware"]:
            fam = "family" if m.get("is_family") else "instance"
            lines.append(f"  - {m.get('name')} ({fam})")
    if s["attack_patterns"]:
        lines.append("\nAttack patterns:")
        for a in s["attack_patterns"]:
            lines.append(f"  - {a.get('attack_id') or '?'}  {a.get('name')}")
    if s["relationships"]:
        lines.append("\nRelationships:")
        for r in s["relationships"]:
            lines.append(f"  - {r['source_name']} --{r['relationship_type']}--> "
                         f"{r['target_name']}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Summarize a STIX 2.x bundle")
    ap.add_argument("bundle", nargs="?", help="STIX bundle JSON; omit to read stdin")
    ap.add_argument("--json", action="store_true", help="emit JSON summary")
    args = ap.parse_args(argv)

    try:
        if args.bundle:
            with open(args.bundle, encoding="utf-8-sig") as f:
                data = json.load(f)
        else:
            data = json.loads(sys.stdin.read())
    except (OSError, json.JSONDecodeError) as e:
        print(f"error reading STIX bundle: {e}", file=sys.stderr)
        return 3

    if not isinstance(data, dict):
        print("error: STIX bundle is not a JSON object", file=sys.stderr)
        return 3

    try:
        summary = summarize(data)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3

    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print(_render_text(summary))

    total = sum(summary["counts"].values())
    return 0 if total else 1


if __name__ == "__main__":
    raise SystemExit(main())
