#!/usr/bin/env python3
"""Build a MITRE ATT&CK Navigator layer (JSON) from a list of technique IDs.

Takes technique IDs (as arguments or from a file, one spec per line), validates
each against the ``Txxxx`` / ``Txxxx.yyy`` format, **rejects malformed IDs**, and
emits a Navigator layer v4.5 document that the analyst can open in ATT&CK
Navigator to visualize a campaign's observed techniques.

Each spec is ``ID`` or ``ID,score`` or ``ID,score,comment``. Duplicate IDs are
merged, keeping the maximum score and the first non-empty comment.

Offline and side-effect-free: it only transforms the supplied ID list into a
layer document; it fetches no ATT&CK data and contacts no target.

Usage:
  attack_layer_build.py T1059.001 T1053.005 T1566
  attack_layer_build.py --input techniques.txt --name "APT-Example" -o layer.json
  attack_layer_build.py T1059.001,80 T1566.001,40,"phishing attachment"

Exit: 0 layer written, 2 one or more malformed IDs, 3 usage/read error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys

TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

LAYER_VERSIONS = {"attack": "14", "navigator": "4.9.1", "layer": "4.5"}
DEFAULT_GRADIENT = {
    "colors": ["#ffffff", "#ff6666"],
    "minValue": 0,
    "maxValue": 100,
}


def parse_spec(line: str):
    """Parse 'ID[,score[,comment]]' -> (id, score|None, comment|None).

    Raises ValueError if the ID part is missing.
    """
    parts = [p.strip() for p in line.split(",", 2)]
    tid = parts[0]
    if not tid:
        raise ValueError("empty technique spec")
    score = None
    comment = None
    if len(parts) >= 2 and parts[1] != "":
        try:
            score = float(parts[1])
        except ValueError:
            raise ValueError(f"score for {tid!r} is not a number: {parts[1]!r}")
    if len(parts) == 3 and parts[2] != "":
        comment = parts[2].strip('"').strip("'")
    return tid, score, comment


def validate_ids(specs):
    """Return the list of IDs that do NOT match the ATT&CK technique format."""
    return [tid for tid, _, _ in specs if not TECHNIQUE_RE.match(tid)]


def build_layer(specs, name="ATT&CK Layer", domain="enterprise-attack",
                description=""):
    """Build a Navigator layer dict from validated (id, score, comment) specs.

    Raises ValueError if any technique ID is malformed.
    """
    bad = validate_ids(specs)
    if bad:
        raise ValueError("malformed technique IDs: " + ", ".join(bad))

    merged = {}  # id -> {score, comment}
    for tid, score, comment in specs:
        entry = merged.setdefault(tid, {"score": None, "comment": None})
        if score is not None:
            if entry["score"] is None or score > entry["score"]:
                entry["score"] = score
        if comment and not entry["comment"]:
            entry["comment"] = comment

    techniques = []
    for tid in sorted(merged):
        entry = merged[tid]
        tech = {"techniqueID": tid, "enabled": True}
        if entry["score"] is not None:
            tech["score"] = entry["score"]
        if entry["comment"]:
            tech["comment"] = entry["comment"]
        techniques.append(tech)

    return {
        "name": name,
        "versions": LAYER_VERSIONS,
        "domain": domain,
        "description": description,
        "techniques": techniques,
        "gradient": DEFAULT_GRADIENT,
        "legendItems": [],
        "hideDisabled": False,
    }


def _read_input_file(path: str):
    specs = []
    with open(path, encoding="utf-8-sig") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            specs.append(parse_spec(line))
    return specs


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Build a MITRE ATT&CK Navigator layer")
    ap.add_argument("techniques", nargs="*", help="technique specs: ID[,score[,comment]]")
    ap.add_argument("--input", help="file of technique specs, one per line")
    ap.add_argument("--name", default="ATT&CK Layer", help="layer name")
    ap.add_argument("--domain", default="enterprise-attack", help="ATT&CK domain")
    ap.add_argument("--description", default="", help="layer description")
    ap.add_argument("-o", "--output", help="write layer JSON here (default stdout)")
    args = ap.parse_args(argv)

    specs = []
    try:
        if args.input:
            specs.extend(_read_input_file(args.input))
        for arg in args.techniques:
            specs.append(parse_spec(arg))
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 3

    if not specs:
        print("error: no technique IDs given (positional args or --input)",
              file=sys.stderr)
        return 3

    try:
        layer = build_layer(specs, name=args.name, domain=args.domain,
                            description=args.description)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    text = json.dumps(layer, indent=2)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(text + "\n")
        except OSError as e:
            print(f"error writing {args.output}: {e}", file=sys.stderr)
            return 3
        print(f"wrote {len(layer['techniques'])} technique(s) to {args.output}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
