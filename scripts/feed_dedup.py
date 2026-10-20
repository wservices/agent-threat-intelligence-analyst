#!/usr/bin/env python3
"""Aggregate, deduplicate, and age-out IOCs across several threat-feed files.

Reads multiple already-exported feed files (JSON arrays and/or CSV with a
header), normalizes each row to one schema, and merges on ``(type, value)``:
  * sources are unioned and counted (multi-feed agreement is signal);
  * first_seen keeps the EARLIEST date, last_seen the LATEST;
  * confidence takes the MAX (numeric 0-100, or high/medium/low mapped to
    85/50/15), keeping the label that produced it;
  * with --max-age-days, indicators whose last_seen is older than the cutoff
    (relative to --now, default today UTC) are dropped.

Offline, read-only parsing — it never contacts the indicators themselves.

Usage:
  feed_dedup.py otx.json misp.csv blocklist.csv
  feed_dedup.py --max-age-days 90 --now 2026-10-20 *.json
  feed_dedup.py --csv feeds/*.json > merged.csv

Exit: 0 on success, 3 usage/parse error.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from datetime import datetime, timezone

_CONF_LABELS = {"high": 85.0, "medium": 50.0, "med": 50.0, "low": 15.0,
                "unknown": 0.0, "": 0.0}


def conf_to_num(value) -> float:
    """Map a confidence (number, numeric string, or label) to a 0-100 float."""
    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    s = str(value).strip().lower()
    if s in _CONF_LABELS:
        return _CONF_LABELS[s]
    try:
        return float(s)
    except ValueError:
        return 0.0


def parse_dt(value):
    """Parse an ISO date/datetime to a naive-UTC datetime, or None."""
    if not value:
        return None
    s = str(value).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _sources_of(row) -> list:
    srcs = row.get("sources")
    if isinstance(srcs, list):
        vals = srcs
    elif srcs:
        vals = [srcs]
    else:
        vals = []
    one = row.get("source")
    if one:
        vals = list(vals) + [one]
    return [str(s).strip() for s in vals if str(s).strip()]


def load_feed(path: str) -> list:
    """Load one feed file (JSON array or CSV with header) into a list of dicts."""
    with open(path, encoding="utf-8-sig") as f:
        text = f.read()
    if path.lower().endswith(".json"):
        data = json.loads(text)
        if not isinstance(data, list):
            raise ValueError(f"{path}: JSON feed must be an array of objects")
        return [r for r in data if isinstance(r, dict)]
    # CSV (default for anything non-.json)
    return list(csv.DictReader(io.StringIO(text)))


def merge(rows):
    """Merge normalized feed rows on (type, value). Returns a dict keyed by pair."""
    merged = {}
    for row in rows:
        rtype = str(row.get("type", "")).strip().lower()
        value = str(row.get("value", "")).strip()
        if not rtype or not value:
            continue
        key = (rtype, value.lower())
        cur = merged.get(key)
        conf_num = conf_to_num(row.get("confidence"))
        fs, ls = row.get("first_seen"), row.get("last_seen")
        if cur is None:
            merged[key] = {
                "type": rtype,
                "value": value,
                "sources": set(_sources_of(row)),
                "first_seen": fs,
                "last_seen": ls,
                "confidence": conf_num,
                "confidence_label": str(row.get("confidence", "")).strip(),
            }
            continue
        cur["sources"].update(_sources_of(row))
        if conf_num > cur["confidence"]:
            cur["confidence"] = conf_num
            cur["confidence_label"] = str(row.get("confidence", "")).strip()
        cur["first_seen"] = _earlier(cur["first_seen"], fs)
        cur["last_seen"] = _later(cur["last_seen"], ls)
    return merged


def _earlier(a, b):
    return _pick(a, b, want_min=True)


def _later(a, b):
    return _pick(a, b, want_min=False)


def _pick(a, b, want_min: bool):
    da, db = parse_dt(a), parse_dt(b)
    if da is None:
        return b if b else a
    if db is None:
        return a
    if want_min:
        return a if da <= db else b
    return a if da >= db else b


def finalize(merged, max_age_days=None, now=None):
    """Turn the merged map into sorted records, dropping aged-out indicators."""
    now_dt = parse_dt(now) if now else datetime.now(timezone.utc).replace(tzinfo=None)
    records, aged_out = [], 0
    for (_rtype, _val), v in merged.items():
        if max_age_days is not None:
            ls = parse_dt(v["last_seen"])
            if ls is not None and (now_dt - ls).days > max_age_days:
                aged_out += 1
                continue
        records.append({
            "type": v["type"],
            "value": v["value"],
            "sources": sorted(v["sources"]),
            "source_count": len(v["sources"]),
            "first_seen": v["first_seen"],
            "last_seen": v["last_seen"],
            "confidence": v["confidence"],
            "confidence_label": v["confidence_label"],
        })
    records.sort(key=lambda r: (r["type"], r["value"].lower()))
    return records, aged_out


def _to_csv(records) -> str:
    buf = io.StringIO()
    cols = ["type", "value", "sources", "source_count", "first_seen",
            "last_seen", "confidence", "confidence_label"]
    w = csv.writer(buf)
    w.writerow(cols)
    for r in records:
        w.writerow([r["type"], r["value"], ";".join(r["sources"]),
                    r["source_count"], r["first_seen"] or "", r["last_seen"] or "",
                    r["confidence"], r["confidence_label"]])
    return buf.getvalue()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Aggregate + dedupe + age-out feed IOCs")
    ap.add_argument("files", nargs="+", help="feed files (.json arrays or .csv)")
    ap.add_argument("--max-age-days", type=int, default=None,
                    help="drop indicators whose last_seen is older than this")
    ap.add_argument("--now", default=None,
                    help="reference date for age-out (ISO); default today UTC")
    ap.add_argument("--csv", action="store_true", help="emit CSV (default JSON)")
    args = ap.parse_args(argv)

    rows = []
    for p in args.files:
        try:
            rows.extend(load_feed(p))
        except (OSError, ValueError, json.JSONDecodeError) as e:
            print(f"error reading {p}: {e}", file=sys.stderr)
            return 3

    merged = merge(rows)
    records, aged_out = finalize(merged, max_age_days=args.max_age_days, now=args.now)

    print(f"merged {len(rows)} row(s) -> {len(records)} unique indicator(s); "
          f"aged out {aged_out}", file=sys.stderr)

    if args.csv:
        sys.stdout.write(_to_csv(records))
    else:
        print(json.dumps(records, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
