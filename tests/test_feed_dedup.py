"""Behavior tests for feed_dedup.py — merge, confidence, dates, age-out."""
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("feed_dedup", ROOT / "scripts" / "feed_dedup.py")
mod = importlib.util.module_from_spec(spec)
sys.modules["feed_dedup"] = mod
spec.loader.exec_module(mod)

ROWS = [
    {"type": "ip", "value": "198.51.100.23", "source": "OTX",
     "first_seen": "2026-09-01", "last_seen": "2026-10-10", "confidence": "medium"},
    {"type": "ip", "value": "198.51.100.23", "source": "AbuseIPDB",
     "first_seen": "2026-08-15", "last_seen": "2026-10-15T12:00:00Z", "confidence": 85},
    {"type": "domain", "value": "Evil.Example", "source": "OTX",
     "first_seen": "2026-08-01", "last_seen": "2026-10-01", "confidence": "low"},
    {"type": "ip", "value": "203.0.113.9", "source": "OTX",
     "first_seen": "2025-01-01", "last_seen": "2025-02-01", "confidence": "high"},
]


def test_conf_to_num_mapping():
    assert mod.conf_to_num("high") == 85.0
    assert mod.conf_to_num("medium") == 50.0
    assert mod.conf_to_num("low") == 15.0
    assert mod.conf_to_num(72) == 72.0
    assert mod.conf_to_num("30") == 30.0
    assert mod.conf_to_num("garbage") == 0.0


def test_merge_unions_sources_and_min_max_dates():
    merged = mod.merge(ROWS)
    recs, aged = mod.finalize(merged, now="2026-10-20")
    ip = next(r for r in recs if r["value"] == "198.51.100.23")
    assert sorted(ip["sources"]) == ["AbuseIPDB", "OTX"]
    assert ip["source_count"] == 2
    assert ip["first_seen"] == "2026-08-15"          # earliest kept
    assert ip["last_seen"] == "2026-10-15T12:00:00Z"  # latest kept
    assert ip["confidence"] == 85.0                   # max confidence


def test_merge_is_case_insensitive_on_value():
    rows = [
        {"type": "domain", "value": "Evil.Example", "source": "A", "confidence": "low"},
        {"type": "domain", "value": "evil.example", "source": "B", "confidence": "high"},
    ]
    recs, _ = mod.finalize(mod.merge(rows))
    assert len(recs) == 1
    assert recs[0]["confidence"] == 85.0
    assert sorted(recs[0]["sources"]) == ["A", "B"]


def test_age_out_drops_stale_last_seen():
    merged = mod.merge(ROWS)
    recs, aged = mod.finalize(merged, max_age_days=90, now="2026-10-20")
    values = {r["value"] for r in recs}
    assert "203.0.113.9" not in values  # last_seen 2025-02 -> aged out
    assert "198.51.100.23" in values
    assert aged == 1


def test_load_feed_json_and_csv(tmp_path):
    import json
    j = tmp_path / "a.json"
    j.write_text(json.dumps([{"type": "ip", "value": "1.2.3.4"}]), encoding="utf-8")
    c = tmp_path / "b.csv"
    c.write_text("type,value,source\nip,1.2.3.4,feedB\n", encoding="utf-8")
    assert mod.load_feed(str(j))[0]["value"] == "1.2.3.4"
    assert mod.load_feed(str(c))[0]["source"] == "feedB"
