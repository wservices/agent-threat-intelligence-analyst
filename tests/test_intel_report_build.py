"""Behavior tests for intel_report_build.py — Markdown rendering + defang."""
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("intel_report_build", ROOT / "scripts" / "intel_report_build.py")
mod = importlib.util.module_from_spec(spec)
sys.modules["intel_report_build"] = mod
spec.loader.exec_module(mod)

DATA = {
    "subject": "AgentTesla wave",
    "intel_id": "INTEL-2026-014",
    "overall_confidence": "medium",
    "key_judgments": [
        {"text": "Phishing wave targeting finance.", "confidence": "high",
         "driver": "three vendor reports"},
    ],
    "ttps": [
        {"tactic": "Execution", "technique": "Scripting", "id": "T1059.001",
         "basis": "observed", "confidence": "high"},
    ],
    "iocs": [
        {"value": "198.51.100.23", "type": "ip", "disposition": "malicious",
         "confidence": "high", "source": "VT", "last_seen": "2026-10-15"},
        {"value": "evil.example", "type": "domain", "disposition": "suspicious",
         "confidence": "medium", "source": "OTX", "last_seen": "2026-10-10"},
    ],
    "assessment": "Consistent across sources.",
    "recommendations": [
        {"audience": "Detection Engineer", "action": "Build a rule."},
        "Escalate if seen on an exposed asset.",
    ],
    "sources": ["VendorX - accessed 2026-10-18"],
}


def test_defang_values():
    assert mod.defang("198.51.100.23", "ip") == "198[.]51[.]100[.]23"
    assert mod.defang("http://evil.example", "url").startswith("hxxp://")
    assert mod.defang("a@b.com", "email") == "a[at]b[.]com"


def test_render_has_all_sections():
    md = mod.render(DATA)
    for heading in ("# Threat Intelligence Brief", "## Executive Summary",
                    "## ATT&CK / TTP Mapping", "## Indicators", "## Assessment",
                    "## Recommendations (advisory)", "## Sources"):
        assert heading in md


def test_render_defangs_ioc_table():
    md = mod.render(DATA)
    assert "198[.]51[.]100[.]23" in md
    assert "evil[.]example" in md
    assert "198.51.100.23" not in md  # raw value must not leak into prose


def test_render_key_judgments_recs_and_ttp_row():
    md = mod.render(DATA)
    assert "**J1.**" in md
    assert "three vendor reports" in md
    assert "T1059.001" in md
    assert "Count: 2" in md
    assert "- Detection Engineer: Build a rule." in md       # dict recommendation
    assert "- Escalate if seen on an exposed asset." in md   # string recommendation


def test_empty_sections_get_placeholders():
    md = mod.render({"subject": "bare"})
    assert "_No key judgments supplied._" in md
    assert "_No indicators._" in md
    assert "_No sources cited._" in md


def test_main_missing_subject_then_writes_output(tmp_path):
    import json
    bad = tmp_path / "bad.json"
    bad.write_text('{"intel_id": "X"}', encoding="utf-8")
    assert mod.main([str(bad)]) == 2  # missing required 'subject'
    good = tmp_path / "f.json"
    good.write_text(json.dumps(DATA), encoding="utf-8")
    out = tmp_path / "brief.md"
    assert mod.main([str(good), "-o", str(out)]) == 0
    assert "## Indicators" in out.read_text(encoding="utf-8")
