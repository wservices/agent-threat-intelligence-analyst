"""Behavior tests for stix_ioc_extract.py — parse a STIX 2.x bundle."""
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("stix_ioc_extract", ROOT / "scripts" / "stix_ioc_extract.py")
mod = importlib.util.module_from_spec(spec)
sys.modules["stix_ioc_extract"] = mod
spec.loader.exec_module(mod)

BUNDLE = {
    "type": "bundle",
    "id": "bundle--0",
    "objects": [
        {"type": "indicator", "id": "indicator--a1", "name": "C2 domain",
         "pattern_type": "stix", "pattern": "[domain-name:value = 'evil.example']"},
        {"type": "indicator", "id": "indicator--a2", "name": "Dropper",
         "pattern": "[file:hashes.'SHA-256' = 'abc123']"},
        {"type": "malware", "id": "malware--m1", "name": "AgentTesla",
         "is_family": True, "malware_types": ["keylogger"]},
        {"type": "attack-pattern", "id": "attack-pattern--t1",
         "name": "Scripting", "external_references": [
             {"source_name": "mitre-attack", "external_id": "T1059"}]},
        {"type": "relationship", "id": "relationship--r1",
         "relationship_type": "indicates",
         "source_ref": "indicator--a1", "target_ref": "malware--m1"},
        {"type": "identity", "id": "identity--i1", "name": "Vendor"},
    ],
}


def test_counts_by_type():
    s = mod.summarize(BUNDLE)
    assert s["counts"] == {"indicators": 2, "malware": 1,
                           "attack_patterns": 1, "relationships": 1}


def test_pattern_values_extracted():
    vals = mod.extract_pattern_values("[file:hashes.'SHA-256' = 'abc123']")
    assert vals == [{"path": "file:hashes.'SHA-256'", "value": "abc123"}]
    s = mod.summarize(BUNDLE)
    domain_ind = next(i for i in s["indicators"] if i["name"] == "C2 domain")
    assert domain_ind["values"][0]["value"] == "evil.example"


def test_attack_pattern_external_id():
    s = mod.summarize(BUNDLE)
    assert s["attack_patterns"][0]["attack_id"] == "T1059"


def test_relationship_refs_resolved_to_names():
    s = mod.summarize(BUNDLE)
    rel = s["relationships"][0]
    assert rel["source_name"] == "C2 domain"
    assert rel["target_name"] == "AgentTesla"
    assert rel["relationship_type"] == "indicates"


def test_dangling_relationship_keeps_raw_id():
    bundle = {"objects": [
        {"type": "relationship", "id": "relationship--r9",
         "relationship_type": "uses",
         "source_ref": "malware--missing", "target_ref": "attack-pattern--missing"}]}
    s = mod.summarize(bundle)
    assert s["relationships"][0]["source_name"] == "malware--missing"


def test_bad_objects_field_raises():
    import pytest
    with pytest.raises(ValueError):
        mod.summarize({"objects": {"not": "a list"}})
