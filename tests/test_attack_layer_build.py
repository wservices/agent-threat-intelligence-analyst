"""Behavior tests for attack_layer_build.py — ID validation + Navigator layer."""
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("attack_layer_build", ROOT / "scripts" / "attack_layer_build.py")
mod = importlib.util.module_from_spec(spec)
sys.modules["attack_layer_build"] = mod
spec.loader.exec_module(mod)


def test_parse_spec_forms():
    assert mod.parse_spec("T1059") == ("T1059", None, None)
    assert mod.parse_spec("T1059.001,80") == ("T1059.001", 80.0, None)
    assert mod.parse_spec('T1566.001,40,"phishing"') == ("T1566.001", 40.0, "phishing")


def test_validate_ids_flags_malformed():
    specs = [("T1059", None, None), ("T99", None, None), ("TABCD", None, None),
             ("T1059.001", None, None)]
    assert mod.validate_ids(specs) == ["T99", "TABCD"]


def test_build_layer_structure_and_sort():
    layer = mod.build_layer([("T1566", None, None), ("T1059.001", 50.0, None)],
                            name="Camp")
    assert layer["name"] == "Camp"
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["layer"] == "4.5"
    ids = [t["techniqueID"] for t in layer["techniques"]]
    assert ids == ["T1059.001", "T1566"]  # sorted


def test_build_layer_merges_dup_keeps_max_score_and_comment():
    layer = mod.build_layer([
        ("T1059.001", 40.0, None),
        ("T1059.001", 80.0, "powershell"),
        ("T1059.001", 10.0, None),
    ])
    assert len(layer["techniques"]) == 1
    tech = layer["techniques"][0]
    assert tech["score"] == 80.0
    assert tech["comment"] == "powershell"


def test_main_exit_codes(tmp_path):
    out = tmp_path / "layer.json"
    assert mod.main(["T1059.001", "T1053.005", "-o", str(out)]) == 0
    import json
    layer = json.loads(out.read_text(encoding="utf-8"))
    assert len(layer["techniques"]) == 2
    assert mod.main(["T99"]) == 2       # malformed -> 2
    assert mod.main([]) == 3            # no input -> 3
