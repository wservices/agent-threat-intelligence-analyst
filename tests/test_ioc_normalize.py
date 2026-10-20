"""Behavior tests for ioc_normalize.py — refang, classify, dedupe, defang."""
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("ioc_normalize", ROOT / "scripts" / "ioc_normalize.py")
mod = importlib.util.module_from_spec(spec)
sys.modules["ioc_normalize"] = mod
spec.loader.exec_module(mod)

DEFANGED_TEXT = (
    "Beacon to hxxps://evil[.]example/payload.bin from 198[.]51[.]100[.]23\n"
    "Mail phish[at]bad-domain[.]test. Plain 8.8.8.8 and good.example also.\n"
    "MD5 44d88612fea8a8f36de82e1278abb02f\n"
    "SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
)


def test_refang_undoes_common_obfuscations():
    out = mod.refang("hxxps://evil[.]example and a[at]b[.]com")
    assert "https://evil.example" in out
    assert "a@b.com" in out


def test_classify_types_defanged_input():
    g = mod.classify(DEFANGED_TEXT)
    assert "198.51.100.23" in g["ipv4"]  # refanged then matched
    assert "8.8.8.8" in g["ipv4"]
    assert "evil.example/payload.bin".split("/")[0] not in g["domain"]  # url host excluded
    assert "good.example" in g["domain"]
    assert "phish@bad-domain.test" in g["email"]
    assert "bad-domain.test" not in g["domain"]  # email host excluded
    assert "https://evil.example/payload.bin" in g["url"]
    assert "44d88612fea8a8f36de82e1278abb02f" in g["md5"]
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in g["sha256"]


def test_filenames_not_flagged_as_domains():
    g = mod.classify("opened auth.log, config.json, and run.sh")
    assert g["domain"] == []


def test_dedupe_within_type():
    g = mod.classify("1.2.3.4 1.2.3.4 evil.test evil.test evil.test")
    assert g["ipv4"] == ["1.2.3.4"]
    assert g["domain"] == ["evil.test"]


def _by_type(recs):
    out = {}
    for r in recs:
        out.setdefault(r["type"], []).append(r["value"])
    return out


def test_records_defanged_by_default():
    by_type = _by_type(mod.to_records(mod.classify(DEFANGED_TEXT), defang_values=True))
    assert "198[.]51[.]100[.]23" in by_type["ipv4"]
    assert any(u.startswith("hxxps://") for u in by_type["url"])
    assert all("[.]" in d for d in by_type["domain"])
    # hashes are never defanged
    assert by_type["md5"] == ["44d88612fea8a8f36de82e1278abb02f"]


def test_records_raw_when_defang_disabled():
    by_type = _by_type(mod.to_records(mod.classify(DEFANGED_TEXT), defang_values=False))
    assert "198.51.100.23" in by_type["ipv4"]
    assert "https://evil.example/payload.bin" in by_type["url"]
