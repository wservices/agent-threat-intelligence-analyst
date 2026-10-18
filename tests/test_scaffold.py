"""Offline scaffold smoke test for the threat-intelligence-analyst profile.

Validates, with no network and stdlib + PyYAML only:
  * distribution.yaml parses and carries the required manifest fields;
  * every skills/*/SKILL.md has valid frontmatter (description <=60 chars ending
    with a period, semver version, platforms subset of {linux,macos,windows});
  * every SKILL.md body has the 7 required section headings, in order.
"""
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SLUG = "threat-intelligence-analyst"
SEMVER = re.compile(r"^\d+\.\d+\.\d+$")
VALID_PLATFORMS = {"linux", "macos", "windows"}
REQUIRED_SECTIONS = [
    "## When to Use",
    "## Prerequisites",
    "## How to Run",
    "## Quick Reference",
    "## Procedure",
    "## Pitfalls",
    "## Verification",
]
SKILL_FILES = sorted((ROOT / "skills").glob("*/SKILL.md"))


def _frontmatter(text: str) -> dict:
    """Return the YAML frontmatter mapping between the first two '---' fences."""
    assert text.startswith("---\n"), "SKILL.md must start with a '---' frontmatter fence"
    end = text.index("\n---", 4)
    return yaml.safe_load(text[4:end])


def test_distribution_parses_and_has_required_fields():
    manifest = yaml.safe_load((ROOT / "distribution.yaml").read_text(encoding="utf-8"))
    for field in ("name", "version", "description", "hermes_requires", "author", "license"):
        assert manifest.get(field), f"distribution.yaml missing required field: {field}"
    assert manifest["name"] == SLUG
    assert SEMVER.match(str(manifest["version"])), "version must be semver"
    assert isinstance(manifest.get("env_requires"), list) and manifest["env_requires"], "env_requires must be a non-empty list"
    assert isinstance(manifest.get("distribution_owned"), list) and manifest["distribution_owned"]


def test_env_requires_entries_well_formed():
    manifest = yaml.safe_load((ROOT / "distribution.yaml").read_text(encoding="utf-8"))
    for entry in manifest["env_requires"]:
        assert entry.get("name"), "each env_requires entry needs a name"
        assert "required" in entry, f"{entry.get('name')} must declare 'required'"
        assert entry.get("description"), f"{entry.get('name')} must have a description"


def test_skills_present():
    assert SKILL_FILES, "no skills/*/SKILL.md found"


@pytest.mark.parametrize("skill_path", SKILL_FILES, ids=lambda p: p.parent.name)
def test_skill_frontmatter(skill_path):
    fm = _frontmatter(skill_path.read_text(encoding="utf-8"))
    # name matches its directory
    assert fm.get("name") == skill_path.parent.name
    # description: <=60 chars, ends with a period
    desc = fm.get("description", "")
    assert isinstance(desc, str) and desc, "description required"
    assert len(desc) <= 60, f"description >60 chars ({len(desc)}): {desc!r}"
    assert desc.endswith("."), f"description must end with a period: {desc!r}"
    # version: semver
    assert SEMVER.match(str(fm.get("version", ""))), "skill version must be semver"
    # platforms: subset of allowed
    platforms = fm.get("platforms")
    assert isinstance(platforms, list) and platforms, "platforms must be a non-empty list"
    assert set(platforms) <= VALID_PLATFORMS, f"invalid platforms: {platforms}"
    # metadata.hermes.tags / related_skills present
    hermes = (fm.get("metadata") or {}).get("hermes") or {}
    assert isinstance(hermes.get("tags"), list) and hermes["tags"], "metadata.hermes.tags required"
    assert "related_skills" in hermes, "metadata.hermes.related_skills required"


@pytest.mark.parametrize("skill_path", SKILL_FILES, ids=lambda p: p.parent.name)
def test_skill_sections_in_order(skill_path):
    lines = skill_path.read_text(encoding="utf-8").splitlines()
    positions = []
    for section in REQUIRED_SECTIONS:
        matches = [i for i, ln in enumerate(lines) if ln.strip() == section]
        assert matches, f"{skill_path.parent.name}: missing section {section!r}"
        positions.append(matches[0])
    assert positions == sorted(positions), (
        f"{skill_path.parent.name}: required sections out of order: {positions}"
    )
