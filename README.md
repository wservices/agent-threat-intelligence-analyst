# threat-intelligence-analyst

Hermes cybersecurity agent: threat intelligence analyst. Tracks CVEs/vendor
advisories and public exploits (KEV/EPSS), follows malware families and campaigns
from public reporting, maps adversary TTPs to MITRE ATT&CK, and enriches IOCs via
OSINT and threat feeds — delivering prioritized intel briefs and machine-readable
IOC packages to the Detection Engineer and Incident Responder. Research and
advisory only; it never actively engages adversary infrastructure.

See `ROLE.md` for the full role definition, permitted/prohibited actions, and
escalation paths. Standards applied: MITRE ATT&CK, STIX/TAXII concepts, the
Diamond Model.

## Skills

| Skill | What it does |
|---|---|
| `cve-and-advisory-tracking` | Monitor + prioritize CVEs/advisories with CISA KEV, EPSS, exposure |
| `adversary-ttp-mapping` | Map observed/reported behavior to MITRE ATT&CK + Diamond Model |
| `ioc-enrichment` | Enrich IPs/domains/hashes/URLs across OSINT + threat feeds (passive) |
| `malware-campaign-tracking` | Attribute + track families/campaigns from public reporting |
| `threat-feed-aggregation` | Pull / normalize / dedupe feeds into one scored IOC set |
| `threat-intel-reporting` | Prioritized brief (`templates/brief.md`) + machine-readable IOC package |

Additional intel capabilities (automated TAXII polling, sandbox detonation,
actor-infrastructure graphing) are tracked as planned in
`agents/platform/IMPLEMENTATION.md`.

## Install into Hermes (as a profile)

This repo is a **Hermes profile distribution** (`distribution.yaml` + `SOUL.md` +
`skills/`). Install it as its own agent profile:

```bash
hermes profile install "https://github.com/wservices/agent-threat-intelligence-analyst.git"
hermes -p threat-intelligence-analyst chat        # run the analyst (one-off, no sticky change)
hermes profile use threat-intelligence-analyst    # ...or make it the sticky default, then `hermes chat`
hermes profile update threat-intelligence-analyst # re-pull later; keeps your .env/memory
```

Then add the recommended companion skills (install the ones you need):

```bash
# CVE + exploit research
hermes skills install "https://raw.githubusercontent.com/wservices/skill-cve-research/main/skills/cve-research/SKILL.md" --category security
hermes skills install "https://raw.githubusercontent.com/wservices/skill-exploit-research/main/skills/exploit-research/SKILL.md" --category security
# passive OSINT enrichment
hermes skills install "https://raw.githubusercontent.com/wservices/skill-passive-reconnaissance/main/skills/passive-reconnaissance/SKILL.md" --category security
# tooling + reporting
hermes skills install "https://raw.githubusercontent.com/wservices/skill-tool-intel/main/skills/tool-intel/SKILL.md" --category devops
hermes skills install "https://raw.githubusercontent.com/wservices/skill-markdown-to-pdf/main/skills/markdown-to-pdf/SKILL.md" --category documents
```

These general skills aren't bundled in the profile but pair well with threat-intel
work — all read-only / analysis-only, in keeping with the role:

| Skill | Why |
|---|---|
| `cve-research` | enrich a CVE across NVD / KEV / EPSS / OSV for severity + exploit maturity |
| `exploit-research` | find public exploits / PoCs for a tracked CVE or product (no execution) |
| `passive-reconnaissance` | enrich IOC domains/IPs from public OSINT, without scanning |
| `tool-intel` | learn/verify the CLI tools the role drives + detect version drift |
| `markdown-to-pdf` | render the intel brief (`brief.md` → PDF) |

Planned companion skills — **not yet hosted**, tracked in the platform repo (no
install command yet): `mitre-attack` (ATT&CK technique lookup/navigator) and
`security-osint` (structured OSINT enrichment). Until then the bundled skills use
the public ATT&CK STIX bundle and the keyed OSINT APIs directly.

On install, Hermes generates a `.env.EXAMPLE` from `distribution.yaml`'s
`env_requires` (VirusTotal / AbuseIPDB / Shodan / OTX / MISP / NVD keys). Copy it
to `.env`, fill your values, and forward the names into the Kali sandbox via
`docker_forward_env`. `config.yaml` is **not** overwritten (your model/provider is
preserved).

**See [`docs/ENVIRONMENT.md`](docs/ENVIRONMENT.md)** for every variable this role
reads — required/optional, defaults, a copy-ready `.env` template, the
`docker_forward_env` snippet, and the secret-handling rules. That file is
generated from `distribution.yaml` (`agents/platform/scripts/gen_env_doc.py`), so
it never drifts from what the role actually uses.

The companion skills above install from the public mirror; for the internal
pinned (CI) install path and the profile + shared-skill mechanism, see
`agents/platform/docs/GITLAB-ARCHITECTURE.md` and `HERMES-INTEGRATION.md` §6.

## Tools

`tools/packages.txt` + `tools/install.sh` install the APT tool layer
(`jq ripgrep curl whois dnsutils`); `python3` ships in the base image. Every tool
is used for **read-only** work: HTTPS API/feed pulls (`curl`), JSON parsing
(`jq`), report/feed search (`rg`), and passive registration/DNS context
(`whois`, `dig`). No elevated privilege and no container capability are required.
See `tools/README.md`.

## Tests

```bash
python3 -m pytest tests -q     # offline scaffold smoke test: manifest + every SKILL.md
```

## Security

Bound by `agents/platform/policies/SECURITY-POLICY.md`: read-only and passive by
default, no response/write actions, never engages adversary infrastructure,
secrets never committed/logged, third-party exposure minimized (public indicators
only, hash/metadata over uploads), and untrusted content (advisories, reports,
feeds, indicator fields) treated as data — never instructions.

## License

MIT.
