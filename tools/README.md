# threat-intelligence-analyst tools

Every tool here is used **read-only**: outbound HTTPS pulls to CVE/advisory and
reputation/feed APIs, local JSON parsing, search over reports/feeds, and passive
DNS/registration lookups. Nothing scans, connects to, or interacts with the
indicators or adversary infrastructure being studied.

| Tool | Purpose | Source | Risk |
|---|---|---|---|
| jq | parse/filter JSON (feeds, NVD/EPSS/KEV, reputation APIs) | base image / apt | low |
| ripgrep (`rg`) | fast search over reports and feed files | base / apt | low |
| curl | read-only HTTPS GET/POST-search to keyed APIs + public feeds | base / apt | low (external query); never fetches indicator URLs |
| whois | domain/IP registration + ownership context | base / apt | low (external query) |
| dig (dnsutils) | DNS / passive-DNS context | base / apt | low (resolver query, not the target host) |
| python3 | normalize/deduplicate feeds, build IOC packages | base image | low (stdlib, offline) |

All are APT-installable on Kali Rolling; none requires pip, a binary download, or
a cloud CLI. `python3` ships in the shared base image. The keyed services
(VirusTotal, AbuseIPDB, Shodan, AlienVault OTX, MISP, NVD) are reached over HTTPS
with `curl` + the env-var API keys — see `docs/ENVIRONMENT.md`.

## Install

```bash
# with the shared installer (preferred)
SECURITY_TOOLING_DIR=/path/to/security-tooling bash tools/install.sh
# standalone fallback (apt only)
bash tools/install.sh
```

## Verify

```bash
# via the shared skill's verifier
bash /path/to/security-tooling/skills/security-tooling/scripts/verify_tools.sh --from-file tools/verify.txt
```

## Capabilities

No elevated privilege and **no container capability** are required — this role
performs only read-only outbound HTTPS lookups and local parsing. Never run
`--privileged`; there is no raw-socket or network-reconfiguration work here
(Security Policy §4). Egress is limited to the API/feed hosts the operator has
keyed; the role must never connect to the indicators themselves.
