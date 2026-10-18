# Threat Intelligence Brief — <subject> (<intel-id>)

- Date (UTC): <YYYY-MM-DDThh:mm:ssZ>
- Analyst: threat-intelligence-analyst
- Scope / question: <what this brief answers>
- Distribution: Detection Engineer, Incident Responder, Security Team Lead
- Overall confidence: <high / medium / low>

> All indicators in this prose are **defanged**. The machine-readable package
> (`iocs.json` / `iocs.csv`) is the authoritative data artifact. This brief is
> advisory — it recommends; it takes no response action.

## Key Judgments

Bottom line up front. 3–5 judgments, each with confidence and the driving fact.

- **J1.** <judgment>. (Confidence: <high/medium/low>; driver: <single fact>.)
- **J2.** <judgment>. (Confidence: …; driver: ….)
- **J3.** <judgment>. (Confidence: …; driver: ….)

## Prioritized CVEs

| Rank | CVE | CVSS | EPSS | KEV | Exposed? | Why it ranks | Conf. |
|---|---|---|---|---|---|---|---|
| 1 | CVE-… | 9.8 | 0.94 | yes | yes | KEV + internet-facing product | high |
| 2 | CVE-… | 7.5 | 0.40 | no | yes | high EPSS on exposed product | med |

## Campaign / TTP Summary

- Family / campaign: <canonical name> (aliases: <…>)
- Capability / tooling: <loaders, malware, delivery>
- Targeting: <sectors / geos, reported vs. inferred>
- Narrative: <2–4 sentences, reporting separated from analysis>

## ATT&CK Mapping

| Tactic | Technique (ID) | Evidence basis | Confidence |
|---|---|---|---|
| Execution | <T1059.x name> (T1059.x) | observed in <source> | high |
| Persistence | <T1053.005 name> (T1053.005) | inferred from <source> | med |

ATT&CK version mapped against: <bundle date / version>.

## Indicators

Defanged summary; full set in `iocs.json` / `iocs.csv`. Count: <n> (must match
the package).

| Indicator (defanged) | Type | Disposition | Confidence | Source | Last seen |
|---|---|---|---|---|---|
| 1[.]2[.]3[.]4 | ip | malicious | high | VT, AbuseIPDB | <UTC> |
| evil[.]example | domain | suspicious | med | OTX | <UTC> |

## Confidence

- Scale: high / medium / low, per judgment and per indicator.
- Estimative language used throughout (likely / possible / unlikely).
- Known gaps / collection limits: <what could not be determined>.

## Sources

Every judgment and indicator cites at least one of these (stored response, report
URL + access date, feed name).

1. <source> — <URL or evidence path> — accessed <UTC>.
2. <source> — <URL or evidence path> — accessed <UTC>.

## Recommended next steps (advisory)

- Detection Engineer: <what to build from the IOC package / ATT&CK mapping>.
- Incident Responder: <context / hunt leads if active>.
- Escalation: <raise to Security Team Lead if KEV-on-exposed-asset / active
  targeting>.
