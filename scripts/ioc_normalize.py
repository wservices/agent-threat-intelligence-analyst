#!/usr/bin/env python3
"""Normalize indicators of compromise (IOCs) from mixed free text.

Reads report/alert text (files or stdin), **refangs** common obfuscations so a
pasted-in advisory is understood (``hxxp://evil[.]com`` -> ``http://evil.com``),
then extracts and classifies indicators by type (IPv4, domain, URL, email,
MD5/SHA1/SHA256), deduplicates them, and emits them **defanged by default** so a
report or downstream tool never accidentally resolves or visits an attacker
indicator (Security Policy §2).

All input is treated as untrusted DATA. The tool never executes, fetches, or
resolves anything — it only pattern-matches text. Read-only, offline, stdlib.

Usage:
  ioc_normalize.py advisory.txt                 # text summary, defanged
  cat alert.json | ioc_normalize.py --json      # JSON records on stdin
  ioc_normalize.py --csv report.md              # CSV (type,value)
  ioc_normalize.py --no-defang --json report.md # raw values (feed a tool)

Exit: 0 if any IOCs found, 1 if none, 3 usage/read error.
"""
from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import json
import re
import sys

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
URL_RE = re.compile(r"\bhttps?://[^\s\"'<>)\]]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
DOMAIN_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b"
)
MD5_RE = re.compile(r"\b[A-Fa-f0-9]{32}\b")
SHA1_RE = re.compile(r"\b[A-Fa-f0-9]{40}\b")
SHA256_RE = re.compile(r"\b[A-Fa-f0-9]{64}\b")

# Types in stable report order.
TYPES = ("ipv4", "domain", "url", "email", "md5", "sha1", "sha256")

# File extensions that match the domain regex but are not real domains.
_NON_DOMAIN_TLD = {
    "log", "txt", "json", "conf", "py", "sh", "md", "gz", "exe", "dll",
    "zip", "csv", "yaml", "yml", "pdf", "doc", "docx", "bin", "dat",
}

# Common defang notations -> their real character. Order matters: the longer /
# more specific markers are replaced before the shorter ones.
_REFANG = [
    (re.compile(r"hxxps", re.IGNORECASE), "https"),
    (re.compile(r"hxxp", re.IGNORECASE), "http"),
    (re.compile(r"\[://\]"), "://"),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[\.\]|\(\.\)|\[dot\]|\(dot\)", re.IGNORECASE), "."),
    (re.compile(r"\[at\]|\(at\)", re.IGNORECASE), "@"),
]


def refang(text: str) -> str:
    """Undo common IOC defanging so real indicators can be matched."""
    for pat, repl in _REFANG:
        text = pat.sub(repl, text)
    return text


def _valid_ipv4(s: str) -> bool:
    try:
        ipaddress.IPv4Address(s)
        return True
    except ValueError:
        return False


def _url_host(url: str) -> str:
    """Return the hostname of a URL without resolving or fetching it."""
    rest = re.sub(r"^https?://", "", url, flags=re.IGNORECASE)
    rest = rest.split("@")[-1]  # strip any userinfo
    host = re.split(r"[/?#]", rest, maxsplit=1)[0]
    return host.split(":")[0].lower()


def defang(kind: str, value: str) -> str:
    """Render an indicator inert for safe inclusion in a report."""
    if kind == "ipv4":
        return value.replace(".", "[.]")
    if kind == "url":
        return (value.replace("https://", "hxxps://").replace("http://", "hxxp://")
                .replace(".", "[.]"))
    if kind in ("domain", "email"):
        return value.replace(".", "[.]").replace("@", "[at]")
    return value  # hashes are safe as-is


def classify(text: str) -> dict:
    """Extract and type indicators from (already refanged) text; dedupe each type."""
    text = refang(text)

    sha256 = set(SHA256_RE.findall(text))
    sha1 = set(SHA1_RE.findall(text)) - sha256
    md5 = set(MD5_RE.findall(text)) - sha256 - sha1

    ipv4 = {ip for ip in IPV4_RE.findall(text) if _valid_ipv4(ip)}
    urls = set(URL_RE.findall(text))
    emails = set(EMAIL_RE.findall(text))

    # Hosts that already belong to a URL or an email are not standalone domains.
    url_hosts = {_url_host(u) for u in urls}
    email_hosts = {e.split("@", 1)[1].lower() for e in emails}

    domains = set()
    for d in DOMAIN_RE.findall(text):
        dl = d.lower()
        if dl.rsplit(".", 1)[-1] in _NON_DOMAIN_TLD:
            continue
        if _valid_ipv4(d):  # e.g. "1.2.3.4" also matches the domain regex
            continue
        if dl in url_hosts or dl in email_hosts:
            continue
        domains.add(d)

    return {
        "ipv4": sorted(ipv4),
        "domain": sorted(domains),
        "url": sorted(urls),
        "email": sorted(emails),
        "md5": sorted(md5),
        "sha1": sorted(sha1),
        "sha256": sorted(sha256),
    }


def to_records(grouped: dict, defang_values: bool = True) -> list:
    """Flatten the grouped indicators into typed, ordered records."""
    records = []
    for kind in TYPES:
        for value in grouped.get(kind, []):
            out = defang(kind, value) if defang_values else value
            records.append({"type": kind, "value": out})
    return records


def _read_inputs(files) -> str:
    if not files:
        return sys.stdin.read()
    chunks = []
    for p in files:
        with open(p, encoding="utf-8-sig", errors="replace") as f:
            chunks.append(f.read())
    return "\n".join(chunks)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Normalize + defang IOCs from text")
    ap.add_argument("files", nargs="*", help="input files; omit to read stdin")
    ap.add_argument("--json", action="store_true", help="emit JSON records")
    ap.add_argument("--csv", action="store_true", help="emit CSV (type,value)")
    ap.add_argument("--no-defang", action="store_true", help="emit raw indicators")
    args = ap.parse_args(argv)

    try:
        text = _read_inputs(args.files)
    except OSError as e:
        print(f"error reading input: {e}", file=sys.stderr)
        return 3

    grouped = classify(text)
    records = to_records(grouped, defang_values=not args.no_defang)

    if args.json:
        print(json.dumps(records, indent=2))
    elif args.csv:
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["type", "value"])
        for r in records:
            w.writerow([r["type"], r["value"]])
        sys.stdout.write(buf.getvalue())
    else:
        for kind in TYPES:
            vals = [r["value"] for r in records if r["type"] == kind]
            if vals:
                print(f"[{kind}] ({len(vals)})")
                for v in vals:
                    print(f"  {v}")
    return 0 if records else 1


if __name__ == "__main__":
    raise SystemExit(main())
