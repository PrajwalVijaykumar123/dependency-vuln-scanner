#!/usr/bin/env python3
"""
Dependency Vulnerability Scanner

Checks every pinned package in a requirements.txt against the OSV.dev
vulnerability database (the same open database GitHub's Dependabot and
pip-audit draw from) and reports known CVEs/GHSAs - a lightweight,
from-scratch software composition analysis (SCA) tool.

Usage:
    python3 scanner.py requirements.txt
    python3 scanner.py requirements.txt --json report.json
    python3 scanner.py requirements.txt --api-base http://127.0.0.1:8085  (used by tests)
"""

import sys
import json
import argparse

import requests

from parser import parse_requirements
from osv_client import query_batch, get_vuln_details, summarize_severity, DEFAULT_API_BASE

SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def scan(requirements_path, api_base=DEFAULT_API_BASE):
    packages, skipped = parse_requirements(requirements_path)
    if not packages:
        return {"packages": [], "skipped": skipped, "errors": []}

    errors = []
    try:
        vuln_ids_by_package = query_batch(packages, api_base=api_base)
    except requests.RequestException as e:
        return {"packages": [], "skipped": skipped, "errors": [f"OSV batch query failed: {e}"]}

    package_reports = []
    for (name, version) in packages:
        vuln_ids = vuln_ids_by_package.get((name, version), [])
        vulns = []
        for vid in vuln_ids:
            try:
                record = get_vuln_details(vid, api_base=api_base)
                vulns.append({
                    "id": vid,
                    "summary": record.get("summary", "(no summary provided)"),
                    "severity": summarize_severity(record),
                    "aliases": record.get("aliases", []),
                })
            except requests.RequestException as e:
                errors.append(f"Failed to fetch details for {vid}: {e}")
                vulns.append({"id": vid, "summary": "(details unavailable)", "severity": "UNKNOWN", "aliases": []})

        vulns.sort(key=lambda v: SEVERITY_RANK.get(str(v["severity"]).upper().split("/")[0], 0), reverse=True)
        package_reports.append({"name": name, "version": version, "vulnerabilities": vulns})

    return {"packages": package_reports, "skipped": skipped, "errors": errors}


def worst_severity(package_reports):
    rank = 0
    label = None
    for pkg in package_reports:
        for v in pkg["vulnerabilities"]:
            sev = str(v["severity"]).upper()
            base = sev.split("/")[0] if "/" in sev else sev  # CVSS vector strings aren't rankable; treat as UNKNOWN
            base = base if base in SEVERITY_RANK else "UNKNOWN"
            if SEVERITY_RANK[base] > rank:
                rank = SEVERITY_RANK[base]
                label = base
    return label


def print_report(result):
    vulnerable = [p for p in result["packages"] if p["vulnerabilities"]]
    clean = [p for p in result["packages"] if not p["vulnerabilities"]]

    print(f"\nScanned {len(result['packages'])} pinned package(s).")

    if vulnerable:
        print(f"\n{len(vulnerable)} package(s) with known vulnerabilities:\n")
        for pkg in vulnerable:
            print(f"  {pkg['name']}=={pkg['version']}  ({len(pkg['vulnerabilities'])} finding(s))")
            for v in pkg["vulnerabilities"]:
                aliases = f" (aka {', '.join(v['aliases'])})" if v["aliases"] else ""
                print(f"    [{v['severity']}] {v['id']}{aliases}")
                print(f"        {v['summary']}")
            print()

    if clean:
        names = ", ".join(f"{p['name']}=={p['version']}" for p in clean)
        print(f"{len(clean)} package(s) with no known vulnerabilities: {names}")

    if result["skipped"]:
        print(f"\n{len(result['skipped'])} line(s) skipped (not an exact-version pin OSV can check):")
        for line, reason in result["skipped"]:
            print(f"    {line!r} - {reason}")

    for err in result["errors"]:
        print(f"\n[ERROR] {err}")


def main():
    parser = argparse.ArgumentParser(description="Scan a requirements.txt for known-vulnerable package versions via OSV.dev.")
    parser.add_argument("requirements", help="Path to a requirements.txt-style file")
    parser.add_argument("--api-base", default=DEFAULT_API_BASE, help="OSV API base URL (default: the real osv.dev API; tests point this at a local fixture server)")
    parser.add_argument("--json", metavar="FILE", help="Also write a JSON report to FILE")
    parser.add_argument("--fail-on", choices=["low", "moderate", "high", "critical", "any", "none"], default="any",
                         help="Minimum severity that causes a non-zero exit code (default: any finding at all)")
    args = parser.parse_args()

    result = scan(args.requirements, api_base=args.api_base)
    print_report(result)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\nJSON report written to {args.json}")

    if result["errors"] and not result["packages"]:
        sys.exit(2)

    if args.fail_on == "none":
        sys.exit(0)

    worst = worst_severity(result["packages"])
    if worst is None:
        sys.exit(0)
    if args.fail_on == "any":
        sys.exit(1)

    threshold_rank = SEVERITY_RANK.get(args.fail_on.upper(), 0)
    sys.exit(1 if SEVERITY_RANK.get(worst, 0) >= threshold_rank else 0)


if __name__ == "__main__":
    main()
