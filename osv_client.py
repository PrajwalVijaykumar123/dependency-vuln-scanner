"""
Thin client for the OSV.dev vulnerability database API
(https://osv.dev/docs/). Two calls:

  POST {api_base}/v1/querybatch   - given many (package, version) pairs,
                                     returns which vuln IDs affect each one
  GET  {api_base}/v1/vulns/{id}   - full details (summary, severity,
                                     aliases) for one vuln ID

querybatch deliberately returns only IDs (and a `modified` timestamp) to
keep batch responses small, so a second round of per-ID lookups is the
documented way to get the actual summary/severity - this mirrors OSV's
own API design, not an inefficiency added here.
"""

import requests

DEFAULT_API_BASE = "https://api.osv.dev"
BATCH_SIZE = 100  # OSV's documented limit per querybatch call


def query_batch(packages, api_base=DEFAULT_API_BASE, session=None, timeout=15):
    """packages: list of (name, version) tuples.
    Returns: dict mapping (name, version) -> list of vuln IDs."""
    session = session or requests.Session()
    results = {}

    for chunk_start in range(0, len(packages), BATCH_SIZE):
        chunk = packages[chunk_start:chunk_start + BATCH_SIZE]
        queries = [
            {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
            for name, version in chunk
        ]
        resp = session.post(f"{api_base}/v1/querybatch", json={"queries": queries}, timeout=timeout)
        resp.raise_for_status()
        body = resp.json()

        for (name, version), entry in zip(chunk, body.get("results", [])):
            vuln_ids = [v["id"] for v in entry.get("vulns", [])]
            results[(name, version)] = vuln_ids

    return results


def get_vuln_details(vuln_id, api_base=DEFAULT_API_BASE, session=None, timeout=15):
    """Returns the full OSV vulnerability record for one ID."""
    session = session or requests.Session()
    resp = session.get(f"{api_base}/v1/vulns/{vuln_id}", timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def summarize_severity(vuln_record):
    """OSV severity can show up as a qualitative label in
    'database_specific' (common for GHSA entries) or as a top-level CVSS
    vector/score. Prefers the qualitative label when present, since
    LOW/MODERATE/HIGH/CRITICAL reads better in a report than a bare
    CVSS number - falls back to the score, then 'UNKNOWN'."""
    db_specific = vuln_record.get("database_specific", {})
    if "severity" in db_specific:
        return db_specific["severity"]

    for affected in vuln_record.get("affected", []):
        db = affected.get("database_specific", {})
        if "severity" in db:
            return db["severity"]

    for sev in vuln_record.get("severity", []):
        if sev.get("type") in ("CVSS_V3", "CVSS_V4"):
            return sev.get("score", "UNKNOWN")

    return "UNKNOWN"
