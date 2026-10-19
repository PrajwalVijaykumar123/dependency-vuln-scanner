# Dependency Vulnerability Scanner

Checks every exact-pinned package in a `requirements.txt` against [OSV.dev](https://osv.dev) — the open vulnerability database that GitHub's Dependabot and `pip-audit` both draw from — and reports known CVEs/GHSAs with severity, a short summary, and known aliases. A minimal, from-scratch software composition analysis (SCA) tool.

## What This Project Does

- **Real vulnerability data, not a static local list**: queries OSV.dev's actual batch API for every pinned package, then fetches full details (summary, severity, CVE/GHSA aliases) for anything flagged
- **Only checks what it can check honestly**: unpinned requirements (`flask>=2.0`), VCS/URL installs, and option lines (`-r other.txt`) are reported as explicitly skipped with a reason, rather than silently ignored or guessed at — an unpinned range has no single version to look up
- **Severity-aware exit codes**: `--fail-on critical` (or high/moderate/low/any/none) controls what counts as a CI failure, so this can gate a pipeline without failing the build over a low-severity advisory in a transitive dependency you don't control
- **PEP 503 name normalization**: `Some_Weird.Pkg` and `some-weird-pkg` are treated as the same package, matching how PyPI and OSV actually identify packages
- **JSON output** alongside the console report, for feeding into other tooling

## Why a second lookup per finding, instead of one batch call

OSV's `querybatch` endpoint deliberately returns only vulnerability IDs and a modification timestamp — not the full record — to keep batch responses fast and small when checking hundreds of packages at once. Getting the actual summary, severity, and aliases means a second `GET /v1/vulns/{id}` call per distinct finding. That's not an inefficiency added here; it's how OSV's own API is designed, and the scanner follows that two-step shape rather than working around it.

## Example Output

```
Scanned 3 pinned package(s).

2 package(s) with known vulnerabilities:

  bad-pkg==1.0.0  (1 finding(s))
    [HIGH] FAKE-2024-0001 (aka CVE-2024-00001)
        Arbitrary file write via crafted archive path (path traversal)

  very-bad-pkg==0.1.0  (2 finding(s))
    [CRITICAL] FAKE-2024-0002 (aka CVE-2024-00002, GHSA-xxxx-yyyy-zzzz)
        Remote code execution via unsafe deserialization of cached responses
    [MODERATE] FAKE-2024-0003
        Denial of service via unbounded recursive parsing

1 package(s) with no known vulnerabilities: clean-pkg==2.0.0

2 line(s) skipped (not an exact-version pin OSV can check):
    'flask>=2.0' - not pinned to an exact version (==) - can't look up a range
    'git+https://github.com/example/example.git' - VCS/URL install - no fixed version to look up
```

(Real output from the test suite's local OSV-shaped fixture server — see Testing below. Package names and CVE IDs here are fake test fixtures, not real advisories.)

## Tech Stack

- Python 3.11
- `requests` for the OSV.dev HTTP API

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

```bash
python3 scanner.py requirements.txt
python3 scanner.py requirements.txt --json report.json
python3 scanner.py requirements.txt --fail-on high    # only non-zero exit on HIGH/CRITICAL findings
```

## Testing

OSV.dev's real database changes daily, so pinning a test to "this exact package version has this exact CVE today" would break on its own over time. For a deterministic test, `test_fixtures/mock_osv_server.py` implements OSV's real two-endpoint API shape (`POST /v1/querybatch`, `GET /v1/vulns/<id>`) with fixed, clearly-fake fixture records:

```bash
sh test_fixtures/run_test.sh
```

This runs the real `scanner.py` against the real HTTP server over actual sockets on `127.0.0.1` — not a mocked `requests` call — and verifies: a vulnerable package is flagged with the correct ID and severity, a clean package is reported as clean, unpinned/VCS lines are correctly skipped with a reason, and the `--fail-on` exit-code logic is correct in both directions.

## Architecture

```
requirements.txt
        |
        v
parser.py: split into (name, version) pairs OSV can check,
            vs. skipped lines (unpinned, VCS, flags) with a reason
        |
        v
osv_client.py: POST /v1/querybatch  -> vuln IDs per package
                GET /v1/vulns/{id}  -> summary, severity, aliases (per finding)
        |
        v
scanner.py: assemble per-package report, rank by severity,
             decide exit code against --fail-on threshold
        |
        v
Console report + optional JSON report
```

## Project Structure

```
dependency-vuln-scanner/
├── scanner.py                    # CLI: ties parsing + OSV client + reporting together
├── parser.py                      # requirements.txt parsing and PyPI name normalization
├── osv_client.py                  # OSV.dev API client (querybatch + per-ID details)
├── requirements.txt
└── test_fixtures/
    ├── mock_osv_server.py         # Local HTTP server implementing OSV's real API shape
    ├── sample_requirements.txt    # Mix of vulnerable/clean/unpinned/VCS lines for the test
    └── run_test.sh                  # Starts the mock server, runs scanner.py, verifies output
```

## What I Learned

- Why "can we look this version up at all" has to be a separate, honestly-reported category from "did we check it and find nothing" — an unpinned `flask>=2.0` isn't a clean bill of health, it's a line this tool can't resolve to a single version, and collapsing that into either "vulnerable" or "clean" would be a false signal either way
- OSV's split between a cheap batch ID lookup and a separate per-ID details call is a deliberate API design trade-off (keep the common case - checking hundreds of packages - fast), not an accident, and worth mirroring rather than working around with a single denormalized call that doesn't exist
- Severity data in OSV isn't uniform across advisory sources: some records carry a qualitative label (`database_specific.severity`), others only a raw CVSS score, and a few have neither - a severity-sorting feature has to handle all three without crashing or silently mis-ranking
- PEP 503 name normalization matters for correctness here specifically because OSV's PyPI ecosystem keys vulnerabilities by normalized name - `Django` and `django` and `DJ-ango` all need to resolve to the same lookup key

## Next Steps

- Resolve transitive dependencies (not just what's directly pinned in requirements.txt) via `pip show`/a dependency tree, since most real-world vulnerable packages arrive as someone else's dependency
- Suggest the nearest non-vulnerable version for each flagged package, using OSV's `affected[].ranges` data
- Support `pyproject.toml`/Poetry lock files, not just requirements.txt
- A GitHub Action wrapper so this can run as a PR check
