"""
A local HTTP server that implements the two OSV.dev endpoints this tool
actually calls (POST /v1/querybatch and GET /v1/vulns/<id>), with a
small set of fixed, fake vulnerability records - so scanner.py's real
HTTP client code runs against a real server over a real socket, not a
mocked requests.post/get.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

# (package_name, version) -> list of vuln IDs
VULNERABLE = {
    ("bad-pkg", "1.0.0"): ["FAKE-2024-0001"],
    ("very-bad-pkg", "0.1.0"): ["FAKE-2024-0002", "FAKE-2024-0003"],
}

# vuln_id -> full OSV-shaped record
VULN_RECORDS = {
    "FAKE-2024-0001": {
        "id": "FAKE-2024-0001",
        "summary": "Arbitrary file write via crafted archive path (path traversal)",
        "aliases": ["CVE-2024-00001"],
        "severity": [{"type": "CVSS_V3", "score": "7.5"}],
        "database_specific": {"severity": "HIGH"},
    },
    "FAKE-2024-0002": {
        "id": "FAKE-2024-0002",
        "summary": "Remote code execution via unsafe deserialization of cached responses",
        "aliases": ["CVE-2024-00002", "GHSA-xxxx-yyyy-zzzz"],
        "severity": [],
        "database_specific": {"severity": "CRITICAL"},
    },
    "FAKE-2024-0003": {
        "id": "FAKE-2024-0003",
        "summary": "Denial of service via unbounded recursive parsing",
        "aliases": [],
        "severity": [],
        "database_specific": {"severity": "MODERATE"},
    },
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # keep test output quiet

    def _send_json(self, status, body):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self):
        if self.path != "/v1/querybatch":
            self._send_json(404, {"error": "not found"})
            return

        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length))
        results = []
        for q in body.get("queries", []):
            name = q["package"]["name"]
            version = q["version"]
            vuln_ids = VULNERABLE.get((name, version), [])
            results.append({"vulns": [{"id": vid} for vid in vuln_ids]})

        self._send_json(200, {"results": results})

    def do_GET(self):
        prefix = "/v1/vulns/"
        if not self.path.startswith(prefix):
            self._send_json(404, {"error": "not found"})
            return

        vuln_id = self.path[len(prefix):]
        record = VULN_RECORDS.get(vuln_id)
        if record is None:
            self._send_json(404, {"error": "unknown vuln id"})
            return
        self._send_json(200, record)


def start_server(port=18085):
    server = HTTPServer(("127.0.0.1", port), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


if __name__ == "__main__":
    srv = start_server()
    print("Mock OSV server running on http://127.0.0.1:18085 (Ctrl+C to stop)")
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        srv.shutdown()
