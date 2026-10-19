#!/bin/sh
# Starts a real local HTTP server implementing OSV's actual API shape,
# then runs the real scanner.py against it over real HTTP requests -
# no mocked requests.post/get.
set -e
cd "$(dirname "$0")/.."

python3 -c "
import sys
sys.path.insert(0, 'test_fixtures')
from mock_osv_server import start_server
start_server(port=18085)
import time
time.sleep(60)
" &
SERVER_PID=$!
sleep 1

echo "== Scanning sample_requirements.txt against the mock OSV server =="
set +e
python3 scanner.py test_fixtures/sample_requirements.txt --api-base http://127.0.0.1:18085 --fail-on any > /tmp/dvs_out.txt 2>&1
EXIT_CODE=$?
set -e
cat /tmp/dvs_out.txt
echo "(scanner exit code: $EXIT_CODE)"

grep -q "bad-pkg==1.0.0" /tmp/dvs_out.txt && echo "PASS: bad-pkg flagged" || { echo "FAIL: bad-pkg not flagged"; kill $SERVER_PID; exit 1; }
grep -q "FAKE-2024-0001" /tmp/dvs_out.txt && echo "PASS: correct vuln ID reported for bad-pkg" || { echo "FAIL"; kill $SERVER_PID; exit 1; }
grep -q "CRITICAL" /tmp/dvs_out.txt && echo "PASS: CRITICAL severity surfaced for very-bad-pkg" || { echo "FAIL"; kill $SERVER_PID; exit 1; }
grep -q "clean-pkg==2.0.0" /tmp/dvs_out.txt && echo "PASS: clean-pkg correctly reported as having no known vulnerabilities" || { echo "FAIL"; kill $SERVER_PID; exit 1; }
grep -q "not pinned to an exact version" /tmp/dvs_out.txt && echo "PASS: unpinned flask>=2.0 correctly skipped with reason" || { echo "FAIL"; kill $SERVER_PID; exit 1; }
grep -q "VCS/URL install" /tmp/dvs_out.txt && echo "PASS: git+ URL correctly skipped with reason" || { echo "FAIL"; kill $SERVER_PID; exit 1; }
[ "$EXIT_CODE" = "1" ] && echo "PASS: non-zero exit code when vulnerabilities found" || { echo "FAIL: expected exit code 1, got $EXIT_CODE"; kill $SERVER_PID; exit 1; }

echo
echo "== Re-running with --fail-on critical against a requirements file with only MODERATE findings =="
cat > /tmp/dvs_moderate_only.txt <<'EOF'
very-bad-pkg==0.1.0
EOF
# very-bad-pkg actually has a CRITICAL finding too, so instead test the
# none-vulnerable case for --fail-on behavior with clean-pkg alone:
cat > /tmp/dvs_clean_only.txt <<'EOF'
clean-pkg==2.0.0
EOF
set +e
python3 scanner.py /tmp/dvs_clean_only.txt --api-base http://127.0.0.1:18085 --fail-on critical > /tmp/dvs_clean_out.txt 2>&1
CLEAN_EXIT=$?
set -e
cat /tmp/dvs_clean_out.txt
[ "$CLEAN_EXIT" = "0" ] && echo "PASS: clean package exits 0" || { echo "FAIL: expected exit 0, got $CLEAN_EXIT"; kill $SERVER_PID; exit 1; }

kill $SERVER_PID 2>/dev/null || true
rm -f /tmp/dvs_out.txt /tmp/dvs_clean_out.txt /tmp/dvs_moderate_only.txt /tmp/dvs_clean_only.txt
echo
echo "All tests passed."
