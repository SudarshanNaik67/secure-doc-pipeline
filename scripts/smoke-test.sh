#!/usr/bin/env bash
# End-to-end smoke test: upload a file to the scanner, show the audit result,
# and (in mock mode) read back exactly what "Box" received.
#
# Usage:  ./scripts/smoke-test.sh [file]          (default: sample-data/sample.txt)
# Env:    SCANNER_URL  (default http://localhost:8000)
#         BOX_URL      (default http://localhost:3000, only used for mock read-back)
#         INGEST_API_KEY, INTERNAL_API_KEY  (match your .env / secrets)
set -euo pipefail

SCANNER_URL="${SCANNER_URL:-http://localhost:8000}"
BOX_URL="${BOX_URL:-http://localhost:3000}"
INTERNAL_API_KEY="${INTERNAL_API_KEY:-dev-internal-key-change-me}"
INGEST_API_KEY="${INGEST_API_KEY:-}"
FILE="${1:-sample-data/sample.txt}"

auth=()
[ -n "$INGEST_API_KEY" ] && auth=(-H "X-API-Key: $INGEST_API_KEY")

echo "==> Scanner readiness ($SCANNER_URL/ready)"
curl -fsS "$SCANNER_URL/ready"; echo

echo "==> Uploading $FILE"
RESP=$(curl -sS -w '\n%{http_code}' "${auth[@]}" -F "file=@${FILE}" "$SCANNER_URL/api/v1/documents/scan")
CODE=$(echo "$RESP" | tail -n1)
BODY=$(echo "$RESP" | sed '$d')
echo "$BODY"
echo "HTTP $CODE"
[ "$CODE" = "200" ] || { echo "Upload did not succeed."; exit 1; }

SCAN_ID=$(echo "$BODY" | sed -n 's/.*"scan_id":"\([^"]*\)".*/\1/p')
BOX_ID=$(echo "$BODY"  | sed -n 's/.*"box_file_id":"\([^"]*\)".*/\1/p')

echo
echo "==> Audit record (metadata only - no raw PII)"
curl -fsS "${auth[@]}" "$SCANNER_URL/api/v1/scans/$SCAN_ID"; echo

echo
echo "==> What Box received (mock mode only)"
if curl -fsS -H "X-Internal-Api-Key: $INTERNAL_API_KEY" "$BOX_URL/mock/files/$BOX_ID" 2>/dev/null; then
  :
else
  echo "(not available: real Box mode, or box-service is not exposed on $BOX_URL."
  echo " Check the file in your Box account instead: box_file_id=$BOX_ID)"
fi
