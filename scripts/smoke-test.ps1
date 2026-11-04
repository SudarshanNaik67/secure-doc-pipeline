# End-to-end smoke test for Windows PowerShell / PowerShell 7.
# Usage:  .\scripts\smoke-test.ps1 [-File sample-data\sample.txt]
param(
  [string]$File = "sample-data\sample.txt",
  [string]$ScannerUrl = $(if ($env:SCANNER_URL) { $env:SCANNER_URL } else { "http://localhost:8000" }),
  [string]$BoxUrl = $(if ($env:BOX_URL) { $env:BOX_URL } else { "http://localhost:3000" }),
  [string]$InternalKey = $(if ($env:INTERNAL_API_KEY) { $env:INTERNAL_API_KEY } else { "dev-internal-key-change-me" }),
  [string]$IngestKey = $env:INGEST_API_KEY
)
$ErrorActionPreference = "Stop"

Write-Host "==> Scanner readiness"
curl.exe -fsS "$ScannerUrl/ready"; Write-Host ""

Write-Host "==> Uploading $File"
$curlArgs = @("-sS", "-F", "file=@$File")
if ($IngestKey) { $curlArgs += @("-H", "X-API-Key: $IngestKey") }
$json = curl.exe @curlArgs "$ScannerUrl/api/v1/documents/scan"
$json
$resp = $json | ConvertFrom-Json

Write-Host "`n==> Audit record (metadata only - no raw PII)"
$auditArgs = @("-fsS")
if ($IngestKey) { $auditArgs += @("-H", "X-API-Key: $IngestKey") }
curl.exe @auditArgs "$ScannerUrl/api/v1/scans/$($resp.scan_id)"

Write-Host "`n`n==> What Box received (mock mode only)"
curl.exe -fsS -H "X-Internal-Api-Key: $InternalKey" "$BoxUrl/mock/files/$($resp.box.box_file_id)"
