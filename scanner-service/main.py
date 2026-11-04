"""
Ingestion & DLP Scan Engine (Microservice 1)
============================================

Flow for POST /api/v1/documents/scan:
  1. Authenticate caller (optional shared key) and validate the upload.
  2. Scan the text for sensitive data (credit cards w/ Luhn check, US SSNs,
     emails, AWS access keys) using regex + validation logic.
  3. Mask every finding.
  4. Write an audit record to MongoDB. The record NEVER contains raw PII:
     only counts per type, a SHA-256 of the original, and metadata.
  5. Forward the *masked* file to the Box Integration Service.
  6. Update the audit record with the final outcome.

Design choices:
  * Sync ("def") endpoints: FastAPI runs them in a threadpool, which is the
    right fit for blocking pymongo + httpx.Client calls.
  * Fail closed: if the audit log cannot be written, nothing is forwarded.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import mimetypes
import os
import re
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Dict, Optional, Pattern, Tuple

import httpx
from fastapi import FastAPI, File, Header, HTTPException, UploadFile
from pymongo import ASCENDING, MongoClient
from pymongo.collection import Collection
from pymongo.errors import PyMongoError

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("scanner-service")


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
class Settings:
    """Runtime configuration read from environment variables."""

    def __init__(self) -> None:
        # Standard MongoDB Atlas SRV URI, e.g.
        # mongodb+srv://user:pass@cluster0.xxxxx.mongodb.net/?retryWrites=true&w=majority
        self.mongodb_uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
        self.mongodb_db = os.getenv("MONGODB_DB", "dlp_pipeline")
        # In Kubernetes / Docker Compose this resolves via DNS to the box-service.
        self.box_service_url = os.getenv(
            "BOX_SERVICE_URL", "http://box-service:3000"
        ).rstrip("/")
        # Shared secret sent to box-service (service-to-service auth).
        self.internal_api_key = os.getenv("INTERNAL_API_KEY", "")
        # Optional key that callers must present to this service. Empty = disabled.
        self.ingest_api_key = os.getenv("INGEST_API_KEY", "")
        self.max_upload_bytes = int(
            os.getenv("MAX_UPLOAD_BYTES", str(5 * 1024 * 1024))
        )
        # "true" -> reject files containing PII instead of masking + forwarding.
        self.block_on_findings = (
            os.getenv("DLP_BLOCK_ON_FINDINGS", "false").lower() == "true"
        )


settings = Settings()

ALLOWED_EXTENSIONS = {".txt", ".csv", ".json", ".md", ".log"}


# --------------------------------------------------------------------------- #
# DLP engine: detection rules, validators, maskers
# --------------------------------------------------------------------------- #
def luhn_valid(candidate: str) -> bool:
    """Return True if the digits in `candidate` pass the Luhn checksum.

    Filters out the vast majority of random 13-19 digit numbers so we only
    flag strings that could be real payment card numbers.
    """
    digits = [int(c) for c in candidate if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    for index, digit in enumerate(reversed(digits)):
        if index % 2 == 1:  # double every second digit from the right
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def mask_card(raw: str) -> str:
    """Keep only the last four digits (PCI-DSS style truncation)."""
    digits = re.sub(r"\D", "", raw)
    return "****-****-****-" + digits[-4:]


def mask_ssn(raw: str) -> str:
    return "***-**-" + raw[-4:]


def mask_email(raw: str) -> str:
    local, _, domain = raw.partition("@")
    return f"{local[:1]}***@{domain}"


def mask_aws_key(_raw: str) -> str:
    return "[REDACTED_AWS_KEY]"


@dataclass(frozen=True)
class DlpRule:
    name: str
    pattern: Pattern[str]
    masker: Callable[[str], str]
    validator: Optional[Callable[[str], bool]] = None


# Card numbers are matched in the shapes they really appear in:
#   4-4-4-N  (Visa/MC/Discover, 13-19 digits), 4-6-4/5 (Amex, Diners), or
#   13-19 contiguous digits. Using fixed groups (instead of "any digits and
#   separators") stops a card from swallowing digits of an adjacent value,
#   e.g. "4111 1111 1111 1111 123-45-6789".
CARD_PATTERN = re.compile(
    r"\b(?:"
    r"\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{1,7}"
    r"|\d{4}[ -]?\d{6}[ -]?\d{4,5}"
    r"|\d{13,19}"
    r")\b"
)

# Rule order matters: each rule runs on the output of the previous one.
DLP_RULES: Tuple[DlpRule, ...] = (
    DlpRule(
        name="CREDIT_CARD",
        pattern=CARD_PATTERN,
        masker=mask_card,
        validator=luhn_valid,
    ),
    DlpRule(
        name="SSN",
        # US SSN: excludes area 000/666/9xx, group 00, serial 0000.
        pattern=re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
        masker=mask_ssn,
    ),
    DlpRule(
        name="EMAIL",
        pattern=re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        masker=mask_email,
    ),
    DlpRule(
        name="AWS_ACCESS_KEY",
        pattern=re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        masker=mask_aws_key,
    ),
)


def scan_and_mask(text: str) -> Tuple[str, Dict[str, int]]:
    """Scan `text` for sensitive data and return (masked_text, counts_by_type)."""
    counts: Dict[str, int] = {}
    masked = text
    for rule in DLP_RULES:

        def _replace(match: re.Match, rule: DlpRule = rule) -> str:
            value = match.group(0)
            if rule.validator and not rule.validator(value):
                return value  # looks like PII but fails validation: leave as-is
            counts[rule.name] = counts.get(rule.name, 0) + 1
            return rule.masker(value)

        masked = rule.pattern.sub(_replace, masked)
    return masked, counts


# --------------------------------------------------------------------------- #
# MongoDB (lazy connection so the module imports cleanly in tests)
# --------------------------------------------------------------------------- #
_mongo_client: Optional[MongoClient] = None


def get_collection() -> Collection:
    """Return the audit collection, creating the shared client on first use."""
    global _mongo_client
    if _mongo_client is None:
        _mongo_client = MongoClient(
            settings.mongodb_uri,
            serverSelectionTimeoutMS=5000,
            appname="dlp-scanner-service",
        )
    return _mongo_client[settings.mongodb_db]["scan_audit"]


def update_audit(scan_id: str, fields: dict) -> None:
    """Best-effort status update; failures are logged, never raised."""
    try:
        get_collection().update_one(
            {"_id": scan_id},
            {"$set": {**fields, "updated_at": datetime.now(timezone.utc)}},
        )
    except PyMongoError:
        logger.exception("audit_update_failed scan_id=%s", scan_id)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    try:
        collection = get_collection()
        collection.create_index([("created_at", ASCENDING)])
        collection.create_index([("sha256", ASCENDING)])
        logger.info("mongodb_ready db=%s", settings.mongodb_db)
    except PyMongoError as exc:
        # Don't crash: /ready will report 503 until Mongo is reachable.
        logger.warning("mongodb_unavailable_at_startup error=%s", exc)
    yield
    if _mongo_client is not None:
        _mongo_client.close()


app = FastAPI(
    title="DLP Scanner Service",
    version="1.0.0",
    description="Scans uploads for PII, masks it, audits to MongoDB, "
    "and forwards sanitized files to the Box integration service.",
    lifespan=lifespan,
)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def require_ingest_key(provided: Optional[str]) -> None:
    """Constant-time check of the optional inbound API key."""
    expected = settings.ingest_api_key
    if not expected:
        return
    if not provided or not hmac.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key")


def sanitize_filename(name: Optional[str]) -> str:
    """Strip any path components and unsafe characters from a client filename."""
    base = os.path.basename((name or "").replace("\\", "/"))
    return re.sub(r"[^A-Za-z0-9._-]", "_", base).lstrip(".")[:128]


class ForwardError(Exception):
    """Raised when the downstream Box service cannot accept the file."""


def forward_to_box_service(
    *,
    filename: str,
    content_type: str,
    payload: bytes,
    scan_id: str,
    findings_total: int,
) -> dict:
    """POST the sanitized file to box-service as multipart/form-data."""
    headers = {"X-Internal-Api-Key": settings.internal_api_key, "X-Scan-Id": scan_id}
    transport = httpx.HTTPTransport(retries=2)  # retries connection failures only
    timeout = httpx.Timeout(30.0, connect=5.0)
    try:
        with httpx.Client(transport=transport, timeout=timeout) as client:
            response = client.post(
                f"{settings.box_service_url}/upload",
                headers=headers,
                files={"file": (filename, payload, content_type)},
                data={"scan_id": scan_id, "dlp_findings": str(findings_total)},
            )
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as exc:
        raise ForwardError(
            f"box-service responded {exc.response.status_code}: {exc.response.text[:300]}"
        ) from exc
    except (httpx.HTTPError, ValueError) as exc:
        raise ForwardError(f"box-service unreachable or invalid response: {exc}") from exc


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.get("/health")
def health() -> dict:
    """Liveness probe: process is up (no dependency checks)."""
    return {"status": "ok"}


@app.get("/ready")
def ready() -> dict:
    """Readiness probe: verifies MongoDB connectivity."""
    try:
        get_collection().database.client.admin.command("ping")
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="MongoDB not reachable") from exc
    return {"status": "ready"}


@app.post("/api/v1/documents/scan")
def scan_document(
    file: UploadFile = File(...),
    x_api_key: Optional[str] = Header(default=None),
) -> dict:
    require_ingest_key(x_api_key)

    # ---- 1. Validate the upload ------------------------------------------- #
    filename = sanitize_filename(file.filename)
    if not filename:
        raise HTTPException(status_code=400, detail="A filename is required")
    extension = os.path.splitext(filename)[1].lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported file type. Allowed: {sorted(ALLOWED_EXTENSIONS)}",
        )

    raw = file.file.read(settings.max_upload_bytes + 1)  # bounded read
    if len(raw) > settings.max_upload_bytes:
        raise HTTPException(status_code=413, detail="File exceeds size limit")
    if not raw:
        raise HTTPException(status_code=400, detail="File is empty")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=415, detail="File must be UTF-8 text") from exc

    # ---- 2. DLP scan + mask ----------------------------------------------- #
    masked_text, findings = scan_and_mask(text)
    findings_total = sum(findings.values())
    masked_bytes = masked_text.encode("utf-8")
    content_type = mimetypes.guess_type(filename)[0] or "text/plain"

    if findings_total and settings.block_on_findings:
        decision = "blocked"
    elif findings_total:
        decision = "masked"
    else:
        decision = "clean"

    # ---- 3. Audit record (metadata only, never raw PII) ------------------- #
    scan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    record = {
        "_id": scan_id,
        "filename": filename,
        "content_type": content_type,
        "size_bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "findings": findings,
        "findings_total": findings_total,
        "decision": decision,
        "status": "received",
        "created_at": now,
        "updated_at": now,
    }
    try:
        get_collection().insert_one(record)
    except PyMongoError as exc:
        logger.exception("audit_insert_failed scan_id=%s", scan_id)
        raise HTTPException(
            status_code=503, detail="Audit log unavailable; file not processed"
        ) from exc

    logger.info(
        "scan_complete scan_id=%s decision=%s findings=%s", scan_id, decision, findings
    )

    if decision == "blocked":
        update_audit(scan_id, {"status": "blocked"})
        raise HTTPException(
            status_code=422,
            detail={
                "message": "Sensitive data detected; policy is to block",
                "scan_id": scan_id,
                "findings": findings,
            },
        )

    # ---- 4. Forward the sanitized file to Microservice 2 ------------------ #
    try:
        box_result = forward_to_box_service(
            filename=filename,
            content_type=content_type,
            payload=masked_bytes,
            scan_id=scan_id,
            findings_total=findings_total,
        )
    except ForwardError as exc:
        logger.error("forward_failed scan_id=%s error=%s", scan_id, exc)
        update_audit(scan_id, {"status": "forward_failed", "error": str(exc)[:500]})
        raise HTTPException(
            status_code=502, detail={"message": "Upstream failure", "scan_id": scan_id}
        ) from exc

    update_audit(
        scan_id,
        {"status": "forwarded", "box_file_id": str(box_result.get("box_file_id", ""))},
    )
    return {
        "scan_id": scan_id,
        "decision": decision,
        "findings": findings,
        "findings_total": findings_total,
        "forwarded": True,
        "box": box_result,
    }


@app.get("/api/v1/scans/{scan_id}")
def get_scan(scan_id: str, x_api_key: Optional[str] = Header(default=None)) -> dict:
    """Retrieve an audit record (useful for compliance queries)."""
    require_ingest_key(x_api_key)
    try:
        document = get_collection().find_one({"_id": scan_id})
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="Audit log unavailable") from exc
    if document is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return document
