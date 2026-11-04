"""Unit + endpoint tests. No MongoDB or network needed (both are faked)."""
from fastapi.testclient import TestClient

import main


class FakeCollection:
    """Minimal in-memory stand-in for a pymongo Collection."""

    def __init__(self) -> None:
        self.docs: dict = {}

    def insert_one(self, doc: dict) -> None:
        self.docs[doc["_id"]] = dict(doc)

    def update_one(self, flt: dict, update: dict) -> None:
        self.docs[flt["_id"]].update(update["$set"])

    def find_one(self, flt: dict):
        return self.docs.get(flt["_id"])


# --------------------------- DLP engine unit tests --------------------------- #
def test_luhn_accepts_known_test_card():
    assert main.luhn_valid("4111 1111 1111 1111")


def test_luhn_rejects_random_digits():
    assert not main.luhn_valid("1234 5678 9012 3456")


def test_scan_and_mask_redacts_all_types():
    text = "Card 4111 1111 1111 1111, SSN 123-45-6789, mail jane.doe@example.com"
    masked, findings = main.scan_and_mask(text)
    assert findings == {"CREDIT_CARD": 1, "SSN": 1, "EMAIL": 1}
    assert "4111 1111" not in masked
    assert "123-45-6789" not in masked
    assert "****-****-****-1111" in masked
    assert "***-**-6789" in masked
    assert "j***@example.com" in masked


def test_card_formats_amex_dashed_and_contiguous():
    text = "amex 3782 822463 10005 | dashed 5555-5555-5555-4444 | plain 4012888888881881"
    masked, findings = main.scan_and_mask(text)
    assert findings == {"CREDIT_CARD": 3}
    for raw in ("3782 822463 10005", "5555-5555-5555-4444", "4012888888881881"):
        assert raw not in masked


def test_card_followed_directly_by_ssn_both_detected():
    masked, findings = main.scan_and_mask("4111 1111 1111 1111 123-45-6789")
    assert findings == {"CREDIT_CARD": 1, "SSN": 1}
    assert "123-45-6789" not in masked


def test_aws_key_is_redacted():
    masked, findings = main.scan_and_mask("key=AKIAIOSFODNN7EXAMPLE")
    assert findings == {"AWS_ACCESS_KEY": 1}
    assert "AKIAIOSFODNN7EXAMPLE" not in masked


def test_invalid_ssn_and_card_are_left_untouched():
    text = "ssn 000-12-3456 and 666-12-3456 and card 1234 5678 9012 3456"
    masked, findings = main.scan_and_mask(text)
    assert findings == {}
    assert masked == text


def test_clean_text_is_unchanged():
    text = "Quarterly report: revenue up 12% year over year."
    masked, findings = main.scan_and_mask(text)
    assert findings == {} and masked == text


# ------------------------------ endpoint tests ------------------------------- #
def _client_with_fakes(monkeypatch, forward=None):
    fake = FakeCollection()
    forwarded: dict = {}

    def default_forward(**kwargs):
        forwarded.update(kwargs)
        return {"box_file_id": "999"}

    monkeypatch.setattr(main, "get_collection", lambda: fake)
    monkeypatch.setattr(main, "forward_to_box_service", forward or default_forward)
    return TestClient(main.app), fake, forwarded


def test_endpoint_masks_audits_and_forwards(monkeypatch):
    client, fake, forwarded = _client_with_fakes(monkeypatch)
    body = b"card 4111 1111 1111 1111 ssn 123-45-6789"
    resp = client.post(
        "/api/v1/documents/scan", files={"file": ("sample.txt", body, "text/plain")}
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["decision"] == "masked"
    assert b"4111 1111" not in forwarded["payload"]
    record = fake.docs[data["scan_id"]]
    assert record["status"] == "forwarded"
    assert "123-45-6789" not in str(record)  # no raw PII in the audit log
    assert "4111 1111" not in str(record)


def test_endpoint_blocks_when_policy_is_block(monkeypatch):
    client, fake, forwarded = _client_with_fakes(monkeypatch)
    monkeypatch.setattr(main.settings, "block_on_findings", True)
    resp = client.post(
        "/api/v1/documents/scan",
        files={"file": ("s.txt", b"ssn 123-45-6789", "text/plain")},
    )
    assert resp.status_code == 422
    assert forwarded == {}  # nothing was forwarded
    (record,) = fake.docs.values()
    assert record["status"] == "blocked"


def test_endpoint_reports_502_when_box_service_fails(monkeypatch):
    def failing_forward(**_kwargs):
        raise main.ForwardError("boom")

    client, fake, _ = _client_with_fakes(monkeypatch, forward=failing_forward)
    resp = client.post(
        "/api/v1/documents/scan",
        files={"file": ("s.txt", b"hello world", "text/plain")},
    )
    assert resp.status_code == 502
    (record,) = fake.docs.values()
    assert record["status"] == "forward_failed"


def test_endpoint_rejects_unsupported_extension():
    client = TestClient(main.app)
    resp = client.post(
        "/api/v1/documents/scan", files={"file": ("malware.exe", b"x", "text/plain")}
    )
    assert resp.status_code == 415


def test_ingest_key_enforced_when_configured(monkeypatch):
    client, _, _ = _client_with_fakes(monkeypatch)
    monkeypatch.setattr(main.settings, "ingest_api_key", "secret")
    files = {"file": ("s.txt", b"hello", "text/plain")}
    assert client.post("/api/v1/documents/scan", files=files).status_code == 401
    ok = client.post(
        "/api/v1/documents/scan", files=files, headers={"X-API-Key": "secret"}
    )
    assert ok.status_code == 200
