import json
import os
import sys
from datetime import datetime, timedelta, timezone
from io import StringIO
from unittest.mock import patch

import sqrc.verify as verify_mod
from sqrc.crypto import encrypt_email, generate_key_pair, sign_data, signed_message

AES_KEY = os.urandom(32)
AES_KEY_B64 = __import__("base64").b64encode(AES_KEY).decode()
ENV = {"AES_KEY": AES_KEY_B64, "AWS_REGION": "us-east-1", "DYNAMODB_TABLE": "t", "S3_BUCKET": "b"}


def _make_payload(email: str = "user@example.com", days_ago: int = 0) -> tuple[dict, str]:
    issued_at = (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")
    private_key, _, public_pem = generate_key_pair()
    enc = encrypt_email(email, AES_KEY)
    msg = signed_message(enc["email_enc"], enc["iv"], enc["tag"], issued_at)
    payload = {**enc, "issued_at": issued_at, "sig": sign_data(msg, private_key)}
    return payload, public_pem


def _run(args: list[str], public_pem: str | None) -> tuple[int, str, str]:
    old_argv, sys.argv = sys.argv, ["sqrc-verify"] + args
    stdout_cap, stderr_cap = StringIO(), StringIO()
    exit_code = 0
    try:
        with patch.dict(os.environ, ENV), \
             patch.object(verify_mod, "fetch_public_key", return_value=public_pem), \
             patch("sys.stdout", stdout_cap), \
             patch("sys.stderr", stderr_cap):
            verify_mod.main()
    except SystemExit as e:
        exit_code = e.code or 0
    finally:
        sys.argv = old_argv
    return exit_code, stdout_cap.getvalue(), stderr_cap.getvalue()


def test_verify_valid_payload():
    payload, public_pem = _make_payload()
    code, out, _ = _run(["--json", json.dumps(payload)], public_pem)
    assert code == 0
    assert out.strip() == "user@example.com"


def test_verify_tampered_sig_fails():
    payload, public_pem = _make_payload()
    payload["sig"] = payload["sig"][:-4] + "AAAA"
    code, _, err = _run(["--json", json.dumps(payload)], public_pem)
    assert code != 0
    assert "FAILED" in err or "Error" in err


def test_verify_expired_payload():
    payload, public_pem = _make_payload(days_ago=400)
    code, _, err = _run(["--json", json.dumps(payload)], public_pem)
    assert code != 0
    assert "expired" in err.lower()


def test_verify_missing_field():
    payload, public_pem = _make_payload()
    del payload["sig"]
    code, _, err = _run(["--json", json.dumps(payload)], public_pem)
    assert code != 0
    assert "sig" in err


def test_verify_no_public_key_in_dynamo():
    payload, _ = _make_payload()
    code, _, err = _run(["--json", json.dumps(payload)], None)
    assert code != 0
    assert "no public key" in err.lower()
