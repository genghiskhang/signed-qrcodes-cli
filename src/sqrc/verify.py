import argparse
import json
import sys
from datetime import datetime, timezone, timedelta

from .aws import fetch_public_key
from .config import get_aes_key, get_aws_config
from .crypto import decrypt_email, signed_message, verify_signature

DEFAULT_MAX_AGE_DAYS = 365


def _load_payload(args) -> dict:
    if args.json:
        try:
            return json.loads(args.json)
        except json.JSONDecodeError as e:
            print(f"Error: invalid JSON payload: {e}", file=sys.stderr)
            sys.exit(1)

    import os
    try:
        from pyzbar.pyzbar import decode
        from PIL import Image
    except ImportError as exc:
        print(f"Error: image decoding requires libzbar — {exc}", file=sys.stderr)
        sys.exit(1)

    path = os.path.abspath(os.path.expanduser(args.image))
    try:
        img = Image.open(path)
    except FileNotFoundError:
        print(f"Error: image not found: {path}", file=sys.stderr)
        sys.exit(1)
    results = decode(img)
    if not results:
        print("Error: no QR code found in image.", file=sys.stderr)
        sys.exit(1)
    try:
        return json.loads(results[0].data.decode("utf-8"))
    except json.JSONDecodeError as e:
        print(f"Error: QR code data is not valid JSON: {e}", file=sys.stderr)
        sys.exit(1)


def _check_expiry(issued_at: str, max_age_days: int) -> None:
    try:
        issued = datetime.strptime(issued_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        print(f"Error: unrecognised issued_at format: {issued_at!r}", file=sys.stderr)
        sys.exit(1)
    age = datetime.now(timezone.utc) - issued
    if age > timedelta(days=max_age_days):
        print(f"Error: QR code expired (issued {issued_at}, max age {max_age_days} days).", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sqrc-verify",
        description="Verify and decrypt a signed QR code payload.",
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--json", type=str, metavar="PAYLOAD", help="QR payload as a JSON string")
    src.add_argument("--image", type=str, metavar="PATH", help="Path to QR code image (PNG/JPG)")
    parser.add_argument(
        "--max-age-days",
        type=int,
        default=DEFAULT_MAX_AGE_DAYS,
        metavar="N",
        help=f"Reject QR codes older than N days (default: {DEFAULT_MAX_AGE_DAYS})",
    )
    parser.add_argument("--verbose", action="store_true", help="Print the full raw payload")
    args = parser.parse_args()

    aes_key = get_aes_key()
    aws = get_aws_config()

    payload = _load_payload(args)

    for field in ("email_enc", "iv", "tag", "issued_at", "sig"):
        if field not in payload:
            print(f"Error: payload missing required field '{field}'.", file=sys.stderr)
            sys.exit(1)

    if args.verbose:
        print(json.dumps(payload, indent=2), file=sys.stderr)

    _check_expiry(payload["issued_at"], args.max_age_days)

    try:
        email = decrypt_email(payload, aes_key)
    except Exception as e:
        print(f"Error: decryption failed — {e}", file=sys.stderr)
        sys.exit(1)

    public_pem = fetch_public_key(email, aws["region"], aws["table"])
    if public_pem is None:
        print(f"Error: no public key found in DynamoDB for '{email}'.", file=sys.stderr)
        sys.exit(1)

    message = signed_message(payload["email_enc"], payload["iv"], payload["tag"], payload["issued_at"])
    if not verify_signature(message, payload["sig"], public_pem):
        print("Error: signature verification FAILED — payload may have been tampered with.", file=sys.stderr)
        sys.exit(1)

    print(email)


if __name__ == "__main__":
    main()
