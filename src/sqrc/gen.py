import argparse
import base64
import json
import os
import re
import sys
from datetime import datetime, timezone

import qrcode

from .aws import store_public_key, upload_to_s3
from .config import get_aes_key, get_aws_config
from .crypto import encrypt_email, generate_key_pair, sign_data, signed_message

OUTPUT_DIR = "./outputs"
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _generate_and_save_qr(payload: dict, email: str) -> str:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    safe_name = email.replace("@", "_at_").replace("/", "_")
    path = os.path.join(OUTPUT_DIR, f"{safe_name}.png")
    qr = qrcode.make(json.dumps(payload, separators=(",", ":")))
    qr.save(path)
    return path


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sqrc-gen",
        description="Generate a signed QR code for an email address.",
    )
    parser.add_argument("email", nargs="?", help="Email address to encode")
    parser.add_argument(
        "--genkey",
        action="store_true",
        help="Generate a random AES-256 key and print the .env line",
    )
    parser.add_argument(
        "--no-upload",
        action="store_true",
        help="Skip S3 upload (useful for local testing without AWS)",
    )
    args = parser.parse_args()

    if args.genkey:
        key = base64.b64encode(os.urandom(32)).decode()
        print(f"AES_KEY={key}")
        print("Add this line to your .env file.", file=sys.stderr)
        return

    if not args.email:
        parser.error("email argument is required (or use --genkey)")

    if not EMAIL_RE.match(args.email):
        print(f"Error: '{args.email}' does not look like a valid email address.", file=sys.stderr)
        sys.exit(1)

    aes_key = get_aes_key()
    aws = get_aws_config()

    issued_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    private_key, _private_pem, public_pem = generate_key_pair()
    encrypted = encrypt_email(args.email, aes_key)
    message = signed_message(encrypted["email_enc"], encrypted["iv"], encrypted["tag"], issued_at)
    sig = sign_data(message, private_key)

    store_public_key(args.email, public_pem, issued_at, aws["region"], aws["table"])

    payload = {**encrypted, "issued_at": issued_at, "sig": sig}
    qr_path = _generate_and_save_qr(payload, args.email)
    print(f"QR code saved: {qr_path}", file=sys.stderr)

    if not args.no_upload:
        safe_name = args.email.replace("@", "_at_").replace("/", "_")
        s3_uri = upload_to_s3(qr_path, f"qrcodes/{safe_name}.png", aws["bucket"], aws["region"])
        print(f"Uploaded: {s3_uri}", file=sys.stderr)

    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
