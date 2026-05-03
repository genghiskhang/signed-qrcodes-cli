import base64
import os
import sys

from dotenv import load_dotenv

load_dotenv()


def _require(name: str) -> str:
    val = os.getenv(name)
    if not val:
        print(f"Error: environment variable {name} is not set. See .env.example.", file=sys.stderr)
        sys.exit(1)
    return val


def get_aes_key() -> bytes:
    raw = _require("AES_KEY")
    try:
        key = base64.b64decode(raw)
    except Exception:
        print("Error: AES_KEY is not valid base64. Run `sqrc-gen --genkey` to generate one.", file=sys.stderr)
        sys.exit(1)
    if len(key) != 32:
        print(f"Error: AES_KEY must decode to 32 bytes (got {len(key)}). Run `sqrc-gen --genkey`.", file=sys.stderr)
        sys.exit(1)
    return key


def get_aws_config() -> dict:
    return {
        "region": _require("AWS_REGION"),
        "table": _require("DYNAMODB_TABLE"),
        "bucket": _require("S3_BUCKET"),
    }
