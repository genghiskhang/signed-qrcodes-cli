# signed-qrcodes-cli

Generate and verify tamper-evident QR codes that encode an encrypted email address and a cryptographic signature, backed by AWS DynamoDB and S3.

## How it works

**Generation (`sqrc-gen`)**
1. Encrypts the email with AES-256-GCM (shared secret from `.env`).
2. Generates a per-QR RSA-2048 key pair.
3. Signs `email_enc|iv|tag|issued_at` with the private key using RSA-PSS/SHA-256.
4. Stores **only** the public key in DynamoDB (keyed by email).
5. Embeds the encrypted email, IV, tag, timestamp, and signature in a QR code PNG.
6. Uploads the PNG to S3.

**Verification (`sqrc-verify`)**
1. Reads the payload from a JSON string or image file.
2. Checks the `issued_at` timestamp is within the allowed age window.
3. Decrypts the email with AES-256-GCM.
4. Fetches the matching public key from DynamoDB.
5. Verifies the RSA-PSS signature — exits non-zero if it fails.
6. Prints the email on success.

## Prerequisites

- Python ≥ 3.11
- [uv](https://docs.astral.sh/uv/)
- AWS account with a DynamoDB table and an S3 bucket
- `libzbar` (only needed to read QR codes from image files)
  - macOS: `brew install zbar`
  - Debian/Ubuntu: `apt install libzbar0`

## Setup

```sh
# 1. Clone and install
git clone https://github.com/yourname/signed-qrcodes-cli
cd signed-qrcodes-cli
uv sync

# 2. Create your .env
cp .env.example .env

# 3. Generate an AES key and paste it into .env
uv run sqrc-gen --genkey >> .env

# 4. Fill in the remaining .env values (AWS_REGION, DYNAMODB_TABLE, S3_BUCKET)
```

### DynamoDB table

Create a table with `email` (String) as the partition key. No sort key needed.

```sh
aws dynamodb create-table \
  --table-name signed-qrcodes \
  --attribute-definitions AttributeName=email,AttributeType=S \
  --key-schema AttributeName=email,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST
```

## Usage

```sh
# Generate a signed QR code
uv run sqrc-gen user@example.com

# Generate without uploading to S3 (local testing)
uv run sqrc-gen user@example.com --no-upload

# Verify from a JSON payload string
uv run sqrc-verify --json '{"email_enc":"...","iv":"...","tag":"...","issued_at":"...","sig":"..."}'

# Verify from a QR code image
uv run sqrc-verify --image outputs/user_at_example.com.png

# Verify with a custom expiry window (default: 365 days)
uv run sqrc-verify --image outputs/user_at_example.com.png --max-age-days 30

# Show the raw payload while verifying
uv run sqrc-verify --image outputs/user_at_example.com.png --verbose
```

`sqrc-verify` exits 0 on success and prints the email to stdout. All status messages go to stderr, so you can pipe the email safely.

## AWS credentials

`sqrc-gen` and `sqrc-verify` use the standard boto3 credential chain. In production, attach an IAM role to your instance/container. For local development you can set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` in `.env` (see `.env.example`).

## Development

```sh
uv sync
uv run pytest
```
