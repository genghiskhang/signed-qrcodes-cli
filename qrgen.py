import argparse
import json
import base64
import os
import qrcode
import boto3
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv
load_dotenv()

AWS_ACCESS_KEY = os.getenv('AWS_ACCESS_KEY', '')
AWS_SECRET_KEY = os.getenv('AWS_SECRET_KEY', '')

DYNAMODB_TABLE = os.getenv('DYNAMODB_TABLE', '')
S3_BUCKET = os.getenv('S3_BUCKET', '')
AWS_REGION = os.getenv('AWS_REGION', '')
OUTPUT_DIR = './outputs'

AES_KEY = base64.b64decode(os.getenv('AES_KEY', ''))

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return private_key, private_pem, public_pem

def encrypt_email(email):
    aesgcm = AESGCM(AES_KEY)
    iv = os.urandom(12)
    encrypted = aesgcm.encrypt(iv, email.encode(), None)
    ciphertext, tag = encrypted[:-16], encrypted[-16:]
    return {
        'email_enc': base64.b64encode(ciphertext).decode(),
        'iv': base64.b64encode(iv).decode(),
        'tag': base64.b64encode(tag).decode()
    }

def store_keys(email, private_pem, public_pem, issued_at):
    dynamodb = boto3.resource(
        'dynamodb',
        region_name=AWS_REGION,
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY
    )
    table = dynamodb.Table(DYNAMODB_TABLE)
    table.put_item(Item={
        'email': email,
        'private_key': private_pem,
        'public_key': public_pem,
        'issued_at': issued_at
    })

def sign_data(message, private_key):
    signature = private_key.sign(
        message.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()

def generate_qr(payload, filename):
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
    path = os.path.join(OUTPUT_DIR, filename)
    qr = qrcode.make(json.dumps(payload))
    qr.save(path)
    print(f'QR code saved to {path}')
    return path

def upload_to_s3(file_path, email):
    s3 = boto3.client(
        's3',
        region_name=AWS_REGION,
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY
    )
    s3_key = f'{os.path.basename(file_path)}'
    s3.upload_file(file_path, S3_BUCKET, s3_key)
    print(f'Uploaded to S3 at s3://{S3_BUCKET}/{s3_key}')

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('email', nargs='?', help='Email to encrypt and sign')
    parser.add_argument('--genkey', action='store_true', help='Generate and print AES-256 key for .env')
    args = parser.parse_args()

    if args.genkey:
        aes_key = base64.b64encode(os.urandom(32)).decode()
        print('Generated AES-256 key:\n')
        print(f'AES_KEY={aes_key}\n')
        print('Copy this line into your .env file')
        return

    if not args.email:
        print('You must provide an email or use --genkey')
        return

    issued_at = datetime.utcnow().isoformat() + 'Z'
    message = f'{args.email}|{issued_at}'

    private_key, private_pem, public_pem = generate_key_pair()
    signature = sign_data(message, private_key)
    store_keys(args.email, private_pem, public_pem, issued_at)

    encrypted_email = encrypt_email(args.email)
    payload = {
        **encrypted_email,
        'issued_at': issued_at,
        'sig': signature
    }

    filename = f'{args.email.replace("@", "_at_")}.png'
    qr_path = generate_qr(payload, filename)
    upload_to_s3(qr_path, args.email)
    print(f'QR code saved to {qr_path}')
    print(f'Payload:\n{json.dumps(payload, indent=2)}')

if __name__ == '__main__':
    main()