import argparse
import json
import base64
import os
from pyzbar.pyzbar import decode
from PIL import Image
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv
load_dotenv()

AES_KEY = base64.b64decode(os.getenv('AES_KEY'))

def decrypt_email(payload):
    ciphertext = base64.b64decode(payload['email_enc'])
    iv = base64.b64decode(payload['iv'])
    tag = base64.b64decode(payload['tag'])
    aesgcm = AESGCM(AES_KEY)
    decrypted = aesgcm.decrypt(iv, ciphertext + tag, None)
    return decrypted.decode()

def extract_payload_from_image(image_path):
    image_path = os.path.abspath(os.path.expanduser(image_path))
    img = Image.open(image_path)
    results = decode(img)
    if not results:
        raise ValueError('No QR code found in image.')
    data = results[0].data.decode('utf-8')
    return json.loads(data)

def main():
    parser = argparse.ArgumentParser(description='Decrypt and read a signed QR payload.')
    parser.add_argument('--json', type=str, help='QR payload as JSON string')
    parser.add_argument('--image', type=str, help='Path to QR code image (PNG/JPG)')
    parser.add_argument('--verbose', action='store_true', help='Show full payload')

    args = parser.parse_args()

    if not args.json and not args.image:
        parser.error('Must provide either --json or --image')

    try:
        payload = json.loads(args.json) if args.json else extract_payload_from_image(args.image)

        if args.verbose:
            print('Raw Content:')
            print(json.dumps(payload, indent=2))

        decrypted_email = decrypt_email(payload)
        print('Decrypted Content:')
        print(decrypted_email)
    except Exception as e:
        print(f'Failed: {e}')

if __name__ == '__main__':
    main()