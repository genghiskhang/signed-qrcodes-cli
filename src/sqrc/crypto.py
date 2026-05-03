import base64
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature


def generate_key_pair() -> tuple[RSAPrivateKey, str, str]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_key, private_pem, public_pem


def sign_data(message: str, private_key: RSAPrivateKey) -> str:
    sig = private_key.sign(message.encode(), padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    ), hashes.SHA256())
    return base64.b64encode(sig).decode()


def verify_signature(message: str, signature_b64: str, public_pem: str) -> bool:
    public_key: RSAPublicKey = serialization.load_pem_public_key(public_pem.encode())
    sig = base64.b64decode(signature_b64)
    try:
        public_key.verify(sig, message.encode(), padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ), hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def encrypt_email(email: str, aes_key: bytes) -> dict:
    aesgcm = AESGCM(aes_key)
    iv = os.urandom(12)
    encrypted = aesgcm.encrypt(iv, email.encode(), None)
    ciphertext, tag = encrypted[:-16], encrypted[-16:]
    return {
        "email_enc": base64.b64encode(ciphertext).decode(),
        "iv": base64.b64encode(iv).decode(),
        "tag": base64.b64encode(tag).decode(),
    }


def decrypt_email(payload: dict, aes_key: bytes) -> str:
    ciphertext = base64.b64decode(payload["email_enc"])
    iv = base64.b64decode(payload["iv"])
    tag = base64.b64decode(payload["tag"])
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(iv, ciphertext + tag, None).decode()


def signed_message(email_enc: str, iv: str, tag: str, issued_at: str) -> str:
    """Canonical message string that is signed and verified."""
    return f"{email_enc}|{iv}|{tag}|{issued_at}"
