import os
import pytest
from sqrc.crypto import (
    decrypt_email,
    encrypt_email,
    generate_key_pair,
    sign_data,
    signed_message,
    verify_signature,
)

AES_KEY = os.urandom(32)


def test_encrypt_decrypt_roundtrip():
    email = "test@example.com"
    payload = encrypt_email(email, AES_KEY)
    assert decrypt_email(payload, AES_KEY) == email


def test_encrypt_produces_distinct_ivs():
    payload1 = encrypt_email("a@b.com", AES_KEY)
    payload2 = encrypt_email("a@b.com", AES_KEY)
    assert payload1["iv"] != payload2["iv"]


def test_decrypt_wrong_key_raises():
    payload = encrypt_email("test@example.com", AES_KEY)
    with pytest.raises(Exception):
        decrypt_email(payload, os.urandom(32))


def test_sign_verify_roundtrip():
    private_key, _, public_pem = generate_key_pair()
    msg = "hello|world"
    sig = sign_data(msg, private_key)
    assert verify_signature(msg, sig, public_pem) is True


def test_verify_tampered_message_fails():
    private_key, _, public_pem = generate_key_pair()
    sig = sign_data("original", private_key)
    assert verify_signature("tampered", sig, public_pem) is False


def test_verify_wrong_key_fails():
    private_key, _, _ = generate_key_pair()
    _, _, other_public_pem = generate_key_pair()
    sig = sign_data("msg", private_key)
    assert verify_signature("msg", sig, other_public_pem) is False


def test_signed_message_is_deterministic():
    m1 = signed_message("enc", "iv", "tag", "2025-01-01T00:00:00Z")
    m2 = signed_message("enc", "iv", "tag", "2025-01-01T00:00:00Z")
    assert m1 == m2


def test_signed_message_changes_with_field():
    base = signed_message("enc", "iv", "tag", "2025-01-01T00:00:00Z")
    tampered = signed_message("enc", "iv", "tag", "2025-01-02T00:00:00Z")
    assert base != tampered
