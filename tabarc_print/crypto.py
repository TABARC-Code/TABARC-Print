"""Authenticated document encryption for cloud print mailboxes."""
import base64
import hashlib
import hmac
import json
import os

ALGORITHM = 'AES-256-GCM'
MAX_OVERHEAD = 64


def _crypto():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
    except ImportError as exc:
        raise RuntimeError('Encrypted printing requires: pip install -r requirements-security.txt') from exc
    return AESGCM, HKDF, hashes


def _key(secret: bytes, job_id: str) -> bytes:
    if len(secret) < 32:
        raise ValueError('Gateway secret must contain at least 32 bytes')
    AESGCM, HKDF, hashes = _crypto()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=bytes.fromhex(job_id),
                info=b'TABARC Print document encryption v1').derive(secret)


def associated_data(job_id: str, printer_id: str, created_at: int) -> bytes:
    return json.dumps({'created_at': created_at, 'job_id': job_id,
                       'printer_id': printer_id}, sort_keys=True,
                       separators=(',', ':')).encode()


def sign_v2(secret: bytes, fields: dict) -> str:
    body = json.dumps(fields, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
    return hmac.new(secret, b'TABARC Print manifest v2\x00' + body, hashlib.sha256).hexdigest()


def encrypt_pdf(secret: bytes, job_id: str, printer_id: str, created_at: int, pdf: bytes):
    AESGCM, _, _ = _crypto()
    nonce = os.urandom(12)
    cipher = AESGCM(_key(secret, job_id)).encrypt(
        nonce, pdf, associated_data(job_id, printer_id, created_at))
    return cipher, {'algorithm': ALGORITHM, 'nonce': base64.urlsafe_b64encode(nonce).decode('ascii')}


def decrypt_pdf(secret: bytes, job_id: str, printer_id: str, created_at: int,
                ciphertext: bytes, encryption: dict) -> bytes:
    AESGCM, _, _ = _crypto()
    if not isinstance(encryption, dict) or set(encryption) != {'algorithm', 'nonce'}:
        raise ValueError('Invalid encryption metadata')
    if encryption['algorithm'] != ALGORITHM or not isinstance(encryption['nonce'], str):
        raise ValueError('Unsupported encryption method')
    try:
        nonce = base64.b64decode(encryption['nonce'], altchars=b'-_', validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError('Invalid encryption nonce') from exc
    if len(nonce) != 12:
        raise ValueError('Invalid encryption nonce length')
    try:
        return AESGCM(_key(secret, job_id)).decrypt(
            nonce, ciphertext, associated_data(job_id, printer_id, created_at))
    except Exception as exc:
        raise ValueError('Document decryption or authentication failed') from exc
