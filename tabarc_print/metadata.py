"""AES-256-GCM envelopes for mailbox metadata. Only opaque job IDs travel in filenames."""
import json
import os

from .common import safe_job_id, validate_printer_id
from .crypto import _crypto
from .receiver_identity import check_receiver_id

MANIFEST_SUFFIX = '.job.bin'
RECEIPT_SUFFIX = '.receipt.bin'
MAX_METADATA_BYTES = 8192
_PREFIXES = {'manifest': b'TPM4', 'receipt': b'TPR4'}


def _key(secret: bytes, job_id: str, kind: str) -> bytes:
    if not isinstance(secret, bytes) or len(secret) < 32:
        raise ValueError('A random gateway secret of at least 256 bits is required')
    safe_job_id(job_id)
    if kind not in _PREFIXES:
        raise ValueError('Unsupported metadata envelope')
    _, HKDF, hashes = _crypto()
    return HKDF(algorithm=hashes.SHA256(), length=32,
                salt=bytes.fromhex(job_id),
                info=b'TABARC Print encrypted metadata v4:' + kind.encode('ascii')).derive(secret)


def _aad(job_id: str, kind: str) -> bytes:
    return b'TABARC Print metadata v4\x00' + kind.encode('ascii') + b'\x00' + bytes.fromhex(job_id)


def seal(secret: bytes, job_id: str, kind: str, fields: dict) -> bytes:
    safe_job_id(job_id)
    if not isinstance(fields, dict) or fields.get('job_id') != job_id:
        raise ValueError('Invalid metadata job ID')
    AESGCM, _, _ = _crypto()
    raw = json.dumps(fields, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('utf-8')
    if len(raw) > MAX_METADATA_BYTES - 32:
        raise ValueError('Oversized metadata')
    nonce = os.urandom(12)
    return _PREFIXES[kind] + nonce + AESGCM(_key(secret, job_id, kind)).encrypt(
        nonce, raw, _aad(job_id, kind))


def open_envelope(secret: bytes, job_id: str, kind: str, envelope: bytes) -> dict:
    safe_job_id(job_id)
    if not isinstance(envelope, bytes) or not 33 <= len(envelope) <= MAX_METADATA_BYTES:
        raise ValueError('Invalid encrypted metadata length')
    if kind not in _PREFIXES or envelope[:4] != _PREFIXES[kind]:
        raise ValueError('Readable or unsupported metadata refused')
    AESGCM, _, _ = _crypto()
    try:
        raw = AESGCM(_key(secret, job_id, kind)).decrypt(
            envelope[4:16], envelope[16:], _aad(job_id, kind))
        fields = json.loads(raw)
    except Exception as exc:
        raise ValueError('Metadata authentication failed') from exc
    if not isinstance(fields, dict) or fields.get('job_id') != job_id:
        raise ValueError('Metadata job identity mismatch')
    return fields


def open_manifest(secret: bytes, job_id: str, envelope: bytes) -> dict:
    fields = open_envelope(secret, job_id, 'manifest', envelope)
    required = {'version', 'job_id', 'printer_id', 'sha256', 'created_at', 'encryption'}
    if fields.get('version') != 4 or not set(fields) in (required, required | {'target_receiver'}):
        raise ValueError('Unsupported manifest fields')
    validate_printer_id(fields['printer_id'])
    if type(fields['created_at']) is not int:
        raise ValueError('Invalid manifest timestamp')
    if not isinstance(fields['sha256'], str) or len(fields['sha256']) != 64 or any(c not in '0123456789abcdef' for c in fields['sha256']):
        raise ValueError('Invalid document digest')
    if not isinstance(fields['encryption'], dict) or set(fields['encryption']) != {'algorithm', 'nonce'} or fields['encryption']['algorithm'] != 'AES-256-GCM':
        raise ValueError('Unsupported document encryption')
    if 'target_receiver' in fields:
        check_receiver_id(fields['target_receiver'])
    return fields


def seal_receipt(secret: bytes, job_id: str, state: str, message: str, at: int) -> bytes:
    if not isinstance(state, str) or len(state) > 40 or not state:
        raise ValueError('Invalid receipt state')
    if not isinstance(message, str) or type(at) is not int:
        raise ValueError('Invalid receipt details')
    return seal(secret, job_id, 'receipt', {'version': 4, 'job_id': job_id, 'state': state,
                                         'message': message[:300], 'at': at})


def open_receipt(secret: bytes, job_id: str, envelope: bytes) -> dict:
    fields = open_envelope(secret, job_id, 'receipt', envelope)
    if set(fields) != {'version', 'job_id', 'state', 'message', 'at'} or fields['version'] != 4:
        raise ValueError('Unsupported receipt format')
    if not isinstance(fields['state'], str) or not 1 <= len(fields['state']) <= 40:
        raise ValueError('Invalid receipt state')
    if not isinstance(fields['message'], str) or len(fields['message']) > 300 or type(fields['at']) is not int:
        raise ValueError('Invalid receipt details')
    return fields
