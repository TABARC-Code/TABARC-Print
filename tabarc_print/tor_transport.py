"""Tor onion-only transport with end-to-end AES-256-GCM document encryption.

Tor itself runs separately. The listener never accepts a public interface, and
outbound connections never fall back to direct TCP or DNS resolution.
"""
from __future__ import annotations

import argparse
from contextlib import closing
from getpass import getpass
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import socket
import socketserver
import threading
import sqlite3
import struct
import subprocess
import time
import uuid

from .cloud_auth import private_auth_dir
from .common import MAX_FILE_BYTES, safe_job_id, validate_pdf, validate_printer_id
from .crypto import encrypt_pdf, decrypt_pdf, sign_v2, MAX_OVERHEAD
from .receiver_identity import check_receiver_id, ReceiverIdentity
from .secret_store import SecretStore
from .local_queue import LocalQueue, default_state_dir
from .cloud_gateway import sign_receipt, verify_receipt, receipt_bytes
from .tor_control import TorControlSocket, new_client_key, check_public_key

_ONION = re.compile(r'^[a-z2-7]{56}\.onion$')
_MAX_MANIFEST = 4096
_MAX_RECEIPT = 4096
_MAGIC = b'TPRINT01'
_TIMEOUT = 30


def check_onion(host: str) -> str:
    if not isinstance(host, str) or not _ONION.fullmatch(host):
        raise ValueError('Only a 56-character Tor v3 .onion address is permitted')
    decoded = base64.b32decode(host[:56].upper())
    key, checksum, version = decoded[:32], decoded[32:34], decoded[34:35]
    expected = hashlib.sha3_256(b'.onion checksum' + key + version).digest()[:2]
    if version != b'\x03' or not hmac.compare_digest(checksum, expected):
        raise ValueError('Invalid Tor v3 onion address checksum')
    return host


def _exact(sock, size: int) -> bytes:
    result = bytearray()
    deadline = time.monotonic() + _TIMEOUT
    while len(result) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('Tor print frame deadline exceeded')
        sock.settimeout(min(_TIMEOUT, remaining))
        block = sock.recv(min(size - len(result), 65536))
        if not block:
            raise ConnectionError('Incomplete Tor print frame')
        result.extend(block)
    return bytes(result)


def _packet(sock, max_size: int) -> bytes:
    length = struct.unpack('!I', _exact(sock, 4))[0]
    if length < 1 or length > max_size:
        raise ValueError('Tor print frame length refused')
    return _exact(sock, length)


def _send_packet(sock, payload: bytes, max_size: int) -> None:
    if not 0 < len(payload) <= max_size:
        raise ValueError('Tor print frame too large')
    sock.sendall(struct.pack('!I', len(payload)) + payload)


def connect_socks_onion(onion: str, virtual_port: int, *, socks_port=9050):
    """SOCKS5 ATYP=domain: Tor resolves the .onion; the OS never does."""
    onion = check_onion(onion)
    if not isinstance(virtual_port, int) or not 1 <= virtual_port <= 65535:
        raise ValueError('Invalid onion service port')
    if not isinstance(socks_port, int) or not 1 <= socks_port <= 65535:
        raise ValueError('Invalid local Tor SOCKS port')
    sock = socket.create_connection(('127.0.0.1', socks_port), _TIMEOUT)
    try:
        sock.settimeout(_TIMEOUT)
        sock.sendall(b'\x05\x01\x00')
        if _exact(sock, 2) != b'\x05\x00':
            raise ConnectionError('Tor SOCKS5 no-auth negotiation failed')
        domain = onion.encode('ascii')
        sock.sendall(b'\x05\x01\x00\x03' + bytes([len(domain)]) + domain + struct.pack('!H', virtual_port))
        header = _exact(sock, 4)
        if header[:2] != b'\x05\x00' or header[2] != 0:
            raise ConnectionError('Tor onion service connection refused')
        if header[3] == 1:
            _exact(sock, 4 + 2)
        elif header[3] == 3:
            _exact(sock, _exact(sock, 1)[0] + 2)
        elif header[3] == 4:
            _exact(sock, 16 + 2)
        else:
            raise ConnectionError('Invalid Tor proxy response')
        return sock
    except BaseException:
        sock.close()
        raise


def _crypto():
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    return AESGCM, HKDF, hashes


def _receipt_key(secret: bytes, jid: str) -> bytes:
    AESGCM, HKDF, hashes = _crypto()
    return HKDF(algorithm=hashes.SHA384(), length=32, salt=bytes.fromhex(jid),
                info=b'TABARC Tor encrypted receipt v1').derive(secret)


def _seal_receipt(secret: bytes, jid: str, state: str) -> bytes:
    AESGCM, _, _ = _crypto()
    receipt = sign_receipt(secret, receipt_bytes(jid, state,
                       'Accepted by local print spooler; physical output not confirmed' if state == 'submitted' else state))
    nonce = os.urandom(12)
    return nonce + AESGCM(_receipt_key(secret, jid)).encrypt(nonce, receipt, bytes.fromhex(jid))


def _open_receipt(secret: bytes, jid: str, payload: bytes):
    AESGCM, _, _ = _crypto()
    if not 28 <= len(payload) <= _MAX_RECEIPT:
        raise ValueError('Invalid encrypted Tor receipt')
    try:
        raw = AESGCM(_receipt_key(secret, jid)).decrypt(payload[:12], payload[12:], bytes.fromhex(jid))
    except Exception as exc:
        raise ValueError('Tor receipt authentication failed') from exc
    return verify_receipt(secret, jid, raw)


def _document(secret: bytes, pdf: bytes, printer: str, receiver_id: str):
    validate_pdf(pdf)
    validate_printer_id(printer)
    check_receiver_id(receiver_id)
    jid, created = uuid.uuid4().hex, int(time.time())
    encrypted, info = encrypt_pdf(secret, jid, printer, created, pdf)
    manifest = {'version': 3, 'job_id': jid, 'printer_id': printer,
                'created_at': created, 'sha256': hashlib.sha256(encrypted).hexdigest(),
                'encryption': info, 'target_receiver': receiver_id}
    manifest['signature'] = sign_v2(secret, manifest)
    return jid, json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode(), encrypted


def _read_pdf(path: Path) -> bytes:
    # Descriptor-bound validation prevents replacing an upload with a symlink.
    import stat
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    path = Path(path)
    if path.is_symlink():
        raise ValueError('PDF symlinks are not accepted')
    with os.fdopen(os.open(path, flags), 'rb') as f:
        info = os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
            raise ValueError('Invalid or oversized PDF')
        payload = f.read(MAX_FILE_BYTES + 1)
    validate_pdf(payload)
    return payload


class TorPrintSender:
    def __init__(self, secret: bytes):
        if not isinstance(secret, bytes) or len(secret) != 32:
            raise ValueError('Tor transport requires exactly one random 256-bit shared secret')
        self.secret = secret

    def send(self, pdf: Path, printer: str, receiver_id: str, onion: str, virtual_port=8787, *, socks_port=9050):
        jid, manifest, encrypted = _document(self.secret, _read_pdf(pdf), printer, receiver_id)
        with closing(connect_socks_onion(onion, virtual_port, socks_port=socks_port)) as sock:
            sock.sendall(_MAGIC)
            _send_packet(sock, manifest, _MAX_MANIFEST)
            _send_packet(sock, encrypted, MAX_FILE_BYTES + MAX_OVERHEAD)
            result = _packet(sock, _MAX_RECEIPT)
        return jid, _open_receipt(self.secret, jid, result)


def submit_to_cups(pdf: bytes, printer: str) -> str:
    """Use stdin instead of writing a temporary plaintext document."""
    if os.name == 'nt':
        raise RuntimeError('Tor in-memory printing is not enabled on Windows')
    validate_pdf(pdf)
    validate_printer_id(printer)
    result = subprocess.run(['lp', '-d', printer, '-'], input=pdf,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=120, check=False)
    if result.returncode:
        raise RuntimeError('CUPS rejected print submission')
    return result.stdout.decode('utf-8', errors='replace')[:200]


class TorPrintReceiver:
    def __init__(self, secret: bytes, receiver_id: str, state_dir: Path, printer_map: dict[str, str],
                 *, spooler=None, dry_run=False, allow_direct_submission=False, queue=None):
        if not isinstance(secret, bytes) or len(secret) != 32:
            raise ValueError('Tor transport requires one random 256-bit shared secret')
        self.secret = secret
        self.receiver_id = check_receiver_id(receiver_id)
        self.root = private_auth_dir(state_dir)
        self.dbfile = self.root / 'tor-received.sqlite3'
        if self.dbfile.is_symlink():
            raise ValueError('Tor receipt database cannot be a symlink')
        if not printer_map:
            raise ValueError('At least one printer mapping is required')
        for external, internal in printer_map.items():
            validate_printer_id(external)
            validate_printer_id(internal)
        self.printers = dict(printer_map)
        self.dry_run = dry_run
        self.allow_direct_submission = allow_direct_submission
        self.spooler = spooler or submit_to_cups
        self.queue = None if allow_direct_submission else (queue or LocalQueue(self.root / 'queue'))
        with closing(sqlite3.connect(self.dbfile)) as db:
            db.execute('CREATE TABLE IF NOT EXISTS processed (job TEXT PRIMARY KEY, state TEXT NOT NULL, at INTEGER NOT NULL)')
            db.commit()
        if os.name != 'nt':
            os.chmod(self.dbfile, 0o600)

    def _check_manifest(self, manifest: bytes):
        if len(manifest) > _MAX_MANIFEST:
            raise ValueError('Manifest too large')
        data = json.loads(manifest)
        needed = {'version','job_id','printer_id','created_at','sha256','encryption','target_receiver','signature'}
        if not isinstance(data, dict) or set(data) != needed or type(data['version']) is not int or data['version'] != 3:
            raise ValueError('Encrypted, targeted manifest required')
        jid = safe_job_id(data['job_id'])
        validate_printer_id(data['printer_id'])
        check_receiver_id(data['target_receiver'])
        if data['target_receiver'] != self.receiver_id or data['printer_id'] not in self.printers:
            raise PermissionError('Job targets an unapproved device or printer')
        at = data['created_at']
        if type(at) is not int or abs(int(time.time()) - at) > 86400:
            raise ValueError('Expired Tor print job')
        if not isinstance(data['sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', data['sha256']):
            raise ValueError('Invalid document digest')
        signature = data.pop('signature')
        if not isinstance(signature, str) or not hmac.compare_digest(sign_v2(self.secret, data), signature):
            raise PermissionError('Invalid job authentication')
        data['signature'] = signature
        return data

    def accept(self, manifest: bytes, payload: bytes) -> bytes:
        job = self._check_manifest(manifest)
        jid = job['job_id']
        if not 16 <= len(payload) <= MAX_FILE_BYTES + MAX_OVERHEAD:
            raise ValueError('Encrypted document size invalid')
        if not hmac.compare_digest(hashlib.sha256(payload).hexdigest(), job['sha256']):
            raise ValueError('Encrypted document digest mismatch')
        pdf = decrypt_pdf(self.secret, jid, job['printer_id'], job['created_at'], payload, job['encryption'])
        validate_pdf(pdf)
        with closing(sqlite3.connect(self.dbfile, timeout=10)) as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT state FROM processed WHERE job=?', (jid,)).fetchone()
            if row:
                state = row[0]
                db.commit()
                return _seal_receipt(self.secret, jid, state)
            if self.allow_direct_submission:
                # Old direct-print compatibility: claim before the side effect.
                db.execute('INSERT INTO processed (job,state,at) VALUES (?,?,?)', (jid,'uncertain',int(time.time())))
            db.commit()
        # Incoming documents must be approved locally before reaching a spooler.
        # The queue's source reference also closes the crash gap between intake
        # and recording the receipt in this separate ledger.
        if not self.allow_direct_submission:
            self.queue.submit_bytes(pdf, self.printers[job['printer_id']],
                                    filename='incoming-' + jid[:12] + '.pdf',
                                    held=True, source_id='tor:' + jid)
            state = 'held'
        else:
            state = 'uncertain'
            try:
                if self.dry_run:
                    state = 'simulated'
                else:
                    self.spooler(pdf, self.printers[job['printer_id']])
                    state = 'submitted'
            except Exception:
                state = 'uncertain'
        with closing(sqlite3.connect(self.dbfile, timeout=10)) as db:
            db.execute('INSERT OR IGNORE INTO processed(job,state,at) VALUES (?,?,?)',
                       (jid, state, int(time.time())))
            db.execute('UPDATE processed SET state=?,at=? WHERE job=?', (state,int(time.time()),jid))
            db.commit()
        return _seal_receipt(self.secret, jid, state)


class _ReceiverHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(_TIMEOUT)
        try:
            if _exact(self.request, len(_MAGIC)) != _MAGIC:
                return
            manifest = _packet(self.request, _MAX_MANIFEST)
            # Authenticate the small manifest before reading a large payload.
            self.server.receiver._check_manifest(manifest)
            ciphertext = _packet(self.request, MAX_FILE_BYTES + MAX_OVERHEAD)
            encrypted_receipt = self.server.receiver.accept(manifest, ciphertext)
            _send_packet(self.request, encrypted_receipt, _MAX_RECEIPT)
        except (ValueError, PermissionError, TimeoutError, ConnectionError, OSError, json.JSONDecodeError):
            # Never send unauthenticated details or document contents to a caller.
            return


class TorPrintListener(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = False
    daemon_threads = True
    block_on_close = False
    request_queue_size = 4

    def __init__(self, receiver: TorPrintReceiver, port: int = 8787):
        if not isinstance(port, int) or not 0 <= port <= 65535:
            raise ValueError('Invalid local listener port')
        self.receiver = receiver
        self._slots = threading.BoundedSemaphore(4)
        super().__init__(('127.0.0.1', port), _ReceiverHandler)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def _secret(store: SecretStore, reference: str) -> bytes:
    raw = store.read(reference)
    if not re.fullmatch(r'[0-9a-f]{64}', raw):
        raise ValueError('Invalid vault key; a random 256-bit key is required')
    return bytes.fromhex(raw)


def main():
    parser = argparse.ArgumentParser(description='Experimental onion-only encrypted print transport')
    p = parser.add_subparsers(dest='action', required=True)
    for name in ('create-key', 'import-key', 'new-client-auth', 'send', 'receive'):
        sub = p.add_parser(name)
        sub.add_argument('--state-dir', type=Path, default=Path.home()/'.config'/'tabarc-print')
        if name in ('send', 'receive'):
            sub.add_argument('--key-ref', required=True, help='OS vault reference, not a secret')
            sub.add_argument('--control-socket', type=Path, help='Private user-owned Tor Unix ControlSocket')
        if name == 'send':
            sub.add_argument('--onion', required=True)
            sub.add_argument('--remote-port', type=int, default=8787)
            sub.add_argument('--socks-port', type=int, default=9050)
            sub.add_argument('--pdf', type=Path, required=True)
            sub.add_argument('--printer', required=True)
            sub.add_argument('--receiver-id', required=True)
            sub.add_argument('--client-auth-ref', help='OS vault reference for ephemeral Tor client authorisation')
        if name == 'receive':
            sub.add_argument('--listen-port', type=int, default=8787)
            sub.add_argument('--queue-state-dir', type=Path, help='Local held-job queue used by the desktop')
            sub.add_argument('--printer', action='append', required=True, help='remote-id=local-CUPS-queue')
            sub.add_argument('--enable-printing', action='store_true', help='Retired; remote intake is always held')
            sub.add_argument('--client-public', action='append', default=[], help='Approved Tor client public key (repeatable)')
    args = parser.parse_args()
    vault = SecretStore(args.state_dir)
    if args.action == 'create-key':
        print('Local OS-vault reference:', vault.store(secrets.token_hex(32)))
        return
    if args.action == 'import-key':
        key = getpass('Enter the 64-character shared pairing key (hidden): ').lower()
        if not re.fullmatch(r'[0-9a-f]{64}', key):
            parser.error('A full random 256-bit key is required')
        print('Local OS-vault reference:', vault.store(key))
        return
    if args.action == 'new-client-auth':
        ref, public = new_client_key(vault)
        print('Client credential vault reference:', ref)
        print('Public client authorisation key:', public)
        return
    secret = _secret(vault, args.key_ref)
    if args.action == 'send':
        if not args.control_socket or not args.client_auth_ref:
            parser.error('Tor sending requires --control-socket and --client-auth-ref')
        with TorControlSocket(args.control_socket) as control:
            control.client_authorisation(args.onion, vault, args.client_auth_ref)
        jid, receipt = TorPrintSender(secret).send(args.pdf, args.printer, args.receiver_id,
                            args.onion, args.remote_port, socks_port=args.socks_port)
        print(jid, receipt['state'])
        return
    printers = {}
    for item in args.printer:
        remote, sep, local = item.partition('=')
        if not sep or not local:
            parser.error('Use remote-id=local-CUPS-queue')
        printers[validate_printer_id(remote)] = validate_printer_id(local)
    receiver_id = ReceiverIdentity(args.state_dir / 'tor-identity').load_or_create()
    print('Receiver ID:', receiver_id)
    if args.enable_printing:
        parser.error('Automatic printing of remote Tor jobs is disabled; release held jobs in the desktop app')
    receiver = TorPrintReceiver(secret, receiver_id, args.state_dir / 'tor', printers,
                                queue=LocalQueue(args.queue_state_dir or default_state_dir()))
    if not args.control_socket or not args.client_public:
        parser.error('Receiving requires a private Tor ControlSocket and at least one approved client')
    with TorPrintListener(receiver, args.listen_port) as listener:
        if args.control_socket:
            with TorControlSocket(args.control_socket) as control:
                onion = control.ephemeral_service(args.client_public, listener.server_address[1])
                print('Ephemeral, client-authorised Tor service:', onion, flush=True)
                listener.serve_forever(poll_interval=0.5)
        else:
            listener.serve_forever(poll_interval=0.5)

if __name__ == '__main__':
    main()
