"""Restricted Unix-domain Tor controller. No TCP control port or disk key exports."""
from __future__ import annotations

import base64
import os
from pathlib import Path
import re
import socket
import stat

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization


_PUBLIC = re.compile(r'^[a-z2-7]{52}$')
_MAX_LINE = 4096


def check_public_key(value: str) -> str:
    if not isinstance(value, str) or not _PUBLIC.fullmatch(value):
        raise ValueError('Tor client public key must be 52 lowercase base32 characters')
    try:
        raw = base64.b32decode(value.upper() + '====', casefold=False)
    except Exception as exc:
        raise ValueError('Invalid Tor client public key') from exc
    if len(raw) != 32 or not any(raw):
        raise ValueError('Invalid Tor client public key')
    return value


def new_client_key(store):
    private = X25519PrivateKey.generate()
    raw = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                serialization.NoEncryption())
    public = private.public_key().public_bytes(serialization.Encoding.Raw,
                                               serialization.PublicFormat.Raw)
    reference = store.store(raw.hex())
    return reference, base64.b32encode(public).decode('ascii').lower().rstrip('=')


def _client_key(store, reference):
    raw = store.read(reference)
    if not isinstance(raw, str) or not re.fullmatch(r'[0-9a-f]{64}', raw):
        raise ValueError('Invalid client authorisation key in vault')
    return base64.b64encode(bytes.fromhex(raw)).decode('ascii').rstrip('=')


class TorControlSocket:
    """ControlSocket with OS-owned peer and NULL authentication, never network control."""

    def __init__(self, path):
        self.path = Path(path)
        self.sock = None
        self.input = b''

    def __enter__(self):
        if not hasattr(socket, 'AF_UNIX') or os.name == 'nt' or not hasattr(os, 'getuid'):
            raise RuntimeError('Secure Tor ControlSocket requires a Unix account')
        directory = self.path.parent
        parent = directory.lstat()
        target = self.path.lstat()
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid() or parent.st_mode & 0o077:
            raise PermissionError('Tor control directory must be owned by this user with mode 0700')
        if not stat.S_ISSOCK(target.st_mode) or target.st_uid != os.getuid() or target.st_mode & 0o077:
            raise PermissionError('Tor control socket must be owned by this user and private')
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(10)
        try:
            sock.connect(str(self.path))
            if hasattr(socket, 'SO_PEERCRED'):
                import struct
                uid = struct.unpack('3i', sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[1]
                if uid != os.getuid():
                    raise PermissionError('Tor control peer has an unexpected user identity')
            self.sock = sock
            protocol = self.command('PROTOCOLINFO 1')
            if not any(line.startswith('250-AUTH ') and
                       'NULL' in line.partition('METHODS=')[2].split()[0].split(',')
                       for line in protocol if 'METHODS=' in line):
                raise PermissionError('Tor ControlSocket must advertise NULL authentication on a private Unix socket')
            self.command('AUTHENTICATE')
            return self
        except BaseException:
            sock.close()
            self.sock = None
            raise

    def __exit__(self, *_):
        if self.sock:
            self.sock.close()
            self.sock = None

    def _line(self):
        while b'\n' not in self.input:
            block = self.sock.recv(1024)
            if not block:
                raise ConnectionError('Tor control connection closed')
            if len(self.input) + len(block) > _MAX_LINE * 2:
                raise ValueError('Tor control response exceeded the size limit')
            self.input += block
        line, self.input = self.input.split(b'\n', 1)
        if len(line) > _MAX_LINE or not line.endswith(b'\r'):
            raise ValueError('Invalid Tor control line')
        return line[:-1].decode('ascii', 'strict')

    def command(self, message):
        if not self.sock or not isinstance(message, str) or any(x in message for x in ('\r', '\n', '\x00')):
            raise ValueError('Invalid Tor control command')
        data = message.encode('ascii')
        if len(data) > _MAX_LINE:
            raise ValueError('Tor control command too long')
        self.sock.sendall(data + b'\r\n')
        lines = []
        for _ in range(32):
            line = self._line()
            if not re.fullmatch(r'[0-9]{3}[ -].*', line):
                raise ValueError('Unexpected Tor control response framing')
            lines.append(line)
            if line[3] == ' ':
                if line[:3] not in ('250', '251', '252'):
                    raise RuntimeError('Tor rejected the requested control operation')
                return lines
        raise ValueError('Too many Tor control response lines')

    def ephemeral_service(self, public_keys: list[str], local_port: int, virtual_port=8787):
        if not public_keys or len(public_keys) > 16:
            raise ValueError('An onion service requires 1 to 16 approved clients')
        if not isinstance(local_port, int) or not 1 <= local_port <= 65535:
            raise ValueError('Invalid local port')
        if not isinstance(virtual_port, int) or not 1 <= virtual_port <= 65535:
            raise ValueError('Invalid virtual port')
        unique = list(dict.fromkeys(check_public_key(key) for key in public_keys))
        msg = ('ADD_ONION NEW:ED25519-V3 Flags=DiscardPK,V3Auth '
               f'Port={virtual_port},127.0.0.1:{local_port} ' +
               ' '.join('ClientAuthV3=' + key for key in unique))
        reply = self.command(msg)
        if any('PrivateKey=' in line for line in reply):
            raise RuntimeError('Tor unexpectedly returned an onion private key')
        services = [line[14:] for line in reply if line.startswith('250-ServiceID=')]
        if len(services) != 1:
            raise RuntimeError('Tor did not return one onion service identity')
        from .tor_transport import check_onion
        return check_onion(services[0] + '.onion')

    def client_authorisation(self, onion: str, vault, reference: str):
        from .tor_transport import check_onion
        check_onion(onion)
        private = _client_key(vault, reference)
        # No Permanent flag: Tor keeps this credential in memory only.
        self.command(f'ONION_CLIENT_AUTH_ADD {onion[:-6]} x25519:{private}')
