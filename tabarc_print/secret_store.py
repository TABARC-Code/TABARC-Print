"""Optional operating-system credential storage for cloud pairing keys."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import secrets

_KEY_REF = re.compile(r'^keyring:([0-9a-f]{32})$')


class SecretStore:
    def __init__(self, root: Path, backend=None):
        self.root = Path(root).resolve()
        self.service = 'TABARC Print - ' + hashlib.sha256(str(self.root).encode()).hexdigest()[:24]
        if backend is None:
            try:
                import keyring
                current = keyring.get_keyring()
                backend_module = type(current).__module__
                permitted = ('keyring.backends.Windows', 'keyring.backends.macOS',
                             'keyring.backends.SecretService', 'keyring.backends.kwallet',
                             'keyring.backends.libsecret')
                self.backend = current if getattr(current, 'priority', 0) > 0 and backend_module.startswith(permitted) else None
            except (ImportError, RuntimeError):
                self.backend = None
        else:
            self.backend = backend

    def require(self):
        if self.backend is None:
            raise RuntimeError('OS credential vault required; plaintext secret storage is disabled')
        return self.backend

    def put_named(self, name: str, value: str):
        if not re.fullmatch(r'[a-z0-9_.-]{1,64}', name):
            raise ValueError('Invalid vault entry name')
        self.require().set_password(self.service, name, value)

    def get_named(self, name: str):
        if not re.fullmatch(r'[a-z0-9_.-]{1,64}', name):
            raise ValueError('Invalid vault entry name')
        return self.require().get_password(self.service, name)

    def delete_named(self, name: str):
        if not re.fullmatch(r'[a-z0-9_.-]{1,64}', name):
            raise ValueError('Invalid vault entry name')
        vault = self.require()
        existing = vault.get_password(self.service, name)
        if existing is None:
            return False
        vault.delete_password(self.service, name)
        return True

    @staticmethod
    def is_reference(value):
        return isinstance(value, str) and bool(_KEY_REF.fullmatch(value))

    def store(self, value):
        if self.backend is None:
            raise RuntimeError('No usable operating-system credential store; install and configure keyring')
        ref = 'keyring:' + secrets.token_hex(16)
        self.backend.set_password(self.service, ref, value)
        return ref

    def read(self, ref):
        if not self.is_reference(ref):
            raise ValueError('Invalid credential reference')
        if self.backend is None:
            raise RuntimeError('Operating-system credential storage is unavailable')
        value = self.backend.get_password(self.service, ref)
        if not value:
            raise RuntimeError('Pairing key is missing from the operating-system credential store')
        return value

    def remove(self, ref):
        if not self.is_reference(ref) or self.backend is None:
            return
        try:
            self.backend.delete_password(self.service, ref)
        except Exception:
            pass
