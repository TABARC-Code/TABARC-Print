"""Stable identity for an installed receiver, kept outside shared pairing settings."""
from __future__ import annotations

import os
from pathlib import Path
import re
import secrets
import stat

from .cloud_auth import private_auth_dir

RECEIVER_ID = re.compile(r'^[0-9a-f]{32}$')


def check_receiver_id(value):
    if not isinstance(value, str) or not RECEIVER_ID.fullmatch(value):
        raise ValueError('Receiver ID must contain 32 lowercase hexadecimal characters')
    return value


class ReceiverIdentity:
    def __init__(self, root):
        self.root = private_auth_dir(root)
        self.path = self.root / 'receiver-id'

    def load_or_create(self):
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
            fd = os.open(self.path, flags, 0o600)
        except FileExistsError:
            pass
        else:
            try:
                value = secrets.token_hex(16)
                with os.fdopen(fd, 'w', encoding='ascii') as file:
                    file.write(value)
                    file.flush()
                    os.fsync(file.fileno())
            except Exception:
                self.path.unlink(missing_ok=True)
                raise
        if self.path.is_symlink():
            raise ValueError('Receiver identity cannot be a symbolic link')
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
        with os.fdopen(os.open(self.path, flags), 'rb') as file:
            info = os.fstat(file.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size != 32:
                raise ValueError('Invalid receiver identity file')
            if os.name != 'nt' and info.st_mode & 0o077:
                raise PermissionError('Receiver identity must have mode 0600')
            raw = file.read(33)
        return check_receiver_id(raw.decode('ascii'))
