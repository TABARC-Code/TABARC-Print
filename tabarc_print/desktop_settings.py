"""Per-user desktop preferences. Never store account tokens here."""
from __future__ import annotations

import json
import os
from pathlib import Path
import stat

from .common import atomic_write


class DesktopSettings:
    def __init__(self, state_root):
        self.file = Path(state_root) / 'desktop-settings.json'

    def renderer(self):
        path = self.file
        if path.is_symlink():
            raise ValueError('Desktop settings must not be a symbolic link')
        if not path.exists():
            return None
        details = path.stat()
        if not stat.S_ISREG(details.st_mode) or details.st_size > 4096:
            raise ValueError('Invalid desktop settings file')
        if os.name != 'nt' and details.st_mode & 0o077:
            raise PermissionError('Desktop settings must be private')
        settings = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(settings, dict) or set(settings) != {'windows_renderer'}:
            raise ValueError('Invalid desktop settings')
        path = settings['windows_renderer']
        if not isinstance(path, str) or len(path) > 1024:
            raise ValueError('Invalid PDF renderer setting')
        return path or None

    def set_renderer(self, executable):
        path = Path(executable).expanduser()
        if not path.is_absolute() or path.is_symlink() or not path.is_file() or path.name.lower() != 'sumatrapdf.exe':
            raise ValueError('Choose an installed, trusted SumatraPDF.exe file')
        if self.file.is_symlink():
            raise ValueError('Desktop settings must not be a symbolic link')
        atomic_write(self.file, json.dumps({'windows_renderer': str(path.resolve())}).encode('utf-8'))
        return str(path.resolve())
