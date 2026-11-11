"""Explicit, per-user Linux service setup. No root installer or hosted server."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

from .common import atomic_write

MARKER = '# Installed by TABARC Print (user service)'
UNIT_FILENAME = 'tabarc-print.service'


def _unit_argument(value):
    text = str(value)
    if not text or any(c in text for c in '\r\n\x00'):
        raise ValueError('Invalid systemd argument')
    # systemd expands percent specifiers and $ variables even in quoted values.
    return '"' + text.replace('\\', '\\\\').replace('"', '\\"').replace('%', '%%').replace('$', '$$') + '"'


def generate_unit(python_path=None, state_dir=None, backend='auto', interval=3):
    if backend not in ('auto', 'cups'):
        raise ValueError('Linux service supports CUPS or auto')
    if interval < 1 or interval > 300:
        raise ValueError('Worker interval must be 1–300 seconds')
    binary = Path(python_path or sys.executable).expanduser()
    if not binary.is_absolute():
        raise ValueError('Python executable must be an absolute path')
    argv = [str(binary), '-m', 'tabarc_print.local']
    if state_dir is not None:
        location = Path(state_dir).expanduser()
        if not location.is_absolute():
            raise ValueError('State directory must be an absolute path')
        argv.extend(['--state-dir', str(location)])
    argv.extend(['--backend', backend, 'work', '--interval', str(interval)])
    command = ' '.join(_unit_argument(value) for value in argv)
    return (MARKER + '\n'
        '[Unit]\nDescription=TABARC Print local queue worker\n'
        '[Service]\nType=simple\nExecStart=' + command + '\n'
        'Restart=on-failure\nRestartSec=5\nUMask=0077\nNoNewPrivileges=true\n'
        '[Install]\nWantedBy=default.target\n')


def unit_path(home=None):
    return (Path(home).expanduser() if home is not None else Path.home()) / '.config' / 'systemd' / 'user' / UNIT_FILENAME


def install_unit(path, content):
    path = Path(path)
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError('Service destination must be a regular file')
    if path.exists() and not path.read_text(encoding='utf-8').startswith(MARKER):
        raise ValueError('Existing service was not installed by TABARC Print; not overwriting')
    if path.parent.is_symlink():
        raise ValueError('Service directory must not be a symbolic link')
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(path, content.encode('utf-8'))
    if os.name != 'nt':
        path.chmod(0o600)


def remove_unit(path):
    path = Path(path)
    if not path.exists():
        return False
    if path.is_symlink() or not path.is_file() or not path.read_text(encoding='utf-8').startswith(MARKER):
        raise ValueError('Refusing to remove unrecognised service file')
    path.unlink()
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description='Install a local Linux systemd user worker')
    parser.add_argument('action', choices=('show', 'install', 'remove'))
    parser.add_argument('--state-dir', type=Path)
    parser.add_argument('--backend', default='auto', choices=('auto', 'cups'))
    parser.add_argument('--interval', type=int, default=3)
    args = parser.parse_args(argv)
    if sys.platform != 'linux':
        parser.error('This helper is for Linux systemd user services only')
    location = unit_path()
    if args.action == 'remove':
        print('Removed' if remove_unit(location) else 'Already absent', location)
        print('Run: systemctl --user daemon-reload')
        return 0
    content = generate_unit(state_dir=args.state_dir, backend=args.backend, interval=args.interval)
    if args.action == 'show':
        print(content)
        return 0
    install_unit(location, content)
    print('Installed', location)
    print('To activate, run:')
    print('  systemctl --user daemon-reload')
    print('  systemctl --user enable --now tabarc-print.service')
    print('To stop: systemctl --user disable --now tabarc-print.service')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
