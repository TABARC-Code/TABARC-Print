"""Built-in print and transport plug-ins.

The registry is deliberately explicit. Installing a wheel or adding a file must not
make the privileged print service execute new code without operator approval.
"""
from dataclasses import dataclass
import os
import re
from pathlib import Path
import subprocess
from typing import Callable

from .common import spool_pdf


@dataclass(frozen=True)
class PluginInfo:
    name: str
    kind: str
    description: str
    permissions: tuple[str, ...]
    optional: bool = False


class PrinterBackend:
    """Thin adapter. Submission only means the OS accepted the job."""

    def __init__(self, name: str):
        self.name = name

    def submit(self, document: Path, printer: str, *, dry_run: bool = False,
               windows_renderer: str | None = None) -> str:
        return spool_pdf(document, printer, dry_run=dry_run,
                         backend=self.name, windows_renderer=windows_renderer)

    def submit_bytes(self, pdf: bytes, printer: str, *, dry_run=False) -> str:
        """Submit a PDF through CUPS stdin, without a plaintext temporary file."""
        from .common import validate_pdf
        validate_pdf(pdf)
        if self.name != 'cups':
            raise RuntimeError('Secure in-memory PDF submission is not available for this backend')
        if not isinstance(printer, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,79}', printer):
            raise ValueError('Invalid CUPS printer queue')
        if dry_run:
            return 'DRY_RUN'
        finished = subprocess.run(['lp', '-d', printer, '-'], input=pdf,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  timeout=120, check=False)
        if finished.returncode:
            raise RuntimeError('The local CUPS spooler rejected this document')
        return finished.stdout.decode('utf-8', errors='replace')[:200]


class PluginRegistry:
    def __init__(self):
        self._plugins = {
            'cups': PluginInfo('cups', 'printer', 'CUPS/IPP queues on Unix', ('local-printer',)),
            'windows-sumatra': PluginInfo('windows-sumatra', 'printer',
                 'Windows PDF renderer and local spooler', ('local-printer', 'local-executable')),
            'tor-onion': PluginInfo('tor-onion', 'transport',
                 'Tor v3 onion-only encrypted peer transport (experimental)', ('local-tor-proxy', 'approved-remote-peer'), True),
            'folder': PluginInfo('folder', 'transport',
                 'Private folder, optionally synchronised by a cloud client', ('folder-read', 'folder-write')),
            'google': PluginInfo('google', 'transport',
                 'Google Drive app files', ('cloud-oauth', 'cloud-file-access'), True),
            'onedrive': PluginInfo('onedrive', 'transport',
                 'Microsoft Graph files', ('cloud-oauth', 'cloud-file-access'), True),
        }

    def list(self, kind=None):
        if kind not in (None, 'printer', 'transport'):
            raise ValueError('Unsupported plug-in kind')
        return tuple(p for p in self._plugins.values() if kind is None or p.kind == kind)

    def printer(self, name='auto'):
        if name == 'auto':
            name = 'windows-sumatra' if os.name == 'nt' else 'cups'
        info = self._plugins.get(name)
        if info is None or info.kind != 'printer':
            raise ValueError('Printer plug-in is not approved: ' + str(name))
        return PrinterBackend(name)

    def cloud_store(self, name: str, credentials):
        if name == 'google':
            from .cloud_api import GoogleDrive
            return GoogleDrive(credentials)
        if name == 'onedrive':
            from .cloud_api import OneDrive
            return OneDrive(credentials)
        raise ValueError('Not a supported direct cloud transport: ' + str(name))


def parse_cups_job_reference(response: str) -> str | None:
    """Capture the identifier returned by lp; not evidence of physical printing."""
    if not isinstance(response, str) or any(char in response for char in '\r\n\x00'):
        return None
    match = re.search(r'\brequest id is ([A-Za-z0-9][A-Za-z0-9._-]{0,159})(?=\s|$)', response)
    return match.group(1) if match else None


REGISTRY = PluginRegistry()


def discover_printers(backend='auto') -> list[str]:
    """Read-only discovery, with a fixed executable and bounded output."""
    resolved = REGISTRY.printer(backend).name
    if resolved == 'cups':
        command = ['lpstat', '-e']
    else:
        if os.name != 'nt':
            raise RuntimeError('Windows printer discovery requires Windows')
        command = ['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
                   'Get-Printer | Select-Object -ExpandProperty Name']
    result = subprocess.run(command, capture_output=True, text=True, timeout=15,
                            check=False)
    if result.returncode:
        raise RuntimeError('Printer discovery failed: ' + result.stderr[:200])
    if len(result.stdout) > 65536:
        raise ValueError('Too many printer names returned')
    return sorted(set(line.strip() for line in result.stdout.splitlines() if line.strip()))
