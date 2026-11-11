"""Explicit, user-owned cloud print controls. Local printing never calls this module."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import secrets
import stat

from .cloud_accounts import CloudAccountSettings
from .cloud_auth import GoogleAuth, MicrosoftAuth, private_auth_dir
from .cloud_gateway import CloudGateway
from .common import atomic_write, safe_job_id, validate_printer_id
from .plugins import REGISTRY
from .secret_store import SecretStore
from .receiver_identity import ReceiverIdentity, check_receiver_id
from .local_queue import LocalQueue

PROVIDERS = ('google', 'onedrive')
KEY_FORMAT = re.compile(r'^[0-9a-fA-F]{64}$')


def _provider(value):
    if value not in PROVIDERS:
        raise ValueError('Choose Google Drive or OneDrive')
    return value


def _key_hex(value):
    if not isinstance(value, str) or not KEY_FORMAT.fullmatch(value):
        raise ValueError('Pairing key must be exactly 64 hexadecimal characters (256 bits)')
    return value.lower()


def _printer_name(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 255 or value.startswith('-') or any(c in value for c in '\r\n\x00'):
        raise ValueError('Invalid local printer name')
    return value


class CloudProfiles:
    """Pairing profiles contain no raw key when a credential vault is available."""

    def __init__(self, root, secret_store=None):
        self.root = private_auth_dir(root)
        self.path = self.root / 'cloud-profiles.json'
        self.secret_store = secret_store if secret_store is not None else SecretStore(self.root)

    @staticmethod
    def generate_key():
        return secrets.token_hex(32)

    @staticmethod
    def empty():
        return {'secret': '', 'remote_id': '', 'local_printer': '',
                'receive_enabled': False, 'receiver_id': ''}

    @staticmethod
    def validate(profile, *, stored=False):
        if not isinstance(profile, dict) or not set(profile).issubset(CloudProfiles.empty()) or not set(CloudProfiles.empty()) - {'receiver_id'} <= set(profile):
            raise ValueError('Invalid cloud pairing profile')
        value = profile['secret']
        if value and not (stored and SecretStore.is_reference(value)):
            _key_hex(value)
        if profile['remote_id']:
            validate_printer_id(profile['remote_id'])
        if profile['local_printer']:
            _printer_name(profile['local_printer'])
        if profile.get('receiver_id'):
            check_receiver_id(profile['receiver_id'])
        if not isinstance(profile['receive_enabled'], bool):
            raise ValueError('Invalid receiver setting')
        if profile['receive_enabled'] and not all(profile[k] for k in ('secret', 'remote_id', 'local_printer')):
            raise ValueError('Receiver requires a pairing key and a printer mapping')
        return profile

    def _read(self):
        if self.path.is_symlink():
            raise ValueError('Cloud pairing settings must not be a symbolic link')
        try:
            handle = os.open(self.path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        except FileNotFoundError:
            return {}
        with os.fdopen(handle, 'rb') as file:
            meta = os.fstat(file.fileno())
            if not stat.S_ISREG(meta.st_mode) or meta.st_size > 8192:
                raise ValueError('Invalid cloud pairing settings file')
            if os.name != 'nt' and meta.st_mode & 0o077:
                raise PermissionError('Cloud pairing settings must have mode 0600')
            raw = file.read(8193)
            if len(raw) > 8192:
                raise ValueError('Invalid cloud pairing settings file')
        data = json.loads(raw)
        if not isinstance(data, dict) or not set(data).issubset(PROVIDERS):
            raise ValueError('Invalid cloud pairing settings structure')
        for profile in data.values():
            self.validate(profile, stored=True)
            if profile['secret'] and not SecretStore.is_reference(profile['secret']):
                raise PermissionError('Plaintext pairing key found; legacy profiles are blocked. Re-pair using the OS vault.')
        return data

    def load(self, provider):
        profile = dict(self.empty())
        profile.update(self._read().get(_provider(provider), {}))
        if SecretStore.is_reference(profile['secret']):
            profile['secret'] = _key_hex(self.secret_store.read(profile['secret']))
        elif profile['secret']:
            raise PermissionError('Plaintext pairing key found; legacy profiles are blocked. Re-pair using the OS vault.')
        return profile

    def save(self, provider, *, secret, remote_id='', local_printer='',
             receive_enabled=False, receiver_id=''):
        provider = _provider(provider)
        profile = {
            'secret': _key_hex(secret) if secret else '',
            'remote_id': validate_printer_id(remote_id) if remote_id else '',
            'local_printer': _printer_name(local_printer) if local_printer else '',
            'receive_enabled': receive_enabled,
            'receiver_id': check_receiver_id(receiver_id) if receiver_id else '',
        }
        self.validate(profile)
        data = self._read()
        old_ref = data.get(provider, {}).get('secret', '')
        new_ref = ''
        if profile['secret']:
            new_ref = self.secret_store.store(profile['secret'])
            data[provider] = dict(profile, secret=new_ref)
        else:
            data[provider] = profile
        try:
            atomic_write(self.path, json.dumps(data, sort_keys=True).encode('utf-8'))
        except Exception:
            if new_ref:
                self.secret_store.remove(new_ref)
            raise
        if old_ref and old_ref != new_ref:
            self.secret_store.remove(old_ref)
        return profile


class CloudDesktopController:
    """Use the real cloud API only when a user explicitly requests an operation."""

    def __init__(self, accounts: CloudAccountSettings, state_dir, profiles=None, store_factory=None):
        self.accounts = accounts
        self.state_dir = private_auth_dir(state_dir)
        self.profiles = profiles or CloudProfiles(self.accounts.root)
        self.store_factory = store_factory or REGISTRY.cloud_store
        self.receiver_identity = ReceiverIdentity(self.state_dir)

    def receiver_id(self):
        return self.receiver_identity.load_or_create()

    def _gateway(self, provider, *, receiving=False, dry_run=False, backend='auto', windows_renderer=None):
        _provider(provider)
        profile = self.profiles.load(provider)
        if not profile['secret']:
            raise ValueError('Create or import a 256-bit pairing key before using cloud printing')
        status = self.accounts.status(provider)
        if not status['configured'] or not status['cached']:
            raise ValueError('Configure the provider and sign in under Cloud accounts first')
        config = self.accounts.load()
        if provider == 'google':
            auth = GoogleAuth(self.accounts.root, config['google_credentials'])
        else:
            auth = MicrosoftAuth(self.accounts.root, config['microsoft_client_id'], config['microsoft_tenant'])
        printers = None
        if receiving:
            if not profile['receive_enabled']:
                raise ValueError('Enable the receiving printer mapping before fetching cloud jobs')
            printers = {profile['remote_id']: profile['local_printer']}
        store = self.store_factory(provider, auth)
        gateway = CloudGateway(store, bytes.fromhex(profile['secret']),
            self.state_dir / provider, printers, dry_run=dry_run, encrypt=True,
            allow_legacy_plaintext=False, backend=backend, windows_renderer=windows_renderer,
            receiver_id=self.receiver_id() if receiving else None,
            target_receiver=profile['receiver_id'] if not receiving else None,
            queue=LocalQueue(self.state_dir.parent, backend=backend, windows_renderer=windows_renderer) if receiving else None)
        return gateway

    def send(self, provider, pdf, remote_id):
        validate_printer_id(remote_id)
        return self._gateway(provider).send(Path(pdf), remote_id)

    def status(self, provider, job_id):
        safe_job_id(job_id)
        return self._gateway(provider).status(job_id)

    def receive_once(self, provider, *, dry_run=False, backend='auto', windows_renderer=None):
        return self._gateway(provider, receiving=True, dry_run=dry_run,
                             backend=backend, windows_renderer=windows_renderer).once()
