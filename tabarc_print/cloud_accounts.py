"""Local cloud-account settings. No cloud connection is necessary for local printing."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import stat

from .cloud_auth import GoogleAuth, MicrosoftAuth, private_auth_dir
from .common import atomic_write
from .secret_store import SecretStore

is_reference = SecretStore.is_reference

CLIENT_ID = re.compile(r'^[0-9a-fA-F]{8}-(?:[0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')


def default_auth_dir() -> Path:
    # Match the original CLI default, so an existing login remains usable.
    return Path.home() / '.config' / 'tabarc-print'


class CloudAccountSettings:
    """Persist only public OAuth configuration. Provider tokens stay in their own caches."""

    def __init__(self, root=None):
        self.root = private_auth_dir(root or default_auth_dir())
        self.path = self.root / 'account-settings.json'

    def load(self):
        if self.path.is_symlink():
            raise ValueError('Account settings may not be a symbolic link')
        if not self.path.exists():
            return {'google_credentials': '', 'microsoft_client_id': '', 'microsoft_tenant': 'consumers'}
        info = self.path.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 8192:
            raise ValueError('Unexpected account settings file')
        if os.name != 'nt' and info.st_mode & 0o077:
            raise PermissionError('Account settings must be private (chmod 600)')
        data = json.loads(self.path.read_text(encoding='utf-8'))
        if not isinstance(data, dict) or set(data) != {'google_credentials', 'microsoft_client_id', 'microsoft_tenant'}:
            raise ValueError('Invalid account settings')
        if any(not isinstance(v, str) or len(v) > 1024 for v in data.values()):
            raise ValueError('Invalid account settings values')
        if data['google_credentials'] and not is_reference(data['google_credentials']):
            raise PermissionError('Legacy Google OAuth client JSON path refused; re-import into the OS vault')
        return data

    def save(self, google_credentials='', microsoft_client_id='', microsoft_tenant='consumers'):
        google_credentials = google_credentials.strip()
        microsoft_client_id = microsoft_client_id.strip()
        microsoft_tenant = microsoft_tenant.strip()
        payload = None
        if google_credentials and not is_reference(google_credentials):
            path = Path(google_credentials).expanduser()
            if not path.is_absolute() or path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
                raise ValueError('Choose a local, regular Google desktop OAuth JSON file under 64 KB')
            try:
                payload = json.loads(path.read_text(encoding='utf-8'))
            except (ValueError, UnicodeError) as exc:
                raise ValueError('Google credentials are not valid JSON') from exc
            if not isinstance(payload, dict) or not isinstance(payload.get('installed'), dict) or not payload['installed'].get('client_id'):
                raise ValueError('Expected an installed-app Google OAuth client JSON file')
        if microsoft_client_id and not CLIENT_ID.fullmatch(microsoft_client_id):
            raise ValueError('Microsoft client ID must be a valid UUID')
        if microsoft_tenant not in ('consumers', 'organizations', 'common') and not CLIENT_ID.fullmatch(microsoft_tenant):
            raise ValueError('Invalid Microsoft tenant')
        if self.path.is_symlink():
            raise ValueError('Account settings may not be a symbolic link')
        previous = self.load()
        previous_ref = previous['google_credentials']
        reference = ''
        if payload is not None:
            reference = SecretStore(self.root).store(json.dumps(payload, sort_keys=True))
        elif google_credentials:
            if not is_reference(google_credentials):
                raise ValueError('Invalid Google credentials vault reference')
            reference = google_credentials
        config = {'google_credentials': reference,
                  'microsoft_client_id': microsoft_client_id,
                  'microsoft_tenant': microsoft_tenant}
        try:
            atomic_write(self.path, json.dumps(config, sort_keys=True).encode('utf-8'))
        except Exception:
            if payload is not None:
                SecretStore(self.root).remove(reference)
            raise
        if previous_ref and previous_ref != reference:
            SecretStore(self.root).remove(previous_ref)
        return config

    def _token_path(self, provider):
        files = {'google': 'google-token.json', 'onedrive': 'microsoft-msal-cache.json'}
        if provider not in files:
            raise ValueError('Unsupported account provider')
        return self.root / files[provider]

    def status(self, provider):
        settings = self.load()
        configured = bool(settings['google_credentials'] if provider == 'google' else settings['microsoft_client_id'])
        token = self._token_path(provider)
        if token.exists() or token.is_symlink():
            raise PermissionError('Legacy plaintext token cache detected. Revoke the token, remove the file and sign in again.')
        try:
            cached = SecretStore(self.root).get_named('oauth.google.v1' if provider == 'google' else 'oauth.microsoft.v1') is not None
            message = 'Vault token present; live session not checked' if cached else 'Ready to sign in' if configured else 'Set up the provider app first'
        except RuntimeError:
            cached = False
            message = 'OS credential vault unavailable; cloud sign-in disabled'
        return {'configured': configured, 'cached': cached, 'message': message}

    def sign_in(self, provider, notify=None):
        config = self.load()
        if provider == 'google':
            if not config['google_credentials']:
                raise ValueError('Choose Google credentials and save settings first')
            GoogleAuth(self.root, config['google_credentials']).login()
        elif provider == 'onedrive':
            if not config['microsoft_client_id']:
                raise ValueError('Save a Microsoft application ID first')
            MicrosoftAuth(self.root, config['microsoft_client_id'], config['microsoft_tenant']).login(notify=notify)
        else:
            raise ValueError('Unsupported account provider')
        return self.status(provider)

    def forget_local_token(self, provider):
        token = self._token_path(provider)
        if token.exists() or token.is_symlink():
            raise PermissionError('Legacy token cache must be handled separately; no automatic unsafe file migration')
        return SecretStore(self.root).delete_named('oauth.google.v1' if provider == 'google' else 'oauth.microsoft.v1')
