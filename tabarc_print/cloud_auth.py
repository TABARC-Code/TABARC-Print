"""Separate OAuth login and short-lived API access tokens from the print queue."""
import json
import os
from pathlib import Path
from .secret_store import SecretStore

GOOGLE_SCOPE = 'https://www.googleapis.com/auth/drive.file'
MS_SCOPES = ['Files.ReadWrite']


def private_auth_dir(path):
    path = Path(path).expanduser()
    if path.exists() and path.is_symlink():
        raise ValueError('Token folder cannot be a symlink')
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != 'nt' and path.stat().st_mode & 0o077:
        raise PermissionError('Token folder is accessible to other users; chmod 700 ' + str(path))
    return path


def _private_token_file(path):
    if path.is_symlink():
        raise ValueError('Token cache cannot be a symlink')
    if path.exists() and os.name != 'nt' and path.stat().st_mode & 0o077:
        raise PermissionError('Token file is accessible to other users; chmod 600 ' + str(path))


class GoogleAuth:
    def __init__(self, state, credentials_file=None, vault=None):
        self.state = private_auth_dir(state)
        self.cache = self.state / 'google-token.json'
        self.vault = vault or SecretStore(self.state)
        self.credentials_file = credentials_file
        self.credentials = None

    def _refuse_legacy(self):
        if self.cache.exists() or self.cache.is_symlink():
            raise PermissionError('Legacy plaintext OAuth token cache detected. Revoke and remove it before signing in.')

    def login(self):
        self._refuse_legacy()
        if not self.credentials_file:
            raise ValueError('Provide --google-credentials (desktop OAuth client JSON)')
        try:
            from google_auth_oauthlib.flow import InstalledAppFlow
        except ImportError as exc:
            raise RuntimeError('Install the optional Google OAuth packages from requirements-cloud.txt') from exc
        if not SecretStore.is_reference(self.credentials_file):
            raise PermissionError('Google OAuth registration must be stored in the OS vault')
        registration = self.vault.read(self.credentials_file)
        try:
            settings = json.loads(registration)
            if not isinstance(settings, dict) or not isinstance(settings.get('installed'), dict):
                raise ValueError()
        except (ValueError, TypeError) as exc:
            raise ValueError('Invalid vaulted Google OAuth registration') from exc
        flow = InstalledAppFlow.from_client_config(settings, [GOOGLE_SCOPE])
        self.credentials = flow.run_local_server(host='localhost', port=0, open_browser=True,
                                                  access_type='offline', prompt='consent')
        self._refuse_legacy()
        self.vault.put_named('oauth.google.v1', self.credentials.to_json())

    def __call__(self):
        try:
            from google.oauth2.credentials import Credentials
            from google.auth.transport.requests import Request
        except ImportError as exc:
            raise RuntimeError('Install the optional Google OAuth packages from requirements-cloud.txt') from exc
        self._refuse_legacy()
        if self.credentials is None:
            encoded = self.vault.get_named('oauth.google.v1')
            if encoded is None:
                raise RuntimeError('Google account not connected; sign in again')
            self.credentials = Credentials.from_authorized_user_info(json.loads(encoded), [GOOGLE_SCOPE])
        if not self.credentials.valid:
            if not self.credentials.refresh_token:
                raise RuntimeError('Google refresh token missing; run login again')
            self.credentials.refresh(Request())
            self.vault.put_named('oauth.google.v1', self.credentials.to_json())
        return self.credentials.token


class MicrosoftAuth:
    def __init__(self, state, client_id, tenant='consumers', vault=None):
        self.state = private_auth_dir(state)
        self.cache = self.state / 'microsoft-msal-cache.json'
        self.vault = vault or SecretStore(self.state)
        if self.cache.exists() or self.cache.is_symlink():
            raise PermissionError('Legacy plaintext Microsoft token cache detected. Revoke and remove it before signing in.')
        if not client_id:
            raise ValueError('Provide --microsoft-client-id')
        if tenant not in ('consumers', 'organizations', 'common') and not (len(tenant) == 36 and tenant.count('-') == 4):
            raise ValueError('Invalid Microsoft tenant')
        try:
            import msal
        except ImportError as exc:
            raise RuntimeError('Install the optional MSAL dependency from requirements-cloud.txt') from exc
        self.msal = msal
        self.cache_obj = msal.SerializableTokenCache()
        saved = self.vault.get_named('oauth.microsoft.v1')
        if saved is not None:
            self.cache_obj.deserialize(saved)
        self.app = msal.PublicClientApplication(client_id,
            authority=f'https://login.microsoftonline.com/{tenant}', token_cache=self.cache_obj)

    def persist(self):
        if self.cache_obj.has_state_changed:
            self.vault.put_named('oauth.microsoft.v1', self.cache_obj.serialize())

    def login(self, notify=None):
        flow = self.app.initiate_device_flow(scopes=MS_SCOPES)
        if 'user_code' not in flow:
            raise RuntimeError('Microsoft device login could not start')
        if notify is None:
            print(flow['message'])
        else:
            notify({'message': flow['message'], 'code': flow['user_code'],
                    'url': flow.get('verification_uri', 'https://microsoft.com/devicelogin')})
        token = self.app.acquire_token_by_device_flow(flow)
        self.persist()
        if 'access_token' not in token:
            raise RuntimeError('Microsoft login failed: ' + token.get('error_description', str(token.get('error', 'unknown'))))

    def __call__(self):
        accounts = self.app.get_accounts()
        if len(accounts) != 1:
            raise RuntimeError('Microsoft token cache must contain exactly one account; use a dedicated state folder')
        token = self.app.acquire_token_silent(MS_SCOPES, account=accounts[0])
        self.persist()
        if not token or 'access_token' not in token:
            raise RuntimeError('Microsoft session expired; run cloud-gateway login')
        return token['access_token']
