"""Small, explicit Google Drive and Microsoft Graph mailbox adapters."""
import ipaddress
import json
import re
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, HTTPRedirectHandler, build_opener

from .common import MAX_FILE_BYTES
from .crypto import MAX_OVERHEAD

FILE_NAME = re.compile(r"^[0-9a-f]{32}\.(?:pdf|bin|job\.json|json)$")
DATA_LIMIT = MAX_FILE_BYTES + 65536


class CloudError(RuntimeError):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Transport:
    def __init__(self):
        self.opener = build_opener(NoRedirect())

    def request(self, method, url, token=None, body=None, headers=None, max_bytes=DATA_LIMIT):
        if urlsplit(url).scheme != 'https':
            raise CloudError('Cloud transport requires HTTPS')
        h = dict(headers or {})
        if token:
            h['Authorization'] = 'Bearer ' + token
        req = Request(url, data=body, headers=h, method=method)
        try:
            with self.opener.open(req, timeout=60) as response:
                data = response.read(max_bytes + 1)
                if len(data) > max_bytes:
                    raise CloudError('Cloud response exceeds size limit')
                return response.status, response.headers, data
        except HTTPError as err:
            # A Graph content download is a redirect to a temporary, preauthenticated URL.
            if err.code in (301, 302, 303, 307, 308):
                return err.code, err.headers, b''
            detail = err.read(1024).decode('utf-8', errors='replace')
            raise CloudError(f'Cloud API returned HTTP {err.code}: {detail[:250]}', err.code) from err
        except URLError as err:
            raise CloudError('Cloud network error: ' + str(err.reason)[:200]) from err


def checked_url(url, host, prefix):
    parts = urlsplit(url)
    if parts.scheme != 'https' or parts.hostname != host or not parts.path.startswith(prefix):
        raise CloudError('Unexpected cloud API URL')
    return url


def checked_download_url(url):
    parts = urlsplit(url)
    host = parts.hostname or ''
    if parts.scheme != 'https' or not host or host in ('localhost',) or host.endswith('.local') or parts.username or parts.password:
        raise CloudError('Unsafe download redirect')
    try:
        ipaddress.ip_address(host)
        raise CloudError('IP-address download redirects are not permitted')
    except ValueError:
        pass
    return url


def json_response(payload):
    try:
        return json.loads(payload)
    except (ValueError, UnicodeError) as exc:
        raise CloudError('Malformed JSON from cloud provider') from exc


def job_filename(name):
    if not isinstance(name, str) or not FILE_NAME.fullmatch(name):
        raise ValueError('Invalid cloud mailbox filename')
    return name


class GoogleDrive:
    provider = 'google'
    BASE = 'https://www.googleapis.com/drive/v3/files'
    UPLOAD = 'https://www.googleapis.com/upload/drive/v3/files'
    FOLDER_TYPE = 'application/vnd.google-apps.folder'

    def __init__(self, token, transport=None, folder_name='TABARC-Print'):
        self.token = token
        self.http = transport or Transport()
        self.folder_name = folder_name
        self.folders = {}

    def call(self, method, url, body=None, headers=None, max_bytes=DATA_LIMIT):
        checked_url(url, 'www.googleapis.com', '/drive/v3/files') if url.startswith(self.BASE) else checked_url(url, 'www.googleapis.com', '/upload/drive/v3/files')
        return self.http.request(method, url, self.token(), body, headers, max_bytes)

    def list_in(self, folder_id):
        q = f"'{folder_id}' in parents and trashed = false"
        params = {'q': q, 'fields': 'nextPageToken,incompleteSearch,files(id,name,mimeType,size)', 'pageSize': '1000'}
        items = []
        pages = 0
        while True:
            pages += 1
            if pages > 100:
                raise CloudError('Too many pages in cloud mailbox')
            _, _, payload = self.call('GET', self.BASE + '?' + urlencode(params), max_bytes=3*1024*1024)
            page = json_response(payload)
            if page.get('incompleteSearch'):
                raise CloudError('Google Drive returned an incomplete search')
            items.extend(page.get('files', []))
            nxt = page.get('nextPageToken')
            if not nxt:
                return items
            params['pageToken'] = nxt

    def ensure_subfolder(self, parent, name):
        matches = [f for f in self.list_in(parent) if f.get('name') == name and f.get('mimeType') == self.FOLDER_TYPE]
        if len(matches) > 1:
            raise CloudError('Multiple identically named Google Drive folders; resolve the conflict manually')
        if matches:
            return matches[0]['id']
        data = json.dumps({'name': name, 'mimeType': self.FOLDER_TYPE, 'parents': [parent]}).encode()
        _, _, payload = self.call('POST', self.BASE + '?fields=id,name', data, {'Content-Type': 'application/json'})
        folder_id = json_response(payload)['id']
        matches = [f for f in self.list_in(parent) if f.get('name') == name and f.get('mimeType') == self.FOLDER_TYPE]
        if len(matches) > 1:
            raise CloudError('Duplicate Google Drive folders were created concurrently; resolve manually')
        return folder_id

    def folder(self, kind):
        if kind not in ('inbox', 'receipts'):
            raise ValueError('Unknown mailbox folder')
        if not self.folders:
            root = self.ensure_subfolder('root', self.folder_name)
            self.folders = {'inbox': self.ensure_subfolder(root, 'inbox'),
                            'receipts': self.ensure_subfolder(root, 'receipts')}
        return self.folders[kind]

    def list_files(self, kind):
        return [f for f in self.list_in(self.folder(kind)) if f.get('mimeType') != self.FOLDER_TYPE]

    def upload(self, kind, name, content, mime='application/octet-stream'):
        job_filename(name)
        if len(content) > MAX_FILE_BYTES + MAX_OVERHEAD:
            raise ValueError('Upload too large')
        metadata = json.dumps({'name': name, 'parents': [self.folder(kind)], 'mimeType': mime}).encode()
        url = self.UPLOAD + '?uploadType=resumable&fields=id,name'
        _, headers, _ = self.call('POST', url, metadata, {
            'Content-Type': 'application/json; charset=UTF-8',
            'X-Upload-Content-Type': mime,
            'X-Upload-Content-Length': str(len(content))}, max_bytes=2048)
        session = headers.get('Location', '')
        checked_url(session, 'www.googleapis.com', '/upload/drive/v3/files')
        status, _, payload = self.call('PUT', session, content, {'Content-Type': mime}, max_bytes=4096)
        if status not in (200, 201):
            raise CloudError('Google upload did not complete')
        return json_response(payload)['id']

    def download(self, item_id, max_bytes=DATA_LIMIT):
        _, _, payload = self.call('GET', self.BASE + '/' + quote(item_id, safe='') + '?alt=media', max_bytes=max_bytes)
        return payload

    def delete(self, item_id):
        self.call('DELETE', self.BASE + '/' + quote(item_id, safe=''), max_bytes=4096)


class OneDrive:
    provider = 'onedrive'
    BASE = 'https://graph.microsoft.com/v1.0'

    def __init__(self, token, transport=None, folder_name='TABARC-Print'):
        self.token = token
        self.http = transport or Transport()
        self.folder_name = folder_name
        self.folders = {}

    def call(self, method, path, body=None, headers=None, max_bytes=DATA_LIMIT):
        url = self.BASE + path if path.startswith('/') else path
        checked_url(url, 'graph.microsoft.com', '/v1.0/')
        return self.http.request(method, url, self.token(), body, headers, max_bytes)

    def find_or_create_folder(self, parent_id, name):
        folder_path = '/me/drive/root/children' if parent_id == 'root' else '/me/drive/items/' + quote(parent_id, safe='') + '/children'
        items = self.list_in(parent_id)
        match = next((x for x in items if x.get('name') == name and 'folder' in x), None)
        if match:
            return match['id']
        data = json.dumps({'name': name, 'folder': {}, '@microsoft.graph.conflictBehavior': 'fail'}).encode()
        try:
            _, _, payload = self.call('POST', folder_path, data, {'Content-Type': 'application/json'})
            return json_response(payload)['id']
        except CloudError as exc:
            if exc.status == 409:
                items = self.list_in(parent_id)
                match = next((x for x in items if x.get('name') == name and 'folder' in x), None)
                if match:
                    return match['id']
            raise

    def list_in(self, parent_id):
        path = '/me/drive/root/children' if parent_id == 'root' else '/me/drive/items/' + quote(parent_id, safe='') + '/children'
        url = self.BASE + path + '?$select=id,name,size,file,folder&$top=200'
        items = []
        for _ in range(100):
            _, _, payload = self.call('GET', url, max_bytes=3*1024*1024)
            page = json_response(payload)
            items.extend(page.get('value', []))
            url = page.get('@odata.nextLink')
            if not url:
                return items
            checked_url(url, 'graph.microsoft.com', '/v1.0/')
        raise CloudError('Too many pages in OneDrive mailbox')

    def folder(self, kind):
        if kind not in ('inbox', 'receipts'):
            raise ValueError('Unknown mailbox folder')
        if not self.folders:
            root = self.find_or_create_folder('root', self.folder_name)
            self.folders = {'inbox': self.find_or_create_folder(root, 'inbox'),
                            'receipts': self.find_or_create_folder(root, 'receipts')}
        return self.folders[kind]

    def list_files(self, kind):
        return [f for f in self.list_in(self.folder(kind)) if 'file' in f]

    def upload(self, kind, name, content, mime='application/octet-stream'):
        job_filename(name)
        if len(content) > MAX_FILE_BYTES + MAX_OVERHEAD:
            raise ValueError('Upload too large')
        parent = quote(self.folder(kind), safe='')
        path = '/me/drive/items/' + parent + ':/' + quote(name, safe='') + ':/content?@microsoft.graph.conflictBehavior=fail'
        _, _, payload = self.call('PUT', path, content,
                                  {'Content-Type': mime, 'If-None-Match': '*'})
        return json_response(payload)['id']

    def download(self, item_id, max_bytes=DATA_LIMIT):
        status, headers, payload = self.call('GET', '/me/drive/items/' + quote(item_id, safe='') + '/content', max_bytes=max_bytes)
        if status == 302:
            target = checked_download_url(headers.get('Location', ''))
            # Never send the Graph bearer token to a preauthenticated download URL.
            code, _, payload = self.http.request('GET', target, None, max_bytes=max_bytes)
            if code != 200:
                raise CloudError('Unexpected OneDrive download response')
        elif status != 200:
            raise CloudError('Unexpected OneDrive response')
        return payload

    def delete(self, item_id):
        self.call('DELETE', '/me/drive/items/' + quote(item_id, safe=''), max_bytes=4096)
