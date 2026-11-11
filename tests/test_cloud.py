import json
from contextlib import closing
from pathlib import Path
import tempfile
import unittest
from urllib.parse import urlsplit, parse_qs

from tabarc_print.cloud_api import CloudError, GoogleDrive, OneDrive, checked_download_url, job_filename
from tabarc_print.cloud_gateway import CloudGateway, verify_receipt
from tabarc_print.common import MAX_FILE_BYTES

PDF = b'%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n'
SECRET = b'print-mailbox-secret-at-least-32-bytes-123'


class MemoryCloud:
    def __init__(self):
        self.files = {'inbox': {}, 'receipts': {}}
        self.counter = 0
        self.receipt_fault = False

    def upload(self, kind, name, data, mime='application/octet-stream'):
        if self.receipt_fault and kind == 'receipts':
            self.receipt_fault = False
            raise CloudError('Simulated network outage')
        self.counter += 1
        ident = str(self.counter)
        self.files[kind][ident] = {'name': name, 'data': data}
        return ident

    def list_files(self, kind):
        return [{'id': key, 'name': value['name']} for key, value in self.files[kind].items()]

    def download(self, item_id, max_bytes=MAX_FILE_BYTES+65536):
        for items in self.files.values():
            if item_id in items:
                value = items[item_id]['data']
                if len(value) > max_bytes:
                    raise CloudError('Object is oversized')
                return value
        raise CloudError('Not found', 404)

    def delete(self, item_id):
        for items in self.files.values():
            if item_id in items:
                del items[item_id]
                return
        raise CloudError('Not found', 404)


class CloudMailboxTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = MemoryCloud()
        self.pdf = self.root / 'file.pdf'
        self.pdf.write_bytes(PDF)
        self.sender = CloudGateway(self.store, SECRET, self.root / 'send')
        self.receiver = CloudGateway(self.store, SECRET, self.root / 'receive', {'office':'local'}, dry_run=True, allow_direct_submission=True)

    def tearDown(self):
        self.tmp.cleanup()

    def test_direct_cloud_round_trip_receipt_and_cleanup(self):
        jid = self.sender.send(self.pdf, 'office')
        self.assertIsNone(self.sender.status(jid))
        self.assertEqual(self.receiver.once()[jid], 'submitted')
        self.assertEqual(self.sender.status(jid)['message'], 'DRY_RUN')
        self.assertEqual(len(self.store.list_files('inbox')), 0)
        self.assertEqual(self.receiver.once(), {})
        self.assertEqual(len(self.store.list_files('receipts')), 1)

    def test_tamper_rejected_and_never_printed(self):
        jid = self.sender.send(self.pdf, 'office')
        for f in self.store.files['inbox'].values():
            if f['name'] == jid + '.bin':
                f['data'] += b'evil'
        self.assertIn('integrity', self.receiver.once()[jid])
        self.assertIsNone(self.sender.status(jid))
        self.assertEqual(len(self.store.list_files('receipts')), 0)

    def test_failed_receipt_publish_never_resubmits(self):
        jid = self.sender.send(self.pdf, 'office')
        self.store.receipt_fault = True
        with self.assertRaises(CloudError):
            self.receiver.once()
        self.assertEqual(self.receiver.once(), {})
        self.assertEqual(self.sender.status(jid)['state'], 'submitted')
        self.assertEqual(len(self.store.list_files('inbox')), 0)
        self.assertEqual(len(self.store.list_files('receipts')), 1)

    def test_claim_crash_creates_uncertain_receipt(self):
        jid = self.sender.send(self.pdf, 'office')
        with closing(self.receiver.worker.db()) as db:
            db.execute('INSERT INTO processed(id,state,at) VALUES (?, ?, ?)', (jid, 'claimed', 12))
            db.commit()
        self.assertEqual(self.receiver.once()[jid], 'recovered')
        receipt = self.sender.status(jid)
        self.assertEqual(receipt['state'], 'uncertain')
        self.assertIn('inspect', receipt['message'])

    def test_receipt_tamper_caught(self):
        jid = self.sender.send(self.pdf, 'office')
        self.receiver.once()
        for file in self.store.files['receipts'].values():
            file['data'] = file['data'][:-1] + bytes([file['data'][-1] ^ 1])
        with self.assertRaises(ValueError):
            self.sender.status(jid)


class GoogleHttp:
    def __init__(self):
        self.calls = []
        self.folder_count = 0

    def request(self, method, url, token, body=None, headers=None, max_bytes=None):
        self.calls.append((method, url, token, body, headers))
        if method == 'GET' and url.startswith('https://www.googleapis.com/drive/v3/files?'):
            return (200, {}, b'{"files": []}')
        if method == 'POST' and '/upload/' in url:
            return (200, {'Location': 'https://www.googleapis.com/upload/drive/v3/files?upload_id=xyz'}, b'')
        if method == 'POST':
            self.folder_count += 1
            return (200, {}, json.dumps({'id': 'folder' + str(self.folder_count)}).encode())
        if method == 'PUT':
            return (200, {}, b'{"id":"pdf-id"}')
        if method == 'DELETE':
            return (204, {}, b'')
        return (200, {}, b'hello')


class ApiAdapterTests(unittest.TestCase):
    def test_google_upload_uses_resumable_session_and_app_folder(self):
        mock = GoogleHttp()
        drive = GoogleDrive(lambda: 'token', mock)
        ident = drive.upload('inbox', 'a'*32+'.pdf', PDF, 'application/pdf')
        self.assertEqual(ident, 'pdf-id')
        creation = [c for c in mock.calls if c[0] == 'POST' and '/upload/' in c[1]][0]
        metadata = json.loads(creation[3])
        self.assertEqual(metadata['parents'], ['folder2'])
        self.assertEqual(creation[4]['X-Upload-Content-Length'], str(len(PDF)))
        upload = [c for c in mock.calls if c[0] == 'PUT'][0]
        self.assertEqual(upload[3], PDF)
        self.assertTrue(all(c[2] == 'token' for c in mock.calls))

    def test_google_rejects_untrusted_upload_location(self):
        class EvilGoogle(GoogleHttp):
            def request(self, method, url, token, body=None, headers=None, max_bytes=None):
                if method == 'POST' and '/upload/' in url:
                    return (200, {'Location': 'https://fake-domain.com/upload/steal'}, b'')
                return super().request(method, url, token, body, headers, max_bytes)
        with self.assertRaises(CloudError):
            GoogleDrive(lambda: 'token', EvilGoogle()).upload('inbox', 'a'*32+'.pdf', PDF)

    def test_microsoft_download_redirect_does_not_leak_bearer_token(self):
        class FakeGraph:
            calls = []
            def request(self, method, url, token, body=None, headers=None, max_bytes=None):
                self.calls.append((url, token))
                if 'graph.microsoft.com' in url:
                    return (302, {'Location': 'https://files.1drv.com/download-id'}, b'')
                return (200, {}, PDF)
        mock = FakeGraph()
        drive = OneDrive(lambda: 'graph-token', mock)
        self.assertEqual(drive.download('abc'), PDF)
        self.assertEqual(mock.calls[0][1], 'graph-token')
        self.assertIsNone(mock.calls[1][1])

    def test_onedrive_upload_refuses_overwrite(self):
        class FakeGraph:
            def __init__(self):
                self.calls = []
            def request(self, method, url, token, body=None, headers=None, max_bytes=None):
                self.calls.append((method, url, token, body, headers))
                if method == 'GET':
                    return (200, {}, b'{"value": []}')
                if method == 'POST':
                    return (201, {}, b'{"id": "folder-id"}')
                return (201, {}, b'{"id":"uploaded"}')
        transport = FakeGraph()
        adapter = OneDrive(lambda: 'token', transport)
        result = adapter.upload('inbox', 'a'*32+'.pdf', PDF, 'application/pdf')
        self.assertEqual(result, 'uploaded')
        upload = [x for x in transport.calls if x[0] == 'PUT'][0]
        self.assertIn(':/content?@microsoft.graph.conflictBehavior=fail', upload[1])
        self.assertEqual(upload[4]['If-None-Match'], '*')

    def test_microsoft_list_uses_pagination(self):
        class FakeGraph:
            def request(self, method, url, token, body=None, headers=None, max_bytes=None):
                if 'nextpage' in url:
                    return (200, {}, b'{"value":[{"id":"2","name":"second"}]}')
                return (200, {}, json.dumps({'value':[{'id':'1','name':'first'}],
                       '@odata.nextLink':'https://graph.microsoft.com/v1.0/me/drive/root/children?nextpage=1'}).encode())
        self.assertEqual(len(OneDrive(lambda:'token', FakeGraph()).list_in('root')), 2)

    def test_reject_unsafe_redirects_and_file_names(self):
        for url in ('http://files.1drv.com/one', 'https://127.0.0.1/private',
                    'https://localhost/data'):
            with self.assertRaises(CloudError):
                checked_download_url(url)
        for name in ('../../pdf', 'otherfile.pdf', 'a'*32+'.pdf/../foo'):
            with self.assertRaises(ValueError):
                job_filename(name)

if __name__ == '__main__':
    unittest.main()
