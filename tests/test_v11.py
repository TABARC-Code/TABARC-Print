"""Secure metadata and ephemeral Tor control tests."""
import base64
from contextlib import closing
from pathlib import Path
import hashlib
import os
import socket
import stat
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from security_fixtures import local_vault_patch, TestVault
from tabarc_print.local_queue import LocalQueue
from tabarc_print.secret_store import SecretStore
from tabarc_print.tor_control import TorControlSocket, new_client_key, check_public_key

PDF = b'%PDF-1.7\n1 0 obj<<>>endobj\n%%EOF\n'


def sample_onion():
    key = bytes(range(32)); version = b'\x03'
    check = hashlib.sha3_256(b'.onion checksum' + key + version).digest()[:2]
    return base64.b32encode(key + check + version).decode().lower() + '.onion'


class ProtectedMetadataTests(unittest.TestCase):
    def setUp(self):
        self.patch_vault = local_vault_patch()
        self.patch_vault.start()
        self.addCleanup(self.patch_vault.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pdf = self.root/'secret-document.pdf'
        self.pdf.write_bytes(PDF)
        self.q = LocalQueue(self.root/'queue', backend='cups')

    def test_metadata_never_in_sqlite_cleartext(self):
        jid = self.q.submit(self.pdf, 'My-Custom-Laser-Printer', held=True)
        self.q.release(jid)
        with patch('tabarc_print.plugins.PrinterBackend.submit_bytes', return_value='request id is Laser-345 (1 file(s))'):
            self.q.process_one(jid)
        raw = self.q.db_path.read_bytes()
        for forbidden in (b'My-Custom-Laser-Printer', b'secret-document.pdf',
                          b'Laser-345', b'Hand-off to local spooler started',
                          b'Accepted by'):
            self.assertNotIn(forbidden, raw)
        item = self.q.status(jid)
        self.assertEqual(item['printer'], 'My-Custom-Laser-Printer')
        self.assertEqual(item['filename'], 'secret-document.pdf')
        self.assertEqual(item['spool_ref'], 'Laser-345')
        self.assertEqual(self.q.history(jid)[0]['state'], 'submitted')

    def test_corrupted_ciphertext_fails_closed(self):
        jid = self.q.submit(self.pdf, 'Printer', held=True)
        with closing(self.q._db()) as db:
            db.execute('UPDATE jobs SET printer=? WHERE id=?', ('meta1:AQ==', jid))
            db.commit()
        with self.assertRaises(ValueError):
            self.q.status(jid)
        with patch('tabarc_print.plugins.PrinterBackend.submit_bytes') as spool:
            self.q.release(jid)
            self.assertEqual(self.q.process_one(jid)[1], 'uncertain')
            spool.assert_not_called()

    def test_upgrade_encrypts_historical_metadata(self):
        jid = self.q.submit(self.pdf, 'Printer', held=True)
        with closing(self.q._db()) as db:
            db.execute('UPDATE jobs SET printer=?,message=? WHERE id=?', ('Legacy-Printer-Secret', 'Old message', jid))
            db.execute('UPDATE job_events SET detail=? WHERE job_id=?', ('Old detail', jid))
            db.execute("DELETE FROM queue_settings WHERE name='metadata_encryption'")
            db.commit()
        recovered = LocalQueue(self.q.root, backend='cups')
        self.assertEqual(recovered.status(jid)['printer'], 'Legacy-Printer-Secret')
        self.assertEqual(recovered.status(jid)['message'], 'Old message')
        self.assertEqual(recovered.history(jid)[0]['detail'], 'Old detail')
        self.assertNotIn(b'Legacy-Printer-Secret', recovered.db_path.read_bytes())


class FakeTorController:
    def __init__(self, sockpath, *, allow=True, service=None):
        self.sockpath = sockpath
        self.allow = allow
        self.service = (service or sample_onion())[:-6]
        self.commands = []
        self.ready = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)

    def __enter__(self):
        self.thread.start()
        if not self.ready.wait(timeout=2):
            raise RuntimeError('Mock controller did not start')
        return self

    def __exit__(self, *_):
        if self.thread.is_alive():
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as wake:
                    wake.settimeout(0.5)
                    wake.connect(str(self.sockpath))
            except OSError:
                pass
        self.thread.join(timeout=2)
        if self.thread.is_alive():
            raise RuntimeError('Mock controller hung')
        self.sockpath.unlink(missing_ok=True)

    def serve(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(self.sockpath)); os.chmod(self.sockpath, 0o600)
            server.listen(1)
            self.ready.set()
            conn, _ = server.accept()
            with conn:
                r = conn.makefile('rb')
                while True:
                    raw = r.readline()
                    if not raw:
                        break
                    cmd = raw.decode().strip()
                    self.commands.append(cmd)
                    if cmd == 'PROTOCOLINFO 1':
                        mode = 'NULL' if self.allow else 'COOKIE'
                        conn.sendall(('250-PROTOCOLINFO 1\r\n250-AUTH METHODS='+mode+'\r\n250 OK\r\n').encode())
                    elif cmd == 'AUTHENTICATE':
                        conn.sendall(b'250 OK\r\n')
                    elif cmd.startswith('ADD_ONION '):
                        conn.sendall(('250-ServiceID='+self.service+'\r\n250 OK\r\n').encode())
                    elif cmd.startswith('ONION_CLIENT_AUTH_ADD '):
                        conn.sendall(b'250 OK\r\n')
                    else:
                        conn.sendall(b'500 Rejected\r\n')


@unittest.skipIf(os.name == 'nt' or not hasattr(socket, 'AF_UNIX'), 'Unix socket required')
class TorControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        os.chmod(self.root, 0o700)
        self.path = self.root/'tor.sock'
        self.vault = TestVault()
        self.store = SecretStore(self.root, backend=self.vault)

    def test_new_client_keys_are_stored_only_in_vault(self):
        ref, public = new_client_key(self.store)
        self.assertEqual(len(public), 52)
        self.assertEqual(check_public_key(public), public)
        self.assertEqual(len(self.store.read(ref)), 64)
        self.assertNotIn(self.store.read(ref), str(list(self.root.iterdir())))
        with self.assertRaises(ValueError):
            check_public_key('not-a-client-key')

    def test_ephemeral_onion_and_client_authorisation(self):
        ref, public = new_client_key(self.store)
        with FakeTorController(self.path) as tor:
            with TorControlSocket(self.path) as session:
                service = session.ephemeral_service([public], 8787)
                session.client_authorisation(service, self.store, ref)
        self.assertEqual(service, sample_onion())
        self.assertIn('Flags=DiscardPK,V3Auth', tor.commands[2])
        self.assertIn('ClientAuthV3='+public, tor.commands[2])
        self.assertNotIn('Flags=Permanent', '\n'.join(tor.commands))
        self.assertTrue(tor.commands[3].startswith('ONION_CLIENT_AUTH_ADD '))

    def test_private_socket_requirements(self):
        with FakeTorController(self.path, allow=False):
            with self.assertRaises(PermissionError):
                with TorControlSocket(self.path):
                    pass
        # New fake socket with an insecure directory must be refused.
        os.chmod(self.root, 0o755)
        with FakeTorController(self.path):
            with self.assertRaises(PermissionError):
                with TorControlSocket(self.path):
                    pass


if __name__ == '__main__':
    unittest.main()

class VaultedGoogleRegistrationTests(unittest.TestCase):
    def setUp(self):
        from tabarc_print.cloud_accounts import CloudAccountSettings
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.vault = TestVault()
        self.vault_patch = patch('tabarc_print.cloud_accounts.SecretStore',
                                 side_effect=lambda root: SecretStore(root, backend=self.vault))
        self.vault_patch.start()
        self.addCleanup(self.vault_patch.stop)
        self.accounts = CloudAccountSettings(self.root / 'accounts')
        self.source = self.root / 'oauth-client.json'
        self.source.write_text('{"installed":{"client_id":"local.apps.googleusercontent.com",'
                               '"client_secret":"never-write-me-in-settings"}}')

    def test_google_registration_is_imported_to_vault(self):
        self.accounts.save(google_credentials=str(self.source))
        saved = self.accounts.load()['google_credentials']
        self.assertTrue(SecretStore.is_reference(saved))
        self.assertNotIn('never-write-me-in-settings', self.accounts.path.read_text())
        self.assertNotIn(str(self.source), self.accounts.path.read_text())
        self.assertIn('never-write-me-in-settings', SecretStore(self.accounts.root, self.vault).read(saved))

    def test_vault_failure_cannot_write_google_registration(self):
        with patch.object(self.vault, 'set_password', side_effect=RuntimeError('Vault locked')):
            with self.assertRaises(RuntimeError):
                self.accounts.save(google_credentials=str(self.source))
        self.assertFalse(self.accounts.path.exists())
