"""Held remote intake, local encryption and recovery boundaries."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch

from security_fixtures import local_vault_patch, TestVault
from tabarc_print.secret_store import SecretStore
from tabarc_print.local_queue import LocalQueue
from tabarc_print.tor_transport import TorPrintReceiver, _document, _open_receipt
from tabarc_print.gateway import FolderGateway, build_job
from tabarc_print.metadata import open_receipt
from tabarc_print.cloud_gateway import CloudGateway
from test_cloud import MemoryCloud

PDF = b'%PDF-1.7\n1 0 obj<<>>endobj\n%%EOF\n'
KEY = bytes(range(32))
DEVICE = 'b' * 32


class SecureQueueTest(unittest.TestCase):
    def setUp(self):
        self.vault_patch = local_vault_patch()
        self.vault_patch.start()
        self.addCleanup(self.vault_patch.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.q = LocalQueue(self.root / 'queue', backend='cups')

    def test_in_memory_intake_writes_ciphertext_only(self):
        jid = self.q.submit_bytes(PDF, 'Office', filename='secret-report.pdf', source_id='tor:hello')
        self.assertEqual(self.q.status(jid)['state'], 'held')
        self.assertNotIn(PDF, (self.q.docs / (jid + '.bin')).read_bytes())
        self.assertEqual(self.q.status(jid)['filename'], 'secret-report.pdf')
        self.assertNotIn(b'secret-report.pdf', self.q.db_path.read_bytes())
        self.assertNotIn(b'tor:hello', self.q.db_path.read_bytes())
        self.assertEqual(len(self.q.jobs()), 1)

    def test_duplicate_delivery_is_idempotent(self):
        first = self.q.submit_bytes(PDF, 'Office', source_id='tor:repeat')
        second = self.q.submit_bytes(PDF, 'Office', source_id='tor:repeat')
        self.assertEqual(first, second)
        self.assertEqual(len(self.q.jobs()), 1)

    def test_duplicate_with_different_document_refused(self):
        self.q.submit_bytes(PDF, 'Office', source_id='tor:repeat')
        with self.assertRaisesRegex(ValueError, 'different print data'):
            self.q.submit_bytes(PDF + b'changed', 'Office', source_id='tor:repeat')
        with self.assertRaisesRegex(ValueError, 'different print data'):
            self.q.submit_bytes(PDF, 'Other', source_id='tor:repeat')

    def test_path_components_are_rejected(self):
        for name in ('../secrets.pdf', 'folder\\secrets.pdf', '', 'hello\n.pdf'):
            with self.assertRaises(ValueError):
                self.q.submit_bytes(PDF, 'Office', filename=name)
        self.assertEqual(len(self.q.jobs()), 0)

    def test_held_jobs_cannot_print_before_release(self):
        jid = self.q.submit_bytes(PDF, 'Office')
        with patch('tabarc_print.plugins.PrinterBackend.submit_bytes') as spool:
            self.assertIsNone(self.q.process_one(jid))
            spool.assert_not_called()
        self.assertTrue(self.q.release(jid))
        with patch('tabarc_print.plugins.PrinterBackend.submit_bytes', return_value='DRY_RUN') as spool:
            self.assertEqual(self.q.process_one(jid, dry_run=True)[1], 'simulated')
            spool.assert_called_once()

    def test_plaintext_metadata_in_sealed_database_refused(self):
        jid = self.q.submit_bytes(PDF, 'Office')
        with closing(self.q._db()) as db:
            db.execute('UPDATE jobs SET message=? WHERE id=?', ('LEAKED', jid))
            db.commit()
        with self.assertRaisesRegex(PermissionError, 'Readable metadata'):
            LocalQueue(self.q.root)

    def test_first_run_key_creation_is_serialised(self):
        store = TestVault()
        root = self.root / 'simultaneous'
        with patch('tabarc_print.local_queue.SecretStore', side_effect=lambda path: SecretStore(path, backend=store)):
            q1, q2 = LocalQueue(root), LocalQueue(root)
            fence = threading.Barrier(2)
            def submit(q):
                fence.wait()
                return q.submit_bytes(PDF, 'Office', source_id='remote:once')
            with ThreadPoolExecutor(max_workers=2) as pool:
                jobs = list(pool.map(submit, (q1, q2)))
            self.assertEqual(jobs[0], jobs[1])
            self.assertEqual(len(q1.jobs()), 1)
            self.assertEqual(len(store.values), 1)

    def test_vault_unavailable_fails_closed(self):
        with patch('tabarc_print.local_queue.SecretStore', side_effect=lambda path: SecretStore(path, backend=None)):
            blocked = LocalQueue(self.root / 'unavailable')
            with self.assertRaisesRegex(RuntimeError, 'vault'):
                blocked.submit_bytes(PDF, 'Office')
            self.assertEqual(list(blocked.docs.glob('*.bin')), [])


class RemoteIntakeTest(unittest.TestCase):
    def setUp(self):
        self.vault_patch = local_vault_patch()
        self.vault_patch.start()
        self.addCleanup(self.vault_patch.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.q = LocalQueue(self.root / 'queue', backend='cups')
        self.pdf = self.root / 'original.pdf'
        self.pdf.write_bytes(PDF)

    def test_tor_delivery_held_with_no_spool(self):
        calls = []
        receiver = TorPrintReceiver(KEY, DEVICE, self.root / 'tor', {'remote': 'Laser'},
            spooler=lambda *args: calls.append(args), queue=self.q)
        jid, manifest, payload = _document(KEY, PDF, 'remote', DEVICE)
        receipt = _open_receipt(KEY, jid, receiver.accept(manifest, payload))
        self.assertEqual(receipt['state'], 'held')
        self.assertEqual(calls, [])
        self.assertEqual(self.q.jobs()[0]['printer'], 'Laser')
        self.assertEqual(self.q.jobs()[0]['state'], 'held')

    def test_tor_replay_after_lost_ledger_no_duplicate(self):
        receiver = TorPrintReceiver(KEY, DEVICE, self.root / 'tor', {'remote': 'Laser'}, queue=self.q)
        jid, manifest, payload = _document(KEY, PDF, 'remote', DEVICE)
        receiver.accept(manifest, payload)
        with closing(sqlite3.connect(receiver.dbfile)) as db:
            db.execute('DELETE FROM processed WHERE job=?', (jid,))
            db.commit()
        self.assertEqual(_open_receipt(KEY, jid, receiver.accept(manifest, payload))['state'], 'held')
        self.assertEqual(len(self.q.jobs()), 1)

    def test_tor_rejected_key_never_queues(self):
        receiver = TorPrintReceiver(KEY, DEVICE, self.root / 'tor', {'remote': 'Laser'}, queue=self.q)
        _, manifest, payload = _document(b'X' * 32, PDF, 'remote', DEVICE)
        with self.assertRaises(PermissionError):
            receiver.accept(manifest, payload)
        self.assertEqual(self.q.jobs(), [])

    def test_folder_delivery_held_with_signed_receipt(self):
        folder = self.root / 'sync'
        jid = build_job(folder, self.pdf, 'remote', KEY)
        receiver = FolderGateway(folder, {'remote': 'Laser'}, KEY,
                                 state_dir=self.root / 'gateway', queue=self.q)
        with patch('tabarc_print.plugins.PrinterBackend.submit_bytes') as spool:
            self.assertEqual(receiver.process_one(jid), 'held')
            spool.assert_not_called()
        receipt = open_receipt(KEY, jid, (folder / 'receipts' / (jid + '.receipt.bin')).read_bytes())
        self.assertEqual(receipt['state'], 'held')
        self.assertEqual(receipt['version'], 4)
        self.assertEqual(self.q.jobs()[0]['state'], 'held')
        self.assertFalse((folder / 'inbox' / (jid + '.bin')).exists())

    def test_folder_claim_lost_after_queue_commit_deduplicates(self):
        folder = self.root / 'sync'
        jid = build_job(folder, self.pdf, 'remote', KEY)
        receiver = FolderGateway(folder, {'remote': 'Laser'}, KEY,
                                 state_dir=self.root / 'gateway', queue=self.q)
        self.assertEqual(receiver.process_one(jid), 'held')
        with closing(receiver.db()) as db:
            db.execute('DELETE FROM processed WHERE id=?', (jid,))
            db.commit()
        # Deliberately restore the signed encrypted input to simulate lost cleanup.
        jid2 = build_job(folder, self.pdf, 'remote', KEY)
        self.assertEqual(receiver.process_one(jid2), 'held')
        self.assertEqual(receiver.process_one(jid2), 'duplicate')
        self.assertEqual(len(self.q.jobs()), 2)

    def test_cloud_delivery_published_held_without_spool(self):
        store = MemoryCloud()
        sender = CloudGateway(store, KEY, self.root / 'sender')
        receiver = CloudGateway(store, KEY, self.root / 'cloud', {'remote': 'Laser'}, queue=self.q)
        jid = sender.send(self.pdf, 'remote')
        with patch('tabarc_print.plugins.PrinterBackend.submit_bytes') as spool:
            self.assertEqual(receiver.once()[jid], 'held')
            spool.assert_not_called()
        self.assertEqual(sender.status(jid)['state'], 'held')
        self.assertEqual(len(self.q.jobs()), 1)
        self.assertEqual(store.list_files('inbox'), [])

    def test_cloud_corrupt_payload_does_not_enqueue(self):
        store = MemoryCloud()
        sender = CloudGateway(store, KEY, self.root / 'sender')
        receiver = CloudGateway(store, KEY, self.root / 'cloud', {'remote': 'Laser'}, queue=self.q)
        jid = sender.send(self.pdf, 'remote')
        for entry in store.files['inbox'].values():
            if entry['name'] == jid + '.bin':
                entry['data'] = b'bad' + entry['data'][3:]
        self.assertIn('integrity', receiver.once()[jid])
        self.assertEqual(self.q.jobs(), [])


if __name__ == '__main__':
    unittest.main()

class DesktopIntakeTest(unittest.TestCase):
    def test_desktop_receives_into_its_existing_queue(self):
        from unittest.mock import Mock
        from tabarc_print.desktop_cloud import CloudDesktopController
        from tabarc_print.desktop import DesktopController
        with tempfile.TemporaryDirectory() as tmp, local_vault_patch():
            root = Path(tmp)
            desktop = DesktopController(root / 'state', backend='cups', auth_dir=root / 'auth')
            pdf = root / 'report.pdf'
            pdf.write_bytes(PDF)
            store = MemoryCloud()
            sender = CloudGateway(store, KEY, root / 'sender')
            jid = sender.send(pdf, 'remote')
            accounts = Mock()
            accounts.status.return_value = {'configured': True, 'cached': True}
            accounts.load.return_value = {'microsoft_client_id': 'fake', 'microsoft_tenant': 'consumers'}
            profiles = Mock()
            profiles.load.return_value = {
                'secret': KEY.hex(), 'remote_id': 'remote', 'local_printer': 'Laser',
                'receive_enabled': True, 'receiver_id': ''}
            controller = CloudDesktopController(accounts, desktop.queue.root / 'cloud-gateways',
                                                 profiles=profiles, store_factory=lambda *args: store)
            with patch('tabarc_print.desktop_cloud.MicrosoftAuth'):
                with patch('tabarc_print.plugins.PrinterBackend.submit_bytes') as spool:
                    result = controller.receive_once('onedrive')
                    spool.assert_not_called()
            self.assertEqual(result[jid], 'held')
            self.assertEqual(desktop.jobs()[0]['printer'], 'Laser')
            self.assertEqual(desktop.jobs()[0]['state'], 'held')
