"""AES-256 metadata confidentiality, downgrade resistance and queue isolation."""
from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch

from tabarc_print.cloud_gateway import CloudGateway
from tabarc_print.gateway import FolderGateway, build_job, private_file_bytes
from tabarc_print.metadata import (
    MANIFEST_SUFFIX, RECEIPT_SUFFIX, open_manifest, open_receipt, seal,
    seal_receipt, open_envelope,
)
from test_cloud import MemoryCloud, PDF
from security_fixtures import local_vault_patch

KEY = bytes(range(32))
WRONG = bytes(range(1, 33))
JID = 'a' * 32
DEVICE = 'b' * 32


class EnvelopeTests(unittest.TestCase):
    def test_two_metadata_categories_use_separate_keys(self):
        payload = {'job_id': JID, 'version': 4}
        manifest = seal(KEY, JID, 'manifest', payload)
        receipt = seal(KEY, JID, 'receipt', payload)
        self.assertEqual(open_envelope(KEY, JID, 'manifest', manifest), payload)
        self.assertEqual(open_envelope(KEY, JID, 'receipt', receipt), payload)
        with self.assertRaises(ValueError):
            open_envelope(KEY, JID, 'receipt', manifest)
        with self.assertRaises(ValueError):
            open_envelope(KEY, JID, 'manifest', receipt)
        self.assertNotEqual(manifest, seal(KEY, JID, 'manifest', payload))

    def test_tamper_and_wrong_key_fail_without_fallback(self):
        original = seal(KEY, JID, 'manifest', {'job_id': JID, 'secret': 'kept-private'})
        self.assertNotIn(b'kept-private', original)
        for candidate in (original[:-1] + bytes([original[-1] ^ 1]),
                          original[:4] + bytes([original[4] ^ 1]) + original[5:],
                          original[:16] + bytes([original[16] ^ 1]) + original[17:],
                          original[:-1], b'{"job_id":"' + JID.encode() + b'"}'):
            with self.subTest(candidate=candidate[:8]), self.assertRaises(ValueError):
                open_envelope(KEY, JID, 'manifest', candidate)
        with self.assertRaises(ValueError):
            open_envelope(WRONG, JID, 'manifest', original)
        with self.assertRaises(ValueError):
            open_envelope(KEY, 'c' * 32, 'manifest', original)

    def test_receipt_validation(self):
        sealed = seal_receipt(KEY, JID, 'held', 'Not yet printed', 4)
        self.assertNotIn(b'Not yet printed', sealed)
        self.assertEqual(open_receipt(KEY, JID, sealed)['state'], 'held')
        with self.assertRaises(ValueError):
            open_receipt(KEY, JID, seal(KEY, JID, 'receipt', {'job_id': JID, 'version': 3}))


class MetadataMailboxTests(unittest.TestCase):
    def setUp(self):
        self.vault = local_vault_patch()
        self.vault.start()
        self.addCleanup(self.vault.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.pdf = self.root / 'private-document.pdf'
        self.pdf.write_bytes(PDF)

    def test_folder_manifest_and_receipt_expose_no_print_metadata(self):
        folder = self.root / 'sync'
        jid = build_job(folder, self.pdf, 'medical-room', KEY, target_receiver=DEVICE)
        listing = list((folder / 'inbox').iterdir())
        self.assertEqual({f.name for f in listing}, {jid + '.bin', jid + MANIFEST_SUFFIX})
        manifest = (folder / 'inbox' / (jid + MANIFEST_SUFFIX)).read_bytes()
        for value in (b'medical-room', DEVICE.encode(), b'created_at', b'printer_id', PDF):
            self.assertNotIn(value, manifest)
        self.assertEqual(open_manifest(KEY, jid, manifest)['target_receiver'], DEVICE)
        recv = FolderGateway(folder, {'medical-room': 'Office'}, KEY,
                             receiver_id=DEVICE, state_dir=self.root / 'ledger')
        self.assertEqual(recv.process_one(jid), 'held')
        receipt = (folder / 'receipts' / (jid + RECEIPT_SUFFIX)).read_bytes()
        for value in (b'held', b'approval', b'message', b'Office'):
            self.assertNotIn(value, receipt)
        self.assertEqual(open_receipt(KEY, jid, receipt)['state'], 'held')

    def test_cloud_manifest_and_receipt_expose_no_print_metadata(self):
        store = MemoryCloud()
        sender = CloudGateway(store, KEY, self.root / 'sender', target_receiver=DEVICE)
        receiver = CloudGateway(store, KEY, self.root / 'receiver', {'medical-room': 'Office'},
                                receiver_id=DEVICE)
        jid = sender.send(self.pdf, 'medical-room')
        files = {item['name']: item['data'] for item in store.files['inbox'].values()}
        self.assertEqual(set(files), {jid + '.bin', jid + MANIFEST_SUFFIX})
        self.assertNotIn(b'medical-room', files[jid + MANIFEST_SUFFIX])
        self.assertNotIn(DEVICE.encode(), files[jid + MANIFEST_SUFFIX])
        self.assertEqual(receiver.once()[jid], 'held')
        posted = next(iter(store.files['receipts'].values()))
        self.assertEqual(posted['name'], jid + RECEIPT_SUFFIX)
        self.assertNotIn(b'held', posted['data'])
        self.assertEqual(sender.status(jid)['state'], 'held')

    def test_legacy_readable_cloud_jobs_refused_without_download(self):
        store = MemoryCloud()
        store.upload('inbox', JID + '.job.json', b'{"printer_id":"secret"}')
        receiver = CloudGateway(store, KEY, self.root / 'receiver', {'medical-room': 'Office'})
        self.assertIn('legacy readable', receiver.once()[JID])
        store.upload('receipts', JID + '.json', b'{"state":"printed"}')
        sender = CloudGateway(store, KEY, self.root / 'sender')
        with self.assertRaisesRegex(ValueError, 'Legacy readable'):
            sender.status(JID)

    def test_legacy_readable_folder_jobs_refused(self):
        folder = self.root / 'sync'
        (folder / 'inbox').mkdir(parents=True)
        (folder / 'inbox' / (JID + '.job.json')).write_bytes(b'plaintext')
        receiver = FolderGateway(folder, {'medical-room': 'Office'}, KEY,
                                 state_dir=self.root / 'ledger')
        self.assertIn('legacy readable', receiver.once()[JID])

    def test_symlinked_pdf_refused(self):
        if not hasattr(os, 'O_NOFOLLOW'):
            self.skipTest('Requires no-follow support')
        folder = self.root / 'sync'
        link = self.root / 'shortcut.pdf'
        link.symlink_to(self.pdf)
        with self.assertRaises(OSError):
            build_job(folder, link, 'medical-room', KEY)

    def test_symlinked_gateway_ledger_refused(self):
        folder = self.root / 'sync'
        state = self.root / 'ledger'
        state.mkdir(mode=0o700)
        state.chmod(0o700)
        destination = self.root / 'elsewhere'
        destination.write_text('leave alone')
        (state / 'gateway-ledger.sqlite3').symlink_to(destination)
        with self.assertRaisesRegex(ValueError, 'symbolic link'):
            FolderGateway(folder, {'medical-room': 'Office'}, KEY, state_dir=state)
        self.assertEqual(destination.read_text(), 'leave alone')


if __name__ == '__main__':
    unittest.main()

class DowngradeCollisionTests(unittest.TestCase):
    def setUp(self):
        self.patcher = local_vault_patch()
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pdf = self.root / 'document.pdf'
        self.pdf.write_bytes(PDF)

    def test_folder_conflicting_new_and_old_manifest_never_prints(self):
        root = self.root / 'sync'
        jid = build_job(root, self.pdf, 'office', KEY)
        (root / 'inbox' / (jid + '.job.json')).write_bytes(b'{}')
        gateway = FolderGateway(root, {'office': 'local'}, KEY,
                                state_dir=self.root / 'ledger')
        with patch('tabarc_print.local_queue.LocalQueue.submit_bytes') as submit:
            self.assertIn('ambiguous', gateway.once()[jid])
            submit.assert_not_called()

    def test_cloud_conflicting_new_and_old_manifest_never_downloads_payload(self):
        cloud = MemoryCloud()
        sender = CloudGateway(cloud, KEY, self.root / 'sender')
        jid = sender.send(self.pdf, 'office')
        cloud.upload('inbox', jid + '.job.json', b'{}')
        recv = CloudGateway(cloud, KEY, self.root / 'receiver', {'office': 'local'})
        with patch('tabarc_print.local_queue.LocalQueue.submit_bytes') as submit:
            self.assertIn('ambiguous', recv.once()[jid])
            submit.assert_not_called()
