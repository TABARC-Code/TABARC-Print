"""Device-targeting and local credential storage checks."""
from contextlib import closing
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from tabarc_print.cloud_gateway import CloudGateway
from tabarc_print.desktop_cloud import CloudProfiles
from tabarc_print.receiver_identity import ReceiverIdentity
from tabarc_print.secret_store import SecretStore
from tabarc_print.gateway import FolderGateway, build_job
from tabarc_print.metadata import open_manifest
from test_cloud import MemoryCloud, PDF, SECRET


class DummyVault:
    def __init__(self):
        self.items = {}
        self.reject = False

    def set_password(self, service, name, value):
        if self.reject:
            raise RuntimeError('Vault locked')
        self.items[(service, name)] = value

    def get_password(self, service, name):
        return self.items.get((service, name))

    def delete_password(self, service, name):
        self.items.pop((service, name), None)


class CredentialsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.vault = DummyVault()
        self.secrets = SecretStore(self.root, backend=self.vault)
        self.profiles = CloudProfiles(self.root, secret_store=self.secrets)
        self.key = CloudProfiles.generate_key()

    def test_raw_key_does_not_appear_in_profile(self):
        self.profiles.save('google', secret=self.key, remote_id='desk')
        on_disk = self.profiles.path.read_text()
        self.assertNotIn(self.key, on_disk)
        self.assertIn('keyring:', on_disk)
        self.assertEqual(self.profiles.load('google')['secret'], self.key)

    def test_missing_vault_entry_fails_closed(self):
        self.profiles.save('google', secret=self.key)
        self.vault.items.clear()
        with self.assertRaisesRegex(RuntimeError, 'missing'):
            self.profiles.load('google')
        self.assertNotIn(self.key, self.profiles.path.read_text())

    def test_legacy_plaintext_profile_is_refused(self):
        old = {'google': {'secret': self.key, 'remote_id': 'desk',
               'local_printer': '', 'receive_enabled': False, 'receiver_id': ''}}
        self.profiles.path.write_text(json.dumps(old))
        if os.name != 'nt':
            self.profiles.path.chmod(0o600)
        with self.assertRaisesRegex(PermissionError, 'Plaintext'):
            self.profiles.load('google')

    def test_vault_unavailable_prevents_secret_storage(self):
        unavailable = CloudProfiles(self.root/'no-vault',
            secret_store=SecretStore(self.root/'no-vault', backend=None))
        with self.assertRaises(RuntimeError):
            unavailable.save('google', secret=self.key)
        self.assertFalse(unavailable.path.exists())

    def test_locked_vault_leaves_previous_profile_unchanged(self):
        self.profiles.save('google', secret=self.key)
        before = self.profiles.path.read_bytes()
        self.vault.reject = True
        with self.assertRaisesRegex(RuntimeError, 'Vault locked'):
            self.profiles.save('google', secret='e'*64)
        self.assertEqual(before, self.profiles.path.read_bytes())
        self.assertEqual(self.profiles.load('google')['secret'], self.key)

    def test_key_rotation_discards_previous_vault_entry(self):
        self.profiles.save('google', secret=self.key)
        self.profiles.save('google', secret='d'*64)
        self.assertEqual(self.profiles.load('google')['secret'], 'd'*64)
        self.assertEqual(len(self.vault.items), 1)

    def test_cross_provider_vault_isolation(self):
        self.profiles.save('google', secret=self.key)
        self.profiles.save('onedrive', secret='e'*64)
        self.assertEqual(self.profiles.load('google')['secret'], self.key)
        self.assertEqual(self.profiles.load('onedrive')['secret'], 'e'*64)
        self.assertEqual(len(self.vault.items), 2)


class RecipientTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pdf = self.root / 'doc.pdf'
        self.pdf.write_bytes(PDF)
        self.cloud = MemoryCloud()
        self.first = ReceiverIdentity(self.root / 'receiver-1').load_or_create()
        self.second = ReceiverIdentity(self.root / 'receiver-2').load_or_create()

    def test_receiver_ids_are_local_and_stable(self):
        self.assertEqual(self.first, ReceiverIdentity(self.root / 'receiver-1').load_or_create())
        self.assertNotEqual(self.first, self.second)
        if os.name != 'nt':
            self.assertEqual(stat.S_IMODE((self.root/'receiver-1'/'receiver-id').stat().st_mode), 0o600)

    def test_sender_targets_only_one_receiver(self):
        sender = CloudGateway(self.cloud, SECRET, self.root/'sender', target_receiver=self.first)
        jid = sender.send(self.pdf, 'office')
        first_file = next(f for f in self.cloud.files['inbox'].values() if f['name'].endswith('.job.bin'))
        self.assertNotIn(self.first.encode(), first_file['data'])
        manifest = open_manifest(SECRET, jid, first_file['data'])
        self.assertEqual(manifest['version'], 4)
        self.assertEqual(manifest['target_receiver'], self.first)
        other = CloudGateway(self.cloud, SECRET, self.root/'other', {'office': 'desk'},
                             dry_run=True, receiver_id=self.second, allow_direct_submission=True)
        with patch('tabarc_print.plugins.PrinterBackend.submit_bytes') as print_file:
            self.assertEqual(other.once()[jid], 'not-for-this-device')
            print_file.assert_not_called()
        self.assertEqual(self.cloud.list_files('receipts'), [])
        correct = CloudGateway(self.cloud, SECRET, self.root/'correct', {'office': 'desk'},
                               dry_run=True, receiver_id=self.first, allow_direct_submission=True)
        with patch('tabarc_print.plugins.PrinterBackend.submit_bytes', return_value='DRY_RUN') as print_file:
            self.assertEqual(correct.once()[jid], 'submitted')
            print_file.assert_called_once()
        self.assertEqual(sender.status(jid)['state'], 'submitted')
        self.assertEqual(len(self.cloud.list_files('inbox')), 0)

    def test_tampered_target_does_not_print(self):
        sender = CloudGateway(self.cloud, SECRET, self.root/'sender', target_receiver=self.first)
        jid = sender.send(self.pdf, 'office')
        for entry in self.cloud.files['inbox'].values():
            if entry['name'].endswith('.job.bin'):
                entry['data'] = entry['data'][:-1] + bytes([entry['data'][-1] ^ 1])
        receiver = CloudGateway(self.cloud, SECRET, self.root/'receiver', {'office':'local'},
                                dry_run=True, receiver_id=self.second, allow_direct_submission=True)
        with patch('tabarc_print.plugins.PrinterBackend.submit_bytes') as print_file:
            self.assertIn('authentication', receiver.once()[jid])
            print_file.assert_not_called()

    def test_invalid_target_rejected_at_submission(self):
        with self.assertRaises(ValueError):
            CloudGateway(self.cloud, SECRET, self.root/'sender', target_receiver='printer')
        with self.assertRaises(ValueError):
            build_job(self.root, self.pdf, 'office', SECRET, encrypt=False, target_receiver=self.first)

    def test_untargeted_jobs_keep_legacy_compatibility(self):
        sender = CloudGateway(self.cloud, SECRET, self.root/'sender')
        jid = sender.send(self.pdf, 'office')
        receiver = CloudGateway(self.cloud, SECRET, self.root/'receiver', {'office': 'local'},
                                dry_run=True, receiver_id=self.second, allow_direct_submission=True)
        with patch('tabarc_print.plugins.PrinterBackend.submit_bytes', return_value='DRY_RUN'):
            self.assertEqual(receiver.once()[jid], 'submitted')

    def test_malformed_receiver_identity_refused(self):
        identity = ReceiverIdentity(self.root / 'not-valid')
        identity.path.write_text('not-a-valid-id')
        with self.assertRaises(ValueError):
            identity.load_or_create()

    def test_targeted_folder_job_requires_receiver(self):
        folder = self.root/'folder'
        (folder/'inbox').mkdir(parents=True)
        jid = build_job(folder, self.pdf, 'office', SECRET, encrypt=True, target_receiver=self.first)
        agent = FolderGateway(folder, {'office':'local'}, SECRET, dry_run=True,
                              state_dir=self.root/'folder-state', allow_direct_submission=True)
        with patch('tabarc_print.plugins.PrinterBackend.submit_bytes') as print_file:
            self.assertEqual(agent.process_one(jid), 'not-for-this-device')
            print_file.assert_not_called()


if __name__ == '__main__':
    unittest.main()
