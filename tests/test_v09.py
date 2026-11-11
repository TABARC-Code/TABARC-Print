"""Desktop cloud workflows never need live accounts or physical printers for unit tests."""
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from tabarc_print.cloud_accounts import CloudAccountSettings
from tabarc_print.desktop_cloud import CloudDesktopController, CloudProfiles
from tabarc_print.desktop import DesktopController
from test_cloud import MemoryCloud, PDF
from test_v10 import DummyVault
from tabarc_print.secret_store import SecretStore
from security_fixtures import local_vault_patch


class CloudProfileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.vault = DummyVault()
        profile_root = self.root / 'secret-settings'
        self.profiles = CloudProfiles(profile_root, secret_store=SecretStore(profile_root, backend=self.vault))
        self.key = CloudProfiles.generate_key()

    def test_generate_key_is_256_bit_random_hex(self):
        self.assertEqual(len(self.key), 64)
        self.assertNotEqual(self.key, CloudProfiles.generate_key())
        bytes.fromhex(self.key)

    def test_per_provider_profiles_and_permissions(self):
        self.profiles.save('google', secret=self.key, remote_id='home', local_printer='HP Printer', receive_enabled=True)
        self.assertEqual(self.profiles.load('google')['local_printer'], 'HP Printer')
        self.assertEqual(self.profiles.load('onedrive'), CloudProfiles.empty())
        if os.name != 'nt':
            self.assertEqual(stat.S_IMODE(self.profiles.path.stat().st_mode), 0o600)
        self.assertEqual(self.profiles.save('onedrive', secret='A'*64)['secret'], 'a'*64)

    def test_refuse_invalid_key_and_mappings(self):
        for key in ('password', 'a' * 63, 'g' * 64):
            with self.assertRaises(ValueError):
                self.profiles.save('google', secret=key)
        with self.assertRaises(ValueError):
            self.profiles.save('google', secret=self.key, remote_id='-bad', local_printer='Laser')
        with self.assertRaises(ValueError):
            self.profiles.save('google', secret=self.key, remote_id='home', local_printer='\nprinter')
        with self.assertRaises(ValueError):
            self.profiles.save('google', secret=self.key, receive_enabled=True)
        with self.assertRaises(ValueError):
            self.profiles.save('dropbox', secret=self.key)

    def test_refuse_symlink_and_exposed_settings(self):
        link = self.profiles.path
        target = self.root / 'unrelated'
        target.write_text('{}')
        try:
            link.symlink_to(target)
        except OSError:
            self.skipTest('Symlinks unavailable')
        with self.assertRaises(ValueError):
            self.profiles.load('google')
        with self.assertRaises(ValueError):
            self.profiles.save('google', secret=self.key)
        link.unlink()
        self.profiles.save('google', secret=self.key)
        if os.name != 'nt':
            link.chmod(0o644)
            with self.assertRaises(PermissionError):
                self.profiles.load('google')


class DesktopCloudTests(unittest.TestCase):
    def setUp(self):
        self.local_vault = local_vault_patch()
        self.local_vault.start()
        self.addCleanup(self.local_vault.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.store = MemoryCloud()
        self.accounts = CloudAccountSettings(self.root / 'accounts')
        self.accounts.save(microsoft_client_id='12345678-90ab-cdef-1234-567890abcdef')
        self.vault = DummyVault()
        self.tokens = SecretStore(self.accounts.root, backend=self.vault)
        self.tokens.put_named('oauth.microsoft.v1', 'test-only-vault-cache')
        self.status_patch = patch('tabarc_print.cloud_accounts.SecretStore',
                                  side_effect=lambda path: SecretStore(path, backend=self.vault))
        self.status_patch.start()
        self.addCleanup(self.status_patch.stop)
        self.key = CloudProfiles.generate_key()
        profiles = CloudProfiles(self.accounts.root, secret_store=self.tokens)
        self.controller = CloudDesktopController(self.accounts, self.root / 'state',
                                                profiles=profiles,
                                                store_factory=lambda name, auth: self.store)
        self.pdf = self.root / 'paper.pdf'
        self.pdf.write_bytes(PDF)

    def test_local_queue_still_works_without_cloud(self):
        desktop = DesktopController(self.root / 'local', 'cups', auth_dir=self.root / 'other-auth')
        with patch('tabarc_print.desktop_cloud.REGISTRY.cloud_store') as factory:
            jid = desktop.submit(self.pdf, 'Printer', held=True)
            self.assertEqual(desktop.queue.status(jid)['state'], 'held')
            factory.assert_not_called()

    def test_require_pairing_and_signin(self):
        with self.assertRaisesRegex(ValueError, 'pairing'):
            self.controller.send('onedrive', self.pdf, 'home')
        self.controller.profiles.save('onedrive', secret=self.key, remote_id='home')
        self.tokens.delete_named('oauth.microsoft.v1')
        with self.assertRaisesRegex(ValueError, 'sign in'):
            self.controller.send('onedrive', self.pdf, 'home')

    def test_encrypt_send_receive_receipt_without_physical_spool(self):
        self.controller.profiles.save('onedrive', secret=self.key, remote_id='home',
                                      local_printer='Desk', receive_enabled=True)
        with patch('tabarc_print.desktop_cloud.MicrosoftAuth'):
            jid = self.controller.send('onedrive', self.pdf, 'home')
            self.assertEqual(self.controller.status('onedrive', jid), None)
            docs = self.store.list_files('inbox')
            self.assertEqual({x['name'] for x in docs}, {jid + '.bin', jid + '.job.bin'})
            with patch('tabarc_print.plugins.PrinterBackend.submit_bytes', return_value='DRY_RUN') as spool:
                results = self.controller.receive_once('onedrive', dry_run=True)
                spool.assert_not_called()
            self.assertEqual(results[jid], 'held')
            self.assertEqual(self.controller.status('onedrive', jid)['state'], 'held')
            self.assertEqual(self.controller.receive_once('onedrive', dry_run=True), {})
            self.assertEqual(len(self.store.list_files('inbox')), 0)

    def test_receiving_requires_explicit_local_optin(self):
        self.controller.profiles.save('onedrive', secret=self.key, remote_id='home', local_printer='Desk', receive_enabled=False)
        with self.assertRaisesRegex(ValueError, 'Enable'):
            with patch('tabarc_print.desktop_cloud.MicrosoftAuth'):
                self.controller.receive_once('onedrive')
        self.assertEqual(self.store.list_files('inbox'), [])

    def test_wrong_cloud_key_does_not_spool(self):
        self.controller.profiles.save('onedrive', secret=self.key, remote_id='home', local_printer='Desk', receive_enabled=True)
        with patch('tabarc_print.desktop_cloud.MicrosoftAuth'):
            jid = self.controller.send('onedrive', self.pdf, 'home')
            self.controller.profiles.save('onedrive', secret=CloudProfiles.generate_key(), remote_id='home',
                                          local_printer='Desk', receive_enabled=True)
            with patch('tabarc_print.plugins.PrinterBackend.submit_bytes') as spool:
                result = self.controller.receive_once('onedrive', dry_run=True)
                self.assertIn('authentication', result[jid])
                spool.assert_not_called()

    def test_invalid_remote_identifier_never_uploads(self):
        self.controller.profiles.save('onedrive', secret=self.key)
        with self.assertRaises(ValueError):
            self.controller.send('onedrive', self.pdf, '../../printer')
        self.assertEqual(self.store.list_files('inbox'), [])


if __name__ == '__main__':
    unittest.main()
