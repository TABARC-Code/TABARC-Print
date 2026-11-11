"""Account configuration and distribution boundaries for v0.8."""
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
from security_fixtures import local_vault_patch, TestVault
from tabarc_print.secret_store import SecretStore

from tabarc_print.cloud_accounts import CloudAccountSettings
from tabarc_print.desktop import DesktopController
from tabarc_print.desktop_settings import DesktopSettings


class AccountSettingsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.vault = TestVault()
        self.secret_patch = patch('tabarc_print.cloud_accounts.SecretStore',
                                  side_effect=lambda root: SecretStore(root, backend=self.vault))
        self.secret_patch.start()
        self.addCleanup(self.secret_patch.stop)
        self.accounts = CloudAccountSettings(self.path / 'private')
        self.google = self.path / 'google-client.json'
        self.google.write_text(json.dumps({'installed': {'client_id': 'example.apps.googleusercontent.com',
                                                     'client_secret': 'fake-secret'}}))

    def test_local_queue_does_not_require_accounts(self):
        ctrl = DesktopController(self.path / 'jobs', 'cups', auth_dir=self.path / 'private')
        self.assertEqual(ctrl.accounts.status('google')['configured'], False)
        self.assertEqual(ctrl.accounts.status('onedrive')['configured'], False)
        with patch('tabarc_print.cloud_accounts.GoogleAuth.login') as login:
            self.assertEqual(ctrl.jobs(), [])
            login.assert_not_called()

    def test_save_settings_only_records_app_information(self):
        saved = self.accounts.save(str(self.google), '12345678-90ab-cdef-1234-567890abcdef', 'consumers')
        self.assertEqual(self.accounts.load(), saved)
        text = self.accounts.path.read_text()
        self.assertNotIn('fake-secret', text)
        self.assertNotIn('access_token', text)
        if os.name != 'nt':
            self.assertEqual(stat.S_IMODE(self.accounts.path.stat().st_mode), 0o600)

    def test_refuse_invalid_google_client(self):
        with self.assertRaises(ValueError):
            self.accounts.save(str(self.path / 'missing.json'))
        self.google.write_text('{"web": {"client_id":"not-desktop"}}')
        with self.assertRaises(ValueError):
            self.accounts.save(str(self.google))
        self.google.write_text('not json')
        with self.assertRaises(ValueError):
            self.accounts.save(str(self.google))

    def test_refuse_bad_microsoft_registration(self):
        with self.assertRaises(ValueError):
            self.accounts.save(microsoft_client_id='some-app')
        with self.assertRaises(ValueError):
            self.accounts.save(microsoft_tenant='not-a-tenant')

    def test_legacy_plaintext_token_is_blocked(self):
        self.accounts.save(str(self.google))
        token = self.accounts.root / 'google-token.json'
        token.write_text('{}')
        if os.name != 'nt':
            token.chmod(0o600)
        with self.assertRaisesRegex(PermissionError, 'Legacy plaintext'):
            self.accounts.status('google')

    def test_google_signin_calls_existing_auth_client(self):
        self.accounts.save(str(self.google))
        with patch('tabarc_print.cloud_accounts.GoogleAuth.login') as login:
            self.accounts.sign_in('google')
            login.assert_called_once()

    def test_microsoft_signin_passes_device_code_notifier(self):
        self.accounts.save(microsoft_client_id='12345678-90ab-cdef-1234-567890abcdef')
        notifications = []
        with patch('tabarc_print.cloud_accounts.MicrosoftAuth') as mock_auth:
            self.accounts.sign_in('onedrive', notify=notifications.append)
            self.assertEqual(mock_auth.return_value.login.call_args.kwargs['notify'], notifications.append)

    def test_unconfigured_provider_must_not_start_login(self):
        with patch('tabarc_print.cloud_accounts.GoogleAuth') as google:
            with self.assertRaises(ValueError):
                self.accounts.sign_in('google')
            google.assert_not_called()

    def test_plaintext_token_removal_is_not_silently_managed(self):
        self.accounts.save(str(self.google))
        token = self.accounts.root / 'google-token.json'
        token.write_text('old unsafe cache')
        if os.name != 'nt':
            token.chmod(0o600)
        with self.assertRaises(PermissionError):
            self.accounts.forget_local_token('google')
        self.assertTrue(token.exists())
        self.assertTrue(SecretStore.is_reference(self.accounts.load()['google_credentials']))

    def test_reject_token_symlink(self):
        target = self.path / 'target'
        target.write_text('secret')
        token = self.accounts.root / 'google-token.json'
        try:
            token.symlink_to(target)
        except OSError:
            self.skipTest('Symlinks unavailable')
        with self.assertRaises(PermissionError):
            self.accounts.forget_local_token('google')
        self.assertEqual(target.read_text(), 'secret')

    def test_reject_settings_symlink(self):
        target = self.path / 'target'
        target.write_text('{}')
        try:
            self.accounts.path.symlink_to(target)
        except OSError:
            self.skipTest('Symlinks unavailable')
        with self.assertRaises(ValueError):
            self.accounts.load()
        with self.assertRaises(ValueError):
            self.accounts.save()
        self.assertEqual(target.read_text(), '{}')

    def test_disallow_unapproved_providers(self):
        for action in (self.accounts.status, self.accounts.forget_local_token):
            with self.assertRaises(ValueError):
                action('random-provider')


class RendererSettingsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.settings = DesktopSettings(self.root)

    def test_choose_trusted_named_renderer(self):
        binary = self.root / 'SumatraPDF.exe'
        binary.write_bytes(b'example')
        self.assertEqual(self.settings.set_renderer(binary), str(binary))
        self.assertEqual(self.settings.renderer(), str(binary))
        ctrl = DesktopController(self.root / 'queue', 'cups', auth_dir=self.root / 'auth')
        self.assertEqual(ctrl.set_windows_renderer(binary), str(binary))
        self.assertEqual(ctrl.queue.windows_renderer, str(binary))

    def test_reject_wrong_executable(self):
        binary = self.root / 'not-sumatra.exe'
        binary.write_bytes(b'example')
        with self.assertRaises(ValueError):
            self.settings.set_renderer(binary)
        with self.assertRaises(ValueError):
            self.settings.set_renderer(self.root / 'missing' / 'SumatraPDF.exe')

    def test_refuse_configuration_symlink(self):
        target = self.root / 'elsewhere'
        target.write_text('important')
        try:
            self.settings.file.symlink_to(target)
        except OSError:
            self.skipTest('Symlinks unavailable')
        with self.assertRaises(ValueError):
            self.settings.renderer()
        self.assertEqual(target.read_text(), 'important')


class PackagingLayoutTests(unittest.TestCase):
    def test_windows_packaging_is_opt_in(self):
        root = Path(__file__).resolve().parent.parent
        builder = (root / 'packaging/windows/build-windows.ps1').read_text()
        installer = (root / 'packaging/windows/TABARCPrint.iss').read_text()
        task = (root / 'packaging/windows/configure-windows-worker.ps1').read_text()
        self.assertIn('PyInstaller', builder)
        self.assertIn('PrivilegesRequired=lowest', installer)
        self.assertIn('New-ScheduledTaskTrigger -AtLogOn', task)
        self.assertIn("[ValidateSet('Show','Install','Remove')]", task)
        self.assertNotIn('Start-ScheduledTask -TaskName', task)
        self.assertIn('Refusing to remove a task', task)


if __name__ == '__main__':
    unittest.main()
