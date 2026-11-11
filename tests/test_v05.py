"""Local-first printing, approved plug-ins and recovery checks."""
import json
from pathlib import Path
from contextlib import closing
import tempfile
import unittest
from unittest.mock import patch
from security_fixtures import local_vault_patch

from tabarc_print.local import main as local_main
from tabarc_print.local_queue import LocalQueue
from tabarc_print.plugins import REGISTRY, discover_printers

PDF = b'%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n'


class LocalTests(unittest.TestCase):
    def setUp(self):
        self.secure_vault_patch = local_vault_patch()
        self.secure_vault_patch.start()
        self.addCleanup(self.secure_vault_patch.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.pdf = self.root / 'test.pdf'
        self.pdf.write_bytes(PDF)
        self.q = LocalQueue(self.root / 'private', 'cups')

    def test_queued_pdf_is_encrypted_at_rest(self):
        jid = self.q.submit(self.pdf, 'Office', held=True)
        sealed = (self.q.docs / (jid + '.bin')).read_bytes()
        self.assertTrue(sealed.startswith(b'TPQENC01'))
        self.assertNotIn(PDF, sealed)
        self.assertEqual(self.q._open(self.q._data_key(), jid, sealed), PDF)

    def test_submit_and_print_only_once(self):
        jid = self.q.submit(self.pdf, 'Laser_Printer')
        with patch('tabarc_print.plugins.PrinterBackend.submit_bytes', return_value='spooled') as spool:
            result = self.q.process_one(jid)
            self.assertEqual(result[:2], (jid, 'submitted'))
            self.assertIsNone(self.q.process_one(jid))
            spool.assert_called_once()
        self.assertEqual(self.q.status(jid)['state'], 'submitted')
        self.assertFalse((self.q.docs / (jid + '.bin')).exists())

    def test_second_worker_will_not_duplicate(self):
        jid = self.q.submit(self.pdf, 'Office')
        other = LocalQueue(self.root / 'private', 'cups')
        with patch('tabarc_print.plugins.PrinterBackend.submit_bytes', return_value='spooled') as spool:
            self.assertEqual(other.process_one()[0], jid)
            self.assertIsNone(self.q.process_one())
            self.assertEqual(spool.call_count, 1)

    def test_claimed_job_remains_unprintable_after_restart(self):
        jid = self.q.submit(self.pdf, 'Office')
        # Simulate stopping the programme between its durable claim and the spooler.
        with closing(self.q._db()) as db:
            db.execute("UPDATE jobs SET state='claimed' WHERE id=?", (jid,))
            db.commit()
        other = LocalQueue(self.root / 'private', 'cups')
        with patch('tabarc_print.plugins.PrinterBackend.submit_bytes') as spool:
            self.assertIsNone(other.process_one(jid))
            spool.assert_not_called()
        self.assertTrue(other.mark_interrupted(jid))
        self.assertEqual(other.status(jid)['state'], 'uncertain')
        self.assertIsNone(other.process_one(jid))

    def test_failure_is_uncertain_and_not_retried(self):
        jid = self.q.submit(self.pdf, 'Office')
        with patch('tabarc_print.plugins.PrinterBackend.submit_bytes', side_effect=TimeoutError('spooler timed out')) as spool:
            self.assertEqual(self.q.process_one(jid)[1], 'uncertain')
            self.assertIsNone(self.q.process_one(jid))
            spool.assert_called_once()
        self.assertTrue((self.q.docs / (jid + '.bin')).exists())

    def test_cancel_queued_job(self):
        jid = self.q.submit(self.pdf, 'Office')
        self.assertTrue(self.q.cancel(jid))
        self.assertFalse(self.q.cancel(jid))
        self.assertEqual(self.q.status(jid)['state'], 'cancelled')
        self.assertFalse((self.q.docs / (jid + '.bin')).exists())

    def test_refuse_bad_pdf(self):
        self.pdf.write_bytes(b'not pdf')
        with self.assertRaises(ValueError):
            self.q.submit(self.pdf, 'Office')
        self.assertFalse(self.q.jobs())

    def test_refuse_symlink_pdf(self):
        link = self.root / 'link.pdf'
        try:
            link.symlink_to(self.pdf)
        except (OSError, NotImplementedError):
            self.skipTest('Symlinks unavailable')
        with self.assertRaises(ValueError):
            self.q.submit(link, 'Office')

    def test_printer_name_argument_validation(self):
        for name in ('-not-a-printer', '', 'one\ntwo', 'bad\0name'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.q.submit(self.pdf, name)


    def test_dry_run_does_not_claim_physical_submission(self):
        jid = self.q.submit(self.pdf, 'Office')
        with patch('tabarc_print.plugins.PrinterBackend.submit_bytes', return_value='DRY_RUN'):
            result = self.q.process_one(jid, dry_run=True)
        self.assertEqual(result[1], 'simulated')
        self.assertEqual(self.q.status(jid)['state'], 'simulated')
        self.assertTrue((self.q.docs / (jid + '.bin')).exists())
        self.assertIsNone(self.q.process_one(jid))

    def test_private_folder_mode(self):
        if __import__('os').name != 'nt':
            self.assertEqual(self.q.root.stat().st_mode & 0o077, 0)
            self.assertEqual(self.q.db_path.stat().st_mode & 0o077, 0)

    def test_cli_from_local_file(self):
        with patch('tabarc_print.plugins.PrinterBackend.submit_bytes', return_value='DRY_RUN') as spool:
            self.assertEqual(local_main(['--state-dir', str(self.root/'cli'), 'submit',
                '--pdf', str(self.pdf), '--printer', 'Office', '--print-now', '--dry-run']), 0)
            spool.assert_called_once()


class PluginsTests(unittest.TestCase):
    def test_list_contains_approved_builtins(self):
        self.assertEqual({p.name for p in REGISTRY.list('transport')}, {'folder', 'google', 'onedrive', 'tor-onion'})
        self.assertEqual({p.name for p in REGISTRY.list('printer')}, {'cups', 'windows-sumatra'})

    def test_unknown_plugins_do_not_execute(self):
        with self.assertRaises(ValueError):
            REGISTRY.printer('../external-module')
        with self.assertRaises(ValueError):
            REGISTRY.cloud_store('external-plugin', object())

    def test_known_cloud_store_factories(self):
        with patch('tabarc_print.cloud_api.GoogleDrive') as google:
            REGISTRY.cloud_store('google', lambda: 'token')
            google.assert_called_once()
        with patch('tabarc_print.cloud_api.OneDrive') as microsoft:
            REGISTRY.cloud_store('onedrive', lambda: 'token')
            microsoft.assert_called_once()

    def test_cups_discovery_uses_fixed_command(self):
        from unittest.mock import Mock
        with patch('tabarc_print.plugins.subprocess.run', return_value=Mock(
                returncode=0, stdout='office\nlab\noffice\n', stderr='')) as run:
            self.assertEqual(discover_printers('cups'), ['lab', 'office'])
            self.assertEqual(run.call_args.args[0], ['lpstat', '-e'])
            self.assertNotIn('shell', run.call_args.kwargs)

    def test_refuse_unbounded_discovery(self):
        from unittest.mock import Mock
        with patch('tabarc_print.plugins.subprocess.run', return_value=Mock(
                returncode=0, stdout='a'*70000, stderr='')):
            with self.assertRaises(ValueError):
                discover_printers('cups')


if __name__ == '__main__':
    unittest.main()
