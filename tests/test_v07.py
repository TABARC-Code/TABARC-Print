"""v0.7 local desktop and managed user worker boundaries."""
import tempfile
from contextlib import closing
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch
from security_fixtures import local_vault_patch

from tabarc_print.desktop import DesktopController, _time_label
from tabarc_print.service import generate_unit, install_unit, remove_unit, unit_path

PDF = b'%PDF-1.6\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n'


class DesktopControllerTests(TestCase):
    def setUp(self):
        self.secure_vault_patch = local_vault_patch()
        self.secure_vault_patch.start()
        self.addCleanup(self.secure_vault_patch.stop)
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.root = Path(td.name)
        self.document = self.root / 'example.pdf'
        self.document.write_bytes(PDF)
        self.ctrl = DesktopController(self.root / 'state', backend='cups')

    def test_submit_hold_release_and_explicit_spool(self):
        jid = self.ctrl.submit(self.document, 'Office', held=True)
        self.assertEqual(self.ctrl.jobs()[0]['state'], 'held')
        self.assertIsNone(self.ctrl.process(jid))
        self.assertTrue(self.ctrl.release(jid))
        with patch('tabarc_print.plugins.PrinterBackend.submit_bytes', return_value='request id is Office-222 (1 file(s))') as spool:
            self.assertEqual(self.ctrl.process(jid)[1], 'submitted')
            spool.assert_called_once()
        self.assertEqual(self.ctrl.jobs()[0]['spool_ref'], 'Office-222')
        self.assertEqual([x['state'] for x in self.ctrl.history(jid)][:3], ['submitted', 'claimed', 'queued'])

    def test_cancel_prevents_printing(self):
        jid = self.ctrl.submit(self.document, 'Office', held=True)
        self.assertTrue(self.ctrl.cancel(jid))
        with patch('tabarc_print.plugins.PrinterBackend.submit_bytes') as spool:
            self.assertIsNone(self.ctrl.process(jid))
            spool.assert_not_called()

    def test_printers_and_builtins_are_thin_interfaces(self):
        with patch('tabarc_print.desktop.discover_printers', return_value=['Printer A']) as discover:
            self.assertEqual(self.ctrl.printers(), ['Printer A'])
            discover.assert_called_once_with('cups')
        self.assertIn('google', {p.name for p in self.ctrl.plugins()})

    def test_interrupted_job_never_automatically_reprints(self):
        jid = self.ctrl.submit(self.document, 'Office')
        with closing(self.ctrl.queue._db()) as db:
            db.execute("UPDATE jobs SET state='claimed' WHERE id=?", (jid,))
            db.commit()
        self.assertTrue(self.ctrl.interrupted(jid))
        with patch('tabarc_print.plugins.PrinterBackend.submit_bytes') as spool:
            self.assertIsNone(self.ctrl.process(jid))
            spool.assert_not_called()
        self.assertEqual(self.ctrl.queue.status(jid)['state'], 'uncertain')

    def test_no_unexpected_document_copy_to_cloud(self):
        with patch('tabarc_print.plugins.PluginRegistry.cloud_store') as cloud:
            self.ctrl.submit(self.document, 'Office')
            cloud.assert_not_called()

    def test_timestamp_fallback(self):
        self.assertEqual(_time_label(None), 'Unknown')


class UserServiceTests(TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        self.root = Path(td.name)

    def test_service_uses_user_worker_only(self):
        unit = generate_unit('/usr/bin/python3', backend='cups')
        self.assertIn('NoNewPrivileges=true', unit)
        self.assertIn('UMask=0077', unit)
        self.assertIn('tabarc_print.local', unit)
        self.assertIn('"work"', unit)
        self.assertNotIn('TABARC-Print-Cloud', unit)

    def test_unit_quotes_special_characters(self):
        unit = generate_unit('/opt/Some Space/py%thon', state_dir=self.root / 'print $files', backend='cups')
        self.assertIn('Some Space/py%%thon', unit)
        self.assertIn('print $$files', unit)
        with self.assertRaises(ValueError):
            generate_unit('/usr/bin/python\nX')
        with self.assertRaises(ValueError):
            generate_unit('/usr/bin/python', state_dir=Path('relative'))
        with self.assertRaises(ValueError):
            generate_unit('/usr/bin/python', backend='windows-sumatra')

    def test_installer_refuses_unowned_unit(self):
        path = unit_path(self.root)
        path.parent.mkdir(parents=True)
        path.write_text('[Service]\nExecStart=/bin/true')
        with self.assertRaises(ValueError):
            install_unit(path, generate_unit('/usr/bin/python3'))
        with self.assertRaises(ValueError):
            remove_unit(path)
        self.assertIn('/bin/true', path.read_text())

    def test_install_remove_only_owned_unit(self):
        path = unit_path(self.root)
        install_unit(path, generate_unit('/usr/bin/python3'))
        self.assertTrue(path.exists())
        self.assertTrue(remove_unit(path))
        self.assertFalse(remove_unit(path))

    def test_reject_symlink_destination(self):
        destination = self.root / 'bad.service'
        target = self.root / 'target'
        target.write_text('untouched')
        try:
            destination.symlink_to(target)
        except OSError:
            self.skipTest('Symbolic links unavailable')
        with self.assertRaises(ValueError):
            install_unit(destination, generate_unit('/usr/bin/python3'))
        self.assertEqual(target.read_text(), 'untouched')
