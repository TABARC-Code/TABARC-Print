"""The queue should survive a dropped connection without inventing a printed page."""
from contextlib import closing
from pathlib import Path
from unittest.mock import patch
from security_fixtures import local_vault_patch
import sqlite3
import tempfile
import threading
import unittest

from tabarc_print.local_queue import LocalQueue
from tabarc_print.plugins import parse_cups_job_reference
from tabarc_print.local import main as local_main

PDF = b'%PDF-1.5\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n'


class QueuesFromThePrinterWorkbench(unittest.TestCase):
    def setUp(self):
        self.secure_vault_patch = local_vault_patch()
        self.secure_vault_patch.start()
        self.addCleanup(self.secure_vault_patch.stop)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.doc = self.root / 'report.pdf'
        self.doc.write_bytes(PDF)
        self.queue = LocalQueue(self.root / 'state', 'cups')

    def test_held_job_cannot_print_until_released(self):
        job = self.queue.submit(self.doc, 'Office', held=True)
        with patch('tabarc_print.plugins.PrinterBackend.submit_bytes') as spool:
            self.assertIsNone(self.queue.process_one())
            self.assertIsNone(self.queue.process_one(job))
            spool.assert_not_called()
        self.assertTrue(self.queue.release(job))
        self.assertFalse(self.queue.release(job))
        with patch('tabarc_print.plugins.PrinterBackend.submit_bytes', return_value='request id is Office-42 (1 file(s))'):
            self.assertEqual(self.queue.process_one(job)[1], 'submitted')
        status = self.queue.status(job)
        self.assertEqual(status['spool_ref'], 'Office-42')
        self.assertIsNotNone(status['submitted_at'])
        self.assertEqual([entry['state'] for entry in self.queue.history(job)],
                         ['submitted', 'claimed', 'queued', 'held'])

    def test_queued_job_can_be_held_and_cancelled(self):
        job = self.queue.submit(self.doc, 'Office')
        self.assertTrue(self.queue.hold(job))
        self.assertFalse(self.queue.hold(job))
        self.assertTrue(self.queue.cancel(job))
        self.assertFalse(self.queue.release(job))
        self.assertFalse((self.queue.docs / (job + '.bin')).exists())
        self.assertEqual(self.queue.history(job)[0]['state'], 'cancelled')

    def test_corrupt_queued_payload_is_never_submitted(self):
        job = self.queue.submit(self.doc, 'Office')
        (self.queue.docs / (job + '.bin')).write_bytes(PDF + b'dirty change')
        with patch('tabarc_print.plugins.PrinterBackend.submit_bytes') as spool:
            self.assertEqual(self.queue.process_one(job)[1], 'uncertain')
            spool.assert_not_called()
        self.assertIn('changed since submission', self.queue.status(job)['message'])

    def test_queue_rejects_symlinked_stored_document(self):
        job = self.queue.submit(self.doc, 'Office')
        stored = self.queue.docs / (job + '.bin')
        stored.unlink()
        try:
            stored.symlink_to(self.doc)
        except (OSError, NotImplementedError):
            self.skipTest('No symlinks here')
        with patch('tabarc_print.plugins.PrinterBackend.submit_bytes') as spool:
            self.assertEqual(self.queue.process_one(job)[1], 'uncertain')
            spool.assert_not_called()

    def test_cups_identifier_not_a_printed_confirmation(self):
        job = self.queue.submit(self.doc, 'Office')
        with patch('tabarc_print.plugins.PrinterBackend.submit_bytes', return_value='request id is Office-123 (1 file(s))'):
            self.queue.process_one(job)
        self.assertEqual(self.queue.status(job)['state'], 'submitted')
        self.assertEqual(self.queue.status(job)['spool_ref'], 'Office-123')
        self.assertNotIn('printed', [e['state'] for e in self.queue.history(job)])

    def test_loss_of_acknowledgement_keeps_job_uncertain(self):
        job = self.queue.submit(self.doc, 'Office')
        with patch('tabarc_print.plugins.PrinterBackend.submit_bytes', side_effect=TimeoutError('spooler unknown')) as spool:
            self.assertEqual(self.queue.process_one(job)[1], 'uncertain')
            self.assertIsNone(LocalQueue(self.queue.root).process_one(job))
            spool.assert_called_once()
        self.assertIsNone(self.queue.status(job)['spool_ref'])

    def test_event_history_guardrails(self):
        with self.assertRaises(ValueError):
            self.queue.history('../nope')
        with self.assertRaises(ValueError):
            self.queue.history('a' * 32, limit=501)
        self.assertEqual(self.queue.history('a' * 32), [])

    def test_upgrades_previous_database_in_place(self):
        old_root = self.root / 'old'
        old_root.mkdir(mode=0o700)
        old_db = old_root / 'local-jobs.sqlite3'
        with closing(sqlite3.connect(old_db)) as db:
            db.execute('CREATE TABLE jobs (id TEXT PRIMARY KEY, printer TEXT NOT NULL, '
                       'filename TEXT NOT NULL, state TEXT NOT NULL, message TEXT NOT NULL, '
                       'created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL)')
            db.execute('INSERT INTO jobs VALUES (?,?,?,?,?,?,?)', ('b'*32,'Office','old.pdf','submitted','ok',1,1))
            db.commit()
        migrated = LocalQueue(old_root, 'cups')
        self.assertEqual(migrated.status('b'*32)['state'], 'submitted')
        self.assertIsNone(migrated.status('b'*32)['spool_ref'])
        with closing(migrated._db()) as db:
            self.assertIn('document_sha256', {r['name'] for r in db.execute('PRAGMA table_info(jobs)')})

    def test_two_workers_one_submission_even_with_hold(self):
        job = self.queue.submit(self.doc, 'Office', held=True)
        self.assertTrue(self.queue.release(job))
        other = LocalQueue(self.queue.root, 'cups')
        results = []
        lock = threading.Lock()
        with patch('tabarc_print.plugins.PrinterBackend.submit_bytes', return_value='request id is Office-1 (1 file(s))') as spool:
            def worker(queue):
                result = queue.process_one()
                with lock:
                    results.append(result)
            first = threading.Thread(target=worker, args=(self.queue,))
            second = threading.Thread(target=worker, args=(other,))
            first.start(); second.start(); first.join(); second.join()
            self.assertEqual(spool.call_count, 1)
            self.assertEqual(sum(result is not None for result in results), 1)

    def test_cli_held_job_is_not_printed(self):
        with patch('tabarc_print.plugins.PrinterBackend.submit_bytes') as spool:
            self.assertEqual(local_main(['--state-dir', str(self.root/'cli'), 'submit',
                    '--pdf', str(self.doc), '--printer', 'Office', '--hold']), 0)
            spool.assert_not_called()


class SpoolerAcknowledgementTests(unittest.TestCase):
    def test_exact_request_format(self):
        self.assertEqual(parse_cups_job_reference('request id is lab_print-842 (1 file(s))'), 'lab_print-842')
        self.assertIsNone(parse_cups_job_reference('Printer prints immediately'))
        self.assertIsNone(parse_cups_job_reference('request id is ./../../etc/passwd'))
        self.assertIsNone(parse_cups_job_reference('request id is x\nsecond line'))


if __name__ == '__main__':
    unittest.main()
