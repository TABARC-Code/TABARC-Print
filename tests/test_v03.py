"""Encrypted jobs, old-format compatibility and spool recovery."""
import json
from pathlib import Path
from unittest import TestCase
from unittest.mock import patch, Mock
import tempfile

from tabarc_print.cloud_gateway import CloudGateway
from tabarc_print.common import spool_pdf
from tabarc_print.gateway import build_job, FolderGateway
from tabarc_print.metadata import open_manifest
from tabarc_print.ledger import AgentLedger
from tabarc_print.agent import Agent
from tabarc_print.server import Coordinator
from test_cloud import MemoryCloud, SECRET, PDF


class EncryptedGatewayTests(TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.pdf = self.root / 'document.pdf'
        self.pdf.write_bytes(PDF)
        self.store = MemoryCloud()
        self.sender = CloudGateway(self.store, SECRET, self.root / 'sender')
        self.receiver = CloudGateway(self.store, SECRET, self.root / 'receiver', {'remote':'local'}, dry_run=True, allow_direct_submission=True)

    def test_cloud_transport_does_not_store_plaintext(self):
        jid = self.sender.send(self.pdf, 'remote')
        stored = {x['name']: x['data'] for x in self.store.files['inbox'].values()}
        self.assertEqual(set(stored), {jid + '.bin', jid + '.job.bin'})
        self.assertNotIn(PDF, stored[jid + '.bin'])
        self.assertFalse(stored[jid + '.bin'].startswith(b'%PDF-'))
        self.assertNotIn(b'remote', stored[jid + '.job.bin'])
        manifest = open_manifest(SECRET, jid, stored[jid + '.job.bin'])
        self.assertEqual(manifest['version'], 4)
        self.assertEqual(manifest['encryption']['algorithm'], 'AES-256-GCM')
        self.assertEqual(self.receiver.once()[jid], 'submitted')
        self.assertEqual(self.sender.status(jid)['state'], 'submitted')
        self.assertEqual(self.store.list_files('inbox'), [])

    def test_tampered_ciphertext_rejected(self):
        jid = self.sender.send(self.pdf, 'remote')
        for entry in self.store.files['inbox'].values():
            if entry['name'] == jid + '.bin':
                entry['data'] = entry['data'][:-1] + bytes([entry['data'][-1] ^ 1])
        self.assertIn('integrity', self.receiver.once()[jid])
        self.assertIsNone(self.sender.status(jid))

    def test_tampered_nonce_rejected(self):
        jid = self.sender.send(self.pdf, 'remote')
        for entry in self.store.files['inbox'].values():
            if entry['name'].endswith('.job.bin'):
                entry['data'] = entry['data'][:4] + bytes([entry['data'][4] ^ 1]) + entry['data'][5:]
        self.assertIn('authentication', self.receiver.once()[jid])

    def test_wrong_decryption_secret_refused(self):
        jid = self.sender.send(self.pdf, 'remote')
        wrong = CloudGateway(self.store, b'z' * 42, self.root / 'wrong', {'remote': 'local'}, dry_run=True, allow_direct_submission=True)
        self.assertIn('authentication', wrong.once()[jid])

    def test_legacy_plaintext_is_disabled(self):
        with self.assertRaisesRegex(ValueError, 'Plaintext'):
            CloudGateway(self.store, SECRET, self.root / 'old', encrypt=False)
        with self.assertRaisesRegex(ValueError, 'Plaintext'):
            CloudGateway(self.store, SECRET, self.root / 'compat', {'remote':'local'},
                         dry_run=True, allow_legacy_plaintext=True)

    def test_folder_encryption_with_no_sync_client(self):
        folder = self.root / 'shared'
        jid = build_job(folder, self.pdf, 'remote', SECRET, encrypt=True)
        self.assertTrue((folder / 'inbox' / (jid + '.bin')).exists())
        self.assertFalse((folder / 'inbox' / (jid + '.pdf')).exists())
        receiver = FolderGateway(folder, {'remote':'local'}, SECRET, dry_run=True,
                                 state_dir=self.root / 'ledger', require_encryption=True, allow_direct_submission=True)
        self.assertEqual(receiver.process_one(jid), 'submitted')


class WindowsBackendTests(TestCase):
    def test_windows_renderer_uses_argument_list_not_shell(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            exe = root / 'SumatraPDF.exe'
            exe.write_bytes(b'not-an-executable')
            pdf = root / 'test.pdf'
            pdf.write_bytes(PDF)
            completed = Mock(returncode=0, stdout='', stderr='')
            with patch('tabarc_print.common.subprocess.run', return_value=completed) as run:
                self.assertIn('Windows', spool_pdf(pdf, 'Office Printer', backend='windows-sumatra', windows_renderer=str(exe)))
            args = run.call_args.args[0]
            self.assertEqual(args[:4], [str(exe.resolve()), '-print-to', 'Office Printer', '-silent'])
            self.assertEqual(args[-1], str(pdf.resolve()))
            self.assertNotIn('shell', run.call_args.kwargs)

    def test_windows_renderer_missing_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            pdf = Path(d) / 'a.pdf'
            pdf.write_bytes(PDF)
            with self.assertRaises(ValueError):
                spool_pdf(pdf, 'Office', backend='windows-sumatra', windows_renderer=str(Path(d) / 'missing.exe'))


class DurableAgentTests(TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.jid = 'a' * 32

    def make_agent(self):
        return Agent('http://127.0.0.1:8999', 'agent-' + 'x'*40, 'agent1',
                     {'remote':'queue'}, dry_run=True, state_dir=self.root / 'ledger')

    def test_retry_of_spooled_job_does_not_respool(self):
        agent = self.make_agent()
        job = {'id': self.jid, 'printer_id': 'remote'}
        calls = []
        def request(method, path, data=None, content_type='application/json'):
            calls.append((method, path, data))
            if path == '/v1/agent/claim':
                return {'job': job}
            if path.startswith('/v1/agent/document/'):
                return PDF
            if path.startswith('/v1/agent/complete/') and len([x for x in calls if x[1].startswith('/v1/agent/complete/')]) == 1:
                raise ConnectionError('Response lost after submission')
            return {'ok':True}
        agent.request = request
        with self.assertRaises(ConnectionError):
            agent.once()
        self.assertEqual(agent.ledger.claim(self.jid)[0], 'submitted')
        self.assertTrue(agent.once())
        self.assertEqual(len([c for c in calls if c[1].startswith('/v1/agent/document/')]), 1)
        self.assertEqual(calls[-1][2]['success'], True)

    def test_crash_after_claim_is_uncertain_not_printed_again(self):
        agent = self.make_agent()
        agent.ledger.claim(self.jid)
        calls = []
        def request(method, path, data=None, content_type='application/json'):
            calls.append((method, path, data))
            return {'job': {'id':self.jid, 'printer_id':'remote'}} if path.endswith('/claim') else {'ok':True}
        agent.request = request
        self.assertTrue(agent.once())
        self.assertFalse(any('/document/' in c[1] for c in calls))
        self.assertTrue(calls[-1][2]['uncertain'])

    def test_rejects_login_information_in_coordinator_url(self):
        for url in ('http://127.0.0.1:8080@evil.example', 'http://localhost:80@evil.example',
                    'http://server.example:8421', 'https://evil.example/?token=abc',
                    'https://evil.example#fragment'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                Agent(url, 'agent-' + 'x'*40, 'agent1', {'remote':'queue'},
                      state_dir=self.root / 'forbidden')

    def test_coordinator_accepts_uncertain_state(self):
        c = Coordinator(self.root / 'server', 'client-'+'a'*40, 'agent-'+'b'*40)
        c.register('agent1','remote','Printer')
        jid = c.submit('remote','x.pdf',PDF)
        self.assertEqual(c.claim('agent1')['id'], jid)
        c.complete(jid, 'agent1', False, 'Unknown outcome', uncertain=True)
        self.assertEqual(c.jobs()[0]['state'], 'uncertain')
        self.assertIsNone(c.claim('agent1'))
