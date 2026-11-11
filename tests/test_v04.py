"""Coordinator boundaries: user sharing, connector identities and lease handling."""
from contextlib import closing

import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
from threading import Thread
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from tabarc_print.access import AccessPolicy, token_digest
from tabarc_print.server import Coordinator, Server

PDF = b'%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n'
TOKENS = {name: 'v04-' + name + '-xyz-' + character * 42 for name, character in (
    ('alice','a'), ('bob','b'), ('edge1','c'), ('edge2','d'))}


def access_file(root):
    config = {'users': [
        {'id':'alice', 'token_sha256': token_digest(TOKENS['alice']), 'printers':['office']},
        {'id':'bob', 'token_sha256': token_digest(TOKENS['bob']), 'printers':['workshop']},
    ], 'agents': [
        {'id':'edge1', 'token_sha256': token_digest(TOKENS['edge1']), 'printers':['office']},
        {'id':'edge2', 'token_sha256': token_digest(TOKENS['edge2']), 'printers':['workshop']},
    ]}
    f = root / 'access.json'
    f.write_text(json.dumps(config))
    f.chmod(0o600)
    return f


class MultiUserCoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.access = access_file(self.root)
        self.coordinator = Coordinator(self.root / 'coordinator', access_file=self.access)
        self.server = Server(('127.0.0.1',0),self.coordinator)
        self.thread = Thread(target=self.server.serve_forever,daemon=True)
        self.thread.start()
        self.addCleanup(self.finish_server)
        self.url = 'http://127.0.0.1:' + str(self.server.server_port)

    def finish_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)

    def request(self, path, who, method='GET', data=None, extra=None):
        headers = {'Authorization':'Bearer '+TOKENS[who]}
        if who.startswith('edge'):
            headers['X-Agent-ID'] = who
        if extra:
            headers.update(extra)
        request = Request(self.url + path, method=method, data=data, headers=headers)
        with urlopen(request, timeout=3) as response:
            return response.status, json.loads(response.read()) if response.headers.get('Content-Type','').startswith('application/json') else response.read()

    def register(self):
        for agent, printer in [('edge1','office'),('edge2','workshop')]:
            self.request('/v1/agent/register',agent,'POST',json.dumps({
                'agent_id':agent,'printer_id':printer,'label':printer}).encode())

    def submit(self, user, printer):
        _, reply = self.request('/v1/jobs',user,'POST',PDF,
                                {'X-Printer-ID':printer,'X-Filename':'private.pdf'})
        return reply['id']

    def assert_http(self, code, path, who, method='GET', data=None, extra=None):
        with self.assertRaises(HTTPError) as exc:
            self.request(path,who,method,data,extra)
        self.assertEqual(exc.exception.code,code)

    def test_share_printers_and_hide_other_users_jobs(self):
        self.register()
        self.assertEqual([x['id'] for x in self.request('/v1/printers','alice')[1]['printers']], ['office'])
        self.assertEqual([x['id'] for x in self.request('/v1/printers','bob')[1]['printers']], ['workshop'])
        self.assertEqual(self.request('/v1/me','alice')[1]['id'], 'alice')
        self.assert_http(403,'/v1/jobs','bob','POST',PDF,{'X-Printer-ID':'office'})
        j1 = self.submit('alice','office')
        j2 = self.submit('bob','workshop')
        self.assertEqual([x['id'] for x in self.request('/v1/jobs','alice')[1]['jobs']], [j1])
        self.assertEqual([x['id'] for x in self.request('/v1/jobs','bob')[1]['jobs']], [j2])

    def test_no_agent_identity_impersonation_or_cross_printer_registration(self):
        self.register()
        payload = json.dumps({'agent_id':'edge2','printer_id':'workshop','label':'hijack'}).encode()
        self.assert_http(403,'/v1/agent/register','edge1','POST',payload)
        payload = json.dumps({'agent_id':'edge1','printer_id':'workshop','label':'hijack'}).encode()
        self.assert_http(403,'/v1/agent/register','edge1','POST',payload)
        self.assert_http(401,'/v1/agent/claim','edge1',extra={'X-Agent-ID':'edge2'})
        self.assert_http(401,'/v1/agent/claim','alice',extra={'X-Agent-ID':'edge1'})
        j1 = self.submit('alice','office')
        j2 = self.submit('bob','workshop')
        self.assertEqual(self.request('/v1/agent/claim','edge1')[1]['job']['id'],j1)
        self.assertEqual(self.request('/v1/agent/claim','edge2')[1]['job']['id'],j2)
        self.assert_http(400,'/v1/agent/document/'+j1,'edge2')
        self.assert_http(403,'/v1/agent/complete/'+j1,'edge2','POST', json.dumps({
            'agent_id':'edge1','success':True}).encode())
        self.request('/v1/agent/complete/'+j1,'edge1','POST',json.dumps({
            'agent_id':'edge1','success':True,'message':'DRY_RUN'}).encode())
        self.assertEqual(self.request('/v1/jobs','alice')[1]['jobs'][0]['state'],'submitted')

    def test_client_can_cancel_own_queued_or_uncertain_job(self):
        self.register()
        j = self.submit('alice','office')
        self.assert_http(403,'/v1/jobs/'+j,'bob','DELETE')
        self.assertEqual(self.request('/v1/jobs/'+j,'alice','DELETE')[1],{'ok':True})
        self.assertFalse((self.coordinator.docs/(j+'.pdf')).exists())
        self.assertEqual(self.request('/v1/jobs','alice')[1]['jobs'][0]['state'],'cancelled')
        self.assertIsNone(self.request('/v1/agent/claim','edge1')[1]['job'])
        self.assert_http(400,'/v1/jobs/'+j,'alice','DELETE')

    def test_leased_job_cannot_be_cancelled_by_user(self):
        self.register()
        jid = self.submit('alice','office')
        self.request('/v1/agent/claim','edge1')
        self.assert_http(400,'/v1/jobs/'+jid,'alice','DELETE')

    def test_expired_lease_becomes_uncertain_and_never_requeued(self):
        self.register()
        with patch('tabarc_print.server.now', return_value=1000):
            jid = self.submit('alice','office')
            claimed = self.request('/v1/agent/claim','edge1')[1]['job']
            self.assertEqual(claimed['id'],jid)
        with patch('tabarc_print.server.now', return_value=1300):
            self.assertIsNone(self.request('/v1/agent/claim','edge1')[1]['job'])
        self.assertEqual(self.request('/v1/jobs','alice')[1]['jobs'][0]['state'],'uncertain')
        self.assert_http(400, '/v1/agent/document/'+jid,'edge1')
        self.request('/v1/jobs/'+jid,'alice','DELETE')
        self.assertFalse((self.coordinator.docs/(jid+'.pdf')).exists())

    def test_server_data_is_private(self):
        if os.name != 'nt':
            for path in (self.coordinator.root, self.coordinator.docs, self.coordinator.dbfile):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o077, 0, str(path))

    def test_legacy_database_migration_does_not_expose_old_jobs(self):
        old = self.root/'old'
        old.mkdir()
        db = old/'print.sqlite3'
        with closing(sqlite3.connect(db)) as con:
            con.executescript('''CREATE TABLE printers (id TEXT PRIMARY KEY,label TEXT,agent_id TEXT,created_at INTEGER);
            CREATE TABLE jobs (id TEXT PRIMARY KEY,printer_id TEXT,state TEXT,filename TEXT,sha256 TEXT,
            created_at INTEGER,updated_at INTEGER,leased_until INTEGER,leased_to TEXT,error TEXT);
            INSERT INTO jobs VALUES ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','office','submitted','old.pdf','0',1,1,NULL,NULL,NULL);''')
        policy = Coordinator(old, access_file=self.access)
        self.assertEqual(policy.jobs(policy.authenticate(TOKENS['alice'],'client')),[])
        with closing(sqlite3.connect(db)) as con:
            row = con.execute('SELECT owner_id FROM jobs').fetchone()
        self.assertEqual(row[0],'@legacy')


class AccessFileTests(unittest.TestCase):
    def test_reject_bad_permissions_and_duplicate_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            file=access_file(root)
            if os.name != 'nt':
                file.chmod(0o644)
                with self.assertRaises(PermissionError): AccessPolicy.from_file(file)
                file.chmod(0o600)
            cfg=json.loads(file.read_text())
            cfg['agents'][0]['token_sha256']=cfg['users'][0]['token_sha256']
            file.write_text(json.dumps(cfg))
            with self.assertRaises(ValueError): AccessPolicy.from_file(file)

    def test_reject_symlink_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            file=access_file(root)
            link=root/'link'
            try: link.symlink_to(file)
            except (OSError,NotImplementedError): self.skipTest('No symlinks available')
            with self.assertRaises(ValueError): AccessPolicy.from_file(link)

if __name__=='__main__': unittest.main()
