"""Tor mode security and handoff tests, without a Tor daemon or live printer."""
import base64
import hashlib
import json
from pathlib import Path
import socket
import struct
import tempfile
import threading
import unittest
from unittest.mock import patch

from tabarc_print.tor_transport import (
    TorPrintReceiver, TorPrintSender, TorPrintListener, _document, _open_receipt,
    _seal_receipt, _packet, _send_packet, connect_socks_onion, check_onion,
    _MAX_MANIFEST, _MAGIC,
)

PDF = b'%PDF-1.4\n1 0 obj<<>>endobj\n%%EOF\n'
SECRET = bytes(range(32))
RECEIVER = 'c' * 32


def onion():
    public = bytes(range(32))
    v = b'\x03'
    check = hashlib.sha3_256(b'.onion checksum' + public + v).digest()[:2]
    return base64.b32encode(public + check + v).decode().lower() + '.onion'


class TestTorPrint(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.pdf = self.root / 'original.pdf'
        self.pdf.write_bytes(PDF)
        self.calls = []
        self.agent = TorPrintReceiver(SECRET, RECEIVER, self.root/'state',
                                      {'remote':'local'}, spooler=lambda p, q:self.calls.append((p, q)), allow_direct_submission=True)

    def test_accept_encrypted_targeted_job_and_durable_dedup(self):
        jid, manifest, payload = _document(SECRET, PDF, 'remote', RECEIVER)
        self.assertNotIn(PDF, payload)
        receipt = _open_receipt(SECRET, jid, self.agent.accept(manifest, payload))
        self.assertEqual(receipt['state'], 'submitted')
        self.assertEqual(self.calls, [(PDF, 'local')])
        second = TorPrintReceiver(SECRET, RECEIVER, self.root/'state', {'remote':'local'},
                                   spooler=lambda p,q:self.calls.append((p,q)), allow_direct_submission=True)
        self.assertEqual(_open_receipt(SECRET, jid, second.accept(manifest,payload))['state'], 'submitted')
        self.assertEqual(len(self.calls), 1)

    def test_wrong_key_and_modified_payload_rejected(self):
        _, m, p = _document(SECRET, PDF, 'remote', RECEIVER)
        wrong = TorPrintReceiver(b'2'*32, RECEIVER, self.root/'other', {'remote':'local'}, dry_run=True)
        with self.assertRaises(PermissionError):
            wrong.accept(m,p)
        with self.assertRaisesRegex(ValueError, 'digest'):
            self.agent.accept(m,p[:-1] + bytes([p[-1] ^ 1]))
        self.assertEqual(self.calls, [])

    def test_plaintext_version_and_wrong_device_rejected(self):
        _, m, p = _document(SECRET, PDF, 'remote', RECEIVER)
        data = json.loads(m)
        data.pop('encryption')
        data['version'] = 1
        with self.assertRaises(ValueError):
            self.agent.accept(json.dumps(data).encode(), p)
        other = TorPrintReceiver(SECRET, 'd'*32, self.root/'other', {'remote':'local'}, dry_run=True)
        with self.assertRaises(PermissionError):
            other.accept(m,p)

    def test_failed_spool_does_not_retry(self):
        errors = TorPrintReceiver(SECRET, RECEIVER, self.root/'error', {'remote':'local'},
            spooler=lambda p,q: (_ for _ in ()).throw(RuntimeError('printer lost')), allow_direct_submission=True)
        jid,m,p = _document(SECRET,PDF,'remote',RECEIVER)
        self.assertEqual(_open_receipt(SECRET,jid,errors.accept(m,p))['state'],'uncertain')
        self.assertEqual(_open_receipt(SECRET,jid,errors.accept(m,p))['state'],'uncertain')

    def test_receipt_is_encrypted_and_authenticated(self):
        jid='a'*32
        sealed = _seal_receipt(SECRET, jid, 'submitted')
        self.assertNotIn(b'submitted', sealed)
        with self.assertRaisesRegex(ValueError,'authentication'):
            _open_receipt(SECRET,jid,sealed[:-1] + bytes([sealed[-1]^1]))

    def test_reject_non_onion_and_bad_checksum(self):
        valid=onion()
        self.assertEqual(check_onion(valid),valid)
        for bad in ('google.com', '127.0.0.1', 'https://'+valid, valid[:-6]+'a.onion', 'a'*56+'.onion'):
            with self.assertRaises(ValueError):
                check_onion(bad)

    def test_sender_through_socks5_proxy_with_domain_only(self):
        expected=onion()
        with TorPrintListener(self.agent,0) as listener:
            listener_thread=threading.Thread(target=listener.serve_forever,daemon=True)
            listener_thread.start()
            with socket.socket() as sock:
                sock.bind(('127.0.0.1',0));sock.listen(1)
                port=sock.getsockname()[1]
                seen=[]
                # Avoid fragile loopback relay in this test: only check SOCKS handshake.
                def just_handshake():
                    conn,_=sock.accept()
                    with conn:
                        conn.settimeout(3)
                        self.assertEqual(conn.recv(3),b'\x05\x01\x00')
                        conn.sendall(b'\x05\x00')
                        h=conn.recv(5)
                        self.assertEqual(h[:4],b'\x05\x01\x00\x03')
                        seen.append(conn.recv(h[4]).decode())
                        conn.recv(2)
                        conn.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
                t=threading.Thread(target=just_handshake,daemon=True)
                t.start()
                connected=connect_socks_onion(expected,8787,socks_port=port)
                connected.close();t.join(3)
                self.assertEqual(seen,[expected])
            listener.shutdown(); listener_thread.join(3)

    def test_sender_listener_complete_encrypted_round_trip(self):
        target = onion()
        with TorPrintListener(self.agent, 0) as listener:
            thread = threading.Thread(target=listener.serve_forever, daemon=True)
            thread.start()
            with patch('tabarc_print.tor_transport.connect_socks_onion',
                       side_effect=lambda *a, **kw: socket.create_connection(listener.server_address)):
                jid, receipt = TorPrintSender(SECRET).send(self.pdf, 'remote', RECEIVER, target)
            listener.shutdown()
            thread.join(3)
        self.assertEqual(receipt['job_id'], jid)
        self.assertEqual(receipt['state'], 'submitted')
        self.assertEqual(self.calls, [(PDF, 'local')])

    def test_listener_ignores_unauthenticated_plaintext(self):
        with TorPrintListener(self.agent,0) as listener:
            thread=threading.Thread(target=listener.serve_forever,daemon=True);thread.start()
            with socket.create_connection(listener.server_address) as sock:
                sock.sendall(_MAGIC)
                _send_packet(sock,b'{"version":1}',_MAX_MANIFEST)
                self.assertEqual(sock.recv(1),b'')
            listener.shutdown();thread.join(3)
            self.assertEqual(self.calls,[])

if __name__=='__main__':unittest.main()

class TorSpoolerTests(unittest.TestCase):
    def test_cups_submits_document_through_stdin(self):
        from unittest.mock import Mock
        from tabarc_print.plugins import PrinterBackend
        with patch('tabarc_print.plugins.subprocess.run', return_value=Mock(
                returncode=0, stdout=b'request id is Office-10', stderr=b'')) as run:
            self.assertEqual(PrinterBackend('cups').submit_bytes(PDF, 'Office'), 'request id is Office-10')
        self.assertEqual(run.call_args.args[0], ['lp', '-d', 'Office', '-'])
        self.assertEqual(run.call_args.kwargs['input'], PDF)
        self.assertNotIn('shell', run.call_args.kwargs)

    def test_windows_secure_byte_submission_is_blocked(self):
        from tabarc_print.plugins import PrinterBackend
        with self.assertRaisesRegex(RuntimeError, 'not available'):
            PrinterBackend('windows-sumatra').submit_bytes(PDF, 'Office')
