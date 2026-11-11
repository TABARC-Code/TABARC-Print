"""Direct-API print mailbox, without a sync client or exposed inbound print port."""
import argparse
from contextlib import closing
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import time

from .cloud_api import CloudError, GoogleDrive, OneDrive, job_filename
from .cloud_auth import GoogleAuth, MicrosoftAuth, private_auth_dir
from .common import MAX_FILE_BYTES, atomic_write, safe_job_id, validate_printer_id
from .crypto import MAX_OVERHEAD
from .gateway import FolderGateway, build_job
from .metadata import MANIFEST_SUFFIX, RECEIPT_SUFFIX, open_manifest, open_receipt, seal_receipt
from .receiver_identity import check_receiver_id

MANIFEST_RE = re.compile(r'^([0-9a-f]{32})\.job\.bin$')


def receipt_bytes(job_id, state, message):
    from .common import now
    return {'job_id': job_id, 'state': state, 'message': message[:300], 'at': now()}


def sign_receipt(secret, receipt):
    body = json.dumps(receipt, sort_keys=True, separators=(',', ':')).encode()
    receipt = dict(receipt)
    receipt['signature'] = hmac.new(secret, body, hashlib.sha256).hexdigest()
    return json.dumps(receipt, sort_keys=True).encode()


def verify_receipt(secret, job_id, raw):
    safe_job_id(job_id)
    if len(secret) < 32:
        raise ValueError('Gateway secret must contain at least 32 bytes')
    if len(raw) > 8192:
        raise ValueError('Oversized receipt')
    receipt = json.loads(raw)
    if not isinstance(receipt, dict) or receipt.get('job_id') != job_id:
        raise ValueError('Wrong receipt ID')
    signature = receipt.pop('signature', None)
    if not isinstance(signature, str):
        raise ValueError('Missing receipt signature')
    expected = hmac.new(secret, json.dumps(receipt, sort_keys=True, separators=(',', ':')).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError('Invalid receipt signature')
    return receipt


def unique_names(items):
    result = {}
    for item in items:
        name = item.get('name')
        if name in result:
            raise CloudError('Duplicate filename in cloud mailbox: ' + str(name)[:100])
        result[name] = item
    return result


class CloudGateway:
    def __init__(self, store, secret, state_dir, printers=None, dry_run=False,
                 encrypt=True, allow_legacy_plaintext=False, backend='auto', windows_renderer=None,
                 receiver_id=None, target_receiver=None, allow_direct_submission=False, queue=None):
        if len(secret) < 32:
            raise ValueError('Use a random gateway secret of at least 32 bytes')
        if not encrypt or allow_legacy_plaintext:
            raise ValueError('Plaintext transport is disabled')
        self.store = store
        self.secret = secret
        self.state = private_auth_dir(state_dir)
        self.printers = printers
        self.encrypt = encrypt
        self.allow_legacy_plaintext = allow_legacy_plaintext
        self.receiver_id = check_receiver_id(receiver_id) if receiver_id else None
        self.target_receiver = check_receiver_id(target_receiver) if target_receiver else None
        if self.target_receiver and not encrypt:
            raise ValueError('Receiver-targeted cloud jobs must be encrypted')
        self.local = self.state / 'mailbox'
        self.local.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.inbox = self.local / 'inbox'
        self.receipts = self.local / 'receipts'
        self.inbox.mkdir(exist_ok=True)
        self.receipts.mkdir(exist_ok=True)
        self.worker = (FolderGateway(self.local, printers, secret, dry_run,
                                     self.state / 'ledger',
                                     require_encryption=not allow_legacy_plaintext,
                                     backend=backend, windows_renderer=windows_renderer,
                                     receiver_id=self.receiver_id,
                                     allow_direct_submission=allow_direct_submission, queue=queue) if printers else None)

    def send(self, pdf: Path, printer_id: str):
        validate_printer_id(printer_id)
        with tempfile.TemporaryDirectory(prefix='tabarc-send-') as tmp:
            root = Path(tmp)
            jid = build_job(root, pdf, printer_id, self.secret, encrypt=self.encrypt,
                            target_receiver=self.target_receiver)
            inbox = root / 'inbox'
            # Upload the manifest last. A receiver ignores orphan files.
            suffix = '.bin'
            mime = 'application/octet-stream'
            self.store.upload('inbox', jid + suffix, (inbox / (jid + suffix)).read_bytes(), mime)
            self.store.upload('inbox', jid + MANIFEST_SUFFIX, (inbox / (jid + MANIFEST_SUFFIX)).read_bytes(), 'application/octet-stream')
            return jid

    def status(self, jid):
        safe_job_id(jid)
        name = jid + RECEIPT_SUFFIX
        items = unique_names(self.store.list_files('receipts'))
        if name not in items:
            if jid + '.json' in items:
                raise ValueError('Legacy readable receipt refused; re-send using encrypted metadata')
            return None
        raw = self.store.download(items[name]['id'], 8192)
        return open_receipt(self.secret, jid, raw)

    def recover_missing_receipt(self, jid):
        # The durable claim stops double printing after a crash. A missing receipt
        # must be reconstructed rather than leaving the sender waiting forever.
        with closing(self.worker.db()) as db:
            row = db.execute('SELECT state FROM processed WHERE id=?', (jid,)).fetchone()
        if not row:
            return False
        state = row[0]
        if state == 'claimed':
            result = 'uncertain'
            message = 'Connector stopped after claiming; inspect the local spooler before resubmitting'
        elif state == 'held':
            result = 'held'
            message = 'Recovered remote intake; document remains held locally'
        elif state == 'submitted':
            result = 'submitted'
            message = 'Recovered submission record; physical printing is not confirmed'
        else:
            result = 'failed'
            message = 'Recovered failed job record; original error details unavailable'
        atomic_write(self.receipts / (jid + RECEIPT_SUFFIX),
                     seal_receipt(self.secret, jid, result, message, int(time.time())))
        return True

    def publish(self, jid, inbox_index, receipt_index):
        filename = jid + RECEIPT_SUFFIX
        local_receipt = self.receipts / filename
        if not local_receipt.exists():
            return False
        raw = local_receipt.read_bytes()
        open_receipt(self.secret, jid, raw)
        if filename in receipt_index:
            remote = self.store.download(receipt_index[filename]['id'], 8192)
            if remote != raw:
                raise CloudError('Conflicting remote receipt; refusing to delete print job')
        else:
            uploaded_id = self.store.upload('receipts', filename, raw, 'application/octet-stream')
            remote = self.store.download(uploaded_id, 8192)
            if remote != raw:
                raise CloudError('Receipt upload could not be verified')
            receipt_index[filename] = {'id': uploaded_id, 'name': filename}
        # Receipt is verifiably present remotely. Never remove the only acknowledgement.
        for suffix in (MANIFEST_SUFFIX, '.bin'):
            item = inbox_index.get(jid + suffix)
            if item:
                try:
                    self.store.delete(item['id'])
                except CloudError as exc:
                    if exc.status != 404:
                        raise
        return True

    def once(self):
        if self.worker is None:
            raise ValueError('Configure --printer for a receiving connector')
        inbox_index = unique_names(self.store.list_files('inbox'))
        receipt_index = unique_names(self.store.list_files('receipts'))
        results = {}
        for name in inbox_index:
            old = re.fullmatch(r'([0-9a-f]{32})\.job\.json', name)
            if old:
                results[old.group(1)] = 'rejected: legacy readable manifest; re-send using encrypted metadata'
        # Finish any receipts left unpublished after a previous network failure.
        for receipt in sorted(self.receipts.glob('*' + RECEIPT_SUFFIX)):
            jid = receipt.name.removesuffix(RECEIPT_SUFFIX)
            if re.fullmatch(r'[0-9a-f]{32}', jid):
                self.publish(jid, inbox_index, receipt_index)
        for name, item in sorted(inbox_index.items()):
            match = MANIFEST_RE.fullmatch(name)
            if not match:
                continue
            jid = match.group(1)
            if jid in results:
                results[jid] = 'rejected: ambiguous legacy and encrypted metadata'
                continue
            if self.receipts.joinpath(jid + RECEIPT_SUFFIX).exists():
                continue
            if self.recover_missing_receipt(jid):
                self.publish(jid, inbox_index, receipt_index)
                results[jid] = 'recovered'
                continue
            doc_candidates = [(suffix, inbox_index[jid + suffix]) for suffix in ('.bin',)
                              if jid + suffix in inbox_index]
            if not doc_candidates:
                results[jid] = 'pending-document'
                continue
            if len(doc_candidates) != 1:
                results[jid] = 'rejected: ambiguous document'
                continue
            suffix, doc_item = doc_candidates[0]
            # Do not persist the job locally until both objects are fully fetched.
            manifest = self.store.download(item['id'], 8192)
            # A recipient checks metadata authentication before fetching the document.
            try:
                header = open_manifest(self.secret, jid, manifest)
            except (ValueError, TypeError) as exc:
                results[jid] = 'rejected: ' + str(exc)[:150]
                continue
            if 'target_receiver' in header and header['target_receiver'] != self.receiver_id:
                results[jid] = 'not-for-this-device'
                continue
            document = self.store.download(doc_item['id'], MAX_FILE_BYTES + MAX_OVERHEAD + 1)
            if len(document) > MAX_FILE_BYTES + MAX_OVERHEAD:
                results[jid] = 'rejected: oversized document'
                continue
            atomic_write(self.inbox / (jid + suffix), document)
            atomic_write(self.inbox / (jid + MANIFEST_SUFFIX), manifest)
            result = self.worker.process_one(jid)
            results[jid] = result
            if result in ('held', 'submitted', 'failed'):
                self.publish(jid, inbox_index, receipt_index)
            elif result.startswith('rejected'):
                (self.inbox / (jid + MANIFEST_SUFFIX)).unlink(missing_ok=True)
                (self.inbox / (jid + suffix)).unlink(missing_ok=True)
        return results


def make_auth(args):
    if args.provider == 'google':
        return GoogleAuth(args.auth_dir, args.google_credentials)
    return MicrosoftAuth(args.auth_dir, args.microsoft_client_id, args.microsoft_tenant)


def main():
    parser = argparse.ArgumentParser(description='Direct Google Drive / OneDrive print gateway')
    sub = parser.add_subparsers(dest='action', required=True)
    for action in ('login', 'send', 'status', 'receive'):
        subp = sub.add_parser(action)
        subp.add_argument('--provider', choices=('google', 'onedrive'), required=True)
        if action != 'login':
            subp.add_argument('--key-ref', required=True, help='OS credential vault reference; never a raw key')
        subp.add_argument('--auth-dir', default=str(Path.home() / '.config' / 'tabarc-print'))
        subp.add_argument('--google-credentials', help='Google desktop OAuth client JSON, for login')
        subp.add_argument('--microsoft-client-id', default=os.environ.get('TABARC_MICROSOFT_CLIENT_ID', ''))
        subp.add_argument('--microsoft-tenant', default='consumers')
        if action == 'send':
            subp.add_argument('--pdf', type=Path, required=True)
            subp.add_argument('--printer', required=True)
        if action == 'status':
            subp.add_argument('--job', required=True)
        if action == 'receive':
            subp.add_argument('--printer', action='append', required=True, help='remote-id=local-CUPS-queue')
            subp.add_argument('--state-dir', default=None)
            subp.add_argument('--interval', type=float, default=10)
            subp.add_argument('--once', action='store_true')
            subp.add_argument('--dry-run', action='store_true')
            subp.add_argument('--backend', choices=('auto', 'cups', 'windows-sumatra'), default='auto')
            subp.add_argument('--windows-renderer')
    args = parser.parse_args()
    auth = make_auth(args)
    if args.action == 'login':
        auth.login()
        print('Connected', args.provider)
        return
    from .secret_store import SecretStore
    from .local_queue import LocalQueue, default_state_dir
    key = SecretStore(args.auth_dir).read(args.key_ref)
    if not re.fullmatch(r'[0-9a-f]{64}', key):
        parser.error('A random 256-bit key from the OS credential vault is required')
    secret = bytes.fromhex(key)
    from .plugins import REGISTRY
    store = REGISTRY.cloud_store(args.provider, auth)
    printers = None
    if args.action == 'receive':
        printers = {}
        for entry in args.printer:
            key, sep, val = entry.partition('=')
            if not sep or not val:
                parser.error('Printer mapping must be remote-id=local-CUPS-queue')
            validate_printer_id(key)
            printers[key] = val
    state = args.state_dir if args.action == 'receive' and args.state_dir else str(Path.home() / '.local' / 'state' / 'tabarc-print' / args.provider)
    gateway = CloudGateway(store, secret, state, printers,
                           args.dry_run if args.action == 'receive' else False,
                           encrypt=True,
                           allow_legacy_plaintext=False,
                           backend=args.backend if args.action == 'receive' else 'auto',
                           windows_renderer=args.windows_renderer if args.action == 'receive' else None,
                           queue=LocalQueue(default_state_dir()) if args.action == 'receive' else None)
    if args.action == 'send':
        print('Cloud job', gateway.send(args.pdf, args.printer))
    elif args.action == 'status':
        result = gateway.status(args.job)
        print(json.dumps(result or {'state': 'pending'}, indent=2))
    else:
        while True:
            try:
                print(json.dumps(gateway.once()))
            except (CloudError, OSError, ValueError) as exc:
                print('Cloud connector error:', str(exc)[:300])
                if args.once:
                    raise
            if args.once:
                break
            time.sleep(max(3, args.interval))


if __name__ == '__main__':
    main()
