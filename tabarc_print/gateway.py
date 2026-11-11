"""Signed print-job handoff through a shared or cloud-synchronised folder."""
import argparse
from contextlib import closing
import hmac
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import time
import uuid
from .crypto import MAX_OVERHEAD, encrypt_pdf, decrypt_pdf
from .metadata import MANIFEST_SUFFIX, RECEIPT_SUFFIX, open_manifest, open_receipt, seal, seal_receipt
from .receiver_identity import check_receiver_id
from .plugins import REGISTRY
from .local_queue import LocalQueue
from .common import (MAX_FILE_BYTES, atomic_write, now, safe_job_id,
                     sha256, sign_manifest, spool_pdf, validate_pdf, validate_printer_id)

EXPIRY_SECONDS = 24 * 3600


def private_file_bytes(path: Path, max_size: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as fh:
        info = os.fstat(fh.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('Only regular files are allowed')
        if info.st_size > max_size:
            raise ValueError("File too large")
        result = fh.read(max_size + 1)
    if len(result) > max_size:
        raise ValueError("File too large")
    return result


def build_job(folder: Path, pdf: Path, printer_id: str, secret: bytes, at: int | None = None, encrypt: bool = True, target_receiver: str | None = None) -> str:
    validate_printer_id(printer_id)
    if not encrypt:
        raise ValueError('Plaintext print-job transport is disabled')
    if target_receiver:
        check_receiver_id(target_receiver)
        if not encrypt:
            raise ValueError("Receiver-targeted jobs must be encrypted")
    if len(secret) < 32:
        raise ValueError("Use a random secret of at least 32 bytes")
    document = private_file_bytes(Path(pdf), MAX_FILE_BYTES)
    validate_pdf(document)
    job_id = uuid.uuid4().hex
    created = now() if at is None else at
    document, encryption = encrypt_pdf(secret, job_id, printer_id, created, document)
    manifest = {"version": 4, "job_id": job_id, "printer_id": printer_id,
                "sha256": sha256(document), "created_at": created, "encryption": encryption}
    if target_receiver:
        manifest["target_receiver"] = target_receiver
    inbox = Path(folder) / "inbox"
    atomic_write(inbox / (job_id + '.bin'), document)
    # The last object is the authenticated commit marker for this job.
    atomic_write(inbox / (job_id + MANIFEST_SUFFIX), seal(secret, job_id, 'manifest', manifest))
    return job_id


class FolderGateway:
    def __init__(self, folder: Path, printer_map: dict[str, str], secret: bytes, dry_run=False, state_dir: Path | None = None, require_encryption=True, backend="auto", windows_renderer=None, receiver_id=None, allow_direct_submission=False, queue=None):
        if len(secret) < 32:
            raise ValueError("Use a random secret of at least 32 bytes")
        if not require_encryption:
            raise ValueError("Legacy plaintext reception is disabled")
        if not printer_map:
            raise ValueError("Configure at least one printer")
        for k in printer_map:
            validate_printer_id(k)
        self.folder, self.printer_map, self.secret, self.dry_run = Path(folder), printer_map, secret, dry_run
        self.require_encryption = require_encryption
        self.backend = backend
        self.windows_renderer = windows_renderer
        self.receiver_id = check_receiver_id(receiver_id) if receiver_id else None
        self.allow_direct_submission = allow_direct_submission
        self.inbox, self.receipts = self.folder / "inbox", self.folder / "receipts"
        self.inbox.mkdir(parents=True, exist_ok=True)
        self.receipts.mkdir(parents=True, exist_ok=True)
        # Keep the SQLite ledger outside cloud synchronisation: only jobs and receipts travel.
        if state_dir is None:
            state_dir = Path.home() / ".local" / "state" / "tabarc-print" / sha256(str(self.folder.resolve()).encode())[:20]
        state_dir = Path(state_dir)
        if state_dir.is_symlink():
            raise ValueError('Gateway state directory cannot be a symbolic link')
        state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name != 'nt':
            if state_dir.stat().st_uid != os.getuid() or state_dir.stat().st_mode & 0o077:
                raise PermissionError('Gateway state directory must be private (0700)')
        self.dbfile = state_dir / "gateway-ledger.sqlite3"
        if self.dbfile.is_symlink():
            raise ValueError('Gateway ledger cannot be a symbolic link')
        self.queue = None if allow_direct_submission else (queue or LocalQueue(state_dir / "queue"))
        with closing(self.db()) as c:
            c.execute("CREATE TABLE IF NOT EXISTS processed (id TEXT PRIMARY KEY, state TEXT NOT NULL, at INTEGER NOT NULL)")
            c.commit()

    def db(self):
        if self.dbfile.is_symlink():
            raise ValueError('Gateway ledger cannot be a symbolic link')
        connection = sqlite3.connect(self.dbfile, timeout=10)
        if os.name != 'nt':
            if self.dbfile.stat().st_uid != os.getuid():
                connection.close()
                raise PermissionError('Gateway ledger has an unexpected owner')
            os.chmod(self.dbfile, 0o600)
        return connection

    def process_one(self, job_id: str):
        safe_job_id(job_id)
        manifest_path = self.inbox / (job_id + MANIFEST_SUFFIX)
        with closing(self.db()) as c:
            if c.execute("SELECT 1 FROM processed WHERE id=?", (job_id,)).fetchone():
                return "duplicate"
        try:
            data = open_manifest(self.secret, job_id, private_file_bytes(manifest_path, 8192))
            pid = data['printer_id']
            if pid not in self.printer_map:
                raise ValueError("Printer not allowed")
            created = data['created_at']
            if created > now() + 60 or now() - created > EXPIRY_SECONDS:
                raise ValueError("Expired job")
            digest = data['sha256']
            if 'target_receiver' in data and self.receiver_id != data['target_receiver']:
                return 'not-for-this-device'
            extension = '.bin'
            document_path = self.inbox / (job_id + extension)
            payload = private_file_bytes(document_path, MAX_FILE_BYTES + MAX_OVERHEAD)
            if not hmac.compare_digest(sha256(payload), digest):
                raise ValueError("Document integrity check failed")
            document = decrypt_pdf(self.secret, job_id, pid, created, payload, data['encryption'])
            validate_pdf(document)
            if not self.allow_direct_submission:
                # Never print a remotely supplied PDF during collection.
                self.queue.submit_bytes(document, self.printer_map[pid],
                    filename='incoming-' + job_id[:12] + '.pdf', held=True,
                    source_id='folder:' + sha256(str(self.folder.resolve()).encode()) + ':' + job_id)
                state, message = 'held', 'Remote document held for local approval'
                with closing(self.db()) as c:
                    c.execute("INSERT OR IGNORE INTO processed (id,state,at) VALUES (?,?,?)", (job_id, state, now()))
                    c.commit()
            else:
                # Explicit compatibility mode; never enabled by the public commands.
                with closing(self.db()) as c:
                    c.execute("INSERT INTO processed (id,state,at) VALUES (?,?,?)", (job_id, "claimed", now()))
                    c.commit()
                try:
                    message = REGISTRY.printer(self.backend).submit_bytes(
                        document, self.printer_map[pid], dry_run=self.dry_run)
                    state = "submitted"
                except Exception as exc:
                    state, message = "failed", str(exc)[:300]
            with closing(self.db()) as c:
                c.execute("UPDATE processed SET state=?,at=? WHERE id=?", (state, now(), job_id))
                c.commit()
            atomic_write(self.receipts / (job_id + RECEIPT_SUFFIX),
                         seal_receipt(self.secret, job_id, state, message, now()))
            manifest_path.unlink(missing_ok=True)
            document_path.unlink(missing_ok=True)
            return state
        except FileNotFoundError:
            # Sync client may not have downloaded the PDF yet.
            return "pending"
        except (ValueError, OSError, TypeError, json.JSONDecodeError) as exc:
            # Invalid or malicious files are not submitted; keep them for operator review.
            return "rejected: " + str(exc)[:150]

    def once(self):
        results = {}
        for legacy in sorted(self.inbox.glob('*.job.json')):
            job_id = legacy.name.removesuffix('.job.json')
            try:
                safe_job_id(job_id)
            except ValueError:
                continue
            results[job_id] = 'rejected: legacy readable manifest; re-send using encrypted metadata'
        for manifest in sorted(self.inbox.glob("*" + MANIFEST_SUFFIX)):
            job_id = manifest.name.removesuffix(MANIFEST_SUFFIX)
            try:
                safe_job_id(job_id)
            except ValueError:
                continue
            if job_id in results:
                results[job_id] = 'rejected: ambiguous legacy and encrypted metadata'
                continue
            try:
                results[job_id] = self.process_one(job_id)
            except ValueError:
                continue
        return results


def main():
    parser = argparse.ArgumentParser(description="Signed Google Drive / OneDrive folder print gateway")
    sub = parser.add_subparsers(dest="command", required=True)
    send = sub.add_parser("send")
    send.add_argument("--folder", required=True)
    send.add_argument("--key-ref", required=True, help="OS credential vault reference")
    send.add_argument("--pdf", required=True)
    send.add_argument("--printer", required=True)
    status = sub.add_parser("status")
    status.add_argument("--folder", required=True)
    status.add_argument("--key-ref", required=True, help="OS credential vault reference")
    status.add_argument("--job", required=True)
    receive = sub.add_parser("receive")
    receive.add_argument("--folder", required=True)
    receive.add_argument("--key-ref", required=True, help="OS credential vault reference")
    receive.add_argument("--printer", action="append", required=True, help="remote-id=local-CUPS-queue")
    receive.add_argument("--interval", type=float, default=5)
    receive.add_argument("--dry-run", action="store_true")
    receive.add_argument("--state-dir", default=None, help="local state folder, outside the sync folder")
    receive.add_argument('--backend', choices=('auto', 'cups', 'windows-sumatra'), default='auto')
    receive.add_argument('--windows-renderer', help='Absolute path to a trusted SumatraPDF.exe')
    args = parser.parse_args()
    from .secret_store import SecretStore
    import re
    vault_key = SecretStore(Path.home() / '.config' / 'tabarc-print').read(args.key_ref)
    if not re.fullmatch(r'[0-9a-f]{64}', vault_key):
        parser.error('Provide a 256-bit key stored in the OS vault')
    secret = bytes.fromhex(vault_key)
    if args.command == "send":
        print("Created cloud job", build_job(Path(args.folder), Path(args.pdf), args.printer, secret,
                                            encrypt=True))
    elif args.command == "status":
        safe_job_id(args.job)
        receipt = open_receipt(secret, args.job, private_file_bytes(
            Path(args.folder) / "receipts" / (args.job + RECEIPT_SUFFIX), 8192))
        print(json.dumps(receipt, indent=2))
    else:
        from .local_queue import default_state_dir
        printers = {}
        for item in args.printer:
            pid, sep, queue = item.partition("=")
            if not sep or not queue:
                parser.error("--printer must be remote-id=local-queue")
            printers[pid] = queue
        gateway = FolderGateway(Path(args.folder), printers, secret, args.dry_run,
                                Path(args.state_dir) if args.state_dir else None,
                                require_encryption=True,
                                backend=args.backend, windows_renderer=args.windows_renderer,
                                queue=LocalQueue(default_state_dir(), backend=args.backend, windows_renderer=args.windows_renderer))
        while True:
            for job_id, result in gateway.once().items():
                if result != "pending":
                    print(job_id, result)
            time.sleep(max(2.0, args.interval))

if __name__ == "__main__":
    main()
