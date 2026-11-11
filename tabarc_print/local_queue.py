"""User-owned local print queue. No network service or cloud account required."""
from contextlib import closing, contextmanager
from pathlib import Path
import os
import sqlite3
import time
import uuid
import stat
import hashlib
import hmac
import threading
import base64
import secrets
from .secret_store import SecretStore
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .cloud_auth import private_auth_dir
from .common import MAX_FILE_BYTES, atomic_write, safe_job_id, validate_pdf
from .plugins import REGISTRY, parse_cups_job_reference


def default_state_dir() -> Path:
    root = os.environ.get('LOCALAPPDATA') if os.name == 'nt' else os.environ.get('XDG_STATE_HOME')
    return Path(root).expanduser() / 'TABARC-Print' if root else Path.home() / '.local' / 'state' / 'tabarc-print'


_ENVELOPE = b'TPQENC01'
_META_PREFIX = 'meta1:'
_VAULT_CREATION_MUTEX = threading.Lock()


class LocalQueue:
    def __init__(self, state_dir=None, backend='auto', windows_renderer=None, secret_store=None):
        self.root = private_auth_dir(state_dir or default_state_dir())
        self.docs = private_auth_dir(self.root / 'documents')
        self.db_path = self.root / 'local-jobs.sqlite3'
        self.secrets = secret_store or SecretStore(self.root)
        # Do not silently open old plaintext queued documents under the new release.
        if any(self.docs.glob('*.pdf')):
            raise PermissionError('Legacy readable PDFs found in queue; re-submit them after secure removal')
        self.backend = REGISTRY.printer(backend)
        self.windows_renderer = windows_renderer
        if self.db_path.is_symlink():
            raise ValueError('Local database cannot be a symbolic link')
        with closing(self._db()) as db:
            db.execute('CREATE TABLE IF NOT EXISTS jobs ('
                'id TEXT PRIMARY KEY, printer TEXT NOT NULL, filename TEXT NOT NULL, '
                'state TEXT NOT NULL, message TEXT NOT NULL, created_at INTEGER NOT NULL, '
                'updated_at INTEGER NOT NULL)')
            columns = {record['name'] for record in db.execute('PRAGMA table_info(jobs)')}
            if 'spool_ref' not in columns:
                db.execute('ALTER TABLE jobs ADD COLUMN spool_ref TEXT')
            if 'document_sha256' not in columns:
                db.execute('ALTER TABLE jobs ADD COLUMN document_sha256 TEXT')
            if 'submitted_at' not in columns:
                db.execute('ALTER TABLE jobs ADD COLUMN submitted_at INTEGER')
            if 'source_ref' not in columns:
                db.execute('ALTER TABLE jobs ADD COLUMN source_ref TEXT')
            if 'source_digest' not in columns:
                db.execute('ALTER TABLE jobs ADD COLUMN source_digest TEXT')
            db.execute('CREATE UNIQUE INDEX IF NOT EXISTS unique_external_job ON jobs(source_ref)')
            db.execute('CREATE TABLE IF NOT EXISTS queue_settings (name TEXT PRIMARY KEY, value TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS job_events ('
                'seq INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL, '
                'state TEXT NOT NULL, detail TEXT NOT NULL, at INTEGER NOT NULL)')
            db.execute('CREATE INDEX IF NOT EXISTS job_events_by_job ON job_events(job_id,seq)')
            db.commit()
        if os.name != 'nt':
            os.chmod(self.db_path, 0o600)
        self._migrate_metadata()

    def _db(self):
        db = sqlite3.connect(self.db_path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA busy_timeout=10000')
        db.execute('PRAGMA synchronous=FULL')
        db.execute('PRAGMA secure_delete=ON')
        return db

    @staticmethod
    def _read_regular_document(path: Path) -> bytes:
        # Open one descriptor and check that same file. No link-following on platforms that support it.
        flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0)
        if hasattr(os, 'O_NOFOLLOW'):
            flags |= os.O_NOFOLLOW
        if path.is_symlink():
            raise ValueError('Document must not be a symbolic link')
        try:
            fd = os.open(path, flags)
        except OSError as exc:
            raise ValueError('Could not open a regular PDF') from exc
        with os.fdopen(fd, 'rb') as fh:
            info = os.fstat(fh.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ValueError('Choose a regular PDF file')
            if info.st_size > MAX_FILE_BYTES:
                raise ValueError('PDF exceeds the 20 MB limit')
            document = fh.read(MAX_FILE_BYTES + 1)
        validate_pdf(document)
        return document

    @contextmanager
    def _vault_creation_lock(self):
        """Keep concurrent first runs from creating two different queue keys."""
        lockpath = self.root / '.vault-create.lock'
        flags = os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0)
        with _VAULT_CREATION_MUTEX:
            fd = os.open(lockpath, flags, 0o600)
            try:
                if os.name == 'nt':
                    import msvcrt
                    os.lseek(fd, 0, os.SEEK_SET)
                    if os.fstat(fd).st_size == 0:
                        os.write(fd, b'\0')
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
                else:
                    import fcntl
                    fcntl.flock(fd, fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    if os.name == 'nt':
                        os.lseek(fd, 0, os.SEEK_SET)
                        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
                    else:
                        fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def _data_key(self):
        name = 'local.documents.v1'
        with self._vault_creation_lock():
            key = self.secrets.get_named(name)
            if key is None:
                if any(self.docs.glob('*.bin')):
                    raise RuntimeError('Document vault key missing; existing encrypted jobs are locked')
                with closing(self._db()) as db:
                    has_sealed = db.execute("SELECT 1 FROM jobs WHERE filename LIKE 'name1:%' OR printer LIKE 'meta1:%' LIMIT 1").fetchone()
                if has_sealed:
                    raise RuntimeError('Document vault key missing; existing encrypted jobs are locked')
                key = secrets.token_hex(32)
                self.secrets.put_named(name, key)
        if not isinstance(key, str) or len(key) != 64:
            raise RuntimeError('Invalid local document encryption key')
        try:
            return bytes.fromhex(key)
        except ValueError as exc:
            raise RuntimeError('Invalid local document encryption key') from exc

    @staticmethod
    def _seal(key, job_id, plaintext):
        nonce = os.urandom(12)
        return _ENVELOPE + nonce + AESGCM(key).encrypt(nonce, plaintext,
                        b'TABARC Print local queue v1' + bytes.fromhex(job_id))

    @staticmethod
    def _open(key, job_id, ciphertext):
        if len(ciphertext) < len(_ENVELOPE) + 12 + 16 or not ciphertext.startswith(_ENVELOPE):
            raise ValueError('Encrypted queued document is missing or damaged')
        nonce = ciphertext[len(_ENVELOPE):len(_ENVELOPE) + 12]
        try:
            document = AESGCM(key).decrypt(nonce, ciphertext[len(_ENVELOPE) + 12:],
                        b'TABARC Print local queue v1' + bytes.fromhex(job_id))
        except Exception as exc:
            raise ValueError('Queued document decryption failed') from exc
        validate_pdf(document)
        return document

    def _seal_name(self, key: bytes, jid: str, name: str) -> str:
        nonce = os.urandom(12)
        encoded = AESGCM(key).encrypt(nonce, name.encode('utf-8'),
                                  b'TABARC Print local filename v1' + bytes.fromhex(jid))
        return 'name1:' + base64.urlsafe_b64encode(nonce + encoded).decode('ascii')

    def _open_name(self, jid: str, value: str) -> str:
        if not value.startswith('name1:'):
            raise PermissionError('Readable legacy filename is not permitted')
        try:
            raw = base64.b64decode(value[6:], altchars=b'-_', validate=True)
            result = AESGCM(self._data_key()).decrypt(raw[:12], raw[12:],
                    b'TABARC Print local filename v1' + bytes.fromhex(jid))
            return result.decode('utf-8')
        except Exception as exc:
            raise ValueError('Local job filename cannot be decrypted') from exc

    @staticmethod
    def _read_sealed(path):
        flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
        if path.is_symlink():
            raise ValueError('Stored document cannot be a symbolic link')
        with os.fdopen(os.open(path, flags), 'rb') as f:
            info = os.fstat(f.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES + 128:
                raise ValueError('Invalid encrypted queued document')
            blob = f.read(MAX_FILE_BYTES + 129)
        if len(blob) > MAX_FILE_BYTES + 128:
            raise ValueError('Oversized encrypted queued document')
        return blob

    @staticmethod
    def _protect_meta(key: bytes, jid: str, field: str, value: str | None):
        if value is None:
            return None
        nonce = os.urandom(12)
        aad = b'TABARC Print queue metadata v1/' + bytes.fromhex(jid) + b'/' + field.encode()
        payload = AESGCM(key).encrypt(nonce, str(value).encode('utf-8'), aad)
        return _META_PREFIX + base64.urlsafe_b64encode(nonce + payload).decode('ascii')

    def _seal_meta(self, jid: str, field: str, value: str | None):
        return self._protect_meta(self._data_key(), jid, field, value)

    def _open_meta(self, jid: str, field: str, value: str | None):
        if value is None:
            return None
        if not isinstance(value, str) or not value.startswith(_META_PREFIX):
            raise PermissionError('Legacy readable queue metadata is not permitted')
        try:
            raw = base64.b64decode(value[len(_META_PREFIX):], altchars=b'-_', validate=True)
            if len(raw) < 28:
                raise ValueError('Too short')
            aad = b'TABARC Print queue metadata v1/' + bytes.fromhex(jid) + b'/' + field.encode()
            result = AESGCM(self._data_key()).decrypt(raw[:12], raw[12:], aad)
            return result.decode('utf-8')
        except Exception as exc:
            raise ValueError('Encrypted queue metadata cannot be authenticated') from exc

    def _migrate_metadata(self):
        """Encrypt old queue metadata in place; never submit a job during migration."""
        with closing(self._db()) as db:
            db.execute('BEGIN IMMEDIATE')
            entries = db.execute('SELECT id,printer,filename,message,spool_ref FROM jobs').fetchall()
            events = db.execute('SELECT seq,job_id,detail FROM job_events').fetchall()
            legacy = (any(not str(row['printer']).startswith(_META_PREFIX) or
                          not str(row['filename']).startswith('name1:') or
                          not str(row['message']).startswith(_META_PREFIX) or
                          (row['spool_ref'] is not None and not str(row['spool_ref']).startswith(_META_PREFIX))
                          for row in entries) or
                      any(not str(row['detail']).startswith(_META_PREFIX) for row in events))
            already_sealed = db.execute("SELECT value FROM queue_settings WHERE name='metadata_encryption'").fetchone()
            if legacy and already_sealed:
                raise PermissionError('Readable metadata inserted into a sealed queue; database refused')
            if not legacy:
                db.execute("INSERT OR REPLACE INTO queue_settings(name,value) VALUES ('metadata_encryption','v1')")
                db.commit()
                return
            key = self._data_key()
            for row in entries:
                jid = safe_job_id(row['id'])
                update = {}
                for field in ('printer', 'message', 'spool_ref'):
                    value = row[field]
                    if value is not None and not str(value).startswith(_META_PREFIX):
                        update[field] = self._protect_meta(key, jid, field, value)
                if not str(row['filename']).startswith('name1:'):
                    update['filename'] = self._seal_name(key, jid, row['filename'])
                if update:
                    assignments = ', '.join(k + '=?' for k in update)
                    db.execute('UPDATE jobs SET ' + assignments + ' WHERE id=?', (*update.values(), jid))
            for row in events:
                if not str(row['detail']).startswith(_META_PREFIX):
                    db.execute('UPDATE job_events SET detail=? WHERE seq=?',
                               (self._protect_meta(key, safe_job_id(row['job_id']), 'detail', row['detail']), row['seq']))
            db.execute("INSERT OR REPLACE INTO queue_settings(name,value) VALUES ('metadata_encryption','v1')")
            db.commit()
            # VACUUM can remove old metadata from live SQLite pages. Filesystem
            # snapshots, SSD remanence and backups still require separate handling.
            db.execute('VACUUM')

    def _event(self, db, job_id: str, state: str, detail: str = ''):
        db.execute('INSERT INTO job_events(job_id,state,detail,at) VALUES (?,?,?,?)',
                   (job_id, state, self._seal_meta(job_id, 'detail', detail[:300]), int(time.time())))

    def submit(self, source: Path, printer: str, held: bool = False) -> str:
        source = Path(source)
        return self.submit_bytes(self._read_regular_document(source), printer,
                                 filename=source.name, held=held)

    def submit_bytes(self, document: bytes, printer: str, *, filename='remote.pdf',
                     held=True, source_id=None) -> str:
        """Encrypt bytes straight into the queue; remote jobs are always held."""
        if not isinstance(printer, str) or not printer or len(printer) > 255 or printer.startswith('-') or any(c in printer for c in '\r\n\x00'):
            raise ValueError('Invalid local printer name')
        if not isinstance(filename, str) or not filename or any(c in filename for c in '/\\\r\n\x00'):
            raise ValueError('Invalid local document name')
        validate_pdf(document)
        if source_id is not None and (not isinstance(source_id, str) or not 1 <= len(source_id) <= 250):
            raise ValueError('Invalid external job reference')
        job_id = uuid.uuid4().hex
        document_path = self.docs / (job_id + '.bin')
        data_key = self._data_key()
        sealed = self._seal(data_key, job_id, document)
        protected_name = self._seal_name(data_key, job_id, filename[:240])
        source_ref = (hmac.new(data_key, b'job-ref:' + source_id.encode(), hashlib.sha256).hexdigest()
                      if source_id is not None else None)
        source_digest = (hmac.new(data_key, b'job-payload:' + printer.encode() + b'\0' + document,
                                   hashlib.sha256).hexdigest() if source_id is not None else None)
        if source_ref:
            with closing(self._db()) as db:
                prior = db.execute('SELECT id,source_digest FROM jobs WHERE source_ref=?', (source_ref,)).fetchone()
            if prior:
                if not hmac.compare_digest(prior['source_digest'], source_digest):
                    raise ValueError('External job ID reused with different print data')
                return prior['id']
        atomic_write(document_path, sealed)
        state = 'held' if held else 'queued'
        digest = hashlib.sha256(sealed).hexdigest()
        try:
            with closing(self._db()) as db:
                timestamp = int(time.time())
                try:
                    db.execute('INSERT INTO jobs (id, printer, filename, state, message, created_at, updated_at, document_sha256, source_ref, source_digest) '
                               'VALUES (?,?,?,?,?,?,?,?,?,?)',
                               (job_id, self._seal_meta(job_id, 'printer', printer), protected_name, state,
                                self._seal_meta(job_id, 'message', ''), timestamp, timestamp, digest, source_ref, source_digest))
                except sqlite3.IntegrityError:
                    if not source_ref:
                        raise
                    prior = db.execute('SELECT id,source_digest FROM jobs WHERE source_ref=?', (source_ref,)).fetchone()
                    if not prior or not hmac.compare_digest(prior['source_digest'], source_digest):
                        raise ValueError('External job ID reused with different print data')
                    return prior['id']
                self._event(db, job_id, state)
                db.commit()
        finally:
            # Successful insert keeps its ciphertext. A duplicate never keeps a stray file.
            with closing(self._db()) as db:
                exists = db.execute('SELECT 1 FROM jobs WHERE id=?', (job_id,)).fetchone()
            if not exists:
                document_path.unlink(missing_ok=True)
        return job_id

    def hold(self, job_id):
        safe_job_id(job_id)
        with closing(self._db()) as db:
            db.execute('BEGIN IMMEDIATE')
            changed = db.execute("UPDATE jobs SET state='held',updated_at=? WHERE id=? AND state='queued'",
                (int(time.time()), job_id)).rowcount
            if changed:
                self._event(db, job_id, 'held')
            db.commit()
        return bool(changed)

    def release(self, job_id):
        safe_job_id(job_id)
        with closing(self._db()) as db:
            db.execute('BEGIN IMMEDIATE')
            changed = db.execute("UPDATE jobs SET state='queued',updated_at=? WHERE id=? AND state='held'",
                (int(time.time()), job_id)).rowcount
            if changed:
                self._event(db, job_id, 'queued', 'Released by local user')
            db.commit()
        return bool(changed)

    def history(self, job_id, limit=50):
        safe_job_id(job_id)
        if not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValueError('Invalid event limit')
        with closing(self._db()) as db:
            rows = [dict(row) for row in db.execute(
                'SELECT seq, state, detail, at FROM job_events WHERE job_id=? ORDER BY seq DESC LIMIT ?',
                (job_id, limit))]
        for item in rows:
            item['detail'] = self._open_meta(job_id, 'detail', item['detail'])
        return rows

    def jobs(self, limit=100):
        if not isinstance(limit, int) or not 1 <= limit <= 500:
            raise ValueError('Invalid job limit')
        with closing(self._db()) as db:
            result = [dict(row) for row in db.execute('SELECT * FROM jobs ORDER BY created_at DESC,id DESC LIMIT ?', (limit,))]
        for item in result:
            self._decode_job(item)
        return result

    def status(self, job_id):
        safe_job_id(job_id)
        with closing(self._db()) as db:
            row = db.execute('SELECT * FROM jobs WHERE id=?', (job_id,)).fetchone()
            result = dict(row) if row else None
        if result:
            self._decode_job(result)
        return result

    def _decode_job(self, item):
        jid = item['id']
        item['filename'] = self._open_name(jid, item['filename'])
        for field in ('printer', 'message', 'spool_ref'):
            item[field] = self._open_meta(jid, field, item[field])

    def cancel(self, job_id):
        safe_job_id(job_id)
        with closing(self._db()) as db:
            db.execute('BEGIN IMMEDIATE')
            changed = db.execute("UPDATE jobs SET state='cancelled',updated_at=? "
                                 "WHERE id=? AND state IN ('queued','held')", (int(time.time()), job_id)).rowcount
            if changed:
                self._event(db, job_id, 'cancelled')
            db.commit()
        if changed:
            (self.docs / (job_id + '.bin')).unlink(missing_ok=True)
        return bool(changed)

    def mark_interrupted(self, job_id):
        """Manual recovery when the prior agent is definitely stopped."""
        safe_job_id(job_id)
        with closing(self._db()) as db:
            db.execute('BEGIN IMMEDIATE')
            changed = db.execute("UPDATE jobs SET state='uncertain',message=?,updated_at=? "
                "WHERE id=? AND state='claimed'", (self._seal_meta(job_id, 'message',
                      'Submission may have reached the spooler; inspect before retrying'),
                                                     int(time.time()), job_id)).rowcount
            if changed:
                self._event(db, job_id, 'uncertain', 'Manual interruption recovery')
            db.commit()
        return bool(changed)

    def process_one(self, job_id=None, dry_run=False):
        if job_id is not None:
            safe_job_id(job_id)
        with closing(self._db()) as db:
            db.execute('BEGIN IMMEDIATE')
            if job_id:
                row = db.execute("SELECT * FROM jobs WHERE id=? AND state='queued'", (job_id,)).fetchone()
            else:
                row = db.execute("SELECT * FROM jobs WHERE state='queued' ORDER BY created_at,id LIMIT 1").fetchone()
            if row is None:
                db.commit()
                return None
            jid = row['id']
            db.execute("UPDATE jobs SET state='claimed',updated_at=? WHERE id=?", (int(time.time()), jid))
            self._event(db, jid, 'claimed', 'Hand-off to local spooler started')
            db.commit()
        state, message = 'uncertain', ''
        spool_ref = None
        try:
            document_path = self.docs / (jid + '.bin')
            sealed = self._read_sealed(document_path)
            if row['document_sha256'] and hashlib.sha256(sealed).hexdigest() != row['document_sha256']:
                raise ValueError('Queued document has changed since submission')
            document = self._open(self._data_key(), jid, sealed)
            message = self.backend.submit_bytes(document, self._open_meta(jid, 'printer', row['printer']), dry_run=dry_run)
            state = 'simulated' if dry_run else 'submitted'
            if state == 'submitted' and self.backend.name == 'cups':
                spool_ref = parse_cups_job_reference(message)
        except Exception as exc:
            message = 'Local submission outcome needs inspection: ' + str(exc)[:230]
        finally:
            with closing(self._db()) as db:
                db.execute("UPDATE jobs SET state=?,message=?,updated_at=?,spool_ref=?,submitted_at=? WHERE id=? AND state='claimed'",
                           (state, self._seal_meta(jid, 'message', str(message)[:300]), int(time.time()),
                            self._seal_meta(jid, 'spool_ref', spool_ref),
                            int(time.time()) if state == 'submitted' else None, jid))
                self._event(db, jid, state, str(message))
                db.commit()
            # Deleting after the durable outcome means a crash leaves private debris, not a lost result.
            if state == 'submitted':
                (self.docs / (jid + '.bin')).unlink(missing_ok=True)
        return jid, state, message
