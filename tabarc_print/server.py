"""Basic print coordinator. Put behind TLS before any remote deployment."""
import argparse
from contextlib import closing
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sqlite3
from threading import Lock
import uuid
from urllib.parse import urlsplit, unquote
from .common import MAX_FILE_BYTES, atomic_write, now, safe_job_id, sha256, validate_pdf, validate_printer_id
from .access import AccessPolicy, Principal

SCHEMA = """
CREATE TABLE IF NOT EXISTS printers (
 id TEXT PRIMARY KEY, label TEXT NOT NULL, agent_id TEXT NOT NULL,
 created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS jobs (
 id TEXT PRIMARY KEY, printer_id TEXT NOT NULL REFERENCES printers(id),
 state TEXT NOT NULL, filename TEXT NOT NULL, sha256 TEXT NOT NULL,
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
 leased_until INTEGER, leased_to TEXT, error TEXT,
 owner_id TEXT NOT NULL DEFAULT '@legacy'
);
CREATE INDEX IF NOT EXISTS jobs_pick ON jobs(state, printer_id, created_at);
"""

class Coordinator:
    def __init__(self, root: Path, client_token: str = '', agent_token: str = '', access_file=None):
        self.policy = AccessPolicy.from_file(access_file) if access_file is not None else None
        if self.policy is None and (len(client_token) < 24 or len(agent_token) < 24 or client_token == agent_token):
            raise ValueError("Set different, random client and agent tokens (24+ characters each)")
        self.root = Path(root)
        self.docs = self.root / "documents"
        self.dbfile = self.root / "print.sqlite3"
        for location in (self.root, self.docs, self.dbfile):
            if location.is_symlink():
                raise ValueError('Print data paths must not be symlinks')
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.docs.mkdir(exist_ok=True, mode=0o700)
        self.dbfile.touch(mode=0o600, exist_ok=True)
        if os.name != 'nt':
            # Older installations used default permissions; tighten these on upgrade.
            os.chmod(self.root, 0o700)
            os.chmod(self.docs, 0o700)
            os.chmod(self.dbfile, 0o600)
        self.client_token = client_token
        self.agent_token = agent_token
        self.lock = Lock()
        with closing(self.db()) as conn:
            conn.executescript(SCHEMA)
            columns = {row['name'] for row in conn.execute('PRAGMA table_info(jobs)')}
            if 'owner_id' not in columns:
                conn.execute("ALTER TABLE jobs ADD COLUMN owner_id TEXT NOT NULL DEFAULT '@legacy'")
            conn.commit()

    def db(self):
        c = sqlite3.connect(self.dbfile, timeout=10)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA busy_timeout=10000")
        c.execute("PRAGMA foreign_keys=ON")
        return c

    def authenticate(self, given: str, role: str, agent_id: str = ''):
        if self.policy is not None:
            principal = self.policy.authenticate(given, role)
            if role == 'agent' and principal is not None and principal.identifier != agent_id:
                return None
            return principal
        expected = self.client_token if role == "client" else self.agent_token
        if not hmac.compare_digest(given, expected):
            return None
        return Principal('@legacy' if role == 'client' else agent_id, role, frozenset({'*'}))

    @staticmethod
    def authorised(principal: Principal, printer_id: str):
        if principal is None or not principal.permits(printer_id):
            raise PermissionError('Printer access denied')

    def register(self, agent_id, printer_id, label, principal=None):
        validate_printer_id(agent_id)
        validate_printer_id(printer_id)
        if principal is not None:
            self.authorised(principal, printer_id)
            if principal.role != 'agent' or principal.identifier != agent_id:
                raise PermissionError('Connector identity does not match credential')
        if not isinstance(label, str) or len(label) > 100 or not label.strip():
            raise ValueError("Invalid label")
        with self.lock, closing(self.db()) as c:
            c.execute("BEGIN IMMEDIATE")
            old = c.execute("SELECT agent_id FROM printers WHERE id=?", (printer_id,)).fetchone()
            if old and old["agent_id"] != agent_id:
                c.rollback()
                raise ValueError("Printer belongs to another connector")
            c.execute("INSERT INTO printers VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET label=excluded.label",
                      (printer_id, label, agent_id, now()))
            c.commit()

    def printers(self, principal=None):
        with closing(self.db()) as c:
            items = [dict(x) for x in c.execute("SELECT id,label FROM printers ORDER BY label")]
        return [x for x in items if principal is None or principal.permits(x['id'])]

    def submit(self, printer_id, filename, body, principal=None):
        validate_printer_id(printer_id)
        if principal is not None:
            self.authorised(principal, printer_id)
        validate_pdf(body)
        if not isinstance(filename, str) or not filename.lower().endswith(".pdf"):
            raise ValueError("Use a PDF filename")
        filename = unquote(filename)
        filename = filename.rsplit("/", 1)[-1].rsplit("\\", 1)[-1][:120]
        if not filename or any(ord(c) < 32 for c in filename):
            raise ValueError("Invalid PDF filename")
        job_id = uuid.uuid4().hex
        with self.lock, closing(self.db()) as c:
            if c.execute("SELECT 1 FROM printers WHERE id=?", (printer_id,)).fetchone() is None:
                raise ValueError("Unknown printer")
            atomic_write(self.docs / (job_id + ".pdf"), body)
            try:
                t = now()
                c.execute("INSERT INTO jobs (id,printer_id,state,filename,sha256,created_at,updated_at,leased_until,leased_to,error,owner_id) "
                          "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                          (job_id, printer_id, "queued", filename, sha256(body), t, t, None, None, None,
                           principal.identifier if principal else '@legacy'))
                c.commit()
            except Exception:
                (self.docs / (job_id + ".pdf")).unlink(missing_ok=True)
                raise
        return job_id

    def claim(self, agent_id, principal=None):
        validate_printer_id(agent_id)
        if principal is not None and (principal.role != 'agent' or principal.identifier != agent_id):
            raise PermissionError('Connector identity does not match credential')
        with self.lock, closing(self.db()) as c:
            c.execute("BEGIN IMMEDIATE")
            t = now()
            # A lease expiring does not establish that printing was never submitted.
            c.execute("UPDATE jobs SET state='uncertain',leased_to=NULL,leased_until=NULL,updated_at=?, "
                      "error='Connector lease expired; inspect spooler before resubmitting' "
                      "WHERE state='leased' AND leased_until<=?", (t, t))
            allowed = sorted(principal.printers) if principal is not None and '*' not in principal.printers else None
            if allowed is not None:
                placeholders = ','.join('?' for _ in allowed)
                query = ("SELECT j.* FROM jobs j JOIN printers p ON p.id=j.printer_id "
                         "WHERE j.state='queued' AND p.agent_id=? AND j.printer_id IN (" + placeholders + ") "
                         "ORDER BY j.created_at,j.id LIMIT 1")
                j = c.execute(query, (agent_id, *allowed)).fetchone()
            else:
                j = c.execute("SELECT j.* FROM jobs j JOIN printers p ON p.id=j.printer_id "
                              "WHERE j.state='queued' AND p.agent_id=? ORDER BY j.created_at,j.id LIMIT 1",
                              (agent_id,)).fetchone()
            if not j:
                c.commit()
                return None
            c.execute("UPDATE jobs SET state='leased',leased_to=?,leased_until=?,updated_at=? WHERE id=?",
                      (agent_id, t + 300, t, j["id"]))
            c.commit()
            return {"id": j["id"], "printer_id": j["printer_id"], "filename": j["filename"]}

    def document(self, job_id, agent_id, principal=None):
        safe_job_id(job_id)
        with closing(self.db()) as c:
            j = c.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not j or j["state"] != "leased" or j["leased_to"] != agent_id or j["leased_until"] <= now():
            raise ValueError("Document is not leased to this connector")
        if principal is not None:
            self.authorised(principal, j['printer_id'])
            if principal.identifier != agent_id:
                raise PermissionError('Connector identity does not match credential')
        b = (self.docs / (job_id + ".pdf")).read_bytes()
        if sha256(b) != j["sha256"]:
            raise ValueError("Document integrity check failed")
        return b

    def complete(self, job_id, agent_id, success, message, uncertain=False, principal=None):
        safe_job_id(job_id)
        if not isinstance(success, bool) or not isinstance(uncertain, bool) or (uncertain and success):
            raise ValueError("Invalid completion outcome")
        if not isinstance(message, str):
            raise ValueError("Invalid message")
        with self.lock, closing(self.db()) as c:
            c.execute("BEGIN IMMEDIATE")
            row = c.execute("SELECT state,leased_to,printer_id FROM jobs WHERE id=?", (job_id,)).fetchone()
            if not row or row["state"] != "leased" or row["leased_to"] != agent_id:
                c.rollback()
                raise ValueError("Job isn't leased to this connector")
            if principal is not None:
                self.authorised(principal, row['printer_id'])
                if principal.identifier != agent_id:
                    raise PermissionError('Connector identity does not match credential')
            c.execute("UPDATE jobs SET state=?,leased_to=NULL,leased_until=NULL,updated_at=?,error=? WHERE id=?",
                      ('uncertain' if uncertain else ('submitted' if success else 'failed'),
                       now(), message[:300], job_id))
            c.commit()
        (self.docs / (job_id + ".pdf")).unlink(missing_ok=True)

    def jobs(self, principal=None):
        with closing(self.db()) as c:
            if principal is None:
                rows = c.execute("SELECT id,printer_id,state,filename,created_at,updated_at,error "
                                 "FROM jobs ORDER BY created_at DESC LIMIT 50")
            else:
                rows = c.execute("SELECT id,printer_id,state,filename,created_at,updated_at,error "
                                 "FROM jobs WHERE owner_id=? ORDER BY created_at DESC LIMIT 50",
                                 (principal.identifier,))
            return [dict(x) for x in rows]

    def cancel(self, job_id, principal):
        safe_job_id(job_id)
        if principal is None or principal.role != 'client':
            raise PermissionError('Client credentials required')
        with self.lock, closing(self.db()) as c:
            c.execute('BEGIN IMMEDIATE')
            row = c.execute('SELECT owner_id,state FROM jobs WHERE id=?', (job_id,)).fetchone()
            if not row or row['owner_id'] != principal.identifier:
                raise PermissionError('Job access denied')
            if row['state'] not in ('queued', 'uncertain'):
                raise ValueError('Only queued or uncertain jobs can be cancelled')
            c.execute("UPDATE jobs SET state='cancelled',updated_at=?,error='Cancelled by owner' WHERE id=?",
                      (now(), job_id))
            c.commit()
        (self.docs / (job_id + '.pdf')).unlink(missing_ok=True)

class Handler(BaseHTTPRequestHandler):
    server_version = "TABARC-Print/0.4"
    def json_reply(self, code, payload):
        data = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def error_reply(self, status, description):
        self.json_reply(status, {"error": description})

    def role(self, role):
        bearer = self.headers.get("Authorization", "")
        token = bearer[7:] if bearer.startswith("Bearer ") else ""
        agent_id = self.headers.get('X-Agent-ID', '') if role == 'agent' else ''
        principal = self.server.coordinator.authenticate(token, role, agent_id)
        if principal is None:
            self.error_reply(401, "Unauthorised")
        return principal

    def body(self, json_body=True):
        try:
            size = int(self.headers.get("Content-Length", "-1"))
        except ValueError:
            raise ValueError("Invalid content length")
        limit = 64 * 1024 if json_body else MAX_FILE_BYTES
        if not 0 <= size <= limit:
            raise ValueError("Invalid document length")
        data = self.rfile.read(size)
        if len(data) != size:
            raise ValueError("Incomplete request")
        if json_body:
            return json.loads(data)
        return data

    def route(self):
        return urlsplit(self.path).path

    def do_GET(self):
        path = self.route()
        c = self.server.coordinator
        try:
            if path == "/":
                data = (Path(__file__).with_name("index.html")).read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'")
                self.end_headers()
                self.wfile.write(data)
            elif path in ('/v1/printers', '/v1/jobs', '/v1/me'):
                principal = self.role('client')
                if principal is None: return
                if path == '/v1/printers':
                    result = {'printers': c.printers(principal)}
                elif path == '/v1/jobs':
                    result = {'jobs': c.jobs(principal)}
                else:
                    result = {'id': principal.identifier, 'printers': sorted(principal.printers)}
                self.json_reply(200, result)
            elif path == '/v1/agent/claim':
                principal = self.role('agent')
                if principal is None: return
                self.json_reply(200, {'job': c.claim(principal.identifier, principal)})
            elif path.startswith('/v1/agent/document/'):
                principal = self.role('agent')
                if principal is None: return
                job_id = path.rsplit('/', 1)[-1]
                content = c.document(job_id, principal.identifier, principal)
                self.send_response(200)
                self.send_header('Content-Type', 'application/pdf')
                self.send_header('Content-Length', str(len(content)))
                self.send_header('Cache-Control', 'no-store')
                self.send_header('X-Content-Type-Options', 'nosniff')
                self.end_headers()
                self.wfile.write(content)
            else:
                self.error_reply(404, 'Unknown endpoint')
        except PermissionError:
            self.error_reply(403, 'Forbidden')
        except ValueError as exc:
            self.error_reply(400, str(exc))
        except OSError:
            self.error_reply(500, 'Storage or I/O failure')

    def do_POST(self):
        path = self.route()
        c = self.server.coordinator
        try:
            if path == '/v1/agent/register':
                principal = self.role('agent')
                if principal is None: return
                payload = self.body()
                if c.policy is None:
                    c.register(payload['agent_id'], payload['printer_id'], payload['label'])
                else:
                    if payload['agent_id'] != principal.identifier:
                        raise PermissionError('Connector identity does not match credential')
                    c.register(principal.identifier, payload['printer_id'], payload['label'], principal)
                self.json_reply(200, {'ok': True})
            elif path == '/v1/jobs':
                principal = self.role('client')
                if principal is None: return
                body = self.body(json_body=False)
                job_id = c.submit(self.headers.get('X-Printer-ID', ''),
                                  self.headers.get('X-Filename', 'document.pdf'), body, principal)
                self.json_reply(201, {'id': job_id, 'state': 'queued'})
            elif path.startswith('/v1/agent/complete/'):
                principal = self.role('agent')
                if principal is None: return
                payload = self.body()
                if c.policy is None:
                    c.complete(path.rsplit('/', 1)[-1], payload['agent_id'], payload['success'],
                               payload.get('message', ''), payload.get('uncertain', False))
                else:
                    if payload['agent_id'] != principal.identifier:
                        raise PermissionError('Connector identity does not match credential')
                    c.complete(path.rsplit('/', 1)[-1], principal.identifier, payload['success'],
                               payload.get('message', ''), payload.get('uncertain', False), principal)
                self.json_reply(200, {'ok': True})
            else:
                self.error_reply(404, 'Unknown endpoint')
        except PermissionError:
            self.error_reply(403, 'Forbidden')
        except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
            self.error_reply(400, str(exc))
        except OSError:
            self.error_reply(500, 'Storage or I/O failure')

    def do_DELETE(self):
        path = self.route()
        if not path.startswith('/v1/jobs/'):
            self.error_reply(404, 'Unknown endpoint')
            return
        principal = self.role('client')
        if principal is None: return
        try:
            self.server.coordinator.cancel(path.rsplit('/', 1)[-1], principal)
            self.json_reply(200, {'ok': True})
        except PermissionError:
            self.error_reply(403, 'Forbidden')
        except ValueError as exc:
            self.error_reply(400, str(exc))
        except OSError:
            self.error_reply(500, 'Storage or I/O failure')

class Server(ThreadingHTTPServer):
    daemon_threads = True
    def __init__(self, address, coordinator):
        super().__init__(address, Handler)
        self.coordinator = coordinator


def main():
    raise SystemExit('Legacy HTTP coordinator is disabled in this security preview; use local printing or encrypted Tor/cloud transport')
    p = argparse.ArgumentParser(description="TABARC Print coordinator")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", default=8421, type=int)
    p.add_argument("--data", default="./print-data")
    p.add_argument('--access-file', default=os.getenv('TABARC_ACCESS_FILE'),
                   help='Private JSON file with distinct client and connector token digests')
    args = p.parse_args()
    if args.host not in ("127.0.0.1", "::1", "localhost") and os.getenv("TABARC_ALLOW_NONLOCAL") != "yes":
        p.error("Remote binding requires TABARC_ALLOW_NONLOCAL=yes and a TLS reverse proxy")
    if args.access_file is None and args.host not in ("127.0.0.1", "::1", "localhost"):
        p.error('Shared legacy tokens are limited to loopback; use --access-file for multi-device access')
    coordinator = Coordinator(Path(args.data), os.getenv("TABARC_CLIENT_TOKEN", ""),
                              os.getenv("TABARC_AGENT_TOKEN", ""), access_file=args.access_file)
    with Server((args.host, args.port), coordinator) as server:
        print(f"TABARC Print on http://{args.host}:{args.port}")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass

if __name__ == "__main__":
    main()
