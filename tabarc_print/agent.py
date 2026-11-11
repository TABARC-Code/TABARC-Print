"""Fetches assigned jobs and submits them to an approved local printer."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
from urllib.request import Request, urlopen
from urllib.parse import urlsplit
from urllib.error import HTTPError, URLError
from .common import spool_pdf, validate_pdf, validate_printer_id, atomic_write
from .ledger import AgentLedger

class Agent:
    def __init__(self, server: str, token: str, agent_id: str, printers: dict[str, str], dry_run=False,
                 state_dir=None, backend='auto', windows_renderer=None):
        target = urlsplit(server)
        if (not target.hostname or target.username or target.password or target.fragment
                or target.query or target.path not in ('', '/') or target.scheme not in ('https', 'http')):
            raise ValueError('Invalid print coordinator URL')
        try:
            _ = target.port
        except ValueError as exc:
            raise ValueError('Invalid print coordinator port') from exc
        if target.scheme == 'http' and target.hostname not in ('127.0.0.1', 'localhost', '::1'):
            raise ValueError('Use HTTPS for remote access')
        if len(token) < 24:
            raise ValueError("Agent token is missing")
        validate_printer_id(agent_id)
        for k in printers:
            validate_printer_id(k)
        self.server, self.token, self.agent_id = server.rstrip("/"), token, agent_id
        self.printers = printers
        self.dry_run = dry_run
        self.backend, self.windows_renderer = backend, windows_renderer
        if state_dir is None:
            root = Path(os.environ.get('LOCALAPPDATA', str(Path.home() / '.local' / 'state')))
            name = hashlib.sha256((self.server + '\0' + agent_id).encode()).hexdigest()[:20]
            state_dir = root / 'TABARC-Print' / name
        self.ledger = AgentLedger(state_dir)

    def request(self, method, path, data=None, content_type="application/json"):
        payload = json.dumps(data).encode() if data is not None else None
        req = Request(self.server + path, data=payload, method=method,
                      headers={"Authorization": "Bearer " + self.token,
                               "X-Agent-ID": self.agent_id, "Content-Type": content_type})
        with urlopen(req, timeout=30) as response:
            raw = response.read(20 * 1024 * 1024 + 100)
            if response.headers.get("Content-Type", "").startswith("application/pdf"):
                return raw
            return json.loads(raw)

    def register(self):
        for printer_id, queue in self.printers.items():
            self.request("POST", "/v1/agent/register", {"agent_id": self.agent_id,
                "printer_id": printer_id, "label": queue})

    def once(self):
        job = self.request("GET", "/v1/agent/claim")["job"]
        if job is None:
            return False
        jid = job['id']
        previous = self.ledger.claim(jid)
        if previous is not None:
            state, message = previous
            if state == 'claimed':
                state = 'uncertain'
                message = 'Connector restarted during submission; inspect local spooler'
                self.ledger.finish(jid, state, message)
            self._acknowledge(jid, state, message)
            return True
        state, message = 'failed', ''
        try:
            queue = self.printers.get(job['printer_id'])
            if queue is None:
                raise ValueError('No local queue mapping for printer')
            document = self.request('GET', '/v1/agent/document/' + jid)
            validate_pdf(document)
            with tempfile.TemporaryDirectory(prefix='tabarc-print-') as d:
                pdf = Path(d) / 'document.pdf'
                atomic_write(pdf, document)
                try:
                    message = spool_pdf(pdf, queue, self.dry_run,
                                        backend=self.backend, windows_renderer=self.windows_renderer)
                    state = 'submitted'
                except Exception as exc:
                    state = 'uncertain'
                    message = 'Print command outcome uncertain: ' + str(exc)[:240]
        except Exception as exc:
            message = str(exc)[:300]
        self.ledger.finish(jid, state, message)
        self._acknowledge(jid, state, message)
        return True

    def _acknowledge(self, jid, state, message):
        self.request('POST', '/v1/agent/complete/' + jid,
                     {'agent_id': self.agent_id, 'success': state == 'submitted',
                      'uncertain': state == 'uncertain', 'message': message})

def main():
    raise SystemExit('Legacy HTTP coordinator is disabled in this security preview; use local printing or encrypted Tor/cloud transport')
    ap = argparse.ArgumentParser(description="TABARC print connector")
    ap.add_argument("--server", default="http://127.0.0.1:8421")
    ap.add_argument("--id", default="local-agent")
    ap.add_argument("--printer", action="append", required=True, help="remote-id=local-CUPS-queue")
    ap.add_argument("--interval", type=float, default=5)
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument('--state-dir', help='Private local job ledger; never place in a synchronised folder')
    ap.add_argument('--backend', choices=('auto', 'cups', 'windows-sumatra'), default='auto')
    ap.add_argument('--windows-renderer', help='Absolute path to trusted SumatraPDF.exe')
    args = ap.parse_args()
    printers = {}
    for item in args.printer:
        key, sep, val = item.partition("=")
        if not sep or not val:
            ap.error("--printer must be remote-id=local-queue")
        printers[key] = val
    agent = Agent(args.server, os.getenv("TABARC_AGENT_TOKEN", ""), args.id, printers,
                  args.dry_run, args.state_dir, args.backend, args.windows_renderer)
    agent.register()
    print("Agent registered", ", ".join(printers))
    while True:
        try:
            if not agent.once():
                time.sleep(max(1.0, args.interval))
        except (HTTPError, URLError, OSError, ValueError) as exc:
            print("Connector error:", exc)
            time.sleep(max(5.0, args.interval))

if __name__ == "__main__":
    main()
