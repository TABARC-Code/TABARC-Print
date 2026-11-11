"""Local durable job decisions. A lease retry must never silently print twice."""
from contextlib import closing
from pathlib import Path
import sqlite3
import time

from .cloud_auth import private_auth_dir
from .common import safe_job_id


class AgentLedger:
    def __init__(self, path):
        self.root = private_auth_dir(Path(path))
        self.dbfile = self.root / 'agent-jobs.sqlite3'
        with closing(self.connect()) as db:
            db.execute('CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, state TEXT NOT NULL, '
                       'message TEXT NOT NULL, updated_at INTEGER NOT NULL)')
            db.commit()

    def connect(self):
        db = sqlite3.connect(self.dbfile, timeout=10)
        db.execute('PRAGMA busy_timeout=10000')
        db.execute('PRAGMA synchronous=FULL')
        return db

    def claim(self, jid):
        safe_job_id(jid)
        with closing(self.connect()) as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT state,message FROM jobs WHERE id=?', (jid,)).fetchone()
            if row is None:
                db.execute('INSERT INTO jobs VALUES (?, ?, ?, ?)', (jid, 'claimed', '', int(time.time())))
                db.commit()
                return None
            db.commit()
            return row

    def finish(self, jid, state, message):
        safe_job_id(jid)
        if state not in ('submitted', 'failed', 'uncertain'):
            raise ValueError('Unknown local job state')
        with closing(self.connect()) as db:
            db.execute('UPDATE jobs SET state=?,message=?,updated_at=? WHERE id=?',
                       (state, str(message)[:300], int(time.time()), jid))
            db.commit()
