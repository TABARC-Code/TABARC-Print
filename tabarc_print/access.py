"""Small, explicit printer access list for the local coordinator."""
import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import sys

from .common import validate_printer_id


@dataclass(frozen=True)
class Principal:
    identifier: str
    role: str
    printers: frozenset[str]

    def permits(self, printer_id: str) -> bool:
        return '*' in self.printers or printer_id in self.printers


def token_digest(token: str) -> str:
    if not isinstance(token, str) or not 32 <= len(token) <= 256:
        raise ValueError('Access tokens must be between 32 and 256 characters')
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


class AccessPolicy:
    def __init__(self, principals):
        self.by_digest = {}
        ids = set()
        for token_hash, principal in principals:
            if token_hash in self.by_digest or (principal.role, principal.identifier) in ids:
                raise ValueError('Duplicate access credential or account ID')
            self.by_digest[token_hash] = principal
            ids.add((principal.role, principal.identifier))

    @classmethod
    def from_file(cls, filename):
        path = Path(filename).expanduser()
        if path.is_symlink() or not path.is_file():
            raise ValueError('Access file must be a regular file, not a symlink')
        if os.name != 'nt' and stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise PermissionError('Restrict access file to its owner: chmod 600 ' + str(path))
        data = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(data, dict) or set(data) != {'users', 'agents'}:
            raise ValueError('Access file must contain only users and agents')
        principals = []
        for key, role in (('users', 'client'), ('agents', 'agent')):
            rows = data[key]
            if not isinstance(rows, list):
                raise ValueError('Accounts must be a list')
            for entry in rows:
                if not isinstance(entry, dict) or set(entry) != {'id', 'token_sha256', 'printers'}:
                    raise ValueError('Each account requires id, token_sha256 and printers')
                identity = validate_printer_id(entry['id'])
                digest = entry['token_sha256']
                if not isinstance(digest, str) or len(digest) != 64 or any(c not in '0123456789abcdef' for c in digest):
                    raise ValueError('Invalid SHA256 token digest')
                names = entry['printers']
                if not isinstance(names, list) or not names or len(names) != len(set(names)):
                    raise ValueError('Printer permissions must be a nonempty unique list')
                if role == 'agent' and '*' in names:
                    raise ValueError('Agent printer permissions must be explicit')
                for printer_id in names:
                    if printer_id != '*' or role != 'client':
                        validate_printer_id(printer_id)
                principals.append((digest, Principal(identity, role, frozenset(names))))
        if not any(p.role == 'agent' for _, p in principals) or not any(p.role == 'client' for _, p in principals):
            raise ValueError('Access file needs at least one user and one agent')
        return cls(principals)

    def authenticate(self, token: str, role: str):
        if not isinstance(token, str) or not 32 <= len(token) <= 256:
            return None
        # The file holds only digests, never bearer secrets.
        principal = self.by_digest.get(hashlib.sha256(token.encode('utf-8')).hexdigest())
        return principal if principal is not None and principal.role == role else None


def main():
    ap = argparse.ArgumentParser(description='Generate or hash a private access token')
    ap.add_argument('action', choices=['new-token', 'hash-stdin'])
    args = ap.parse_args()
    if args.action == 'new-token':
        token = secrets.token_urlsafe(48)
        print('Token (keep private):', token)
        print('token_sha256:', token_digest(token))
    else:
        token = sys.stdin.readline().rstrip('\r\n')
        print(token_digest(token))


if __name__ == '__main__':
    main()
