import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import subprocess
import time

MAX_FILE_BYTES = 20 * 1024 * 1024
PRINTER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$")
JOB_ID_RE = re.compile(r"^[0-9a-f]{32}$")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def validate_pdf(data: bytes) -> None:
    if len(data) == 0 or len(data) > MAX_FILE_BYTES:
        raise ValueError("Document must be between 1 byte and 20 MB")
    # Validation of the header is deliberately not treated as complete PDF validation.
    if not data.startswith(b"%PDF-"):
        raise ValueError("Only PDF documents are accepted")


def validate_printer_id(value: str) -> str:
    if not isinstance(value, str) or not PRINTER_ID_RE.fullmatch(value):
        raise ValueError("Invalid printer ID")
    return value


def safe_job_id(value: str) -> str:
    if not isinstance(value, str) or not JOB_ID_RE.fullmatch(value):
        raise ValueError("Invalid job ID")
    return value


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.urandom(6).hex()}.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def canonical_manifest_fields(job_id: str, printer_id: str, digest: str, created_at: int) -> bytes:
    return json.dumps(
        {"created_at": created_at, "job_id": job_id, "printer_id": printer_id, "sha256": digest},
        sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("utf-8")


def sign_manifest(key: bytes, job_id: str, printer_id: str, digest: str, created_at: int) -> str:
    return hmac.new(key, canonical_manifest_fields(job_id, printer_id, digest, created_at), hashlib.sha256).hexdigest()


def spool_pdf(pdf: Path, queue: str, dry_run: bool = False,
              backend: str = 'auto', windows_renderer: str | None = None) -> str:
    # Queue selection comes from the local administrator's configuration.
    if not queue or queue.startswith("-") or any(c in queue for c in "\n\r\x00"):
        raise ValueError("Invalid local print queue")
    if backend == 'auto':
        backend = 'windows-sumatra' if os.name == 'nt' else 'cups'
    if backend not in ('cups', 'windows-sumatra'):
        raise ValueError('Unknown print backend')
    if backend == 'windows-sumatra':
        renderer = windows_renderer or os.environ.get('TABARC_SUMATRA_PATH', '')
        if not renderer:
            raise ValueError('Set --windows-renderer to the trusted SumatraPDF.exe path')
        binary = Path(renderer).expanduser()
        if not binary.is_absolute() or not binary.is_file() or binary.suffix.lower() != '.exe':
            raise ValueError('Windows PDF renderer must be an existing, absolute .exe path')
        command = [str(binary.resolve()), '-print-to', queue, '-silent', str(pdf.resolve())]
    else:
        command = ['lp', '-d', queue, str(pdf.resolve())]
    if dry_run:
        return 'DRY_RUN'
    completed = subprocess.run(command,
        capture_output=True, text=True, check=False, timeout=120,
    )
    if completed.returncode:
        raise RuntimeError((completed.stderr or "Print submission failed")[:300])
    return completed.stdout.strip()[:200] if backend == 'cups' else 'Submitted to Windows print driver' 


def now() -> int:
    return int(time.time())
