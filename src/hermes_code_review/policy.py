from __future__ import annotations

import fcntl
import json
import os
import re
import tempfile
import time
import uuid
from pathlib import Path, PurePosixPath


class PolicyViolation(RuntimeError):
    """A local fail-closed policy rejected the review before code left the host."""


_SENSITIVE_NAMES = {
    '.env', 'id_rsa', 'id_ed25519', 'credentials.json', 'secrets.json',
    'service-account.json', 'auth.json',
}
_SENSITIVE_SUFFIXES = {'.pem', '.p12', '.pfx', '.key', '.keystore', '.jks'}
_SECRET_PATTERNS = [
    re.compile(rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    re.compile(rb'AKIA[0-9A-Z]{16}'),
    re.compile(rb'gh[pousr]_[A-Za-z0-9]{20,}'),
    re.compile(rb'sk-[A-Za-z0-9_-]{20,}'),
    re.compile(rb'(?i)authorization\s*:\s*bearer\s+[A-Za-z0-9._~+/=-]{16,}'),
    re.compile(rb'''(?ix)
        (?:api[_-]?key|client[_-]?secret|access[_-]?token|password)
        \s*[:=]\s*["']?
        (?!os\.environ|process\.env|env\()
        [A-Za-z0-9_./+=-]{16,}
    '''),
]


def _sensitive_path(value: str) -> bool:
    path = PurePosixPath(value.replace('\\', '/'))
    name = path.name.lower()
    if name in {'.env.example', '.env.sample', '.env.template'}:
        return False
    if name in _SENSITIVE_NAMES or name.startswith('.env.'):
        return True
    return path.suffix.lower() in _SENSITIVE_SUFFIXES


def check_privacy(paths: list[str], diff: bytes, requirements: str, evidence: str) -> None:
    blocked = [path for path in paths if _sensitive_path(path)]
    if blocked:
        raise PolicyViolation(f'sensitive path is not allowed in external review payload: {blocked[0]}')
    material = diff + b'\n' + requirements.encode('utf-8', errors='replace') + b'\n' + evidence.encode('utf-8', errors='replace')
    if any(pattern.search(material) for pattern in _SECRET_PATTERNS):
        raise PolicyViolation('secret-like material detected; external review payload blocked')


def estimate_tokens(text: str | bytes) -> int:
    size = len(text.encode('utf-8') if isinstance(text, str) else text)
    return (size + 3) // 4


def assert_request_budget(prompt: str, *, max_input_tokens: int) -> int:
    estimate = estimate_tokens(prompt)
    if estimate > max_input_tokens:
        raise PolicyViolation(f'request token estimate {estimate} exceeds limit {max_input_tokens}')
    return estimate


def _atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f'.{path.name}.', suffix='.tmp', dir=path.parent)
    temp = Path(name)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            json.dump(value, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def _load(path: Path, day: str) -> dict:
    try:
        value = json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        value = {}
    if value.get('day') != day:
        return {'day': day, 'routes': {}, 'reservations': {}}
    value.setdefault('routes', {})
    value.setdefault('reservations', {})
    return value


def _day(now: float) -> str:
    return time.strftime('%Y-%m-%d', time.gmtime(now))


def reserve_budget(path: Path, *, route_sha: str, estimated_input_tokens: int,
                   daily_limit: int, now: float | None = None) -> str:
    now = time.time() if now is None else now
    if estimated_input_tokens <= 0 or daily_limit <= 0:
        raise PolicyViolation('review budget limits must be positive')
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(f'.{path.name}.lock')
    with lock_path.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        value = _load(path, _day(now))
        row = dict(value['routes'].get(route_sha) or {})
        used = int(row.get('input_tokens') or 0) + int(row.get('reserved_input_tokens') or 0)
        if used + estimated_input_tokens > daily_limit:
            raise PolicyViolation('daily review budget exhausted')
        reservation = uuid.uuid4().hex
        row['reserved_input_tokens'] = int(row.get('reserved_input_tokens') or 0) + estimated_input_tokens
        row.setdefault('input_tokens', 0)
        row.setdefault('output_tokens', 0)
        value['routes'][route_sha] = row
        value['reservations'][reservation] = {
            'route_sha': route_sha,
            'estimated_input_tokens': estimated_input_tokens,
            'created_at': now,
        }
        _atomic_json(path, value)
        return reservation


def reconcile_budget(path: Path, reservation: str, *, actual_input_tokens: int,
                     actual_output_tokens: int, now: float | None = None) -> None:
    now = time.time() if now is None else now
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(f'.{path.name}.lock')
    with lock_path.open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        value = _load(path, _day(now))
        reserved = value['reservations'].pop(reservation, None)
        if not reserved:
            raise PolicyViolation('unknown or expired budget reservation')
        route_sha = reserved['route_sha']
        estimated = int(reserved['estimated_input_tokens'])
        row = dict(value['routes'].get(route_sha) or {})
        row['reserved_input_tokens'] = max(0, int(row.get('reserved_input_tokens') or 0) - estimated)
        row['input_tokens'] = int(row.get('input_tokens') or 0) + int(actual_input_tokens)
        row['output_tokens'] = int(row.get('output_tokens') or 0) + int(actual_output_tokens)
        value['routes'][route_sha] = row
        _atomic_json(path, value)
