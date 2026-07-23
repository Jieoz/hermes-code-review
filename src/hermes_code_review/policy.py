from __future__ import annotations

import fcntl
import json
import os
import re
import stat
import tempfile
import time
import uuid
from contextlib import contextmanager
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


def assert_public_payload_safe(value: object, *, forbidden: list[str]) -> None:
    """Fail closed if a public result contains known credentials or secret syntax."""
    material = json.dumps(value, ensure_ascii=False, sort_keys=True).encode('utf-8')
    for secret in forbidden:
        if secret and secret.encode('utf-8') in material:
            raise PolicyViolation('credential material detected in public review result')
    if any(pattern.search(material) for pattern in _SECRET_PATTERNS):
        raise PolicyViolation('secret-like material detected in public review result')


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


@contextmanager
def exclusive_lock(path: Path):
    """Open an owned regular lock file without following symlinks."""
    flags = os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC | getattr(os, 'O_NOFOLLOW', 0)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise PolicyViolation('unsafe policy lock file') from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise PolicyViolation('unsafe policy lock file')
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'a') as handle:
            fd = -1
            fcntl.flock(handle, fcntl.LOCK_EX)
            yield handle
    finally:
        if fd >= 0:
            os.close(fd)


def _load(path: Path, day: str) -> dict:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | getattr(os, 'O_NOFOLLOW', 0))
    except FileNotFoundError:
        value = {}
    except OSError as exc:
        raise PolicyViolation('unsafe budget ledger') from exc
    else:
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
                raise PolicyViolation('unsafe budget ledger')
            data = os.read(fd, 1_048_577)
            if len(data) > 1_048_576:
                raise PolicyViolation('budget ledger is unexpectedly large')
            try:
                value = json.loads(data.decode('utf-8'))
            except (UnicodeDecodeError, json.JSONDecodeError):
                value = {}
        finally:
            os.close(fd)
    if value.get('day') != day:
        return {'day': day, 'routes': {}, 'reservations': {}}
    value.setdefault('routes', {})
    value.setdefault('reservations', {})
    return value


def _day(now: float) -> str:
    return time.strftime('%Y-%m-%d', time.gmtime(now))


def _global_usage(value: dict) -> tuple[int, int]:
    input_used = output_used = 0
    for route in value.get('routes', {}).values():
        if not isinstance(route, dict):
            continue
        input_used += int(route.get('input_tokens') or 0)
        input_used += int(route.get('reserved_input_tokens') or 0)
        output_used += int(route.get('output_tokens') or 0)
        output_used += int(route.get('reserved_output_tokens') or 0)
    return input_used, output_used


def budget_status(path: Path, *, route_sha: str, daily_input_limit: int,
                  daily_output_limit: int, release_input_reserve: int = 0,
                  now: float | None = None) -> dict:
    now = time.time() if now is None else now
    if min(daily_input_limit, daily_output_limit, release_input_reserve) < 0:
        raise PolicyViolation('review budget limits cannot be negative')
    if daily_input_limit > 0 and release_input_reserve > daily_input_limit:
        raise PolicyViolation('release input reserve exceeds daily input limit')
    value = _load(path, _day(now))
    input_used, output_used = _global_usage(value)
    input_unlimited = daily_input_limit == 0
    output_unlimited = daily_output_limit == 0
    input_remaining = None if input_unlimited else max(0, daily_input_limit - input_used)
    effective_reserve = 0 if input_unlimited else release_input_reserve
    routine_input_remaining = (
        None if input_unlimited
        else max(0, daily_input_limit - input_used - effective_reserve)
    )
    reset_epoch = ((int(now) // 86_400) + 1) * 86_400
    return {
        'day_utc': value['day'],
        'input_used': input_used,
        'input_remaining': input_remaining,
        'routine_input_remaining': routine_input_remaining,
        'release_input_reserve': effective_reserve,
        'output_used': output_used,
        'output_remaining': None if output_unlimited else max(0, daily_output_limit - output_used),
        'reset_at': None if input_unlimited and output_unlimited else time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(reset_epoch)),
    }


def reserve_budget(path: Path, *, route_sha: str, estimated_input_tokens: int,
                   estimated_output_tokens: int, daily_input_limit: int,
                   daily_output_limit: int, release_input_reserve: int = 0,
                   allow_release_reserve: bool = False,
                   now: float | None = None) -> str:
    now = time.time() if now is None else now
    if min(estimated_input_tokens, estimated_output_tokens) <= 0:
        raise PolicyViolation('review token estimates must be positive')
    if min(daily_input_limit, daily_output_limit, release_input_reserve) < 0:
        raise PolicyViolation('review budget limits cannot be negative')
    if daily_input_limit > 0 and release_input_reserve > daily_input_limit:
        raise PolicyViolation('release input reserve exceeds daily input limit')
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(f'.{path.name}.lock')
    with exclusive_lock(lock_path) as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        value = _load(path, _day(now))
        row = dict(value['routes'].get(route_sha) or {})
        used_input, used_output = _global_usage(value)
        available_input_limit = daily_input_limit if allow_release_reserve else daily_input_limit - release_input_reserve
        if daily_input_limit > 0 and used_input + estimated_input_tokens > available_input_limit:
            detail = 'daily review input budget exhausted'
            if not allow_release_reserve and release_input_reserve:
                detail = 'daily review input budget reached protected release reserve'
            raise PolicyViolation(detail)
        if daily_output_limit > 0 and used_output + estimated_output_tokens > daily_output_limit:
            raise PolicyViolation('daily review output budget exhausted')
        reservation = uuid.uuid4().hex
        row['reserved_input_tokens'] = int(row.get('reserved_input_tokens') or 0) + estimated_input_tokens
        row['reserved_output_tokens'] = int(row.get('reserved_output_tokens') or 0) + estimated_output_tokens
        row.setdefault('input_tokens', 0)
        row.setdefault('output_tokens', 0)
        value['routes'][route_sha] = row
        value['reservations'][reservation] = {
            'route_sha': route_sha,
            'estimated_input_tokens': estimated_input_tokens,
            'estimated_output_tokens': estimated_output_tokens,
            'created_at': now,
        }
        _atomic_json(path, value)
        return reservation


def reconcile_budget(path: Path, reservation: str, *, actual_input_tokens: int,
                     actual_output_tokens: int, now: float | None = None) -> None:
    now = time.time() if now is None else now
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(f'.{path.name}.lock')
    with exclusive_lock(lock_path) as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        value = _load(path, _day(now))
        reserved = value['reservations'].pop(reservation, None)
        if not reserved:
            raise PolicyViolation('unknown or expired budget reservation')
        route_sha = reserved['route_sha']
        estimated_input = int(reserved['estimated_input_tokens'])
        estimated_output = int(reserved['estimated_output_tokens'])
        row = dict(value['routes'].get(route_sha) or {})
        row['reserved_input_tokens'] = max(0, int(row.get('reserved_input_tokens') or 0) - estimated_input)
        row['reserved_output_tokens'] = max(0, int(row.get('reserved_output_tokens') or 0) - estimated_output)
        row['input_tokens'] = int(row.get('input_tokens') or 0) + int(actual_input_tokens)
        row['output_tokens'] = int(row.get('output_tokens') or 0) + int(actual_output_tokens)
        value['routes'][route_sha] = row
        _atomic_json(path, value)
